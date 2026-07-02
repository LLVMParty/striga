from typing import TypeAlias, Callable, NamedTuple

from capstone import (
    CS_ARCH_X86,
    CS_MODE_64,
    CS_OP_REG,
    CS_OP_MEM,
    CS_OP_IMM,
    Cs,
    CsInsn,
)
from capstone.x86 import X86Op
from capstone.x86_const import (
    X86_REG_EIP,
    X86_REG_RIP,
    X86_REG_INVALID,
    X86_REG_GS,
)

from llvm import (
    Value,
    Builder,
    Module,
    Function,
    Opcode,
    IntPredicate,
    Type,
    BasicBlock,
    Metadata,
)


class GPR(NamedTuple):
    r64: str
    r32: str
    r16: str
    r8l: str
    r8h: str = ""


GPRS = [
    GPR("rax", "eax", "ax", "al", "ah"),
    GPR("rbx", "ebx", "bx", "bl", "bh"),
    GPR("rcx", "ecx", "cx", "cl", "ch"),
    GPR("rdx", "edx", "dx", "dl", "dh"),
    GPR("rsi", "esi", "si", "sil"),
    GPR("rdi", "edi", "di", "dil"),
    GPR("rsp", "esp", "sp", "spl"),
    GPR("rbp", "ebp", "bp", "bpl"),
    GPR("r8", "r8d", "r8w", "r8b"),
    GPR("r9", "r9d", "r9w", "r9b"),
    GPR("r10", "r10d", "r10w", "r10b"),
    GPR("r11", "r11d", "r11w", "r11b"),
    GPR("r12", "r12d", "r12w", "r12b"),
    GPR("r13", "r13d", "r13w", "r13b"),
    GPR("r14", "r14d", "r14w", "r14b"),
    GPR("r15", "r15d", "r15w", "r15b"),
]

FLAGS = {
    "cf": 0,
    "pf": 2,
    "af": 4,
    "zf": 6,
    "sf": 7,
    "df": 10,
    "of": 11,
}

XMM_REGS = [f"xmm{i}" for i in range(32)]


class Successor(NamedTuple):
    src: int
    dst: Value


SemanticFn: TypeAlias = Callable[["Semantics"], list[Successor] | None]
_semantics: dict[str, SemanticFn] = {}


def semantic(fn: SemanticFn):
    name = getattr(fn, "__name__")
    _semantics[name.removesuffix("_")] = fn
    return fn


class Semantics:
    def __init__(self, module: Module, *, verbose=False):
        self.module = module
        self.verbose = verbose

        # Disassembler
        self.cs = Cs(CS_ARCH_X86, CS_MODE_64)
        self.cs.detail = True

        # Aliases
        self.context = module.context
        types = self.context.types
        self.types = self.context.types
        self.i1 = types.i1
        self.i8 = types.i8
        self.i16 = types.i16
        self.i32 = types.i32
        self.i64 = types.i64
        self.i128 = types.i128

        # Register state
        self.subregs: dict[str, tuple[str, int, int]] = {}
        for r64, r32, r16, r8l, r8h in GPRS:
            self.subregs[r32] = (r64, 32, 0)
            self.subregs[r16] = (r64, 16, 0)
            self.subregs[r8l] = (r64, 8, 0)
            if r8h:
                self.subregs[r8h] = (r64, 8, 8)

        self.reg_sizes = {
            **{gpr.r64: 64 for gpr in GPRS},
            "gsbase": 64,
            **{name: 128 for name in XMM_REGS},
            "cf": 8,
            "zf": 8,
            "sf": 8,
            "of": 8,
            "pf": 8,
            "af": 8,
            "df": 8,
        }
        self.reg_types = {
            name: types.int_n(size) for name, size in self.reg_sizes.items()
        }

        def md_node(*args):
            return self.context.md_node(args)

        def md_string(s):
            return self.context.md_string(s)

        tbaa_root = md_node(md_string("state_root"))
        self.tbaa_tags: dict[str, Metadata] = {}
        for name in self.reg_types:
            tbaa_type = md_node(md_string(name), tbaa_root)
            self.tbaa_tags[name] = md_node(
                tbaa_type, tbaa_type, self.i64.constant(0).as_metadata()
            )
        self.reg_indices = {name: i for i, name in enumerate(self.reg_types)}
        self.state_ty = types.struct("State", self.reg_types.values())
        self.lifted_ty = types.function(types.void, [types.ptr, types.ptr])

        helper_ty = types.function(types.void, [self.i64])
        undef_flag_ty = types.function(self.i1, [self.i64])
        self.jmp_handler = self.module.add_function("__striga_jmp", helper_ty)
        self.call_handler = self.module.add_function("__striga_call", helper_ty)
        self.ret_handler = self.module.add_function("__striga_ret", helper_ty)
        self.syscall_handler = self.module.add_function("__striga_syscall", helper_ty)

        def add_undef_flag(name: str) -> Function:
            helper = self.module.add_function(f"__striga_undef_{name}", undef_flag_ty)
            # Undefined-flag helpers model arbitrary values, not side effects.
            # Match Remill's symbolic/undefined helper annotations so calls can
            # be deleted after their flag stores are proven dead.
            helper.attributes.add_memory("none")
            helper.attributes.add("nounwind")
            helper.attributes.add("willreturn")
            return helper

        self.undef_flags = {name: add_undef_flag(name) for name in FLAGS}

        # Set per function lifted
        self.insn_blocks: dict[int, BasicBlock] = {}
        self.function: Function
        self.reg_ptrs: dict[str, Value] = {}

        # Set per instruction
        self.ir: Builder
        self.insn: CsInsn

    def const64(self, val: int, sign_extend=False):
        return self.const_n(val, 64, sign_extend)

    def const_n(self, val: int, bits: int, sign_extend=False):
        return self.types.int_n(bits).constant(val, sign_extend)

    def resize_int(self, value: Value, ty: Type, *, sign_extend=False) -> Value:
        """Resize an integer value to ``ty`` with trunc/zext/sext as needed."""
        if value.type == ty:
            return value
        if value.type.int_width > ty.int_width:
            return self.ir.trunc(value, ty)
        if sign_extend:
            return self.ir.sext(value, ty)
        return self.ir.zext(value, ty)

    def begin(self, address: int) -> Function:
        name = f"lifted_{hex(address)}"
        fn = self.module.get_function(name)
        if fn is None:
            fn = self.module.add_function(name, self.lifted_ty)
            fn.param_attributes(0).add("noalias")
            fn.param_attributes(1).add("noalias")
            state, memory = fn.params
            memory.name = "memory"
            state.name = "state"
            self.function = fn
            self.reg_ptrs = {}
            self.insn_blocks = {}

            entry = fn.append_basic_block("initialize")
            assert fn.last_basic_block == entry
            with entry.create_builder() as ir:
                ir.br(self.get_or_create_block(address))
        else:
            self.function = fn
            self.reg_ptrs = {}
            self.insn_blocks = {}
            entry = fn.entry_block
            assert entry.name == "initialize", (
                "unexpected basic block for lifted function"
            )
            for block in fn.basic_blocks:
                if block.name.startswith("insn_"):
                    self.insn_blocks[int(block.name.removeprefix("insn_"), 16)] = block
            for insn in entry.instructions:
                if (
                    insn.opcode == Opcode.GetElementPtr
                    and insn.gep_source_element_type == self.state_ty
                ):
                    assert insn.name in self.reg_types, "unexpected GEP"
                    self.reg_ptrs[insn.name] = insn
        return self.function

    def cs_disasm(self, address: int, code: bytes) -> CsInsn:
        for insn in self.cs.disasm(code, address, count=1):  # ty: ignore[missing-argument, invalid-argument-type]
            return insn
        raise ValueError(f"Failed to disassemble {code.hex()}@{hex(address)}")

    def get_or_create_block(self, address: int) -> BasicBlock:
        block = self.insn_blocks.get(address)
        if block is None:
            block = self.function.append_basic_block(f"insn_{hex(address)}")
            with block.create_builder() as ir:
                ir.ret_void()
            self.insn_blocks[address] = block
        assert block.function == self.function
        return block

    def lift_bytes(self, address: int, code: bytes) -> list[Successor]:
        # Ensure we have a function to lift into
        if not hasattr(self, "function"):
            self.begin(address)

        insn = self.cs_disasm(address, code)
        if self.verbose:
            print(";", hex(insn.address), insn.mnemonic, insn.op_str)

        # Skip lifting if the block is already populated
        block = self.get_or_create_block(address)
        assert block.first_instruction
        if block.first_instruction.opcode == Opcode.Ret:
            block.first_instruction.erase_from_parent()
        else:
            return []

        with block.create_builder() as ir:
            # State used by semantic handlers
            self.ir = ir
            self.insn = insn

            handler = _semantics.get(insn.mnemonic)
            if handler is None and insn.mnemonic.startswith("lock "):
                # LOCK preserves the single-threaded architectural result; the
                # lifter does not model inter-thread atomicity separately.
                handler = _semantics.get(insn.mnemonic.removeprefix("lock "))
            if handler is None:
                raise NotImplementedError(insn.mnemonic)

            successors = handler(self)
            if successors is None:
                # Linear fallthrough - handler didn't emit a terminator.
                fallthrough = address + insn.size
                ir.br(self.get_or_create_block(fallthrough))
                successors = [Successor(address, self.const64(fallthrough))]

            # Make sure the handler produced valid IR
            self.module.verify_or_raise()
            return successors

    def reg_name(self, reg_id: int) -> str:
        return self.insn.reg_name(reg_id)  # pyright: ignore[reportReturnType]

    def reg_ptr(self, name: str) -> Value:
        reg_ptr = self.reg_ptrs.get(name)
        if reg_ptr is not None:
            return reg_ptr

        entry = self.function.entry_block
        state = self.function.get_param(0)
        with entry.create_builder() as ir:
            ir.position_before(entry.terminator)
            reg_ptr = ir.struct_gep(self.state_ty, state, self.reg_indices[name], name)
        self.reg_ptrs[name] = reg_ptr
        return reg_ptr

    def reg_read(self, name: str) -> Value:
        if name in self.reg_types:
            load = self.ir.load(self.reg_types[name], self.reg_ptr(name))
            load.metadata["tbaa"] = self.tbaa_tags[name]
            return load

        full_name, size, bit_offset = self.subregs[name]
        load = self.ir.load(self.reg_types[full_name], self.reg_ptr(full_name))
        load.metadata["tbaa"] = self.tbaa_tags[full_name]

        if bit_offset:
            load = self.ir.lshr(load, self.const64(bit_offset))
        return self.ir.trunc(load, self.types.int_n(size))

    def reg_write(self, name: str, value: Value):
        if name in self.reg_types:
            assert value.type.int_width == self.reg_sizes[name]
            store = self.ir.store(value, self.reg_ptr(name))
            store.metadata["tbaa"] = self.tbaa_tags[name]
            return

        full_name, size, bit_offset = self.subregs[name]
        assert value.type.int_width == size
        full_ptr = self.reg_ptr(full_name)

        # x86-64 writes to r32 zero-extend into the enclosing r64 register.
        if size == 32:
            store = self.ir.store(self.ir.zext(value, self.i64), full_ptr)
            store.metadata["tbaa"] = self.tbaa_tags[full_name]
            return

        # Narrow writes update only the addressed bits of the full register.
        mask = ((1 << size) - 1) << bit_offset
        load = self.ir.load(self.i64, full_ptr)
        load.metadata["tbaa"] = self.tbaa_tags[full_name]
        cleared = self.ir.and_(load, self.const64(~mask))
        widened = self.ir.zext(value, self.i64)
        if bit_offset:
            widened = self.ir.shl(widened, self.const64(bit_offset))
        store = self.ir.store(self.ir.or_(cleared, widened), full_ptr)
        store.metadata["tbaa"] = self.tbaa_tags[full_name]

    def mem_read(self, addr: Value, ty: Type) -> Value:
        memory = self.function.get_param(1)
        ptr = self.ir.gep(self.i8, memory, [addr])
        load = self.ir.load(ty, ptr)
        load.inst_alignment = 1
        return load

    def mem_write(self, addr: Value, value: Value):
        memory = self.function.get_param(1)
        ptr = self.ir.gep(self.i8, memory, [addr])
        store = self.ir.store(value, ptr)
        store.inst_alignment = 1

    def op_mem(self, op: X86Op) -> Value:
        assert op.type == CS_OP_MEM

        ir = self.ir
        addr_bits = self.insn.addr_size * 8
        addr_ty = self.types.int_n(addr_bits)
        addr: Value | None = None

        index = op.mem.index
        if index != X86_REG_INVALID:
            index_name = self.reg_name(index)  # pyright: ignore[reportAssignmentType]
            index_value = self.resize_int(self.reg_read(index_name), addr_ty)
            scale_value = addr_ty.constant(op.mem.scale)
            addr = ir.mul(index_value, scale_value)

        base = op.mem.base
        if base != X86_REG_INVALID:
            if base in (X86_REG_RIP, X86_REG_EIP):
                next_ip = self.insn.address + self.insn.size
                base_value = addr_ty.constant(next_ip)
            else:
                base_name = self.reg_name(base)  # pyright: ignore[reportAssignmentType]
                base_value = self.resize_int(self.reg_read(base_name), addr_ty)
            addr = ir.add(base_value, addr) if addr else base_value

        disp = op.mem.disp
        if disp != 0 or addr is None:
            disp_value = addr_ty.constant(disp)
            addr = ir.add(addr, disp_value) if addr else disp_value

        if addr.type != self.i64:
            addr = self.resize_int(addr, self.i64)

        if op.mem.segment == X86_REG_GS:
            addr = ir.add(addr, self.reg_read("gsbase"))

        return addr

    def op_read(self, index: int) -> Value:
        op: X86Op = self.insn.operands[index]
        if op.type == CS_OP_REG:
            name = self.reg_name(op.reg)  # pyright: ignore[reportAssignmentType]
            return self.reg_read(name)
        if op.type == CS_OP_IMM:
            # Capstone exposes x86 immediates at the architecturally consumed
            # width. That includes sign-extending compressed imm8/imm32 forms
            # when the instruction semantics require it, while leaving unsigned
            # full-width immediates as their original bit patterns.
            return self.const_n(op.imm, op.size * 8)
        if op.type == CS_OP_MEM:
            addr = self.op_mem(op)
            return self.mem_read(addr, self.types.int_n(op.size * 8))
        assert False

    def op_write(self, index: int, value: Value):
        op: X86Op = self.insn.operands[index]
        if op.type == CS_OP_REG:
            name = self.reg_name(op.reg)  # pyright: ignore[reportAssignmentType]
            self.reg_write(name, value)
        elif op.type == CS_OP_IMM:
            raise ValueError("Cannot write to CS_OP_IMM")
        elif op.type == CS_OP_MEM:
            addr = self.op_mem(op)
            # Memory operands write exactly op.size bytes; discard high bits if
            # a semantic helper produced a wider temporary value.
            store_bits = op.size * 8
            if value.type.int_width > store_bits:
                value = self.ir.trunc(value, self.types.int_n(store_bits))
            assert value.type.int_width == store_bits
            self.mem_write(addr, value)

    def _bool_to_flag(self, value: Value) -> Value:
        """Convert an LLVM i1 flag predicate to the i8 state representation."""
        if value.type == self.i8:
            return value
        assert value.type == self.i1
        return self.ir.zext(value, self.i8)

    def flag_read(self, name: str) -> Value:
        """Read an i8 flag from state as an LLVM i1 predicate."""
        return self.ir.icmp(IntPredicate.NE, self.reg_read(name), self.const_n(0, 8))

    def flag_write(self, name: str, value: Value):
        self.reg_write(name, self._bool_to_flag(value))

    def flag_write_if(self, cond: Value, name: str, value: Value):
        """Update a flag only when ``cond`` is true; otherwise preserve it."""
        assert cond.type == self.i1
        old_value = self.reg_read(name)
        new_value = self._bool_to_flag(value)
        self.reg_write(name, self.ir.select(cond, new_value, old_value))

    def flag_undef(self, name: str) -> Value:
        helper = self.undef_flags[name]
        return self.ir.call(helper, [self.const64(self.insn.address)])

    def flag_write_undef(self, name: str):
        self.flag_write(name, self.flag_undef(name))

    def flag_write_undef_if(self, cond: Value, name: str):
        self.flag_write_if(cond, name, self.flag_undef(name))

    def push(self, value: Value):
        byte_width = value.type.int_width // 8
        rsp = self.reg_read("rsp")
        rsp_sub = self.ir.sub(rsp, self.const64(byte_width))
        self.reg_write("rsp", rsp_sub)
        self.mem_write(rsp_sub, value)

    def pop(self, ty: Type) -> Value:
        byte_width = ty.int_width // 8
        rsp = self.reg_read("rsp")
        value = self.mem_read(rsp, ty)
        rsp_add = self.ir.add(rsp, self.const64(byte_width))
        self.reg_write("rsp", rsp_add)
        return value

    def rflags_value(self) -> Value:
        value = self.const64(1 << 1)  # Reserved bit 1 is always set.
        for name, bit in FLAGS.items():
            flag = self.ir.zext(self.flag_read(name), self.i64)
            if bit:
                flag = self.ir.shl(flag, self.const64(bit))
            value = self.ir.or_(value, flag)
        return value

    def result_is_zero(self, result: Value) -> Value:
        return self.ir.icmp(IntPredicate.EQ, result, result.type.constant(0))

    def result_sign_bit(self, result: Value) -> Value:
        sign_shift = result.type.constant(result.type.int_width - 1)
        return self.ir.trunc(self.ir.lshr(result, sign_shift), self.i1)

    def result_parity_even(self, result: Value) -> Value:
        """Return PF: even parity in the low byte of ``result``."""
        low = self.resize_int(result, self.i8)
        x = self.ir.xor(low, self.ir.lshr(low, self.const_n(4, 8)))
        x = self.ir.xor(x, self.ir.lshr(x, self.const_n(2, 8)))
        x = self.ir.xor(x, self.ir.lshr(x, self.const_n(1, 8)))
        return self.ir.icmp(
            IntPredicate.EQ,
            self.ir.and_(x, self.const_n(1, 8)),
            self.const_n(0, 8),
        )
