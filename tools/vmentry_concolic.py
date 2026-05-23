from __future__ import annotations

# ruff: noqa: E402

import argparse
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from capstone import CS_GRP_CALL, CS_GRP_JUMP, CS_OP_IMM, CS_OP_MEM, CsInsn
from capstone.x86_const import X86_REG_RIP
from llvm import BasicBlock, Function, IntPredicate, Opcode, Value, create_context

from container import PEContainer
from striga import Semantics
from tools.bright_step import call_name, parse_assignment, parse_int


SeedKind = Literal[
    "imm",
    "push_imm",
    "mov_imm",
    "lea_addr",
    "call_return",
    "image_backing",
    "overlay_store",
    "control_load",
]
CONTROL_SEED_KINDS: frozenset[SeedKind] = frozenset(
    {
        "push_imm",
        "mov_imm",
        "lea_addr",
        "call_return",
        "image_backing",
        "overlay_store",
        "control_load",
    }
)


@dataclass(frozen=True)
class Seed:
    kind: SeedKind
    insn_addr: int
    value: int
    detail: str
    source_addr: int | None = None


@dataclass(frozen=True)
class Address:
    base: Literal["abs", "stack", "teb", "peb", "unknown"]
    offset: int = 0

    @property
    def concrete(self) -> int | None:
        return self.offset if self.base == "abs" else None

    def add(self, delta: int) -> Address:
        return Address(self.base, self.offset + delta)

    def text(self) -> str:
        if self.base == "abs":
            return f"{self.offset:#x}"
        if self.offset == 0:
            return self.base
        return f"{self.base}{self.offset:+#x}"


@dataclass(frozen=True)
class SymVal:
    text: str
    concrete: int | None
    width: int | None
    address: Address | None = None
    unknowns: tuple[str, ...] = ()
    deps: frozenset[str] = frozenset()
    xor_symbols: frozenset[str] = frozenset()
    xor_address: Address | None = None
    xor_const: int = 0

    def with_width(self, width: int | None, *, signed: bool = False) -> SymVal:
        if width is None or self.width == width:
            return self
        concrete = None
        if self.concrete is not None:
            concrete = sext_value(self.concrete, self.width, width) if signed else mask_value(self.concrete, width)
        address = self.address if width == 64 and self.width == 64 else None
        xor_address = self.xor_address if width == self.width else None
        xor_symbols = self.xor_symbols if width == self.width else frozenset()
        xor_const = self.xor_const if width == self.width else 0
        return SymVal(
            f"{cast_text('sext' if signed else 'zext', self.text, width)}",
            concrete,
            width,
            address,
            self.unknowns,
            self.deps,
            xor_symbols,
            xor_address,
            xor_const,
        )

    @staticmethod
    def const(value: int, width: int | None, text: str | None = None) -> SymVal:
        concrete = mask_value(value, width)
        return SymVal(text or format_int(concrete), concrete, width, xor_const=concrete)

    @staticmethod
    def unknown(text: str, width: int | None) -> SymVal:
        return SymVal(text, None, width, unknowns=(text,), xor_symbols=frozenset({text}))

    @staticmethod
    def env(base: Literal["stack", "teb", "peb"], width: int = 64) -> SymVal:
        address = Address(base, 0)
        return SymVal(base, None, width, address, xor_address=address)


@dataclass(frozen=True)
class PtrVal:
    kind: Literal["state", "memory", "unknown"]
    offset: SymVal | None = None
    reg: str | None = None

    def text(self) -> str:
        if self.kind == "state":
            return f"state.{self.reg}"
        if self.kind == "memory" and self.offset is not None:
            return f"memory[{self.offset.text}]"
        return "unknown_ptr"


@dataclass(frozen=True)
class MemoryKey:
    base: str
    offset: int

    def add(self, delta: int) -> MemoryKey:
        return MemoryKey(self.base, self.offset + delta)

    def text(self) -> str:
        if self.base == "abs":
            return f"{self.offset:#x}"
        if self.offset == 0:
            return self.base
        return f"{self.base}{self.offset:+#x}"


@dataclass
class MemoryModel:
    container: PEContainer
    seeds: list[Seed]
    zero_unknown_abs: bool = False
    exact: dict[tuple[MemoryKey, int], SymVal] = field(default_factory=dict)
    bytes: dict[MemoryKey, SymVal] = field(default_factory=dict)

    def key_from_offset(self, offset: SymVal) -> MemoryKey | None:
        if offset.address is not None:
            return MemoryKey(offset.address.base, offset.address.offset)
        if offset.concrete is not None:
            return MemoryKey("abs", offset.concrete)
        return None

    def read(self, offset: SymVal, width: int, *, insn_addr: int = 0) -> SymVal:
        key = self.key_from_offset(offset)
        if key is None:
            return SymVal.unknown(f"load_i{width}({offset.text})", width)

        env = self._read_environment(key, width)
        if env is not None:
            return env

        exact = self.exact.get((key, width))
        if exact is not None:
            return exact.with_width(width)
        covered = self._read_covering_exact(key, width)
        if covered is not None:
            return covered

        byte_width = width // 8
        parts = [self.bytes.get(key.add(i)) for i in range(byte_width)]
        if all(part is not None and part.concrete is not None for part in parts):
            concrete = 0
            texts: list[str] = []
            deps: frozenset[str] = frozenset()
            for i, part in enumerate(parts):
                assert part is not None and part.concrete is not None
                concrete |= (part.concrete & 0xFF) << (i * 8)
                texts.append(part.text)
                deps = deps | part.deps
            text = format_int(concrete) if not deps and len(set(texts)) == 1 else "concat_le(" + ", ".join(texts) + ")"
            return SymVal(
                text,
                mask_value(concrete, width),
                width,
                deps=deps,
                xor_const=mask_value(concrete, width),
            )

        if key.base == "abs":
            if self.container.in_range(key.offset) and self.container.in_range(key.offset + byte_width - 1):
                data = self.container.get_data(key.offset, byte_width)
                value = int.from_bytes(data, "little")
                seed = Seed(
                    "image_backing",
                    insn_addr,
                    value,
                    f"read i{width} from initial image {key.offset:#x}; addr_expr={offset.text}",
                    key.offset,
                )
                add_seed(self.seeds, seed)
                marker = seed_marker(seed)
                return SymVal(
                    f"{value:#x}/*{marker}*/{{addr={offset.text}}}",
                    mask_value(value, width),
                    width,
                    deps=offset.deps | frozenset({marker}),
                    xor_const=mask_value(value, width),
                )
            if self.zero_unknown_abs:
                return SymVal.const(0, width, f"0/*zero_uninit@{key.offset:#x}*/")

        return SymVal.unknown(f"load_i{width}({key.text()})", width)

    def write(self, offset: SymVal, value: SymVal, *, insn_addr: int = 0) -> None:
        key = self.key_from_offset(offset)
        width = value.width
        if key is None or width is None or width % 8:
            return
        byte_width = width // 8
        self._remove_overlapping_exact(key, byte_width)
        stored = self._annotate_overlay_store(key, value.with_width(width), insn_addr)
        self.exact[(key, width)] = stored
        for i in range(byte_width):
            byte_key = key.add(i)
            if stored.concrete is not None:
                byte = (stored.concrete >> (i * 8)) & 0xFF
                text = f"byte{i}({stored.text})" if stored.deps else f"{byte:#x}"
                self.bytes[byte_key] = SymVal(
                    text,
                    byte,
                    8,
                    unknowns=stored.unknowns,
                    deps=stored.deps,
                    xor_const=byte,
                )
            else:
                self.bytes[byte_key] = SymVal(
                    f"byte{i}({stored.text})",
                    None,
                    8,
                    unknowns=stored.unknowns,
                    deps=stored.deps,
                )

    def _annotate_overlay_store(
        self, key: MemoryKey, value: SymVal, insn_addr: int
    ) -> SymVal:
        if key.base != "abs" or insn_addr == 0 or value.concrete is None:
            return value
        seed = Seed(
            "overlay_store",
            insn_addr,
            value.concrete,
            f"store i{value.width} to memory {key.offset:#x}; value_expr={value.text}",
            key.offset,
        )
        add_seed(self.seeds, seed)
        marker = seed_marker(seed)
        if marker in value.text:
            return value
        return SymVal(
            f"overlay_store[{key.offset:#x}]({value.text})/*{marker}*/",
            value.concrete,
            value.width,
            value.address,
            value.unknowns,
            value.deps | frozenset({marker}),
            value.xor_symbols,
            value.xor_address,
            value.xor_const,
        )

    def _read_covering_exact(self, key: MemoryKey, width: int) -> SymVal | None:
        byte_width = width // 8
        for (exact_key, exact_width), exact in self.exact.items():
            if exact_key.base != key.base:
                continue
            exact_byte_width = exact_width // 8
            start = key.offset
            end = start + byte_width
            exact_start = exact_key.offset
            exact_end = exact_start + exact_byte_width
            if not (exact_start <= start and end <= exact_end):
                continue
            shift = (start - exact_start) * 8
            concrete = None
            if exact.concrete is not None:
                concrete = mask_value(exact.concrete >> shift, width)
            if shift:
                text = f"trunc(({exact.text} >>> {format_int(shift)}) -> i{width})"
            else:
                text = f"trunc({exact.text} -> i{width})"
            return SymVal(
                text,
                concrete,
                width,
                unknowns=exact.unknowns,
                deps=exact.deps,
                xor_const=mask_value(exact.xor_const >> shift, width),
            )
        return None

    def _remove_overlapping_exact(self, key: MemoryKey, byte_width: int) -> None:
        to_delete: list[tuple[MemoryKey, int]] = []
        start = key.offset
        end = start + byte_width
        for exact_key, width in self.exact:
            if exact_key.base != key.base:
                continue
            exact_start = exact_key.offset
            exact_end = exact_start + width // 8
            if start < exact_end and exact_start < end:
                to_delete.append((exact_key, width))
        for item in to_delete:
            del self.exact[item]

    def _read_environment(self, key: MemoryKey, width: int) -> SymVal | None:
        if key.base == "teb" and width == 64:
            if key.offset == 0x60:
                return SymVal.env("peb")
            if key.offset == 0x30:
                return SymVal.const(0, 64, "teb.self_or_stack_cookie" )
        if key.base == "peb" and key.offset == 0x10 and width == 64:
            return SymVal.const(self.container.image_base, 64, f"{self.container.image_base:#x}/*image_base*/")
        return None


@dataclass
class ExecutionState:
    regs: dict[str, SymVal]
    memory: MemoryModel
    seeds: list[Seed]
    locals: dict[int, SymVal | PtrVal] = field(default_factory=dict)
    boundary_call: str | None = None
    boundary_value: SymVal | None = None
    steps: int = 0


@dataclass
class ConcolicConfig:
    binary: Path
    rip: int
    out_dir: Path
    follow_calls: set[int] = field(default_factory=set)
    concrete_regs: dict[str, int] = field(default_factory=dict)
    max_steps: int = 200_000
    trace_limit: int = 400
    zero_unknown_abs: bool = False


@dataclass
class ConcolicResult:
    start: int
    stop: int
    instruction: str
    boundary_call: str | None
    boundary_value: SymVal | None
    steps: int
    trace: list[str]
    module_text: str
    seeds: list[Seed]


def format_int(value: int) -> str:
    return hex(value) if abs(value) >= 10 else str(value)


def mask_value(value: int, width: int | None) -> int:
    if width is None:
        return value
    return value & ((1 << width) - 1)


def sign_extend(value: int, from_width: int | None) -> int:
    if from_width is None or from_width == 0:
        return value
    value = mask_value(value, from_width)
    sign_bit = 1 << (from_width - 1)
    return value - (1 << from_width) if value & sign_bit else value


def sext_value(value: int, from_width: int | None, to_width: int | None) -> int:
    return mask_value(sign_extend(value, from_width), to_width)


def value_width(value: Value) -> int | None:
    return value.type.int_width if value.type.is_integer else None


def cast_text(name: str, text: str, width: int | None) -> str:
    return f"{name}({text} -> i{width})"


def parse_int_set(items: list[int]) -> set[int]:
    return set(items)


def seed_marker(seed: Seed) -> str:
    marker = f"{seed.kind}@{seed.insn_addr:#x}"
    if seed.source_addr is not None:
        marker = f"{marker}:{seed.source_addr:#x}"
    return marker


def add_seed(seeds: list[Seed], seed: Seed) -> None:
    key = (seed.kind, seed.insn_addr, mask_value(seed.value, 64), seed.detail, seed.source_addr)
    if any(
        (item.kind, item.insn_addr, mask_value(item.value, 64), item.detail, item.source_addr) == key
        for item in seeds
    ):
        return
    seeds.append(seed)


def instruction_address_from_metadata(inst: Value) -> int | None:
    name = inst.name
    if name.startswith("mem_read_"):
        token = name.removeprefix("mem_read_").split(".", 1)[0]
        try:
            return int(token, 16)
        except ValueError:
            pass
    md = inst.metadata.get("striga.insn")
    if md is None or not md.is_node:
        return None
    operands = md.operands
    if not operands or not operands[0].is_string:
        return None
    return int(operands[0].string, 0)


def annotate_value_with_instruction_seed(
    value: SymVal, insn_addr: int | None, seeds: list[Seed]
) -> SymVal:
    if insn_addr is None or value.concrete is None:
        return value
    for seed in seeds:
        if seed.kind not in CONTROL_SEED_KINDS:
            continue
        if seed.insn_addr != insn_addr:
            continue
        if mask_value(seed.value, value.width) != mask_value(value.concrete, value.width):
            continue
        marker = seed_marker(seed)
        if marker in value.text:
            return value
        return SymVal(
            f"{format_int(value.concrete)}/*{marker}*/",
            value.concrete,
            value.width,
            value.address,
            value.unknowns,
            value.deps | frozenset({marker}),
            value.xor_symbols,
            value.xor_address,
            value.xor_const,
        )
    return value


class LLVMConcolicExecutor:
    def __init__(self, container: PEContainer, cfg: ConcolicConfig):
        self.container = container
        self.cfg = cfg
        self.trace: list[str] = []

    def run(self) -> ConcolicResult:
        with create_context() as context:
            with context.create_module(f"vmentry_concolic_{self.cfg.rip:x}") as module:
                sem = Semantics(module, verbose=False)
                sem.begin(self.cfg.rip)
                state = self._initial_state(sem)
                rip = self.cfg.rip
                stop = rip
                instruction = ""

                for step in range(self.cfg.max_steps):
                    state.steps = step + 1
                    code = self.container.get_data(rip, 15)
                    insn = sem.cs_disasm(rip, code)
                    instruction = f"{insn.mnemonic} {insn.op_str}".strip()
                    self._record_seed_candidates(insn, state)
                    if len(self.trace) < self.cfg.trace_limit:
                        self.trace.append(f"{rip:#x}: {instruction}")

                    if insn.group(CS_GRP_CALL) and rip in self.cfg.follow_calls:
                        self._lift_followed_call(sem, insn)
                    else:
                        block = sem.get_or_create_block(rip)
                        if block.first_instruction is not None and block.first_instruction.opcode == Opcode.Ret:
                            sem.lift_bytes(rip, code)

                    block = sem.insn_blocks[rip]
                    next_rip = self._execute_block(sem.function, block, state)
                    if state.boundary_call is not None:
                        stop = rip
                        break
                    if next_rip is None:
                        stop = rip
                        break
                    rip = next_rip
                else:
                    stop = rip
                    state.boundary_call = "step_limit"
                    state.boundary_value = SymVal.unknown("step_limit", 64)

                result = ConcolicResult(
                    self.cfg.rip,
                    stop,
                    instruction,
                    state.boundary_call,
                    state.boundary_value,
                    state.steps,
                    self.trace,
                    str(module),
                    state.seeds,
                )
                self._write_outputs(result)
                return result

    def _initial_state(self, sem: Semantics) -> ExecutionState:
        regs: dict[str, SymVal] = {}
        for name, ty in sem.reg_types.items():
            width = ty.int_width
            if name in self.cfg.concrete_regs:
                regs[name] = SymVal.const(self.cfg.concrete_regs[name], width)
            elif name == "rsp":
                regs[name] = SymVal.env("stack", width)
            elif name == "gsbase":
                regs[name] = SymVal.env("teb", width)
            else:
                regs[name] = SymVal.unknown(f"source_{name}()", width)
        seeds: list[Seed] = []
        return ExecutionState(
            regs,
            MemoryModel(self.container, seeds, self.cfg.zero_unknown_abs),
            seeds,
        )

    def _record_seed_candidates(self, insn, state: ExecutionState) -> None:
        for op in insn.operands:
            if op.type == CS_OP_IMM:
                if insn.mnemonic == "call":
                    add_seed(
                        state.seeds,
                        Seed(
                            "call_return",
                            insn.address,
                            insn.address + insn.size,
                            f"call return {insn.address + insn.size:#x}",
                        ),
                    )
                    continue
                if insn.group(CS_GRP_JUMP):
                    continue
                kind: SeedKind = "imm"
                if insn.mnemonic == "push":
                    kind = "push_imm"
                elif insn.mnemonic in {"mov", "movabs"}:
                    kind = "mov_imm"
                add_seed(state.seeds, Seed(kind, insn.address, op.imm, f"{insn.mnemonic} {insn.op_str}"))
            elif op.type == CS_OP_MEM and insn.mnemonic == "lea" and op.mem.base == X86_REG_RIP:
                addr = insn.address + insn.size + op.mem.disp
                add_seed(state.seeds, Seed("lea_addr", insn.address, addr, f"lea {insn.op_str}"))

    def _lift_followed_call(self, sem: Semantics, insn: CsInsn) -> None:
        block = sem.get_or_create_block(insn.address)
        if block.first_instruction is not None and block.first_instruction.opcode == Opcode.Ret:
            block.first_instruction.erase_from_parent()
        else:
            return
        target = insn.operands[0].imm
        fallthrough = insn.address + insn.size
        with block.create_builder() as ir:
            sem.ir = ir
            sem.insn = insn
            sem.push(sem.const64(fallthrough))
            ir.br(sem.get_or_create_block(target))
        sem.module.verify_or_raise()

    def _execute_block(
        self, function: Function, block: BasicBlock, state: ExecutionState
    ) -> int | None:
        state.locals = {}
        for inst in block.instructions:
            if inst == block.terminator:
                break
            self._execute_instruction(function, inst, state)
            if state.boundary_call is not None:
                return None
        terminator = block.terminator
        if terminator is None:
            return None
        if terminator.opcode == Opcode.Br:
            if terminator.is_conditional:
                cond = self._eval_value(terminator.condition, state).with_width(1)
                if cond.concrete is None:
                    state.boundary_call = "symbolic_branch"
                    state.boundary_value = cond
                    return None
                successor = terminator.get_successor(0 if cond.concrete else 1)
            else:
                successor = terminator.get_successor(0)
            return block_address(successor)
        if terminator.opcode == Opcode.Ret:
            return None
        state.boundary_call = f"unsupported_terminator_{terminator.opcode.value}"
        state.boundary_value = SymVal.unknown(str(terminator).strip(), None)
        return None

    def _execute_instruction(
        self, function: Function, inst: Value, state: ExecutionState
    ) -> None:
        op = inst.opcode
        if op == Opcode.Store:
            value = annotate_value_with_instruction_seed(
                self._eval_value(inst.get_operand(0), state),
                instruction_address_from_metadata(inst),
                state.seeds,
            )
            ptr = self._eval_pointer(inst.get_operand(1), state)
            if ptr.kind == "state" and ptr.reg is not None:
                state.regs[ptr.reg] = value.with_width(state.regs[ptr.reg].width)
            elif ptr.kind == "memory" and ptr.offset is not None:
                state.memory.write(
                    ptr.offset.with_width(64),
                    value,
                    insn_addr=instruction_address_from_metadata(inst) or 0,
                )
            return
        if op == Opcode.Call:
            self._eval_call(inst, state)
            return
        if inst.type.is_void:
            return
        if op in {Opcode.Load, Opcode.GetElementPtr, Opcode.PtrToInt, Opcode.IntToPtr}:
            if op == Opcode.GetElementPtr:
                state.locals[hash(inst)] = self._eval_pointer(inst, state)
            else:
                state.locals[hash(inst)] = self._eval_value(inst, state)
            return
        state.locals[hash(inst)] = self._eval_value(inst, state)

    def _eval_value(self, value: Value, state: ExecutionState) -> SymVal:
        cached = state.locals.get(hash(value))
        if isinstance(cached, SymVal):
            return cached
        width = value_width(value)
        if value.is_constant_int:
            return SymVal.const(value.const_zext_value, width)
        if value.is_argument:
            if value.name == "memory":
                return SymVal.unknown("%memory", width)
            if value.name == "state":
                return SymVal.unknown("%state", width)
            return SymVal.unknown(f"%{value.name}", width)
        if not value.is_instruction:
            return SymVal.unknown(str(value).strip(), width)
        op = value.opcode
        if op == Opcode.Load:
            ptr = self._eval_pointer(value.get_operand(0), state)
            if ptr.kind == "state" and ptr.reg is not None:
                return state.regs[ptr.reg].with_width(width)
            if ptr.kind == "memory" and ptr.offset is not None and width is not None:
                return state.memory.read(
                    ptr.offset.with_width(64),
                    width,
                    insn_addr=instruction_address_from_metadata(value) or 0,
                )
            return SymVal.unknown(f"load({ptr.text()})", width)
        if op == Opcode.Call:
            return self._eval_call(value, state)
        if op in BINARY_OPS:
            return self._eval_binary(value, state)
        if op in {Opcode.Trunc, Opcode.ZExt, Opcode.SExt}:
            inner = self._eval_value(value.get_operand(0), state)
            if op == Opcode.Trunc:
                concrete = None if inner.concrete is None else mask_value(inner.concrete, width)
                return SymVal(
                    cast_text("trunc", inner.text, width),
                    concrete,
                    width,
                    unknowns=inner.unknowns,
                    deps=inner.deps,
                    xor_const=mask_value(inner.xor_const, width),
                )
            return inner.with_width(width, signed=op == Opcode.SExt)
        if op == Opcode.ICmp:
            return self._eval_icmp(value, state)
        if op == Opcode.Select:
            cond = self._eval_value(value.get_operand(0), state).with_width(1)
            true_value = self._eval_value(value.get_operand(1), state).with_width(width)
            false_value = self._eval_value(value.get_operand(2), state).with_width(width)
            if cond.concrete is not None:
                return true_value if cond.concrete else false_value
            concrete = true_value.concrete if true_value.concrete == false_value.concrete else None
            return SymVal(
                f"select({cond.text}, {true_value.text}, {false_value.text})",
                concrete,
                width,
                unknowns=(*cond.unknowns, *true_value.unknowns, *false_value.unknowns),
                deps=cond.deps | true_value.deps | false_value.deps,
            )
        if op == Opcode.GetElementPtr:
            ptr = self._eval_pointer(value, state)
            if ptr.kind == "memory" and ptr.offset is not None:
                return ptr.offset
            return SymVal.unknown(ptr.text(), width)
        if op == Opcode.PtrToInt:
            ptr = self._eval_pointer(value.get_operand(0), state)
            if ptr.kind == "memory" and ptr.offset is not None:
                return ptr.offset.with_width(width)
            return SymVal.unknown(f"ptrtoint({ptr.text()})", width)
        if op == Opcode.IntToPtr:
            return self._eval_value(value.get_operand(0), state).with_width(width)
        return SymVal.unknown(f"unsupported:{op.value}:{str(value).strip()}", width)

    def _eval_pointer(self, value: Value, state: ExecutionState) -> PtrVal:
        cached = state.locals.get(hash(value))
        if isinstance(cached, PtrVal):
            return cached
        if value.is_argument:
            if value.name == "memory":
                return PtrVal("memory", SymVal.const(0, 64))
            if value.name == "state":
                return PtrVal("state", reg="root")
        if value.is_instruction and value.opcode == Opcode.GetElementPtr:
            if value.name in state.regs and value.num_operands >= 1:
                base = value.get_operand(0)
                if base.is_argument and base.name == "state":
                    return PtrVal("state", reg=value.name)
            base_ptr = self._eval_pointer(value.get_operand(0), state)
            index = self._eval_value(value.get_operand(value.num_operands - 1), state).with_width(64)
            if base_ptr.kind == "memory" and base_ptr.offset is not None:
                return PtrVal("memory", combine_values(base_ptr.offset, index, Opcode.Add, 64))
        as_value = self._eval_value(value, state).with_width(64)
        return PtrVal("memory", as_value)

    def _eval_call(self, inst: Value, state: ExecutionState) -> SymVal:
        name = call_name(inst)
        width = value_width(inst)
        if name is None:
            return SymVal.unknown("unknown_call()", width)
        if name.startswith("__striga_undef_"):
            return SymVal.unknown(f"{name}()", width)
        if name == "__striga_jmp":
            target_arg = inst.get_arg_operand(0)
            target = self._eval_value(target_arg, state).with_width(64)
            state.boundary_call = name
            state.boundary_value = self._annotate_control_load(target_arg, target, state)
            return SymVal.const(0, width)
        if name in {"__striga_call", "__striga_ret", "__striga_syscall"}:
            target_arg = inst.get_arg_operand(0)
            target = self._eval_value(target_arg, state).with_width(64)
            state.boundary_call = name
            state.boundary_value = self._annotate_control_load(target_arg, target, state)
            return SymVal.const(0, width)
        if name.startswith("llvm.fshl."):
            return self._eval_funnel_shift(inst, state, left=True)
        if name.startswith("llvm.fshr."):
            return self._eval_funnel_shift(inst, state, left=False)
        return SymVal.unknown(f"{name}()", width)

    def _annotate_control_load(
        self, arg: Value, target: SymVal, state: ExecutionState
    ) -> SymVal:
        if not arg.is_instruction or arg.opcode != Opcode.Load:
            return target
        if target.concrete is None:
            return target
        ptr = self._eval_pointer(arg.get_operand(0), state)
        if ptr.kind != "memory" or ptr.offset is None:
            return target
        offset = ptr.offset.with_width(64)
        source_addr = offset.concrete
        if source_addr is None:
            return target
        insn_addr = instruction_address_from_metadata(arg)
        if insn_addr is None:
            return target
        seed = Seed(
            "control_load",
            insn_addr,
            target.concrete,
            f"load i{target.width} from memory {source_addr:#x}; addr_expr={offset.text}",
            source_addr,
        )
        add_seed(state.seeds, seed)
        marker = seed_marker(seed)
        if marker in target.text:
            return target
        return SymVal(
            f"control_load[{source_addr:#x}]({target.text})/*{marker}*/",
            target.concrete,
            target.width,
            target.address,
            target.unknowns,
            target.deps | frozenset({marker}),
            target.xor_symbols,
            target.xor_address,
            target.xor_const,
        )

    def _eval_binary(self, value: Value, state: ExecutionState) -> SymVal:
        width = value_width(value)
        lhs = self._eval_value(value.get_operand(0), state).with_width(width)
        rhs = self._eval_value(value.get_operand(1), state).with_width(width)
        return combine_values(lhs, rhs, value.opcode, width)

    def _eval_icmp(self, value: Value, state: ExecutionState) -> SymVal:
        lhs = self._eval_value(value.get_operand(0), state)
        rhs = self._eval_value(value.get_operand(1), state).with_width(lhs.width)
        concrete = None
        if lhs.concrete is not None and rhs.concrete is not None:
            concrete = int(eval_icmp(value.icmp_predicate, lhs.concrete, rhs.concrete, lhs.width))
        return SymVal(
            f"icmp.{value.icmp_predicate.name.lower()}({lhs.text}, {rhs.text})",
            concrete,
            1,
            unknowns=(*lhs.unknowns, *rhs.unknowns),
            deps=lhs.deps | rhs.deps,
        )

    def _eval_funnel_shift(self, value: Value, state: ExecutionState, *, left: bool) -> SymVal:
        width = value_width(value)
        lhs = self._eval_value(value.get_arg_operand(0), state).with_width(width)
        rhs = self._eval_value(value.get_arg_operand(1), state).with_width(width)
        shift = self._eval_value(value.get_arg_operand(2), state).with_width(width)
        concrete = None
        if width is not None and lhs.concrete is not None and rhs.concrete is not None and shift.concrete is not None:
            amount = shift.concrete % width
            mask = (1 << width) - 1
            if amount == 0:
                concrete = lhs.concrete & mask
            elif left:
                concrete = ((lhs.concrete << amount) | (rhs.concrete >> (width - amount))) & mask
            else:
                concrete = ((lhs.concrete >> amount) | (rhs.concrete << (width - amount))) & mask
        name = "fshl" if left else "fshr"
        return SymVal(
            f"{name}({lhs.text}, {rhs.text}, {shift.text})",
            concrete,
            width,
            unknowns=(*lhs.unknowns, *rhs.unknowns, *shift.unknowns),
            deps=lhs.deps | rhs.deps | shift.deps,
        )

    def _write_outputs(self, result: ConcolicResult) -> None:
        self.cfg.out_dir.mkdir(parents=True, exist_ok=True)
        (self.cfg.out_dir / "trace.txt").write_text("\n".join(result.trace) + "\n", encoding="utf-8")
        (self.cfg.out_dir / "module.ll").write_text(result.module_text + "\n", encoding="utf-8")
        (self.cfg.out_dir / "summary.md").write_text(render_result(result), encoding="utf-8")


BINARY_OPS = {
    Opcode.Add,
    Opcode.Sub,
    Opcode.Mul,
    Opcode.UDiv,
    Opcode.SDiv,
    Opcode.URem,
    Opcode.SRem,
    Opcode.And,
    Opcode.Or,
    Opcode.Xor,
    Opcode.Shl,
    Opcode.LShr,
    Opcode.AShr,
}


def combine_address(lhs: SymVal, rhs: SymVal, opcode: Opcode) -> Address | None:
    if opcode == Opcode.Add:
        if lhs.address is not None and rhs.concrete is not None:
            return lhs.address.add(sign_extend(rhs.concrete, rhs.width))
        if rhs.address is not None and lhs.concrete is not None:
            return rhs.address.add(sign_extend(lhs.concrete, lhs.width))
    if opcode == Opcode.Sub and lhs.address is not None and rhs.concrete is not None:
        return lhs.address.add(-sign_extend(rhs.concrete, rhs.width))
    return None


def combine_values(lhs: SymVal, rhs: SymVal, opcode: Opcode, width: int | None) -> SymVal:
    if opcode == Opcode.Xor:
        simplified = combine_xor(lhs, rhs, width)
        if simplified is not None:
            return simplified
    concrete = None
    if lhs.concrete is not None and rhs.concrete is not None:
        concrete = eval_binary(opcode, lhs.concrete, rhs.concrete, width)
    address = combine_address(lhs, rhs, opcode) if width == 64 else None
    xor_address = address if address is not None else None
    return SymVal(
        f"({lhs.text} {opcode_symbol(opcode)} {rhs.text})",
        concrete,
        width,
        address,
        (*lhs.unknowns, *rhs.unknowns),
        lhs.deps | rhs.deps,
        xor_address=xor_address,
    )


def combine_xor(lhs: SymVal, rhs: SymVal, width: int | None) -> SymVal | None:
    if width is None:
        return None
    lhs_symbols, lhs_address, lhs_const = xor_components(lhs)
    rhs_symbols, rhs_address, rhs_const = xor_components(rhs)
    symbols = lhs_symbols.symmetric_difference(rhs_symbols)
    if lhs_address is None:
        address = rhs_address
    elif rhs_address is None:
        address = lhs_address
    elif lhs_address == rhs_address:
        address = None
    else:
        symbols = symbols.symmetric_difference(
            {lhs_address.text(), rhs_address.text()}
        )
        address = None
    const = mask_value(lhs_const ^ rhs_const, width)
    concrete = const if address is None and not symbols else None
    value_address = address if address is not None and not symbols and const == 0 else None
    parts = sorted(symbols)
    if address is not None:
        parts.insert(0, address.text())
    if const:
        parts.append(format_int(const))
    if not parts:
        if has_provenance_marker(lhs.text) or has_provenance_marker(rhs.text):
            text = f"({lhs.text} ^ {rhs.text})"
        else:
            text = format_int(concrete or 0)
    else:
        text = " ^ ".join(parts)
    return SymVal(
        text,
        concrete,
        width,
        value_address,
        (*lhs.unknowns, *rhs.unknowns),
        lhs.deps | rhs.deps,
        frozenset(symbols),
        address,
        const,
    )


def has_provenance_marker(text: str) -> bool:
    return "/*" in text or "@0x" in text or "{addr=" in text


def xor_components(value: SymVal) -> tuple[frozenset[str], Address | None, int]:
    symbols = value.xor_symbols
    address = value.xor_address or value.address
    const = mask_value(value.xor_const, value.width)
    if not symbols and address is None and value.concrete is not None:
        const = mask_value(value.concrete, value.width)
    if not symbols and address is None and value.concrete is None:
        symbols = frozenset({value.text})
    return symbols, address, const


def eval_binary(opcode: Opcode, lhs: int, rhs: int, width: int | None) -> int:
    shift = rhs if width is None else rhs % width
    if opcode == Opcode.Add:
        value = lhs + rhs
    elif opcode == Opcode.Sub:
        value = lhs - rhs
    elif opcode == Opcode.Mul:
        value = lhs * rhs
    elif opcode == Opcode.UDiv:
        value = 0 if rhs == 0 else lhs // rhs
    elif opcode == Opcode.SDiv:
        value = 0 if rhs == 0 else int(sign_extend(lhs, width) / sign_extend(rhs, width))
    elif opcode == Opcode.URem:
        value = 0 if rhs == 0 else lhs % rhs
    elif opcode == Opcode.SRem:
        value = 0 if rhs == 0 else sign_extend(lhs, width) % sign_extend(rhs, width)
    elif opcode == Opcode.And:
        value = lhs & rhs
    elif opcode == Opcode.Or:
        value = lhs | rhs
    elif opcode == Opcode.Xor:
        value = lhs ^ rhs
    elif opcode == Opcode.Shl:
        value = lhs << shift
    elif opcode == Opcode.LShr:
        value = lhs >> shift
    elif opcode == Opcode.AShr:
        value = sign_extend(lhs, width) >> shift
    else:
        value = 0
    return mask_value(value, width)


def opcode_symbol(opcode: Opcode) -> str:
    return {
        Opcode.Add: "+",
        Opcode.Sub: "-",
        Opcode.Mul: "*",
        Opcode.UDiv: "/u",
        Opcode.SDiv: "/s",
        Opcode.URem: "%u",
        Opcode.SRem: "%s",
        Opcode.And: "&",
        Opcode.Or: "|",
        Opcode.Xor: "^",
        Opcode.Shl: "<<",
        Opcode.LShr: ">>>",
        Opcode.AShr: ">>",
    }.get(opcode, str(opcode.value))


def eval_icmp(predicate: IntPredicate, lhs: int, rhs: int, width: int | None) -> bool:
    name = predicate.name
    if name == "EQ":
        return lhs == rhs
    if name == "NE":
        return lhs != rhs
    if name == "ULT":
        return lhs < rhs
    if name == "ULE":
        return lhs <= rhs
    if name == "UGT":
        return lhs > rhs
    if name == "UGE":
        return lhs >= rhs
    lhs_s = sign_extend(lhs, width)
    rhs_s = sign_extend(rhs, width)
    if name == "SLT":
        return lhs_s < rhs_s
    if name == "SLE":
        return lhs_s <= rhs_s
    if name == "SGT":
        return lhs_s > rhs_s
    if name == "SGE":
        return lhs_s >= rhs_s
    return False


def block_address(block: BasicBlock) -> int | None:
    name = block.name
    if name.startswith("insn_"):
        return int(name.removeprefix("insn_"), 16)
    return None


def render_result(result: ConcolicResult) -> str:
    concrete = None if result.boundary_value is None else result.boundary_value.concrete
    expression = "none" if result.boundary_value is None else expression_with_deps(result.boundary_value)
    unknowns: tuple[str, ...] = () if result.boundary_value is None else result.boundary_value.unknowns
    lines = [
        "# LLVM concolic VM-entry report",
        "",
        f"- start: `{result.start:#x}`",
        f"- stop: `{result.stop:#x}`",
        f"- instruction: `{result.instruction}`",
        f"- steps: `{result.steps}`",
        f"- boundary: `{result.boundary_call}`",
        f"- concrete: `{'unknown' if concrete is None else hex(concrete)}`",
        f"- expression: `{expression}`",
    ]
    if unknowns:
        lines.append("- unknowns:")
        for item in sorted(set(unknowns)):
            lines.append(f"  - `{item}`")

    lines.extend(["", "## Seeds involved in control-boundary expression", ""])
    involved = involved_control_seeds(result)
    if involved:
        for seed in involved:
            lines.append(
                f"- `{seed.kind}` at `{seed.insn_addr:#x}` value `{mask_value(seed.value, 64):#x}`: {seed.detail}"
            )
    else:
        lines.append("- none")

    lines.extend(["", "## Seed candidates", ""])
    if result.seeds:
        for seed in result.seeds:
            lines.append(
                f"- `{seed.kind}` at `{seed.insn_addr:#x}` value `{mask_value(seed.value, 64):#x}`: {seed.detail}"
            )
    else:
        lines.append("- none")

    lines.extend(["", "## Trace prefix", ""])
    lines.extend(f"- `{item}`" for item in result.trace)
    return "\n".join(lines) + "\n"


def expression_with_deps(value: SymVal) -> str:
    missing = sorted(dep for dep in value.deps if dep not in value.text)
    if not missing:
        return value.text
    return f"{value.text} {{deps={', '.join(missing)}}}"


def involved_control_seeds(result: ConcolicResult) -> list[Seed]:
    texts = [] if result.boundary_value is None else [result.boundary_value.text]
    deps = frozenset() if result.boundary_value is None else result.boundary_value.deps
    involved: list[Seed] = []
    seen: set[tuple[str, int, int, str, int | None]] = set()
    changed = True
    while changed:
        changed = False
        for seed in result.seeds:
            if seed.kind not in CONTROL_SEED_KINDS:
                continue
            key = (seed.kind, seed.insn_addr, mask_value(seed.value, 64), seed.detail, seed.source_addr)
            if key in seen:
                continue
            marker = seed_marker(seed)
            if marker not in deps and not any(marker in text for text in texts):
                continue
            seen.add(key)
            involved.append(seed)
            texts.append(seed.detail)
            deps = deps | frozenset(extract_seed_markers(seed.detail))
            changed = True
    return involved


def extract_seed_markers(text: str) -> set[str]:
    markers: set[str] = set()
    for kind in CONTROL_SEED_KINDS:
        start = 0
        needle = f"{kind}@"
        while True:
            index = text.find(needle, start)
            if index < 0:
                break
            end = index + len(needle)
            while end < len(text) and (text[end].isalnum() or text[end] in "xabcdefABCDEF:"):
                end += 1
            markers.add(text[index:end])
            start = end
    return markers


def run(cfg: ConcolicConfig) -> ConcolicResult:
    container = PEContainer(str(cfg.binary))
    executor = LLVMConcolicExecutor(container, cfg)
    result = executor.run()
    print(render_result(result))
    print(f"wrote {cfg.out_dir}")
    return result


def main() -> None:
    parser = argparse.ArgumentParser(
        description="LLVM-IR concolic VM-entry executor with constant provenance."
    )
    parser.add_argument("--binary", default="tests/binaryshield.exe")
    parser.add_argument("--rip", required=True, type=parse_int)
    parser.add_argument("--out-dir", type=Path, default=Path("devirt-output/vmentry-concolic"))
    parser.add_argument("--follow-call", action="append", default=[], type=parse_int)
    parser.add_argument("--reg", action="append", default=[])
    parser.add_argument("--max-steps", type=int, default=200_000)
    parser.add_argument("--trace-limit", type=int, default=400)
    parser.add_argument(
        "--zero-unknown-abs",
        action="store_true",
        help="Treat concrete non-image memory without prior writes as zero-initialized.",
    )
    args = parser.parse_args()

    cfg = ConcolicConfig(
        binary=Path(args.binary),
        rip=args.rip,
        out_dir=args.out_dir,
        follow_calls=parse_int_set(args.follow_call),
        concrete_regs=dict(parse_assignment(item) for item in args.reg),
        max_steps=args.max_steps,
        trace_limit=args.trace_limit,
        zero_unknown_abs=args.zero_unknown_abs,
    )
    run(cfg)


if __name__ == "__main__":
    main()
