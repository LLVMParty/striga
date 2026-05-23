from llvm import Linkage, Module, Opcode, Value, global_context

from bfs import lift_bfs
from container import Container, PEContainer

OPT_PIPELINE = "default<O1>"


def rewrite_ram_geps(module: Module, ram: Value):
    """Replace GEPs rooted at @RAM with inttoptr(address)."""
    types = module.context.types

    for gep in ram.users:
        if not gep.is_instruction or gep.opcode != Opcode.GetElementPtr:
            raise ValueError(f"unexpected @RAM user: {gep}")

        if gep.get_operand(0) != ram:
            raise ValueError(f"unexpected @RAM GEP base: {gep}")

        if gep.num_operands == 2:
            if gep.gep_source_element_type != types.i8:
                raise ValueError(f"expected i8 ptradd-style @RAM GEP: {gep}")
            address = gep.get_operand(1)
        elif gep.num_operands == 3:
            zero = gep.get_operand(1)
            if not zero.is_constant_int or zero.const_zext_value != 0:
                raise ValueError(f"expected zero first @RAM GEP index: {gep}")
            address = gep.get_operand(2)
        else:
            raise ValueError(f"unexpected @RAM GEP shape: {gep}")

        with gep.create_builder() as ir:
            ptr = ir.inttoptr(address, types.ptr)
        gep.replace_all_uses_with(ptr)
        gep.erase_from_parent()

    if not ram.users:
        ram.delete_global()

    module.verify_or_raise()


def define_ret_stub(module: Module):
    """Make the modeled return hook removable for this demo wrapper."""
    ret_handler = module.get_function("__striga_ret")
    if ret_handler is not None and ret_handler.is_declaration:
        ret_handler.linkage = Linkage.Internal
        entry = ret_handler.append_basic_block("entry")
        with entry.create_builder() as ir:
            ir.ret_void()


def lift_brightened(container: Container, entry: int, args: list[str]):
    with global_context().create_module("blog") as module:
        sem = lift_bfs(module, container, entry, verbose=True)

        # Convenience aliases
        types = module.context.types
        i8 = types.i8
        i64 = types.i64

        # Global RAM array
        ram = module.add_global(types.array(i8, 0), "RAM")
        ram.alignment = 1

        # TODO: support different register sizes
        brightened_ty = types.function(i64, [i64 for _ in args])
        brightened = module.add_function(f"brightened_{hex(entry)}", brightened_ty)
        with brightened.create_builder() as ir:
            state = ir.alloca(sem.state_ty, "state")

            def reg_ptr(name: str) -> Value:
                return ir.struct_gep(sem.state_ty, state, sem.reg_indices[name], name)

            # Assign arguments to register state
            for i, name in enumerate(args):
                ir.store(brightened.get_param(i), reg_ptr(name))

            # Set up gsbase
            teb = ir.alloca(i8, i64.constant(4096), "teb")
            ir.store(ir.ptrtoint(teb, i64), reg_ptr("gsbase"))
            peb_ptr = ir.gep(i8, teb, [i64.constant(0x60)], "peb_ptr")
            peb = ir.alloca(i8, i64.constant(4096), "peb")
            ir.store(peb, peb_ptr)
            imagebase_ptr = ir.gep(i8, peb, [i64.constant(0x10)], "imagebase_ptr")
            ir.store(i64.constant(container.image_base), imagebase_ptr)

            # Set up function stack
            stack = ir.alloca(i8, i64.constant(4096), "stack")
            stack_ptr = ir.gep(i8, stack, [i64.constant(4096 - 8)])
            ir.store(ir.ptrtoint(stack_ptr, i64), reg_ptr("rsp"))

            # Set up return address
            retaddr_store = ir.store(i64.constant(0xDEADBEEF), stack_ptr)
            retaddr_store.inst_alignment = 1

            # Call lifted function
            ir.call(sem.function, [state, ram])

            # Load return value from rax and return it
            ir.ret(ir.load(i64, reg_ptr("rax")))

        module.verify_or_raise()

        print(module)

        # 1. Inline/optimize with @RAM assigned to the lifted memory parameter.
        module.optimize(OPT_PIPELINE)

        print(module)

        # 2. Brighten lifted memory: @RAM + integer address -> inttoptr(address).
        rewrite_ram_geps(module, ram)

        # 3. Now that RAM accesses have been brightened, discard the modeled ret
        #    hook for this demo and let LLVM clean up the remaining wrapper noise.
        #    Undefined flag helpers are already declared memory(none) by Semantics,
        #    so their dead uses fold away without local stub definitions.
        define_ret_stub(module)
        module.verify_or_raise()
        module.optimize(OPT_PIPELINE)

        print(brightened)


pe = PEContainer("tests/binaryshield.exe")

lift_brightened(
    pe,
    0x140017A41,
    [
        "rax",
        "rbx",
        "rcx",
        "rdx",
        "rbp",
        "rsp",
        "rsi",
        "rdi",
        "r8",
        "r9",
        "r10",
        "r11",
        "r12",
        "r13",
        "r14",
        "r15",
    ],
)
