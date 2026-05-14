from llvm import Linkage, Module, Opcode, Value, global_context

from bfs import lift_bfs
from container import RawContainer

CODE = RawContainer(
    bytes.fromhex("48 01 F7 48 89 F8 C3"),
    0x1000,
)

OPT_PIPELINE = "default<O3>"


def rewrite_ram_geps(module: Module, ram: Value) -> int:
    """Replace GEPs rooted at @RAM with inttoptr(address)."""
    types = module.context.types
    geps = []

    # Save users first: we mutate/delete them below.
    for user in list(ram.users):
        if not user.is_instruction or user.opcode != Opcode.GetElementPtr:
            raise ValueError(f"unexpected @RAM user: {user}")
        geps.append(user)

    for gep in geps:
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

        with gep.parent.create_builder() as ir:
            ir.position_before(gep)
            ptr = ir.inttoptr(address, types.ptr)
        gep.replace_all_uses_with(ptr)
        gep.erase_from_parent()

    if not ram.users:
        ram.delete_global()

    module.verify_or_raise()
    return len(geps)


with global_context().create_module("blog") as module:
    start = 0x1000
    sem = lift_bfs(module, CODE, start, verbose=False)

    # Optimize lifted function for readablity (not strictly necessary)
    sem.function.optimize("instcombine,simplifycfg,early-cse<memssa>,dse,adce")
    print(sem.function)

    # Implement __striga_ret
    sem.ret_handler.linkage = Linkage.Internal
    with sem.ret_handler.create_builder() as ir:
        ir.ret_void()

    # Convenience aliases
    types = module.context.types
    i8 = types.i8
    i64 = types.i64

    # Global RAM array
    ram = module.add_global(types.array(i8, 0), "RAM")

    brightened_ty = types.function(i64, [i64, i64])
    brightened = module.add_function(f"brightened_{hex(start)}", brightened_ty)
    with brightened.create_builder() as ir:
        state = ir.alloca(sem.state_ty, "state")

        def reg_ptr(name: str) -> Value:
            return ir.struct_gep(sem.state_ty, state, sem.reg_indices[name], name)

        # Assign arguments to register state
        ir.store(brightened.get_param(0), reg_ptr("rdi"))
        ir.store(brightened.get_param(1), reg_ptr("rsi"))

        # Set up function stack
        stack = ir.alloca(i8, i64.constant(4096), "stack")
        stack_ptr = ir.gep(i8, stack, [i64.constant(4096 - 8)])
        ir.store(ir.ptrtoint(stack_ptr, i64), reg_ptr("rsp"))

        # Set up return address
        retaddr_store = ir.store(i64.constant(0xDEADBEEF), stack_ptr)
        retaddr_store.inst_alignment = 1

        # Call lifted function
        ir.call(sem.function, [ram, state])

        # Load return value from rax and return it
        ir.ret(ir.load(i64, reg_ptr("rax")))

    module.verify_or_raise()

    # 1. Inline/optimize with @RAM assigned to the lifted memory parameter.
    module.optimize(OPT_PIPELINE)

    # 2. Brighten lifted memory: @RAM + integer address -> inttoptr(address).
    rewrite_ram_geps(module, ram)

    module.optimize(OPT_PIPELINE)

    print(module)
