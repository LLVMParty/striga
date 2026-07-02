from capstone import CS_OP_REG, CS_OP_MEM
from llvm import lookup_intrinsic_id, IntPredicate
from ..semantics import FLAGS, Semantics, Successor, semantic, _semantics


@semantic
def push(sem: Semantics):
    sem.push(sem.op_read(0))


@semantic
def pop(sem: Semantics):
    dst_ty = sem.types.int_n(sem.insn.operands[0].size * 8)
    sem.op_write(0, sem.pop(dst_ty))


@semantic
def pushfq(sem: Semantics):
    sem.push(sem.rflags_value())


@semantic
def popfq(sem: Semantics):
    value = sem.pop(sem.i64)
    value = sem.resize_int(value, sem.i64)
    for name, bit in FLAGS.items():
        flag = sem.ir.trunc(sem.ir.lshr(value, sem.const64(bit)), sem.i1)
        sem.flag_write(name, flag)


@semantic
def mov(sem: Semantics):
    value = sem.op_read(1)
    sem.op_write(0, value)


@semantic
def movabs(sem: Semantics):
    mov(sem)


@semantic
def movaps(sem: Semantics):
    mov(sem)


@semantic
def movups(sem: Semantics):
    mov(sem)


@semantic
def movdqa(sem: Semantics):
    mov(sem)


@semantic
def movzx(sem: Semantics):
    src = sem.op_read(1)
    dst_ty = sem.types.int_n(sem.insn.operands[0].size * 8)
    sem.op_write(0, sem.resize_int(src, dst_ty))


@semantic
def movsx(sem: Semantics):
    src = sem.op_read(1)
    dst_ty = sem.types.int_n(sem.insn.operands[0].size * 8)
    sem.op_write(0, sem.resize_int(src, dst_ty, sign_extend=True))


@semantic
def movsxd(sem: Semantics):
    movsx(sem)


@semantic
def lea(sem: Semantics):
    src = sem.op_mem(sem.insn.operands[1])
    dst_ty = sem.types.int_n(sem.insn.operands[0].size * 8)
    sem.op_write(0, sem.resize_int(src, dst_ty))


def operand_reg_name(sem: Semantics, index: int) -> str | None:
    op = sem.insn.operands[index]
    if op.type != CS_OP_REG:
        return None
    return sem.reg_name(op.reg)


@semantic
def movq(sem: Semantics):
    dst_name = operand_reg_name(sem, 0)
    dst_is_xmm = dst_name is not None and dst_name.startswith("xmm")
    src = sem.op_read(1)

    if dst_is_xmm:
        if src.type.int_width > 64:
            low_qword = sem.ir.trunc(src, sem.i64)
        else:
            low_qword = sem.resize_int(src, sem.i64)
        sem.op_write(0, sem.ir.zext(low_qword, sem.i128))
        return

    dst_ty = sem.types.int_n(sem.insn.operands[0].size * 8)
    sem.op_write(0, sem.resize_int(src, dst_ty))


@semantic
def movlhps(sem: Semantics):
    dst = sem.op_read(0)
    src = sem.op_read(1)
    low_mask = sem.ir.zext(sem.const64(-1), sem.i128)
    low = sem.ir.and_(dst, low_mask)
    high = sem.ir.shl(sem.ir.and_(src, low_mask), sem.i128.constant(64))
    sem.op_write(0, sem.ir.or_(low, high))


@semantic
def cbw(sem: Semantics):
    sem.reg_write("ax", sem.ir.sext(sem.reg_read("al"), sem.i16))


@semantic
def cwde(sem: Semantics):
    sem.reg_write("eax", sem.ir.sext(sem.reg_read("ax"), sem.i32))


@semantic
def cdqe(sem: Semantics):
    sem.reg_write("rax", sem.ir.sext(sem.reg_read("eax"), sem.i64))


@semantic
def cwd(sem: Semantics):
    ax = sem.reg_read("ax")
    sem.reg_write("dx", sem.ir.ashr(ax, sem.i16.constant(15)))


@semantic
def cdq(sem: Semantics):
    eax = sem.reg_read("eax")
    sem.reg_write("edx", sem.ir.ashr(eax, sem.i32.constant(31)))


@semantic
def cqo(sem: Semantics):
    rax = sem.reg_read("rax")
    sem.reg_write("rdx", sem.ir.ashr(rax, sem.const64(63)))


@semantic
def bswap(sem: Semantics):
    op = sem.insn.operands[0]

    if op.size == 2:
        full, _, _ = sem.subregs[sem.reg_name(op.reg)]
        value = sem.ir.trunc(sem.reg_read(full), sem.i32)
    else:
        value = sem.op_read(0)

    intrinsic = sem.module.get_intrinsic_declaration(lookup_intrinsic_id("llvm.bswap"), [value.type])
    result = sem.ir.call(intrinsic, [value])
    sem.op_write(0, sem.resize_int(result, sem.i16) if op.size == 2 else result)

@semantic
def xchg(sem: Semantics):
    src = sem.op_read(1)
    dst = sem.op_read(0)
    sem.op_write(0, src)
    sem.op_write(1, dst)


def _movs_step(sem: Semantics):
    size = sem.insn.operands[0].size
    sem.op_write(0, sem.op_read(1))
    df = sem.flag_read("df")
    delta = sem.ir.select(
        df, sem.const64(-size, sign_extend=True), sem.const64(size)
    )
    sem.reg_write("rsi", sem.ir.add(sem.reg_read("rsi"), delta))
    sem.reg_write("rdi", sem.ir.add(sem.reg_read("rdi"), delta))


@semantic
def movsb(sem: Semantics):
    _movs_step(sem)


@semantic
def movsw(sem: Semantics):
    _movs_step(sem)


@semantic
def movsq(sem: Semantics):
    _movs_step(sem)


@semantic
def movsd(sem: Semantics):
    if all(op.type == CS_OP_MEM for op in sem.insn.operands):
        _movs_step(sem)
    else:
        mov(sem)


def _rep(sem: Semantics, step_fn):
    addr = sem.insn.address
    fallthrough = addr + sem.insn.size
    check = sem.function.append_basic_block(f"rep_check_{addr:#x}")
    body = sem.function.append_basic_block(f"rep_body_{addr:#x}")
    exit_block = sem.get_or_create_block(fallthrough)

    sem.ir.br(check)

    with check.create_builder() as ir:
        sem.ir = ir
        cond = sem.ir.icmp(IntPredicate.NE, sem.reg_read("rcx"), sem.const64(0))
        sem.ir.cond_br(cond, body, exit_block)

    with body.create_builder() as ir:
        sem.ir = ir
        step_fn(sem)
        sem.reg_write("rcx", sem.ir.sub(sem.reg_read("rcx"), sem.const64(1)))
        sem.ir.br(check)

    return [Successor(addr, sem.const64(fallthrough))]


def _rep_movs(sem: Semantics):
    return _rep(sem, _movs_step)


for _m in ("rep movsb", "rep movsw", "rep movsd", "rep movsq"):
    _semantics[_m] = _rep_movs
