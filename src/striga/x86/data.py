from capstone import CS_OP_REG

from ..semantics import FLAGS, Semantics, semantic


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
    dst = sem.op_read(0)
    width = dst.type.int_width
    if width not in {32, 64}:
        raise NotImplementedError(f"bswap width {width}")
    result = dst.type.constant(0)
    for i in range(width // 8):
        byte = sem.ir.and_(
            sem.ir.lshr(dst, dst.type.constant(i * 8)),
            dst.type.constant(0xFF),
        )
        shift = width - 8 - i * 8
        if shift:
            byte = sem.ir.shl(byte, dst.type.constant(shift))
        result = sem.ir.or_(result, byte)
    sem.op_write(0, result)


@semantic
def xchg(sem: Semantics):
    src = sem.op_read(1)
    dst = sem.op_read(0)
    sem.op_write(0, src)
    sem.op_write(1, dst)
