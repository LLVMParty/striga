from typing import TypeAlias, Callable

from ..semantics import semantic, Semantics
from llvm import Value, Opcode, IntPredicate

ArithFlagWriter: TypeAlias = Callable[[Semantics, Value, Value, Value], None]


def aux_carry(sem: Semantics, lhs: Value, rhs: Value, result: Value) -> Value:
    nibble_carry = sem.ir.and_(
        sem.ir.xor(sem.ir.xor(lhs, rhs), result),
        lhs.type.constant(0x10),
    )
    return sem.ir.icmp(IntPredicate.NE, nibble_carry, lhs.type.constant(0))


def add_overflow(sem: Semantics, lhs: Value, rhs: Value, result: Value) -> Value:
    sign_mask = lhs.type.constant(-(1 << (lhs.type.int_width - 1)))
    overflow_bits = sem.ir.and_(
        sem.ir.xor(lhs, result),
        sem.ir.xor(rhs, result),
    )
    return sem.ir.icmp(
        IntPredicate.NE,
        sem.ir.and_(overflow_bits, sign_mask),
        lhs.type.constant(0),
    )


def sub_overflow(sem: Semantics, lhs: Value, rhs: Value, result: Value) -> Value:
    sign_mask = lhs.type.constant(-(1 << (lhs.type.int_width - 1)))
    overflow_bits = sem.ir.and_(
        sem.ir.xor(lhs, rhs),
        sem.ir.xor(lhs, result),
    )
    return sem.ir.icmp(
        IntPredicate.NE,
        sem.ir.and_(overflow_bits, sign_mask),
        lhs.type.constant(0),
    )


def write_common_arith_flags(sem: Semantics, lhs: Value, rhs: Value, result: Value):
    sem.flag_write("pf", sem.result_parity_even(result))
    sem.flag_write("af", aux_carry(sem, lhs, rhs, result))
    sem.flag_write("zf", sem.result_is_zero(result))
    sem.flag_write("sf", sem.result_sign_bit(result))


def write_add_flags(
    sem: Semantics,
    lhs: Value,
    rhs: Value,
    result: Value,
    *,
    write_cf: bool = True,
):
    if write_cf:
        sem.flag_write("cf", sem.ir.icmp(IntPredicate.ULT, result, lhs))
    write_common_arith_flags(sem, lhs, rhs, result)
    sem.flag_write("of", add_overflow(sem, lhs, rhs, result))


def write_sub_flags(
    sem: Semantics,
    lhs: Value,
    rhs: Value,
    result: Value,
    *,
    write_cf: bool = True,
):
    if write_cf:
        sem.flag_write("cf", sem.ir.icmp(IntPredicate.ULT, lhs, rhs))
    write_common_arith_flags(sem, lhs, rhs, result)
    sem.flag_write("of", sub_overflow(sem, lhs, rhs, result))


def arith_binop(sem: Semantics, opcode: Opcode, write_flags: ArithFlagWriter):
    dst = sem.op_read(0)
    src = sem.resize_int(sem.op_read(1), dst.type)
    result = sem.ir.binop(opcode, dst, src)
    sem.op_write(0, result)
    write_flags(sem, dst, src, result)


@semantic
def add(sem: Semantics):
    arith_binop(sem, Opcode.Add, write_add_flags)


@semantic
def sub(sem: Semantics):
    arith_binop(sem, Opcode.Sub, write_sub_flags)


@semantic
def cmp(sem: Semantics):
    dst = sem.op_read(0)
    src = sem.resize_int(sem.op_read(1), dst.type)
    result = sem.ir.sub(dst, src)
    write_sub_flags(sem, dst, src, result)


@semantic
def inc(sem: Semantics):
    dst = sem.op_read(0)
    src = dst.type.constant(1)
    result = sem.ir.add(dst, src)
    sem.op_write(0, result)
    write_add_flags(sem, dst, src, result, write_cf=False)


@semantic
def dec(sem: Semantics):
    dst = sem.op_read(0)
    src = dst.type.constant(1)
    result = sem.ir.sub(dst, src)
    sem.op_write(0, result)
    write_sub_flags(sem, dst, src, result, write_cf=False)


@semantic
def neg(sem: Semantics):
    dst = sem.op_read(0)
    zero = dst.type.constant(0)
    result = sem.ir.sub(zero, dst)
    sem.op_write(0, result)
    sem.flag_write("cf", sem.ir.icmp(IntPredicate.NE, dst, zero))
    write_common_arith_flags(sem, zero, dst, result)
    sem.flag_write("of", sub_overflow(sem, zero, dst, result))


@semantic
def adc(sem: Semantics):
    dst = sem.op_read(0)
    src = sem.resize_int(sem.op_read(1), dst.type)
    carry = sem.ir.zext(sem.flag_read("cf"), dst.type)
    src_plus_carry = sem.ir.add(src, carry)
    result = sem.ir.add(dst, src_plus_carry)
    sem.op_write(0, result)

    wide_ty = sem.types.int_n(dst.type.int_width + 1)
    wide_sum = sem.ir.add(
        sem.ir.add(sem.ir.zext(dst, wide_ty), sem.ir.zext(src, wide_ty)),
        sem.ir.zext(carry, wide_ty),
    )
    cf = sem.ir.trunc(sem.ir.lshr(wide_sum, wide_ty.constant(dst.type.int_width)), sem.i1)
    sem.flag_write("cf", cf)
    write_common_arith_flags(sem, dst, src_plus_carry, result)
    sem.flag_write("of", add_overflow(sem, dst, src_plus_carry, result))


@semantic
def sbb(sem: Semantics):
    dst = sem.op_read(0)
    src = sem.resize_int(sem.op_read(1), dst.type)
    cf_in = sem.flag_read("cf")
    borrow = sem.ir.zext(cf_in, dst.type)
    src_plus_borrow = sem.ir.add(src, borrow)
    result = sem.ir.sub(dst, src_plus_borrow)
    sem.op_write(0, result)

    cf = sem.ir.or_(
        sem.ir.icmp(IntPredicate.ULT, dst, src),
        sem.ir.and_(sem.ir.icmp(IntPredicate.EQ, dst, src), cf_in),
    )
    sem.flag_write("cf", cf)
    write_common_arith_flags(sem, dst, src, result)
    sem.flag_write("of", sub_overflow(sem, dst, src, result))


@semantic
def cmpxchg(sem: Semantics):
    dst = sem.op_read(0)
    src = sem.resize_int(sem.op_read(1), dst.type)
    acc_name = {8: "al", 16: "ax", 32: "eax", 64: "rax"}[dst.type.int_width]
    acc = sem.reg_read(acc_name)
    result = sem.ir.sub(acc, dst)
    equal = sem.result_is_zero(result)

    write_sub_flags(sem, acc, dst, result)
    sem.reg_write(acc_name, sem.ir.select(equal, acc, dst))
    sem.op_write(0, sem.ir.select(equal, src, dst))


def write_undef_arith_flags(sem: Semantics):
    sem.flag_write_undef("cf")
    sem.flag_write_undef("of")
    sem.flag_write_undef("sf")
    sem.flag_write_undef("zf")
    sem.flag_write_undef("af")
    sem.flag_write_undef("pf")


def write_mul_flags(sem: Semantics, overflow: Value):
    sem.flag_write("cf", overflow)
    sem.flag_write("of", overflow)
    sem.flag_write_undef("sf")
    sem.flag_write_undef("zf")
    sem.flag_write_undef("af")
    sem.flag_write_undef("pf")


def signed_wide_mul(sem: Semantics, lhs: Value, rhs: Value) -> tuple[Value, Value]:
    wide_ty = sem.types.int_n(lhs.type.int_width * 2)
    wide_lhs = sem.resize_int(lhs, wide_ty, sign_extend=True)
    wide_rhs = sem.resize_int(rhs, wide_ty, sign_extend=True)
    product = sem.ir.mul(wide_lhs, wide_rhs)
    truncated = sem.ir.trunc(product, lhs.type)
    overflow = sem.ir.icmp(
        IntPredicate.NE,
        sem.ir.sext(truncated, wide_ty),
        product,
    )
    return product, overflow


def unsigned_wide_mul(sem: Semantics, lhs: Value, rhs: Value) -> tuple[Value, Value]:
    wide_ty = sem.types.int_n(lhs.type.int_width * 2)
    wide_lhs = sem.resize_int(lhs, wide_ty)
    wide_rhs = sem.resize_int(rhs, wide_ty)
    product = sem.ir.mul(wide_lhs, wide_rhs)
    truncated = sem.ir.trunc(product, lhs.type)
    overflow = sem.ir.icmp(
        IntPredicate.NE,
        sem.ir.zext(truncated, wide_ty),
        product,
    )
    return product, overflow


@semantic
def imul(sem: Semantics):
    if len(sem.insn.operands) == 1:
        src = sem.op_read(0)
        width = src.type.int_width
        match width:
            case 8:
                lhs = sem.reg_read("al")
                product, overflow = signed_wide_mul(sem, lhs, src)
                sem.reg_write("ax", product)
            case 16:
                lhs = sem.reg_read("ax")
                product, overflow = signed_wide_mul(sem, lhs, src)
                sem.reg_write("ax", sem.ir.trunc(product, sem.i16))
                sem.reg_write(
                    "dx",
                    sem.ir.trunc(sem.ir.lshr(product, sem.const_n(16, 32)), sem.i16),
                )
            case 32:
                lhs = sem.reg_read("eax")
                product, overflow = signed_wide_mul(sem, lhs, src)
                sem.reg_write("eax", sem.ir.trunc(product, sem.i32))
                sem.reg_write(
                    "edx",
                    sem.ir.trunc(sem.ir.lshr(product, sem.const_n(32, 64)), sem.i32),
                )
            case 64:
                lhs = sem.reg_read("rax")
                product, overflow = signed_wide_mul(sem, lhs, src)
                sem.reg_write("rax", sem.ir.trunc(product, sem.i64))
                sem.reg_write(
                    "rdx",
                    sem.ir.trunc(sem.ir.lshr(product, sem.const_n(64, 128)), sem.i64),
                )
            case _:
                raise NotImplementedError(f"imul width {width}")
        write_mul_flags(sem, overflow)
        return

    if len(sem.insn.operands) == 2:
        lhs = sem.op_read(0)
        rhs = sem.resize_int(sem.op_read(1), lhs.type, sign_extend=True)
    elif len(sem.insn.operands) == 3:
        lhs = sem.resize_int(
            sem.op_read(1), sem.types.int_n(sem.insn.operands[0].size * 8)
        )
        rhs = sem.resize_int(sem.op_read(2), lhs.type, sign_extend=True)
    else:
        raise NotImplementedError("imul operand count")

    product, overflow = signed_wide_mul(sem, lhs, rhs)
    sem.op_write(0, sem.ir.trunc(product, lhs.type))
    write_mul_flags(sem, overflow)


@semantic
def mul(sem: Semantics):
    src = sem.op_read(0)
    width = src.type.int_width
    match width:
        case 8:
            lhs = sem.reg_read("al")
            product, overflow = unsigned_wide_mul(sem, lhs, src)
            sem.reg_write("ax", product)
        case 16:
            lhs = sem.reg_read("ax")
            product, overflow = unsigned_wide_mul(sem, lhs, src)
            sem.reg_write("ax", sem.ir.trunc(product, sem.i16))
            sem.reg_write(
                "dx",
                sem.ir.trunc(sem.ir.lshr(product, sem.const_n(16, 32)), sem.i16),
            )
        case 32:
            lhs = sem.reg_read("eax")
            product, overflow = unsigned_wide_mul(sem, lhs, src)
            sem.reg_write("eax", sem.ir.trunc(product, sem.i32))
            sem.reg_write(
                "edx",
                sem.ir.trunc(sem.ir.lshr(product, sem.const_n(32, 64)), sem.i32),
            )
        case 64:
            lhs = sem.reg_read("rax")
            product, overflow = unsigned_wide_mul(sem, lhs, src)
            sem.reg_write("rax", sem.ir.trunc(product, sem.i64))
            sem.reg_write(
                "rdx", sem.ir.trunc(sem.ir.lshr(product, sem.const_n(64, 128)), sem.i64)
            )
        case _:
            raise NotImplementedError(f"mul width {width}")
    write_mul_flags(sem, overflow)


def divmod_wide(
    sem: Semantics, high: Value, low: Value, divisor: Value, *, signed=False
):
    wide_ty = sem.types.int_n(divisor.type.int_width * 2)
    wide_high = sem.resize_int(high, wide_ty)
    wide_low = sem.resize_int(low, wide_ty)
    dividend = sem.ir.or_(
        sem.ir.shl(wide_high, wide_ty.constant(divisor.type.int_width)), wide_low
    )
    wide_divisor = sem.resize_int(divisor, wide_ty, sign_extend=signed)
    if signed:
        return sem.ir.sdiv(dividend, wide_divisor), sem.ir.srem(dividend, wide_divisor)
    return sem.ir.udiv(dividend, wide_divisor), sem.ir.urem(dividend, wide_divisor)


@semantic
def div(sem: Semantics):
    src = sem.op_read(0)
    match src.type.int_width:
        case 8:
            quotient, remainder = divmod_wide(
                sem, sem.reg_read("ah"), sem.reg_read("al"), src
            )
            sem.reg_write("al", sem.ir.trunc(quotient, sem.i8))
            sem.reg_write("ah", sem.ir.trunc(remainder, sem.i8))
        case 16:
            quotient, remainder = divmod_wide(
                sem, sem.reg_read("dx"), sem.reg_read("ax"), src
            )
            sem.reg_write("ax", sem.ir.trunc(quotient, sem.i16))
            sem.reg_write("dx", sem.ir.trunc(remainder, sem.i16))
        case 32:
            quotient, remainder = divmod_wide(
                sem, sem.reg_read("edx"), sem.reg_read("eax"), src
            )
            sem.reg_write("eax", sem.ir.trunc(quotient, sem.i32))
            sem.reg_write("edx", sem.ir.trunc(remainder, sem.i32))
        case 64:
            quotient, remainder = divmod_wide(
                sem, sem.reg_read("rdx"), sem.reg_read("rax"), src
            )
            sem.reg_write("rax", sem.ir.trunc(quotient, sem.i64))
            sem.reg_write("rdx", sem.ir.trunc(remainder, sem.i64))
        case width:
            raise NotImplementedError(f"div width {width}")
    write_undef_arith_flags(sem)


@semantic
def idiv(sem: Semantics):
    src = sem.op_read(0)
    match src.type.int_width:
        case 8:
            quotient, remainder = divmod_wide(
                sem, sem.reg_read("ah"), sem.reg_read("al"), src, signed=True
            )
            sem.reg_write("al", sem.ir.trunc(quotient, sem.i8))
            sem.reg_write("ah", sem.ir.trunc(remainder, sem.i8))
        case 16:
            quotient, remainder = divmod_wide(
                sem, sem.reg_read("dx"), sem.reg_read("ax"), src, signed=True
            )
            sem.reg_write("ax", sem.ir.trunc(quotient, sem.i16))
            sem.reg_write("dx", sem.ir.trunc(remainder, sem.i16))
        case 32:
            quotient, remainder = divmod_wide(
                sem, sem.reg_read("edx"), sem.reg_read("eax"), src, signed=True
            )
            sem.reg_write("eax", sem.ir.trunc(quotient, sem.i32))
            sem.reg_write("edx", sem.ir.trunc(remainder, sem.i32))
        case 64:
            quotient, remainder = divmod_wide(
                sem, sem.reg_read("rdx"), sem.reg_read("rax"), src, signed=True
            )
            sem.reg_write("rax", sem.ir.trunc(quotient, sem.i64))
            sem.reg_write("rdx", sem.ir.trunc(remainder, sem.i64))
        case width:
            raise NotImplementedError(f"idiv width {width}")
    write_undef_arith_flags(sem)
