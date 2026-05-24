from __future__ import annotations

from typing import Protocol

from llvm import IntPredicate, Opcode


class MemoryBacking(Protocol):
    @property
    def image_base(self) -> int: ...

    @property
    def image_size(self) -> int: ...

    def in_range(self, va: int) -> bool: ...

    def get_data(self, va: int, size: int) -> bytes: ...


def mask_value(value: int, width: int | None) -> int:
    if width is None:
        return value
    if width <= 0:
        return 0
    return value & ((1 << width) - 1)


def sign_extend(value: int, from_width: int | None) -> int:
    if from_width is None or from_width <= 0:
        return value
    value = mask_value(value, from_width)
    sign_bit = 1 << (from_width - 1)
    return value - (1 << from_width) if value & sign_bit else value


def sext_value(value: int, from_width: int | None, to_width: int | None) -> int:
    return mask_value(sign_extend(value, from_width), to_width)


def _trunc_div(lhs: int, rhs: int) -> int:
    if rhs == 0:
        return 0
    sign = -1 if (lhs < 0) ^ (rhs < 0) else 1
    return sign * (abs(lhs) // abs(rhs))


def eval_binary(opcode: Opcode, lhs: int, rhs: int, width: int | None) -> int:
    shift = rhs if width is None or width <= 0 else rhs % width
    if opcode == Opcode.Add:
        value = lhs + rhs
    elif opcode == Opcode.Sub:
        value = lhs - rhs
    elif opcode == Opcode.Mul:
        value = lhs * rhs
    elif opcode == Opcode.UDiv:
        value = 0 if rhs == 0 else lhs // rhs
    elif opcode == Opcode.SDiv:
        value = _trunc_div(sign_extend(lhs, width), sign_extend(rhs, width))
    elif opcode == Opcode.URem:
        value = 0 if rhs == 0 else lhs % rhs
    elif opcode == Opcode.SRem:
        lhs_s = sign_extend(lhs, width)
        rhs_s = sign_extend(rhs, width)
        value = 0 if rhs_s == 0 else lhs_s - _trunc_div(lhs_s, rhs_s) * rhs_s
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


def eval_funnel_shift_value(
    high: int, low: int, amount: int, width: int | None, *, left: bool
) -> int:
    if width is None or width <= 0:
        return 0
    shift = amount % width
    mask = (1 << width) - 1
    if shift == 0:
        return high & mask
    if left:
        return ((high << shift) | (low >> (width - shift))) & mask
    return ((high >> shift) | (low << (width - shift))) & mask


def bytes_for_width(width: int) -> int:
    if width <= 0 or width % 8:
        raise ValueError(f"memory width must be a positive byte multiple, got {width}")
    return width // 8


def data_from_backing(backing: MemoryBacking) -> tuple[bytearray, int]:
    return bytearray(
        backing.get_data(backing.image_base, backing.image_size)
    ), backing.image_base
