from __future__ import annotations

from dataclasses import dataclass

from llvm import IntPredicate, Opcode

from striga.interpreter import MemoryState, RegisterState, ValueDomain

from ._utils import (
    MemoryBacking,
    bytes_for_width,
    eval_binary,
    eval_funnel_shift_value,
    eval_icmp,
    mask_value,
    sext_value,
)


@dataclass(frozen=True)
class Interval:
    lo: int
    hi: int
    width: int

    @staticmethod
    def exact(value: int, width: int) -> Interval:
        value = mask_value(value, width)
        return Interval(value, value, width)

    @staticmethod
    def full(width: int) -> Interval:
        return Interval(0, (1 << width) - 1, width)

    @property
    def is_exact(self) -> bool:
        return self.lo == self.hi

    @property
    def span(self) -> int:
        return self.hi - self.lo + 1 if self.hi >= self.lo else 0

    def with_bounds(self, lo: int, hi: int, width: int) -> Interval:
        mask = (1 << width) - 1
        lo &= mask
        hi &= mask
        if lo <= hi:
            return Interval(lo, hi, width)
        return Interval.full(width)


class IntervalDomain(ValueDomain[Interval]):
    """Unsigned interval abstract domain."""

    def constant(self, value: int, width: int | None) -> Interval:
        return Interval.exact(value, width or 64)

    def unknown(self, text: str, width: int | None) -> Interval:
        del text
        return Interval.full(width or 64)

    def binary(self, op: Opcode, lhs: Interval, rhs: Interval, width: int | None) -> Interval:
        w = width or max(lhs.width, rhs.width, 64)
        if lhs.is_exact and rhs.is_exact:
            return Interval.exact(eval_binary(op, lhs.lo, rhs.lo, w), w)
        if op == Opcode.Add:
            return self._bounded(lhs.lo + rhs.lo, lhs.hi + rhs.hi, w)
        if op == Opcode.Sub:
            return self._bounded(lhs.lo - rhs.hi, lhs.hi - rhs.lo, w)
        if op == Opcode.And and rhs.is_exact:
            return Interval(0, min((1 << w) - 1, rhs.lo), w)
        if op == Opcode.And and lhs.is_exact:
            return Interval(0, min((1 << w) - 1, lhs.lo), w)
        return Interval.full(w)

    def icmp(self, predicate: IntPredicate, lhs: Interval, rhs: Interval, width: int | None) -> Interval:
        del width
        if lhs.is_exact and rhs.is_exact:
            return Interval.exact(int(eval_icmp(predicate, lhs.lo, rhs.lo, lhs.width)), 1)
        name = predicate.name
        if name == "EQ" and (lhs.hi < rhs.lo or rhs.hi < lhs.lo):
            return Interval.exact(0, 1)
        if name == "NE" and (lhs.hi < rhs.lo or rhs.hi < lhs.lo):
            return Interval.exact(1, 1)
        if name == "ULT" and lhs.hi < rhs.lo:
            return Interval.exact(1, 1)
        if name == "ULT" and lhs.lo >= rhs.hi:
            return Interval.exact(0, 1)
        return Interval.full(1)

    def select(self, cond: Interval, true_val: Interval, false_val: Interval, width: int | None) -> Interval:
        if cond.is_exact:
            return true_val if cond.lo else false_val
        w = width or max(true_val.width, false_val.width, 64)
        return self._bounded(min(true_val.lo, false_val.lo), max(true_val.hi, false_val.hi), w)

    def cast(self, op: Opcode, val: Interval, from_width: int | None, to_width: int | None) -> Interval:
        w = to_width or val.width
        if val.is_exact:
            if op == Opcode.SExt:
                return Interval.exact(sext_value(val.lo, from_width, w), w)
            return Interval.exact(mask_value(val.lo, w), w)
        if op == Opcode.Trunc and w < val.width:
            return Interval.full(w)
        return self._bounded(mask_value(val.lo, w), mask_value(val.hi, w), w)

    def funnel_shift(
        self,
        high: Interval,
        low: Interval,
        amount: Interval,
        width: int | None,
        *,
        left: bool,
    ) -> Interval:
        w = width or max(high.width, low.width, amount.width, 64)
        if high.is_exact and low.is_exact and amount.is_exact:
            return Interval.exact(eval_funnel_shift_value(high.lo, low.lo, amount.lo, w, left=left), w)
        return Interval.full(w)

    def concrete_bool(self, val: Interval) -> bool | None:
        if val.is_exact:
            return bool(val.lo)
        if val.hi == 0:
            return False
        if val.lo != 0:
            return True
        return None

    def with_width(self, val: Interval, width: int | None, *, signed: bool = False) -> Interval:
        w = width or val.width
        if val.is_exact:
            if signed:
                return Interval.exact(sext_value(val.lo, val.width, w), w)
            return Interval.exact(mask_value(val.lo, w), w)
        return self._bounded(mask_value(val.lo, w), mask_value(val.hi, w), w)

    @staticmethod
    def _bounded(lo: int, hi: int, width: int) -> Interval:
        mask = (1 << width) - 1
        lo &= mask
        hi &= mask
        if lo <= hi:
            return Interval(lo, hi, width)
        return Interval.full(width)


class IntervalMemory(MemoryState[Interval]):
    """Concrete-address memory that returns full intervals for unknown bytes."""

    def __init__(self, backing: MemoryBacking | None = None):
        self.backing = backing
        self.store: dict[tuple[int, int], Interval] = {}

    def read(self, offset: Interval, width: int, *, insn_addr: int = 0) -> Interval:
        del insn_addr
        bytes_for_width(width)
        if not offset.is_exact:
            return Interval.full(width)
        stored = self.store.get((offset.lo, width))
        if stored is not None:
            return stored
        if self.backing is not None:
            byte_width = width // 8
            if self.backing.in_range(offset.lo) and self.backing.in_range(offset.lo + byte_width - 1):
                data = self.backing.get_data(offset.lo, byte_width)
                return Interval.exact(int.from_bytes(data, "little"), width)
        return Interval.full(width)

    def write(self, offset: Interval, value: Interval, width: int, *, insn_addr: int = 0) -> None:
        del insn_addr
        bytes_for_width(width)
        if offset.is_exact:
            self.store[(offset.lo, width)] = value


class IntervalRegisters(RegisterState[Interval]):
    def __init__(self, reg_sizes: dict[str, int], initial: dict[str, int | Interval] | None = None):
        self._sizes = reg_sizes
        initial = initial or {}
        self._regs: dict[str, Interval] = {}
        for name, size in reg_sizes.items():
            value = initial.get(name, 0)
            self._regs[name] = value if isinstance(value, Interval) else Interval.exact(value, size)

    def read(self, name: str) -> Interval:
        return self._regs[name]

    def write(self, name: str, value: Interval) -> None:
        self._regs[name] = IntervalDomain().with_width(value, self._sizes[name])

    def width(self, name: str) -> int:
        return self._sizes[name]


__all__ = ["Interval", "IntervalDomain", "IntervalMemory", "IntervalRegisters"]
