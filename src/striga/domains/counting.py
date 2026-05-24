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
class Counted:
    value: int
    width: int | None
    ops: dict[str, int]

    @staticmethod
    def const(value: int, width: int | None) -> Counted:
        return Counted(mask_value(value, width), width, {})

    def merge_ops(self, *others: Counted, op_name: str) -> dict[str, int]:
        merged = dict(self.ops)
        for other in others:
            for key, count in other.ops.items():
                merged[key] = merged.get(key, 0) + count
        merged[op_name] = merged.get(op_name, 0) + 1
        return merged


class CountingDomain(ValueDomain[Counted]):
    """Concrete execution with operation counting."""

    def constant(self, value: int, width: int | None) -> Counted:
        return Counted.const(value, width)

    def unknown(self, text: str, width: int | None) -> Counted:
        del text
        return Counted(0, width, {})

    def binary(self, op: Opcode, lhs: Counted, rhs: Counted, width: int | None) -> Counted:
        concrete = eval_binary(op, lhs.value, rhs.value, width)
        return Counted(concrete, width, lhs.merge_ops(rhs, op_name=op.name))

    def icmp(self, predicate: IntPredicate, lhs: Counted, rhs: Counted, width: int | None) -> Counted:
        concrete = int(eval_icmp(predicate, lhs.value, rhs.value, width))
        return Counted(concrete, 1, lhs.merge_ops(rhs, op_name=f"icmp_{predicate.name}"))

    def select(self, cond: Counted, true_val: Counted, false_val: Counted, width: int | None) -> Counted:
        chosen = true_val if cond.value else false_val
        return Counted(
            mask_value(chosen.value, width),
            width,
            cond.merge_ops(true_val, false_val, op_name="select"),
        )

    def cast(self, op: Opcode, val: Counted, from_width: int | None, to_width: int | None) -> Counted:
        if op == Opcode.SExt:
            concrete = sext_value(val.value, from_width, to_width)
        else:
            concrete = mask_value(val.value, to_width)
        ops = dict(val.ops)
        ops[op.name] = ops.get(op.name, 0) + 1
        return Counted(concrete, to_width, ops)

    def funnel_shift(
        self,
        high: Counted,
        low: Counted,
        amount: Counted,
        width: int | None,
        *,
        left: bool,
    ) -> Counted:
        concrete = eval_funnel_shift_value(high.value, low.value, amount.value, width, left=left)
        return Counted(concrete, width, high.merge_ops(low, amount, op_name="funnel_shift"))

    def concrete_bool(self, val: Counted) -> bool | None:
        return bool(val.value)

    def with_width(self, val: Counted, width: int | None, *, signed: bool = False) -> Counted:
        if signed:
            return Counted(sext_value(val.value, val.width, width), width, val.ops)
        return Counted(mask_value(val.value, width), width, val.ops)


class CountingMemory(MemoryState[Counted]):
    """Concrete-address memory for profiling domains."""

    def __init__(self, backing: MemoryBacking | None = None):
        self.backing = backing
        self.store: dict[tuple[int, int], Counted] = {}

    def read(self, offset: Counted, width: int, *, insn_addr: int = 0) -> Counted:
        del insn_addr
        bytes_for_width(width)
        stored = self.store.get((offset.value, width))
        if stored is not None:
            return stored
        if self.backing is not None:
            byte_width = width // 8
            if self.backing.in_range(offset.value) and self.backing.in_range(offset.value + byte_width - 1):
                data = self.backing.get_data(offset.value, byte_width)
                return Counted.const(int.from_bytes(data, "little"), width)
        return Counted.const(0, width)

    def write(self, offset: Counted, value: Counted, width: int, *, insn_addr: int = 0) -> None:
        del insn_addr
        bytes_for_width(width)
        self.store[(offset.value, width)] = Counted(mask_value(value.value, width), width, value.ops)


class CountingRegisters(RegisterState[Counted]):
    def __init__(self, reg_sizes: dict[str, int], initial: dict[str, int | Counted] | None = None):
        self._sizes = reg_sizes
        initial = initial or {}
        self._regs: dict[str, Counted] = {}
        for name, size in reg_sizes.items():
            value = initial.get(name, 0)
            self._regs[name] = value if isinstance(value, Counted) else Counted.const(value, size)

    def read(self, name: str) -> Counted:
        return self._regs[name]

    def write(self, name: str, value: Counted) -> None:
        self._regs[name] = CountingDomain().with_width(value, self._sizes[name])

    def width(self, name: str) -> int:
        return self._sizes[name]


__all__ = ["Counted", "CountingDomain", "CountingMemory", "CountingRegisters"]
