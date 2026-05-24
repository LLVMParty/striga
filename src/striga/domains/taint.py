from __future__ import annotations

from dataclasses import dataclass, field

from llvm import IntPredicate, Opcode

from striga.interpreter import MemoryState, RegisterState, ValueDomain

from ._utils import (
    MemoryBacking,
    bytes_for_width,
    data_from_backing,
    eval_binary,
    eval_funnel_shift_value,
    eval_icmp,
    mask_value,
    sext_value,
)


@dataclass(frozen=True)
class Tainted:
    value: int
    width: int | None
    labels: frozenset[str]


class TaintDomain(ValueDomain[Tainted]):
    """Concrete execution with taint label propagation."""

    def constant(self, value: int, width: int | None) -> Tainted:
        return Tainted(mask_value(value, width), width, frozenset())

    def unknown(self, text: str, width: int | None) -> Tainted:
        return Tainted(0, width, frozenset({text}))

    def binary(
        self, op: Opcode, lhs: Tainted, rhs: Tainted, width: int | None
    ) -> Tainted:
        return Tainted(
            eval_binary(op, lhs.value, rhs.value, width), width, lhs.labels | rhs.labels
        )

    def icmp(
        self, predicate: IntPredicate, lhs: Tainted, rhs: Tainted, width: int | None
    ) -> Tainted:
        return Tainted(
            int(eval_icmp(predicate, lhs.value, rhs.value, width)),
            1,
            lhs.labels | rhs.labels,
        )

    def select(
        self, cond: Tainted, true_val: Tainted, false_val: Tainted, width: int | None
    ) -> Tainted:
        chosen = true_val if cond.value else false_val
        return Tainted(
            mask_value(chosen.value, width),
            width,
            cond.labels | true_val.labels | false_val.labels,
        )

    def cast(
        self, op: Opcode, val: Tainted, from_width: int | None, to_width: int | None
    ) -> Tainted:
        if op == Opcode.SExt:
            return Tainted(
                sext_value(val.value, from_width, to_width), to_width, val.labels
            )
        return Tainted(mask_value(val.value, to_width), to_width, val.labels)

    def funnel_shift(
        self,
        high: Tainted,
        low: Tainted,
        amount: Tainted,
        width: int | None,
        *,
        left: bool,
    ) -> Tainted:
        concrete = eval_funnel_shift_value(
            high.value, low.value, amount.value, width, left=left
        )
        return Tainted(concrete, width, high.labels | low.labels | amount.labels)

    def concrete_bool(self, val: Tainted) -> bool | None:
        return bool(val.value)

    def with_width(
        self, val: Tainted, width: int | None, *, signed: bool = False
    ) -> Tainted:
        if signed:
            return Tainted(sext_value(val.value, val.width, width), width, val.labels)
        return Tainted(mask_value(val.value, width), width, val.labels)


@dataclass
class TaintMemory(MemoryState[Tainted]):
    """Byte-addressed concrete memory with per-byte taint labels."""

    data: bytearray
    base: int = 0
    overlay: dict[int, int] = field(default_factory=dict)
    taint: dict[int, frozenset[str]] = field(default_factory=dict)

    @classmethod
    def from_backing(cls, backing: MemoryBacking) -> TaintMemory:
        data, base = data_from_backing(backing)
        return cls(data, base)

    def read(self, offset: Tainted, width: int, *, insn_addr: int = 0) -> Tainted:
        del insn_addr
        byte_width = bytes_for_width(width)
        value = 0
        labels = offset.labels
        for i in range(byte_width):
            address = offset.value + i
            value |= self._read_byte(address) << (i * 8)
            labels = labels | self.taint.get(address, frozenset())
        return Tainted(mask_value(value, width), width, labels)

    def write(
        self, offset: Tainted, value: Tainted, width: int, *, insn_addr: int = 0
    ) -> None:
        del insn_addr
        byte_width = bytes_for_width(width)
        concrete = mask_value(value.value, width)
        labels = offset.labels | value.labels
        for i in range(byte_width):
            address = offset.value + i
            self._write_byte(address, (concrete >> (i * 8)) & 0xFF)
            self.taint[address] = labels

    def _read_byte(self, address: int) -> int:
        byte = self.overlay.get(address)
        if byte is not None:
            return byte
        index = address - self.base
        if 0 <= index < len(self.data):
            return self.data[index]
        return 0

    def _write_byte(self, address: int, value: int) -> None:
        byte = value & 0xFF
        self.overlay[address] = byte
        index = address - self.base
        if 0 <= index < len(self.data):
            self.data[index] = byte


class TaintRegisters(RegisterState[Tainted]):
    def __init__(
        self, reg_sizes: dict[str, int], initial: dict[str, int | Tainted] | None = None
    ):
        self._sizes = reg_sizes
        initial = initial or {}
        self._regs: dict[str, Tainted] = {}
        for name, size in reg_sizes.items():
            value = initial.get(name, 0)
            if isinstance(value, Tainted):
                self._regs[name] = Tainted(
                    mask_value(value.value, size), size, value.labels
                )
            else:
                self._regs[name] = Tainted(mask_value(value, size), size, frozenset())

    def read(self, name: str) -> Tainted:
        return self._regs[name]

    def write(self, name: str, value: Tainted) -> None:
        self._regs[name] = Tainted(
            mask_value(value.value, self._sizes[name]), self._sizes[name], value.labels
        )

    def width(self, name: str) -> int:
        return self._sizes[name]
