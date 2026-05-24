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
class ConcreteValue:
    value: int
    width: int | None


class ConcreteDomain(ValueDomain[ConcreteValue]):
    """Masked integer execution with width tracking."""

    def constant(self, value: int, width: int | None) -> ConcreteValue:
        return ConcreteValue(mask_value(value, width), width)

    def unknown(self, text: str, width: int | None) -> ConcreteValue:
        del text
        return ConcreteValue(0, width)

    def binary(
        self, op: Opcode, lhs: ConcreteValue, rhs: ConcreteValue, width: int | None
    ) -> ConcreteValue:
        return ConcreteValue(eval_binary(op, lhs.value, rhs.value, width), width)

    def icmp(
        self,
        predicate: IntPredicate,
        lhs: ConcreteValue,
        rhs: ConcreteValue,
        width: int | None,
    ) -> ConcreteValue:
        return ConcreteValue(int(eval_icmp(predicate, lhs.value, rhs.value, width)), 1)

    def select(
        self,
        cond: ConcreteValue,
        true_val: ConcreteValue,
        false_val: ConcreteValue,
        width: int | None,
    ) -> ConcreteValue:
        return self.with_width(true_val if cond.value else false_val, width)

    def cast(
        self,
        op: Opcode,
        val: ConcreteValue,
        from_width: int | None,
        to_width: int | None,
    ) -> ConcreteValue:
        if op == Opcode.SExt:
            return ConcreteValue(sext_value(val.value, from_width, to_width), to_width)
        return ConcreteValue(mask_value(val.value, to_width), to_width)

    def funnel_shift(
        self,
        high: ConcreteValue,
        low: ConcreteValue,
        amount: ConcreteValue,
        width: int | None,
        *,
        left: bool,
    ) -> ConcreteValue:
        return ConcreteValue(
            eval_funnel_shift_value(
                high.value, low.value, amount.value, width, left=left
            ),
            width,
        )

    def concrete_bool(self, val: ConcreteValue) -> bool | None:
        return bool(val.value)

    def with_width(
        self, val: ConcreteValue, width: int | None, *, signed: bool = False
    ) -> ConcreteValue:
        if signed:
            return ConcreteValue(sext_value(val.value, val.width, width), width)
        return ConcreteValue(mask_value(val.value, width), width)


@dataclass
class ConcreteMemory(MemoryState[ConcreteValue]):
    """Byte-addressed concrete memory with sparse writes over optional backing data."""

    data: bytearray
    base: int = 0
    overlay: dict[int, int] = field(default_factory=dict)

    @classmethod
    def from_backing(cls, backing: MemoryBacking) -> ConcreteMemory:
        data, base = data_from_backing(backing)
        return cls(data, base)

    def read(
        self, offset: ConcreteValue, width: int, *, insn_addr: int = 0
    ) -> ConcreteValue:
        del insn_addr
        byte_width = bytes_for_width(width)
        value = 0
        for i in range(byte_width):
            value |= self._read_byte(offset.value + i) << (i * 8)
        return ConcreteValue(mask_value(value, width), width)

    def write(
        self,
        offset: ConcreteValue,
        value: ConcreteValue,
        width: int,
        *,
        insn_addr: int = 0,
    ) -> None:
        del insn_addr
        byte_width = bytes_for_width(width)
        concrete = mask_value(value.value, width)
        for i in range(byte_width):
            self._write_byte(offset.value + i, (concrete >> (i * 8)) & 0xFF)

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


class ConcreteRegisters(RegisterState[ConcreteValue]):
    def __init__(
        self,
        reg_sizes: dict[str, int],
        initial: dict[str, int | ConcreteValue] | None = None,
    ):
        self._sizes = reg_sizes
        initial = initial or {}
        self._regs: dict[str, ConcreteValue] = {}
        for name, size in reg_sizes.items():
            value = initial.get(name, 0)
            if isinstance(value, ConcreteValue):
                self._regs[name] = ConcreteValue(mask_value(value.value, size), size)
            else:
                self._regs[name] = ConcreteValue(mask_value(value, size), size)

    def read(self, name: str) -> ConcreteValue:
        return self._regs[name]

    def write(self, name: str, value: ConcreteValue) -> None:
        self._regs[name] = ConcreteValue(
            mask_value(value.value, self._sizes[name]), self._sizes[name]
        )

    def width(self, name: str) -> int:
        return self._sizes[name]
