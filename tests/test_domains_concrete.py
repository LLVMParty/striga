from __future__ import annotations

# ruff: noqa: E402

import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from llvm import IntPredicate, Opcode

from striga.domains.concrete import (
    ConcreteDomain,
    ConcreteMemory,
    ConcreteRegisters,
    ConcreteValue,
)


@dataclass(frozen=True)
class FakeBacking:
    image_base: int
    data: bytes

    @property
    def image_size(self) -> int:
        return len(self.data)

    def in_range(self, va: int) -> bool:
        return self.image_base <= va < self.image_base + len(self.data)

    def get_data(self, va: int, size: int) -> bytes:
        offset = va - self.image_base
        return self.data[offset : offset + size]


def test_concrete_domain_masks_constants_and_width_changes() -> None:
    domain = ConcreteDomain()

    assert domain.constant(0x1FF, 8) == ConcreteValue(0xFF, 8)
    assert domain.with_width(ConcreteValue(0x1234, 16), 8) == ConcreteValue(0x34, 8)
    assert domain.with_width(ConcreteValue(0x80, 8), 16, signed=True) == ConcreteValue(
        0xFF80, 16
    )
    assert domain.with_width(ConcreteValue(0x80, 8), 16) == ConcreteValue(0x80, 16)


def test_concrete_domain_binary_operations_wrap_and_shift() -> None:
    domain = ConcreteDomain()
    a = ConcreteValue(0xFE, 8)
    b = ConcreteValue(4, 8)

    assert domain.binary(Opcode.Add, a, b, 8) == ConcreteValue(2, 8)
    assert domain.binary(Opcode.Sub, ConcreteValue(2, 8), b, 8) == ConcreteValue(
        0xFE, 8
    )
    assert domain.binary(Opcode.Mul, ConcreteValue(0x20, 8), b, 8) == ConcreteValue(
        0x80, 8
    )
    assert domain.binary(Opcode.And, a, ConcreteValue(0x0F, 8), 8) == ConcreteValue(
        0x0E, 8
    )
    assert domain.binary(
        Opcode.Or, ConcreteValue(0xF0, 8), ConcreteValue(0x0F, 8), 8
    ) == ConcreteValue(0xFF, 8)
    assert domain.binary(
        Opcode.Xor, ConcreteValue(0xAA, 8), ConcreteValue(0xFF, 8), 8
    ) == ConcreteValue(0x55, 8)
    assert domain.binary(
        Opcode.Shl, ConcreteValue(1, 8), ConcreteValue(9, 8), 8
    ) == ConcreteValue(2, 8)
    assert domain.binary(
        Opcode.LShr, ConcreteValue(0x80, 8), ConcreteValue(1, 8), 8
    ) == ConcreteValue(0x40, 8)
    assert domain.binary(
        Opcode.AShr, ConcreteValue(0x80, 8), ConcreteValue(1, 8), 8
    ) == ConcreteValue(0xC0, 8)


def test_concrete_domain_division_remainder_and_comparisons() -> None:
    domain = ConcreteDomain()

    assert domain.binary(
        Opcode.UDiv, ConcreteValue(250, 8), ConcreteValue(10, 8), 8
    ) == ConcreteValue(25, 8)
    assert domain.binary(
        Opcode.SDiv, ConcreteValue(0xF6, 8), ConcreteValue(3, 8), 8
    ) == ConcreteValue(0xFD, 8)
    assert domain.binary(
        Opcode.URem, ConcreteValue(250, 8), ConcreteValue(10, 8), 8
    ) == ConcreteValue(0, 8)
    assert domain.binary(
        Opcode.SRem, ConcreteValue(0xF6, 8), ConcreteValue(3, 8), 8
    ) == ConcreteValue(0xFF, 8)
    assert domain.binary(
        Opcode.UDiv, ConcreteValue(1, 8), ConcreteValue(0, 8), 8
    ) == ConcreteValue(0, 8)

    assert domain.icmp(
        IntPredicate.ULT, ConcreteValue(0xFF, 8), ConcreteValue(1, 8), 8
    ) == ConcreteValue(0, 1)
    assert domain.icmp(
        IntPredicate.SLT, ConcreteValue(0xFF, 8), ConcreteValue(1, 8), 8
    ) == ConcreteValue(1, 1)
    assert domain.icmp(
        IntPredicate.EQ, ConcreteValue(7, 8), ConcreteValue(7, 8), 8
    ) == ConcreteValue(1, 1)
    assert domain.concrete_bool(ConcreteValue(0, 1)) is False
    assert domain.concrete_bool(ConcreteValue(2, 8)) is True


def test_concrete_domain_select_cast_and_funnel_shift() -> None:
    domain = ConcreteDomain()

    assert domain.select(
        ConcreteValue(1, 1), ConcreteValue(0x1234, 16), ConcreteValue(0, 16), 8
    ) == ConcreteValue(0x34, 8)
    assert domain.select(
        ConcreteValue(0, 1), ConcreteValue(1, 8), ConcreteValue(2, 8), 8
    ) == ConcreteValue(2, 8)
    assert domain.cast(Opcode.Trunc, ConcreteValue(0x1234, 16), 16, 8) == ConcreteValue(
        0x34, 8
    )
    assert domain.cast(Opcode.ZExt, ConcreteValue(0x80, 8), 8, 16) == ConcreteValue(
        0x80, 16
    )
    assert domain.cast(Opcode.SExt, ConcreteValue(0x80, 8), 8, 16) == ConcreteValue(
        0xFF80, 16
    )
    assert domain.funnel_shift(
        ConcreteValue(0x12, 8),
        ConcreteValue(0x34, 8),
        ConcreteValue(4, 8),
        8,
        left=True,
    ) == ConcreteValue(0x23, 8)
    assert domain.funnel_shift(
        ConcreteValue(0x12, 8),
        ConcreteValue(0x34, 8),
        ConcreteValue(4, 8),
        8,
        left=False,
    ) == ConcreteValue(0x41, 8)


def test_concrete_memory_is_little_endian_sparse_and_overlayed() -> None:
    memory = ConcreteMemory.from_backing(FakeBacking(0x1000, b"\x11\x22\x33\x44"))
    domain = ConcreteDomain()

    assert memory.read(domain.constant(0x1000, 64), 32) == ConcreteValue(0x44332211, 32)

    memory.write(domain.constant(0x1001, 64), domain.constant(0xAABB, 16), 16)
    assert memory.read(domain.constant(0x1000, 64), 32) == ConcreteValue(0x44AABB11, 32)

    memory.write(domain.constant(0x9000, 64), domain.constant(0xCCDD, 16), 16)
    assert memory.read(domain.constant(0x9000, 64), 16) == ConcreteValue(0xCCDD, 16)
    assert memory.read(domain.constant(0xDEAD, 64), 16) == ConcreteValue(0, 16)


def test_concrete_registers_mask_initial_and_written_values() -> None:
    regs = ConcreteRegisters({"al": 8, "rax": 64}, {"al": 0x123, "rax": 1})

    assert regs.read("al") == ConcreteValue(0x23, 8)
    regs.write("al", ConcreteValue(0x1FF, 16))
    assert regs.read("al") == ConcreteValue(0xFF, 8)
    assert regs.width("rax") == 64


def main() -> None:
    test_concrete_domain_masks_constants_and_width_changes()
    test_concrete_domain_binary_operations_wrap_and_shift()
    test_concrete_domain_division_remainder_and_comparisons()
    test_concrete_domain_select_cast_and_funnel_shift()
    test_concrete_memory_is_little_endian_sparse_and_overlayed()
    test_concrete_registers_mask_initial_and_written_values()
    print("PASS concrete domain tests")


if __name__ == "__main__":
    main()
