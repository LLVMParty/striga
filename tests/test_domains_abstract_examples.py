from __future__ import annotations

# ruff: noqa: E402

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import smt_wire as smt
from llvm import IntPredicate, Opcode

from striga.domains.interval import (
    Interval,
    IntervalDomain,
    IntervalMemory,
    IntervalRegisters,
)
from striga.domains.smt import SmtDomain, SmtMemory, SmtRegisters
from striga.domains.taint import TaintDomain, TaintMemory, TaintRegisters, Tainted


def test_taint_domain_combines_labels_without_tainting_constants() -> None:
    domain = TaintDomain()
    lhs = Tainted(0x10, 64, frozenset({"bytecode"}))
    rhs = Tainted(0x22, 64, frozenset({"key"}))

    result = domain.binary(Opcode.Xor, lhs, rhs, 64)

    assert result.value == 0x32
    assert result.labels == frozenset({"bytecode", "key"})
    assert domain.constant(0x1234, 64).labels == frozenset()
    assert domain.unknown("opaque", 64).labels == frozenset({"opaque"})


def test_taint_domain_select_keeps_condition_and_both_arm_labels() -> None:
    domain = TaintDomain()

    result = domain.select(
        Tainted(1, 1, frozenset({"condition"})),
        Tainted(0xAA, 8, frozenset({"true"})),
        Tainted(0xBB, 8, frozenset({"false"})),
        8,
    )

    assert result.value == 0xAA
    assert result.labels == frozenset({"condition", "true", "false"})


def test_taint_memory_propagates_address_and_value_labels_per_byte() -> None:
    memory = TaintMemory(bytearray())

    memory.write(
        Tainted(0x8000, 64, frozenset({"addr"})),
        Tainted(0xAABB, 16, frozenset({"value"})),
        16,
    )

    assert memory.read(Tainted(0x8000, 64, frozenset()), 16) == Tainted(
        0xAABB, 16, frozenset({"addr", "value"})
    )
    assert memory.read(
        Tainted(0x8001, 64, frozenset({"read_addr"})), 8
    ).labels == frozenset({"read_addr", "addr", "value"})


def test_taint_registers_mask_values_and_preserve_labels() -> None:
    regs = TaintRegisters({"al": 8}, {"al": Tainted(0x123, 16, frozenset({"input"}))})

    assert regs.read("al") == Tainted(0x23, 8, frozenset({"input"}))
    regs.write("al", Tainted(0x1FF, 16, frozenset({"write"})))
    assert regs.read("al") == Tainted(0xFF, 8, frozenset({"write"}))


def test_interval_domain_tracks_ranges_and_definite_comparisons() -> None:
    domain = IntervalDomain()

    assert domain.binary(
        Opcode.Add, Interval(10, 20, 64), Interval(1, 2, 64), 64
    ) == Interval(11, 22, 64)
    assert domain.binary(
        Opcode.Sub, Interval(10, 20, 64), Interval(1, 2, 64), 64
    ) == Interval(8, 19, 64)
    assert domain.binary(
        Opcode.And, Interval.full(8), Interval.exact(0x1F, 8), 8
    ) == Interval(0, 0x1F, 8)
    assert domain.icmp(
        IntPredicate.ULT, Interval(1, 3, 8), Interval(4, 9, 8), 1
    ) == Interval.exact(1, 1)
    assert domain.icmp(
        IntPredicate.EQ, Interval(1, 3, 8), Interval(4, 9, 8), 1
    ) == Interval.exact(0, 1)
    assert domain.icmp(
        IntPredicate.EQ, Interval(1, 3, 8), Interval(3, 9, 8), 1
    ) == Interval.full(1)
    assert domain.select(
        Interval(0, 1, 1), Interval(10, 20, 64), Interval(30, 40, 64), 64
    ) == Interval(10, 40, 64)
    assert domain.concrete_bool(Interval(1, 3, 1)) is True
    assert domain.concrete_bool(Interval(0, 1, 1)) is None


def test_interval_memory_and_registers_handle_unknown_addresses() -> None:
    memory = IntervalMemory()
    memory.write(Interval.exact(0x2000, 64), Interval.exact(0x1234, 16), 16)

    assert memory.read(Interval.exact(0x2000, 64), 16) == Interval.exact(0x1234, 16)
    assert memory.read(Interval(0x2000, 0x2001, 64), 16) == Interval.full(16)

    regs = IntervalRegisters({"al": 8}, {"al": Interval(0, 0x1FF, 16)})
    assert regs.read("al") == Interval(0, 0xFF, 8)


def test_smt_domain_builds_expected_terms_and_concrete_bools() -> None:
    ctx = smt.Context()
    domain = SmtDomain(ctx)
    x = ctx.bv_var("x", 64)
    y = ctx.bv_var("y", 64)

    expr = domain.binary(Opcode.Add, x, y, 64)
    smt2 = expr.to_smt2(depth=-1)

    assert "bvadd" in smt2
    assert "x" in smt2
    assert "y" in smt2
    assert domain.concrete_bool(ctx.bool_const(True)) is True
    assert domain.concrete_bool(ctx.bool_const(False)) is False
    assert domain.concrete_bool(x) is None


def test_smt_memory_distinguishes_concrete_and_symbolic_addresses() -> None:
    ctx = smt.Context()
    memory = SmtMemory(ctx)
    domain = SmtDomain(ctx)

    memory.write(ctx.bv_const(0x4000, 64), ctx.bv_const(0xBEEF, 16), 16)
    concrete_read = memory.read(ctx.bv_const(0x4000, 64), 16)
    symbolic_read = memory.read(ctx.bv_var("addr", 64), 16, insn_addr=0x1234)

    assert concrete_read.width == 16
    assert symbolic_read.width == 16
    assert "mem_1234_16" in symbolic_read.to_smt2(depth=-1)
    assert domain.with_width(ctx.bool_const(True), 8).to_smt2(depth=-1)


def test_smt_registers_can_seed_concrete_and_symbolic_values() -> None:
    ctx = smt.Context()
    regs = SmtRegisters(
        ctx,
        {"rax": 64, "al": 8, "rbx": 64},
        {"rax": 0x1234, "al": ctx.bv_var("input_al", 16)},
        symbolic_missing=True,
    )

    al = regs.read("al")

    assert regs.read("rax").to_smt2(depth=-1)
    assert isinstance(al, smt.BVTerm)
    assert al.width == 8
    assert "source_rbx" in regs.read("rbx").to_smt2(depth=-1)


def main() -> None:
    test_taint_domain_combines_labels_without_tainting_constants()
    test_taint_domain_select_keeps_condition_and_both_arm_labels()
    test_taint_memory_propagates_address_and_value_labels_per_byte()
    test_taint_registers_mask_values_and_preserve_labels()
    test_interval_domain_tracks_ranges_and_definite_comparisons()
    test_interval_memory_and_registers_handle_unknown_addresses()
    test_smt_domain_builds_expected_terms_and_concrete_bools()
    test_smt_memory_distinguishes_concrete_and_symbolic_addresses()
    test_smt_registers_can_seed_concrete_and_symbolic_values()
    print("PASS abstract example domain tests")


if __name__ == "__main__":
    main()
