from __future__ import annotations

# ruff: noqa: E402

import sys
from pathlib import Path
from typing import cast

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import smt_wire as smt
from llvm import Opcode, create_context

from striga import BoundaryResult, Interpreter, Semantics, StopResult
from striga.domains import (
    ConcreteDomain,
    ConcreteMemory,
    ConcreteRegisters,
    ConcreteValue,
    Counted,
    CountingDomain,
    CountingMemory,
    CountingRegisters,
    Interval,
    IntervalDomain,
    IntervalMemory,
    SmtDomain,
    SmtMemory,
    SmtRegisters,
    TaintDomain,
    TaintMemory,
    TaintRegisters,
    Tainted,
)


def test_concrete_domain_executes_lifted_xor() -> None:
    with create_context() as context:
        with context.create_module("concrete_xor") as module:
            sem = Semantics(module)
            sem.begin(0x1000)
            sem.lift_instruction(sem.cs_disasm(0x1000, b"\x48\x31\xc0"))  # xor rax, rax

            regs = ConcreteRegisters(sem.reg_sizes, {"rax": 0xDEADBEEF})
            interp = Interpreter(
                ConcreteDomain(),
                regs,
                ConcreteMemory(bytearray(0x1000)),
                sem.reg_sizes,
                sem.state_ty,
                sem.reg_indices,
            )

            result = interp.execute_block(sem.insn_blocks[0x1000])

            assert not isinstance(result, BoundaryResult)
            assert regs.read("rax").value == 0
            assert regs.read("zf").value == 1


def test_taint_domain_propagates_register_labels() -> None:
    with create_context() as context:
        with context.create_module("taint_mov") as module:
            sem = Semantics(module)
            sem.begin(0x1000)
            sem.lift_instruction(sem.cs_disasm(0x1000, b"\x48\x89\xc8"))  # mov rax, rcx

            regs = TaintRegisters(
                sem.reg_sizes,
                {"rcx": Tainted(0x1234, 64, frozenset({"input_rcx"}))},
            )
            interp = Interpreter(
                TaintDomain(),
                regs,
                TaintMemory(bytearray(0x1000)),
                sem.reg_sizes,
                sem.state_ty,
                sem.reg_indices,
            )

            interp.execute_block(sem.insn_blocks[0x1000])

            assert regs.read("rax").value == 0x1234
            assert regs.read("rax").labels == frozenset({"input_rcx"})


def test_interval_domain_tracks_exact_addition() -> None:
    domain = IntervalDomain()
    result = domain.binary(Opcode.Add, Interval.exact(10, 64), Interval.exact(32, 64), 64)

    assert result == Interval.exact(42, 64)
    assert domain.concrete_bool(Interval(1, 1, 1)) is True
    assert domain.concrete_bool(Interval(0, 1, 1)) is None


def test_counting_domain_profiles_lifted_add() -> None:
    with create_context() as context:
        with context.create_module("count_add") as module:
            sem = Semantics(module)
            sem.begin(0x1000)
            sem.lift_instruction(sem.cs_disasm(0x1000, b"\x48\x01\xc8"))  # add rax, rcx

            regs = CountingRegisters(sem.reg_sizes, {"rax": 40, "rcx": 2})
            interp = Interpreter(
                CountingDomain(),
                regs,
                CountingMemory(),
                sem.reg_sizes,
                sem.state_ty,
                sem.reg_indices,
            )

            interp.execute_block(sem.insn_blocks[0x1000])

            assert regs.read("rax").value == 42
            assert regs.read("rax").ops.get("Add", 0) >= 1


def test_smt_domain_builds_register_expression() -> None:
    ctx = smt.Context()
    with create_context() as context:
        with context.create_module("smt_mov") as module:
            sem = Semantics(module)
            sem.begin(0x1000)
            sem.lift_instruction(sem.cs_disasm(0x1000, b"\x48\x89\xc8"))  # mov rax, rcx

            regs = SmtRegisters(
                ctx,
                sem.reg_sizes,
                {"rcx": ctx.bv_var("in_rcx", 64)},
                symbolic_missing=False,
            )
            interp = Interpreter(
                SmtDomain(ctx),
                regs,
                SmtMemory(ctx),
                sem.reg_sizes,
                sem.state_ty,
                sem.reg_indices,
            )

            interp.execute_block(sem.insn_blocks[0x1000])

            rax = regs.read("rax")
            assert isinstance(rax, smt.BVTerm)
            assert "in_rcx" in rax.to_smt2()
            assert SmtDomain(ctx).concrete_bool(ctx.bool_const(True)) is True


def test_domain_memory_round_trips_sparse_writes() -> None:
    concrete = ConcreteMemory(bytearray(4), base=0x1000)
    concrete.write(ConcreteDomain().constant(0x800000, 64), ConcreteDomain().constant(0xAABBCCDD, 32), 32)
    assert concrete.read(ConcreteDomain().constant(0x800000, 64), 32).value == 0xAABBCCDD

    taint = TaintMemory(bytearray(4), base=0x1000)
    taint.write(
        Tainted(0x800000, 64, frozenset({"addr"})),
        Tainted(0x11, 8, frozenset({"value"})),
        8,
    )
    assert taint.read(Tainted(0x800000, 64, frozenset()), 8).labels == frozenset({"addr", "value"})

    interval_mem = IntervalMemory()
    interval_mem.write(Interval.exact(0x2000, 64), Interval.exact(0x1234, 16), 16)
    assert interval_mem.read(Interval.exact(0x2000, 64), 16) == Interval.exact(0x1234, 16)

    counted_mem = CountingMemory()
    counted_mem.write(Counted.const(0x3000, 64), Counted.const(0x55, 8), 8)
    assert counted_mem.read(Counted.const(0x3000, 64), 8).value == 0x55

    ctx = smt.Context()
    smt_mem = SmtMemory(ctx)
    smt_mem.write(ctx.bv_const(0x4000, 64), ctx.bv_const(0xBEEF, 16), 16)
    smt_value = smt_mem.read(ctx.bv_const(0x4000, 64), 16)
    assert smt_value.width == 16


def test_concrete_boundary_result_uses_domain_value() -> None:
    with create_context() as context:
        with context.create_module("concrete_ret") as module:
            sem = Semantics(module)
            sem.begin(0x1000)
            sem.lift_instruction(sem.cs_disasm(0x1000, b"\xc3"))  # ret

            regs = ConcreteRegisters(sem.reg_sizes, {"rsp": 0x2000})
            mem = ConcreteMemory(bytearray())
            mem.write(ConcreteDomain().constant(0x2000, 64), ConcreteDomain().constant(0x12345678, 64), 64)
            interp = Interpreter(ConcreteDomain(), regs, mem, sem.reg_sizes, sem.state_ty, sem.reg_indices)

            result = interp.execute_block(sem.insn_blocks[0x1000])

            assert isinstance(result, BoundaryResult)
            boundary = cast("BoundaryResult[ConcreteValue]", result)
            assert boundary.name == "__striga_ret"
            assert boundary.target.value == 0x12345678


def test_stop_result_import_is_public() -> None:
    from tools.domains.concrete import ConcreteDomain as ToolConcreteDomain

    assert StopResult("ret").reason == "ret"
    assert ToolConcreteDomain is ConcreteDomain


def main() -> None:
    test_concrete_domain_executes_lifted_xor()
    test_taint_domain_propagates_register_labels()
    test_interval_domain_tracks_exact_addition()
    test_counting_domain_profiles_lifted_add()
    test_smt_domain_builds_register_expression()
    test_domain_memory_round_trips_sparse_writes()
    test_concrete_boundary_result_uses_domain_value()
    test_stop_result_import_is_public()
    print("PASS interpreter domain smoke")


if __name__ == "__main__":
    main()
