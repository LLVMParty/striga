from __future__ import annotations

# ruff: noqa: E402

import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import cast

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import smt_wire as smt
from llvm import create_context

from striga import BoundaryResult, Interpreter, PtrVal, StopResult
from striga.domains.concrete import (
    ConcreteDomain,
    ConcreteMemory,
    ConcreteRegisters,
    ConcreteValue,
)
from striga.domains.interval import (
    Interval,
    IntervalDomain,
    IntervalMemory,
    IntervalRegisters,
)
from striga.domains.smt import SmtDomain, SmtMemory, SmtRegisters
from striga.domains.taint import TaintDomain, TaintMemory, TaintRegisters, Tainted
from striga.semantics import Semantics


def _execute_sequence(
    sem: Semantics, interp: Interpreter, start: int, insns: list[bytes]
):
    rip = start
    result = None
    for code in insns:
        sem.lift_instruction(sem.cs_disasm(rip, code))
        result = interp.execute_block(sem.insn_blocks[rip])
        if isinstance(result, int):
            rip = result
            continue
        return result
    return result


@dataclass
class ProfilingHooks:
    instructions: int = 0
    opcodes: dict[str, int] = field(default_factory=dict)
    stores: int = 0
    boundaries: list[str] = field(default_factory=list)

    def pre_instruction(self, inst):
        self.instructions += 1
        name = inst.opcode.name
        self.opcodes[name] = self.opcodes.get(name, 0) + 1

    def post_store(self, inst, value: ConcreteValue, ptr: PtrVal[ConcreteValue]):
        self.stores += 1
        return value

    def post_boundary(self, inst, name, target: ConcreteValue, target_arg, target_ptr):
        self.boundaries.append(name)
        return target


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


def test_concrete_domain_executes_stack_memory_round_trip() -> None:
    with create_context() as context:
        with context.create_module("concrete_stack") as module:
            sem = Semantics(module)
            sem.begin(0x1000)
            regs = ConcreteRegisters(
                sem.reg_sizes, {"rsp": 0x8000, "rcx": 0x123456789ABCDEF0}
            )
            memory = ConcreteMemory(bytearray())
            interp = Interpreter(
                ConcreteDomain(),
                regs,
                memory,
                sem.reg_sizes,
                sem.state_ty,
                sem.reg_indices,
            )

            _execute_sequence(
                sem,
                interp,
                0x1000,
                [
                    b"\x48\x89\x0c\x24",  # mov qword ptr [rsp], rcx
                    b"\x48\x8b\x04\x24",  # mov rax, qword ptr [rsp]
                ],
            )

            assert regs.read("rax") == ConcreteValue(0x123456789ABCDEF0, 64)
            assert (
                memory.read(ConcreteValue(0x8000, 64), 64).value == 0x123456789ABCDEF0
            )


def test_profiling_uses_hooks_not_a_counting_value_domain() -> None:
    with create_context() as context:
        with context.create_module("profile_hooks") as module:
            sem = Semantics(module)
            sem.begin(0x1000)
            hooks = ProfilingHooks()
            regs = ConcreteRegisters(sem.reg_sizes, {"rsp": 0x2000, "rcx": 0x55})
            memory = ConcreteMemory(bytearray())
            interp = Interpreter(
                ConcreteDomain(),
                regs,
                memory,
                sem.reg_sizes,
                sem.state_ty,
                sem.reg_indices,
                hooks=hooks,
            )

            result = _execute_sequence(
                sem,
                interp,
                0x1000,
                [
                    b"\x48\x89\x0c\x24",  # mov [rsp], rcx
                    b"\xc3",  # ret -> __striga_ret boundary
                ],
            )

            assert isinstance(result, BoundaryResult)
            assert hooks.instructions > 0
            assert hooks.stores >= 1
            assert hooks.boundaries == ["__striga_ret"]
            assert "Store" in hooks.opcodes


def test_taint_domain_propagates_through_lifted_memory() -> None:
    with create_context() as context:
        with context.create_module("taint_mem") as module:
            sem = Semantics(module)
            sem.begin(0x1000)

            regs = TaintRegisters(
                sem.reg_sizes,
                {
                    "rsp": 0x7000,
                    "rcx": Tainted(0x1234, 64, frozenset({"input_rcx"})),
                },
            )
            memory = TaintMemory(bytearray())
            interp = Interpreter(
                TaintDomain(),
                memory=memory,
                regs=regs,
                reg_sizes=sem.reg_sizes,
                state_ty=sem.state_ty,
                reg_indices=sem.reg_indices,
            )

            _execute_sequence(
                sem,
                interp,
                0x1000,
                [
                    b"\x48\x89\x0c\x24",  # mov [rsp], rcx
                    b"\x48\x8b\x04\x24",  # mov rax, [rsp]
                ],
            )

            assert regs.read("rax").value == 0x1234
            assert regs.read("rax").labels == frozenset({"input_rcx"})
            assert memory.read(
                Tainted(0x7000, 64, frozenset({"addr"})), 64
            ).labels == frozenset({"addr", "input_rcx"})


def test_interval_domain_interprets_lifted_masked_range() -> None:
    with create_context() as context:
        with context.create_module("interval_mask") as module:
            sem = Semantics(module)
            sem.begin(0x1000)
            regs = IntervalRegisters(
                sem.reg_sizes,
                {"rcx": Interval.full(64)},
            )
            interp = Interpreter(
                IntervalDomain(),
                regs,
                memory=IntervalMemory(),
                reg_sizes=sem.reg_sizes,
                state_ty=sem.state_ty,
                reg_indices=sem.reg_indices,
            )

            _execute_sequence(
                sem,
                interp,
                0x1000,
                [
                    b"\x48\x89\xc8",  # mov rax, rcx
                    b"\x48\x83\xe0\x1f",  # and rax, 0x1f
                ],
            )

            assert regs.read("rax") == Interval(0, 0x1F, 64)


def test_smt_domain_builds_arithmetic_expression() -> None:
    ctx = smt.Context()
    with create_context() as context:
        with context.create_module("smt_add") as module:
            sem = Semantics(module)
            sem.begin(0x1000)
            sem.lift_instruction(sem.cs_disasm(0x1000, b"\x48\x01\xc8"))  # add rax, rcx

            regs = SmtRegisters(
                ctx,
                sem.reg_sizes,
                {"rax": ctx.bv_var("in_rax", 64), "rcx": ctx.bv_var("in_rcx", 64)},
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
            smt2 = rax.to_smt2(depth=-1)
            assert "in_rax" in smt2
            assert "in_rcx" in smt2
            assert "bvadd" in smt2
            assert SmtDomain(ctx).concrete_bool(ctx.bool_const(True)) is True


def test_concrete_boundary_result_uses_domain_value() -> None:
    with create_context() as context:
        with context.create_module("concrete_ret") as module:
            sem = Semantics(module)
            sem.begin(0x1000)
            sem.lift_instruction(sem.cs_disasm(0x1000, b"\xc3"))  # ret

            regs = ConcreteRegisters(sem.reg_sizes, {"rsp": 0x2000})
            mem = ConcreteMemory(bytearray())
            mem.write(
                ConcreteDomain().constant(0x2000, 64),
                ConcreteDomain().constant(0x12345678, 64),
                64,
            )
            interp = Interpreter(
                ConcreteDomain(),
                regs,
                mem,
                sem.reg_sizes,
                sem.state_ty,
                sem.reg_indices,
            )

            result = interp.execute_block(sem.insn_blocks[0x1000])

            assert isinstance(result, BoundaryResult)
            boundary = cast("BoundaryResult[ConcreteValue]", result)
            assert boundary.name == "__striga_ret"
            assert boundary.target.value == 0x12345678


def test_stop_result_import_is_public() -> None:
    from striga.domains.concrete import ConcreteDomain as ToolConcreteDomain

    assert StopResult("ret").reason == "ret"
    assert ToolConcreteDomain is ConcreteDomain


def main() -> None:
    test_concrete_domain_executes_lifted_xor()
    test_concrete_domain_executes_stack_memory_round_trip()
    test_profiling_uses_hooks_not_a_counting_value_domain()
    test_taint_domain_propagates_through_lifted_memory()
    test_interval_domain_interprets_lifted_masked_range()
    test_smt_domain_builds_arithmetic_expression()
    test_concrete_boundary_result_uses_domain_value()
    test_stop_result_import_is_public()
    print("PASS interpreter domain smoke")


if __name__ == "__main__":
    main()
