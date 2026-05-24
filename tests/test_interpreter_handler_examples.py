from __future__ import annotations

# ruff: noqa: E402

import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import cast

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from llvm import create_context

from striga import BoundaryResult, Interpreter, PtrVal
from striga.domains.concrete import (
    ConcreteDomain,
    ConcreteMemory,
    ConcreteRegisters,
    ConcreteValue,
)
from striga.domains.taint import TaintDomain, TaintMemory, TaintRegisters, Tainted
from striga.semantics import Semantics

HANDLER_BYTES = [
    b"\x48\x8b\x06",  # mov rax, qword ptr [rsi]
    b"\x48\x31\xd8",  # xor rax, rbx
    b"\x48\x89\x44\x24\x08",  # mov qword ptr [rsp + 8], rax
    b"\x48\x8b\x4c\x24\x08",  # mov rcx, qword ptr [rsp + 8]
    b"\xc3",  # ret
]


@dataclass
class HandlerProfile:
    instructions: int = 0
    stores: int = 0
    boundaries: list[str] = field(default_factory=list)

    def pre_instruction(self, inst) -> None:
        self.instructions += 1

    def post_store(
        self, inst, value: ConcreteValue, ptr: PtrVal[ConcreteValue]
    ) -> ConcreteValue:
        self.stores += 1
        return value

    def post_boundary(
        self, inst, name, target: ConcreteValue, target_arg, target_ptr
    ) -> ConcreteValue:
        self.boundaries.append(name)
        return target


def _run_handler(sem: Semantics, interp: Interpreter, start: int = 0x1000):
    rip = start
    result = None
    for code in HANDLER_BYTES:
        sem.lift_instruction(sem.cs_disasm(rip, code))
        result = interp.execute_block(sem.insn_blocks[rip])
        if not isinstance(result, int):
            return result
        rip = result
    return result


def test_concrete_handler_like_sequence_has_meaningful_state_and_boundary() -> None:
    with create_context() as context:
        with context.create_module("concrete_handler") as module:
            sem = Semantics(module)
            sem.begin(0x1000)
            regs = ConcreteRegisters(
                sem.reg_sizes,
                {"rsi": 0x5000, "rbx": 0x1111, "rsp": 0x8000},
            )
            memory = ConcreteMemory(bytearray())
            domain = ConcreteDomain()
            memory.write(domain.constant(0x5000, 64), domain.constant(0x2222, 64), 64)
            memory.write(domain.constant(0x8000, 64), domain.constant(0x9000, 64), 64)
            profile = HandlerProfile()
            interp = Interpreter(
                domain,
                regs,
                memory,
                sem.reg_sizes,
                sem.state_ty,
                sem.reg_indices,
                hooks=profile,
            )

            result = _run_handler(sem, interp)

            assert isinstance(result, BoundaryResult)
            boundary = cast("BoundaryResult[ConcreteValue]", result)
            assert boundary.name == "__striga_ret"
            assert boundary.target == ConcreteValue(0x9000, 64)
            assert regs.read("rcx") == ConcreteValue(0x3333, 64)
            assert memory.read(domain.constant(0x8008, 64), 64) == ConcreteValue(
                0x3333, 64
            )
            assert profile.boundaries == ["__striga_ret"]
            assert profile.stores >= 1
            assert profile.instructions > 0


def test_taint_handler_like_sequence_tracks_loaded_bytecode_to_output_register() -> (
    None
):
    with create_context() as context:
        with context.create_module("taint_handler") as module:
            sem = Semantics(module)
            sem.begin(0x1000)
            regs = TaintRegisters(
                sem.reg_sizes,
                {
                    "rsi": Tainted(0x5000, 64, frozenset()),
                    "rbx": Tainted(0x1111, 64, frozenset({"key"})),
                    "rsp": 0x8000,
                },
            )
            memory = TaintMemory(bytearray())
            memory.write(
                Tainted(0x5000, 64, frozenset()),
                Tainted(0x2222, 64, frozenset({"bytecode"})),
                64,
            )
            memory.write(
                Tainted(0x8000, 64, frozenset()), Tainted(0x9000, 64, frozenset()), 64
            )
            interp = Interpreter(
                TaintDomain(),
                regs,
                memory,
                sem.reg_sizes,
                sem.state_ty,
                sem.reg_indices,
            )

            result = _run_handler(sem, interp)

            assert isinstance(result, BoundaryResult)
            assert regs.read("rcx") == Tainted(
                0x3333, 64, frozenset({"bytecode", "key"})
            )
            assert memory.read(Tainted(0x8008, 64, frozenset()), 64) == Tainted(
                0x3333, 64, frozenset({"bytecode", "key"})
            )


def main() -> None:
    test_concrete_handler_like_sequence_has_meaningful_state_and_boundary()
    test_taint_handler_like_sequence_tracks_loaded_bytecode_to_output_register()
    print("PASS interpreter handler example tests")


if __name__ == "__main__":
    main()
