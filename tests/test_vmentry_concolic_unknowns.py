from __future__ import annotations

# ruff: noqa: E402

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from llvm import Opcode

from tools.vmentry_concolic import SymVal, combine_values


def test_unknown_sources_are_deduplicated_across_repeated_composition() -> None:
    source = SymVal.unknown("source_rax()", 64)
    value = source

    for _ in range(100):
        value = combine_values(value, source, Opcode.Add, 64)

    assert value.unknowns == frozenset({"source_rax()"})


def test_add_sub_cancellation_preserves_xor_provenance() -> None:
    stack = SymVal.env("stack")
    source = SymVal.unknown("source_r14()", 64)
    mixed = combine_values(stack, source, Opcode.Xor, 64)

    adjusted = combine_values(mixed, SymVal.const(0x5E7EC899, 64), Opcode.Sub, 64)
    restored = combine_values(adjusted, SymVal.const(0x5E7EC899, 64), Opcode.Add, 64)
    cancelled = combine_values(restored, source, Opcode.Xor, 64)

    assert restored.xor_address == stack.address
    assert restored.xor_symbols == frozenset({"source_r14()"})
    assert cancelled.address == stack.address


if __name__ == "__main__":
    test_unknown_sources_are_deduplicated_across_repeated_composition()
    test_add_sub_cancellation_preserves_xor_provenance()
    print("PASS unknown-source deduplication")
