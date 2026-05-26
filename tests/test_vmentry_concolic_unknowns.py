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


if __name__ == "__main__":
    test_unknown_sources_are_deduplicated_across_repeated_composition()
    print("PASS unknown-source deduplication")
