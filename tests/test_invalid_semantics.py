from __future__ import annotations

# ruff: noqa: E402

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from llvm import create_context

from striga import Semantics


def test_invalid_bytes_lift_to_invalid_helper_and_stop() -> None:
    with create_context() as context:
        with context.create_module("invalid_byte") as module:
            sem = Semantics(module)
            sem.begin(0x1000)
            try:
                sem.cs_disasm(0x1000, bytes.fromhex("06"))
            except ValueError:
                pass
            else:
                raise AssertionError("invalid byte unexpectedly disassembled")

            successors = sem.lift_invalid(0x1000)
            text = str(module)

    assert successors == []
    assert "@__striga_invalid" in text
    assert "i64 4096" in text
    assert "ret void" in text


if __name__ == "__main__":
    test_invalid_bytes_lift_to_invalid_helper_and_stop()
    print("PASS invalid-byte helper")
