from __future__ import annotations

# ruff: noqa: E402

import sys
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from container import PEContainer
from tools.vmentry_concolic import ConcolicConfig, LLVMConcolicExecutor


@dataclass(frozen=True)
class SmokeCase:
    name: str
    binary: str
    rip: int
    boundary: str
    stop: int
    target: int | None
    follow_calls: set[int] = field(default_factory=set)
    concrete_regs: dict[str, int] = field(default_factory=dict)
    zero_unknown_abs: bool = False


CASES = [
    SmokeCase(
        name="binaryshield",
        binary="tests/binaryshield.exe",
        rip=0x140017A41,
        boundary="__striga_jmp",
        stop=0x14001604C,
        target=0x140016101,
    ),
    SmokeCase(
        name="vmprotect",
        binary="tests/basic_vm_targets.309.dll",
        rip=0x1800E3C42,
        follow_calls={0x1800E3C47},
        boundary="__striga_jmp",
        stop=0x18004BA98,
        target=0x180082187,
    ),
    SmokeCase(
        name="themida-example2",
        binary="tests/example2-virt.bin",
        rip=0x140001000,
        follow_calls={0x1401BA2A8},
        boundary="__striga_jmp",
        stop=0x1401BAF5D,
        target=0x1400118C8,
        zero_unknown_abs=True,
    ),
    SmokeCase(
        name="minivm-switch",
        binary="tests/minivm-switch.exe",
        rip=0x1400012B0,
        boundary="__striga_jmp",
        stop=0x140001314,
        target=0x140001390,
    ),
    SmokeCase(
        name="minivm-threaded",
        binary="tests/minivm-threaded.exe",
        rip=0x140001070,
        boundary="__striga_call",
        stop=0x1400010D3,
        target=0x1400014E0,
    ),
    SmokeCase(
        name="stackvm-switch-old",
        binary="tests/stackvm-switch-old.exe",
        rip=0x140001290,
        follow_calls={0x1400012AC},
        boundary="__striga_jmp",
        stop=0x140001075,
        target=0x1400010A0,
    ),
    SmokeCase(
        name="stackvm-threaded",
        binary="tests/stackvm-threaded.exe",
        rip=0x140001060,
        boundary="__striga_call",
        stop=0x1400010AB,
        target=0x140001390,
    ),
    SmokeCase(
        name="stackvm-switch-symbolic",
        binary="tests/stackvm-switch.exe",
        rip=0x1400011A0,
        boundary="symbolic_branch",
        stop=0x14000128C,
        target=None,
    ),
    SmokeCase(
        name="stackvm-switch-rcx42",
        binary="tests/stackvm-switch.exe",
        rip=0x1400011A0,
        concrete_regs={"rcx": 42},
        boundary="__striga_ret",
        stop=0x14000133F,
        target=None,
    ),
]


def run_case(case: SmokeCase) -> str:
    cfg = ConcolicConfig(
        binary=ROOT / case.binary,
        rip=case.rip,
        out_dir=ROOT / "devirt-output" / "vmentry-concolic-smoke" / case.name,
        follow_calls=case.follow_calls,
        concrete_regs=case.concrete_regs,
        max_steps=50_000,
        trace_limit=0,
        zero_unknown_abs=case.zero_unknown_abs,
    )
    result = LLVMConcolicExecutor(PEContainer(str(cfg.binary)), cfg).run()
    target = None if result.boundary_value is None else result.boundary_value.concrete

    assert result.boundary_call == case.boundary, (
        case.name,
        "boundary",
        result.boundary_call,
        case.boundary,
    )
    assert result.stop == case.stop, (
        case.name,
        "stop",
        f"{result.stop:#x}",
        f"{case.stop:#x}",
    )
    assert target == case.target, (
        case.name,
        "target",
        "unknown" if target is None else f"{target:#x}",
        "unknown" if case.target is None else f"{case.target:#x}",
    )

    target_text = "unknown" if target is None else f"{target:#x}"
    return (
        f"PASS {case.name}: {result.boundary_call} "
        f"stop={result.stop:#x} target={target_text} steps={result.steps}"
    )


def test_vmentry_concolic_smoke() -> None:
    for case in CASES:
        run_case(case)


def main() -> None:
    for case in CASES:
        print(run_case(case))


if __name__ == "__main__":
    main()
