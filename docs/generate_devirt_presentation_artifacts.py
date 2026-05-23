from __future__ import annotations

import csv
import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent
ARTIFACT_DIR = ROOT / "devirt-presentation-artifacts"
SNIPPET_DIR = ARTIFACT_DIR / "snippets"


@dataclass
class IrStats:
    path: str
    lines: int
    ram_refs: int
    hook_refs: int
    switches: int
    unresolved_refs: int
    calls: int
    loads: int
    stores: int
    icmp_eq_constants: list[int]


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def stats_for(path: Path) -> IrStats:
    text = read(path)
    return IrStats(
        path=str(path.relative_to(ROOT)).replace("\\", "/"),
        lines=len(text.splitlines()),
        ram_refs=text.count("@RAM"),
        hook_refs=len(re.findall(r"__striga_(?:jmp|call|ret|syscall)", text)),
        switches=len(re.findall(r"\bswitch\b", text)),
        unresolved_refs=text.count("unresolved"),
        calls=len(re.findall(r"\bcall\b", text)),
        loads=len(re.findall(r"\bload\b", text)),
        stores=len(re.findall(r"\bstore\b", text)),
        icmp_eq_constants=[int(x) for x in re.findall(r"icmp eq i32 %[-.$A-Za-z0-9_]+, (\d+)", text)],
    )


def window_around(text: str, pattern: str, *, before: int = 8, after: int = 16) -> str:
    lines = text.splitlines()
    rx = re.compile(pattern)
    for index, line in enumerate(lines):
        if rx.search(line):
            start = max(index - before, 0)
            end = min(index + after + 1, len(lines))
            return "\n".join(lines[start:end]) + "\n"
    raise ValueError(f"pattern not found: {pattern}")


def write_snippet(name: str, content: str) -> Path:
    SNIPPET_DIR.mkdir(parents=True, exist_ok=True)
    path = SNIPPET_DIR / name
    path.write_text(content, encoding="utf-8")
    return path


def main() -> None:
    resolver_first_built = ARTIFACT_DIR / "resolvers" / "140016000-01-built.ll"
    resolver_first_inlined = ARTIFACT_DIR / "resolvers" / "140016000-02-inlined-before-hook-rewrite.ll"
    resolver_first_hooked = ARTIFACT_DIR / "resolvers" / "140016000-03-hook-rewritten.ll"
    resolver_first_optimized = ARTIFACT_DIR / "resolvers" / "140016000-04-optimized.ll"
    resolver_jcc_optimized = ARTIFACT_DIR / "resolvers" / "14001676b-04-optimized.ll"
    recovered_skeleton = ARTIFACT_DIR / "recovered" / "01-skeleton-before-inline.ll"
    recovered_round8 = ARTIFACT_DIR / "recovered" / "04-cleanup-round-8.ll"
    recovered_residual = ARTIFACT_DIR / "recovered" / "05-residual-before-final-pattern-cleanup.ll"
    recovered_final = ARTIFACT_DIR / "recovered" / "06-final-clean.ll"

    files = [
        *sorted((ARTIFACT_DIR / "resolvers").glob("*.ll")),
        *sorted((ARTIFACT_DIR / "recovered").glob("*.ll")),
    ]
    stats = [stats_for(path) for path in files]

    snippets = {
        "resolver-built-call.ll": window_around(read(resolver_first_built), r"call void @lifted_0x140016000", before=10, after=4),
        "resolver-inlined-hook-call.ll": window_around(read(resolver_first_inlined), r"__striga_jmp", before=14, after=4),
        "resolver-hook-rewritten-return.ll": window_around(read(resolver_first_hooked), r"insertvalue %TraceResult_140016000", before=8, after=20),
        "resolver-optimized-target.ll": window_around(read(resolver_first_optimized), r"ret %TraceResult_140016000", before=24, after=3),
        "jcc-resolver-select.ll": window_around(read(resolver_jcc_optimized), r"select i1", before=18, after=20),
        "recovered-skeleton-switch.ll": window_around(read(recovered_skeleton), r"switch i64", before=4, after=12),
        "recovered-round8-first-compare.ll": window_around(read(recovered_round8), r"icmp eq i32 %4, 1859", before=12, after=32),
        "recovered-residual-membership.ll": window_around(read(recovered_residual), r"icmp eq i32 %4, 1859", before=12, after=72),
        "recovered-final.ll": read(recovered_final),
    }
    snippet_paths = {name: write_snippet(name, content) for name, content in snippets.items()}

    stats_json = ARTIFACT_DIR / "ir-stage-stats.json"
    stats_json.write_text(json.dumps([asdict(s) for s in stats], indent=2), encoding="utf-8")

    stats_csv = ARTIFACT_DIR / "ir-stage-stats.csv"
    with stats_csv.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(asdict(stats[0]).keys()))
        writer.writeheader()
        for item in stats:
            row = asdict(item)
            row["icmp_eq_constants"] = " ".join(map(str, row["icmp_eq_constants"]))
            writer.writerow(row)

    report_lines = [
        "# BinaryShield devirtualization presentation artifacts",
        "",
        "Generated from `STRIGA_DEVIRT_DUMP_DIR=docs/devirt-presentation-artifacts` and selected resolver dumps for `0x140016000` and `0x14001676b`.",
        "",
        "## Stage statistics",
        "",
        "| File | Lines | @RAM refs | hooks | switches | unresolved | calls | loads | stores | constants |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---|",
    ]
    for item in stats:
        constants = ", ".join(map(str, item.icmp_eq_constants[:8]))
        if len(item.icmp_eq_constants) > 8:
            constants += ", ..."
        report_lines.append(
            f"| `{item.path}` | {item.lines} | {item.ram_refs} | {item.hook_refs} | "
            f"{item.switches} | {item.unresolved_refs} | {item.calls} | {item.loads} | "
            f"{item.stores} | {constants} |"
        )

    report_lines.extend([
        "",
        "## Snippets",
        "",
    ])
    for name, path in snippet_paths.items():
        report_lines.append(f"- `{path.relative_to(ROOT).as_posix()}`")

    snippet_bundle_lines = ["# Intermediate IR snippets", ""]
    for name, content in snippets.items():
        snippet_bundle_lines.extend([f"## {name}", "", "```llvm", content.rstrip(), "```", ""])
    snippet_bundle = ARTIFACT_DIR / "ir-snippets.md"
    snippet_bundle.write_text("\n".join(snippet_bundle_lines), encoding="utf-8")

    (ARTIFACT_DIR / "summary.md").write_text("\n".join(report_lines) + "\n", encoding="utf-8")

    print(f"wrote {stats_json.relative_to(ROOT)}")
    print(f"wrote {stats_csv.relative_to(ROOT)}")
    print(f"wrote {snippet_bundle.relative_to(ROOT)}")
    print(f"wrote {(ARTIFACT_DIR / 'summary.md').relative_to(ROOT)}")
    for path in snippet_paths.values():
        print(f"wrote {path.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
