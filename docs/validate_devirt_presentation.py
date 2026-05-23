from __future__ import annotations

import re
from html.parser import HTMLParser
from pathlib import Path

ROOT = Path(__file__).resolve().parent
HTML = ROOT / "binaryshield-devirt-presentation.html"
ARTIFACTS = ROOT / "devirt-presentation-artifacts"

REQUIRED_SECTIONS = {
    "problem",
    "pipeline",
    "state",
    "resolver",
    "memory",
    "graph",
    "recovery",
    "intermediate",
    "optimization",
    "result",
    "verification",
    "specifics",
    "limits",
}

REQUIRED_SNIPPETS = {
    "resolver-built-call.ll",
    "resolver-inlined-hook-call.ll",
    "resolver-hook-rewritten-return.ll",
    "resolver-optimized-target.ll",
    "jcc-resolver-select.ll",
    "recovered-skeleton-switch.ll",
    "recovered-round8-first-compare.ll",
    "recovered-residual-membership.ll",
    "recovered-final.ll",
}


class StructureParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.sections: set[str] = set()
        self.links: list[str] = []
        self.code_blocks = 0
        self.tables = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr = dict(attrs)
        if tag == "section" and attr.get("id"):
            self.sections.add(attr["id"] or "")
        if tag == "a" and attr.get("href"):
            self.links.append(attr["href"] or "")
        if tag == "pre":
            self.code_blocks += 1
        if tag == "table":
            self.tables += 1


def main() -> None:
    html = HTML.read_text(encoding="utf-8")
    parser = StructureParser()
    parser.feed(html)

    missing_sections = sorted(REQUIRED_SECTIONS - parser.sections)
    assert not missing_sections, f"missing sections: {missing_sections}"

    missing_links = sorted(f"#{section}" for section in REQUIRED_SECTIONS if f"#{section}" not in parser.links)
    assert not missing_links, f"missing toc links: {missing_links}"

    snippet_dir = ARTIFACTS / "snippets"
    missing_snippets = sorted(name for name in REQUIRED_SNIPPETS if not (snippet_dir / name).exists())
    assert not missing_snippets, f"missing snippets: {missing_snippets}"

    required_terms = [
        "Intermediate IR snapshots",
        "VM-specific knowledge encoded",
        "Final membership cleanup",
        "STRIGA_DEVIRT_DUMP_DIR",
        "recovered-round8-first-compare.ll",
        "recovered-residual-membership.ll",
        "_try_clean_binaryshield_membership_ir",
        "llvm-nanobind stale wrappers",
    ]
    for term in required_terms:
        assert term in html, f"missing term: {term}"

    final_ir = (ARTIFACTS / "recovered" / "06-final-clean.ll").read_text(encoding="utf-8")
    constants = {int(x) for x in re.findall(r"icmp eq i32 %x, (\d+)", final_ir)}
    assert constants == {1859, 2418, 1638, 299902, 29763}, constants
    for banned in ["@RAM", "__striga_", "switch ", "unresolved"]:
        assert banned not in final_ir, banned

    print(f"sections={len(parser.sections)}")
    print(f"toc_links={len(parser.links)}")
    print(f"code_blocks={parser.code_blocks}")
    print(f"tables={parser.tables}")
    print("presentation validation passed")


if __name__ == "__main__":
    main()
