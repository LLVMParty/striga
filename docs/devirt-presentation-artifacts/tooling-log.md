# Presentation tooling log

## Dump run

```bash
STRIGA_DEVIRT_DUMP_DIR=docs/devirt-presentation-artifacts \
STRIGA_DEVIRT_DUMP_TRACE_ADDRS=0x140016000,0x14001676b \
  uv run python -X faulthandler devirt.py > docs/devirt-presentation-artifacts-run.log 2>&1
```

Result: exit code 0.

Generated resolver snapshots:

- `resolvers/140016000-01-built.ll`
- `resolvers/140016000-02-inlined-before-hook-rewrite.ll`
- `resolvers/140016000-03-hook-rewritten.ll`
- `resolvers/140016000-04-optimized.ll`
- `resolvers/14001676b-01-built.ll`
- `resolvers/14001676b-02-inlined-before-hook-rewrite.ll`
- `resolvers/14001676b-03-hook-rewritten.ll`
- `resolvers/14001676b-04-optimized.ll`

Generated recovered-function snapshots:

- `recovered/01-skeleton-before-inline.ll`
- `recovered/02-after-inline.ll`
- `recovered/03-after-vm-memory-localization.ll`
- `recovered/04-cleanup-round-1.ll`
- `recovered/04-cleanup-round-8.ll`
- `recovered/05-residual-before-final-pattern-cleanup.ll`
- `recovered/06-final-clean.ll`

## Summary extraction

```bash
uv run python docs/generate_devirt_presentation_artifacts.py
```

Generated:

- `ir-stage-stats.json`
- `ir-stage-stats.csv`
- `summary.md`
- `ir-snippets.md`
- `snippets/*.ll`

## Presentation validation

```bash
uv run python docs/validate_devirt_presentation.py
```

Observed output:

```text
sections=13
toc_links=13
code_blocks=24
tables=4
presentation validation passed
```

## Code validation

```bash
uv run python -m py_compile devirt.py docs/generate_devirt_presentation_artifacts.py docs/validate_devirt_presentation.py
uv run ruff check devirt.py docs/generate_devirt_presentation_artifacts.py docs/validate_devirt_presentation.py
uv run python -X faulthandler devirt.py
```

Observed:

- Ruff passed.
- `devirt.py` completed with exit code 0.
- Final recovered IR has 16 lines.
- Final recovered IR contains no `@RAM`, `__striga_*`, `switch`, or `unresolved` tokens.
