# BinaryShield devirtualization presentation artifacts

Generated from `STRIGA_DEVIRT_DUMP_DIR=docs/devirt-presentation-artifacts` and selected resolver dumps for `0x140016000` and `0x14001676b`.

## Stage statistics

| File | Lines | @RAM refs | hooks | switches | unresolved | calls | loads | stores | constants |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---|
| `devirt-presentation-artifacts/resolvers/140016000-01-built.ll` | 215 | 99 | 0 | 0 | 0 | 1 | 0 | 153 |  |
| `devirt-presentation-artifacts/resolvers/140016000-02-inlined-before-hook-rewrite.ll` | 542 | 119 | 1 | 0 | 0 | 3 | 55 | 219 |  |
| `devirt-presentation-artifacts/resolvers/140016000-03-hook-rewritten.ll` | 707 | 119 | 0 | 0 | 0 | 2 | 110 | 219 |  |
| `devirt-presentation-artifacts/resolvers/140016000-04-optimized.ll` | 156 | 98 | 0 | 0 | 0 | 0 | 0 | 98 |  |
| `devirt-presentation-artifacts/resolvers/14001676b-01-built.ll` | 307 | 99 | 0 | 0 | 0 | 1 | 0 | 153 |  |
| `devirt-presentation-artifacts/resolvers/14001676b-02-inlined-before-hook-rewrite.ll` | 526 | 103 | 1 | 0 | 0 | 3 | 20 | 194 |  |
| `devirt-presentation-artifacts/resolvers/14001676b-03-hook-rewritten.ll` | 691 | 103 | 0 | 0 | 0 | 2 | 75 | 194 |  |
| `devirt-presentation-artifacts/resolvers/14001676b-04-optimized.ll` | 247 | 98 | 0 | 0 | 0 | 0 | 0 | 98 |  |
| `devirt-presentation-artifacts/recovered/01-skeleton-before-inline.ll` | 176045 | 80716 | 0 | 5 | 8 | 861 | 7 | 126207 |  |
| `devirt-presentation-artifacts/recovered/02-after-inline.ll` | 333313 | 83540 | 861 | 5 | 8 | 2961 | 13463 | 153817 | 0, 0, 0, 0, 0, 0, 0, 0, ... |
| `devirt-presentation-artifacts/recovered/03-after-vm-memory-localization.ll` | 413168 | 3685 | 861 | 5 | 8 | 2961 | 13463 | 153817 | 0, 0, 0, 0, 0, 0, 0, 0, ... |
| `devirt-presentation-artifacts/recovered/04-cleanup-round-1.ll` | 7507 | 1230 | 0 | 5 | 8 | 3 | 431 | 795 | 0, 0, 0, 0, 0, 0, 0, 0, ... |
| `devirt-presentation-artifacts/recovered/04-cleanup-round-8.ll` | 358 | 119 | 0 | 5 | 8 | 0 | 4 | 111 | 1859, 2418, 1638, 299902, 29763 |
| `devirt-presentation-artifacts/recovered/05-residual-before-final-pattern-cleanup.ll` | 326 | 86 | 0 | 5 | 8 | 6 | 4 | 72 | 1859, 2418, 1638, 299902, 29763 |
| `devirt-presentation-artifacts/recovered/06-final-clean.ll` | 16 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 1859, 2418, 1638, 299902, 29763 |

## Snippets

- `devirt-presentation-artifacts/snippets/resolver-built-call.ll`
- `devirt-presentation-artifacts/snippets/resolver-inlined-hook-call.ll`
- `devirt-presentation-artifacts/snippets/resolver-hook-rewritten-return.ll`
- `devirt-presentation-artifacts/snippets/resolver-optimized-target.ll`
- `devirt-presentation-artifacts/snippets/jcc-resolver-select.ll`
- `devirt-presentation-artifacts/snippets/recovered-skeleton-switch.ll`
- `devirt-presentation-artifacts/snippets/recovered-round8-first-compare.ll`
- `devirt-presentation-artifacts/snippets/recovered-residual-membership.ll`
- `devirt-presentation-artifacts/snippets/recovered-final.ll`
