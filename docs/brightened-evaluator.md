# Symbolic-but-brightened evaluator

## Goal

Build one native step at a time, return control to the devirtualization algorithm at a conditional or indirect transfer, then optimize the lifted prefix with enough semantic facts to expose its behavior.

This is the interactive primitive behind `(vip, rip)` exploration:

```text
(vip, rip, state)
  -> lift native prefix from rip
  -> follow fallthrough and direct jmp targets implicitly
  -> yield at conditional branches, indirect branches, calls, returns, or cutpoints
  -> wrap with symbolic sources and observable sinks
  -> rewrite object memory and fold image loads
  -> optimize
  -> read branch target, VIP update, and state effects
```

## Native discovery rule

A direct unconditional jump is part of the current native region:

```asm
jmp 0x140016000
```

The lifter follows it and keeps lifting. This handles handlers split across distant blocks and chained by `jmp addr`.

A conditional or indirect transfer yields:

```asm
jz  opcode_add       ; yield: branch condition may fold after brightening
jmp rax              ; yield: indirect dispatch target may fold after brightening
ret                  ; yield: VMEXIT or native return candidate
```

The devirtualization algorithm inspects the optimized result, decides which successor(s) are known, then calls the lifter again.

## Why source/sink functions help

A source function creates a named unknown value:

```llvm
declare i64 @source_rcx() memory(none)
```

A sink function keeps an output observable:

```llvm
declare void @sink_rcx(i64)
```

The wrapper uses sources for unknown program inputs and object sources for environment anchors:

```llvm
%stack_top = call i64 @source_env_stack_top()
%teb_base  = call i64 @source_env_teb_base()
%rcx0      = call i64 @source_rcx()

store i64 %stack_top, ptr %state.rsp
store i64 %teb_base,  ptr %state.gsbase
store i64 %rcx0,      ptr %state.rcx

call void @lifted_0x140017a41(ptr %state, ptr %memory)

%rax1 = load i64, ptr %state.rax
call void @sink_rax(i64 %rax1)
```

LLVM optimizes through the lifted code while sinks preserve selected outputs. This gives a readable optimized summary of a partial handler without requiring a full custom LLVM symbolic executor.

## Memory model used by the brightener

The lifted function still uses Striga's generic memory argument:

```llvm
define void @lifted_0xADDR(ptr noalias %state, ptr noalias %memory)
```

The bright wrapper also takes `%memory` as a `ptr noalias` argument. It does not require a global `@RAM`.

The brightener classifies memory addresses by provenance:

| Address expression | Meaning | Rewrite |
|---|---|---|
| `source_env_stack_top() + k` | native stack object | local alloca slot |
| `source_env_teb_base() + 0x60` | Windows TEB PEB pointer | `source_env_peb_base()` |
| `source_env_peb_base() + 0x10` | Windows PEB imagebase | container image base constant |
| `imagebase + rva` | PE image byte | bytes from `Container` |

No user-visible fake addresses are needed. The object sources are analysis tokens, not runtime addresses.

## Required custom passes around LLVM

LLVM does not know the binary image or VM memory policy. The evaluator supplies these facts:

1. **Environment-object rewriting**: rewrite stack, TEB, and PEB accesses by provenance.
2. **Immutable image folding**: replace `load %memory[constant_image_va]` with bytes from the PE.
3. **Stack localization**: rewrite stack-object memory to a local alloca so SROA/DSE can remove stack traffic.
4. **Boundary memory snapshots**: preserve modified stack slots with `sink_stack_iN(offset, value)` so transition state survives DSE.
5. **Boundary instrumentation**: preserve direct branch targets with `sink_exit_rip(target)` so `simplifycfg` cannot erase the branch distinction before inspection.
6. **Hook preservation**: indirect exits remain visible through `__striga_jmp(target)`, `__striga_ret(target)`, etc.

## Tool

`tools/bright_step.py` implements the current interactive prototype.

Example: start at BinaryShield VM entry. The tool follows the direct `jmp 0x140016000` into the first handler and yields at the handler's indirect dispatch.

```bash
uv run python tools/bright_step.py \
  --rip 0x140017A41 \
  --out-dir devirt-output/bright-step-auto-vmentry
```

Observed boundary:

```text
lifted 0x140017a41 until 0x14001604c: jmp rax
```

The raw boundary is indirect, but after brightening and optimization the summary shows:

```llvm
call void @__striga_jmp(i64 5368799489) ; 0x140016101
```

The final IR also contains boundary stack snapshots for values pushed by VM entry and the first handler:

```llvm
call void @sink_stack_i64(i64 -256, i64 5368709120)
call void @sink_stack_i64(i64 -136, i64 %rflags_snapshot)
call void @sink_stack_i64(i64 -8, i64 92047)
```

That means the evaluator resolved the dispatch target using:

- stack-object forwarding of the pushed bytecode RVA;
- TEB/PEB object rewriting;
- imagebase recovery from the container;
- immutable image load folding;
- LLVM optimization.

## Stage outputs

Each run writes:

```text
01-built.ll
02-inlined.ll
04-opt-round-XX.ll
05-final.ll
summary.md
```

Use these stages to see which fact enabled each simplification. Stack stores may appear as local alloca stores in an intermediate stage and as `sink_stack_iN` calls in the final stage. The final calls are the boundary state that a later `(vip, rip)` step would consume.

## How this connects to full devirtualization

The full explorer will call the same primitive repeatedly.

```python
step = bright_step(vip, rip, state)
successors = read_observable_exits(step)
for vip_out, rip_out in successors:
    graph.add_edge((vip, rip), (vip_out, rip_out))
```

For classical dispatch loops, the helper yields at each conditional opcode-test branch. If the opcode load folds, the condition becomes constant and the algorithm continues through the selected native edge under the same VIP. For threaded handler dispatch, `__striga_jmp(target)` usually gives the next native RIP directly. For superhandlers, direct jumps and fallthrough remain internal; conditional sub-opcode tests yield and then fold under the current VIP context.
