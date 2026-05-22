# Striga: VM Devirtualization via LLVM-Guided Partial Evaluation

## Problem

A VM obfuscator encodes native x86-64 logic as bytecode. Native dispatcher and handler code reads the bytecode stream, computes the next handler, and updates a VM state. The goal is to recover LLVM IR for the original program while deleting dispatcher logic, handler-table lookups, bytecode decoding, and VM bookkeeping.

The recovered IR should use Striga's existing lifted x86 semantics. The devirtualizer should avoid VM-specific names such as "bytecode pointer register" or "opcode register" unless a user supplies them as optional hints.

## Core approach

Treat devirtualization as partial evaluation:

- Values known at devirtualization time are represented as constants.
- Runtime program data is represented as symbolic parameters.
- Static image and bytecode loads are folded from the input container when the address is concrete and the range is immutable.
- LLVM optimization propagates constants through lifted handler IR.
- The trace engine reads the optimized boundary value: next handler target, VM event kind, and post-handler state.

Concrete means known during tracing. It includes VM state, bytecode-derived operands, and original program constants. It is not a proof that a value is VM-internal. VM code disappears later because inlined handler code that only feeds concrete dispatch state becomes dead.

## Existing IR model

The lifter already emits one function per lifted native region:

```llvm
define void @lifted_0xADDR(ptr noalias %state, ptr noalias %memory) alwaysinline
```

`%state` points to Striga's `%State` struct. It contains GPRs, `gsbase`, XMM registers, and flags. GPRs and `gsbase` are `i64`; flags are `i8`; XMM registers are `i128`.

`%memory` is modeled as an `i8` address space rooted at `@RAM`. A memory access at native address `A` appears as a GEP from `@RAM` by integer offset `A` after the wrapper binds `%memory` to `@RAM`.

Control-flow boundary hooks:

| Hook                       | Current meaning                                      |
|----------------------------|------------------------------------------------------|
| `__striga_jmp(i64)`        | Non-constant jump target                             |
| `__striga_call(i64)`       | Call target event; current lifted code then falls through |
| `__striga_ret(i64)`        | Return target event                                  |
| `__striga_syscall(i64)`    | Syscall event at the instruction address             |

Direct native jumps inside a lifted handler are normal LLVM branches. They do not call `__striga_jmp`.

## Trace state

Use an explicit abstract state instead of equating constants with VM internals.

```python
TraceState:
    regs: dict[str, AbsValue]
    mem:  dict[ConcreteAddress, AbsValue]   # bounded VM scratch/stack domain
    env:  concrete process facts            # imagebase, TEB/PEB model, stack base

AbsValue:
    Concrete(width, value)
    Symbol(width, name)
```

Rules:

1. Every `%State` field is initialized before calling a lifted handler. Use a concrete constant or a resolver parameter. Never rely on `undef`, poison, or uninitialized `alloca` contents.
2. Symbolic fields use stable symbol names so logs and cache keys are reproducible.
3. The trace cache key contains the handler address plus all concrete register and tracked-memory entries. Symbol names are not part of the cache key.
4. The memory domain starts small: VM stack slots, VM context slots, and synthetic TEB/PEB slots that have concrete addresses. Static image bytes are folded separately from this domain.

## Phase 1: trace one handler instance

Input: `(handler_addr, TraceState)`.

Output: one or more `TraceOutcome` records:

```python
TraceOutcome:
    event: "jmp" | "call" | "ret" | "syscall" | "unresolved"
    target: int | SymbolicTarget
    post_state: TraceState
```

### 1. Lift or fetch the handler

Call `lift_bfs(module, container, handler_addr)` if the handler has not been lifted. The lifted function may contain direct branches and may end at one or more boundary hook calls.

### 2. Build a resolver function

Build the resolver as a temporary internal function. It may live in the main module with a unique name or in a scratch module if cross-module cloning is available.

The resolver has one parameter for each symbolic register and tracked symbolic memory slot in the input `TraceState`. It is not a zero-argument function.

Resolver body:

1. Allocate `%State`.
2. Store concrete state fields as constants.
3. Store symbolic state fields from resolver parameters.
4. Materialize the synthetic environment: imagebase, TEB/PEB facts, stack base, and tracked memory slots.
5. Call an internal clone of `@lifted_0xADDR(%state, @RAM)`.
6. Temporarily end with `unreachable` or a dummy return.

The clone keeps the original lifted signature. Do not mutate the original function's return type. If the implementation optimizes the whole module, remove `alwaysinline` before adding `optnone/noinline`, then restore the original attributes after cleanup. A scratch module avoids this attribute juggling.

### 3. Inline, then rewrite boundary hooks

Run `always-inline` so the clone body is inside the resolver. Rewrite boundary hook calls inside the resolver, not inside the original lifted function.

For each inlined boundary call:

- `__striga_jmp(target)` becomes a resolver return with event `jmp`, target, and a full state snapshot.
- `__striga_ret(target)` becomes a resolver return with event `ret`, target, and a full state snapshot.
- `__striga_call(target)` becomes a resolver return with event `call`, target, and a full state snapshot.
- `__striga_syscall(addr)` becomes a resolver return with event `syscall`, address, and a full state snapshot.

A state snapshot loads every `%State` field and every tracked memory slot. The resolver return type is chosen up front, for example:

```llvm
%TraceResult = type { i8 event, i64 target, %StateSnapshot snapshot }
```

This avoids changing a cloned function's return type after creation.

### 4. Fold static memory loads

Walk only the resolver. Replace a load with a constant when all conditions hold:

1. The pointer is `@RAM + constant_offset`.
2. The full loaded byte range is inside a known immutable image/bytecode region.
3. No store in the resolver can alias the loaded byte range.
4. The load width and endianness are known.

Use `container.get_data(va, size)` to produce the integer constant. Leave loads from writable sections, stack, heap, or unknown pointers symbolic. If a store to an immutable folded range is observed, stop folding that range and report self-modifying or unsupported behavior.

Tracked VM scratch memory is handled by the `TraceState.mem` map. A load from a tracked concrete address returns its abstract value. A store to a tracked concrete address updates the map. A symbolic address escapes the map and may force the affected memory domain to symbolic.

### 5. Optimize the resolver

Run a scalar pipeline on the resolver, such as:

```text
always-inline,instcombine,sroa,early-cse<memssa>,gvn,simplifycfg,adce,dse
```

`default<O1>` or `default<O2>` can be used after the hook rewrite if the resolver and clones are isolated. Avoid leaving external side-effectful hook calls in code intended for optimization.

### 6. Normalize exits

Read every resolver return. Each return contains an event, target expression, and snapshot expression.

Cases:

1. Constant target: emit one `TraceOutcome`.
2. Multiple returns with constant targets: emit one outcome per return.
3. Finite target expression: split it.
4. Symbolic target with no finite constant set: emit `unresolved`.

A finite target expression is usually a `select`, `phi`, or switch-like expression whose leaves are constant handler addresses. This corresponds to a virtual conditional branch.

Target splitting procedure:

1. Recursively collect constant leaves and their predicates from `select` and `phi` target expressions.
2. For each target leaf, clone the resolver exit or insert an `llvm.assume` for the leaf predicate.
3. Re-run instcombine/simplifycfg on the small clone.
4. Read the snapshot under that predicate.
5. Fields that fold to constants become concrete in that branch's `post_state`; the rest become symbolic.

If the finite set is too large, use a configurable limit and mark the edge unresolved.

### 7. Classify the post-state

For each outcome and each snapshot field:

- Constant integer: `Concrete(width, value)`.
- Non-constant value: `Symbol(width, stable_name)`.

Do not label a constant as VM-internal at trace time. Phase 2 and LLVM DCE decide which concrete work is dead.

### 8. Cache and cleanup

Cache outcomes by:

```python
(handler_addr, trace_state.concrete_key(), static_memory_version)
```

Erase temporary resolver functions and clones. Restore original lifted function attributes if the main module was used.

## Phase 1b: worklist graph construction

The trace result is a graph, not an ordered list.

```python
worklist = [entry_node]
graph = Graph()
visited = set()

while worklist:
    node = worklist.pop()
    if node.key in visited:
        continue
    visited.add(node.key)

    outcomes = trace_handler(node.addr, node.state)
    for outcome in outcomes:
        edge = graph.add_edge(node, outcome)
        if outcome.event == "jmp" and isinstance(outcome.target, int):
            succ = Node(outcome.target, outcome.post_state)
            graph.bind(edge, succ)
            if succ.key not in visited:
                worklist.append(succ)
```

Node identity:

```python
NodeKey = (handler_addr, post_state.concrete_key())
```

If an edge reaches an existing node, keep the edge. That edge is either a merge or a loop backedge. Do not discard it because Phase 2 needs all predecessors for correct PHI construction.

Unresolved edges stay in the graph with diagnostics. They may later become indirect calls, indirect jumps, or user-guided branches.

## Phase 2: recover executable LLVM IR

Phase 2 rebuilds the traced VM program as one LLVM function, then lets LLVM erase the VM implementation.

### 2.1 Build the skeleton

Create one recovered function per virtualized function:

```llvm
define i64 @recovered(i64 %arg0, i64 %arg1, ...) {
entry:
  %state = alloca %State
  br label %node_entry
}
```

Use a single `%State` alloca for the whole recovered function. Initialize ABI inputs or user-selected program inputs into symbolic state fields at entry. Initialize known entry VM fields as constants.

For each trace graph node, create one LLVM basic block.

At the start of a node block:

1. Store every concrete field from the node's `TraceState` into `%state`.
2. Store tracked concrete memory slots if Phase 2 models them directly.
3. Do not store symbolic fields. Their values flow from predecessors through `%state`.
4. Call the corresponding lifted handler with `(%state, @RAM)`.
5. End with a temporary terminator.

This structure lets SROA/mem2reg create PHIs for symbolic program data at merges and loop headers.

### 2.2 Inline handlers and lower dispatch

Run `always-inline` on the recovered function. Then rewrite inlined boundary hooks in each node block according to graph edges.

For a node with one concrete successor:

```llvm
br label %succ
```

For a node with multiple finite successors, keep the computed target expression and lower it to a switch:

```llvm
switch i64 %target, label %unresolved [
  i64 0x140016000, label %node_A
  i64 0x14001604e, label %node_B
]
```

Using a switch avoids extracting a flag condition by hand. If the target was computed as `select %cond, A, B`, LLVM will reduce the switch to a branch on `%cond` during cleanup.

For a `ret` event, branch to a function exit block or return the selected ABI result, such as `%rax`.

For a `call` event, choose a policy:

- recursively devirtualize the callee and emit a call to the recovered callee;
- emit a call to an external placeholder;
- mark the edge unresolved.

For a `syscall` event, emit the project-specific syscall model or an external placeholder.

Do not leave side-effectful `__striga_*` calls in optimized recovered code. Rewritten hooks should become branches, returns, or explicit modeled calls. Unhandled hooks should branch to an unresolved block.

### 2.3 Optimize recovered IR

Run:

1. `always-inline` if any lifted calls remain.
2. `sroa`, `mem2reg`, `instcombine`, `gvn`, `simplifycfg`, `dse`, `adce`, or `default<O1/O2>`.
3. `rewrite_ram_geps` for remaining `@RAM + constant` address expressions.
4. A second cleanup pipeline.

Expected result:

- VM dispatch target computations are dead.
- Bytecode loads used only for dispatch are gone.
- Handler-table loads are gone.
- VM state stores that do not affect program outputs are gone.
- Remaining branches are original program branches.
- Remaining memory accesses are program memory accesses or modeled external effects.

## RAM brightening

After optimization, rewrite remaining GEPs rooted at `@RAM`:

```llvm
getelementptr i8, ptr @RAM, i64 C  -->  inttoptr (i64 C to ptr)
```

Then optimize again. This recovers normal-looking pointer accesses for image globals, stack addresses that survived modeling, and external memory references.

Only apply this pass to remaining program memory operations. Static bytecode loads should already have folded or died.

## Post-processing

### Type recovery

Recovered IR is integer-heavy. Apply standard recovery rules:

- Load/store widths reveal object field widths.
- `trunc`, `zext`, and `sext` reveal original operand sizes.
- Known imports and syscalls constrain call signatures.
- Pointer arithmetic around `inttoptr` addresses identifies globals and structure fields.

### Stack frame recovery

Surviving stack-relative accesses can be converted into `alloca` slots when the base stack object and offsets are known. Stack slots that were only used by the VM should disappear during Phase 2 optimization.

### Function boundaries

A `ret` event terminates the current recovered function. A `call` event needs a call policy: recursive devirtualization, external placeholder, or unresolved edge.

## Implementation order

### Milestone 1: constant-target tracing

- Build resolver functions with all unknown registers passed as parameters.
- Inline one lifted handler into the resolver.
- Rewrite `__striga_jmp` to return `{event, target, snapshot}`.
- Fold immutable `@RAM + constant` loads from `Container`.
- Resolve one constant next-handler target.
- Cache by `(handler_addr, concrete_key)`.

Acceptance checks:

- No resolver uses uninitialized state.
- The first BinaryShield handler resolves the same next target as an emulator trace.
- Folded bytecode loads are visible in debug logs with address, size, and value.

### Milestone 2: finite branch targets

- Detect finite `select`/`phi` target expressions.
- Split branch outcomes and read branch-specific concrete state.
- Add graph edges for both sides of a virtual conditional branch.

Acceptance checks:

- A virtualized conditional jump produces two graph edges.
- Reaching an existing node records a backedge instead of unrolling forever.

### Milestone 3: recovered CFG

- Build one recovered function from the trace graph.
- Use one `%State` alloca across the function.
- Inline handlers.
- Rewrite hook calls to direct branches or `switch` terminators.
- Run cleanup optimization.

Acceptance checks:

- Optimized recovered IR contains no `__striga_jmp` calls for resolved edges.
- Branches remain where the original virtual program branches.
- Merges and loops verify under LLVM without manually constructed PHIs.

### Milestone 4: concrete memory domain

- Track concrete VM stack/context slots in `TraceState.mem`.
- Fold loads from tracked concrete slots.
- Invalidate or symbolize memory ranges on unknown stores.

Acceptance checks:

- A handler that spills bytecode pointer or dispatch state to stack still resolves.
- Aliasing stores prevent unsound folding from the container.

### Milestone 5: calls and function recovery

- Define a calling-convention model for virtualized functions.
- Recover callees recursively or emit placeholders.
- Add return-value and clobber modeling.

## Soundness boundaries

1. Static folding is sound only for immutable bytes. Self-modifying bytecode or writable handler tables require a different memory model.
2. A handler target that remains symbolic after finite-target splitting is an unresolved indirect control transfer.
3. Register-only tracing is incomplete for VMs that spill dispatch state to memory. Track VM stack/context memory before treating unresolved edges as semantic failures.
4. Undefined x86 flags are modeled by helper calls. If dispatch depends on an undefined flag, the target may remain symbolic by design.
5. LLVM optimization is the completeness boundary. If a dispatch computation is semantically constant but LLVM cannot prove it with the available facts, the trace stops or needs a stronger simplification pass.

## Data flow summary

```text
Container bytes ─────────────┐
                             │
x86 bytes ─► lift_bfs ─► lifted handler IR
                             │
                             ▼
                     trace_handler(addr, state)
                       clone + resolver
                       inline
                       fold immutable @RAM loads
                       optimize
                       read event/target/snapshot
                             │
                             ▼
                     trace graph nodes/edges
                             │
                             ▼
                     recover_ir(graph)
                       one State alloca
                       inline handlers
                       rewrite hooks to branches/switches
                       optimize
                       rewrite @RAM GEPs
                             │
                             ▼
                     recovered program LLVM IR
```
