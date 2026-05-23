# VIP/RIP-sensitive devirtualization library plan

## Purpose

This document defines a simpler mental model and a library shape for experimenting with VM devirtualization. The goal is verified recovered LLVM IR, not native patching.

The library should make common devirtualization patterns explicit:

- VM bytecode loads becoming constants.
- Handler dispatch target computation collapsing to a finite native target set.
- Virtual branch target computation producing finite VIP successors.
- VM context and VM stack traffic folding away.
- Loop handling through `(vip, rip)` graph identity plus abstract-state joins.
- Optional SMT use for expression simplification and finite value enumeration, without path-constraint solving.

## Mental model

A virtualization-protected function runs at two program counters:

| Counter | Meaning |
|---|---|
| `rip` | Native instruction pointer inside the interpreter or handler code. |
| `vip` | Virtual instruction pointer into the VM bytecode stream. |

A devirtualization graph node should identify a VM interpreter context by both:

```text
ProgramPoint = (vip, rip, vm_instance)
```

For a single VM instance:

```text
ProgramPoint = (vip, rip)
```

Why both fields are needed:

- `rip` alone merges all executions of the same handler, even when the handler is interpreting different bytecode instructions.
- `vip` alone merges different native interpreter blocks that happen to operate on the same bytecode site.
- `(vip, rip)` separates interpreter context without making the graph path-sensitive.
- Full register and memory state should not be part of the structural graph key because that causes path explosion.

The node has an abstract state, but the state is joined at the node:

```text
node identity: (vip, rip)
node facts:    abstract registers, flags, VM memory, stack object, expression facts
```

When a new edge reaches an existing node:

1. Join incoming state into the existing node state.
2. If the join changes the node state, requeue the node.
3. If the join changes nothing, record the edge and stop.

This is the Pushan-style fixed-point idea: recover structure by revisiting `(vip, rip)` points only when their abstract facts change.

## Strategy

The strategy is constraint-free symbolic devirtualization:

1. Lift native interpreter code to LLVM IR.
2. Evaluate a handler or native block under an abstract state.
3. Fold immutable bytecode and image loads.
4. Forward tracked VM-memory and stack-object stores into later loads.
5. Optimize until dispatch expressions simplify.
6. Read expressions for watched control fields:
   - next native target `rip_out`
   - next virtual target `vip_out`
   - VM exit event
   - ABI-visible outputs
7. Enumerate finite `(vip_out, rip_out)` pairs.
8. Add graph edges without asking whether a user input can satisfy the branch condition.
9. Recover LLVM IR from the graph and optimize away VM machinery.

This is symbolic execution in the sense that registers and memory can hold expressions. It is not dynamic symbolic execution because the engine does not accumulate path constraints and does not solve for program inputs.

## Mixed native/VIP discovery

Native CFG discovery and VIP-sensitive bytecode discovery should run in one worklist, not as two separate phases.

Each work item is an abstract interpreter context:

```text
Frame = (vip_context, rip, abstract_state)
```

`rip` is the native basic block to lift next. `vip_context` is the best known bytecode position for this native execution context. The engine repeatedly lifts native blocks, folds bytecode-dependent expressions under the current VIP, and adds resolved successors back to the same worklist.

The graph being built is a specialized native CFG:

```text
Node = (vip_context, rip)
Edge = native transfer, virtual transfer, VM exit, unresolved transfer
```

A block is therefore not just `rip = 0x401000`; it is `rip = 0x401000 while interpreting vip = 0x1234`. The same native block can appear multiple times under different VIPs, and that is the mechanism that turns one interpreter CFG into a bytecode-sensitive CFG.

Pseudo-code:

```python
worklist = [(entry_vip, entry_rip, entry_state)]

while worklist:
    vip, rip, state = worklist.pop()
    node = graph.get_or_create(vip, rip)
    if not graph.join_state(node, state):
        continue

    block = lifter.lift_basic_block(rip)
    result = evaluator.run(block, state, vip_context=vip)

    for exit in result.exits:
        for succ in split_exit(exit):
            graph.add_edge(node, succ.point, succ.condition, succ.effects)
            worklist.push((succ.vip, succ.rip, succ.state))
```

The evaluator does not need to know whether it is inside a dispatch loop, a threaded handler, or a superhandler. It follows native control flow until it reaches a transfer, and every transfer is interpreted under the current VIP context.

### Transfer classification

Every lifted native block ends in one of these transfer shapes:

| Transfer shape | Example | Action |
|---|---|---|
| Direct native branch | `br label %x` | Add successor `(same_vip, target_rip)`. |
| Conditional native branch | `br cond, a, b` | Fold/prune if condition is constant; otherwise add both `(same_vip, a)` and `(same_vip, b)`. |
| Indirect native branch | `jmp expr` | Enumerate finite native targets; successor is `(current_or_updated_vip, target_rip)`. |
| VIP update plus loop-back | `vip = vip + size; jmp dispatch` | Add `(vip_out, dispatch_rip)`. |
| VM branch | `vip = select(cond, a, b); jmp dispatch` | Add `(a, dispatch_rip)` and `(b, dispatch_rip)`. |
| VM exit | `ret`, sentinel, call exit | Emit recovered return/call/syscall edge. |
| Unknown | symbolic non-finite target or escaped VIP | Emit unresolved edge with expression slice. |

The important part is that `same_vip` is allowed. While walking through an if/else opcode chain, the VIP does not change yet, so all native branch successors stay in the same VIP context until the selected opcode body updates VIP.

### Classical dispatch loop

A classical VM often has one interpreter loop with an opcode chain:

```c
for (;;) {
    op = *vip++;
    if (op == OP_ADD) {
        dst = *vip++;
        src = *vip++;
        vreg[dst] += vreg[src];
    } else if (op == OP_JZ) {
        rel = read_i32(vip);
        vip += flag_z ? rel : 4;
    } else if (op == OP_RET) {
        return vreg[0];
    }
}
```

Native BFS can discover the interpreter blocks, but bytecode CFG recovery is driven by partial evaluation at concrete VIP contexts.

Start with:

```text
(vip = bytecode_entry, rip = dispatch_loop_head)
```

During resolution:

1. The opcode load `load(vip)` folds from immutable bytecode to a constant.
2. The opcode chain comparisons fold, so only the matching native branch remains.
3. Operand loads from `vip + k` fold to constants.
4. The chosen opcode body updates VM state and computes `vip_out`.
5. Returning to the dispatch loop creates a virtual successor `(vip_out, dispatch_loop_head)`.
6. If `vip_out` is finite but conditional, create one successor per finite value and keep the condition as edge metadata.

Example:

```text
bytecode[0x1000] = OP_ADD
bytecode[0x1001] = dst
bytecode[0x1002] = src
```

The dispatch chain becomes:

```text
op = load(0x1000)              -> OP_ADD
op == OP_ADD                   -> true
op == OP_JZ                    -> dead
vip_out                        -> 0x1003
successor                      -> (0x1003, dispatch_loop_head)
```

For a virtual branch:

```text
bytecode[0x1003] = OP_JZ
vip_out = select(flag_z, 0x1040, 0x1008)
rip_out = dispatch_loop_head
```

Successors:

```text
(0x1040, dispatch_loop_head) under flag_z
(0x1008, dispatch_loop_head) under !flag_z
```

The engine never needs an opcode table for this case. The interpreter's own comparison chain acts as the decoder once the opcode byte is promoted to a constant.

There are two useful exploration granularities:

| Granularity | Node key | Use |
|---|---|---|
| Flat native CFG | `(current_vip, native_basic_block_rip)` | Pushan-style complete interpreter-aware CFG recovery. |
| VM-instruction step | `(instruction_start_vip, dispatch_rip)` | Cleaner experiments and recovered virtual CFG construction. |

The flat mode may contain native blocks inside the opcode chain. The VM-step mode treats those blocks as internal to `resolve_point` and emits only virtual-instruction successors. The library should expose both modes because flat mode is better for research diagnostics and VM-step mode is easier for users to inspect.

## Superhandlers and sub-opcodes

A superhandler is handled by the same mixed worklist. The only difference is that the native region may decode more than one bytecode field before producing the next `(vip, rip)` successor.

Example:

```c
op = *vip++;
if (op == OP_ALU) {
    sub = *vip++;
    a = *vip++;
    b = *vip++;

    if (sub == SUB_ADD) vreg[a] += vreg[b];
    if (sub == SUB_OR)  vreg[a] |= vreg[b];
    if (sub == SUB_XOR) vreg[a] ^= vreg[b];

    goto dispatch;
}
```

For `vip = 0x2000`, the evaluator folds:

```text
op  = load(0x2000) -> OP_ALU
sub = load(0x2001) -> SUB_XOR
a   = load(0x2002) -> 3
b   = load(0x2003) -> 5
```

Native branches inside the superhandler collapse under the same VIP context:

```text
sub == SUB_ADD -> false
sub == SUB_OR  -> false
sub == SUB_XOR -> true
```

The successor is:

```text
(vip = 0x2004, rip = dispatch_loop_head)
```

If the sub-opcode is not concrete because the VM bytecode is self-modified or stored in unknown memory, the sub-opcode chain remains a finite native branch set only if the expression can be enumerated. Otherwise the edge is unresolved or over-approximated under a configured limit.

This gives one rule for dispatch loops, threaded handlers, and superhandlers:

```text
Keep walking native CFG under the current VIP context.
When bytecode loads fold, native decoder branches collapse.
When VIP changes, future nodes use the new VIP context.
When native RIP changes without VIP changing, future nodes keep the same VIP context.
```

## Do we need symbolic execution and SMT?

Yes, but the required form is narrow.

### Required symbolic execution

The engine needs an expression domain for values that are not concrete:

```python
Expr = Const(width, value)
     | Var(width, name)
     | BinOp(op, Expr, Expr)
     | UnOp(op, Expr)
     | Extract(high, low, Expr)
     | Concat(parts)
     | Select(cond, then_expr, else_expr)
     | Top(width, reason)
```

The expression domain is used for:

- target expressions that LLVM cannot reduce to constants;
- VIP expressions at virtual branches;
- opaque predicate guards;
- abstract-state joins;
- diagnostics explaining unresolved edges.

### Required SMT

SMT should be an optional backend for a few bounded operations:

| Operation | Query shape | Path constraints? |
|---|---|---|
| `is_constant(expr)` | Check if `expr != candidate` is satisfiable. | No |
| `enumerate_values(expr, limit)` | Ask for models of `expr`, block each found value. | No |
| `simplify(expr)` | Use solver rewriting or custom MBA simplifier. | No |
| `is_always_false(cond)` | Check if `cond` is satisfiable. | No |

The engine should not ask the solver for inputs that drive a path. It should ask what values a target expression can take in isolation.

### Why LLVM is not enough

LLVM optimization handles many concrete and algebraic reductions, especially after bytecode loads are promoted. It may fail on:

- MBA-obfuscated target arithmetic;
- opaque predicates encoded as hard bit-vector formulas;
- values widened to symbolic at loop headers;
- expressions extracted from memory joins;
- finite target expressions hidden behind arithmetic rather than explicit `select` or `switch`.

A practical implementation should start LLVM-first, then use expression extraction and SMT only when LLVM leaves a watched control field unresolved.

## Core data types

### ProgramPoint

```python
@dataclass(frozen=True)
class ProgramPoint:
    vip: AbsValue        # usually concrete; may be symbolic during discovery
    rip: int            # native handler/basic-block address
    vm_instance: int = 0
```

Behavior:

- Used as structural graph identity when `vip` is concrete.
- If `vip` is symbolic but finite, split before creating successors.
- If `vip` is symbolic and not finite, create an unresolved edge.

### AbsValue

```python
AbsValue = Concrete(width, value) | Symbol(width, name) | ExprValue(width, expr) | Top(width, reason)
```

Behavior:

- `Concrete` participates in cache keys.
- `Symbol` names unknown inputs or widened values.
- `ExprValue` carries a reducible expression.
- `Top` means the engine lost enough precision that folding would be unsound.

### AbstractState

```python
@dataclass
class AbstractState:
    regs: RegFile
    flags: FlagFile
    xmm: XmmFile
    memory: DomainMemory
    stack: StackObject
    facts: FactSet
```

Behavior:

- Holds dataflow facts for a node.
- Is joined at existing `(vip, rip)` nodes.
- Does not define graph identity.

### DomainMemory

```python
DomainKind = Literal["immutable", "vm_private", "stack", "program", "external"]
```

Behavior:

- `immutable`: bytecode, handler tables, read-only image bytes; loads may become constants.
- `vm_private`: VM context and VM stack; loads may forward tracked stores.
- `stack`: native stack object; RSP-relative accesses fold by offset.
- `program`: original program memory; preserve in recovered IR unless modeled.
- `external`: OS, heap, MMIO, unknown; do not fold without a model.

### StepResult

```python
@dataclass
class StepResult:
    point: ProgramPoint
    exits: list[ExitExpr]
    state_snapshot: AbstractState
    diagnostics: list[Diagnostic]
```

Behavior:

- Produced by resolving one `(vip, rip)` under a node state.
- Contains expressions for watched control fields after LLVM and memory simplification.

### ExitExpr

```python
@dataclass
class ExitExpr:
    event: Literal["jmp", "call", "ret", "syscall", "unresolved"]
    rip_out: Expr | Const | Top
    vip_out: Expr | Const | Top | None
    path_condition: Expr | None
    effects: EffectSet
```

Behavior:

- `rip_out` is the native continuation.
- `vip_out` is the virtual continuation if the adapter can identify it.
- `path_condition` is diagnostic and IR-building information; it is not accumulated as a global path constraint.

## High-level helper APIs

### `resolve_point`

```python
result = devirt.resolve_point(point, state)
```

Behavior:

1. Lift or fetch native code at `point.rip`.
2. Build an LLVM resolver with state and memory inputs.
3. Inline lifted code.
4. Rewrite control hooks into structured resolver returns.
5. Fold immutable loads and tracked VM/stack memory.
6. Optimize.
7. Extract watched expressions and a state snapshot.

Guarantees:

- Never silently folds a load from writable or unknown memory.
- Emits diagnostics for unsupported instructions and escaped memory.
- Does not mutate cached lifted functions.

### `enumerate_successors`

```python
edges = devirt.enumerate_successors(result, limit=16)
```

Behavior:

1. Collect finite values of `rip_out` and `vip_out`.
2. Split `select`, `phi`, small switches, and solver-enumerable expressions.
3. Produce one edge per finite `(vip_out, rip_out)` pair.
4. Preserve path conditions as edge metadata.

Guarantees:

- Does not check path feasibility.
- Over-approximates when necessary.
- Returns an unresolved edge when a finite set cannot be proven under limits.

### `join_node_state`

```python
changed = graph.join_node_state(point, incoming_state)
```

Behavior:

- Merges incoming facts into the node facts.
- Equal constants stay constant.
- Different constants widen to `Top` or a guarded-value set, depending on the configured domain.
- Symbolic values with different names merge to `Top` unless a value-set domain is enabled.

Guarantees:

- Monotonic: repeated joins reach a fixed point.
- Emits symbolization diagnostics when constants widen.

### `explore_cfg`

```python
graph = devirt.explore_cfg(entry_point, entry_state)
```

Behavior:

1. Pop a point from the worklist.
2. Resolve the point under its current abstract state.
3. Enumerate successors.
4. Add edges.
5. Join successor states into successor nodes.
6. Requeue changed nodes.
7. Stop at fixed point or configured limits.

Guarantees:

- Graph identity is `(vip, rip, vm_instance)`.
- Resolver cache may use state fingerprints, but graph identity does not.
- Backedges are recorded without unbounded unrolling.

### `recover_llvm_ir`

```python
module = devirt.recover_llvm_ir(graph, abi)
```

Behavior:

1. Build one recovered LLVM function.
2. Create one basic block per `(vip, rip)` graph node or per simplified virtual block.
3. Materialize ABI inputs.
4. Inline lifted semantics or reconstructed semantic fragments.
5. Rewrite resolved edges to LLVM branches/switches/returns/calls.
6. Localize VM-private memory to allocas.
7. Optimize until VM scaffolding dies.
8. Verify the LLVM module.

Guarantees:

- Returns verified LLVM IR or a structured failure.
- Leaves unresolved transfers as explicit trap/placeholder blocks.
- Emits a manifest of external effects and assumptions.

## Common patterns as reusable recognizers

Recognizers should produce facts, not perform sample-specific rewrites.

### Immutable bytecode load

Pattern:

```text
load(memory, bytecode_base + constant_offset)
```

Action:

- Replace with a constant if the address range is immutable and no resolver store aliases it.

### VM-private store/load forwarding

Pattern:

```text
store(vm_context + k, value)
...
load(vm_context + k)
```

Action:

- Forward `value` if no intervening aliasing store invalidates the bytes.

### Stack-object access

Pattern:

```text
load(rsp + k)
store(rsp + k, value)
```

Action:

- Convert to stack-object offset access.
- Forward through the stack memory model.

### Direct virtual branch

Pattern:

```text
vip_out = select(cond, vip_a, vip_b)
rip_out = handler_next
```

Action:

- Produce two graph edges:
  - `(vip_a, handler_next)` under `cond`
  - `(vip_b, handler_next)` under `!cond`

### Handler-dispatch branch

Pattern:

```text
rip_out = select(cond, handler_a, handler_b)
vip_out = vip_next
```

Action:

- Produce two graph edges:
  - `(vip_next, handler_a)`
  - `(vip_next, handler_b)`

### Combined virtual and native branch

Pattern:

```text
vip_out = select(cond, vip_a, vip_b)
rip_out = select(cond, handler_a, handler_b)
```

Action:

- Pair values by shared path condition.
- Avoid Cartesian product unless path conditions are independent or unknown.

### Opaque interpreter branch

Pattern:

```text
branch(mba_condition, target_a, target_b)
```

Action:

- If `mba_condition` is always true or false under constraint-free simplification, prune the impossible native edge.
- If it remains symbolic, keep both edges.

### Loop state symbolization

Pattern:

```text
edge reaches existing (vip, rip)
incoming_state.x = Const(a)
existing_state.x = Const(b)
a != b
```

Action:

- Join to `Top`, `Symbol`, or `ValueSet({a, b})` depending on the domain.
- Requeue the node if the state changed.

## Library module layout

```text
src/striga/devirt/
  concepts.py        # ProgramPoint, Edge, Event, Effect
  expr.py            # expression DSL and simplifiers
  smt.py             # optional Z3 translation/enumeration
  absstate.py        # AbsValue, AbstractState, joins
  memory.py          # DomainMemory, StackObject, policies
  resolver.py        # LLVM resolver engine
  split.py           # finite target/VIP enumeration
  graph.py           # VPC-sensitive worklist algorithm
  recover.py         # recovered LLVM IR builder
  diagnostics.py     # structured explanations
  artifacts.py       # dumps, reports, manifests
  adapters/
    generic.py       # default watched fields and exits
    binaryshield.py  # sample config defaults only
    themida.py       # VIP/context discovery and VMEXIT rules
```

## Experiment-first CLI

```bash
striga-devirt explain-config sample.yml
striga-devirt inspect-point sample.yml --vip 0x1678f --rip 0x140016000
striga-devirt step sample.yml --vip 0x1678f --rip 0x140016000 --dump-ir artifacts/step/
striga-devirt enumerate sample.yml --vip 0x1678f --rip 0x140016000 --dump-expr artifacts/expr/
striga-devirt graph sample.yml --out artifacts/graph.json --dot artifacts/graph.dot
striga-devirt recover sample.yml --graph artifacts/graph.json --out recovered.ll
striga-devirt report sample.yml --artifacts artifacts/ --out report.html
```

The `inspect-point`, `step`, and `enumerate` commands are for learning and debugging. They should print:

- the current `(vip, rip)`;
- watched control fields;
- promoted loads;
- refused loads;
- extracted expressions;
- finite successor pairs;
- unresolved reasons.

## SMT backend plan

Start with an optional dependency:

```toml
[project.optional-dependencies]
smt = ["z3-solver>=4.13"]
```

Implement four APIs:

```python
class SolverBackend:
    def simplify(self, expr: Expr) -> Expr: ...
    def is_constant(self, expr: Expr, width: int) -> int | None: ...
    def enumerate_values(self, expr: Expr, width: int, limit: int) -> list[int] | TooMany | Unknown: ...
    def is_unsat_bool(self, expr: Expr) -> bool | Unknown: ...
```

Rules:

- No accumulated path constraints.
- Per-query timeout.
- Width-aware bit-vector translation only.
- Refuse memory arrays initially; translate only scalar expressions.
- Store SMT-LIB2 dumps for failed or slow queries.

## First examples to build

### Example 1: finite virtual branch

A toy handler returns:

```text
vip_out = select(rcx == 0, 0x20, 0x30)
rip_out = 0x1000
```

Expected successors:

```text
(0x20, 0x1000)
(0x30, 0x1000)
```

### Example 2: same handler, different VIP

Two bytecode sites use the same native handler:

```text
(0x20, 0x1000)
(0x30, 0x1000)
```

Expected graph:

- two nodes because VIP differs;
- no path-specific node duplication for different input expressions.

### Example 3: loop widening

A loop reaches the same `(vip, rip)` with different loop-counter constants.

Expected behavior:

- first revisit widens the counter;
- node is requeued;
- later revisit does not unroll indefinitely.

### Example 4: opaque native branch

A native interpreter branch has an MBA guard that is always true.

Expected behavior:

- solver or simplifier prunes the false native edge;
- no path constraint is used.

### Example 5: Themida-style VJCC shape

A toy handler computes:

```text
branch_taken_flag = flags.zf
vip_out = select(branch_taken_flag, vip + rel, vip + fallthrough_size)
rip_out = next_dispatch_handler
```

Expected behavior:

- adapter identifies `vip_out` as a watched control field;
- generic splitter creates two virtual successors;
- no VJCC handler-address special case is needed.

## Development milestones

### C0: concept library skeleton

Deliverables:

- Dataclasses for `ProgramPoint`, `AbsValue`, `AbstractState`, `ExitExpr`, and `Edge`.
- Markdown docs with examples above.
- Unit tests for graph identity and state joins.

### C1: expression DSL and finite splitter

Deliverables:

- Expression classes for constants, variables, bit-vector ops, and select.
- Finite splitter for constants, select trees, and small value sets.
- Pretty printer and JSON serialization.

Acceptance:

- Toy virtual branch examples produce expected `(vip, rip)` successors.

### C2: optional SMT backend

Deliverables:

- Z3 translator for scalar bit-vector expressions.
- Constraint-free constant check and value enumeration.
- Query timeout and SMT-LIB dump support.

Acceptance:

- MBA target toy examples enumerate finite target values under limits.

### C3: LLVM resolver integration

Deliverables:

- Resolver returns watched control fields as LLVM values.
- Extract constants, select trees, and supported scalar expressions from LLVM.
- Fall back to unresolved diagnostics when extraction fails.

Acceptance:

- Existing BinaryShield first handlers still resolve through LLVM-only paths.
- Synthetic VJCC resolver splits on VIP even when native target is identical.

### C4: VPC-sensitive graph explorer

Deliverables:

- Worklist keyed by `(vip, rip)`.
- State joins and requeue-on-change.
- Graph JSON/DOT output.

Acceptance:

- Synthetic loops do not unroll indefinitely.
- Existing BinaryShield trace can be represented in the new graph model.

### C5: recovered LLVM IR builder

Deliverables:

- Build LLVM IR from graph edges.
- Localize VM-private memory.
- Verify final module.

Acceptance:

- BinaryShield sample still recovers clean verified LLVM IR.
- Reports show promoted loads, resolved edges, unresolved edges, and final IR status.
