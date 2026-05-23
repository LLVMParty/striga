# Production devirtualization plan

## Scope

Target Windows x86-64 PE binaries protected by VM-style obfuscators such as BinaryShield, VMProtect, Themida, and CodeVirtualizer. The output target is verified LLVM IR plus trace, diagnostic, and validation artifacts.

This plan assumes authorized samples. It avoids handler-to-instruction pattern matching and treats devirtualization as guided partial evaluation.

## Design principles from the Themida article

1. **Use guided symbolic evaluation.** Lift native VM handlers, seed known process and VM facts, fold concrete control-flow computations, and continue from resolved targets.
2. **Keep VM-specific knowledge narrow.** Avoid matching handler bodies back to x86 instructions. Encode only facts needed to guide evaluation: entry state, immutable byte ranges, VM-private memory ranges, VMEXIT classification, and virtual branch/VIP rules.
3. **Run optimizations to convergence.** Bytecode constant promotion, arithmetic folding, memory forwarding, branch folding, dead store elimination, and instruction combination enable each other.
4. **Model memory explicitly.** Promote loads only from immutable or tracked ranges. Track stores at byte granularity so overlapping stores and loads compose correctly.
5. **Represent RSP as a stack object when possible.** Stack accesses should fold through an alloca-backed or symbolic-base stack domain keyed by offsets from the entry stack pointer. Absolute concrete stack addresses are a prototype shortcut, not a production requirement.
6. **Preserve virtual control flow.** Record virtual instruction pointers and graph backedges to avoid unbounded unrolling.
7. **Split virtual branches by watched control state.** A virtual branch condition may appear in the final native handler target, the VIP snapshot, or both. The VM adapter should identify VIP and related control fields; the generic splitter should split finite expressions in those fields.
8. **Classify VMEXIT behavior by stack shape and VM conventions.** Calls, function returns, unsupported-instruction exits, and epilog returns need separate policies.
9. **Do liveness before final cleanup.** Registers and flags overwritten immediately after VMEXIT are dead outputs and should not anchor symbolic garbage.
10. **Use VPC-sensitive graph identity.** Per Pushan, CFG recovery should key structural nodes by virtual program counter and native instruction pointer, not by full path state.

## Target architecture

```text
config/spec  ─┐
container    ─┼─► lifter ─► resolver engine ─► trace graph ─► recovered IR ─► reports/tests
vm adapter   ─┘          ▲          │               │              │
semantics/tests ─────────┘          └─► artifacts ◄─┴─► validation ─┘
```

### 1. Configuration layer

Use a declarative spec instead of hard-coded constants.

Example fields:

```yaml
binary: tests/binaryshield.exe
architecture: x86_64
entry:
  native_function: 0x1400016d0
  vm_entry: 0x140017a41
  first_handler: 0x140016000
abi:
  args:
    - { name: rcx, type: i64 }
  return: rax
memory:
  immutable_ranges:
    - { name: image_text_rdata, from_sections: [ .text, .rdata ] }
  vm_private_ranges:
    - { name: vm_context, base: 0x10fd00, size: 0x400 }
    - { name: vm_stack, base: 0x10f000, size: 0x1000 }
process:
  stack_base: 0x110000
  teb_base: 0x120000
  peb_base: 0x130000
adapter: binaryshield
limits:
  max_nodes: 20000
  max_split_targets: 16
  max_unroll_per_vip: 2
call_policy: placeholder
```

Production requirements:

- Validate specs with a schema.
- Record the spec hash in every artifact.
- Permit adapter-provided defaults, but require explicit overrides for addresses and writable ranges.
- Separate immutable image sections from VM-private writable ranges.

### 2. Container and memory map

The container layer owns PE parsing, section permissions, relocations, imports, and byte reads.

Production requirements:

- Normalize VA/RVA/file offsets.
- Expose section permissions and relocation-applied bytes.
- Return immutable-read decisions through a policy object, not direct `get_data` calls scattered through tracing.
- Track a `static_memory_version` so caches invalidate if the binary or promotion policy changes.
- Report every promoted load with address, width, section, and reason.

### 3. Lifter and semantic validation

The lifter should remain VM-agnostic. It should expose lifted regions as functions with explicit state and memory parameters.

Production requirements:

- Keep one lifted function per native region or basic block.
- Avoid mutating original lifted functions during resolver construction.
- Add instruction-level semantic tests for flags, partial registers, shifts, rotates, stack operations, calls, returns, and SSE/XMM operations used by handlers.
- Add a differential test mode comparing lifted semantics against an emulator for selected native blocks.
- Represent unsupported instructions as explicit unsupported events with addresses.

### 4. Abstract state

Use an abstract domain that distinguishes concrete values, symbolic values, and unknown escaped values.

```python
AbsValue = Concrete(width, value) | Symbol(width, name) | Top(width, reason)
TraceState = {
    regs: dict[str, AbsValue],
    flags: dict[str, AbsValue],
    xmm: dict[str, AbsValue],
    mem: ByteMemory,
    stack: StackObject,
    env: ProcessFacts,
}
```

Production requirements:

- Stable symbol naming for reproducible logs and cache keys.
- Cache keys include concrete registers, flags, tracked memory bytes, adapter state, and memory policy version.
- `Top` prevents unsound concretization after unknown stores or pointer escapes.
- State snapshots include GPRs, flags, XMM values used by handlers, and tracked memory slots.

### 5. Byte-level memory and stack-object model

Model VM-private memory as intervals of bytes mapped to abstract values. Model the native stack as a separate object when stack addresses are derived from RSP.

Production requirements:

- Store and load at byte granularity.
- Compose overlapping stores into wider loads.
- Split wider stores into bytes or value slices.
- Invalidate ranges on unknown-width or symbolic-address stores.
- Mark memory domains as `immutable`, `vm_private`, `stack`, `program`, or `external`.
- Permit constant promotion only for `immutable` domains with no aliasing writes in the resolver.
- Permit forwarding from `vm_private` and `stack` tracked stores.
- Preserve `program` and `external` memory operations in recovered IR unless a user policy models them.
- Represent RSP as `(stack_object, offset)` or as an alloca-derived pointer plus offset when the address expression is RSP-relative.
- Keep stack offsets symbolic only when the expression is affine and bounded; otherwise mark the stack object escaped.
- Rewrite RSP-derived loads and stores to stack-object accesses before relying on LLVM alias analysis.

### 6. Resolver engine

A resolver evaluates one handler instance under one abstract state.

Production requirements:

- Build each resolver in a scratch module or isolated clone to avoid cross-contamination.
- Inline lifted code, rewrite boundary hooks to structured returns, fold memory, optimize, and read outcomes.
- Do not keep LLVM `Value` wrappers across `module.optimize()` if llvm-nanobind can invalidate them.
- Use named result fields or reconstruct handles after each optimization pass.
- Normalize exits into `{event, target, snapshot, path_condition}` records.
- Split finite `select`/`phi`/`switch` expressions in native targets and adapter-watched control fields within a configurable limit.
- Re-run simplification under each split predicate before reading the branch-specific snapshot.
- Emit unresolved diagnostics with the symbolic expression, dependency slice, and last promoted loads.

### 7. VPC-sensitive trace graph

The trace graph represents the virtualized function, including merges and loops. The structural node key follows Pushan's VPC sensitivity: virtual bytecode location plus native program location.

Production requirements:

- Node key: `(vip, rip, vm_instance)`.
- `vip` is the virtual program counter value or bytecode address for the active VM context.
- `rip` is the native interpreter location being emulated, usually a handler entry or native basic-block address.
- `vm_instance` distinguishes nested or multiple VMs; omit it for single-VM samples.
- Do not include full concrete state in graph node identity.
- Merge incoming abstract states at an existing `(vip, rip, vm_instance)` node.
- Re-queue a node when merging changes its abstract state, for example when differing constants widen to `Top` or a guarded value.
- Record additional incoming edges without re-emulating when the merged state is unchanged.
- Edge data: event, target, path condition, promoted loads, stores, and resolver artifact path.
- Detect existing nodes and record backedges instead of unrolling.
- Preserve all predecessors for PHI construction.
- Store unresolved edges with dependency diagnostics.
- Export GraphML/DOT/JSON for visualization and regression diffs.

Separate graph identity from resolver caching. The resolver outcome cache may include an abstract-state fingerprint or state-version number because simplification results can depend on known constants. The CFG node identity remains `(vip, rip, vm_instance)` so loops and converging paths do not explode into path-specific nodes.

### 8. VM adapter interface

Adapters encode narrow VM-specific guidance.

```python
class VMAdapter:
    def initial_state(spec, container) -> TraceState: ...
    def identify_vip(state, resolver_ir, outcome) -> AbsValue: ...
    def watched_control_fields(spec) -> list[ControlField]: ...
    def classify_exit(outcome, state) -> VMExit: ...
    def call_policy(exit, state) -> CallAction: ...
    def private_memory_ranges(spec, container) -> list[Range]: ...
```

Generic adapter duties:

- Seed ABI inputs and concrete process facts.
- Treat unresolved finite target and watched-control-field expressions generically.
- Classify normal `jmp`, `ret`, `call`, and `syscall` hooks.

BinaryShield adapter duties:

- Provide entry constants, return sentinel policy, and VM-private range defaults.
- Avoid handler-address fast paths.
- Remove sample-specific final cleanup from the core engine and move it into an optional report simplifier.

Themida adapter duties:

- Track VM context pointer, virtual stack, handler table, VIP field, and optional `branch_taken_flag` field from the spec or discovery pass.
- Classify VMEXIT by stack-object offset and adapter-provided stack layout rules.
- Expose VIP as a watched control field so the generic splitter can split path-specific VIP values even when the native handler target is the same on both paths.
- Record backward VIP updates as loop candidates.
- Handle nested virtualization by allowing adapter state to contain a VM-depth or active-context identifier.

### 9. Recovered IR builder

Build one recovered LLVM function per virtualized function from the graph.

Production requirements:

- Initialize ABI inputs in one entry block.
- Use a single state object plus localized VM memory allocas.
- Create one basic block per graph node.
- Inline lifted handlers in graph order.
- Rewrite resolved hook exits to `br`, `switch`, `call`, or `ret`.
- Preserve unresolved exits as explicit trap/placeholder blocks with diagnostics.
- Use LLVM to create PHIs through `mem2reg`/SROA where possible.
- Preserve program memory accesses and remove VM-private stores after localization.

### 10. Optimization passes

Use standard LLVM passes plus small domain-specific passes.

Required passes:

- Constant promotion from immutable memory.
- Byte-level store-to-load forwarding for VM-private memory.
- Constant folding and instruction combine to convergence.
- DSE restricted to VM-private memory.
- Branch folding after target splitting.
- Dead dependency analysis for output registers and flags.
- Stack pointer rewrite from stack-object offsets to RSP-relative form.
- RAM brightening for remaining program memory references.

Acceptance rules:

- A pass must state which memory domains it may read or mutate.
- A pass must emit counters for changes made.
- A pass must have unit tests for alias, overlap, and escaped-pointer cases.

### 11. Calls, syscalls, and VMEXIT

Production recovery needs a policy for every non-jump exit.

Call policies:

1. `placeholder`: emit an external declaration with conservative clobbers.
2. `recursive`: recover the target as another virtualized function.
3. `native`: emit a direct call to a known imported or image function.
4. `unresolved`: stop with diagnostics.

VMEXIT classification data:

- RSP stack-object offset from entry RSP.
- Return target value.
- Call target value and return address slot.
- Native continuation address.
- Adapter-specific exit sentinel values.

Acceptance rules:

- Calls preserve ABI argument registers and stack-passed arguments.
- Unknown indirect calls are explicit in IR.
- Syscalls require a user-selected model or remain unresolved.

### 12. LLVM IR output contract

Recovered LLVM IR is the final artifact.

Production requirements:

- Emit one verified LLVM module per recovered virtualized function or function group.
- Emit stable function names, block names, and metadata linking recovered blocks to `(vip, rip, vm_instance)` graph nodes.
- Preserve modeled external calls, syscalls, and program memory effects explicitly.
- Remove VM-private memory, bytecode dispatch, handler-table lookups, and boundary hooks when resolved.
- Leave unresolved control transfers as explicit trap or placeholder blocks with diagnostics.
- Emit a machine-readable manifest listing ABI inputs, return value source, external effects, unresolved edges, and validation status.

### 13. Validation strategy

Use layered validation.

Unit tests:

- PE mapping and relocation reads.
- Byte-level memory load/store composition.
- Immutable promotion with aliasing writes.
- Resolver hook rewriting.
- Finite target splitting.
- Trace graph loop detection.
- VMEXIT classification.
- Dead dependency pruning.

Integration tests:

- Synthetic VM samples with known source functions.
- BinaryShield sample currently in the repository.
- Authorized Themida/CodeVirtualizer samples with simple arithmetic, branches, loops, and calls.

Differential tests:

- Execute original virtualized code and recovered IR on generated inputs.
- Compare return values, live output registers, and modeled memory effects.
- Use fuzzed inputs for small functions.
- Use SMT or alive-style equivalence checks for straight-line recovered blocks where feasible.

Regression artifacts:

- Resolver IR snapshots.
- Recovered IR snapshots per cleanup round.
- Trace graph JSON/DOT.
- Stage statistics: lines, hooks, `@RAM` refs, unresolved edges, calls, loads, stores, constants.
- HTML reports generated from artifacts.

### 14. Observability and diagnostics

Every unresolved edge should explain why tracing stopped.

Diagnostic fields:

- Virtual IP and native RIP.
- Symbolic target expression.
- Dependency slice for the target.
- Loads promoted during the resolver.
- Loads refused by memory policy.
- Stores that invalidated a memory range.
- Path condition if the edge came from a split.
- Optimization pass counters.

CLI commands:

```bash
striga-devirt trace --config sample.yml --json trace.json --dot trace.dot
striga-devirt recover --config sample.yml --trace trace.json --out recovered.ll
striga-devirt report --config sample.yml --artifacts artifacts/ --out report.html
striga-devirt validate --config sample.yml --inputs corpus.json
```

### 15. Performance and caching

Production tracing needs deterministic caching.

Requirements:

- Cache lifted blocks by `(binary_hash, address, lifter_version)`.
- Cache resolver outcomes by `(vip, rip, state_version_or_fingerprint, adapter_key, memory_policy_version, lifter_version)`.
- Cache optimization artifacts only when debug dumps are enabled.
- Bound finite branch splitting and path conditions.
- Use per-function work queues and persist partial graphs after crashes.
- Record cache hit rates in reports.

### 16. Safety boundaries in the engine

Do not silently produce clean IR when assumptions fail.

Failure modes that must stay explicit:

- Symbolic handler target with no finite constant set.
- Store to immutable promoted byte range.
- Symbolic store into VM-private memory that aliases live tracked slots.
- Dynamic stack allocation or symbolic stack arithmetic that escapes stack-object offset tracking.
- Dispatch depending on undefined flags.
- Unmodeled syscalls or indirect calls.
- Path explosion beyond configured limits.

## Repo refactor plan

Move the prototype out of `devirt.py` into modules while keeping a thin compatibility CLI.

```text
src/striga/devirt/
  __init__.py
  config.py          # YAML/spec parsing and schema validation
  absstate.py        # AbsValue, TraceState, stable naming
  memory.py          # byte-level domains and promotion policy
  resolver.py        # handler resolver construction and outcome reading
  graph.py           # worklist, node keys, serialization
  recover.py         # recovered LLVM IR construction
  passes.py          # RAM folding, localization, brightening, DDA
  diagnostics.py     # structured unresolved-edge reports
  validation.py      # differential execution hooks
  adapters/
    generic.py
    binaryshield.py
    themida.py
cli/
  striga_devirt.py
```

Short-term extraction order:

1. Extract `AbsValue`, `TraceState`, `TraceGraph`, and serialization.
2. Extract memory folding and VM memory localization behind a `MemoryPolicy`.
3. Extract resolver construction and hook rewriting.
4. Extract recovered IR construction.
5. Replace hard-coded BinaryShield constants with a config file and adapter.
6. Move `_try_clean_binaryshield_membership_ir` into a sample report/simplifier, outside the core engine.
7. Add snapshot generation as a first-class artifact API instead of environment-variable-only dumps.

## Milestones

### M0: stabilize the current prototype

Deliverables:

- Keep `devirt.py` working as a compatibility entrypoint.
- Add artifact validation for trace graph, recovered IR, and final report.
- Document llvm-nanobind lifetime rules in developer notes.

Acceptance:

- BinaryShield recovery still produces verified 16-line IR.
- No `@RAM`, `__striga_*`, `switch`, or `unresolved` remains in the final sample IR.
- `python -X faulthandler devirt.py` exits 0.

### M1: configuration and module split

Deliverables:

- `DevirtConfig` schema.
- `binaryshield.yml` sample.
- Modular package structure under `src/striga/devirt`.

Acceptance:

- No BinaryShield addresses are hard-coded in the core engine.
- Trace and recovery can run from config.

### M2: production memory model

Deliverables:

- Byte-level `MemoryDomain` implementation.
- Immutable promotion policy.
- Store/load forwarding tests.

Acceptance:

- Overlapping store/load tests pass.
- Writes to immutable ranges stop promotion and emit diagnostics.
- Unknown stores mark affected domains `Top` instead of folding stale bytes.

### M3: resolver and graph hardening

Deliverables:

- Scratch-module resolver API.
- Finite target splitter with path-specific snapshots.
- Graph serialization and loop detection.

Acceptance:

- Synthetic loop VM records a backedge without unbounded unrolling.
- VJCC-like synthetic handler produces two resolved edges when either the native target or the watched VIP field contains a finite branch expression.

### M4: Themida adapter MVP

Deliverables:

- Themida config fields for VM context, handler table, VIP, virtual stack, and optional branch flag.
- Watched-control-field splitter that handles VJCC path-specific VIP updates without handler-address matching.
- VMEXIT classifier based on stack-object offset and adapter rules.

Acceptance:

- Authorized Themida branch sample recovers both branch edges.
- Authorized Themida loop sample records a loop header/backedge.
- Authorized Themida call sample emits the selected call policy.

### M5: recovered IR quality

Deliverables:

- Dead dependency analysis.
- Stack-object to RSP-relative rewrite.
- VM-private DSE and RAM brightening.

Acceptance:

- Recovered IR for synthetic samples contains no VM-private memory operations.
- Live outputs match emulator results across fuzzed inputs.
- Dead flags overwritten after VMEXIT do not remain as recovered outputs.

### M6: reporting and validation harness

Deliverables:

- `striga-devirt report` HTML output.
- Differential test runner.
- Corpus metadata format.

Acceptance:

- Every run emits trace graph, stage stats, unresolved diagnostics, and final IR verification status.
- Regression reports can diff graph size, unresolved edge count, and IR token counts.

## Production readiness checklist

A devirtualization run is production-ready when:

- The input spec, binary hash, engine version, and adapter version are recorded.
- All assumptions are represented in the config or diagnostics.
- Every promoted load has a policy reason.
- Every unresolved edge has a dependency slice.
- The recovered IR verifies under LLVM.
- Differential tests pass for the configured input corpus.
- The final report lists remaining external calls, memory effects, and unsupported instructions.
- The final LLVM IR and manifest identify every remaining external effect and unresolved transfer.
