# LLVM IR concolic VM-entry engine

## Purpose

`tools/vmentry_concolic.py` bootstraps a virtualized function from the native VM-entry stub to the first VM control boundary. It answers the first question every VM devirtualizer needs answered:

```text
Given a protected entry RIP, what concrete native VM handler or VM dispatcher does this entry reach,
and which constants, stack values, image bytes, and runtime stores explain that target?
```

The engine is an initial-stage executor for virtual machines that hide their first dispatch target behind native setup code. It lifts each native instruction to LLVM IR with Striga semantics, interprets that LLVM IR, follows branches whose conditions are concrete, applies memory writes to a mutable overlay, and stops when lifted control-flow reaches a boundary helper such as `__striga_jmp`.

The output is a report that contains:

- the entry address;
- the stop address and native boundary instruction;
- the boundary helper (`__striga_jmp`, `__striga_call`, `__striga_ret`, symbolic branch, or step limit);
- the concrete target when known;
- a symbolic/provenance expression explaining the target;
- seed candidates and the subset involved in the boundary expression;
- a native trace prefix;
- the lifted LLVM module used during the run.

This engine connects native VM-entry setup to the later `(vip, rip)` handler-graph recovery stage. The handler graph needs a starting handler RIP and an explanation of where the initial VPC/VIP state came from. VM-entry code often computes both through stack seeds, image tables, return addresses, and runtime relocation loops. Static lifting and one-shot optimization do not reliably preserve that causal chain. The concolic engine preserves it while executing the concrete path.

## Why VM-entry needs a separate executor

VM-entry code differs from a normal VM handler. A handler usually consumes an existing VM state: VPC/VIP, virtual stack pointer, virtual registers, and a dispatcher pointer. Entry code constructs that state from native context.

Common entry work includes:

- pushing or moving an encrypted bytecode/VPC seed;
- deriving an image address from that seed;
- reading handler tables or bytecode tables from the image;
- deriving the image base from the process environment;
- relocating tables from RVAs to VAs;
- writing relocated values back to writable image memory;
- entering a native dispatcher with an indirect jump.

A pure static pass sees instructions and constants but misses runtime memory effects. A pure concrete emulator can produce the target but loses the expression explaining the target. The VM-entry concolic engine keeps both values: concrete integers for execution and symbolic/provenance text for analysis.

## Concolic value model

The executor represents each integer as `SymVal`:

```text
SymVal = concrete value + bit width + expression text + optional address object + provenance deps
```

The concrete value drives execution. The expression and dependency set explain why the value exists.

Examples:

```text
0x1678f/*push_imm@0x140017a41*/
0x16101/*image_backing@0x140016041:0x14001678f*/{addr=(...)}
overlay_store[0x1401890f9](...)/*overlay_store@0x1401bae54:0x1401890f9*/
control_load[0x1401890f9](...)/*control_load@0x1401baf5d:0x1401890f9*/
```

A value may fold to a plain constant after arithmetic. The `deps` field keeps provenance markers even when expression text no longer contains the original marker. Reports append missing dependency markers as `{deps=...}`.

The current seed kinds are:

| Seed kind | Meaning |
|---|---|
| `imm` | Immediate candidate from a native instruction. Used for auditability, but excluded from control provenance unless promoted by another kind. |
| `push_imm` | Immediate pushed by entry code. This is a common VPC/VIP seed. |
| `mov_imm` | Immediate materialized with `mov` or `movabs`. |
| `lea_addr` | RIP-relative address materialized by `lea`. |
| `call_return` | Return address pushed by a followed call. Themida-style stubs often derive image base or VPC state from this value. |
| `image_backing` | Value read from the initial PE image before overlay writes. This names the backing store, not the current runtime memory cell. |
| `overlay_store` | Value written into mutable memory during execution. This records relocation and self-modifying data effects. |
| `control_load` | Final memory load used by an indirect control boundary, such as `jmp qword ptr [rax]`. |

`image_base` is modeled as an environment constant. It is not a seed. The seed is the protected-program datum that selects or transforms VM state. For VMProtect, the entry `push imm` is the seed; image reads derived from that seed are consequences.

## Execution pipeline

The engine repeats this loop until a boundary condition stops it:

```text
rip
  -> decode native instruction with Capstone
  -> record immediate/address seed candidates
  -> lift instruction or followed call into Striga LLVM IR
  -> interpret the lifted LLVM IR block
  -> update register state and memory overlay
  -> follow concrete LLVM branches
  -> stop at symbolic branch, ret, unsupported terminator, or __striga_* boundary
```

The engine does not invoke `emulate.py`. Native behavior flows through Striga's LLVM IR semantics, and the executor interprets that IR.

### Lifting

Striga lifts x86-64 instructions into a function with two logical objects:

```llvm
define void @lifted_0xADDR(ptr noalias %state, ptr noalias %memory)
```

`%state` contains architectural registers and flags. `%memory` is the process memory abstraction. Control transfers that cannot remain inside the lifted native region are represented through helper calls:

```llvm
call void @__striga_jmp(i64 %target)
call void @__striga_call(i64 %target)
call void @__striga_ret(i64 %target)
call void @__striga_syscall(i64 %site)
```

The concolic executor interprets these helpers as boundaries and records the target expression.

### Calls selected for following

Some protectors enter a VM through an ordinary native `call`. The engine follows only user-selected call sites:

```bash
--follow-call 0x1401BA2A8
```

A followed call is rewritten as:

```text
push fallthrough_return_address
branch call_target
```

This preserves the return-address push as `call_return@...` and lets the executor run into the callee. This behavior is needed for Themida-style setup code that uses the call return address as a base anchor.

### Branches and loops

Concrete conditional branches are followed internally. Direct unconditional branches are followed as part of normal LLVM block execution. Constant loops execute normally until they exit or the step limit is reached.

Symbolic branches stop execution because the engine is a single-path bootstrapper. It does not fork paths or solve path constraints. This design matches the VM-entry use case: the concrete process state usually determines the entry path, while the provenance expression explains that path.

## Memory model

The memory model has three layers:

```text
environment objects -> mutable overlay -> initial image backing -> unknown or zero policy
```

### Environment objects

The executor models selected Windows environment reads as object-relative values:

- `rsp` starts as a stack object, not a hardcoded concrete stack address.
- `gsbase` starts as a TEB object.
- TEB/PEB reads can recover the image base from the container.

This avoids fake stack, TEB, PEB, and GS addresses in the analysis model. These objects are analysis anchors, not runtime address guesses.

### Mutable overlay

Every concrete memory store updates an overlay before later reads consult the initial image. This behavior is required for VM-entry code that relocates tables in place.

The overlay preserves exact-width stores and byte-level stores. A sub-width read from a wider exact store keeps the store's provenance. This matters for instructions such as `push imm64` followed by a 32-bit read from the same stack slot.

### Initial image backing

A read from a concrete image address without a prior overlay write creates an `image_backing` seed:

```text
image_backing@INSN:ADDRESS
```

The name means “read the initial file/mapped image bytes.” It does not imply that the same instruction is the logical source of the final control target. If a later relocation store overwrites that address, the final value is represented through `overlay_store` and `control_load`.

### Unknown concrete memory

`--zero-unknown-abs` treats concrete non-image memory without prior writes as zero-initialized:

```bash
--zero-unknown-abs
```

This is an exploration policy for cases such as private lock variables or uninitialized protector state. It should be replaced by explicit private-memory and lock-state models when the target requires higher fidelity.

## Provenance preservation

The executor tracks provenance through:

- LLVM integer arithmetic: add, sub, mul, divisions, remainders, and/or/xor, shifts;
- casts: trunc, zext, sext;
- selects and integer comparisons;
- LLVM funnel shifts (`llvm.fshl.*`, `llvm.fshr.*`);
- register loads and stores through `%state`;
- memory loads, stores, partial reads, and byte reassembly;
- XOR cancellation used by stack-cookie-style patterns.

Provenance has two channels:

1. expression text, such as `0x1678f/*push_imm@...*/`;
2. dependency markers in `SymVal.deps`.

The dependency set prevents optimized or simplified expressions from dropping the causal relationship. VMProtect shows why this matters: the final target expression may fold to constants after multiple transformations, but the involved seed list still identifies the original `push_imm` seed.

## Boundary reporting

The report separates three questions that often become conflated:

1. Which value came from the initial image?
2. Which runtime store changed memory?
3. Which memory load supplied the indirect target?

Themida demonstrates the distinction:

```text
image_backing@0x1401bae32:0x1401890f9
overlay_store@0x1401bae32:0x1401890f9
overlay_store@0x1401bae50:0x1401890f9
overlay_store@0x1401bae54:0x1401890f9
control_load@0x1401baf5d:0x1401890f9
```

The first item is the initial table value read from the image. The overlay stores record the relocation writes. The control load records the `jmp qword ptr [rax]` dereference that actually supplies the boundary target.

A simplified reading of the Themida chain is:

```text
initial table RVA 0x118c8
  -> add relocation arithmetic
  -> add image-base expression derived from call_return@0x1401ba2a8
  -> store relocated VA 0x1400118c8 back to 0x1401890f9
  -> jmp qword ptr [0x1401890f9]
```

This distinction prevents a report from claiming that the relocation instruction “is the control load.” It is one producer in the memory-history chain that the control load later consumes.

## Example runs

### BinaryShield

Command:

```bash
uv run python tools/vmentry_concolic.py \
  --binary tests/binaryshield.exe \
  --rip 0x140017A41 \
  --out-dir devirt-output/vmentry-concolic-binaryshield
```

Observed result:

```text
stop:       0x14001604c
instruction jmp rax
boundary:   __striga_jmp
concrete:   0x140016101
```

Relevant provenance:

```text
push_imm@0x140017a41 = 0x1678f
image_backing@0x140016041:0x14001678f = 0x16101
```

The pushed bytecode RVA selects the image-backed table entry. The table entry yields the first handler/dispatch target after image-base addition.

### VMProtect

Command:

```bash
uv run python tools/vmentry_concolic.py \
  --binary tests/basic_vm_targets.309.dll \
  --rip 0x1800E3C42 \
  --follow-call 0x1800E3C47 \
  --out-dir devirt-output/vmentry-concolic-vmprotect
```

Observed result:

```text
stop:       0x18004ba98
instruction jmp rdi
boundary:   __striga_jmp
concrete:   0x180082187
```

Relevant provenance:

```text
push_imm@0x1800e3c42 = 0xffffffff939f5a2f
image_backing@0x1800286c7:0x1800cf295 = 0xcd50e79e
```

The entry `push imm` is the seed. The image-backed read is derived from that seed. The report keeps the push provenance even when the final expression folds through arithmetic.

### Themida

Command:

```bash
uv run python tools/vmentry_concolic.py \
  --binary tests/example2-virt.bin \
  --rip 0x140001000 \
  --follow-call 0x1401BA2A8 \
  --zero-unknown-abs \
  --out-dir devirt-output/vmentry-concolic-themida \
  --max-steps 200000
```

Observed result:

```text
stop:       0x1401baf5d
instruction jmp qword ptr [rax]
boundary:   __striga_jmp
steps:      23714
concrete:   0x1400118c8
```

Relevant provenance:

```text
call_return@0x1401ba2a8 = 0x1401ba2ad
image_backing@0x1401bae32:0x1401890f9 = 0x118c8
overlay_store@0x1401bae54:0x1401890f9 = 0x1400118c8
control_load@0x1401baf5d:0x1401890f9 = 0x1400118c8
```

The result shows that Themida relocates a table entry during VM entry. A pre-relocated memory override would hide the mechanism. The executor observes the initial image value, the runtime stores, and the final control load.

## Synthetic VM coverage

The repository also contains small VM examples that exercise dispatch patterns without protector noise. They use the exported `vm_ifelse` functions and show how the same executor behaves when the VM dispatcher is a switch loop, a threaded table, a wrapper around an older interpreter body, or an if/else cascade.

| Sample | Entry | Design | PC location | Observed boundary |
|---|---:|---|---|---|
| `tests/minivm-switch.exe` | `0x1400012b0` | Classic dispatch loop with a jump-table switch and `jmp r8` | `rcx`, mirrored into `VMContext [rsp+0x10]` | `__striga_jmp` to `0x140001390` at `0x140001314` |
| `tests/minivm-threaded.exe` | `0x140001070` | Threaded dispatch through a handler table | `VMContext [rsp+0x30]` | `__striga_call` to `0x1400014e0` at `0x1400010d3` |
| `tests/stackvm-switch.exe` | `0x1400011a0` | Stack VM with a classic if/else dispatch cascade | `rdx` | `symbolic_branch` at `0x14000128c` with symbolic input; reaches `ret` with concrete `rcx` |
| `tests/stackvm-switch-old.exe` | `0x140001290` | Wrapper around an older stack VM switch dispatcher; follow call at `0x1400012ac` | wrapper passes bytecode in `rcx`; inner dispatcher uses `r9` as PC | `__striga_jmp` to `0x1400010a0` at `0x140001075` |
| `tests/stackvm-threaded.exe` | `0x140001060` | Stack VM with threaded handler table dispatch | `rdx` argument set before dispatch | `__striga_call` to `0x140001390` at `0x1400010ab` |

Verification commands:

```bash
uv run python tools/vmentry_concolic.py \
  --binary tests/minivm-switch.exe \
  --rip 0x1400012B0 \
  --out-dir devirt-output/vmentry-concolic-minivm-switch

uv run python tools/vmentry_concolic.py \
  --binary tests/minivm-threaded.exe \
  --rip 0x140001070 \
  --out-dir devirt-output/vmentry-concolic-minivm-threaded

uv run python tools/vmentry_concolic.py \
  --binary tests/stackvm-switch.exe \
  --rip 0x1400011A0 \
  --out-dir devirt-output/vmentry-concolic-stackvm-switch

uv run python tools/vmentry_concolic.py \
  --binary tests/stackvm-switch-old.exe \
  --rip 0x140001290 \
  --follow-call 0x1400012AC \
  --out-dir devirt-output/vmentry-concolic-stackvm-switch-old

uv run python tools/vmentry_concolic.py \
  --binary tests/stackvm-threaded.exe \
  --rip 0x140001060 \
  --out-dir devirt-output/vmentry-concolic-stackvm-threaded
```

### `minivm-switch`: switch loop with an indirect jump

The first opcode byte is read from the image-backed bytecode at `0x140078450`. The dispatch table entry is read from `0x140065030`, then added to the table base. The native dispatch boundary is:

```text
stop:       0x140001314
instruction jmp r8
boundary:   __striga_jmp
concrete:   0x140001390
```

Relevant provenance:

```text
image_backing@0x140001307:0x140078450 = 0x3
image_backing@0x14000130d:0x140065030 = 0xfff9c36c
```

This sample demonstrates the classic case for VM-entry bootstrap: a concrete VPC selects a bytecode opcode, the opcode selects a jump-table slot, and the boundary helper reports the first handler address.

### `minivm-threaded`: threaded dispatch through a table call

The entry initializes the VM context on the native stack and stores the next PC in `VMContext [rsp+0x30]`. The first opcode selects a handler pointer from the threaded table:

```text
stop:       0x1400010d3
instruction call qword ptr [rdx + rax*8]
boundary:   __striga_call
concrete:   0x1400014e0
```

Relevant provenance:

```text
image_backing@0x1400010b7:0x140078450 = 0x3
image_backing@0x1400010d3:0x140065018 = 0x1400014e0
control_load@0x1400010d3:0x140065018 = 0x1400014e0
```

The `control_load` marker distinguishes the handler-pointer dereference from the backing table bytes. This is the same distinction needed for Themida relocation, but without writable table mutation.

### `stackvm-switch`: if/else dispatch cascade

This sample does not use an indirect native dispatch at the loop head. The dispatcher is a sequence of native comparisons against the current opcode. Because the opcode stream is image-backed and the PC in `rdx` is concrete, the executor follows the cascade internally.

With symbolic `rcx`, execution reaches the VM program's data-dependent branch:

```text
stop:       0x14000128c
instruction je 0x1400011f6
boundary:   symbolic_branch
concrete:   unknown
```

The branch condition depends on the VM stack value computed from `source_rcx()` and the image-backed constant `0x2a`:

```text
image_backing@0x14000125a:0x140078453 = 0x2a
```

This result is expected. The engine is a single-path concolic executor: it follows concrete dispatch decisions and stops when the VM program requests a data-dependent path choice. Supplying a concrete input lets it continue through one path:

```bash
uv run python tools/vmentry_concolic.py \
  --binary tests/stackvm-switch.exe \
  --rip 0x1400011A0 \
  --reg rcx=42 \
  --out-dir devirt-output/vmentry-concolic-stackvm-switch-rcx42
```

With `rcx=42`, the run reaches the function epilogue and stops at `ret` after 119 steps. With `rcx=1`, it reaches `ret` after 106 steps. The ret target is unknown because the caller return address is not seeded in the initial stack object.

### `stackvm-switch-old`: wrapper plus switch dispatcher

The old stack VM sample exports a wrapper at `0x140001290`. The wrapper rearranges arguments, loads the bytecode base into `rcx`, then calls the interpreter body at `0x140001030`. The call must be followed so the executor observes the inner dispatch setup and preserves the wrapper's call-return seed:

```bash
uv run python tools/vmentry_concolic.py \
  --binary tests/stackvm-switch-old.exe \
  --rip 0x140001290 \
  --follow-call 0x1400012AC \
  --out-dir devirt-output/vmentry-concolic-stackvm-switch-old
```

Observed boundary:

```text
stop:       0x140001075
instruction jmp r10
boundary:   __striga_jmp
concrete:   0x1400010a0
```

Relevant provenance:

```text
call_return@0x1400012ac = 0x1400012b1
image_backing@0x140001064:0x140017848 = 0x2
image_backing@0x14000106e:0x140017348 = 0xfffe9d60
```

The first image-backed value is the opcode byte read from the bytecode base supplied by the wrapper. The second is the signed switch-table displacement. Adding that displacement to the table base yields the first native handler target `0x1400010a0`.

### `stackvm-threaded`: threaded stack VM dispatch

The entry stores native arguments in its stack context, then sets the VM PC in `edx` before calling the first handler through a pointer table:

```text
stop:       0x1400010ab
instruction call qword ptr [r8 + rax*8]
boundary:   __striga_call
concrete:   0x140001390
```

Relevant provenance:

```text
image_backing@0x140001093:0x140078450 = 0x2
image_backing@0x1400010ab:0x140065010 = 0x140001390
control_load@0x1400010ab:0x140065010 = 0x140001390
```

This sample exercises the threaded-dispatch case where the PC is a live native value rather than a field loaded from the VM context at the boundary.

These examples show the executor's intended boundary semantics:

- indirect switch dispatch becomes `__striga_jmp` with a concrete handler target;
- threaded dispatch through a table call becomes `__striga_call` with a concrete handler target;
- if/else dispatch stays inside the executor while opcode decisions are concrete;
- data-dependent VM branches stop as `symbolic_branch` unless the user supplies concrete register inputs.

The smoke cases are codified in `tests/test_vmentry_concolic_smoke.py`:

```bash
uv run python tests/test_vmentry_concolic_smoke.py
```

The test writes per-case summaries under `devirt-output/vmentry-concolic-smoke/` and asserts the expected boundary kind, stop RIP, and concrete target. It includes BinaryShield, VMProtect, Themida `tests/example2-virt.bin`, and the synthetic VM variants.

## Output files

Each run writes three files:

| File | Contents |
|---|---|
| `summary.md` | Human-readable report with target, expression, seeds, and trace prefix. |
| `module.ll` | LLVM module containing lifted native blocks. |
| `trace.txt` | Native instruction trace prefix, limited by `--trace-limit`. |

The summary is the primary artifact for analysis. The module is useful when the expression seems wrong or a semantics implementation needs auditing.

## Pipeline role

The concolic engine is the supported VM-entry bootstrapper. It handles prefixes with long concrete loops, runtime table relocation, and sequential memory effects that must be observed in order. It uses LLVM IR as the semantic representation and executes that IR to recover the initial `(vip, rip, memory-overlay)` state for graph recovery.

## Current limitations

The engine is a single-path executor. It follows concrete branches and stops at symbolic branches. It does not fork paths or solve path constraints.

The environment model is intentionally small. It covers the stack object, selected TEB/PEB reads, and image-base recovery. Additional environment reads should become explicit object models rather than hardcoded fake addresses.

`--zero-unknown-abs` is an exploration option. A production Themida pipeline should replace it with explicit private-memory regions and lock-state assumptions.

The expression renderer is provenance-first, not algebra-first. Some expressions contain long chains of equivalent additions and subtractions. Future simplification should canonicalize image-base expressions, repeated `+ 8` table walks, and relocation identities while preserving seed markers.

The tool currently reports the boundary target and provenance. A full VM devirtualizer also needs a compact memory-overlay snapshot and register/state exports that can be consumed directly by handler graph recovery.

## Production direction

A production VM-entry bootstrapper should keep this execution contract:

```text
input:  binary, entry RIP, selected concrete environment facts
output: first VM boundary, concrete target, provenance expression, seed set, overlay snapshot
```

The implementation can improve along these axes:

1. Replace broad zero policies with named private-memory objects.
2. Canonicalize provenance expressions without dropping dependency markers.
3. Export overlay writes and register state as structured data.
4. Attach boundary output directly to `(vip, rip)` graph recovery.
5. Add regression tests for BinaryShield, VMProtect, Themida, partial reads, overlapping stores, and relocation loops.

The central invariant should remain unchanged: the engine must explain the first VM control transfer using lifted LLVM IR semantics, ordered memory effects, and preserved seed provenance.
