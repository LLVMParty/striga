# Striga LLVM IR Interpreter — Design & Implementation Plan

## 1. Motivation

The `vmentry_provenance.py` tool contains a ~400-line LLVM IR interpreter tightly coupled to a single value domain (`SymVal` with provenance tracking). The interpreter's opcode dispatch, register routing, pointer resolution, and block/terminator handling are generic — they depend on Striga's lifting conventions, not on the provenance domain. Extracting this interpreter into Striga as a reusable primitive enables multiple analysis backends (concrete emulation, taint tracking, symbolic execution, interval analysis, instruction counting) without reimplementing the same LLVM IR walking logic.

This document specifies the API shape, the required changes to `Semantics`, the interpreter core, the domain protocols, and concrete examples for each planned use case. It is intended as a complete implementation specification.

---

## 2. Required Changes to `Semantics`

### 2.1. Split `lift_bytes` into `cs_disasm` + `lift_instruction`

**Problem.** The current `lift_bytes` disassembles internally. Callers that need access to the native `CsInsn` (for seed recording, coverage tracking, or any pre-lift hook) must call `cs_disasm` separately, causing double disassembly. Additionally, `CsInsn` already carries `.bytes` so passing `code` separately to `lift_instruction` is redundant.

**Change.** Add a new public method `lift_instruction` that accepts an already-disassembled `CsInsn`. Make `lift_bytes` a thin wrapper.

```python
# In src/striga/semantics.py

def lift_instruction(self, insn: CsInsn) -> list[Successor]:
    """Lift an already-disassembled instruction into the current function.

    The instruction must have been disassembled by this Semantics instance's
    Capstone engine (self.cs) so that register IDs are consistent.
    """
    if not hasattr(self, "function"):
        self.begin(insn.address)

    if self.verbose:
        print(";", hex(insn.address), insn.mnemonic, insn.op_str)

    block = self.get_or_create_block(insn.address)
    assert block.first_instruction
    if block.first_instruction.opcode == Opcode.Ret:
        block.first_instruction.erase_from_parent()
    else:
        return []

    with block.create_builder() as ir:
        self.ir = ir
        self.insn = insn

        handler = _semantics.get(insn.mnemonic)
        if handler is None and insn.mnemonic.startswith("lock "):
            handler = _semantics.get(insn.mnemonic.removeprefix("lock "))
        if handler is None:
            raise NotImplementedError(insn.mnemonic)

        successors = handler(self)
        if successors is None:
            fallthrough = insn.address + insn.size
            ir.br(self.get_or_create_block(fallthrough))
            successors = [Successor(insn.address, self.const64(fallthrough))]

        self.module.verify_or_raise()
        return successors

def lift_bytes(self, address: int, code: bytes) -> list[Successor]:
    """Disassemble and lift a single instruction. Convenience wrapper."""
    if not hasattr(self, "function"):
        self.begin(address)
    insn = self.cs_disasm(address, code)
    return self.lift_instruction(insn)
```

**Backward compatibility.** `lift_bytes` retains its existing signature and behavior. All existing callers continue to work unchanged.

### 2.2. Export convention constants

The interpreter needs to know Striga's conventions without holding a `Semantics` instance. The following are already accessible on `Semantics` and should remain so, but the interpreter will accept them as constructor arguments:

- `reg_sizes: dict[str, int]` — register name → bit width (currently `self.reg_sizes`)
- `state_ty` — the LLVM struct type (needed for GEP matching)
- `reg_indices: dict[str, int]` — register name → struct field index

The boundary intrinsic prefix `__striga_` is a string convention. The interpreter matches on it directly.

### 2.3. No other changes to Semantics

The `Semantics` class is not modified beyond the `lift_instruction` split. It remains responsible for lifting only. The interpreter is a new, separate module.

---

## 3. Interpreter Core

### 3.1. File location

```
src/striga/interpreter.py
```

### 3.2. Domain protocols

```python
from __future__ import annotations
from typing import Protocol, TypeVar, Generic, Any, runtime_checkable
from dataclasses import dataclass
from llvm import Opcode, IntPredicate, Value, BasicBlock, Function

T = TypeVar("T")


@runtime_checkable
class ValueDomain(Protocol[T]):
    """Defines how LLVM IR values are represented and combined."""

    def constant(self, value: int, width: int | None) -> T:
        """Create a domain value from a concrete integer constant."""
        ...

    def unknown(self, text: str, width: int | None) -> T:
        """Create a domain value for an unresolvable or opaque input."""
        ...

    def binary(self, op: Opcode, lhs: T, rhs: T, width: int | None) -> T:
        """Evaluate a binary arithmetic/bitwise operation."""
        ...

    def icmp(self, predicate: IntPredicate, lhs: T, rhs: T, width: int | None) -> T:
        """Evaluate an integer comparison. Returns a 1-bit domain value."""
        ...

    def select(self, cond: T, true_val: T, false_val: T, width: int | None) -> T:
        """Evaluate a select (ternary) operation."""
        ...

    def cast(self, op: Opcode, val: T, from_width: int | None, to_width: int | None) -> T:
        """Evaluate trunc, zext, or sext."""
        ...

    def funnel_shift(self, high: T, low: T, amount: T, width: int | None, *, left: bool) -> T:
        """Evaluate llvm.fshl.* or llvm.fshr.*"""
        ...

    def concrete_bool(self, val: T) -> bool | None:
        """Extract a concrete boolean if possible. Returns None if symbolic/unknown."""
        ...

    def with_width(self, val: T, width: int | None, *, signed: bool = False) -> T:
        """Resize a domain value (trunc/zext/sext to target width)."""
        ...

    # --- Abstract interpretation support (future work) ---
    # These methods are required for multi-path fixed-point analysis but not
    # for single-trace execution. Current domains should raise NotImplementedError.
    # See section 11 for design context and planned use cases.

    def join(self, a: T, b: T) -> T:
        """Least upper bound of two abstract values at a control-flow merge."""
        raise NotImplementedError

    def bottom(self, width: int | None) -> T:
        """Least element representing unreachable / no information yet."""
        raise NotImplementedError

    def is_leq(self, a: T, b: T) -> bool:
        """Partial order: is `a` already approximated by `b`? Used for fixed-point detection."""
        raise NotImplementedError


@runtime_checkable
class RegisterState(Protocol[T]):
    """Mutable register file indexed by name."""

    def read(self, name: str) -> T: ...
    def write(self, name: str, value: T) -> None: ...
    def width(self, name: str) -> int: ...


@runtime_checkable
class MemoryState(Protocol[T]):
    """Mutable memory model."""

    def read(self, offset: T, width: int, *, insn_addr: int = 0) -> T: ...
    def write(self, offset: T, value: T, width: int, *, insn_addr: int = 0) -> None: ...
```

### 3.3. Result types

```python
@dataclass(frozen=True)
class BoundaryResult(Generic[T]):
    """Execution reached a __striga_* boundary intrinsic."""
    name: str          # e.g. "__striga_jmp", "__striga_call", "__striga_ret"
    target: T

@dataclass(frozen=True)
class SymbolicBranch(Generic[T]):
    """Execution reached a conditional branch with a non-concrete condition."""
    condition: T

@dataclass(frozen=True)
class StepLimit:
    """Execution exceeded the configured step limit."""
    steps: int
```

Both `BoundaryResult` and `SymbolicBranch` are generic over `T`, which is bound by the `Interpreter[T]` that produces them. This means the type checker can see through result types to the concrete domain value — no `Any` escapes.

`execute_block` returns `int | BoundaryResult[T] | SymbolicBranch[T] | None`:
- `int` — next block address (follow the successor)
- `BoundaryResult[T]` — hit a boundary intrinsic, stop
- `SymbolicBranch[T]` — branch condition not concrete, stop
- `None` — block ended with ret or unsupported terminator

### 3.4. Pointer resolution

The interpreter must distinguish three pointer kinds, matching the current `PtrVal`:

```python
class PtrKind(enum.Enum):
    STATE = "state"
    MEMORY = "memory"
    UNKNOWN = "unknown"

    def __str__(self) -> str:
        return self.value

@dataclass(frozen=True)
class PtrVal(Generic[T]):
    kind: PtrKind
    offset: T | None = None
    reg: str | None = None
```

`PtrKind` uses `enum.Enum` (not `IntEnum`) so that `str(PtrKind.STATE)` prints `"state"` and the type checker prevents bare string comparisons. Matching uses `PtrKind.STATE`, `PtrKind.MEMORY`, `PtrKind.UNKNOWN`.

A GEP from `%state` with a name present in `reg_sizes` is a state register pointer. A GEP from `%memory` is a memory pointer. Everything else is resolved by evaluating the pointer as an integer value.

### 3.5. Interpreter class

```python
class Interpreter(Generic[T]):
    def __init__(
        self,
        domain: ValueDomain[T],
        regs: RegisterState[T],
        memory: MemoryState[T],
        reg_sizes: dict[str, int],
    ) -> None:
        self.domain = domain
        self.regs = regs
        self.memory = memory
        self.reg_sizes = reg_sizes
        self._locals: dict[int, T | PtrVal[T]] = {}

    def execute_block(self, block: BasicBlock) -> int | BoundaryResult[T] | SymbolicBranch[T] | None:
        """Execute all instructions in a basic block. Returns next address or boundary."""
        self._locals = {}
        for inst in block.instructions:
            if inst == block.terminator:
                break
            boundary = self._execute_instruction(inst)
            if boundary is not None:
                return boundary
        return self._execute_terminator(block.terminator)

    def eval_value(self, value: Value) -> T:
        """Evaluate an LLVM Value into the domain."""
        ...

    def eval_pointer(self, value: Value) -> PtrVal[T]:
        """Evaluate an LLVM Value as a pointer, classifying state vs memory."""
        ...

    # --- Private methods ---

    def _execute_instruction(self, inst: Value) -> BoundaryResult[T] | None:
        """Execute a non-terminator instruction. Returns BoundaryResult if boundary hit."""
        ...

    def _execute_terminator(self, term: Value) -> int | SymbolicBranch[T] | None:
        """Execute a block terminator. Returns next address, SymbolicBranch, or None."""
        ...

    def _eval_call(self, inst: Value) -> T | BoundaryResult[T]:
        """Handle call instructions: boundary intrinsics, undef helpers, funnel shifts."""
        ...
```

### 3.6. Opcode dispatch in `eval_value`

The interpreter handles the following LLVM opcodes. This list matches the current `vmentry_provenance.py` coverage:

| Category | Opcodes |
|---|---|
| Constants | `is_constant_int`, `is_argument` |
| Arithmetic | `Add`, `Sub`, `Mul`, `UDiv`, `SDiv`, `URem`, `SRem` |
| Bitwise | `And`, `Or`, `Xor`, `Shl`, `LShr`, `AShr` |
| Casts | `Trunc`, `ZExt`, `SExt` |
| Comparison | `ICmp` |
| Control | `Select` |
| Memory | `Load`, `Store` (handled in `_execute_instruction`) |
| Pointer | `GetElementPtr`, `PtrToInt`, `IntToPtr` |
| Calls | `Call` (dispatched via `_eval_call`) |
| Terminators | `Br` (conditional and unconditional), `Ret` |

### 3.7. Call handling

The interpreter recognizes calls by function name:

- `__striga_jmp`, `__striga_call`, `__striga_ret`, `__striga_syscall` → `BoundaryResult`
- `__striga_undef_*` → `domain.unknown(...)`
- `llvm.fshl.*`, `llvm.fshr.*` → `domain.funnel_shift(...)`
- Unknown calls → `domain.unknown(...)`

### 3.8. Instruction address extraction

The interpreter reads the `striga.insn` metadata attached by `Semantics.mem_read` and `Semantics.mem_write` to pass instruction addresses to the memory domain. The helper `instruction_address_from_metadata` from `vmentry_provenance.py` moves into the interpreter module.

### 3.9. Block address extraction

The interpreter parses block names with the `insn_` prefix to recover native addresses, matching the existing `block_address` function. This moves into the interpreter module.

### 3.10. Pre/post instruction hooks

The interpreter exposes optional hooks that domains or drivers can use:

```python
class InstructionHooks(Protocol[T]):
    """Optional hooks called by the interpreter around instruction execution."""

    def pre_instruction(self, inst: Value) -> None:
        """Called before executing each non-terminator instruction."""
        ...

    def post_store(self, inst: Value, value: T, ptr: PtrVal[T]) -> T:
        """Called after evaluating a store value, before writing. Can annotate/transform the value.
        
        This is the hook point for seed annotation in the provenance domain.
        """
        ...
```

The hooks argument is optional in the `Interpreter` constructor. When `None`, no hooks are called.

---

## 4. Driver Pattern

The interpreter does not own the decode→lift→interpret loop. The caller (driver) does. All drivers follow this structure:

```python
def drive(container, sem, interp, start_rip, max_steps):
    rip = start_rip
    for step in range(max_steps):
        code = container.get_data(rip, 15)
        insn = sem.cs_disasm(rip, code)

        # Pre-lift hook: native instruction inspection (optional, driver-specific)
        on_native_instruction(insn)

        # Lift
        sem.lift_instruction(insn)

        # Interpret
        block = sem.insn_blocks[rip]
        result = interp.execute_block(block)

        if isinstance(result, BoundaryResult):
            return result
        if isinstance(result, SymbolicBranch):
            return result
        if result is None:
            return None
        rip = result
    return StepLimit(max_steps)
```

The driver is intentionally not a Striga class. Each tool writes its own 10–20 line loop with tool-specific hooks, logging, and termination policy.

---

## 5. Refactoring `vmentry_provenance.py`

### 5.1. What moves into `src/striga/interpreter.py`

- `eval_value` → `Interpreter.eval_value` (generalized over domain)
- `_eval_binary` → dispatches to `domain.binary`
- `_eval_icmp` → dispatches to `domain.icmp`
- `_eval_pointer` → `Interpreter.eval_pointer`
- `_execute_block` → `Interpreter.execute_block`
- `_execute_instruction` → `Interpreter._execute_instruction`
- `_eval_call` → `Interpreter._eval_call`
- `_eval_funnel_shift` → dispatches to `domain.funnel_shift`
- `instruction_address_from_metadata` → module-level function in interpreter
- `block_address` → module-level function in interpreter

### 5.2. What stays in `tools/vmentry_provenance.py`

- `SymVal` — the provenance value type (implements the domain protocol)
- `MemoryModel` — the overlay memory model (implements the memory protocol)
- `Seed`, `SeedKind`, seed recording, seed annotation
- `_record_seed_candidates` — the Capstone-level pre-lift hook
- `_annotate_control_load` — post-store hook via `InstructionHooks.post_store`
- `annotate_value_with_instruction_seed` — post-store hook
- `ProvenanceConfig`, `ProvenanceResult`, `render_result` — tool-specific config/output
- The driver loop in `ProvenanceExecutor.run`

### 5.3. Provenance domain implementation

```python
class ProvenanceDomain:
    """ValueDomain[SymVal] — concrete execution with provenance tracking."""

    def constant(self, value, width):
        return SymVal.const(value, width)

    def unknown(self, text, width):
        return SymVal.unknown(text, width)

    def binary(self, op, lhs, rhs, width):
        return combine_values(lhs, rhs, op, width)

    def icmp(self, predicate, lhs, rhs, width):
        concrete = None
        if lhs.concrete is not None and rhs.concrete is not None:
            concrete = int(eval_icmp(predicate, lhs.concrete, rhs.concrete, lhs.width))
        return SymVal(
            f"icmp.{predicate.name.lower()}({lhs.text}, {rhs.text})",
            concrete, 1,
            unknowns=(*lhs.unknowns, *rhs.unknowns),
            deps=lhs.deps | rhs.deps,
        )

    def select(self, cond, true_val, false_val, width):
        if cond.concrete is not None:
            return true_val if cond.concrete else false_val
        concrete = true_val.concrete if true_val.concrete == false_val.concrete else None
        return SymVal(
            f"select({cond.text}, {true_val.text}, {false_val.text})",
            concrete, width,
            unknowns=(*cond.unknowns, *true_val.unknowns, *false_val.unknowns),
            deps=cond.deps | true_val.deps | false_val.deps,
        )

    def cast(self, op, val, from_width, to_width):
        if op == Opcode.Trunc:
            concrete = None if val.concrete is None else mask_value(val.concrete, to_width)
            return SymVal(cast_text("trunc", val.text, to_width), concrete, to_width,
                          unknowns=val.unknowns, deps=val.deps,
                          xor_const=mask_value(val.xor_const, to_width))
        return val.with_width(to_width, signed=op == Opcode.SExt)

    def funnel_shift(self, high, low, amount, width, *, left):
        concrete = None
        if width and high.concrete is not None and low.concrete is not None and amount.concrete is not None:
            amt = amount.concrete % width
            mask = (1 << width) - 1
            if amt == 0:
                concrete = high.concrete & mask
            elif left:
                concrete = ((high.concrete << amt) | (low.concrete >> (width - amt))) & mask
            else:
                concrete = ((high.concrete >> amt) | (low.concrete << (width - amt))) & mask
        name = "fshl" if left else "fshr"
        return SymVal(
            f"{name}({high.text}, {low.text}, {amount.text})", concrete, width,
            unknowns=(*high.unknowns, *low.unknowns, *amount.unknowns),
            deps=high.deps | low.deps | amount.deps,
        )

    def concrete_bool(self, val):
        if val.concrete is not None:
            return bool(val.concrete)
        return None

    def with_width(self, val, width, *, signed=False):
        return val.with_width(width, signed=signed)
```

### 5.4. Register state wrapper

```python
class ProvenanceRegisters:
    def __init__(self, regs: dict[str, SymVal], reg_sizes: dict[str, int]):
        self._regs = regs
        self._sizes = reg_sizes

    def read(self, name: str) -> SymVal:
        return self._regs[name]

    def write(self, name: str, value: SymVal) -> None:
        self._regs[name] = value.with_width(self._sizes[name])

    def width(self, name: str) -> int:
        return self._sizes[name]
```

### 5.5. Instruction hooks for provenance

```python
class ProvenanceHooks:
    def __init__(self, seeds: list[Seed]):
        self.seeds = seeds

    def pre_instruction(self, inst):
        pass

    def post_store(self, inst, value, ptr):
        insn_addr = instruction_address_from_metadata(inst)
        return annotate_value_with_instruction_seed(value, insn_addr, self.seeds)
```

### 5.6. Refactored driver loop

```python
class ProvenanceExecutor:
    def run(self) -> ProvenanceResult:
        with create_context() as context:
            with context.create_module(...) as module:
                sem = Semantics(module, verbose=False)
                sem.begin(self.cfg.rip)
                state = self._initial_state(sem)

                domain = ProvenanceDomain()
                regs = ProvenanceRegisters(state.regs, sem.reg_sizes)
                hooks = ProvenanceHooks(state.seeds)
                interp = Interpreter(domain, regs, state.memory, sem.reg_sizes, hooks=hooks)

                rip = self.cfg.rip
                for step in range(self.cfg.max_steps):
                    code = self.container.get_data(rip, 15)
                    insn = sem.cs_disasm(rip, code)
                    self._record_seed_candidates(insn, state)

                    if len(self.trace) < self.cfg.trace_limit:
                        self.trace.append(f"{rip:#x}: {insn.mnemonic} {insn.op_str}".strip())

                    # Handle followed calls
                    if insn.group(CS_GRP_CALL) and rip in self.cfg.follow_calls:
                        self._lift_followed_call(sem, insn)
                    else:
                        block = sem.get_or_create_block(rip)
                        if block.first_instruction is not None and block.first_instruction.opcode == Opcode.Ret:
                            sem.lift_instruction(insn)

                    block = sem.insn_blocks[rip]
                    result = interp.execute_block(block)

                    if isinstance(result, BoundaryResult):
                        state.boundary_call = result.name
                        state.boundary_value = self._annotate_control_load_from_result(result, state)
                        stop = rip
                        break
                    if isinstance(result, SymbolicBranch):
                        state.boundary_call = "symbolic_branch"
                        state.boundary_value = result.condition
                        stop = rip
                        break
                    if result is None:
                        stop = rip
                        break
                    rip = result
                # ... build ProvenanceResult as before
```

---

## 6. Use Case Domains

Each use case below specifies its domain, memory, register state, and a usage example.

### 6.1. Concrete Emulator

**Purpose.** Fast execution for testing semantics correctness, fuzzing, and handler enumeration.

**Domain.**

```python
class ConcreteDomain:
    """ValueDomain[int] — plain integer execution."""

    def constant(self, value: int, width: int | None) -> int:
        return mask_value(value, width)

    def unknown(self, text: str, width: int | None) -> int:
        return 0  # or raise, depending on policy

    def binary(self, op: Opcode, lhs: int, rhs: int, width: int | None) -> int:
        return eval_binary(op, lhs, rhs, width)

    def icmp(self, predicate: IntPredicate, lhs: int, rhs: int, width: int | None) -> int:
        return int(eval_icmp(predicate, lhs, rhs, width))

    def select(self, cond: int, true_val: int, false_val: int, width: int | None) -> int:
        return true_val if cond else false_val

    def cast(self, op: Opcode, val: int, from_width: int | None, to_width: int | None) -> int:
        if op == Opcode.Trunc:
            return mask_value(val, to_width)
        if op == Opcode.SExt:
            return sext_value(val, from_width, to_width)
        return mask_value(val, to_width)  # ZExt

    def funnel_shift(self, high: int, low: int, amount: int, width: int | None, *, left: bool) -> int:
        if width is None:
            return 0
        amt = amount % width
        mask = (1 << width) - 1
        if amt == 0:
            return high & mask
        if left:
            return ((high << amt) | (low >> (width - amt))) & mask
        return ((high >> amt) | (low << (width - amt))) & mask

    def concrete_bool(self, val: int) -> bool | None:
        return bool(val)

    def with_width(self, val: int, width: int | None, *, signed: bool = False) -> int:
        if signed:
            return sext_value(val, width, width)  # no-op for same width, real sext otherwise
        return mask_value(val, width)
```

**Memory.**

```python
class ConcreteMemory:
    """MemoryState[int] — flat bytearray."""

    def __init__(self, data: bytearray):
        self.data = data

    def read(self, offset: int, width: int, *, insn_addr: int = 0) -> int:
        byte_width = width // 8
        return int.from_bytes(self.data[offset:offset + byte_width], "little")

    def write(self, offset: int, value: int, width: int, *, insn_addr: int = 0) -> None:
        byte_width = width // 8
        self.data[offset:offset + byte_width] = value.to_bytes(byte_width, "little")
```

**Registers.**

```python
class ConcreteRegisters:
    def __init__(self, reg_sizes: dict[str, int], initial: dict[str, int] | None = None):
        self._sizes = reg_sizes
        self._regs = {name: (initial or {}).get(name, 0) for name in reg_sizes}

    def read(self, name: str) -> int:
        return self._regs[name]

    def write(self, name: str, value: int) -> None:
        self._regs[name] = mask_value(value, self._sizes[name])

    def width(self, name: str) -> int:
        return self._sizes[name]
```

**Usage: semantics regression test.**

```python
def test_xor_self_is_zero():
    """xor rax, rax should zero rax and set ZF."""
    with create_context() as context:
        with context.create_module("test") as module:
            sem = Semantics(module)
            sem.begin(0x1000)

            code = b"\x48\x31\xc0"  # xor rax, rax
            insn = sem.cs_disasm(0x1000, code)
            sem.lift_instruction(insn)

            regs = ConcreteRegisters(sem.reg_sizes, {"rax": 0xDEADBEEF})
            mem = ConcreteMemory(bytearray(4096))
            interp = Interpreter(ConcreteDomain(), regs, mem, sem.reg_sizes)

            block = sem.insn_blocks[0x1000]
            interp.execute_block(block)

            assert regs.read("rax") == 0
            assert regs.read("zf") == 1
```

**Usage: handler enumeration by sweeping opcode bytes.**

```python
def discover_handlers(container, entry_rip, opcode_range):
    """Sweep opcode values to map the VM handler table."""
    handlers = {}
    for opcode_byte in opcode_range:
        with create_context() as context:
            with context.create_module("sweep") as module:
                sem = Semantics(module)
                sem.begin(entry_rip)

                # Set up concrete state with the opcode byte in the expected location
                regs = ConcreteRegisters(sem.reg_sizes, {"rsp": 0x7FFF0000})
                image = bytearray(container.size)
                image[:] = container.raw_bytes()
                # Plant opcode byte at bytecode base
                image[BYTECODE_OFFSET] = opcode_byte
                mem = ConcreteMemory(image)

                interp = Interpreter(ConcreteDomain(), regs, mem, sem.reg_sizes)
                rip = entry_rip

                for _ in range(10_000):
                    code = container.get_data(rip, 15)
                    insn = sem.cs_disasm(rip, code)
                    sem.lift_instruction(insn)
                    result = interp.execute_block(sem.insn_blocks[rip])

                    if isinstance(result, BoundaryResult):
                        handlers[opcode_byte] = result.target
                        break
                    if result is None:
                        break
                    rip = result

    return handlers
```

### 6.2. Taint Tracking

**Purpose.** Determine which input registers/memory influence the boundary target. Cheaper than full provenance when you only need reachability, not the expression chain.

**Domain.**

```python
@dataclass(frozen=True)
class Tainted:
    value: int
    width: int | None
    labels: frozenset[str]


class TaintDomain:
    """ValueDomain[Tainted] — concrete value + taint label set."""

    def constant(self, value: int, width: int | None) -> Tainted:
        return Tainted(mask_value(value, width), width, frozenset())

    def unknown(self, text: str, width: int | None) -> Tainted:
        return Tainted(0, width, frozenset({text}))

    def binary(self, op: Opcode, lhs: Tainted, rhs: Tainted, width: int | None) -> Tainted:
        concrete = eval_binary(op, lhs.value, rhs.value, width)
        return Tainted(concrete, width, lhs.labels | rhs.labels)

    def icmp(self, predicate, lhs: Tainted, rhs: Tainted, width) -> Tainted:
        concrete = int(eval_icmp(predicate, lhs.value, rhs.value, lhs.width))
        return Tainted(concrete, 1, lhs.labels | rhs.labels)

    def select(self, cond: Tainted, tv: Tainted, fv: Tainted, width) -> Tainted:
        chosen = tv if cond.value else fv
        return Tainted(chosen.value, width, cond.labels | tv.labels | fv.labels)

    def cast(self, op, val: Tainted, from_width, to_width) -> Tainted:
        if op == Opcode.Trunc:
            return Tainted(mask_value(val.value, to_width), to_width, val.labels)
        if op == Opcode.SExt:
            return Tainted(sext_value(val.value, from_width, to_width), to_width, val.labels)
        return Tainted(mask_value(val.value, to_width), to_width, val.labels)

    def funnel_shift(self, high, low, amount, width, *, left) -> Tainted:
        concrete = ConcreteDomain().funnel_shift(high.value, low.value, amount.value, width, left=left)
        return Tainted(concrete, width, high.labels | low.labels | amount.labels)

    def concrete_bool(self, val: Tainted) -> bool | None:
        return bool(val.value)

    def with_width(self, val: Tainted, width, *, signed=False) -> Tainted:
        if signed:
            return Tainted(sext_value(val.value, val.width, width), width, val.labels)
        return Tainted(mask_value(val.value, width), width, val.labels)
```

**Memory.**

```python
class TaintMemory:
    """Flat concrete memory with taint propagation."""

    def __init__(self, data: bytearray):
        self.data = data
        self.taint: dict[int, frozenset[str]] = {}

    def read(self, offset: Tainted, width: int, *, insn_addr=0) -> Tainted:
        addr = offset.value
        byte_width = width // 8
        value = int.from_bytes(self.data[addr:addr + byte_width], "little")
        labels = offset.labels
        for i in range(byte_width):
            labels = labels | self.taint.get(addr + i, frozenset())
        return Tainted(value, width, labels)

    def write(self, offset: Tainted, value: Tainted, width: int, *, insn_addr=0) -> None:
        addr = offset.value
        byte_width = width // 8
        self.data[addr:addr + byte_width] = value.value.to_bytes(byte_width, "little")
        for i in range(byte_width):
            self.taint[addr + i] = value.labels | offset.labels
```

**Usage: which inputs reach the dispatch target?**

```python
def taint_analysis(container, entry_rip):
    with create_context() as context:
        with context.create_module("taint") as module:
            sem = Semantics(module)
            sem.begin(entry_rip)

            regs = TaintRegisters(sem.reg_sizes, {
                "rax": Tainted(0, 64, frozenset({"rax"})),
                "rcx": Tainted(0, 64, frozenset({"rcx"})),
                "rdx": Tainted(0, 64, frozenset({"rdx"})),
                "rsp": Tainted(0x7FFF0000, 64, frozenset()),
            })
            mem = TaintMemory(bytearray(container.size))
            interp = Interpreter(TaintDomain(), regs, mem, sem.reg_sizes)

            rip = entry_rip
            for _ in range(50_000):
                insn = sem.cs_disasm(rip, container.get_data(rip, 15))
                sem.lift_instruction(insn)
                result = interp.execute_block(sem.insn_blocks[rip])
                if isinstance(result, BoundaryResult):
                    print(f"Dispatch target tainted by: {result.target.labels}")
                    break
                if result is None:
                    break
                rip = result
```

### 6.3. SMT Symbolic Execution

**Purpose.** Build SMT expressions while executing, enabling solver-backed branch exploration and equivalence checking.

**Domain.**

```python
import smt_wire as smt


class SmtDomain:
    """ValueDomain[smt.BVTerm | smt.BoolTerm] using the SMT wire protocol client."""

    def __init__(self, ctx: smt.Context, client: smt.Client | None = None):
        self.ctx = ctx
        self.client = client

    def constant(self, value, width):
        if width is None or width == 0:
            return self.ctx.bv_const(value, 64)
        return self.ctx.bv_const(value, width)

    def unknown(self, text, width):
        w = width or 64
        return self.ctx.bv_var(text, w)

    def binary(self, op, lhs, rhs, width):
        ops = {
            Opcode.Add: self.ctx.bv_add, Opcode.Sub: self.ctx.bv_sub,
            Opcode.Mul: self.ctx.bv_mul, Opcode.UDiv: self.ctx.bv_udiv,
            Opcode.SDiv: self.ctx.bv_sdiv, Opcode.URem: self.ctx.bv_urem,
            Opcode.SRem: self.ctx.bv_srem, Opcode.And: self.ctx.bv_and,
            Opcode.Or: self.ctx.bv_or, Opcode.Xor: self.ctx.bv_xor,
            Opcode.Shl: self.ctx.bv_shl, Opcode.LShr: self.ctx.bv_lshr,
            Opcode.AShr: self.ctx.bv_ashr,
        }
        return ops[op](lhs, rhs)

    def icmp(self, predicate, lhs, rhs, width):
        preds = {
            IntPredicate.EQ: self.ctx.bv_eq, IntPredicate.NE: self.ctx.bv_ne,
            IntPredicate.ULT: self.ctx.bv_ult, IntPredicate.ULE: self.ctx.bv_ule,
            IntPredicate.UGT: self.ctx.bv_ugt, IntPredicate.UGE: self.ctx.bv_uge,
            IntPredicate.SLT: self.ctx.bv_slt, IntPredicate.SLE: self.ctx.bv_sle,
            IntPredicate.SGT: self.ctx.bv_sgt, IntPredicate.SGE: self.ctx.bv_sge,
        }
        return preds[predicate](lhs, rhs)  # returns BoolTerm

    def select(self, cond, true_val, false_val, width):
        return self.ctx.ite(cond, true_val, false_val)

    def cast(self, op, val, from_width, to_width):
        if op == Opcode.Trunc:
            return self.ctx.bv_extract(val, to_width - 1, 0)
        if op == Opcode.ZExt:
            return self.ctx.bv_zext(val, to_width - from_width)
        if op == Opcode.SExt:
            return self.ctx.bv_sext(val, to_width - from_width)

    def funnel_shift(self, high, low, amount, width, *, left):
        # Lower to shifts and OR
        if width is None:
            return high
        if left:
            return self.ctx.bv_or(
                self.ctx.bv_shl(high, amount),
                self.ctx.bv_lshr(low, self.ctx.bv_sub(self.ctx.bv_const(width, width), amount)),
            )
        return self.ctx.bv_or(
            self.ctx.bv_lshr(high, amount),
            self.ctx.bv_shl(low, self.ctx.bv_sub(self.ctx.bv_const(width, width), amount)),
        )

    def concrete_bool(self, val) -> bool | None:
        # Handle BoolTerm
        if isinstance(val, smt.BoolTerm):
            if val.op is smt.Op.BOOL_TRUE:
                return True
            if val.op is smt.Op.BOOL_FALSE:
                return False
            if self.client is None:
                return None
            # Solver-backed feasibility check
            self.ctx.push()
            self.ctx.assert_(val)
            sat_true = self.client.solve(self.ctx).status is smt.Status.SAT
            self.ctx.pop()
            self.ctx.push()
            self.ctx.assert_(~val)
            sat_false = self.client.solve(self.ctx).status is smt.Status.SAT
            self.ctx.pop()
            if sat_true and not sat_false:
                return True
            if sat_false and not sat_true:
                return False
            return None
        # Handle BVTerm used as i1
        if isinstance(val, smt.BVTerm):
            if val.op is smt.Op.BV_CONST:
                return bool(val.value)
            return None
        return None

    def with_width(self, val, width, *, signed=False):
        if isinstance(val, smt.BoolTerm):
            # Bool → BV: ite(val, 1, 0)
            bv_val = self.ctx.ite(val, self.ctx.bv_const(1, width), self.ctx.bv_const(0, width))
            return bv_val
        current = val.width
        if current == width:
            return val
        if current > width:
            return self.ctx.bv_extract(val, width - 1, 0)
        if signed:
            return self.ctx.bv_sext(val, width - current)
        return self.ctx.bv_zext(val, width - current)
```

**Memory.**

```python
class SmtMemory:
    """Concrete-address memory with symbolic values."""

    def __init__(self, ctx: smt.Context, backing: PEContainer):
        self.ctx = ctx
        self.backing = backing
        self.store: dict[int, smt.BVTerm] = {}

    def read(self, offset, width, *, insn_addr=0):
        # Offset must be concrete for memory lookup
        if isinstance(offset, smt.BVTerm) and offset.op is smt.Op.BV_CONST:
            addr = offset.value
        else:
            # Symbolic address: create uninterpreted variable
            return self.ctx.bv_var(f"mem_{insn_addr:x}_{width}", width)

        if addr in self.store:
            return self.store[addr]

        byte_width = width // 8
        if self.backing.in_range(addr) and self.backing.in_range(addr + byte_width - 1):
            data = self.backing.get_data(addr, byte_width)
            value = int.from_bytes(data, "little")
            return self.ctx.bv_const(value, width)

        return self.ctx.bv_var(f"mem_{addr:x}_{width}", width)

    def write(self, offset, value, width: int, *, insn_addr=0):
        if isinstance(offset, smt.BVTerm) and offset.op is smt.Op.BV_CONST:
            self.store[offset.value] = value
```

**Usage: equivalence checking of two lifted sequences.**

```python
def verify_equivalent(container, rip_a, rip_b, input_regs: list[str]):
    """Verify that two lifted code sequences produce identical outputs."""
    ctx = smt.Context()

    # Shared symbolic inputs
    inputs = {name: ctx.bv_var(f"in_{name}", 64) for name in input_regs}

    def run_one(rip):
        with create_context() as llvm_ctx:
            with llvm_ctx.create_module("verify") as module:
                sem = Semantics(module)
                sem.begin(rip)

                regs = SmtRegisters(ctx, sem.reg_sizes, inputs)
                mem = SmtMemory(ctx, container)
                interp = Interpreter(SmtDomain(ctx), regs, mem, sem.reg_sizes)

                current = rip
                for _ in range(1000):
                    insn = sem.cs_disasm(current, container.get_data(current, 15))
                    sem.lift_instruction(insn)
                    result = interp.execute_block(sem.insn_blocks[current])
                    if isinstance(result, BoundaryResult):
                        return result.target, {name: regs.read(name) for name in input_regs}
                    if result is None:
                        return None, {name: regs.read(name) for name in input_regs}
                    current = result
                return None, {name: regs.read(name) for name in input_regs}

    target_a, outputs_a = run_one(rip_a)
    target_b, outputs_b = run_one(rip_b)

    # Assert that some output differs
    diffs = [ctx.bv_ne(outputs_a[r], outputs_b[r]) for r in input_regs]
    ctx.assert_(functools.reduce(ctx.bool_or, diffs))

    with smt.Client() as client:
        resp = client.solve(ctx)
        if resp.status is smt.Status.UNSAT:
            print("sequences are equivalent")
        elif resp.status is smt.Status.SAT:
            print("counterexample found:")
            if resp.model:
                for var, val in resp.model.items():
                    print(f"  {var.name} = {hex(int(val))}")
```

**Usage: semantics validation against a reference.**

```python
def validate_instruction_semantics(asm_bytes: bytes, input_regs: list[str]):
    """Lift an instruction with Striga, build SMT expression, compare against known-good evaluator."""
    ctx = smt.Context()
    inputs = {name: ctx.bv_var(name, 64) for name in input_regs}

    # Striga path
    with create_context() as llvm_ctx:
        with llvm_ctx.create_module("validate") as module:
            sem = Semantics(module)
            sem.begin(0x1000)
            insn = sem.cs_disasm(0x1000, asm_bytes)
            sem.lift_instruction(insn)

            regs = SmtRegisters(ctx, sem.reg_sizes, inputs)
            mem = SmtMemory(ctx, None)
            interp = Interpreter(SmtDomain(ctx), regs, mem, sem.reg_sizes)
            interp.execute_block(sem.insn_blocks[0x1000])

            # Now regs contain SMT expressions.
            # Use the solver to check: for all inputs, does striga_rax == reference_rax?
            rax_expr = regs.read("rax")

    # Compare rax_expr against known-good symbolic expression from reference lifter
    # ...
```

Using the in-process smt_wire server (what we will use):

```python
import smt_wire as smt
from smt_z3_server import Z3Server

with Z3Server.start(port=0) as server:
    with smt.Client(server.host, server.port) as client:
        # use the existing client API
        pass
```

Regular smt_wire example:

```python
import smt_wire as smt


ctx = smt.Context()
print(ctx)  # Context#1, Context#2, ...

x = ctx.bv_var("x", 32)
y = ctx.bv_var("y", 32)

# Terms are thin handles. Arithmetic/bitwise dunders forward to Context methods,
# and Python ints are coerced to BV constants using the left term's width.
x_plus_y = x + y
mba = (x ^ y) + ((x & y) * 2)
masked = 0xFF & (x + 3)

# Named operations live on Context: comparisons, structural operations, and Bool ops.
identity_holds = ctx.bv_eq(mba, x_plus_y)
low_x_is_42 = ctx.bv_eq(ctx.bv_extract(x, 7, 0), 42)
ctx.assert_(ctx.bool_and(identity_holds, low_x_is_42))

# __str__ renders one layer by default. With to_smt2 you get full depth
print("MBA:", mba)
print("MBA full:", mba.to_smt2())
print("masked:", masked.to_smt2())


# A visitor can lower a returned/simplified DAG into your own IR. This one
# prints a small reverse Polish notation string for the MBA expression.
def to_rpn(term: smt.Term, args: tuple[str, ...]) -> str:
    if term.op is smt.Op.BV_VAR:
        return term.name
    if term.op is smt.Op.BV_CONST:
        assert isinstance(term, smt.BVTerm)
        return f"{term.value}:{term.width}"
    return " ".join((*args, term.op.symbol))


print("RPN:", mba.visit(to_rpn))

# Start the server first:
#   cargo run -p smt-server -- 127.0.0.1:9123
with smt.Client() as client:
    resp = client.solve(ctx)
    print(resp.status)
    if resp.status is smt.Status.SAT and resp.model is not None:
        for var, value in resp.model.items():
            print(f"{var.name} = {hex(int(value))}")

    simplified = client.simplify(mba)
    if simplified.term is not None:
        print("simplified MBA:", simplified.term.to_smt2(depth=-1))

# Dump a full SMT-LIB script for debugging or for feeding to solvers like Z3.
print("\nSMT-LIB:")
ctx_smt2 = ctx.to_smt2()
print(ctx_smt2)

with smt.Client() as client:
    smt_resp = client.smt2(ctx_smt2)
    print(smt_resp)
```

### 6.4. Interval / Stride Analysis

**Purpose.** Bound value ranges to determine jump table sizes, prove array index safety, or guide further analysis.

**Domain.**

```python
@dataclass(frozen=True)
class Interval:
    lo: int
    hi: int
    width: int

    @staticmethod
    def exact(value: int, width: int) -> Interval:
        v = mask_value(value, width)
        return Interval(v, v, width)

    @staticmethod
    def full(width: int) -> Interval:
        return Interval(0, (1 << width) - 1, width)

    @property
    def is_exact(self) -> bool:
        return self.lo == self.hi

    @property
    def span(self) -> int:
        return self.hi - self.lo + 1 if self.hi >= self.lo else 0


class IntervalDomain:
    """ValueDomain[Interval] — unsigned interval abstract domain."""

    def constant(self, value, width):
        return Interval.exact(value, width or 64)

    def unknown(self, text, width):
        return Interval.full(width or 64)

    def binary(self, op, lhs, rhs, width):
        w = width or 64
        if op == Opcode.Add:
            if lhs.is_exact and rhs.is_exact:
                return Interval.exact(lhs.lo + rhs.lo, w)
            return Interval(mask_value(lhs.lo + rhs.lo, w), mask_value(lhs.hi + rhs.hi, w), w)
        if op == Opcode.And and rhs.is_exact:
            return Interval(lhs.lo & rhs.lo, min(lhs.hi, rhs.lo), w)
        if lhs.is_exact and rhs.is_exact:
            return Interval.exact(eval_binary(op, lhs.lo, rhs.lo, w), w)
        return Interval.full(w)

    def icmp(self, predicate, lhs, rhs, width):
        if lhs.is_exact and rhs.is_exact:
            return Interval.exact(int(eval_icmp(predicate, lhs.lo, rhs.lo, lhs.width)), 1)
        return Interval.full(1)

    def select(self, cond, tv, fv, width):
        if cond.is_exact:
            return tv if cond.lo else fv
        return Interval(min(tv.lo, fv.lo), max(tv.hi, fv.hi), width or 64)

    def cast(self, op, val, from_width, to_width):
        w = to_width or 64
        if val.is_exact:
            if op == Opcode.Trunc: return Interval.exact(val.lo, w)
            if op == Opcode.SExt: return Interval.exact(sext_value(val.lo, from_width, w), w)
            return Interval.exact(val.lo, w)
        return Interval.full(w)

    def funnel_shift(self, high, low, amount, width, *, left):
        w = width or 64
        if high.is_exact and low.is_exact and amount.is_exact:
            return Interval.exact(
                ConcreteDomain().funnel_shift(high.lo, low.lo, amount.lo, w, left=left), w)
        return Interval.full(w)

    def concrete_bool(self, val):
        if val.is_exact:
            return bool(val.lo)
        return None

    def with_width(self, val, width, *, signed=False):
        w = width or 64
        if val.is_exact:
            if signed:
                return Interval.exact(sext_value(val.lo, val.width, w), w)
            return Interval.exact(mask_value(val.lo, w), w)
        return Interval.full(w)
```

**Usage: bound a jump table index.**

```python
def bound_jump_table(container, dispatch_rip):
    with create_context() as context:
        with context.create_module("interval") as module:
            sem = Semantics(module)
            sem.begin(dispatch_rip)
            
            regs = IntervalRegisters(sem.reg_sizes, {
                "rax": Interval.full(64),  # unknown opcode index
                "rsp": Interval.exact(0x7FFF0000, 64),
            })
            mem = IntervalMemory(container)
            interp = Interpreter(IntervalDomain(), regs, mem, sem.reg_sizes)

            rip = dispatch_rip
            for _ in range(1000):
                insn = sem.cs_disasm(rip, container.get_data(rip, 15))
                sem.lift_instruction(insn)
                result = interp.execute_block(sem.insn_blocks[rip])
                if isinstance(result, BoundaryResult):
                    target = result.target
                    if target.is_exact:
                        print(f"dispatch always goes to {target.lo:#x}")
                    else:
                        print(f"dispatch target range: {target.lo:#x}..{target.hi:#x} ({target.span} entries)")
                    break
                if result is None:
                    break
                rip = result
```

### 6.5. Instruction Counting / Profiling

**Purpose.** Count operations by type to identify expensive handlers and measure optimization effectiveness.

**Domain.**

```python
@dataclass(frozen=True)
class Counted:
    value: int
    width: int | None
    ops: dict[str, int]  # opcode name → count

    @staticmethod
    def const(value: int, width: int | None) -> Counted:
        return Counted(mask_value(value, width), width, {})

    def merge_ops(self, *others: Counted, op_name: str) -> dict[str, int]:
        merged = dict(self.ops)
        for other in others:
            for k, v in other.ops.items():
                merged[k] = merged.get(k, 0) + v
        merged[op_name] = merged.get(op_name, 0) + 1
        return merged


class CountingDomain:
    """ValueDomain[Counted] — concrete execution with operation counting."""

    def constant(self, value, width):
        return Counted.const(value, width)

    def unknown(self, text, width):
        return Counted(0, width, {})

    def binary(self, op, lhs, rhs, width):
        concrete = eval_binary(op, lhs.value, rhs.value, width)
        return Counted(concrete, width, lhs.merge_ops(rhs, op_name=op.name))

    def icmp(self, predicate, lhs, rhs, width):
        concrete = int(eval_icmp(predicate, lhs.value, rhs.value, lhs.width))
        return Counted(concrete, 1, lhs.merge_ops(rhs, op_name=f"icmp_{predicate.name}"))

    def select(self, cond, tv, fv, width):
        chosen = tv if cond.value else fv
        return Counted(chosen.value, width, cond.merge_ops(tv, fv, op_name="select"))

    def cast(self, op, val, from_width, to_width):
        if op == Opcode.Trunc:
            concrete = mask_value(val.value, to_width)
        elif op == Opcode.SExt:
            concrete = sext_value(val.value, from_width, to_width)
        else:
            concrete = mask_value(val.value, to_width)
        return Counted(concrete, to_width, {**val.ops, op.name: val.ops.get(op.name, 0) + 1})

    def funnel_shift(self, high, low, amount, width, *, left):
        concrete = ConcreteDomain().funnel_shift(high.value, low.value, amount.value, width, left=left)
        return Counted(concrete, width, high.merge_ops(low, amount, op_name="funnel_shift"))

    def concrete_bool(self, val):
        return bool(val.value)

    def with_width(self, val, width, *, signed=False):
        if signed:
            return Counted(sext_value(val.value, val.width, width), width, val.ops)
        return Counted(mask_value(val.value, width), width, val.ops)
```

**Usage: profile a handler.**

```python
def profile_handler(container, handler_rip):
    with create_context() as context:
        with context.create_module("profile") as module:
            sem = Semantics(module)
            sem.begin(handler_rip)

            regs = CountingRegisters(sem.reg_sizes)
            mem = CountingMemory(container)
            interp = Interpreter(CountingDomain(), regs, mem, sem.reg_sizes)

            rip = handler_rip
            total_blocks = 0
            for _ in range(10_000):
                insn = sem.cs_disasm(rip, container.get_data(rip, 15))
                sem.lift_instruction(insn)
                result = interp.execute_block(sem.insn_blocks[rip])
                total_blocks += 1
                if isinstance(result, BoundaryResult):
                    target = result.target
                    print(f"Handler {handler_rip:#x}: {total_blocks} blocks, ops: {target.ops}")
                    break
                if result is None:
                    break
                rip = result
```

### 6.6. Differential / Patch Simulation

**Purpose.** Compare execution before and after a binary patch without running the binary.

**Usage.**

```python
def simulate_patch(container, rip, patch_offset, patch_bytes, input_regs):
    """Run provenance or concrete domain on original and patched binary, compare."""

    # Create patched container
    patched = OverlayContainer(container)
    patched.write(patch_offset, patch_bytes)

    def run_with(cont):
        with create_context() as context:
            with context.create_module("diff") as module:
                sem = Semantics(module)
                sem.begin(rip)
                regs = ConcreteRegisters(sem.reg_sizes, input_regs)
                mem = ConcreteMemory(bytearray(cont.raw_bytes()))
                interp = Interpreter(ConcreteDomain(), regs, mem, sem.reg_sizes)
                current = rip
                for _ in range(10_000):
                    insn = sem.cs_disasm(current, cont.get_data(current, 15))
                    sem.lift_instruction(insn)
                    result = interp.execute_block(sem.insn_blocks[current])
                    if isinstance(result, BoundaryResult):
                        return result, {n: regs.read(n) for n in input_regs}
                    if result is None:
                        return None, {n: regs.read(n) for n in input_regs}
                    current = result
                return None, {}

    result_orig, outputs_orig = run_with(container)
    result_patched, outputs_patched = run_with(patched)

    print("Original:", result_orig)
    print("Patched:", result_patched)
    for name in input_regs:
        if outputs_orig.get(name) != outputs_patched.get(name):
            print(f"  {name}: {outputs_orig.get(name):#x} → {outputs_patched.get(name):#x}")
```

---

## 7. Implementation Order

### Phase 1: Striga changes (src/striga/)

1. Add `lift_instruction(insn: CsInsn) -> list[Successor]` to `Semantics`.
2. Refactor `lift_bytes` to call `lift_instruction` internally.
3. Verify all existing callers still work (BFS lifter, brightening, vmentry_provenance).

### Phase 2: Interpreter core (src/striga/interpreter.py)

4. Define `ValueDomain`, `RegisterState`, `MemoryState` protocols.
5. Define `PtrKind`, `PtrVal`, `BoundaryResult`, `SymbolicBranch` types.
6. Move `instruction_address_from_metadata` and `block_address` from `vmentry_provenance.py`.
7. Implement `Interpreter` class with:
   - `execute_block`
   - `eval_value` (full opcode dispatch)
   - `eval_pointer` (state/memory classification)
   - `_execute_instruction` (store handling, call dispatch)
   - `_execute_terminator` (br/ret)
   - `_eval_call` (boundary detection, undef, funnel shifts)
8. Add optional `InstructionHooks` support.

### Phase 3: Refactor vmentry_provenance.py

9. Implement `ProvenanceDomain(ValueDomain[SymVal])`.
10. Implement `ProvenanceRegisters(RegisterState[SymVal])`.
11. Implement `ProvenanceHooks(InstructionHooks[SymVal])`.
12. Rewrite `ProvenanceExecutor.run` to use `Interpreter`.
13. Remove duplicated opcode dispatch code from vmentry_provenance.
14. Verify all existing test outputs remain identical (BinaryShield, VMProtect, Themida, minivm, stackvm samples).

### Phase 4: Additional domains (secondary, not required for initial merge)

15. `ConcreteDomain` + `ConcreteRegisters` + `ConcreteMemory`.
16. `TaintDomain` + `TaintMemory`.
17. `SmtDomain` + `SmtMemory`.
18. `IntervalDomain`.
19. `CountingDomain`.

---

## 8. Testing Strategy

The primary test is provenance equivalence: after refactoring `vmentry_provenance.py` to use the interpreter, run all existing sample commands (BinaryShield, VMProtect, Themida, minivm-switch, minivm-threaded, stackvm-switch, stackvm-switch-old, stackvm-threaded) and verify that the output `summary.md` files are byte-identical to the pre-refactor outputs.

Broader interpreter correctness testing (lifting individual instructions, cross-validating against Unicorn, domain protocol compliance) is out of scope for this change. The provenance regression suite is the acceptance gate.

---

## 9. File Layout After Implementation

```
src/striga/
    __init__.py
    semantics.py          # Existing, with lift_instruction added
    interpreter.py        # NEW: Interpreter, protocols, result types, helpers
    x86/
        *.py              # Existing semantic handlers, unchanged

tools/
    vmentry_provenance.py # Refactored to use Interpreter + ProvenanceDomain
    domains/              # Secondary, not required for initial merge
        concrete.py       # ConcreteDomain, ConcreteRegisters, ConcreteMemory
        taint.py          # TaintDomain, TaintRegisters, TaintMemory
        smt.py            # SmtDomain, SmtRegisters, SmtMemory
        interval.py       # IntervalDomain, IntervalRegisters
        counting.py       # CountingDomain, CountingRegisters
```

---

## 10. Design Decisions

1. **Width in memory write.** `MemoryState.write` takes an explicit `width: int` parameter. Domain values are not required to carry width metadata (plain `int` doesn't), so the interpreter passes width alongside the value.

2. **Bool vs BV in the SMT domain.** The SMT domain uses `T = smt.BVTerm | smt.BoolTerm` as a union. The `with_width` and `concrete_bool` methods handle the boundary between the two types.

3. **Symbolic memory addresses.** Out of scope. Both the provenance `MemoryModel` and the SMT `SmtMemory` return unknown for symbolic addresses. Array theory support in the SMT wire protocol is a future extension.

---

## 11. Future Work: Full Abstract Interpretation

This section describes the design changes needed to support multi-path fixed-point analysis over the interpreter. None of this is in scope for the current implementation. It is documented here so that the protocol additions (`join`, `bottom`, `is_leq`) have clear design context and so that a future implementer does not need to rediscover the constraints.

### 11.1. What single-trace execution cannot answer

The current interpreter follows one concrete path. Every domain is driven by `concrete_bool` picking a branch direction, and execution stops when the branch condition is not concretely determined. This is correct for VM-entry bootstrap (one entry RIP, one seed, one path) and for handler stepping where register inputs are known.

There are questions that require analyzing all paths through a piece of code simultaneously:

- What is the full set of handlers reachable from a dispatcher, across all opcode values?
- What is the maximum virtual stack depth a handler can produce, across all inputs?
- Which VM registers does a handler read and write on every path, not just the concrete path taken?
- Is a simplified handler replacement correct for every possible VM state, not just one sample input?
- Which handler table entries are unreachable under any valid bytecode input?

These require the analysis to follow both sides of a branch, combine results at merge points, and iterate through loops until the abstract state stabilizes.

### 11.2. The abstract interpretation execution model

Classical abstract interpretation replaces the single-trace driver with a worklist fixed-point solver. The driver maintains a map from block address to the current abstract state at that block's entry. When a block is analyzed, its output state is propagated to successor blocks. If a successor already has a state, the old and new states are joined (least upper bound). If the join produces a strictly wider state than what was there before, the successor is re-added to the worklist. The analysis terminates when no block's state grows — the fixed point.

```
initialize:
    block_states[entry] = initial_state
    worklist = [entry]

iterate:
    while worklist is not empty:
        rip = worklist.pop()
        input_state = block_states[rip]
        output_state, successor = interpreter.execute_block(block, input_state)

        for each target in successors(successor):
            existing = block_states.get(target)
            if existing is None:
                block_states[target] = output_state
                worklist.add(target)
            else:
                joined = domain.join(existing, output_state)  -- per register
                if not domain.is_leq(joined, existing):       -- per register
                    block_states[target] = joined
                    worklist.add(target)
```

### 11.3. Required interpreter changes

The current interpreter mutates register and memory state in place. The fixed-point driver needs to run a block with a given input state and get an output state without destroying the input, because the input may be needed again if the block is re-analyzed after a join widens its incoming state.

Two options:

1. Make `RegisterState` and `MemoryState` support cheap copying (snapshot before execution, keep original intact). The interpreter stays mostly unchanged but the driver copies state before each `execute_block` call.

2. Make the interpreter functionally pure: `execute_block` takes an immutable state and returns a new state. This is cleaner but requires more pervasive changes to the interpreter internals.

Option 1 is lower-risk and preserves compatibility with the single-trace driver.

### 11.4. SymbolicBranch semantics change

In the single-trace driver, `SymbolicBranch` means "stop." In the fixed-point driver, it means "fork — propagate the current state to both successors." The `SymbolicBranch` result type would need to carry both successor addresses:

```python
@dataclass(frozen=True)
class SymbolicBranch(Generic[T]):
    condition: T
    true_target: int
    false_target: int
```

This is backward-compatible: the single-trace driver ignores the target fields and stops. The fixed-point driver uses them to propagate.

### 11.5. Widening for loops

Without widening, a loop that increments a value causes the interval domain to iterate forever: `[0,0]` → `[0,1]` → `[0,2]` → ... Widening is an operator that jumps to a safe overapproximation after a threshold, guaranteeing termination at the cost of precision.

For intervals, widening is: if the new lower bound decreased, jump to 0; if the new upper bound increased, jump to the type maximum. One iteration of widening reaches the fixed point for any monotone loop.

Widening is deliberately not included in the current `ValueDomain` protocol. Its design is heavily domain-specific (intervals widen differently from taint sets, SMT terms need a different strategy entirely), and there is no sensible default. When the fixed-point driver is built, `widen` should be added to the protocol alongside a policy for identifying loop headers (back-edge targets in the lifted CFG).

### 11.6. Memory join

Register state is finite and fixed — joining is per-register. Memory is the hard problem. The current `MemoryState` is an open-ended dictionary from addresses to values. Joining two memory states means joining every address that either state has written to, and the address sets can differ between paths.

For VM analysis specifically, a practical approach is to partition memory into named finite regions: virtual stack slots, VM context fields, handler table entries. Each region has a fixed set of offsets with known widths. Joining is then per-slot within each region, identical to register joining. Accesses outside known regions return `bottom` or `unknown`.

This requires domain-specific knowledge of the VM layout, which makes it unsuitable for a fully generic `MemoryState` protocol. The likely implementation is a `PartitionedMemory` that takes a VM layout descriptor and implements `MemoryState` with finite joinable regions.

### 11.7. Which domains benefit

Not all domains are useful in a multi-path setting:

| Domain | Multi-path viable | Join behavior |
|---|---|---|
| Concrete (`int`) | No | No useful join — different values become "unknown" |
| Provenance (`SymVal`) | No | Expression text and concrete values cannot be meaningfully merged |
| Taint (`Tainted`) | Yes | Join is label set union; concrete value is lost but taint propagation remains sound |
| Interval | Yes | Join is enclosing interval; this is the classical use case for abstract interpretation |
| SMT | Theoretically | Join is disjunction (`ite`); expressions grow exponentially without simplification |
| Counting | No | Cost metrics are path-specific; joining counts from different paths is not meaningful |

The practical multi-path domains are intervals and taint. The SMT domain can work but needs aggressive expression simplification at join points to avoid blowup.

### 11.8. Use cases for VM analysis

**Handler dispatch coverage.** The VM dispatcher reads an opcode byte, indexes a table, and jumps to a handler. With the interval domain, the opcode index enters as `Interval(0, 255)`. The dispatcher's comparison cascade or table lookup produces interval-valued targets. At the boundary, the target interval spans all reachable handler addresses. This recovers the full handler table in one analysis pass instead of 256 concrete sweeps. For multi-byte dispatch keys or multi-level dispatch tables, the advantage grows.

**Virtual stack depth bounds.** VM handlers push and pop from a virtual stack modeled as a pointer offset. An interval analysis tracks the stack pointer's range across all paths through a handler or handler sequence. The resulting interval gives the maximum stack depth, which is needed for allocating concrete stack space during recompilation and for detecting potential stack overflow in the VM program.

**Dead register analysis.** A taint analysis over all paths determines which VM registers a handler reads on any path (tainted by the register's input label) and which it writes on every path (output always has taint from the handler's computation, never from the input label). Registers written on every path are dead-on-entry for successor handlers. This is the liveness information needed for register allocation during recompilation.

**Handler equivalence under all inputs.** When replacing an obfuscated handler with a simplified implementation, verification against a single concrete input is insufficient. An SMT domain with multi-path analysis builds symbolic expressions that cover all paths through both the original and replacement handlers. Asserting that the outputs differ and getting UNSAT proves equivalence for all inputs, not just the tested ones.

**Unreachable handler detection.** Starting from the entry point with the full range of valid bytecode inputs, an abstract interpretation shows which handlers have `bottom` (unreachable) incoming state. These handlers are never dispatched by any valid bytecode and can be classified as dead code, padding, or anti-analysis traps. This reduces the handler set that subsequent analysis stages need to process.

