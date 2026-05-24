from __future__ import annotations

import enum
from dataclasses import dataclass
from typing import Generic, Protocol, TypeVar, runtime_checkable

from llvm import BasicBlock, IntPredicate, Opcode, Type, Value

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

    def cast(
        self, op: Opcode, val: T, from_width: int | None, to_width: int | None
    ) -> T:
        """Evaluate trunc, zext, or sext."""
        ...

    def funnel_shift(
        self, high: T, low: T, amount: T, width: int | None, *, left: bool
    ) -> T:
        """Evaluate llvm.fshl.* or llvm.fshr.*."""
        ...

    def concrete_bool(self, val: T) -> bool | None:
        """Extract a concrete boolean if possible. Returns None if symbolic/unknown."""
        ...

    def with_width(self, val: T, width: int | None, *, signed: bool = False) -> T:
        """Resize a domain value (trunc/zext/sext to target width)."""
        ...


@runtime_checkable
class AbstractValueDomain(ValueDomain[T], Protocol[T]):
    """Extended domain protocol for future multi-path fixed-point analysis."""

    def join(self, a: T, b: T) -> T:
        """Least upper bound of two abstract values at a control-flow merge."""
        ...

    def bottom(self, width: int | None) -> T:
        """Least element representing unreachable / no information yet."""
        ...

    def is_leq(self, a: T, b: T) -> bool:
        """Return whether ``a`` is already approximated by ``b``."""
        ...


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

    def text(self) -> str:
        if self.kind == PtrKind.STATE:
            return f"state.{self.reg}"
        if self.kind == PtrKind.MEMORY and self.offset is not None:
            text_attr = getattr(self.offset, "text", None)
            text = text_attr if isinstance(text_attr, str) else str(self.offset)
            return f"memory[{text}]"
        return "unknown_ptr"


@dataclass(frozen=True)
class BoundaryResult(Generic[T]):
    """Execution reached a __striga_* boundary intrinsic."""

    name: str
    target: T
    target_arg: Value
    target_ptr: PtrVal[T] | None


@dataclass(frozen=True)
class SymbolicBranch(Generic[T]):
    """Execution reached a conditional branch with a non-concrete condition."""

    condition: T
    true_target: int
    false_target: int


@dataclass(frozen=True)
class StopResult(Generic[T]):
    """Execution stopped at a ret or unsupported terminator."""

    reason: str
    value: T | None = None


@runtime_checkable
class InstructionHooks(Protocol[T]):
    """Optional hooks called by the interpreter around instruction execution."""

    def pre_instruction(self, inst: Value) -> None: ...

    def post_store(self, inst: Value, value: T, ptr: PtrVal[T]) -> T: ...

    def post_boundary(
        self,
        inst: Value,
        name: str,
        target: T,
        target_arg: Value,
        target_ptr: PtrVal[T] | None,
    ) -> T: ...


BINARY_OPS = frozenset(
    {
        Opcode.Add,
        Opcode.Sub,
        Opcode.Mul,
        Opcode.UDiv,
        Opcode.SDiv,
        Opcode.URem,
        Opcode.SRem,
        Opcode.And,
        Opcode.Or,
        Opcode.Xor,
        Opcode.Shl,
        Opcode.LShr,
        Opcode.AShr,
    }
)


class Interpreter(Generic[T]):
    def __init__(
        self,
        domain: ValueDomain[T],
        regs: RegisterState[T],
        memory: MemoryState[T],
        reg_sizes: dict[str, int],
        state_ty: Type,
        reg_indices: dict[str, int],
        hooks: InstructionHooks[T] | None = None,
    ) -> None:
        self.domain = domain
        self.regs = regs
        self.memory = memory
        self.reg_sizes = reg_sizes
        self.state_ty = state_ty
        self.reg_indices = reg_indices
        self.hooks = hooks
        self._locals: dict[int, T | PtrVal[T]] = {}

    def execute_block(
        self, block: BasicBlock
    ) -> int | BoundaryResult[T] | SymbolicBranch[T] | StopResult[T]:
        """Execute all instructions in a basic block."""
        self._locals = {}
        for inst in block.instructions:
            if inst == block.terminator:
                break
            boundary = self._execute_instruction(inst)
            if boundary is not None:
                return boundary
        terminator = block.terminator
        if terminator is None:
            return StopResult("missing_terminator")
        return self._execute_terminator(terminator)

    def eval_value(self, value: Value) -> T:
        """Evaluate an LLVM Value into the domain."""
        cached = self._locals.get(hash(value))
        if cached is not None and not isinstance(cached, PtrVal):
            return cached

        width = value_width(value)
        if value.is_constant_int:
            return self.domain.constant(value.const_zext_value, width)
        if value.is_argument:
            if value.name == "memory":
                return self.domain.unknown("%memory", width)
            if value.name == "state":
                return self.domain.unknown("%state", width)
            return self.domain.unknown(f"%{value.name}", width)
        if not value.is_instruction:
            return self.domain.unknown(str(value).strip(), width)

        op = value.opcode
        if op == Opcode.Load:
            ptr = self.eval_pointer(value.get_operand(0))
            if ptr.kind == PtrKind.STATE and ptr.reg is not None:
                return self.domain.with_width(self.regs.read(ptr.reg), width)
            if (
                ptr.kind == PtrKind.MEMORY
                and ptr.offset is not None
                and width is not None
            ):
                return self.memory.read(
                    self.domain.with_width(ptr.offset, 64),
                    width,
                    insn_addr=instruction_address_from_metadata(value) or 0,
                )
            return self.domain.unknown(f"load({ptr.text()})", width)
        if op == Opcode.Call:
            result = self._eval_call(value)
            if isinstance(result, BoundaryResult):
                return result.target
            return result
        if op in BINARY_OPS:
            return self._eval_binary(value)
        if op in {Opcode.Trunc, Opcode.ZExt, Opcode.SExt}:
            inner = self.eval_value(value.get_operand(0))
            from_width = value_width(value.get_operand(0))
            return self.domain.cast(op, inner, from_width, width)
        if op == Opcode.ICmp:
            lhs = self.eval_value(value.get_operand(0))
            rhs = self.domain.with_width(
                self.eval_value(value.get_operand(1)), value_width(value.get_operand(0))
            )
            return self.domain.icmp(
                value.icmp_predicate, lhs, rhs, value_width(value.get_operand(0))
            )
        if op == Opcode.Select:
            cond = self.domain.with_width(self.eval_value(value.get_operand(0)), 1)
            true_value = self.domain.with_width(
                self.eval_value(value.get_operand(1)), width
            )
            false_value = self.domain.with_width(
                self.eval_value(value.get_operand(2)), width
            )
            return self.domain.select(cond, true_value, false_value, width)
        if op == Opcode.GetElementPtr:
            ptr = self.eval_pointer(value)
            if ptr.kind == PtrKind.MEMORY and ptr.offset is not None:
                return ptr.offset
            return self.domain.unknown(ptr.text(), width)
        if op == Opcode.PtrToInt:
            ptr = self.eval_pointer(value.get_operand(0))
            if ptr.kind == PtrKind.MEMORY and ptr.offset is not None:
                return self.domain.with_width(ptr.offset, width)
            return self.domain.unknown(f"ptrtoint({ptr.text()})", width)
        if op == Opcode.IntToPtr:
            return self.domain.with_width(self.eval_value(value.get_operand(0)), width)

        return self.domain.unknown(
            f"unsupported:{op.value}:{str(value).strip()}", width
        )

    def eval_pointer(self, value: Value) -> PtrVal[T]:
        """Evaluate an LLVM Value as a state, memory, or unknown pointer."""
        cached = self._locals.get(hash(value))
        if isinstance(cached, PtrVal):
            return cached

        if value.is_argument:
            if value.name == "memory":
                return PtrVal(PtrKind.MEMORY, self.domain.constant(0, 64))
            if value.name == "state":
                return PtrVal(PtrKind.STATE, reg="root")

        if value.is_instruction and value.opcode == Opcode.GetElementPtr:
            state_reg = self._state_reg_from_gep(value)
            if state_reg is not None:
                return PtrVal(PtrKind.STATE, reg=state_reg)

            base_ptr = self.eval_pointer(value.get_operand(0))
            index = self.domain.with_width(
                self.eval_value(value.get_operand(value.num_operands - 1)), 64
            )
            if base_ptr.kind == PtrKind.MEMORY and base_ptr.offset is not None:
                return PtrVal(
                    PtrKind.MEMORY,
                    self.domain.binary(Opcode.Add, base_ptr.offset, index, 64),
                )
            return PtrVal(PtrKind.UNKNOWN)

        as_value = self.domain.with_width(self.eval_value(value), 64)
        return PtrVal(PtrKind.MEMORY, as_value)

    def _execute_instruction(self, inst: Value) -> BoundaryResult[T] | None:
        if self.hooks is not None:
            self.hooks.pre_instruction(inst)

        op = inst.opcode
        if op == Opcode.Store:
            value = self.eval_value(inst.get_operand(0))
            ptr = self.eval_pointer(inst.get_operand(1))
            if self.hooks is not None:
                value = self.hooks.post_store(inst, value, ptr)
            if ptr.kind == PtrKind.STATE and ptr.reg is not None:
                self.regs.write(
                    ptr.reg, self.domain.with_width(value, self.regs.width(ptr.reg))
                )
            elif ptr.kind == PtrKind.MEMORY and ptr.offset is not None:
                width = value_width(inst.get_operand(0))
                if width is not None:
                    self.memory.write(
                        self.domain.with_width(ptr.offset, 64),
                        self.domain.with_width(value, width),
                        width,
                        insn_addr=instruction_address_from_metadata(inst) or 0,
                    )
            return None

        if op == Opcode.Call:
            result = self._eval_call(inst)
            if isinstance(result, BoundaryResult):
                return result
            if not inst.type.is_void:
                self._locals[hash(inst)] = result
            return None

        if inst.type.is_void:
            return None

        if op == Opcode.GetElementPtr:
            self._locals[hash(inst)] = self.eval_pointer(inst)
        else:
            self._locals[hash(inst)] = self.eval_value(inst)
        return None

    def _execute_terminator(
        self, term: Value
    ) -> int | SymbolicBranch[T] | StopResult[T]:
        if term.opcode == Opcode.Br:
            if term.is_conditional:
                cond = self.domain.with_width(self.eval_value(term.condition), 1)
                true_target = block_address(term.get_successor(0))
                false_target = block_address(term.get_successor(1))
                if true_target is None or false_target is None:
                    return StopResult(
                        "unsupported_branch_target",
                        self.domain.unknown(str(term).strip(), None),
                    )
                concrete = self.domain.concrete_bool(cond)
                if concrete is None:
                    return SymbolicBranch(cond, true_target, false_target)
                return true_target if concrete else false_target
            target = block_address(term.get_successor(0))
            if target is None:
                return StopResult(
                    "unsupported_branch_target",
                    self.domain.unknown(str(term).strip(), None),
                )
            return target

        if term.opcode == Opcode.Ret:
            if term.num_operands:
                return StopResult("ret", self.eval_value(term.get_operand(0)))
            return StopResult("ret")

        return StopResult(
            f"unsupported_terminator_{term.opcode.value}",
            self.domain.unknown(str(term).strip(), None),
        )

    def _eval_call(self, inst: Value) -> T | BoundaryResult[T]:
        name = call_name(inst)
        width = value_width(inst)
        if name is None:
            return self.domain.unknown("unknown_call()", width)
        if name.startswith("__striga_undef_"):
            return self.domain.unknown(f"{name}()", width)
        if name in {
            "__striga_jmp",
            "__striga_call",
            "__striga_ret",
            "__striga_syscall",
        }:
            target_arg = inst.get_arg_operand(0)
            target = self.domain.with_width(self.eval_value(target_arg), 64)
            target_ptr = None
            if target_arg.is_instruction and target_arg.opcode == Opcode.Load:
                target_ptr = self.eval_pointer(target_arg.get_operand(0))
            if self.hooks is not None:
                target = self.hooks.post_boundary(
                    inst, name, target, target_arg, target_ptr
                )
            return BoundaryResult(name, target, target_arg, target_ptr)
        if name.startswith("llvm.fshl."):
            return self._eval_funnel_shift(inst, left=True)
        if name.startswith("llvm.fshr."):
            return self._eval_funnel_shift(inst, left=False)
        return self.domain.unknown(f"{name}()", width)

    def _eval_binary(self, value: Value) -> T:
        width = value_width(value)
        lhs = self.domain.with_width(self.eval_value(value.get_operand(0)), width)
        rhs = self.domain.with_width(self.eval_value(value.get_operand(1)), width)
        return self.domain.binary(value.opcode, lhs, rhs, width)

    def _eval_funnel_shift(self, value: Value, *, left: bool) -> T:
        width = value_width(value)
        high = self.domain.with_width(self.eval_value(value.get_arg_operand(0)), width)
        low = self.domain.with_width(self.eval_value(value.get_arg_operand(1)), width)
        amount = self.domain.with_width(
            self.eval_value(value.get_arg_operand(2)), width
        )
        return self.domain.funnel_shift(high, low, amount, width, left=left)

    def _state_reg_from_gep(self, value: Value) -> str | None:
        if value.gep_source_element_type != self.state_ty:
            return None
        base = value.get_operand(0) if value.num_operands else None
        if base is None or not base.is_argument or base.name != "state":
            return None
        field_index = self._constant_gep_field_index(value)
        if field_index is not None:
            for name, index in self.reg_indices.items():
                if index == field_index:
                    return name
        if value.name in self.reg_sizes:
            return value.name
        return None

    @staticmethod
    def _constant_gep_field_index(value: Value) -> int | None:
        if value.num_operands < 3:
            return None
        field = value.get_operand(value.num_operands - 1)
        if not field.is_constant_int:
            return None
        return field.const_zext_value


# Helpers used by both interpreter users and compatibility drivers.


def value_width(value: Value) -> int | None:
    return value.type.int_width if value.type.is_integer else None


def call_name(value: Value) -> str | None:
    if not value.is_instruction or value.opcode != Opcode.Call:
        return None
    called = value.called_value
    return called.name if called is not None else None


def instruction_address_from_metadata(inst: Value) -> int | None:
    name = inst.name
    if name.startswith("mem_read_"):
        token = name.removeprefix("mem_read_").split(".", 1)[0]
        try:
            return int(token, 16)
        except ValueError:
            pass
    md = inst.metadata.get("striga.insn")
    if md is None or not md.is_node:
        return None
    operands = md.operands
    if not operands or not operands[0].is_string:
        return None
    return int(operands[0].string, 0)


def block_address(block: BasicBlock) -> int | None:
    name = block.name
    if name.startswith("insn_"):
        return int(name.removeprefix("insn_"), 16)
    return None
