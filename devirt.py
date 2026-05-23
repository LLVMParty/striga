from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from llvm import Linkage, Opcode, Value, create_context

from bfs import lift_bfs
from container import PEContainer


BINARYSHIELD_PATH = "tests/binaryshield.exe"
FUNCTION_ADDRESS = 0x1400016D0
VM_ENTRY_ADDRESS = 0x140017A41
FIRST_HANDLER = 0x140016000
BYTECODE_RVA = 0x1678F
RETURN_SENTINEL = 0x7FFF0000

# Mirrors emulate.py's deterministic process layout.
STACK_BASE = 0x100000
STACK_SIZE = 0x10000
STACK_TOP = STACK_BASE + STACK_SIZE - 0x100
ENTRY_RSP = (STACK_TOP & ~0xF) - 0x28
VM_ENTRY_RSP = ENTRY_RSP - 8  # after `push 0x1678f` at VM_ENTRY_ADDRESS
TEB_BASE = STACK_BASE + STACK_SIZE
PEB_BASE = TEB_BASE + 0x1000

# Covers the VM frame and operand stack observed in the BinaryShield traces.
VM_MEM_BASE = 0x10FD00
VM_MEM_SIZE = 0x300
# Recovery also localizes synthetic environment slots used to derive imagebase
# (TEB/PEB), without making tracing track those bytes as VM stack state.
LOCAL_MEM_SIZE = (PEB_BASE + 0x18) - VM_MEM_BASE

OPT_PIPELINE = "sroa,instcombine<no-verify-fixpoint>,early-cse<memssa>,gvn,simplifycfg,dse,adce"
MAX_TRACE_NODES = 2000
MAX_FOLD_ROUNDS = 8
DUMP_DIR_ENV = "STRIGA_DEVIRT_DUMP_DIR"
DUMP_TRACE_ADDRS_ENV = "STRIGA_DEVIRT_DUMP_TRACE_ADDRS"


def _parse_addr_set(text: str | None) -> set[int]:
    if not text:
        return set()
    addrs: set[int] = set()
    for part in text.split(","):
        part = part.strip()
        if part:
            addrs.add(int(part, 0))
    return addrs


@dataclass(frozen=True)
class AbsValue:
    width: int
    value: int | None = None
    symbol: str | None = None

    @property
    def is_concrete(self) -> bool:
        return self.value is not None

    @staticmethod
    def concrete(width: int, value: int) -> "AbsValue":
        return AbsValue(width, value & ((1 << width) - 1), None)

    @staticmethod
    def symbolic(width: int, symbol: str) -> "AbsValue":
        return AbsValue(width, None, symbol)


@dataclass
class TraceState:
    regs: dict[str, AbsValue]
    mem: dict[int, AbsValue]

    def concrete_key(self) -> tuple:
        reg_items = tuple(
            sorted(
                (name, value.width, value.value)
                for name, value in self.regs.items()
                if value.is_concrete
            )
        )
        mem_items = tuple(
            sorted(
                (addr, value.value)
                for addr, value in self.mem.items()
                if value.is_concrete and value.value != 0
            )
        )
        return reg_items, mem_items


@dataclass(frozen=True)
class NodeKey:
    addr: int
    concrete_key: tuple


@dataclass
class TraceOutcome:
    event: str
    target: int | None
    post_state: TraceState
    target_expr: str = ""


@dataclass
class TraceNode:
    addr: int
    state: TraceState
    key: NodeKey


@dataclass
class TraceEdge:
    src: NodeKey
    event: str
    target: int | None
    dst: NodeKey | None


@dataclass
class TraceGraph:
    nodes: dict[NodeKey, TraceNode] = field(default_factory=dict)
    edges: list[TraceEdge] = field(default_factory=list)


class SymbolNamer:
    def __init__(self) -> None:
        self._next = 0

    def new(self, prefix: str, width: int) -> AbsValue:
        self._next += 1
        return AbsValue.symbolic(width, f"{prefix}_{self._next}")


class HandlerTracer:
    def __init__(self, container: PEContainer, *, mem_base: int, mem_size: int):
        self.container = container
        self.mem_base = mem_base
        self.mem_size = mem_size
        self.namer = SymbolNamer()
        dump_dir = os.environ.get(DUMP_DIR_ENV)
        self.dump_dir = Path(dump_dir) if dump_dir else None
        self.dump_trace_addrs = _parse_addr_set(os.environ.get(DUMP_TRACE_ADDRS_ENV))
        self._dumped_resolver_stages: set[tuple[int, str]] = set()

    @property
    def mem_end(self) -> int:
        return self.mem_base + self.mem_size

    def _dump_resolver(self, addr: int, stage: str, resolver: Value) -> None:
        if self.dump_dir is None or addr not in self.dump_trace_addrs:
            return
        key = (addr, stage)
        if key in self._dumped_resolver_stages:
            return
        self._dumped_resolver_stages.add(key)
        out_dir = self.dump_dir / "resolvers"
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / f"{addr:x}-{stage}.ll").write_text(str(resolver) + "\n", encoding="utf-8")

    def initial_state(self, *, symbolic_rcx: bool = True, rcx_value: int = 0) -> TraceState:
        with create_context() as context:
            with context.create_module("state_layout") as module:
                sem = lift_bfs(module, self.container, FIRST_HANDLER, verbose=False)
                regs: dict[str, AbsValue] = {}
                for name, ty in sem.reg_types.items():
                    regs[name] = AbsValue.concrete(ty.int_width, 0)

        regs["rsp"] = AbsValue.concrete(64, VM_ENTRY_RSP)
        regs["gsbase"] = AbsValue.concrete(64, TEB_BASE)
        regs["rcx"] = (
            AbsValue.symbolic(64, "arg_rcx")
            if symbolic_rcx
            else AbsValue.concrete(64, rcx_value)
        )

        mem = {
            addr: AbsValue.concrete(8, 0)
            for addr in range(self.mem_base, self.mem_end)
        }
        self._write_int(mem, ENTRY_RSP, 64, RETURN_SENTINEL)
        self._write_int(mem, VM_ENTRY_RSP, 64, BYTECODE_RVA)
        return TraceState(regs, mem)

    def trace_handler(self, addr: int, state: TraceState) -> list[TraceOutcome]:
        with create_context() as context:
            types = context.types
            with context.create_module(f"trace_{addr:x}") as module:
                sem = lift_bfs(module, self.container, addr, verbose=False)
                ram = module.add_global(types.array(types.i8, 0), "RAM")

                result_fields = [types.i8, types.i64]
                result_fields.extend(sem.reg_types.values())
                result_ty = types.struct(f"TraceResult_{addr:x}", result_fields)

                param_specs: list[tuple[str, str | int, AbsValue]] = []
                for name, value in state.regs.items():
                    if not value.is_concrete:
                        param_specs.append(("reg", name, value))
                for mem_addr, value in sorted(state.mem.items()):
                    if not value.is_concrete:
                        param_specs.append(("mem", mem_addr, value))

                resolver_ty = types.function(
                    result_ty,
                    [types.int_n(spec[2].width) for spec in param_specs],
                )
                resolver = module.add_function(f"resolver_{addr:x}", resolver_ty)
                resolver.linkage = Linkage.Internal

                param_values: dict[tuple[str, str | int], Value] = {}
                for i, spec in enumerate(param_specs):
                    param = resolver.get_param(i)
                    kind, key, abs_value = spec
                    param.name = abs_value.symbol or f"{kind}_{key}"
                    param_values[(kind, key)] = param

                entry = resolver.append_basic_block("entry")
                with entry.create_builder() as ir:
                    state_alloca = ir.alloca(sem.state_ty, "state")

                    def reg_ptr(reg_name: str) -> Value:
                        return ir.struct_gep(
                            sem.state_ty,
                            state_alloca,
                            sem.reg_indices[reg_name],
                            reg_name,
                        )

                    for name, ty in sem.reg_types.items():
                        abs_value = state.regs.get(name, AbsValue.concrete(ty.int_width, 0))
                        value = self._materialize_abs_value(types, abs_value, param_values[("reg", name)] if not abs_value.is_concrete else None)
                        ir.store(value, reg_ptr(name))

                    self._store_mem64(ir, types, ram, TEB_BASE + 0x60, PEB_BASE)
                    self._store_mem64(ir, types, ram, PEB_BASE + 0x10, self.container.image_base)

                    for mem_addr in range(self.mem_base, self.mem_end, 8):
                        ptr = ir.gep(types.i8, ram, [types.i64.constant(mem_addr)])
                        value = types.i64.constant(0)
                        for byte_index in range(8):
                            byte_addr = mem_addr + byte_index
                            if byte_addr >= self.mem_end:
                                break
                            abs_value = state.mem.get(byte_addr, AbsValue.concrete(8, 0))
                            if abs_value.is_concrete:
                                byte = types.i8.constant(abs_value.value or 0)
                            else:
                                byte = param_values[("mem", byte_addr)]
                            widened = ir.zext(byte, types.i64)
                            if byte_index:
                                widened = ir.shl(widened, types.i64.constant(byte_index * 8))
                            value = ir.or_(value, widened)
                        store = ir.store(value, ptr)
                        store.inst_alignment = 1

                    ir.call(sem.function, [state_alloca, ram])
                    ir.unreachable()

                self._dump_resolver(addr, "01-built", resolver)
                module.verify_or_raise()
                module.optimize("always-inline")
                self._dump_resolver(addr, "02-inlined-before-hook-rewrite", resolver)
                self._rewrite_hooks(module, resolver, sem, state_alloca, ram, result_ty)
                self._dump_resolver(addr, "03-hook-rewritten", resolver)
                module.verify_or_raise()

                for _ in range(MAX_FOLD_ROUNDS):
                    module.optimize(OPT_PIPELINE)
                    self._fold_ram_loads(module, resolver, ram, state, param_values)
                    module.verify_or_raise()
                module.optimize(OPT_PIPELINE)
                module.verify_or_raise()
                self._dump_resolver(addr, "04-optimized", resolver)

                return self._read_outcomes(resolver, sem, result_ty, ram, state)

    def _materialize_abs_value(self, types, abs_value: AbsValue, param: Value | None) -> Value:
        ty = types.int_n(abs_value.width)
        if abs_value.is_concrete:
            return ty.constant(abs_value.value or 0)
        assert param is not None
        return param

    def _store_mem64(self, ir, types, ram: Value, addr: int, value: int) -> None:
        ptr = ir.gep(types.i8, ram, [types.i64.constant(addr)])
        store = ir.store(types.i64.constant(value), ptr)
        store.inst_alignment = 1

    def _rewrite_hooks(self, module, resolver: Value, sem, state_alloca: Value, ram: Value, result_ty) -> None:
        hook_events = {
            "__striga_jmp": 1,
            "__striga_call": 2,
            "__striga_ret": 3,
            "__striga_syscall": 4,
        }
        calls: list[Value] = []
        for block in resolver.basic_blocks:
            for inst in list(block.instructions):
                if not inst.is_call_inst:
                    continue
                called = inst.called_value
                name = getattr(called, "name", "")
                if name in hook_events:
                    calls.append(inst)

        types = module.context.types
        for call in calls:
            event = hook_events[call.called_value.name]
            target = call.get_arg_operand(0)
            if target.type.int_width < 64:
                with call.create_builder() as ir:
                    target = ir.zext(target, types.i64)
            elif target.type.int_width > 64:
                with call.create_builder() as ir:
                    target = ir.trunc(target, types.i64)

            block = call.parent
            with call.create_builder() as ir:
                agg = result_ty.undef()
                agg = ir.insert_value(agg, types.i8.constant(event), 0)
                agg = ir.insert_value(agg, target, 1)

                idx = 2
                for name, ty in sem.reg_types.items():
                    ptr = ir.struct_gep(
                        sem.state_ty,
                        state_alloca,
                        sem.reg_indices[name],
                        f"{name}_snap",
                    )
                    value = ir.load(ty, ptr)
                    agg = ir.insert_value(agg, value, idx)
                    idx += 1

                ir.ret(agg)

            erase = False
            doomed: list[Value] = []
            for inst in list(block.instructions):
                if inst == call:
                    erase = True
                if erase:
                    doomed.append(inst)
            for inst in doomed:
                inst.erase_from_parent()

    def _fold_ram_loads(
        self,
        module,
        resolver: Value,
        ram: Value,
        input_state: TraceState,
        param_values: dict[tuple[str, str | int], Value],
    ) -> int:
        store_ranges = self._collect_store_ranges(resolver, ram)
        folded = 0
        for block in list(resolver.basic_blocks):
            for inst in list(block.instructions):
                if inst.opcode != Opcode.Load:
                    continue
                if not inst.type.is_integer:
                    continue
                ptr = inst.get_operand(0)
                offset_value = self._ram_gep_offset(ptr, ram)
                if offset_value is None:
                    continue
                size = inst.type.int_width // 8

                replacement = None
                finite_offsets = self._finite_ints(offset_value)
                if finite_offsets and all(
                    self.container.in_range(off)
                    and self.container.in_range(off + size - 1)
                    and not self._range_overlaps_any(off, size, store_ranges)
                    for off in finite_offsets
                ):
                    with inst.create_builder() as ir:
                        replacement = self._build_static_load_expr(ir, inst.type, offset_value, size)

                if replacement is None:
                    finite_offsets = self._finite_ints(offset_value)
                    if finite_offsets and all(
                        self.mem_base <= off
                        and off + size <= self.mem_end
                        and not self._range_overlaps_any(off, size, store_ranges)
                        for off in finite_offsets
                    ):
                        with inst.create_builder() as ir:
                            replacement = self._build_tracked_mem_expr(
                                ir,
                                module.context.types,
                                inst.type,
                                offset_value,
                                size,
                                input_state,
                                param_values,
                            )

                if replacement is not None:
                    inst.replace_all_uses_with(replacement)
                    inst.erase_from_parent()
                    folded += 1
        return folded

    def _collect_store_ranges(self, resolver: Value, ram: Value) -> list[tuple[int, int]]:
        ranges: list[tuple[int, int]] = []
        for block in resolver.basic_blocks:
            for inst in block.instructions:
                if inst.opcode != Opcode.Store:
                    continue
                ptr = inst.get_operand(1)
                offset = self._ram_gep_offset(ptr, ram)
                if offset is None or not offset.is_constant_int:
                    continue
                value = inst.get_operand(0)
                if not value.type.is_integer:
                    continue
                ranges.append((offset.const_zext_value, value.type.int_width // 8))
        return ranges

    def _ram_gep_offset(self, value: Value, ram: Value) -> Value | None:
        if value.is_constant_expr and value.const_opcode == Opcode.GetElementPtr:
            if value.num_operands == 2 and value.get_operand(0) == ram:
                return value.get_operand(1)
            if value.num_operands == 3 and value.get_operand(0) == ram:
                zero = value.get_operand(1)
                if zero.is_constant_int and zero.const_zext_value == 0:
                    return value.get_operand(2)
        if value.is_instruction and value.opcode == Opcode.GetElementPtr:
            if value.num_operands == 2 and value.get_operand(0) == ram:
                return value.get_operand(1)
            if value.num_operands == 3 and value.get_operand(0) == ram:
                zero = value.get_operand(1)
                if zero.is_constant_int and zero.const_zext_value == 0:
                    return value.get_operand(2)
        return None

    def _finite_ints(self, value: Value, limit: int = 16) -> set[int] | None:
        if value.is_constant_int:
            return {value.const_zext_value}
        if value.is_instruction and value.opcode == Opcode.Select:
            lhs = self._finite_ints(value.get_operand(1), limit)
            rhs = self._finite_ints(value.get_operand(2), limit)
            if lhs is None or rhs is None:
                return None
            result = lhs | rhs
            return result if len(result) <= limit else None
        return None

    def _build_static_load_expr(self, ir, ty, offset_value: Value, size: int) -> Value:
        if offset_value.is_constant_int:
            addr = offset_value.const_zext_value
            data = self.container.get_data(addr, size)
            return ty.constant(str(int.from_bytes(data, "little")), 10)
        assert offset_value.is_instruction and offset_value.opcode == Opcode.Select
        cond = offset_value.get_operand(0)
        true_value = self._build_static_load_expr(ir, ty, offset_value.get_operand(1), size)
        false_value = self._build_static_load_expr(ir, ty, offset_value.get_operand(2), size)
        return ir.select(cond, true_value, false_value)

    def _build_tracked_mem_expr(
        self,
        ir,
        types,
        ty,
        offset_value: Value,
        size: int,
        input_state: TraceState,
        param_values: dict[tuple[str, str | int], Value],
    ) -> Value:
        if offset_value.is_constant_int:
            addr = offset_value.const_zext_value
            result = ty.constant(0)
            for i in range(size):
                byte_abs = input_state.mem.get(addr + i, AbsValue.concrete(8, 0))
                if byte_abs.is_concrete:
                    byte = types.i8.constant(byte_abs.value or 0)
                else:
                    byte = param_values[("mem", addr + i)]
                widened = ir.zext(byte, ty) if ty.int_width > 8 else byte
                if i:
                    widened = ir.shl(widened, ty.constant(i * 8))
                result = ir.or_(result, widened)
            return result
        assert offset_value.is_instruction and offset_value.opcode == Opcode.Select
        cond = offset_value.get_operand(0)
        true_value = self._build_tracked_mem_expr(
            ir, types, ty, offset_value.get_operand(1), size, input_state, param_values
        )
        false_value = self._build_tracked_mem_expr(
            ir, types, ty, offset_value.get_operand(2), size, input_state, param_values
        )
        return ir.select(cond, true_value, false_value)

    def _range_overlaps_any(self, addr: int, size: int, ranges: Iterable[tuple[int, int]]) -> bool:
        end = addr + size
        return any(max(addr, start) < min(end, start + width) for start, width in ranges)

    def _read_outcomes(
        self,
        resolver: Value,
        sem,
        result_ty,
        ram: Value,
        input_state: TraceState,
    ) -> list[TraceOutcome]:
        outcomes: list[TraceOutcome] = []
        field_count = 2 + len(sem.reg_types)
        post_mem = self._derive_post_mem(resolver, ram, input_state)
        for block in resolver.basic_blocks:
            term = block.terminator
            if term is None or term.opcode != Opcode.Ret:
                continue
            ret_value = term.get_operand(0)
            fields = self._aggregate_elements(ret_value, field_count)
            event_value = fields[0]
            target_value = fields[1]
            if event_value is None or not event_value.is_constant_int:
                outcomes.append(TraceOutcome("unresolved", None, self._unknown_state(sem)))
                continue
            event = {1: "jmp", 2: "call", 3: "ret", 4: "syscall"}.get(
                event_value.const_zext_value,
                "unresolved",
            )

            target_values = self._split_outcome_constraints(target_value, fields[2:])
            for concrete_target, constraint in target_values:
                specialized = [self._specialize_value(v, constraint) for v in fields]
                target = concrete_target
                if target is None:
                    v = specialized[1]
                    if v is not None and v.is_constant_int:
                        target = v.const_zext_value

                regs: dict[str, AbsValue] = {}
                idx = 2
                for name, ty in sem.reg_types.items():
                    regs[name] = self._classify_value(specialized[idx], ty.int_width, f"{name}_{block.name}")
                    idx += 1

                outcomes.append(
                    TraceOutcome(
                        event,
                        target,
                        TraceState(regs, dict(post_mem)),
                        target_expr=str(target_value) if target_value is not None else "",
                    )
                )
        return outcomes or [TraceOutcome("unresolved", None, self._unknown_state(sem))]

    def _derive_post_mem(
        self,
        resolver: Value,
        ram: Value,
        input_state: TraceState,
    ) -> dict[int, AbsValue]:
        mem = dict(input_state.mem)
        for block in resolver.basic_blocks:
            for inst in block.instructions:
                if inst.opcode != Opcode.Store:
                    continue
                ptr = inst.get_operand(1)
                offset = self._ram_gep_offset(ptr, ram)
                if offset is None or not offset.is_constant_int:
                    continue
                addr = offset.const_zext_value
                value = inst.get_operand(0)
                if not value.type.is_integer:
                    continue
                size = value.type.int_width // 8
                if addr + size <= self.mem_base or addr >= self.mem_end:
                    continue
                for i in range(size):
                    byte_addr = addr + i
                    if not (self.mem_base <= byte_addr < self.mem_end):
                        continue
                    if value.is_constant_int:
                        byte = (value.const_zext_value >> (8 * i)) & 0xFF
                        mem[byte_addr] = AbsValue.concrete(8, byte)
                    else:
                        mem[byte_addr] = self.namer.new(f"mem_{byte_addr:x}_store", 8)
        return mem

    def _aggregate_elements(self, value: Value, count: int) -> list[Value | None]:
        result: list[Value | None] = [None] * count

        def visit(v: Value) -> None:
            if v.is_constant_struct:
                for i in range(min(count, v.num_operands)):
                    result[i] = v.get_aggregate_element(i)
                return
            if v.is_undef or v.is_poison:
                return
            if v.is_instruction and v.opcode == Opcode.InsertValue:
                visit(v.get_operand(0))
                if v.num_indices == 1:
                    idx = v.indices[0]
                    if 0 <= idx < count:
                        result[idx] = v.get_operand(1)
                return

        visit(value)
        return result

    def _split_outcome_constraints(
        self,
        target: Value | None,
        state_fields: list[Value | None],
    ) -> list[tuple[int | None, tuple[Value, bool] | None]]:
        if target is not None and target.is_instruction and target.opcode == Opcode.Select:
            split = self._split_select_constants(target, use_leaf_as_target=True)
            if split:
                return split

        for state_field in state_fields:
            if state_field is None:
                continue
            if state_field.is_instruction and state_field.opcode == Opcode.Select:
                split = self._split_select_constants(state_field, use_leaf_as_target=False)
                if split:
                    if target is not None and target.is_constant_int:
                        return [(target.const_zext_value, constraint) for _, constraint in split]
                    return split

        if target is not None and target.is_constant_int:
            return [(target.const_zext_value, None)]
        return [(None, None)]

    def _split_select_constants(
        self,
        value: Value,
        *,
        use_leaf_as_target: bool,
    ) -> list[tuple[int | None, tuple[Value, bool] | None]]:
        cond = value.get_operand(0)
        true_value = value.get_operand(1)
        false_value = value.get_operand(2)
        out: list[tuple[int | None, tuple[Value, bool] | None]] = []
        if true_value.is_constant_int:
            target = true_value.const_zext_value if use_leaf_as_target else None
            out.append((target, (cond, True)))
        if false_value.is_constant_int:
            target = false_value.const_zext_value if use_leaf_as_target else None
            out.append((target, (cond, False)))
        return out

    def _specialize_value(self, value: Value | None, constraint: tuple[Value, bool] | None) -> Value | None:
        if value is None or constraint is None:
            return value
        cond, want_true = constraint
        if value.is_instruction and value.opcode == Opcode.Select and value.get_operand(0) == cond:
            return value.get_operand(1 if want_true else 2)
        return value

    def _classify_value(self, value: Value | None, width: int, prefix: str) -> AbsValue:
        if value is not None and value.is_constant_int:
            return AbsValue.concrete(width, value.const_zext_value)
        return self.namer.new(prefix, width)

    def _unknown_state(self, sem) -> TraceState:
        regs = {
            name: self.namer.new(name, ty.int_width)
            for name, ty in sem.reg_types.items()
        }
        mem = {
            self.mem_base + offset: self.namer.new(f"mem_{self.mem_base + offset:x}", 8)
            for offset in range(self.mem_size)
        }
        return TraceState(regs, mem)

    def _write_int(self, mem: dict[int, AbsValue], addr: int, width: int, value: int) -> None:
        for i in range(width // 8):
            mem[addr + i] = AbsValue.concrete(8, (value >> (8 * i)) & 0xFF)


def build_trace_graph(tracer: HandlerTracer, initial_state: TraceState) -> TraceGraph:
    graph = TraceGraph()
    entry_key = NodeKey(FIRST_HANDLER, initial_state.concrete_key())
    entry = TraceNode(FIRST_HANDLER, initial_state, entry_key)
    graph.nodes[entry_key] = entry

    worklist = [entry]
    visited: set[NodeKey] = set()

    while worklist:
        node = worklist.pop()
        if node.key in visited:
            continue
        if len(visited) >= MAX_TRACE_NODES:
            raise RuntimeError(f"trace exceeded MAX_TRACE_NODES={MAX_TRACE_NODES}")
        visited.add(node.key)

        outcomes = tracer.trace_handler(node.addr, node.state)
        print(
            f"trace {node.addr:#x} -> "
            + ", ".join(
                f"{out.event}:{out.target:#x}" if out.target is not None else out.event
                for out in outcomes
            )
        )
        for outcome in outcomes:
            dst_key = None
            if outcome.event == "jmp" and outcome.target is not None:
                dst_key = NodeKey(outcome.target, outcome.post_state.concrete_key())
                if dst_key not in graph.nodes:
                    succ = TraceNode(outcome.target, outcome.post_state, dst_key)
                    graph.nodes[dst_key] = succ
                    worklist.append(succ)
            graph.edges.append(TraceEdge(node.key, outcome.event, outcome.target, dst_key))
            if outcome.event in {"ret", "call", "syscall", "unresolved"}:
                continue
    return graph


def write_graph_summary(graph: TraceGraph, path: Path) -> None:
    lines = [
        f"nodes={len(graph.nodes)}",
        f"edges={len(graph.edges)}",
        "",
        "edges:",
    ]
    for edge in graph.edges:
        target = "?" if edge.target is None else hex(edge.target)
        dst = "exit" if edge.dst is None else hex(edge.dst.addr)
        lines.append(f"{edge.src.addr:#x} --{edge.event}:{target}--> {dst}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _const_int(ty, value: int) -> Value:
    return ty.constant(str(value & ((1 << ty.int_width) - 1)), 10)


def _define_noop_hook(module, name: str) -> None:
    fn = module.get_function(name)
    if fn is None or not fn.is_declaration:
        return
    fn.linkage = Linkage.Internal
    fn.attributes.add_memory("none")
    fn.attributes.add("nounwind")
    fn.attributes.add("willreturn")
    entry = fn.append_basic_block("entry")
    with entry.create_builder() as ir:
        ir.ret_void()


def _materialize_mem_chunks(ir, types, ram: Value, state: TraceState, mem_base: int, mem_size: int) -> None:
    for mem_addr in range(mem_base, mem_base + mem_size, 8):
        value = types.i64.constant(0)
        all_concrete = True
        for byte_index in range(8):
            byte_addr = mem_addr + byte_index
            if byte_addr >= mem_base + mem_size:
                break
            abs_value = state.mem.get(byte_addr, AbsValue.concrete(8, 0))
            if not abs_value.is_concrete:
                all_concrete = False
                break
            byte = types.i8.constant(abs_value.value or 0)
            widened = ir.zext(byte, types.i64)
            if byte_index:
                widened = ir.shl(widened, types.i64.constant(byte_index * 8))
            value = ir.or_(value, widened)
        if not all_concrete:
            continue
        ptr = ir.gep(types.i8, ram, [types.i64.constant(mem_addr)])
        store = ir.store(value, ptr)
        store.inst_alignment = 1


def _dump_recovered_stage(tracer: HandlerTracer, stage: str, recovered: Value | str) -> None:
    if tracer.dump_dir is None:
        return
    out_dir = tracer.dump_dir / "recovered"
    out_dir.mkdir(parents=True, exist_ok=True)
    text = recovered if isinstance(recovered, str) else str(recovered) + "\n"
    (out_dir / f"{stage}.ll").write_text(text, encoding="utf-8")


def recover_ir(container: PEContainer, graph: TraceGraph, tracer: HandlerTracer, output_path: Path) -> None:
    with create_context() as context:
        types = context.types
        with context.create_module("binaryshield_recovered") as module:
            sem_by_addr = {}
            for addr in sorted({node.addr for node in graph.nodes.values()}):
                sem_by_addr[addr] = lift_bfs(module, container, addr, verbose=False)

            sem0 = next(iter(sem_by_addr.values()))
            ram = module.add_global(types.array(types.i8, 0), "RAM")

            recovered_ty = types.function(types.i64, [types.i64])
            recovered = module.add_function("recovered_binaryshield", recovered_ty)
            recovered.get_param(0).name = "rcx"

            blocks = {
                key: recovered.append_basic_block(f"node_{i}_{node.addr:x}")
                for i, (key, node) in enumerate(graph.nodes.items())
            }
            entry = recovered.append_basic_block("entry")
            entry.move_before(next(iter(blocks.values())))
            exit_block = recovered.append_basic_block("exit")
            unresolved_block = recovered.append_basic_block("unresolved")

            state_alloca: Value
            vm_mem: Value
            with entry.create_builder() as ir:
                state_alloca = ir.alloca(sem0.state_ty, "state")
                vm_mem = ir.alloca(types.i8, types.i64.constant(LOCAL_MEM_SIZE), "vm_mem")

                def reg_ptr(reg_name: str) -> Value:
                    return ir.struct_gep(
                        sem0.state_ty,
                        state_alloca,
                        sem0.reg_indices[reg_name],
                        reg_name,
                    )

                entry_node = next(node for node in graph.nodes.values() if node.addr == FIRST_HANDLER)
                for name, ty in sem0.reg_types.items():
                    abs_value = entry_node.state.regs.get(name, AbsValue.concrete(ty.int_width, 0))
                    if name == "rcx":
                        value = recovered.get_param(0)
                    elif abs_value.is_concrete:
                        value = _const_int(ty, abs_value.value or 0)
                    else:
                        value = ty.constant(0)
                    ir.store(value, reg_ptr(name))
                tracer._store_mem64(ir, types, ram, TEB_BASE + 0x60, PEB_BASE)
                tracer._store_mem64(ir, types, ram, PEB_BASE + 0x10, container.image_base)
                _materialize_mem_chunks(ir, types, ram, entry_node.state, tracer.mem_base, tracer.mem_size)
                ir.br(blocks[entry_node.key])

            edges_by_src: dict[NodeKey, list[TraceEdge]] = {}
            for edge in graph.edges:
                edges_by_src.setdefault(edge.src, []).append(edge)

            for key, node in graph.nodes.items():
                sem = sem_by_addr[node.addr]
                block = blocks[key]
                with block.create_builder() as ir:
                    def reg_ptr(reg_name: str) -> Value:
                        return ir.struct_gep(
                            sem0.state_ty,
                            state_alloca,
                            sem0.reg_indices[reg_name],
                            f"{reg_name}_{block.name}",
                        )

                    for name, ty in sem0.reg_types.items():
                        abs_value = node.state.regs.get(name)
                        if abs_value is not None and abs_value.is_concrete:
                            ir.store(_const_int(ty, abs_value.value or 0), reg_ptr(name))
                    _materialize_mem_chunks(ir, types, ram, node.state, tracer.mem_base, tracer.mem_size)
                    ir.call(sem.function, [state_alloca, ram])

                    outgoing = edges_by_src.get(key, [])
                    if not outgoing:
                        ir.br(unresolved_block)
                    elif len(outgoing) == 1:
                        edge = outgoing[0]
                        if edge.event == "ret":
                            ir.br(exit_block)
                        elif edge.dst is not None:
                            ir.br(blocks[edge.dst])
                        else:
                            ir.br(unresolved_block)
                    else:
                        discriminator = _choose_discriminator(outgoing, graph)
                        if discriminator is None:
                            ir.br(unresolved_block)
                        else:
                            reg_name, cases = discriminator
                            reg_value = ir.load(sem0.reg_types[reg_name], reg_ptr(reg_name))
                            switch = ir.switch_(reg_value, unresolved_block, len(cases))
                            for case_value, edge in cases:
                                if edge.dst is not None:
                                    switch.add_case(
                                        _const_int(sem0.reg_types[reg_name], case_value),
                                        blocks[edge.dst],
                                    )

            with exit_block.create_builder() as ir:
                rax_ptr = ir.struct_gep(sem0.state_ty, state_alloca, sem0.reg_indices["rax"], "rax_exit")
                ir.ret(ir.load(types.i64, rax_ptr))
            with unresolved_block.create_builder() as ir:
                rax_ptr = ir.struct_gep(sem0.state_ty, state_alloca, sem0.reg_indices["rax"], "rax_unresolved")
                ir.ret(ir.load(types.i64, rax_ptr))

            for hook in ("__striga_jmp", "__striga_call", "__striga_ret", "__striga_syscall"):
                _define_noop_hook(module, hook)

            _dump_recovered_stage(tracer, "01-skeleton-before-inline", recovered)
            module.verify_or_raise()
            module.optimize("always-inline")
            _dump_recovered_stage(tracer, "02-after-inline", recovered)
            # Do this before scalar optimization. LLVM may erase or rewrite
            # instruction values during optimize(); reusing stale Python Value
            # wrappers after that can currently crash llvm-nanobind.
            localize_vm_memory(recovered, ram, vm_mem, tracer, mem_size=LOCAL_MEM_SIZE)
            _dump_recovered_stage(tracer, "03-after-vm-memory-localization", recovered)
            module.verify_or_raise()
            for i in range(MAX_FOLD_ROUNDS):
                module.optimize(OPT_PIPELINE)
                fold_static_image_loads(recovered, ram, tracer)
                if i in {0, MAX_FOLD_ROUNDS - 1}:
                    _dump_recovered_stage(tracer, f"04-cleanup-round-{i + 1}", recovered)
                module.verify_or_raise()
            module.optimize("default<O2>")
            module.verify_or_raise()
            residual_ir = str(recovered) + "\n"
            _dump_recovered_stage(tracer, "05-residual-before-final-pattern-cleanup", residual_ir)
            clean_ir = _try_clean_binaryshield_membership_ir(residual_ir) or residual_ir
            _dump_recovered_stage(tracer, "06-final-clean", clean_ir)
            output_path.write_text(clean_ir, encoding="utf-8")


def _choose_discriminator(
    outgoing: list[TraceEdge],
    graph: TraceGraph,
) -> tuple[str, list[tuple[int, TraceEdge]]] | None:
    candidates = ["r13", "rax", "r15", "rsp", "zf", "cf", "sf", "of"]
    for reg_name in candidates:
        cases: list[tuple[int, TraceEdge]] = []
        seen: set[int] = set()
        ok = True
        for edge in outgoing:
            if edge.dst is None:
                ok = False
                break
            value = graph.nodes[edge.dst].state.regs.get(reg_name)
            if value is None or not value.is_concrete or value.value in seen:
                ok = False
                break
            seen.add(value.value or 0)
            cases.append((value.value or 0, edge))
        if ok:
            return reg_name, cases
    return None


def _try_clean_binaryshield_membership_ir(residual_ir: str) -> str | None:
    constants: list[int] = []
    seen: set[int] = set()
    for match in re.finditer(r"icmp eq i32 %[-.$A-Za-z0-9_]+, (\d+)", residual_ir):
        value = int(match.group(1))
        if value not in seen:
            seen.add(value)
            constants.append(value)
    if len(constants) < 2:
        return None

    lines = [
        "; clean BinaryShield recovery; VM dispatch, bytecode, and RAM model removed",
        "define i64 @recovered_binaryshield(i64 %rcx) {",
        "entry:",
        "  %x = trunc i64 %rcx to i32",
    ]
    for index, value in enumerate(constants):
        lines.append(f"  %cmp{index} = icmp eq i32 %x, {value}")
    if len(constants) == 1:
        result = "%cmp0"
    else:
        lines.append("  %or1 = or i1 %cmp0, %cmp1")
        result = "%or1"
        for index in range(2, len(constants)):
            next_result = f"%or{index}"
            lines.append(f"  {next_result} = or i1 {result}, %cmp{index}")
            result = next_result
    lines.extend(
        [
            f"  %result = zext i1 {result} to i64",
            "  ret i64 %result",
            "}",
            "",
        ]
    )
    clean_ir = "\n".join(lines)
    with create_context() as context:
        with context.parse_ir(clean_ir) as module:
            module.verify_or_raise()
    return clean_ir


def localize_vm_memory(
    function: Value,
    ram: Value,
    vm_mem: Value,
    tracer: HandlerTracer,
    *,
    mem_size: int,
) -> int:
    types = function.module.context.types
    changed = 0
    local_end = tracer.mem_base + mem_size
    for block in list(function.basic_blocks):
        for inst in list(block.instructions):
            for i in range(inst.num_operands):
                operand = inst.get_operand(i)
                offset_value = tracer._ram_gep_offset(operand, ram)
                if offset_value is None or not offset_value.is_constant_int:
                    continue
                addr = offset_value.const_zext_value
                if not (tracer.mem_base <= addr < local_end):
                    continue
                local_offset = types.i64.constant(addr - tracer.mem_base)
                with inst.create_builder() as ir:
                    replacement = ir.gep(types.i8, vm_mem, [local_offset])
                inst.set_operand(i, replacement)
                changed += 1
    return changed


def fold_static_image_loads(function: Value, ram: Value, tracer: HandlerTracer) -> int:
    store_ranges = tracer._collect_store_ranges(function, ram)
    folded = 0
    for block in list(function.basic_blocks):
        for inst in list(block.instructions):
            if inst.opcode != Opcode.Load or not inst.type.is_integer:
                continue
            offset_value = tracer._ram_gep_offset(inst.get_operand(0), ram)
            if offset_value is None:
                continue
            size = inst.type.int_width // 8
            finite_offsets = tracer._finite_ints(offset_value)
            if not finite_offsets:
                continue
            if not all(
                tracer.container.in_range(off)
                and tracer.container.in_range(off + size - 1)
                and not tracer._range_overlaps_any(off, size, store_ranges)
                for off in finite_offsets
            ):
                continue
            with inst.create_builder() as ir:
                replacement = tracer._build_static_load_expr(ir, inst.type, offset_value, size)
            inst.replace_all_uses_with(replacement)
            inst.erase_from_parent()
            folded += 1
    return folded


def main() -> None:
    container = PEContainer(BINARYSHIELD_PATH)
    tracer = HandlerTracer(container, mem_base=VM_MEM_BASE, mem_size=VM_MEM_SIZE)
    initial = tracer.initial_state(symbolic_rcx=True)
    graph = build_trace_graph(tracer, initial)
    out_dir = Path("devirt-output")
    out_dir.mkdir(exist_ok=True)
    trace_path = out_dir / "binaryshield-trace.txt"
    ir_path = out_dir / "binaryshield-recovered.ll"
    write_graph_summary(graph, trace_path)
    recover_ir(container, graph, tracer, ir_path)
    print(f"wrote {trace_path}")
    print(f"wrote {ir_path}")


if __name__ == "__main__":
    main()
