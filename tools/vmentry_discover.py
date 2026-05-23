from __future__ import annotations

# ruff: noqa: E402

import argparse
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from capstone import CS_GRP_CALL, CS_GRP_JUMP, CS_GRP_RET, CS_OP_IMM, CS_OP_MEM
from capstone.x86_const import X86_REG_RIP
from llvm import Function, Opcode, Value, create_context

from container import PEContainer
from devirt import HandlerTracer
from striga import Semantics, Successor
from tools.bright_step import (
    OPT_PIPELINE,
    BrightConfig,
    EnvModel,
    LiftBoundary,
    RewriteResult,
    StackSlot,
    add_sink,
    build_bright_wrapper,
    call_name,
    dump,
    find_instruction_by_name,
    get_or_create_stack_alloca,
    insert_stack_snapshots,
    match_memory_ptr_base_offset,
    parse_assignment,
    parse_int,
    parse_mem64,
    remove_identity_reg_sinks,
    rewrite_env_memory,
)

SeedKind = Literal[
    "imm",
    "push_imm",
    "mov_imm",
    "lea_addr",
    "call_return",
    "image_load",
]
CONTROL_SEED_KINDS: frozenset[SeedKind] = frozenset(
    {"push_imm", "mov_imm", "lea_addr", "call_return", "image_load"}
)


@dataclass(frozen=True)
class Seed:
    kind: SeedKind
    insn_addr: int
    value: int
    detail: str


@dataclass
class DiscoveryConfig(BrightConfig):
    follow_calls: set[int] = field(default_factory=set)
    cutpoints: set[int] = field(default_factory=set)
    take_branches: dict[int, int] = field(default_factory=dict)
    assumed_loads: dict[int, int] = field(default_factory=dict)
    localize_writable_image: bool = False


@dataclass(frozen=True)
class LoadDependency:
    width: int
    pointer: str
    concrete_address: int | None


@dataclass(frozen=True)
class EvalValue:
    text: str
    concrete: int | None
    width: int | None
    loads: tuple[LoadDependency, ...] = ()
    unknowns: tuple[str, ...] = ()
    env_base: str | None = None
    env_offset: int = 0

    def with_width(self, width: int | None) -> EvalValue:
        if width is None or self.width == width:
            return self
        concrete = None if self.concrete is None else mask_value(self.concrete, width)
        env_base = self.env_base if width == 64 else None
        env_offset = self.env_offset if env_base is not None else 0
        return EvalValue(
            self.text,
            concrete,
            width,
            self.loads,
            self.unknowns,
            env_base,
            env_offset,
        )


@dataclass(frozen=True)
class PointerValue:
    text: str
    base: str | None = None
    offset: EvalValue | None = None

    @property
    def concrete_address(self) -> int | None:
        if self.base not in {"memory", "inttoptr"} or self.offset is None:
            return None
        return self.offset.concrete


@dataclass(frozen=True)
class Observable:
    call: str
    value: EvalValue


@dataclass
class DiscoveryResult:
    module_text: str
    boundary: LiftBoundary
    seeds: list[Seed]
    observables: list[Observable]


def format_int(value: int) -> str:
    return hex(value) if abs(value) >= 10 else str(value)


def parse_int_pair(text: str) -> tuple[int, int]:
    lhs, rhs = text.split("=", 1)
    return parse_int(lhs), parse_int(rhs)


def mask_value(value: int, width: int | None) -> int:
    if width is None:
        return value
    return value & ((1 << width) - 1)


def value_width(value: Value) -> int | None:
    return value.type.int_width if value.type.is_integer else None


def offset_constant(value: int, width: int | None) -> int:
    if width is None:
        return value
    return to_signed(value, width)


def combine_env_offset(
    lhs: EvalValue, rhs: EvalValue, opcode: Opcode, width: int | None
) -> tuple[str | None, int]:
    if width != 64:
        return None, 0
    if opcode == Opcode.Add:
        if lhs.env_base is not None and rhs.concrete is not None:
            return lhs.env_base, lhs.env_offset + offset_constant(rhs.concrete, rhs.width)
        if rhs.env_base is not None and lhs.concrete is not None:
            return rhs.env_base, rhs.env_offset + offset_constant(lhs.concrete, lhs.width)
    if opcode == Opcode.Sub and lhs.env_base is not None and rhs.concrete is not None:
        return lhs.env_base, lhs.env_offset - offset_constant(rhs.concrete, rhs.width)
    return None, 0


class DiscoveryLifter:
    def __init__(self, container: PEContainer, cfg: DiscoveryConfig):
        self.container = container
        self.cfg = cfg
        self.seeds: list[Seed] = []

    def lift_until_yield(self, module, start: int) -> tuple[Semantics, LiftBoundary]:
        sem = Semantics(module, verbose=False)
        sem.begin(start)
        rip = start
        seen: set[int] = set()
        last_src = start

        while True:
            if rip in seen:
                raise RuntimeError(f"linear lift loop reached {rip:#x}")
            seen.add(rip)

            if rip in self.cfg.cutpoints and rip != start:
                return sem, LiftBoundary(
                    start,
                    rip,
                    "cutpoint",
                    hex(rip),
                    [Successor(last_src, sem.const64(rip))],
                )

            code = self.container.get_data(rip, 15)
            insn = sem.cs_disasm(rip, code)
            self._record_seeds(insn)

            is_call = insn.group(CS_GRP_CALL)
            if is_call and rip in self.cfg.follow_calls:
                successors = self._lift_followed_call(sem, insn)
                last_src = rip
                rip = successors[0].dst.const_zext_value
                continue

            successors = sem.lift_bytes(rip, code)
            if rip in self.cfg.take_branches:
                target = self.cfg.take_branches[rip]
                if not any(
                    successor.dst.is_constant
                    and successor.dst.const_zext_value == target
                    for successor in successors
                ):
                    raise RuntimeError(
                        f"configured branch target {target:#x} is not a successor of {rip:#x}"
                    )
                self._force_branch_target(sem, rip, target)
                last_src = rip
                rip = target
                continue

            fallthrough = rip + insn.size
            is_linear = (
                len(successors) == 1
                and successors[0].dst.is_constant
                and successors[0].dst.const_zext_value == fallthrough
            )
            is_branch = insn.group(CS_GRP_JUMP) or insn.group(CS_GRP_RET) or is_call
            is_direct_unconditional_jmp = (
                insn.mnemonic == "jmp"
                and len(successors) == 1
                and successors[0].dst.is_constant
            )
            if is_direct_unconditional_jmp:
                last_src = rip
                rip = successors[0].dst.const_zext_value
                continue

            if is_branch:
                return sem, LiftBoundary(
                    start, rip, insn.mnemonic, insn.op_str, successors
                )
            if not is_linear:
                return sem, LiftBoundary(
                    start, rip, insn.mnemonic, insn.op_str, successors
                )
            last_src = rip
            rip = fallthrough

    def _force_branch_target(self, sem: Semantics, rip: int, target: int) -> None:
        block = sem.insn_blocks.get(rip)
        if block is None or block.terminator is None:
            raise RuntimeError(f"branch block missing terminator at {rip:#x}")
        terminator = block.terminator
        with terminator.create_builder() as ir:
            ir.position_before(terminator)
            ir.br(sem.get_or_create_block(target))
        terminator.erase_from_parent()
        sem.module.verify_or_raise()

    def _lift_followed_call(self, sem: Semantics, insn) -> list[Successor]:
        target = insn.operands[0].imm
        fallthrough = insn.address + insn.size
        block = sem.get_or_create_block(insn.address)
        if block.first_instruction is not None and block.first_instruction.opcode == Opcode.Ret:
            block.first_instruction.erase_from_parent()
        else:
            raise RuntimeError(f"call block already populated at {insn.address:#x}")
        with block.create_builder() as ir:
            sem.ir = ir
            sem.insn = insn
            sem.push(sem.const64(fallthrough))
            ir.br(sem.get_or_create_block(target))
        sem.module.verify_or_raise()
        if not any(
            seed.kind == "call_return"
            and seed.insn_addr == insn.address
            and seed.value == fallthrough
            for seed in self.seeds
        ):
            self.seeds.append(
                Seed(
                    "call_return",
                    insn.address,
                    fallthrough,
                    f"followed call return {fallthrough:#x}",
                )
            )
        return [Successor(insn.address, sem.const64(target))]

    def _record_seeds(self, insn) -> None:
        for op in insn.operands:
            if op.type == CS_OP_IMM:
                if insn.mnemonic == "call":
                    self.seeds.append(
                        Seed(
                            "call_return",
                            insn.address,
                            insn.address + insn.size,
                            f"call return {insn.address + insn.size:#x}",
                        )
                    )
                    continue
                if insn.group(CS_GRP_JUMP):
                    continue
                kind: SeedKind = "imm"
                if insn.mnemonic == "push":
                    kind = "push_imm"
                elif insn.mnemonic == "mov":
                    kind = "mov_imm"
                self.seeds.append(
                    Seed(kind, insn.address, op.imm, f"{insn.mnemonic} {insn.op_str}")
                )
            elif op.type == CS_OP_MEM and insn.mnemonic == "lea" and op.mem.base == X86_REG_RIP:
                addr = insn.address + insn.size + op.mem.disp
                self.seeds.append(Seed("lea_addr", insn.address, addr, f"lea {insn.op_str}"))


def instrument_cutpoint_exits(module, sem: Semantics, boundary: LiftBoundary) -> None:
    types = module.context.types
    exit_sink = module.get_function("sink_exit_rip") or add_sink(module, "exit_rip", types.i64)
    cond_sink = module.get_function("sink_branch_cond") or add_sink(
        module, "branch_cond", types.i1
    )
    source_block = sem.insn_blocks.get(boundary.stop)
    if source_block is not None and source_block.terminator is not None:
        terminator = source_block.terminator
        if terminator.opcode == Opcode.Br and terminator.is_conditional:
            with terminator.create_builder() as ir:
                ir.position_before(terminator)
                ir.call(cond_sink, [terminator.condition])

    for successor in boundary.successors:
        if not successor.dst.is_constant:
            continue
        target = successor.dst.const_zext_value
        block = sem.insn_blocks.get(target)
        if block is None:
            continue
        first = block.first_instruction
        if first is None or first.opcode != Opcode.Ret:
            continue
        with block.create_builder() as ir:
            ir.position_before(first)
            ir.call(exit_sink, [types.i64.constant(target)])


def rewrite_stack_memory_only(function: Function, memory: Value, env: EnvModel) -> RewriteResult:
    types = function.module.context.types
    changed = 0
    stack_stores: set[StackSlot] = set()
    stack_alloca: Value | None = None

    for block in list(function.basic_blocks):
        for inst in list(block.instructions):
            if inst.opcode not in {Opcode.Load, Opcode.Store}:
                continue
            ptr_operand_index = 0 if inst.opcode == Opcode.Load else 1
            ptr = inst.get_operand(ptr_operand_index)
            matched = match_memory_ptr_base_offset(ptr, memory, env)
            if matched is None:
                continue
            base, offset = matched
            if base != "stack":
                continue
            stack_index = env.stack_anchor + offset
            if not 0 <= stack_index < env.stack_anchor * 2:
                continue
            if stack_alloca is None:
                stack_alloca = get_or_create_stack_alloca(function, env)
            with inst.create_builder() as ir:
                replacement = ir.gep(types.i8, stack_alloca, [types.i64.constant(stack_index)])
            inst.set_operand(ptr_operand_index, replacement)
            changed += 1
            if inst.opcode == Opcode.Store:
                stored = inst.get_operand(0)
                if stored.type.is_integer:
                    stack_stores.add(StackSlot(offset, stored.type.int_width))
    return RewriteResult(changed, frozenset(stack_stores))


def seed_marker(seed: Seed) -> str:
    return f"{seed.kind}@{seed.insn_addr:#x}"


def describe_image_address(addr: int, image_base: int, seeds: list[Seed]) -> str | None:
    image_base_marker = "image_base"
    for seed in seeds:
        if seed.kind == "image_load":
            continue
        value = seed.value & ((1 << 64) - 1)
        if seed.kind == "lea_addr" and value == addr:
            return seed_marker(seed)
        if value == addr:
            return seed_marker(seed)
        if image_base + value == addr:
            return f"{image_base_marker} + {seed_marker(seed)}"
    return None


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


def apply_assumed_loads(function: Function, assumptions: dict[int, int]) -> int:
    if not assumptions:
        return 0
    changed = 0
    for block in list(function.basic_blocks):
        for inst in list(block.instructions):
            if inst.opcode != Opcode.Load or not inst.type.is_integer:
                continue
            insn_addr = instruction_address_from_metadata(inst)
            if insn_addr not in assumptions:
                continue
            value = mask_value(assumptions[insn_addr], inst.type.int_width)
            inst.replace_all_uses_with(inst.type.constant(value))
            inst.erase_from_parent()
            changed += 1
    return changed


@dataclass(frozen=True)
class WritableImageSection:
    name: str
    start: int
    size: int

    @property
    def end(self) -> int:
        return self.start + self.size


@dataclass
class WritableImageOverlay:
    initialized_slots: set[tuple[str, int, int]] = field(default_factory=set)


def writable_image_sections(container: PEContainer) -> list[WritableImageSection]:
    sections: list[WritableImageSection] = []
    for section in container.pe.sections:
        characteristics = int(getattr(section, "Characteristics", 0) or 0)
        if characteristics & 0x80000000 == 0:
            continue
        raw_name = getattr(section, "Name", b"") or b""
        name = raw_name.rstrip(b"\0").decode(errors="ignore") or "section"
        name = "".join(ch if ch.isalnum() else "_" for ch in name).strip("_")
        virtual_size = int(getattr(section, "Misc_VirtualSize", 0) or 0)
        raw_size = int(getattr(section, "SizeOfRawData", 0) or 0)
        virtual_address = int(getattr(section, "VirtualAddress", 0) or 0)
        size = max(virtual_size, raw_size)
        sections.append(
            WritableImageSection(name, container.image_base + virtual_address, size)
        )
    return sections


def find_writable_section(
    sections: list[WritableImageSection], addr: int, size: int
) -> WritableImageSection | None:
    for section in sections:
        if section.start <= addr and addr + size <= section.end:
            return section
    return None


def get_or_create_overlay_alloca(function: Function, section: WritableImageSection) -> Value:
    name = f"image_overlay_{section.name}_{section.start:x}"
    existing = find_instruction_by_name(function, name)
    if existing is not None:
        return existing
    types = function.module.context.types
    entry = function.entry_block
    first = entry.first_instruction
    if first is None:
        with entry.create_builder() as ir:
            ir.position_at_end(entry)
            return ir.alloca(types.i8, types.i64.constant(section.size), name)
    with first.create_builder() as ir:
        ir.position_before(first)
        return ir.alloca(types.i8, types.i64.constant(section.size), name)


def entry_after_allocas(function: Function) -> Value | None:
    for inst in function.entry_block.instructions:
        if inst.opcode != Opcode.Alloca:
            return inst
    return None


def insert_overlay_initializer(
    function: Function,
    overlay: Value,
    section: WritableImageSection,
    addr: int,
    size: int,
    value: int,
) -> None:
    types = function.module.context.types
    insert_before = entry_after_allocas(function)
    if insert_before is None:
        with function.entry_block.create_builder() as ir:
            ir.position_at_end(function.entry_block)
            ptr = ir.gep(types.i8, overlay, [types.i64.constant(addr - section.start)])
            store = ir.store(types.int_n(size * 8).constant(value), ptr)
            store.inst_alignment = 1
        return
    with insert_before.create_builder() as ir:
        ir.position_before(insert_before)
        ptr = ir.gep(types.i8, overlay, [types.i64.constant(addr - section.start)])
        store = ir.store(types.int_n(size * 8).constant(value), ptr)
        store.inst_alignment = 1


def rewrite_writable_image_memory(
    function: Function,
    ram: Value,
    tracer: HandlerTracer,
    seeds: list[Seed],
    overlay: WritableImageOverlay,
    initial_values: dict[int, int],
) -> int:
    sections = writable_image_sections(tracer.container)
    if not sections:
        return 0
    changed = 0
    evaluator = SinkEvaluator(function, seeds)
    for block in list(function.basic_blocks):
        for inst in list(block.instructions):
            if inst.opcode not in {Opcode.Load, Opcode.Store}:
                continue
            ptr_operand_index = 0 if inst.opcode == Opcode.Load else 1
            ptr = inst.get_operand(ptr_operand_index)
            offset_value = tracer._ram_gep_offset(ptr, ram)
            if offset_value is None:
                continue
            width = inst.type.int_width if inst.opcode == Opcode.Load else inst.get_operand(0).type.int_width
            if width % 8 != 0:
                continue
            size = width // 8
            offsets = tracer._finite_ints(offset_value)
            if offsets is None or len(offsets) != 1:
                continue
            addr = next(iter(offsets))
            section = find_writable_section(sections, addr, size)
            if section is None:
                continue
            overlay_alloca = get_or_create_overlay_alloca(function, section)
            slot = (section.name, addr, size)
            if inst.opcode == Opcode.Load and slot not in overlay.initialized_slots:
                if size == 8 and addr in initial_values:
                    value = initial_values[addr]
                    detail_prefix = "initial override writable image"
                else:
                    data = tracer.container.get_data(addr, size)
                    value = int.from_bytes(data, "little")
                    detail_prefix = "initial writable image"
                insert_overlay_initializer(function, overlay_alloca, section, addr, size, value)
                load_insn = instruction_address_from_metadata(inst) or 0
                addr_expr = evaluator.eval_value(offset_value).with_width(64).text
                seeds.append(
                    Seed(
                        "image_load",
                        load_insn,
                        value,
                        f"{detail_prefix} i{width} at {addr:#x}; addr_expr={addr_expr}",
                    )
                )
                overlay.initialized_slots.add(slot)
            with inst.create_builder() as ir:
                replacement = ir.gep(
                    function.module.context.types.i8,
                    overlay_alloca,
                    [function.module.context.types.i64.constant(addr - section.start)],
                )
            inst.set_operand(ptr_operand_index, replacement)
            changed += 1
    return changed


ImageAddressProvenance = dict[tuple[int, int, int], str]


def capture_static_image_load_address_provenance(
    function: Function, ram: Value, tracer: HandlerTracer, seeds: list[Seed]
) -> ImageAddressProvenance:
    evaluator = SinkEvaluator(function, seeds)
    provenance: ImageAddressProvenance = {}
    for block in function.basic_blocks:
        for inst in block.instructions:
            if inst.opcode != Opcode.Load or not inst.type.is_integer:
                continue
            offset_value = tracer._ram_gep_offset(inst.get_operand(0), ram)
            if offset_value is None:
                continue
            size = inst.type.int_width // 8
            evaluated = evaluator.eval_value(offset_value).with_width(64)
            if evaluated.concrete is None:
                continue
            addr = evaluated.concrete
            if not (
                tracer.container.in_range(addr)
                and tracer.container.in_range(addr + size - 1)
            ):
                continue
            load_insn = instruction_address_from_metadata(inst) or 0
            provenance[(load_insn, addr, size)] = evaluated.text
    return provenance


def fold_static_image_loads_with_provenance(
    function: Function,
    ram: Value,
    tracer: HandlerTracer,
    seeds: list[Seed],
    address_provenance: ImageAddressProvenance,
) -> int:
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
            load_insn = instruction_address_from_metadata(inst)
            addr_expr = SinkEvaluator(function, seeds).eval_value(offset_value).text
            for off in sorted(finite_offsets):
                data = tracer.container.get_data(off, size)
                value = int.from_bytes(data, "little")
                addr_prov = address_provenance.get((load_insn or 0, off, size))
                if addr_prov is None:
                    addr_prov = describe_image_address(off, tracer.container.image_base, seeds)
                if addr_prov is None:
                    addr_prov = addr_expr
                seeds.append(
                    Seed(
                        "image_load",
                        load_insn or 0,
                        value,
                        f"load i{inst.type.int_width} from image {off:#x}; addr_expr={addr_prov}",
                    )
                )
            with inst.create_builder() as ir:
                replacement = tracer._build_static_load_expr(
                    ir, inst.type, offset_value, size
                )
            inst.replace_all_uses_with(replacement)
            inst.erase_from_parent()
            folded += 1
    return folded


def optimize_for_discovery(
    module,
    wrapper: Function,
    env: EnvModel,
    cfg: DiscoveryConfig,
    container: PEContainer,
    seeds: list[Seed],
) -> list[Observable]:
    cfg.out_dir.mkdir(parents=True, exist_ok=True)
    dump(cfg.out_dir / "01-built.ll", module)
    module.verify_or_raise()
    module.optimize("always-inline")
    dump(cfg.out_dir / "02-inlined.ll", module)

    tracer = HandlerTracer(container, mem_base=0, mem_size=0)
    memory = wrapper.get_param(0)
    address_provenance = capture_static_image_load_address_provenance(
        wrapper, memory, tracer, seeds
    )
    writable_overlay = WritableImageOverlay()
    snapshotted_stack_slots: set[StackSlot] = set()
    stack_snapshot_sinks = 0
    boundary_observables: list[Observable] = []
    for i in range(cfg.rounds):
        module.optimize(OPT_PIPELINE)
        memory = wrapper.get_param(0)
        rewrite_result = rewrite_env_memory(wrapper, memory, env, container.image_base)
        assumed = apply_assumed_loads(wrapper, cfg.assumed_loads)
        localized_writable = 0
        if cfg.localize_writable_image:
            localized_writable = rewrite_writable_image_memory(
                wrapper, memory, tracer, seeds, writable_overlay, cfg.mem64
            )
        new_stack_slots = set(rewrite_result.stack_stores) - snapshotted_stack_slots
        stack_snapshot_sinks += insert_stack_snapshots(wrapper, env, new_stack_slots)
        snapshotted_stack_slots |= new_stack_slots
        folded = fold_static_image_loads_with_provenance(
            wrapper, memory, tracer, seeds, address_provenance
        )
        module.verify_or_raise()
        dump(cfg.out_dir / f"03-discovery-round-{i + 1:02d}.ll", module)
        if rewrite_result.changed or assumed or localized_writable or folded or new_stack_slots:
            boundary_observables = SinkEvaluator(wrapper, seeds).observables()
        if (
            rewrite_result.changed == 0
            and assumed == 0
            and localized_writable == 0
            and folded == 0
            and not new_stack_slots
            and i > 0
        ):
            break

    if not boundary_observables:
        boundary_observables = SinkEvaluator(wrapper, seeds).observables()

    removed_identity_sinks = remove_identity_reg_sinks(wrapper)
    module.optimize(OPT_PIPELINE)
    module.verify_or_raise()
    dump(cfg.out_dir / "04-final.ll", module)
    (cfg.out_dir / "optimizer-summary.txt").write_text(
        f"identity_sinks_removed={removed_identity_sinks}\n"
        f"stack_snapshot_slots={len(snapshotted_stack_slots)}\n"
        f"stack_snapshot_sinks={stack_snapshot_sinks}\n"
        f"writable_image_slots={len(writable_overlay.initialized_slots)}\n",
        encoding="utf-8",
    )
    return boundary_observables


StoreKey = tuple[str, str, int | str]


class SinkEvaluator:
    def __init__(self, function: Function, seeds: list[Seed]):
        self.function = function
        self.seeds = seeds
        self.memo: dict[int, EvalValue] = {}
        self.ptr_memo: dict[int, PointerValue] = {}
        self.stack_store_values: dict[StoreKey, EvalValue] = {}
        self._collect_stack_stores()

    def observables(self) -> list[Observable]:
        rows: list[Observable] = []
        for block in self.function.basic_blocks:
            for inst in block.instructions:
                if inst.opcode != Opcode.Call:
                    continue
                called = inst.called_value
                if called is None:
                    continue
                name = called.name
                if not self._is_observable_call(name):
                    continue
                if inst.num_operands < 1:
                    continue
                if name.startswith("sink_stack") and inst.num_operands >= 2:
                    offset = self.eval_value(inst.get_operand(0))
                    rows.append(Observable(f"{name}(offset={offset.text})", self.eval_value(inst.get_operand(1))))
                    continue
                rows.append(Observable(name, self.eval_value(inst.get_operand(0))))
        return rows

    def eval_value(self, value: Value) -> EvalValue:
        key = hash(value)
        cached = self.memo.get(key)
        if cached is not None:
            return cached
        result = self._eval_value_uncached(value)
        self.memo[key] = result
        return result

    def eval_pointer(self, value: Value) -> PointerValue:
        key = hash(value)
        cached = self.ptr_memo.get(key)
        if cached is not None:
            return cached
        result = self._eval_pointer_uncached(value)
        self.ptr_memo[key] = result
        return result

    def _eval_value_uncached(self, value: Value) -> EvalValue:
        width = value_width(value)
        if value.is_constant_int:
            concrete = mask_value(value.const_zext_value, width)
            return EvalValue(self._const_text(concrete), concrete, width)
        if value.is_argument:
            return EvalValue(f"%{value.name}", None, width, unknowns=(f"argument %{value.name}",))
        if not value.is_instruction:
            return EvalValue(str(value).strip(), None, width, unknowns=("unsupported value",))

        op = value.opcode
        if op == Opcode.Call:
            name = call_name(value)
            if name is not None and name.startswith("llvm.fshl."):
                return self._eval_funnel_shift(value, left=True)
            if name is not None and name.startswith("llvm.fshr."):
                return self._eval_funnel_shift(value, left=False)
            if name is not None and name.startswith("llvm.bswap."):
                return self._eval_bswap(value)
            if name == "source_env_stack_top":
                return EvalValue(f"{name}()", None, width, env_base="stack")
            if name == "source_env_teb_base":
                return EvalValue(f"{name}()", None, width, env_base="teb")
            if name == "source_env_peb_base":
                return EvalValue(f"{name}()", None, width, env_base="peb")
            if name is not None:
                return EvalValue(f"{name}()", None, width)
            return EvalValue(str(value).strip(), None, width, unknowns=("unknown call",))
        if op in {Opcode.Add, Opcode.Sub, Opcode.Xor, Opcode.And, Opcode.Or, Opcode.Shl, Opcode.LShr, Opcode.AShr, Opcode.Mul}:
            return self._eval_binary(value)
        if op in {Opcode.Trunc, Opcode.ZExt, Opcode.SExt}:
            inner = self.eval_value(value.get_operand(0))
            concrete = None if inner.concrete is None else mask_value(inner.concrete, width)
            text = f"{cast_name(op)}({inner.text} -> i{width})"
            env_base = inner.env_base if width == 64 and inner.width == 64 else None
            env_offset = inner.env_offset if env_base is not None else 0
            return EvalValue(
                text,
                concrete,
                width,
                inner.loads,
                inner.unknowns,
                env_base,
                env_offset,
            )
        if op == Opcode.PtrToInt:
            ptr = self.eval_pointer(value.get_operand(0))
            concrete = ptr.concrete_address
            return EvalValue(f"ptrtoint({ptr.text})", concrete, width)
        if op == Opcode.IntToPtr:
            inner = self.eval_value(value.get_operand(0))
            return EvalValue(f"inttoptr({inner.text})", inner.concrete, width, inner.loads, inner.unknowns)
        if op == Opcode.Load:
            return self._eval_load(value)
        if op == Opcode.ICmp:
            return self._eval_icmp(value)
        if op == Opcode.Select:
            cond = self.eval_value(value.get_operand(0))
            true_value = self.eval_value(value.get_operand(1))
            false_value = self.eval_value(value.get_operand(2))
            if cond.concrete is not None:
                chosen = true_value if cond.concrete != 0 else false_value
                return chosen.with_width(width)
            concrete = true_value.concrete if true_value.concrete == false_value.concrete else None
            loads = (*cond.loads, *true_value.loads, *false_value.loads)
            unknowns = (*cond.unknowns, *true_value.unknowns, *false_value.unknowns)
            return EvalValue(
                f"select({cond.text}, {true_value.text}, {false_value.text})",
                concrete,
                width,
                loads,
                unknowns,
            )
        if op == Opcode.GetElementPtr:
            ptr = self.eval_pointer(value)
            return EvalValue(ptr.text, ptr.concrete_address, width)
        if op == Opcode.PHI:
            incoming = [self.eval_value(value.get_incoming_value(i)) for i in range(value.num_incoming)]
            concrete_values = {item.concrete for item in incoming}
            concrete = concrete_values.pop() if len(concrete_values) == 1 else None
            loads = tuple(dep for item in incoming for dep in item.loads)
            unknowns = tuple(dep for item in incoming for dep in item.unknowns)
            return EvalValue(
                "phi(" + ", ".join(item.text for item in incoming) + ")",
                concrete,
                width,
                loads,
                unknowns,
            )
        return EvalValue(str(value).strip(), None, width, unknowns=(f"unsupported opcode {op.value}",))

    def _eval_pointer_uncached(self, value: Value) -> PointerValue:
        if value.is_argument:
            return PointerValue(f"%{value.name}", value.name, EvalValue("0", 0, 64))
        if value.is_instruction and value.opcode == Opcode.Alloca:
            name = value.name or "alloca"
            return PointerValue(f"%{name}", name, EvalValue("0", 0, 64))
        if value.is_instruction and value.opcode == Opcode.GetElementPtr:
            base = self.eval_pointer(value.get_operand(0))
            index = self.eval_value(value.get_operand(value.num_operands - 1)).with_width(64)
            offset = combine_offset(base.offset, index, "+") if base.offset is not None else index
            text = f"{base.text} + {index.text}"
            return PointerValue(text, base.base, offset)
        if value.is_instruction and value.opcode == Opcode.IntToPtr:
            inner = self.eval_value(value.get_operand(0)).with_width(64)
            return PointerValue(f"inttoptr({inner.text})", "inttoptr", inner)
        as_value = self.eval_value(value).with_width(64)
        return PointerValue(as_value.text, "inttoptr", as_value)

    def _eval_bswap(self, value: Value) -> EvalValue:
        width = value_width(value)
        inner = self.eval_value(value.get_arg_operand(0)).with_width(width)
        concrete = None
        if width is not None and width % 8 == 0 and inner.concrete is not None:
            data = inner.concrete.to_bytes(width // 8, "little")
            concrete = int.from_bytes(data, "big")
        return EvalValue(
            f"bswap({inner.text})",
            concrete,
            width,
            inner.loads,
            inner.unknowns,
        )

    def _eval_funnel_shift(self, value: Value, *, left: bool) -> EvalValue:
        width = value_width(value)
        lhs = self.eval_value(value.get_arg_operand(0)).with_width(width)
        rhs = self.eval_value(value.get_arg_operand(1)).with_width(width)
        shift = self.eval_value(value.get_arg_operand(2)).with_width(width)
        concrete = None
        if width is not None and lhs.concrete is not None and rhs.concrete is not None and shift.concrete is not None:
            amount = shift.concrete % width
            mask = (1 << width) - 1
            if amount == 0:
                concrete = lhs.concrete & mask
            elif left:
                concrete = ((lhs.concrete << amount) | (rhs.concrete >> (width - amount))) & mask
            else:
                concrete = ((lhs.concrete >> amount) | (rhs.concrete << (width - amount))) & mask
        name = "fshl" if left else "fshr"
        return EvalValue(
            f"{name}({lhs.text}, {rhs.text}, {shift.text})",
            concrete,
            width,
            (*lhs.loads, *rhs.loads, *shift.loads),
            (*lhs.unknowns, *rhs.unknowns, *shift.unknowns),
        )

    def _eval_binary(self, value: Value) -> EvalValue:
        lhs = self.eval_value(value.get_operand(0)).with_width(value_width(value))
        rhs = self.eval_value(value.get_operand(1)).with_width(value_width(value))
        width = value_width(value)
        concrete = None
        if lhs.concrete is not None and rhs.concrete is not None:
            concrete = eval_binary_concrete(value.opcode, lhs.concrete, rhs.concrete, width)
        op_text = opcode_symbol(value.opcode)
        text = f"({lhs.text} {op_text} {rhs.text})"
        env_base, env_offset = combine_env_offset(lhs, rhs, value.opcode, width)
        return EvalValue(
            text,
            concrete,
            width,
            (*lhs.loads, *rhs.loads),
            (*lhs.unknowns, *rhs.unknowns),
            env_base,
            env_offset,
        )

    def _eval_load(self, value: Value) -> EvalValue:
        ptr = self.eval_pointer(value.get_operand(0))
        width = value_width(value)
        key = self._store_key(ptr)
        if key is not None:
            stored = self.stack_store_values.get(key)
            if stored is not None:
                return stored.with_width(width)
        dep = LoadDependency(width or 0, ptr.text, ptr.concrete_address)
        return EvalValue(f"load_i{width}({ptr.text})", None, width, (dep,))

    def _eval_icmp(self, value: Value) -> EvalValue:
        lhs = self.eval_value(value.get_operand(0))
        rhs = self.eval_value(value.get_operand(1))
        concrete = None
        if lhs.concrete is not None and rhs.concrete is not None:
            concrete = int(eval_icmp_concrete(value.icmp_predicate, lhs.concrete, rhs.concrete, lhs.width))
        pred = value.icmp_predicate.name.lower()
        return EvalValue(
            f"icmp.{pred}({lhs.text}, {rhs.text})",
            concrete,
            1,
            (*lhs.loads, *rhs.loads),
            (*lhs.unknowns, *rhs.unknowns),
        )

    def _collect_stack_stores(self) -> None:
        for block in self.function.basic_blocks:
            for inst in block.instructions:
                if inst.opcode != Opcode.Store:
                    continue
                ptr = self.eval_pointer(inst.get_operand(1))
                key = self._store_key(ptr)
                if key is None:
                    continue
                self.stack_store_values[key] = self.eval_value(inst.get_operand(0))

    @staticmethod
    def _store_key(ptr: PointerValue) -> StoreKey | None:
        if ptr.base is None or ptr.offset is None:
            return None
        if ptr.offset.env_base is not None:
            return (ptr.base, ptr.offset.env_base, ptr.offset.env_offset)
        return (ptr.base, "expr", ptr.offset.text)

    def _const_text(self, value: int) -> str:
        matches = [
            seed
            for seed in self.seeds
            if mask_value(seed.value, 64) == mask_value(value, 64)
            and should_annotate_seed(seed)
        ]
        if not matches:
            return format_int(value)
        first = matches[0]
        return f"{format_int(value)}/*{first.kind}@{first.insn_addr:#x}*/"

    @staticmethod
    def _is_observable_call(name: str) -> bool:
        return (
            name.startswith("__striga_")
            or name.startswith("sink_exit")
            or name.startswith("sink_branch")
            or name.startswith("sink_stack")
        )


def cast_name(opcode: Opcode) -> str:
    return {
        Opcode.Trunc: "trunc",
        Opcode.ZExt: "zext",
        Opcode.SExt: "sext",
    }.get(opcode, str(opcode.value))


def should_annotate_seed(seed: Seed) -> bool:
    value = mask_value(seed.value, 64)
    if seed.kind in {"push_imm", "lea_addr", "call_return", "image_load"}:
        return True
    return 0x100 <= value < (1 << 63)


def opcode_symbol(opcode: Opcode) -> str:
    return {
        Opcode.Add: "+",
        Opcode.Sub: "-",
        Opcode.Xor: "^",
        Opcode.And: "&",
        Opcode.Or: "|",
        Opcode.Shl: "<<",
        Opcode.LShr: ">>>",
        Opcode.AShr: ">>",
        Opcode.Mul: "*",
    }.get(opcode, str(opcode.value))


def eval_binary_concrete(opcode: Opcode, lhs: int, rhs: int, width: int | None) -> int:
    shift = rhs if width is None else rhs % width
    if opcode == Opcode.Add:
        value = lhs + rhs
    elif opcode == Opcode.Sub:
        value = lhs - rhs
    elif opcode == Opcode.Xor:
        value = lhs ^ rhs
    elif opcode == Opcode.And:
        value = lhs & rhs
    elif opcode == Opcode.Or:
        value = lhs | rhs
    elif opcode == Opcode.Shl:
        value = lhs << shift
    elif opcode == Opcode.LShr:
        value = lhs >> shift
    elif opcode == Opcode.AShr:
        value = arithmetic_shift_right(lhs, shift, width)
    elif opcode == Opcode.Mul:
        value = lhs * rhs
    else:
        raise NotImplementedError(opcode)
    return mask_value(value, width)


def arithmetic_shift_right(value: int, shift: int, width: int | None) -> int:
    if width is None or width == 0:
        return value >> shift
    sign_bit = 1 << (width - 1)
    signed = value - (1 << width) if value & sign_bit else value
    return signed >> shift


def eval_icmp_concrete(predicate, lhs: int, rhs: int, width: int | None) -> bool:
    name = predicate.name
    if name == "EQ":
        return lhs == rhs
    if name == "NE":
        return lhs != rhs
    if name in {"ULT", "ULE", "UGT", "UGE"}:
        if name == "ULT":
            return lhs < rhs
        if name == "ULE":
            return lhs <= rhs
        if name == "UGT":
            return lhs > rhs
        return lhs >= rhs
    lhs_s = to_signed(lhs, width)
    rhs_s = to_signed(rhs, width)
    if name == "SLT":
        return lhs_s < rhs_s
    if name == "SLE":
        return lhs_s <= rhs_s
    if name == "SGT":
        return lhs_s > rhs_s
    if name == "SGE":
        return lhs_s >= rhs_s
    return False


def to_signed(value: int, width: int | None) -> int:
    if width is None or width == 0:
        return value
    value = mask_value(value, width)
    sign_bit = 1 << (width - 1)
    return value - (1 << width) if value & sign_bit else value


def combine_offset(lhs: EvalValue, rhs: EvalValue, op: Literal["+", "-"]) -> EvalValue:
    concrete = None
    if lhs.concrete is not None and rhs.concrete is not None:
        concrete = lhs.concrete + rhs.concrete if op == "+" else lhs.concrete - rhs.concrete
        concrete = mask_value(concrete, 64)
    opcode = Opcode.Add if op == "+" else Opcode.Sub
    env_base, env_offset = combine_env_offset(lhs, rhs, opcode, 64)
    return EvalValue(
        f"({lhs.text} {op} {rhs.text})",
        concrete,
        64,
        (*lhs.loads, *rhs.loads),
        (*lhs.unknowns, *rhs.unknowns),
        env_base,
        env_offset,
    )


def render_report(result: DiscoveryResult) -> str:
    lines: list[str] = [
        "# VM entry discovery report",
        "",
        "## Boundary",
        "",
        f"- start: `{result.boundary.start:#x}`",
        f"- stop: `{result.boundary.stop:#x}`",
        f"- instruction: `{result.boundary.mnemonic} {result.boundary.op_str}`",
        "",
        "## Observable boundary values",
        "",
    ]
    if not result.observables:
        lines.append("- none")
    for observable in result.observables:
        value = observable.value
        concrete = "unknown" if value.concrete is None else f"{value.concrete:#x}"
        lines.extend(
            [
                f"### `{observable.call}`",
                "",
                f"- concrete: `{concrete}`",
                f"- expression: `{value.text}`",
            ]
        )
        loads = dedupe_loads(value.loads)
        if loads:
            lines.extend(["- loads:"])
            for dep in loads:
                addr = "unknown" if dep.concrete_address is None else f"{dep.concrete_address:#x}"
                lines.append(f"  - `i{dep.width} {dep.pointer}` concrete_addr=`{addr}`")
        if value.unknowns:
            lines.append("- unknowns:")
            for item in sorted(set(value.unknowns)):
                lines.append(f"  - `{item}`")
        lines.append("")

    control_seeds = involved_control_seeds(result)
    lines.extend(["## Seeds involved in control-boundary expressions", ""])
    if control_seeds:
        for seed in control_seeds:
            lines.append(
                f"- `{seed.kind}` at `{seed.insn_addr:#x}` value `{seed.value & ((1 << 64) - 1):#x}`: {seed.detail}"
            )
    else:
        lines.append("- none")
    lines.append("")

    lines.extend(["## Seed candidates", ""])
    if result.seeds:
        for seed in result.seeds:
            lines.append(f"- `{seed.kind}` at `{seed.insn_addr:#x}` value `{seed.value & ((1 << 64) - 1):#x}`: {seed.detail}")
    else:
        lines.append("- none")
    lines.append("")
    lines.extend(["## Suggested next actions", ""])
    if any(obs.value.loads for obs in result.observables):
        lines.append("- Inspect loads feeding boundary values and choose control-slice loads to fold in a follow-up run.")
    else:
        lines.append("- Boundary values are already concrete or depend only on sources/unsupported expressions.")
    lines.append("- Mark seed candidates as bytecode, handler-table, position-anchor, or VM-constant roles once their flow is clear.")
    lines.append("")
    return "\n".join(lines)


def involved_control_seeds(result: DiscoveryResult) -> list[Seed]:
    texts = [
        observable.value.text
        for observable in result.observables
        if observable.call.startswith("__striga_") or observable.call.startswith("sink_exit")
    ]
    involved: list[Seed] = []
    seen: set[tuple[str, int, int, str]] = set()

    changed = True
    while changed:
        changed = False
        for seed in result.seeds:
            if seed.kind not in CONTROL_SEED_KINDS:
                continue
            marker = seed_marker(seed)
            key = (seed.kind, seed.insn_addr, seed.value, seed.detail)
            if key in seen:
                continue
            if not any(marker in text for text in texts):
                continue
            seen.add(key)
            involved.append(seed)
            texts.append(seed.detail)
            changed = True
    return involved


def dedupe_loads(loads: tuple[LoadDependency, ...]) -> list[LoadDependency]:
    seen: set[tuple[int, str, int | None]] = set()
    result: list[LoadDependency] = []
    for dep in loads:
        key = (dep.width, dep.pointer, dep.concrete_address)
        if key in seen:
            continue
        seen.add(key)
        result.append(dep)
    return result


def run(cfg: DiscoveryConfig) -> DiscoveryResult:
    container = PEContainer(str(cfg.binary))
    with create_context() as context:
        with context.create_module(f"vmentry_discover_{cfg.rip:x}") as module:
            lifter = DiscoveryLifter(container, cfg)
            sem, boundary = lifter.lift_until_yield(module, cfg.rip)
            instrument_cutpoint_exits(module, sem, boundary)
            wrapper, env = build_bright_wrapper(module, sem, cfg, boundary)
            seeds = [*lifter.seeds]
            observables = optimize_for_discovery(
                module, wrapper, env, cfg, container, seeds
            )
            result = DiscoveryResult(str(module), boundary, seeds, observables)
            report = render_report(result)
            (cfg.out_dir / "discovery.md").write_text(report, encoding="utf-8")
            print(report)
            print(f"wrote {cfg.out_dir}")
            return result


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Prototype VM-entry discovery workbench: stack-only brightening plus demand evaluation of boundary sinks."
    )
    parser.add_argument("--binary", default="tests/binaryshield.exe")
    parser.add_argument("--rip", required=True, type=parse_int)
    parser.add_argument("--out-dir", type=Path, default=Path("devirt-output/vmentry-discover"))
    parser.add_argument("--reg", action="append", default=[])
    parser.add_argument("--mem64", action="append", default=[])
    parser.add_argument("--stack-size", type=parse_int, default=0x8000)
    parser.add_argument("--rounds", type=int, default=4)
    parser.add_argument(
        "--follow-call",
        action="append",
        default=[],
        type=parse_int,
        help="Direct call instruction address to inline as push-return + branch-to-target.",
    )
    parser.add_argument(
        "--cutpoint",
        action="append",
        default=[],
        type=parse_int,
        help="Native address where discovery should stop and emit sink_exit_rip.",
    )
    parser.add_argument(
        "--take-branch",
        action="append",
        default=[],
        type=parse_int_pair,
        metavar="RIP=TARGET",
        help="Force a lifted conditional branch to a concrete successor and continue discovery.",
    )
    parser.add_argument(
        "--assume-load",
        action="append",
        default=[],
        type=parse_int_pair,
        metavar="INSN=VALUE",
        help="Replace integer loads emitted for a native instruction with a concrete value.",
    )
    parser.add_argument(
        "--localize-writable-image",
        action="store_true",
        help="Model concrete writable-image loads/stores with local mutable section overlays.",
    )
    args = parser.parse_args()

    cfg = DiscoveryConfig(
        binary=Path(args.binary),
        rip=args.rip,
        out_dir=args.out_dir,
        concrete_regs=dict(parse_assignment(item) for item in args.reg),
        mem64=dict(parse_mem64(item) for item in args.mem64),
        stack_size=args.stack_size,
        rounds=args.rounds,
        stop_at_call=True,
        follow_calls=set(args.follow_call),
        cutpoints=set(args.cutpoint),
        take_branches=dict(args.take_branch),
        assumed_loads=dict(args.assume_load),
        localize_writable_image=args.localize_writable_image,
    )
    run(cfg)


if __name__ == "__main__":
    main()
