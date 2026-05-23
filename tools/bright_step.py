from __future__ import annotations

# ruff: noqa: E402

import argparse
import sys
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from capstone import CS_GRP_CALL, CS_GRP_JUMP, CS_GRP_RET
from llvm import Function, Opcode, Value, create_context

from container import PEContainer
from devirt import HandlerTracer, fold_static_image_loads
from striga import Semantics, Successor

OPT_PIPELINE = (
    "sroa,instcombine<no-verify-fixpoint>,early-cse<memssa>,gvn,simplifycfg,dse,adce"
)


@dataclass
class LiftBoundary:
    start: int
    stop: int
    mnemonic: str
    op_str: str
    successors: list[Successor]


@dataclass
class BrightConfig:
    binary: Path
    rip: int
    out_dir: Path
    concrete_regs: dict[str, int] = field(default_factory=dict)
    mem64: dict[int, int] = field(default_factory=dict)
    stack_size: int = 0x8000
    stop_at_call: bool = True
    rounds: int = 6


@dataclass(frozen=True, order=True)
class StackSlot:
    offset: int
    width: int


@dataclass(frozen=True)
class RewriteResult:
    changed: int
    stack_stores: frozenset[StackSlot]


@dataclass(frozen=True)
class EnvModel:
    stack_alloca_name: str
    stack_anchor: int


class LinearLifter:
    def __init__(self, container: PEContainer):
        self.container = container

    def lift_until_branch(
        self, module, start: int, *, stop_at_call: bool
    ) -> tuple[Semantics, LiftBoundary]:
        sem = Semantics(module, verbose=False)
        sem.begin(start)

        rip = start
        seen: set[int] = set()
        while True:
            if rip in seen:
                raise RuntimeError(f"linear lift loop reached {rip:#x}")
            seen.add(rip)

            code = self.container.get_data(rip, 15)
            insn = sem.cs_disasm(rip, code)
            successors = sem.lift_bytes(rip, code)

            fallthrough = rip + insn.size
            is_linear = (
                len(successors) == 1
                and successors[0].dst.is_constant
                and successors[0].dst.const_zext_value == fallthrough
            )
            is_call = insn.group(CS_GRP_CALL)
            is_branch = insn.group(CS_GRP_JUMP) or insn.group(CS_GRP_RET) or is_call

            is_direct_unconditional_jmp = (
                insn.mnemonic == "jmp"
                and len(successors) == 1
                and successors[0].dst.is_constant
            )
            if is_direct_unconditional_jmp:
                rip = successors[0].dst.const_zext_value
                continue

            if is_branch and (stop_at_call or not is_call):
                return sem, LiftBoundary(
                    start, rip, insn.mnemonic, insn.op_str, successors
                )
            if not is_linear:
                return sem, LiftBoundary(
                    start, rip, insn.mnemonic, insn.op_str, successors
                )
            rip = fallthrough


def parse_int(text: str) -> int:
    return int(text, 0)


def parse_assignment(text: str) -> tuple[str, int]:
    name, value = text.split("=", 1)
    return name.strip().lower(), parse_int(value)


def parse_mem64(text: str) -> tuple[int, int]:
    addr, value = text.split("=", 1)
    return parse_int(addr), parse_int(value)


def add_source(module, name: str, ty):
    fn = module.add_function(f"source_{name}", module.context.types.function(ty, []))
    fn.attributes.add_memory("none")
    fn.attributes.add("nounwind")
    fn.attributes.add("willreturn")
    return fn


def add_sink(module, name: str, ty):
    fn = module.add_function(
        f"sink_{name}", module.context.types.function(module.context.types.void, [ty])
    )
    fn.attributes.add("nounwind")
    return fn


def reg_ptr(ir, sem: Semantics, state: Value, name: str) -> Value:
    return ir.struct_gep(sem.state_ty, state, sem.reg_indices[name], name)


def store_mem64(ir, types, ram: Value, addr: int, value: int) -> None:
    ptr = ir.gep(types.i8, ram, [types.i64.constant(addr)])
    store = ir.store(types.i64.constant(value), ptr)
    store.inst_alignment = 1


def instrument_boundary_exits(module, sem: Semantics, boundary: LiftBoundary) -> None:
    """Make direct boundary successors observable before optimization.

    Striga's direct jcc/jmp lowering branches to target basic blocks. If those
    target blocks are still placeholders, LLVM can merge them and delete the
    branch condition. Insert side-effecting calls into the placeholder blocks so
    an optimized wrapper still shows which branch target survived.
    """

    types = module.context.types
    exit_sink = add_sink(module, "exit_rip", types.i64)

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


def build_bright_wrapper(
    module, sem: Semantics, cfg: BrightConfig, boundary: LiftBoundary
) -> tuple[Function, EnvModel]:
    types = module.context.types
    wrapper_ty = types.function(types.void, [types.ptr])
    wrapper = module.add_function(f"bright_step_{cfg.rip:x}", wrapper_ty)
    wrapper.get_param(0).name = "memory"
    wrapper.param_attributes(0).add("noalias")

    sources = {name: add_source(module, name, ty) for name, ty in sem.reg_types.items()}
    sinks = {name: add_sink(module, name, ty) for name, ty in sem.reg_types.items()}
    env_stack_top = add_source(module, "env_stack_top", types.i64)
    env_teb_base = add_source(module, "env_teb_base", types.i64)
    add_source(module, "env_peb_base", types.i64)

    entry = wrapper.append_basic_block("entry")
    with entry.create_builder() as ir:
        state = ir.alloca(sem.state_ty, "state")
        stack_top = ir.call(env_stack_top, [])
        teb_base = ir.call(env_teb_base, [])

        for name, ty in sem.reg_types.items():
            if name in cfg.concrete_regs:
                value = ty.constant(cfg.concrete_regs[name])
            elif name == "rsp":
                value = stack_top
            elif name == "gsbase":
                value = teb_base
            else:
                value = ir.call(sources[name], [])
            ir.store(value, reg_ptr(ir, sem, state, name))

        memory = wrapper.get_param(0)
        for addr, value in cfg.mem64.items():
            store_mem64(ir, types, memory, addr, value)

        ir.call(sem.function, [state, memory])

        for name, ty in sem.reg_types.items():
            value = ir.load(ty, reg_ptr(ir, sem, state, name))
            ir.call(sinks[name], [value])

        ir.ret_void()

    env = EnvModel(
        stack_alloca_name="bright_stack",
        stack_anchor=cfg.stack_size // 2,
    )
    return wrapper, env


def dump(path: Path, value: Value | object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(str(value) + "\n", encoding="utf-8")


def call_name(value: Value) -> str | None:
    if not value.is_instruction or value.opcode != Opcode.Call:
        return None
    called = value.called_value
    return called.name if called is not None else None


def add_const_offset(
    base_offset: tuple[str, int] | None, delta: int
) -> tuple[str, int] | None:
    if base_offset is None:
        return None
    base, offset = base_offset
    return base, offset + delta


def match_env_base_offset(value: Value, env: EnvModel) -> tuple[str, int] | None:
    name = call_name(value)
    if name == "source_env_stack_top":
        return "stack", 0
    if name == "source_env_teb_base":
        return "teb", 0
    if name == "source_env_peb_base":
        return "peb", 0

    if not value.is_instruction:
        return None

    if value.opcode == Opcode.Add:
        lhs = value.get_operand(0)
        rhs = value.get_operand(1)
        if rhs.is_constant_int:
            return add_const_offset(
                match_env_base_offset(lhs, env), rhs.const_sext_value
            )
        if lhs.is_constant_int:
            return add_const_offset(
                match_env_base_offset(rhs, env), lhs.const_sext_value
            )
        return None

    if value.opcode == Opcode.Sub:
        lhs = value.get_operand(0)
        rhs = value.get_operand(1)
        if rhs.is_constant_int:
            return add_const_offset(
                match_env_base_offset(lhs, env), -rhs.const_sext_value
            )
        return None

    return None


def gep_offset(value: Value, memory: Value) -> Value | None:
    if value.is_instruction and value.opcode == Opcode.GetElementPtr:
        if value.num_operands == 2 and value.get_operand(0) == memory:
            return value.get_operand(1)
        if value.num_operands == 3 and value.get_operand(0) == memory:
            zero = value.get_operand(1)
            if zero.is_constant_int and zero.const_zext_value == 0:
                return value.get_operand(2)
    return None


def match_memory_ptr_base_offset(
    ptr: Value, memory: Value, env: EnvModel
) -> tuple[str, int] | None:
    if not ptr.is_instruction or ptr.opcode != Opcode.GetElementPtr:
        return None

    base_ptr = ptr.get_operand(0)
    index = ptr.get_operand(ptr.num_operands - 1)
    if base_ptr == memory:
        return match_env_base_offset(index, env)

    if not index.is_constant_int:
        return None
    return add_const_offset(
        match_memory_ptr_base_offset(base_ptr, memory, env), index.const_sext_value
    )


def find_instruction_by_name(function: Function, name: str) -> Value | None:
    for block in function.basic_blocks:
        for inst in block.instructions:
            if inst.name == name:
                return inst
    return None


def get_or_create_stack_alloca(function: Function, env: EnvModel) -> Value:
    existing = find_instruction_by_name(function, env.stack_alloca_name)
    if existing is not None:
        return existing
    types = function.module.context.types
    first = function.entry_block.first_instruction
    if first is None:
        entry = function.entry_block
        with entry.create_builder() as ir:
            ir.position_at_end(entry)
            return ir.alloca(
                types.i8,
                types.i64.constant(env.stack_anchor * 2),
                env.stack_alloca_name,
            )
    with first.create_builder() as ir:
        return ir.alloca(
            types.i8,
            types.i64.constant(env.stack_anchor * 2),
            env.stack_alloca_name,
        )


def rewrite_env_memory(
    function: Function, memory: Value, env: EnvModel, image_base: int
) -> RewriteResult:
    types = function.module.context.types
    changed = 0
    stack_stores: set[StackSlot] = set()
    stack_alloca: Value | None = None
    peb_base_fn = function.module.get_function("source_env_peb_base")

    for block in list(function.basic_blocks):
        for inst in list(block.instructions):
            if inst.opcode in {Opcode.Load, Opcode.Store}:
                ptr_operand_index = 0 if inst.opcode == Opcode.Load else 1
                ptr = inst.get_operand(ptr_operand_index)
                matched = match_memory_ptr_base_offset(ptr, memory, env)
                if matched is not None:
                    base, offset = matched
                    if base == "stack":
                        stack_index = env.stack_anchor + offset
                        if 0 <= stack_index < env.stack_anchor * 2:
                            if stack_alloca is None:
                                stack_alloca = get_or_create_stack_alloca(function, env)
                            with inst.create_builder() as ir:
                                replacement = ir.gep(
                                    types.i8,
                                    stack_alloca,
                                    [types.i64.constant(stack_index)],
                                )
                            inst.set_operand(ptr_operand_index, replacement)
                            changed += 1
                            if inst.opcode == Opcode.Store:
                                stored = inst.get_operand(0)
                                if stored.type.is_integer:
                                    stack_stores.add(
                                        StackSlot(offset, stored.type.int_width)
                                    )
                            continue
                    if (
                        inst.opcode == Opcode.Load
                        and inst.type == types.i64
                        and base == "teb"
                        and offset == 0x60
                        and peb_base_fn is not None
                    ):
                        with inst.create_builder() as ir:
                            replacement = ir.call(peb_base_fn, [])
                        inst.replace_all_uses_with(replacement)
                        inst.erase_from_parent()
                        changed += 1
                        continue
                    if (
                        inst.opcode == Opcode.Load
                        and inst.type == types.i64
                        and base == "peb"
                        and offset == 0x10
                    ):
                        replacement = types.i64.constant(image_base)
                        inst.replace_all_uses_with(replacement)
                        inst.erase_from_parent()
                        changed += 1
                        continue
    return RewriteResult(changed, frozenset(stack_stores))


def get_or_create_stack_sink(module, width: int) -> Value:
    types = module.context.types
    name = f"sink_stack_i{width}"
    existing = module.get_function(name)
    if existing is not None:
        return existing
    ty = types.int_n(width)
    fn = module.add_function(name, types.function(types.void, [types.i64, ty]))
    fn.attributes.add("nounwind")
    return fn


def insert_stack_snapshots(
    function: Function, env: EnvModel, slots: set[StackSlot]
) -> int:
    if not slots:
        return 0
    types = function.module.context.types
    stack_alloca = get_or_create_stack_alloca(function, env)
    rets = [
        inst
        for block in function.basic_blocks
        for inst in block.instructions
        if inst.opcode == Opcode.Ret
    ]
    inserted = 0
    for ret in rets:
        with ret.create_builder() as ir:
            ir.position_before(ret)
            for slot in sorted(slots):
                ty = types.int_n(slot.width)
                stack_index = env.stack_anchor + slot.offset
                ptr = ir.gep(types.i8, stack_alloca, [types.i64.constant(stack_index)])
                value = ir.load(ty, ptr)
                value.inst_alignment = 1
                sink = get_or_create_stack_sink(function.module, slot.width)
                ir.call(
                    sink, [types.i64.constant(slot.offset, sign_extend=True), value]
                )
                inserted += 1
    return inserted


def source_suffix(value: Value) -> str | None:
    if not value.is_instruction or value.opcode != Opcode.Call:
        return None
    called = value.called_value
    if called is None or not called.name.startswith("source_"):
        return None
    return called.name.removeprefix("source_")


def remove_identity_reg_sinks(function: Function) -> int:
    removed = 0
    for block in list(function.basic_blocks):
        for inst in list(block.instructions):
            if inst.opcode != Opcode.Call:
                continue
            called = inst.called_value
            if (
                called is None
                or not called.name.startswith("sink_")
                or called.name == "sink_exit_rip"
            ):
                continue
            sink_name = called.name.removeprefix("sink_")
            if inst.num_operands < 1:
                continue
            if source_suffix(inst.get_operand(0)) != sink_name:
                continue
            inst.erase_from_parent()
            removed += 1
    return removed


def find_hook_calls(function: Function) -> list[str]:
    rows: list[str] = []
    for block in function.basic_blocks:
        for inst in block.instructions:
            if inst.opcode != Opcode.Call:
                continue
            text = str(inst)
            if "__striga_" in text or "sink_exit_rip" in text:
                rows.append(text.strip())
    return rows


def optimize_step(
    module, wrapper: Function, env: EnvModel, cfg: BrightConfig, container: PEContainer
) -> None:
    cfg.out_dir.mkdir(parents=True, exist_ok=True)
    dump(cfg.out_dir / "01-built.ll", module)

    module.verify_or_raise()
    module.optimize("always-inline")
    dump(cfg.out_dir / "02-inlined.ll", module)

    tracer = HandlerTracer(container, mem_base=0, mem_size=0)
    snapshotted_stack_slots: set[StackSlot] = set()
    stack_snapshot_sinks = 0

    for i in range(cfg.rounds):
        module.optimize(OPT_PIPELINE)
        memory = wrapper.get_param(0)
        rewrite_result = rewrite_env_memory(wrapper, memory, env, container.image_base)
        new_stack_slots = set(rewrite_result.stack_stores) - snapshotted_stack_slots
        stack_snapshot_sinks += insert_stack_snapshots(wrapper, env, new_stack_slots)
        snapshotted_stack_slots |= new_stack_slots
        folded = fold_static_image_loads(wrapper, memory, tracer)
        module.verify_or_raise()
        dump(cfg.out_dir / f"04-opt-round-{i + 1:02d}.ll", module)
        if folded == 0 and rewrite_result.changed == 0 and not new_stack_slots:
            # Still run at least one more simplify round after a no-change round.
            if i > 0:
                break

    removed_identity_sinks = remove_identity_reg_sinks(wrapper)
    module.optimize(OPT_PIPELINE)
    module.verify_or_raise()
    dump(cfg.out_dir / "05-final.ll", module)

    summary = [
        "# bright step summary",
        "",
        f"identity_sinks_removed={removed_identity_sinks}",
        f"stack_snapshot_slots={len(snapshotted_stack_slots)}",
        f"stack_snapshot_sinks={stack_snapshot_sinks}",
        "",
    ]
    calls = find_hook_calls(wrapper)
    summary.append("## Observable boundary calls")
    summary.append("")
    if calls:
        summary.extend(f"- `{call}`" for call in calls)
    else:
        summary.append("- none")
    summary.append("")
    (cfg.out_dir / "summary.md").write_text("\n".join(summary), encoding="utf-8")


def run(cfg: BrightConfig) -> None:
    container = PEContainer(str(cfg.binary))
    with create_context() as context:
        with context.create_module(f"bright_step_{cfg.rip:x}") as module:
            lifter = LinearLifter(container)
            sem, boundary = lifter.lift_until_branch(
                module, cfg.rip, stop_at_call=cfg.stop_at_call
            )
            successor_descriptions = []
            for successor in boundary.successors:
                dst = (
                    hex(successor.dst.const_zext_value)
                    if successor.dst.is_constant
                    else str(successor.dst)
                )
                successor_descriptions.append((successor.src, dst))

            instrument_boundary_exits(module, sem, boundary)
            wrapper, env = build_bright_wrapper(module, sem, cfg, boundary)
            optimize_step(module, wrapper, env, cfg, container)

            print(
                f"lifted {cfg.rip:#x} until {boundary.stop:#x}: {boundary.mnemonic} {boundary.op_str}"
            )
            for src, dst in successor_descriptions:
                print(f"  successor from {src:#x}: {dst}")
            print(f"wrote {cfg.out_dir}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Lift a native prefix, wrap it with source/sink registers, brighten it, and dump each stage."
    )
    parser.add_argument("--binary", default="tests/binaryshield.exe")
    parser.add_argument("--rip", required=True, type=parse_int)
    parser.add_argument(
        "--out-dir", type=Path, default=Path("devirt-output/bright-step")
    )
    parser.add_argument(
        "--reg",
        action="append",
        default=[],
        help="Optional concrete register assignment for experiments, e.g. rcx=0x1234",
    )
    parser.add_argument(
        "--mem64",
        action="append",
        default=[],
        help="Optional concrete memory qword assignment for experiments, e.g. 0x140001000=0x1234",
    )
    parser.add_argument("--stack-size", type=parse_int, default=0x8000)
    parser.add_argument("--rounds", type=int, default=6)
    parser.add_argument("--continue-through-call", action="store_true")
    args = parser.parse_args()

    concrete_regs = dict(parse_assignment(item) for item in args.reg)
    mem64 = dict(parse_mem64(item) for item in args.mem64)
    cfg = BrightConfig(
        binary=Path(args.binary),
        rip=args.rip,
        out_dir=args.out_dir,
        concrete_regs=concrete_regs,
        mem64=mem64,
        stack_size=args.stack_size,
        stop_at_call=not args.continue_through_call,
        rounds=args.rounds,
    )
    run(cfg)


if __name__ == "__main__":
    main()
