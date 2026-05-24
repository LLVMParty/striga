from __future__ import annotations

from typing import cast

import smt_wire as smt
from llvm import IntPredicate, Opcode

from striga.interpreter import MemoryState, RegisterState, ValueDomain

from ._utils import MemoryBacking, bytes_for_width, mask_value

SmtTerm = smt.BVTerm | smt.BoolTerm


class SmtDomain(ValueDomain[SmtTerm]):
    """SMT expression domain backed by smt-wire terms."""

    def __init__(self, ctx: smt.Context, client: smt.Client | None = None):
        self.ctx = ctx
        self.client = client

    def constant(self, value: int, width: int | None) -> smt.BVTerm:
        concrete_width = width or 64
        return self.ctx.bv_const(mask_value(value, concrete_width), concrete_width)

    def unknown(self, text: str, width: int | None) -> smt.BVTerm:
        return self.ctx.bv_var(_symbol_name(text), width or 64)

    def binary(self, op: Opcode, lhs: SmtTerm, rhs: SmtTerm, width: int | None) -> smt.BVTerm:
        lhs_bv = self._as_bv(lhs, width)
        rhs_bv = self._as_bv(rhs, width or lhs_bv.width)
        ops = {
            Opcode.Add: self.ctx.bv_add,
            Opcode.Sub: self.ctx.bv_sub,
            Opcode.Mul: self.ctx.bv_mul,
            Opcode.UDiv: self.ctx.bv_udiv,
            Opcode.SDiv: self.ctx.bv_sdiv,
            Opcode.URem: self.ctx.bv_urem,
            Opcode.SRem: self.ctx.bv_srem,
            Opcode.And: self.ctx.bv_and,
            Opcode.Or: self.ctx.bv_or,
            Opcode.Xor: self.ctx.bv_xor,
            Opcode.Shl: self.ctx.bv_shl,
            Opcode.LShr: self.ctx.bv_lshr,
            Opcode.AShr: self.ctx.bv_ashr,
        }
        return ops[op](lhs_bv, rhs_bv)

    def icmp(self, predicate: IntPredicate, lhs: SmtTerm, rhs: SmtTerm, width: int | None) -> smt.BoolTerm:
        lhs_bv = self._as_bv(lhs, width)
        rhs_bv = self._as_bv(rhs, lhs_bv.width)
        preds = {
            "EQ": self.ctx.bv_eq,
            "NE": self.ctx.bv_ne,
            "ULT": self.ctx.bv_ult,
            "ULE": self.ctx.bv_ule,
            "UGT": self.ctx.bv_ugt,
            "UGE": self.ctx.bv_uge,
            "SLT": self.ctx.bv_slt,
            "SLE": self.ctx.bv_sle,
            "SGT": self.ctx.bv_sgt,
            "SGE": self.ctx.bv_sge,
        }
        return preds[predicate.name](lhs_bv, rhs_bv)

    def select(self, cond: SmtTerm, true_val: SmtTerm, false_val: SmtTerm, width: int | None) -> SmtTerm:
        true_term = self.with_width(true_val, width)
        false_term = self.with_width(false_val, width or self._term_width(true_term))
        return cast("SmtTerm", self.ctx.ite(self._as_bool(cond), true_term, false_term))

    def cast(self, op: Opcode, val: SmtTerm, from_width: int | None, to_width: int | None) -> SmtTerm:
        del from_width
        if to_width is None:
            return val
        if op == Opcode.SExt:
            return self.with_width(val, to_width, signed=True)
        return self.with_width(val, to_width)

    def funnel_shift(
        self,
        high: SmtTerm,
        low: SmtTerm,
        amount: SmtTerm,
        width: int | None,
        *,
        left: bool,
    ) -> smt.BVTerm:
        if width is None:
            return self._as_bv(high, None)
        high_bv = self._as_bv(high, width)
        low_bv = self._as_bv(low, width)
        amount_bv = self._as_bv(amount, width)
        width_const = self.ctx.bv_const(width, width)
        amount_mod = self.ctx.bv_urem(amount_bv, width_const)
        inverse = self.ctx.bv_sub(width_const, amount_mod)
        if left:
            return self.ctx.bv_or(
                self.ctx.bv_shl(high_bv, amount_mod),
                self.ctx.bv_lshr(low_bv, inverse),
            )
        return self.ctx.bv_or(
            self.ctx.bv_lshr(high_bv, amount_mod),
            self.ctx.bv_shl(low_bv, inverse),
        )

    def concrete_bool(self, val: SmtTerm) -> bool | None:
        if isinstance(val, smt.BoolTerm):
            if val.op is smt.Op.BOOL_TRUE:
                return True
            if val.op is smt.Op.BOOL_FALSE:
                return False
            if self.client is None:
                return None
            self.ctx.push()
            self.ctx.assert_(val)
            sat_true = self.client.solve(self.ctx).status is smt.Status.SAT
            self.ctx.pop()
            self.ctx.push()
            self.ctx.assert_(self.ctx.bool_not(val))
            sat_false = self.client.solve(self.ctx).status is smt.Status.SAT
            self.ctx.pop()
            if sat_true and not sat_false:
                return True
            if sat_false and not sat_true:
                return False
            return None
        if val.op is smt.Op.BV_CONST:
            return bool(val.value)
        return None

    def with_width(self, val: SmtTerm, width: int | None, *, signed: bool = False) -> SmtTerm:
        if isinstance(val, smt.BoolTerm):
            target_width = width or 1
            return cast(
                "SmtTerm",
                self.ctx.ite(
                    val,
                    self.ctx.bv_const(1, target_width),
                    self.ctx.bv_const(0, target_width),
                ),
            )
        if width is None or val.width == width:
            return val
        if width <= 0:
            return self.ctx.bv_const(0, 1)
        if val.width > width:
            return self.ctx.bv_extract(val, width - 1, 0)
        extension = width - val.width
        if signed:
            return self.ctx.bv_sext(val, extension)
        return self.ctx.bv_zext(val, extension)

    def _as_bv(self, val: SmtTerm, width: int | None) -> smt.BVTerm:
        resized = self.with_width(val, width)
        if isinstance(resized, smt.BoolTerm):
            return cast("smt.BVTerm", self.with_width(resized, width or 1))
        return resized

    def _as_bool(self, val: SmtTerm) -> smt.BoolTerm:
        if isinstance(val, smt.BoolTerm):
            return val
        return self.ctx.bv_ne(val, self.ctx.bv_const(0, val.width))

    @staticmethod
    def _term_width(val: SmtTerm) -> int:
        return 1 if isinstance(val, smt.BoolTerm) else val.width


class SmtMemory(MemoryState[SmtTerm]):
    """Concrete-address memory with symbolic byte values."""

    def __init__(self, ctx: smt.Context, backing: MemoryBacking | None = None):
        self.ctx = ctx
        self.backing = backing
        self.store: dict[int, smt.BVTerm] = {}

    def read(self, offset: SmtTerm, width: int, *, insn_addr: int = 0) -> smt.BVTerm:
        byte_width = bytes_for_width(width)
        address = self._concrete_offset(offset)
        if address is None:
            return self.ctx.bv_var(f"mem_{insn_addr:x}_{width}", width)
        bytes_le = [self._read_byte(address + i, insn_addr) for i in range(byte_width)]
        return _concat_le(self.ctx, bytes_le)

    def write(self, offset: SmtTerm, value: SmtTerm, width: int, *, insn_addr: int = 0) -> None:
        del insn_addr
        byte_width = bytes_for_width(width)
        address = self._concrete_offset(offset)
        if address is None:
            return
        value_bv = SmtDomain(self.ctx).with_width(value, width)
        assert isinstance(value_bv, smt.BVTerm)
        for i in range(byte_width):
            self.store[address + i] = self.ctx.bv_extract(value_bv, i * 8 + 7, i * 8)

    def _read_byte(self, address: int, insn_addr: int) -> smt.BVTerm:
        stored = self.store.get(address)
        if stored is not None:
            return stored
        if self.backing is not None and self.backing.in_range(address):
            return self.ctx.bv_const(self.backing.get_data(address, 1)[0], 8)
        return self.ctx.bv_var(f"mem_{address:x}_{insn_addr:x}", 8)

    @staticmethod
    def _concrete_offset(offset: SmtTerm) -> int | None:
        if isinstance(offset, smt.BVTerm) and offset.op is smt.Op.BV_CONST:
            return offset.value
        return None


class SmtRegisters(RegisterState[SmtTerm]):
    def __init__(
        self,
        ctx: smt.Context,
        reg_sizes: dict[str, int],
        initial: dict[str, int | SmtTerm] | None = None,
        *,
        symbolic_missing: bool = True,
    ):
        self.ctx = ctx
        self._sizes = reg_sizes
        self._domain = SmtDomain(ctx)
        initial = initial or {}
        self._regs: dict[str, SmtTerm] = {}
        for name, size in reg_sizes.items():
            value = initial.get(name)
            if isinstance(value, int):
                self._regs[name] = ctx.bv_const(mask_value(value, size), size)
            elif value is not None:
                self._regs[name] = self._domain.with_width(value, size)
            elif symbolic_missing:
                self._regs[name] = ctx.bv_var(f"source_{name}", size)
            else:
                self._regs[name] = ctx.bv_const(0, size)

    def read(self, name: str) -> SmtTerm:
        return self._regs[name]

    def write(self, name: str, value: SmtTerm) -> None:
        self._regs[name] = self._domain.with_width(value, self._sizes[name])

    def width(self, name: str) -> int:
        return self._sizes[name]


def _symbol_name(text: str) -> str:
    cleaned = "".join(ch if ch.isalnum() or ch == "_" else "_" for ch in text)
    return cleaned or "unknown"


def _concat_le(ctx: smt.Context, bytes_le: list[smt.BVTerm]) -> smt.BVTerm:
    if not bytes_le:
        return ctx.bv_const(0, 8)
    result = bytes_le[-1]
    for byte in reversed(bytes_le[:-1]):
        result = ctx.bv_concat(result, byte)
    return result


__all__ = ["SmtDomain", "SmtMemory", "SmtRegisters", "SmtTerm"]
