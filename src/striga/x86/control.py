from ..semantics import FLAGS, semantic, Semantics, Successor
from llvm import Value


def bool_not(sem: Semantics, value: Value) -> Value:
    return sem.ir.xor(value, sem.const_n(1, 1))


def bool_eq(sem: Semantics, lhs: Value, rhs: Value) -> Value:
    return bool_not(sem, sem.ir.xor(lhs, rhs))


def cc_cond(sem: Semantics, cc: str) -> Value:
    def cf():
        return sem.flag_read("cf")

    def zf():
        return sem.flag_read("zf")

    def sf():
        return sem.flag_read("sf")

    def of():
        return sem.flag_read("of")

    def pf():
        return sem.flag_read("pf")

    match cc:
        case "a" | "nbe":
            return sem.ir.and_(bool_not(sem, cf()), bool_not(sem, zf()))
        case "ae" | "nb" | "nc":
            return bool_not(sem, cf())
        case "b" | "nae" | "c":
            return cf()
        case "be" | "na":
            return sem.ir.or_(cf(), zf())
        case "e" | "z":
            return zf()
        case "g" | "nle":
            return sem.ir.and_(bool_not(sem, zf()), bool_eq(sem, sf(), of()))
        case "ge" | "nl":
            return bool_eq(sem, sf(), of())
        case "l" | "nge":
            return sem.ir.xor(sf(), of())
        case "le" | "ng":
            return sem.ir.or_(zf(), sem.ir.xor(sf(), of()))
        case "ne" | "nz":
            return bool_not(sem, zf())
        case "no":
            return bool_not(sem, of())
        case "np" | "po":
            return bool_not(sem, pf())
        case "ns":
            return bool_not(sem, sf())
        case "o":
            return of()
        case "p" | "pe":
            return pf()
        case "s":
            return sf()
    raise NotImplementedError(f"condition code {cc}")


def cmovcc(sem: Semantics, cc: str):
    cond = cc_cond(sem, cc)
    old_value = sem.op_read(0)
    new_value = sem.resize_int(sem.op_read(1), old_value.type)
    sem.op_write(0, sem.ir.select(cond, new_value, old_value))


@semantic
def cmova(sem: Semantics):
    cmovcc(sem, "a")


@semantic
def cmovae(sem: Semantics):
    cmovcc(sem, "ae")


@semantic
def cmovb(sem: Semantics):
    cmovcc(sem, "b")


@semantic
def cmovbe(sem: Semantics):
    cmovcc(sem, "be")


@semantic
def cmove(sem: Semantics):
    cmovcc(sem, "e")


@semantic
def cmovg(sem: Semantics):
    cmovcc(sem, "g")


@semantic
def cmovge(sem: Semantics):
    cmovcc(sem, "ge")


@semantic
def cmovl(sem: Semantics):
    cmovcc(sem, "l")


@semantic
def cmovle(sem: Semantics):
    cmovcc(sem, "le")


@semantic
def cmovne(sem: Semantics):
    cmovcc(sem, "ne")


@semantic
def cmovno(sem: Semantics):
    cmovcc(sem, "no")


@semantic
def cmovnp(sem: Semantics):
    cmovcc(sem, "np")


@semantic
def cmovns(sem: Semantics):
    cmovcc(sem, "ns")


@semantic
def cmovo(sem: Semantics):
    cmovcc(sem, "o")


@semantic
def cmovp(sem: Semantics):
    cmovcc(sem, "p")


@semantic
def cmovs(sem: Semantics):
    cmovcc(sem, "s")


def setcc(sem: Semantics, cc: str):
    sem.op_write(0, sem.ir.zext(cc_cond(sem, cc), sem.i8))


@semantic
def seta(sem: Semantics):
    setcc(sem, "a")


@semantic
def setae(sem: Semantics):
    setcc(sem, "ae")


@semantic
def setb(sem: Semantics):
    setcc(sem, "b")


@semantic
def setbe(sem: Semantics):
    setcc(sem, "be")


@semantic
def sete(sem: Semantics):
    setcc(sem, "e")


@semantic
def setg(sem: Semantics):
    setcc(sem, "g")


@semantic
def setge(sem: Semantics):
    setcc(sem, "ge")


@semantic
def setl(sem: Semantics):
    setcc(sem, "l")


@semantic
def setle(sem: Semantics):
    setcc(sem, "le")


@semantic
def setne(sem: Semantics):
    setcc(sem, "ne")


@semantic
def setno(sem: Semantics):
    setcc(sem, "no")


@semantic
def setnp(sem: Semantics):
    setcc(sem, "np")


@semantic
def setns(sem: Semantics):
    setcc(sem, "ns")


@semantic
def seto(sem: Semantics):
    setcc(sem, "o")


@semantic
def setp(sem: Semantics):
    setcc(sem, "p")


@semantic
def sets(sem: Semantics):
    setcc(sem, "s")


def conditional_jump(sem: Semantics, cond: Value):
    brtrue = sem.insn.operands[0].imm
    brfalse = sem.insn.address + sem.insn.size
    sem.ir.cond_br(
        cond,
        sem.get_or_create_block(brtrue),
        sem.get_or_create_block(brfalse),
    )

    src = sem.insn.address
    return [
        Successor(src, sem.const64(brtrue)),
        Successor(src, sem.const64(brfalse)),
    ]


def jcc(sem: Semantics, cc: str):
    return conditional_jump(sem, cc_cond(sem, cc))


def jcxz(sem: Semantics, reg: str):
    value = sem.reg_read(reg)
    return conditional_jump(sem, sem.result_is_zero(value))


@semantic
def ja(sem: Semantics):
    return jcc(sem, "a")


@semantic
def jae(sem: Semantics):
    return jcc(sem, "ae")


@semantic
def jb(sem: Semantics):
    return jcc(sem, "b")


@semantic
def jbe(sem: Semantics):
    return jcc(sem, "be")


@semantic
def je(sem: Semantics):
    return jcc(sem, "e")


@semantic
def jg(sem: Semantics):
    return jcc(sem, "g")


@semantic
def jge(sem: Semantics):
    return jcc(sem, "ge")


@semantic
def jl(sem: Semantics):
    return jcc(sem, "l")


@semantic
def jle(sem: Semantics):
    return jcc(sem, "le")


@semantic
def jne(sem: Semantics):
    return jcc(sem, "ne")


@semantic
def jno(sem: Semantics):
    return jcc(sem, "no")


@semantic
def jnp(sem: Semantics):
    return jcc(sem, "np")


@semantic
def jns(sem: Semantics):
    return jcc(sem, "ns")


@semantic
def jo(sem: Semantics):
    return jcc(sem, "o")


@semantic
def jp(sem: Semantics):
    return jcc(sem, "p")


@semantic
def js(sem: Semantics):
    return jcc(sem, "s")


@semantic
def jecxz(sem: Semantics):
    return jcxz(sem, "ecx")


@semantic
def jrcxz(sem: Semantics):
    return jcxz(sem, "rcx")


@semantic
def jmp(sem: Semantics):
    dst = sem.op_read(0)
    if dst.is_constant:
        sem.ir.br(sem.get_or_create_block(dst.const_zext_value))
    else:
        sem.ir.call(sem.jmp_handler, [dst])
        sem.ir.ret_void()
    return [Successor(sem.insn.address, dst)]


@semantic
def call(sem: Semantics):
    dst = sem.op_read(0)
    fallthrough = sem.insn.address + sem.insn.size
    sem.push(sem.const64(fallthrough))
    sem.ir.call(sem.call_handler, [dst])
    sem.ir.br(sem.get_or_create_block(fallthrough))
    return [Successor(sem.insn.address, sem.const64(fallthrough))]


@semantic
def ret(sem: Semantics):
    dst = sem.pop(sem.i64)
    if sem.insn.operands:
        rsp = sem.reg_read("rsp")
        sem.reg_write("rsp", sem.ir.add(rsp, sem.const64(sem.insn.operands[0].imm)))
    sem.ir.call(sem.ret_handler, [dst])
    sem.ir.ret_void()
    return [Successor(sem.insn.address, dst)]


@semantic
def syscall(sem: Semantics):
    fallthrough = sem.insn.address + sem.insn.size
    saved_flags = sem.rflags_value()
    sem.reg_write("rcx", sem.const64(fallthrough))
    sem.reg_write("r11", saved_flags)
    for name in FLAGS:
        sem.flag_write_undef(name)
    sem.ir.call(sem.syscall_handler, [sem.const64(sem.insn.address)])
    sem.ir.br(sem.get_or_create_block(fallthrough))
    return [Successor(sem.insn.address, sem.const64(fallthrough))]


@semantic
def stc(sem: Semantics):
    sem.flag_write("cf", sem.i1.constant(1))


@semantic
def clc(sem: Semantics):
    sem.flag_write("cf", sem.i1.constant(0))


@semantic
def std(sem: Semantics):
    sem.flag_write("df", sem.i1.constant(1))


@semantic
def cld(sem: Semantics):
    sem.flag_write("df", sem.i1.constant(0))


@semantic
def int_(sem: Semantics):
    sem.ir.ret_void()
    return []


@semantic
def cmc(sem: Semantics):
    sem.flag_write("cf", bool_not(sem, sem.flag_read("cf")))


@semantic
def int3(sem: Semantics):
    sem.ir.ret_void()
    return []
@semantic
def nop(sem: Semantics):
    pass


@semantic
def pause(sem: Semantics):
    pass
@semantic
def lfence(sem: Semantics):
    pass


@semantic
def mfence(sem: Semantics):
    pass


@semantic
def sfence(sem: Semantics):
    pass
