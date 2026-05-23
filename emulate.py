from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

import icicle
import pefile
from capstone import (
    CS_ARCH_X86,
    CS_MODE_64,
    CS_MODE_32,
    Cs,
    CsInsn,
)


FUNCTION_ADDRESS = 0x00000001400016D0
RCX_INPUTS = [1859, 2418, 1638, 299902, 29763, 1337]
RETURN_ADDRESS = 0x000000007FFF0000
TRACE_DIR = Path("traces")


@dataclass
class TraceResult:
    rcx: int
    trace_path: Path
    steps: int
    return_value: int
    final_rsp: int
    unique_mnemonics: set[str]


class PEmulator:
    def __init__(self, path: str, *, verbose: bool = False):
        self.path = path
        self.verbose = verbose
        self.pe = pefile.PE(path)

        machine = self.pe.FILE_HEADER.Machine
        arch_name = {
            pefile.MACHINE_TYPE["IMAGE_FILE_MACHINE_AMD64"]: "x86_64",
            pefile.MACHINE_TYPE["IMAGE_FILE_MACHINE_I386"]: "x86",
        }.get(machine)
        assert arch_name is not None, f"Unsupported machine: {machine}"
        self.ic = icicle.Icicle(arch_name, shadow_stack=False)

        self.image_base = self.map_image(self.pe)
        self.entry_point = self.pe.OPTIONAL_HEADER.AddressOfEntryPoint + self.image_base
        self.allocation_base = 0x100000

        self.stack_size = 0x10000
        self.stack_base = self.allocate(self.stack_size)

        self.md = Cs(CS_ARCH_X86, CS_MODE_64 if arch_name == "x86_64" else CS_MODE_32)

    def page_align(self, size: int) -> int:
        return (size + 0xFFF) & ~0xFFF

    def allocate(
        self, size: int, protection=icicle.MemoryProtection.ExecuteReadWrite
    ) -> int:
        assert self.allocation_base & 0xFFF == 0
        addr = self.allocation_base
        size = self.page_align(size)
        self.allocation_base += size
        self.ic.mem_map(addr, size, protection)
        return addr

    def map_image(self, pe: pefile.PE, *, image_base: int = 0) -> int:
        assert pe.FILE_HEADER.Machine == self.pe.FILE_HEADER.Machine, (
            "Architecture mismatch"
        )

        image_size = pe.OPTIONAL_HEADER.SizeOfImage
        section_alignment = pe.OPTIONAL_HEADER.SectionAlignment
        assert section_alignment == 0x1000, (
            f"Unsupported section alignment {hex(section_alignment)}"
        )

        if image_base == 0:
            image_base = cast(int, pe.OPTIONAL_HEADER.ImageBase)

        self.ic.mem_map(image_base, image_size, icicle.MemoryProtection.NoAccess)
        mapped_image = pe.get_memory_mapped_image(ImageBase=image_base)
        self.ic.mem_write(image_base, mapped_image)

        sections = cast(list[Any], pe.sections)
        for section in sections:
            name = section.Name.rstrip(b"\0")
            if section_alignment > 0:
                mask = section_alignment - 1
                rva = (section.VirtualAddress + mask) & ~mask
            else:
                rva = section.VirtualAddress
            va = image_base + rva
            size = self.page_align(section.Misc_VirtualSize)

            assert not section.IMAGE_SCN_MEM_SHARED, "Shared sections are not supported"
            assert section.IMAGE_SCN_MEM_READ, "Non-readable sections are not supported"

            execute = section.IMAGE_SCN_MEM_EXECUTE
            write = section.IMAGE_SCN_MEM_WRITE

            protect = icicle.MemoryProtection.ReadOnly
            if write:
                if execute:
                    protect = icicle.MemoryProtection.ExecuteReadWrite
                else:
                    protect = icicle.MemoryProtection.ReadWrite
            elif execute:
                protect = icicle.MemoryProtection.ExecuteRead
            self.ic.mem_protect(va, size, protect)
            if self.verbose:
                print(
                    f"Mapping section '{name.decode()}' {hex(rva)} -> {hex(va)} as {protect}"
                )

        header_size = cast(int, sections[0].VirtualAddress)
        self.ic.mem_protect(image_base, header_size, icicle.MemoryProtection.ReadOnly)
        return image_base

    def setup_minimal_windows_process(self) -> None:
        """Provide enough TEB/PEB state for gs:[0x60]->ImageBaseAddress."""
        teb = self.allocate(0x1000, icicle.MemoryProtection.ReadWrite)
        peb = self.allocate(0x1000, icicle.MemoryProtection.ReadWrite)
        self.ic.mem_write(teb + 0x60, peb.to_bytes(8, "little"))
        self.ic.mem_write(peb + 0x10, self.image_base.to_bytes(8, "little"))
        self.ic.reg_write("GS_OFFSET", teb)

    def setup_call_frame(
        self, callee: int, rcx: int, return_address: int = RETURN_ADDRESS
    ) -> None:
        """
        Enter `callee` exactly as if a Windows x64 caller had called it:
        - RIP = callee
        - RCX = first integer argument
        - [RSP] = return address
        - RSP % 16 == 8 at callee entry
        - 32 bytes of shadow/home space are available at [RSP+8, RSP+0x27]
        """
        # Start with deterministic GPRs; the callee argument and stack are set below.
        for reg in (
            "RAX",
            "RBX",
            "RCX",
            "RDX",
            "RSI",
            "RDI",
            "RBP",
            "R8",
            "R9",
            "R10",
            "R11",
            "R12",
            "R13",
            "R14",
            "R15",
        ):
            self.ic.reg_write(reg, 0)

        stack_top = self.stack_base + self.stack_size - 0x100
        rsp = (stack_top & ~0xF) - 0x28
        assert rsp % 16 == 8

        self.ic.mem_write(rsp, return_address.to_bytes(8, "little"))
        self.ic.mem_write(rsp + 8, b"\x00" * 0x20)  # Windows x64 shadow space
        self.ic.reg_write("RSP", rsp)
        self.ic.reg_write("RCX", rcx)
        self.ic.reg_write("RIP", callee)

    def cs_disasm(self, address: int, code: bytes) -> CsInsn:
        for insn in self.md.disasm(code, address, count=1):  # ty: ignore[missing-argument, invalid-argument-type]
            return insn
        raise ValueError(f"Failed to disassemble {code.hex()}@{hex(address)}")

    def disassemble_one(self, address: int) -> tuple[str, str, int]:
        # x86-64 instructions are at most 15 bytes. Try shorter reads if close to
        # an unmapped/protected page boundary.
        for size in range(15, 0, -1):
            try:
                code = self.ic.mem_read(address, size)
            except Exception:  # icicle.MemoryException in normal failure cases
                continue
            insn = self.cs_disasm(address, code)
            text = insn.mnemonic
            if insn.op_str:
                text += f" {insn.op_str}"
            return insn.mnemonic, text, insn.size
        raise RuntimeError("disassembly failed")

    def trace_call(
        self,
        *,
        callee: int,
        rcx: int,
        trace_path: Path,
        return_address: int = RETURN_ADDRESS,
        max_steps: int = 1_000_000,
    ) -> TraceResult:
        self.setup_minimal_windows_process()
        self.setup_call_frame(callee, rcx, return_address)

        unique_mnemonics: set[str] = set()
        steps = 0

        with trace_path.open("w", encoding="utf-8", newline="\n") as trace_file:
            while True:
                rip = self.ic.reg_read("RIP")
                if rip == return_address:
                    return TraceResult(
                        rcx=rcx,
                        trace_path=trace_path,
                        steps=steps,
                        return_value=self.ic.reg_read("RAX"),
                        final_rsp=self.ic.reg_read("RSP"),
                        unique_mnemonics=unique_mnemonics,
                    )
                if steps >= max_steps:
                    raise RuntimeError(
                        f"Hit max_steps={max_steps} before returning; RIP={rip:#x}"
                    )

                mnemonic, text, _ = self.disassemble_one(rip)
                unique_mnemonics.add(mnemonic)
                trace_file.write(f"{rip:016x}|{text}\n")

                status = self.ic.step(1)
                steps += 1

                # step(1) normally reports InstructionLimit after successfully executing
                # exactly one instruction. Anything else before our return sentinel is an error.
                if status != icicle.RunStatus.InstructionLimit:
                    raise RuntimeError(
                        f"Emulation stopped before return: status={status}, "
                        f"exception={self.ic.exception_code}, value={self.ic.exception_value:#x}, "
                        f"RIP={self.ic.reg_read('RIP'):#x}"
                    )


def main() -> None:
    TRACE_DIR.mkdir(exist_ok=True)

    all_mnemonics: set[str] = set()
    results: list[TraceResult] = []

    for rcx in RCX_INPUTS:
        emu = PEmulator("crackme.exe")
        trace_path = TRACE_DIR / f"trace_rcx_{rcx}.txt"
        result = emu.trace_call(callee=FUNCTION_ADDRESS, rcx=rcx, trace_path=trace_path)
        results.append(result)
        all_mnemonics.update(result.unique_mnemonics)
        print(
            f"rcx={rcx}: {result.steps} instructions, "
            f"rax={result.return_value:#x}, trace={result.trace_path}"
        )

    unique_path = TRACE_DIR / "unique_mnemonics.txt"
    unique_path.write_text("\n".join(sorted(all_mnemonics)) + "\n", encoding="utf-8")

    summary_path = TRACE_DIR / "summary.txt"
    summary_lines = [
        f"function={FUNCTION_ADDRESS:#018x}",
        f"return_sentinel={RETURN_ADDRESS:#018x}",
        "",
    ]
    for result in results:
        summary_lines.append(
            f"rcx={result.rcx} steps={result.steps} rax={result.return_value:#x} "
            f"final_rsp={result.final_rsp:#x} trace={result.trace_path} "
            f"unique_mnemonics={len(result.unique_mnemonics)}"
        )
    summary_lines.extend(["", "unique_mnemonics:", *sorted(all_mnemonics)])
    summary_path.write_text("\n".join(summary_lines) + "\n", encoding="utf-8")

    print(f"unique mnemonics ({len(all_mnemonics)}): {unique_path}")
    print(f"summary: {summary_path}")


if __name__ == "__main__":
    main()
