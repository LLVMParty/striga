from llvm import create_context, Module
from container import PEContainer
from bfs import lift_bfs


def lift_pe(module: Module, filename: str, start: int, *, verbose=False):
    return lift_bfs(module, PEContainer(filename), start, verbose=verbose)


if __name__ == "__main__":
    with create_context() as context:
        with context.create_module("lifted") as module:
            vm_entry = lift_pe(module, "tests/binaryshield.exe", 0x140017A41)
            print(vm_entry)
            cfg = lift_pe(module, "tests/cfg.exe", 0x140001000)
            print(cfg)
            riscvm_run = lift_pe(module, "tests/riscvm.exe", 0x140001104)
            print(riscvm_run)
            themida = lift_pe(module, "tests/example2-virt.bin", 0x140001000)
            print(themida)
