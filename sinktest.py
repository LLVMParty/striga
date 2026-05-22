from llvm import create_context, Module
from container import PEContainer
from striga import Semantics
from bfs import lift_bfs


def lift_pe(module: Module, filename: str, start: int, *, verbose=False) -> Semantics:
    return lift_bfs(module, PEContainer(filename), start, verbose=verbose)


if __name__ == "__main__":
    with create_context() as context:
        with context.create_module("lifted") as module:
            sem = lift_pe(module, "tests/binaryshield.exe", 0x140017A41)
            vm_entry = sem.function

            # module.optimize("default<O3>")
            print(module)
            vm_entry.optimize("instcombine,simplifycfg,early-cse<memssa>,dse,adce")
            print(module)

            vm_entry.attributes.add("alwaysinline")

            types = module.types
            bright_ty = types.function(types.void, [types.ptr])
            bright = module.add_function("bright_symbolic", bright_ty)
            source_ty = types.function(types.i64, [])
            sink_ty = types.function(types.void, [types.i64])

            def source_reg(name: str):
                source_fn = module.add_function(f"source_{name}", source_ty)
                source_fn.attributes.add_memory("none")
                source_fn.attributes.add("nounwind")
                source_fn.attributes.add("willreturn")
                return source_fn

            def sink_reg(name: str):
                sink_fn = module.add_function(f"sink_{name}", sink_ty)
                sink_fn.attributes.add("nounwind")
                sink_fn.attributes.add("willreturn")
                return sink_fn

            sources = {}
            sinks = {}

            for name in sem.reg_ptrs.keys():
                sources[name] = source_reg(name)
                sinks[name] = sink_reg(name)

            with bright.create_builder() as ir:
                for name, fn in sources.items():
                    # TODO: implement source/sink wrapper
                    pass
