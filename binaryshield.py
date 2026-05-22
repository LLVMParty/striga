from llvm import Module, create_context
from lift import lift_pe


def lift_crackme(module: Module, filename: str):
    vm_handlers = [
        0x140016000,
        0x14001604E,
        0x14001606B,
        0x140016091,
        0x1400160B6,
        0x1400160DD,
        0x140016101,
        0x140016126,
        0x14001614A,
        0x140016170,
        0x140016195,
        0x1400161B2,
        0x1400161CF,
        0x1400161EE,
        0x14001620B,
        0x140016223,
        0x14001623B,
        0x140016255,
        0x14001626C,
        0x14001627D,
        0x14001628E,
        0x1400162A0,
        0x1400162B1,
        0x1400162C9,
        0x1400162E5,
        0x140016303,
        0x14001631F,
        0x140016337,
        0x140016353,
        0x140016371,
        0x14001638D,
        0x1400163A5,
        0x1400163C1,
        0x1400163DF,
        0x1400163FB,
        0x140016413,
        0x14001642F,
        0x14001644D,
        0x140016469,
        0x140016481,
        0x14001649D,
        0x1400164BB,
        0x1400164D7,
        0x1400164F9,
        0x14001651D,
        0x140016546,
        0x14001656A,
        0x14001658C,
        0x1400165B0,
        0x1400165D9,
        0x1400165FD,
        0x140016620,
        0x140016642,
        0x140016667,
        0x140016689,
        0x14001669F,
        0x1400166B8,
        0x1400166D3,
        0x1400166EC,
        0x140016707,
        0x140016721,
        0x14001673D,
        0x140016757,
        0x14001676B,
    ]
    for handler in vm_handlers:
        sem = lift_pe(module, filename, handler, verbose=False)
        lifted = sem.function
        print(lifted.name)

    with open("tests/binaryshield.ll", "w") as f:
        f.write(str(module))


if __name__ == "__main__":
    with create_context() as context:
        with context.create_module("binaryshield") as module:
            lift_crackme(module, "tests/binaryshield.exe")
