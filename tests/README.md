# Samples

- minivm-switch: classic loop with switch (jmp r8), pc in rcx and VMContext [rsp+0x10]
- minivm-threaded: threaded dispatch, pc in VMContext [rsp+0x30]
- stackvm-switch: classic loop with switch (if/else cascade), pc in rdx
- stackvm-threaded: threaded dispatch, pc in rdx (arg2)
- riscvm.exe: https://github.com/thesecretclub/riscy-business, if/else single function (no vmenter)
- binaryshield.exe: https://connorjaydunn.github.io/blog/posts/binaryshield-a-bin2bin-x86-64-code-virtualizer/
- example2-virt.bin: https://back.engineering/blog/09/05/2026/
- cfg.exe: simple test executable for BFS
- basic_vm_targets.309.dll: vmprotect 3.0.9 test file
