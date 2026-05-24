---
title: "Pushan: Trace-Free Deobfuscation of Virtualization-Obfuscated Binaries"
source: "https://arxiv.org/html/2603.18355"
language: "en"
word_count: 11512
---

Ashwin Sudhir, Zion Leonahenahe Basque, Wil Gibbs, Ati Priya Bajaj, Pulkit Singh Singaria,  
Mitchell Zakocs, Jie Hu, Moritz Schloegel, Tiffany Bao, Adam Doupe,  
Yan Shoshitaishvili, Ruoyu Wang  
Arizona State University  
CISPA Helmholtz Center for Information Security  
{asudhir1,zbasque,wfgibbs,atipriya,psingari,mzakocs,jiehu12,tbao,doupe,yans,fishw}@asu.edu  
moritz.schloegel@cispa.de

###### Abstract

In the ever-evolving battle against malware, binary obfuscation techniques are a formidable barrier to the effective analysis of malware by both human security analysts and automated systems. In particular, virtualization or VM-based obfuscation is one of the strongest protection mechanisms that evade automated analysis. Despite widespread use of virtualization in practice, existing automated deobfuscation techniques suffer from three major drawbacks. First, they only work on execution traces, which prevents them from recovering *all* logic in an obfuscated binary. Second, they depend on dynamic symbolic execution, which is expensive and does not scale in practice. Third, they cannot generate “well-formed” code, which prevents existing binary decompilers from generating human-friendly decompilation output.

This paper introduces Pushan, a novel and generic technique for deobfuscating virtualization-obfuscated binaries while overcoming the limitations of existing techniques. Pushan is trace-free and avoids path-constraint accumulation by using VPC-sensitive, constraint-free symbolic emulation to recover a complete CFG of the virtualized function. It is the first approach that also decompiles the protected code into high-quality C pseudocode to enable effective analysis. Crucially, Pushan circumvents the traditional reliance on path satisfiability, which is a known NP-hard problem that hampers the scalability of existing deobfuscation techniques. We evaluate Pushan on a diverse set of more than $1,000$ binaries, including targets protected by academic state of the art, Tigress, and by the commercial-strength obfuscators VMProtect and Themida. Pushan successfully deobfuscates these binaries, retrieves their *complete* CFGs, and decompiles them to C pseudocode. We further demonstrate practical applicability by analyzing a previously unanalyzed VMProtect-obfuscated malware sample from VirusTotal, where our decompiled output enables LLM-assisted code simplification, reuse and program understanding, making our approach the first to enable effective end-to-end analysis of code protected by virtualization.

## 1 Introduction

Over 50 years have passed since the birth of the first computer virus in 1971, and malware is still a critical and widespread threat to Internet users. Security companies report that they detected more than 500,000 unique malware samples per day in 2025, which is a 7% increase over 2024 [^22]. The constant flow of newly discovered malware has driven the recruitment of human security analysts and the development of additional intelligent automated techniques for malware analysis. To thwart such attempts, malware authors turned to protection schemes, with virtualization-based binary obfuscation techniques (also referred to as Virtual Machine (VM)-based obfuscation) being the most notable [^1].

A virtualization-based obfuscator protects a binary program from both manual and automated reverse engineering by translating the original instructions into virtual machine (VM) bytecode that uses a custom, usually randomized instruction set. Then, it injects one or more VM interpreters (also called virtual CPUs) into the protected binary, which interpret the newly generated VM bytecode during run time. Essentially, virtualization-based obfuscation hides the original control flow, which is often critical for reverse engineering [^28], and instead exposes only the control flow of the VM interpreters. To reverse engineer such a binary, security analysts must first reverse engineer the VM interpreters, which is tedious, time-consuming, and error-prone.

While academic efforts to automate the deobfuscation of virtualization-obfuscated binaries are extensive [^48] [^35] [^46] [^4] [^9] [^29], three key limitations hinder their practical adoption: (1) Incomplete Path Coverage: Existing techniques are primarily trace-based, reasoning about one execution path at a time to recover a control flow graph (CFG). Given the complex logic and multitude of paths in real-world malware, achieving complete path coverage is virtually impossible, potentially leaving analysts with an incomplete CFG and missing critical logic. (2) Low Scalability: These techniques rely on dynamic symbolic execution [^2] for path exploration, which is computationally expensive and inherently unscalable due to the path explosion problem and the NP-completeness [^39] of satisfiability checking. Furthermore, dynamic symbolic exploration is notoriously brittle and easily defeated by common obfuscation countermeasures [^37] [^45] [^30] [^36] [^3]. (3) Low Usability: Existing techniques output raw instruction traces that are not conducive to downstream analysis. Security analysts rely on familiar tools like binary decompilers to interpret code [^49] [^10] [^43] [^6], which improve the speed and accuracy of malware analysis [^44]. However, these tools expect structured, “well-formed” assembly code and a complete CFG [^7] for correct performance. As Section 3 shows, even industry-standard tools like the Hex-Rays Decompiler fail to produce clean C pseudocode from deobfuscated traces, forcing analysts back into tedious manual reversing.

In this paper, we present Pushan, a scalable technique that deobfuscates virtualization-obfuscated binaries in a *trace-free* manner, recovers a *complete* CFG of the deobfuscated program, and generates decompiled C pseudocode as the output. Pushan builds on the concept of Virtual Program Counter (VPC) sensitivity [^23], which is drawn from the concept of sensitivities in program analysis: We can recover the *original* CFG of a virtualization-obfuscated binary by making CFG recovery sensitive to both the actual program counter (which always points to instructions in an VM interpreter) and the VPC, which always points to a location in the VM bytecode region. To achieve VPC sensitivity, we design a new CFG recovery algorithm based on *constraint-free symbolic emulation*, which symbolically evaluates instructions without accumulating path constraints or performing path exploration. Pushan recovers a VPC-sensitive, flattened CFG (termed a *flat CFG*) that contains both the (now flattened) interpreter logic and the logic of the original program. It then iteratively performs semantics-preserving simplifications to simplify the flat CFG. The goal of simplification is to remove any logic related to VM interpreters and only retain the logic of the original, unobfuscated code. Lastly, Pushan uses a custom binary decompiler to generate C pseudocode, which makes malware easier to analyze [^44]. This advantage largely stems from the correctness of the generated CFG used during decompilation [^16] [^7].

We evaluate Pushan on several datasets to understand its correctness, capabilities, and impact. First, we used 14 programs, including malware samples, open-source software, and synthetic binaries, obfuscated using the widely adopted, commercial obfuscators VMProtect [^42] and Themida [^31], yielding 28 unique obfuscated binaries. Our evaluation shows that Pushan is not hindered by the path satisfiability problem, can fully recover the CFGs, and achieves 100% similarity to the original CFGs for 17 out of the 28 cases, with high similarity in the remaining samples. Then, we evaluated Pushan on 1,000 binaries generated with Tigress using three different VM configurations, finding that Pushan fully analyzed and successfully deobfuscated and decompiled 988 of them. We compared this against the state of the art [^35], which only recovered 68 complete CFGs. We also evaluated Pushan on five CTF challenges obfuscated with bespoke VM implementations. It succeeds in all five samples and for one even revealed the embedded flag value in the decompiled output, highlighting its ability to recover semantically meaningful logic from custom VM designs.

Finally, we evaluated Pushan on a real-world VMProtect-obfuscated binary sample and recovered the logic of a virtualization-obfuscated function in the binary. This allowed us to determine the true nature of this binary and demonstrates that Pushan produces decompiler-consumable control flow that enables practical decompilation of virtualization-obfuscated binaries. To our best knowledge, while this sample has existed since 2018 (according to VirusTotal), this is the first thorough analysis of it.

Contributions. This paper makes three key contributions:

- We review state-of-the-art devirtualization approaches and identify a fundamental problem that limits their scalability and usability.
- We propose Pushan, a scalable deobfuscation framework based on *VPC-sensitive, constraint-free symbolic emulation* that recovers complete control flow from virtualization-obfuscated binaries.
- We evaluate Pushan on binaries protected by commercial-strength obfuscators and demonstrate its ability to recover complete CFGs and produce decompiled code semantically consistent with original code.

## 2 Virtual Machine Deobfuscation

Table 1: A qualitative comparison of Pushan against existing techniques for virtualization-based deobfuscation.

<table><tr><td></td><td>Key Techniques</td><td>Output</td><td>Complex Programs</td><td>CFG Complete?</td><td>Code Decompilable?</td></tr><tr><td>Kinder <sup><a href="#fn:23">23</a></sup></td><td>abstract interpretation, VPC sensitivity</td><td>calls+arguments</td><td>?<sup>1</sup></td><td>–</td><td>✘</td></tr><tr><td>Coogan <sup><a href="#fn:13">13</a></sup></td><td>tracing, slicing</td><td>subtrace</td><td>✓</td><td>–</td><td>✘</td></tr><tr><td>Yadegari <sup><a href="#fn:48">48</a></sup></td><td>tracing, taint analysis</td><td>CFG</td><td>✓</td><td>✘</td><td>✘</td></tr><tr><td>VMHunt <sup><a href="#fn:46">46</a></sup></td><td>tracing, symbolic execution</td><td>Trace</td><td>✓</td><td>–</td><td>✘</td></tr><tr><td>Salwan <sup><a href="#fn:35">35</a></sup></td><td>tracing, taint, formula slicing</td><td>CFG</td><td>✘ <sup>2</sup></td><td>✘</td><td>✓</td></tr><tr><td>Pushan</td><td>emulation, VPC sensitivity</td><td>CFG</td><td>✓</td><td>✓</td><td>✓</td></tr><tr><td colspan="6"><sup>1</sup>: Only one toy example tested      <sup>2</sup>: Supports obfuscated code that contains not more than one or two branches</td></tr></table>

Many obfuscation techniques exist, including Mixed Boolean-Arithmetic (MBAs) [^51] or Opaque Predicates [^11] [^12]. One of the most powerful techniques is *virtualization-based obfuscation*, also referred to as *VM-based obfuscation*. It runs the to-be-protected code inside a custom interpreter that uses a custom bytecode representation. Figure 1 illustrates a typical interpreter design, featuring a centralized fetch-decode-execute loop that dispatches VM bytecode instructions to corresponding handlers. Different architectures are possible, including threaded code [^15] [^32], where the address of the next bytecode (direct threading) or the fetch and decode step (indirect threading) are inlined into the VM handlers, avoiding the easy to identify VM dispatcher loop. The Virtual Program Counter (VPC), akin to its analogous counterpart on a CPU, tracks the execution through the bytecode.

![Refer to caption](https://arxiv.org/html/2603.18355v1/x1.png)

Figure 1: An illustration of virtualization-based obfuscation, where the to-be-protected code has been translated into bytecode. A fetch-decode-execute loop with a central dispatcher dispatches execution to individual VM handler s. Each bytecode instruction will be handled by a VM handler.

Removing VM-based obfuscation requires (1) identifying the VM, (2) mapping VM handlers, (3) reconstructing handler semantics, and (4) developing a disassembler for the VM. Only after these steps can an analyst begin studying the underlying program logic. To alleviate this burden, various works have proposed automating Steps (2) to (4).

Table 1 lists the state-of-the-art solutions in VM deobfuscation with the goal of recovering the original code. Studying their underlying primitives, we can identify two philosophies: techniques that rely on tracing and mount an analysis on these traces, and Kinder’s VPC-sensitive abstract interpretation.

Tracing-based analysis. Trace-based techniques bypass virtualization by observing VM behavior on concrete executions. They (1) capture an execution trace for a given input, and (2) simplify the trace using techniques such as taint analysis to isolate the underlying logic from input-dependent or obfuscation-related noises. Some techniques use program synthesis to find equivalent but simpler expressions for VM handlers [^9] [^29]. While they differ in implementation details and complexity, this approach is fundamentally limited to one execution path and cannot capture the *complete* program behavior. Optionally, (3) they may derive input cases (e.g., by querying an SMT solver) to generate additional exeuction traces, which is popular among prior work [^13] [^48] [^46] [^35]. However, symbolic execution is particularly brittle in the context of obfuscation, which often employs safeguards [^3] [^30], and it still does not guarantee complete path coverage, as we will show in the following section.

VPC-sensitive abstract interpretation. Kinder [^23] proposes VPC-sensitive abstract interpretation. While traditional static analysis would merely analyze the VM’s interpreter, VPC sensitivity accounts for this layer of indirection. The key insight is that in programs under virtualization-based obfuscation, different abstract states exist for different execution contexts, but are merged under the same program location. For example, the VM’s add handler may be called from different contexts, whenever addition is needed. We can account for this by adding a dimension, bytecode location sensitivity, to our analysis [^23]: By tracking the location of the bytecode (i.e., point in program execution) calling the VM handler, static analysis can now differentiate between calls to the same location. Unfortunately, prior work does not scale; It only showed this technique on a toy program to extract specific system calls and their arguments.

Existing techniques either remain coverage-limited when relying on traces, or provide partial analysis results rather than fully deobfuscated program representations. Scalable recovery of complete CFGs and human-consumable output for binaries protected by commercial-strength virtualizers remains unsolved in practice.

## 3 Challenges

Two challenges limit prior work and motivate our approach. Consider the example program in Figure 2(a), which implements a simple hash-based input checker. While the original CFG (Figure 2(b)) is straightforward, the VMProtect-obfuscated version (Figure 3(a)) is significantly larger and structurally unrecognizable. This highlights the main obstacle: Conventional CFG recovery yields the structure of the VM interpreter rather than the original control flow of the protected program.

![Refer to caption](https://arxiv.org/html/2603.18355v1/x2.png)

(a) Original source code

Challenge 1: Incomplete program behaviors captured. Prior work on VM deobfuscation relies on program *traces* to identify executed code. A single trace, as in VMHunt [^46] and Coogan et al. [^13], is insufficient to retrieve the *complete* behavior. Even the simple hash example requires at least two traces to capture both the “success” and “wrong” paths. A single trace (assuming it triggers the “wrong” path) will lead to an incomplete deobfuscated CFG as shown in Figure 3(b).

Challenge 2: Constraint solving-based input generation does not scale. Two works attempt to address Challenge 1 [^35] [^48]. To observe *all feasible* input paths, they turn to repeated dynamic symbolic execution (DSE). They first symbolically execute a trace and collect path constraints, then negate these constraints at branching points and generate an input to trigger the alternate branch. They repeat the process to discover more traces, hoping to reach full path coverage of the protected code.

Unfortunately, this approach inherits the downsides of symbolic execution: It suffers from *path explosion*, where there are (nearly) an infinite number of paths in complex, real-world programs, and it lacks a model for the *environment*, which complicates its application in general. Most importantly, both obfuscation and the original program logic can field *constraints that are difficult to solve* for theorem provers [^3] [^36]. The sample program hash will only execute puts("Correct!") if the user input hashes to a certain value. Without having the intended user input (in this case, 4294967295), a theorem prover must break the hash algorithm’s preimage resistance and find an input that satisfies hash == 226292709949525. We attempted to solve for the correct input using angr and Z3 on the unobfuscated binary. Z3 was unable to find a valid 64-bit input within three hours, which shows the practical limitations of constraint-solving-based approaches. These weaknesses hamper the scalability of symbolic execution as a means of generating new inputs to discover more program behaviors. Obfuscation has moved to specifically target symbolic execution [^36] [^30] [^45] [^47], rendering it even more ineffective.

![Refer to caption](https://arxiv.org/html/2603.18355v1/x3.png)

(a)

## 4 The Design of Pushan

Pushan aims to recover a *complete control-flow structure* of a virtualization-obfuscated binary in a trace-free manner. Our solution depends on two insights:

Bounding symbolic state growth during CFG construction. Pushan recovers the CFG by *symbolically emulating* the program from the entry point and incrementally constructing the CFG. Each time symbolic emulation encounters a control-flow transfer, a corresponding node and edge are added to the graph. Traditional DSE must preserve a distinct symbolic state for every execution path reaching a program location, since path feasibility depends on how that location was reached. This leads to path explosion due to branches and loops.

In contrast, we observe that CFG recovery is a *structural* problem. Once a basic block, identified by both its block address and VPC, has been discovered and emulated, re-executing that basic block along different paths does not reveal new control-flow structures. Accordingly, Pushan symbolically emulates each block at most once. If additional incoming edges to an already-discovered block are later encountered, these edges are recorded in the CFG, but the block itself is not re-emulated. By collapsing all incoming paths at block boundaries, Pushan bounds the number of symbolic states and avoids the path explosion inherent to traditional symbolic execution.

Eliminating reliance on constraint solving. In non-obfuscated binaries, CFG recovery can often be performed syntactically by inspecting branch instructions and extracting explicit targets. Virtualization-based obfuscation breaks this assumption by replacing direct and conditional jumps with indirect jumps whose targets are computed through complex expressions, often involving MBA transformations and values defined far earlier in the program. Some form of symbolic reasoning is necessary to propagate values to jump sites. However, traditional DSE accumulates path constraints and queries an SMT solver to determine whether a branch is feasible. This reliance on satisfiability checking introduces significant overhead and hinders scalability, especially in obfuscated code.

Pushan eliminates this dependency by observing that CFG recovery does not require path feasibility. Our goal is not to determine whether a jump can occur, but to enumerate the set of control-flow targets it may resolve to. Accordingly, when resolving indirect jumps or opaque predicates, Pushan queries an SMT solver on the recovered symbolic expression *without any accumulated path constraints*. The solver is used purely as an expression simplifier and value enumerator, not as an input feasibility checker. This constraint-free usage avoids solver blowups while still recovering all CFG edges.

![Refer to caption](https://arxiv.org/html/2603.18355v1/x6.png)

Figure 4: Overview of the analysis pipeline of Pushan.

The primary contribution of Pushan lies in decoupling CFG recovery from path feasibility. As Figure 3(c) shows, Pushan recovers both feasible and infeasible paths of the hash example, yielding a complete CFG (and subsequently, decompiled and simplified pseudocode) suitable for downstream analyses.

### 4.1 Overview

Pushan utilizes a three-stage pipeline (Figure 4) to recover the original control flow and produce decompiled code.

Stage 1. VPC-sensitive CFG recovery (Section 5). Pushan reconstructs the CFG by emulating the obfuscated binary using an abstract state over registers and memory. By uniquely identifying blocks by both their native address and virtual program counter (VPC), Pushan achieves context-sensitive reconstruction. It propagates values through VM instructions to simplify jump-target expressions, enabling the resolution of indirect jumps and the pruning of constant opaque-predicate branches. It then uses symbolization to recover edges missed during emulation. The output of this stage is a CFG with both VM interpreter logic and the original, unobfuscated program’s logic. We call this CFG a *flat CFG*.

Stage 2. Semantics-preserving simplifications (Section 6). A flat CFG contains redundant low-level logic inherent to the VM logic. In this stage, Pushan applies a series of semantics-preserving transformations on the flat CFG to remove unnecessary artifacts, simplify control flow, and reveal higher-level operations. Pushan iteratively applies these simplifications until convergence.

Stage 3. Decompilation (Section 7). Finally, the simplified CFG is processed by an enhanced decompiler to generate C-like pseudocode that preserves the recovered logic. Our enhancements include rewriting node identifiers into a decompiler-compatible format, improving function boundary detection despite obfuscated calls, and extending stack pointer tracking to handle non-standard arithmetic.

### 4.2 Threat Model

We assume a strong adversary (the virtualization-based obfuscator) with full knowledge of Pushan’s deobfuscation logic and simplification heuristics. Furthermore, we assume the obfuscator uses a dedicated VPC for each VM instance injected into the binary, as is a standard practice in commercial-grade protectors such as VMProtect and Themida.

Automated binary unpacking is out-of-scope; Pushan assumes that the obfuscated binary is either not packed or already unpacked. While Pushan must resolve certain opaque predicates (e.g., MBA expressions) to reconstruct the control flow, the exhaustive simplification of these underlying obfuscation primitives is orthogonal to our work. We treat such techniques as out-of-scope, because specialized solutions like MBA-Blast [^27] can be used to further simplify Pushan’s output by simplifying or removing MBA expressions.

## 5 VPC-Sensitive CFG Recovery

Given an obfuscated binary, Pushan begins by performing VPC-sensitive CFG recovery. While general-purpose tools for automated VPC identification are generally unavailable, the underlying principles are studied by prior work and not our contribution [^38] [^50]. Pushan implements a set of targeted VPC identification heuristics inspired by existing work. We first describe these VPC identification methods for completeness, then detail our methodology for achieving a complete, VPC-sensitive flat CFG reconstruction.

### 5.1 Heuristic VPC Identification

In virtualization-obfuscated binaries, the VPC typically resides in a register or memory location and serves to index the VM bytecode stream. The VPC’s location varies by obfuscator. It may be volatile, updated via multi-instruction arithmetic, and transferred between registers (as seen in VMProtect), or stay in a stable location throughout execution (Themida and Tigress).

To handle volatile instances, Pushan re-evaluates candidate VPC locations at the start of each basic block during symbolic emulation. Following the methodology in VM-Doctor [^50], we identify the VPC by monitoring registers pointing to memory regions with high entropy (a characteristic of VM bytecode regions) and sequential evolution, where the VPC value increases or decreases within some region. For virtualizers with stable location VPCs, we monitor unique behaviors (e.g., the first memory load from a non-conventional section of a binary, which apply for both Themida and Tigress) and use them to infer VPC locations. By combining these strategies, Pushan could successfully identify the VPCs for all evaluated samples across VMProtect, Themida, and Tigress.

While these heuristics are tailored to commercial-strength virtualization-based obfuscators, they are grounded in fundamental properties of virtualization-based obfuscation: Bytecode indexing and predictable execution flows. We expect the VPCs of other virtualizers to remain similarly identifiable with minimal manual effort.

### 5.2 Constraint-Free Symbolic Emulation

During flat CFG recovery, Pushan emulates each instruction from the beginning of the obfuscated code and updates an abstract state. This abstract state includes storage for registers and memory. Pushan uses a custom value domain that includes concrete values (e.g., bitvectors and floating points), symbolic values, and a special abstract value TOP, which is created as the result of the union of two or more values when paths merge.

At the beginning of the emulation, we treat all uninitialized values, e.g., environment variables or user inputs, as symbolic. When encountering external function calls, including standard C library functions and OS APIs, we avoid emulating them. Instead, we simulate the function’s behavior using a function summary when available or return a symbolic value that adheres to the expected calling convention. We also hook any called unobfuscated functions in the binary to return symbolic values. This prevents unnecessary analysis and ensures symbolic return values flow correctly into the obfuscated logic. Note that existing techniques like VMHunt [^46] can be applied to automatically identify the boundaries of the virtualized region and automate the hooking process if desired.

During emulation, Pushan creates a new node for each newly discovered basic block and adds a new edge between the source node and the new node in the CFG when a control flow transfer happens. To implement VPC sensitivity, we uniquely label each node using a tuple of (block address, VPC). We refer to this tuple as the ID of this node. After the initial VPC-sensitive CFG exploration, our graph looks like Figure 5(c).

During each exploration round, Pushan visits each VPC-sensitive block at most once; exploration terminates when no new (address, VPC) pairs are discovered. After each exploration round, symbolization (Section 5.3) may introduce additional symbolic values, which enables the discovery of previously missed control-flow edges in subsequent rounds. This iterative process gradually expands the recovered CFG.

![Refer to caption](https://arxiv.org/html/2603.18355v1/x7.png)

(a)

Pruning branches for direct conditional jumps. Virtualization-based obfuscators frequently apply opaque predicates to thwart static analysis effort, and a common use case for opaque predicates is to convert an unconditional jump into a conditional jump where one of its branches is always satisfiable [^24]. The end result is an excessive number of redundant control-flow transfers in the obfuscated code. Pushan simplifies the CFG and prunes the always-unsatisfiable branches using the following rules:

1. Pruning branches with always-false conditions (opaque predicates). Pushan evaluates each branch condition in isolation, without any path constraints, using an SMT solver as an expression simplifier. This is because static simplification rules cannot handle complex opaque predicates. We note that existing MBA simplification methods can be applied [^27] [^33] [^34].
2. Keeping all branches with symbolic or user input-dependent conditions.

After pruning, our graph looks like Figure 5(d), where all the flattened handler copies unrelated to the current VPC are eliminated along with fake branches that depend on opaque predicates (not shown in the graph).

Resolving obfuscated indirect jump targets. In traditional binary disassembly, determining the target of a conditional jump is straightforward, as the target address is embedded directly in the instruction itself (e.g., jz $+5). In contrast, obfuscated binaries often replace direct jumps with indirect jumps, where the target address is computed. We use symbolic emulation to recover the intended jump targets by executing the relevant instructions and tracking how the jump target is calculated. Obfuscators often apply MBA transformations to make these expressions harder to interpret. Listing 5 shows an example. To resolve such indirect jumps, Pushan applies the same strategy used for pruning opaque branches: It evaluates the recovered expression in isolation, without applying any path constraints. We stress that the goal is not to determine which input would trigger the jump, but to enumerate all possible outputs of the expression—that is, the set of target addresses it may evaluate to. This mirrors traditional disassembling techniques, which recovers jump destinations rather than reasons about the conditions under which they are taken.

\[b\] [⬇](data:text/plain;base64,fih+KDB4ZmZmZmZmZmZmICsgKDB4MCAuLiB+KGlmIH4oMHg1ICsgfmlucHV0KSA9PSAweDAgdGhlbiAxIGVsc2UgMCkpKSB8IC01MzY5MzY0NDgxKQorIH4oKDB4ZmZmZmZmZmZmICsgKDB4MCAuLiAoaWYgfigweDUgKyB+aW5wdXQpID09IDB4MCB0aGVuIDEgZWxzZSAwKSkpIHwgLTUzNjkzNjcyMTYp) ~(~(0xfffffffff + (0x0.. ~(if ~(0x5 + ~input) == 0x0 then 1 else 0))) | -5369364481) + ~((0xfffffffff + (0x0.. (if ~(0x5 + ~input) == 0x0 then 1 else 0))) | -5369367216)

### 5.3 Symbolization

Pruning may lead to missing branches during the first analysis pass of a basic block. Consider the exit branch of a loop that iterates for a constant number of iterations. The obfuscated guard condition of the exit branch will only evaluate to one value (going to the beginning of the loop) unless the execution reaches the last iteration. Pushan would incorrectly prune the exit branch, leading to an incomplete flat CFG. To address this problem, Pushan introduces *symbolization* to discover and symbolize non-constant variables.

1. When emulating each instruction, Pushan keeps the values in registers and memory in an abstract state. Pushan also resolves the addresses of load and store instructions.
2. When two paths merge during emulation (e.g., a back edge reaching the loop header), Pushan merges the abstract states for the two paths, where constant but distinct values at the same location are merged into TOP (an unconstrained symbolic value). For dealing with opaque predicates, we use an SMT solver (without constraints) to check if an expression evaluates to a constant. We also save the information about which locations have been symbolized and at which block ID.
3. Symbolization terminates once the set of symbolic locations reaches a fixed point (i.e., no new symbolic locations are introduced through state merging).
4. When performing CFG recovery (Section 5.2) again, Pushan can use the saved information regarding symbolized locations.

Symbolization allows for symbolic values to flow into the obfuscated conditions of conditional jumps and discover both branches. Symbolization allows Pushan to retrieve all possible jump targets for these types of indirect jumps by symbolizing the constant value that the condition checks for and exploring both branches.

Figure 5(d) examplifies symbolization, where initializing i=0 makes the loop-exit guard false and prunes the edge. After symbolization, i becomes symbolic, and both successors are explored (Figure 5(e)).

Increasing scalability by limiting symbolic solves. Many obfuscated expressions can be simplified to constants using an SMT solver, but it is time-consuming and does not scale. We choose a granularity where we resolve the constants by deciding to not solve for all possible expressions, and only solving for certain types of expressions, e.g., the addresses for loads and stores, because these expressions are usually for loading VM bytecode from the bytecode region. This way, we reduce the time spent in solving and still get the constants that are essential for simplifying away the VM machinery.

Mitigating the NP-hardness of path satisfiability. Existing approaches [^13] [^48] [^35] [^46] first collect an execution trace, then accumulate path constraints, and finally query the solver for inputs that satisfy yet-unexplored paths. In contrast, Pushan sidesteps full path satisfiability by adopting three lightweight techniques:

1. Constraint-free simplification. To enumerate jump targets, we pass the SMT solver only the target expression, omitting all accumulated path constraints. This keeps each query lightweight and tractable.
2. Symbolization. Whenever two paths merge, any differing concrete value is replaced with a fresh symbolic variable (e.g., the initial value 0 of hash in Listing 2(a)), dramatically shrinking the expressions handed to the solver.
3. Single-iteration loop handling. Each loop is executed at most once during symbolic emulation, preventing complex expressions from forming—which would otherwise be harder for the solver to handle. For instance, in Listing 2(a) the symbolized hash variable is computed over only one iteration; although this yields an approximated expression, it is sufficient for recovering all jump targets, as we do not care about the actual feasibility.

These three tactics suffice in practice, but they can be combined with modern MBA simplifiers [^27] [^33] [^34] to reduce complex symbolic expressions into forms from which the jump targets can directly be inferred.

## 6 Semantic-preserving Simplifications

A flat CFG is complete but insufficient for decompilation (or many other downstream analyses), because it contains many redundant instructions that correspond to VM interpreters. Pushan iteratively applies a series of semantic-preserving simplifications on the flat CFG until reaching a fixpoint and producing a simplified CFG that resembles the one in the original unprotected program.

### 6.1 List of Simplifications

Pushan uses the following simplifications.

S1. Standard simplifications. Pushan applys constant propagation across the flat CFG. Pushan treats VM bytecode regions as constant (read-only), allowing bytecode values to propagate. This propagation renders much of the VM interpreter machinery redundant (e.g., handler dispatch logic that loads the handler address from the bytecode region) and eliminatable by subsequent simplifications.

Pushan then applies dead assignment elimination to remove redundant bytecode-processing logic. This step also eliminates opaque predicates by resolving their guard conditions.

Lastly, Pushan performs basic arithmetic simplifications, e.g., grouping together the arithmetic operations performed on the same register. This simplification pass reduces the arithmetic operations left after dead assignment elimination. Figure 12 in the appendix shows an example.

S2. Redundant stack variable removal. A common pattern in simplified code is a value being stored at a stack location and immediately loaded into a register (and the stack location is never loaded after). Pushan simplifies this pattern by removing the redundant stack write. To avoid issues with pointer aliasing, we only apply this simplification within a basic block.

S3. Removing self-defining variables in loops. Pushan further removes self-referential stack and global variables that persist after dead assignment elimination. These variables, often remnants of loop counters, are pruned if their only use is self-incrementing or self-referencing. To maintain semantic integrity, Pushan preserves any variable that influences control-flow guards or serves as a function argument.

S4. Obfuscator-specific simplifications. Both VMProtect and Themida use transformations that are not simplified by previous techniques. For example, Themida converts every conditional jump into two conditional jumps. The first jump computes the check and sets a global variable. The second conditional jump checks the value of the global variable and chooses the correct branch. Pushan includes obfuscator-specific simplifications to simplify such patterns.

### 6.2 Differences to Prior Work

While prior work [^48] has implemented some simplifications (S1), we note some key differences below.

- Unlike prior work that operates on individual traces [^48], Pushan analyzes a complete CFG. This global perspective mitigates the risk of over-simplification inherent in trace-based approaches, which rely on precise, end-to-end taint tracking of user input to maintain correctness. Pushan remains input-agnostic and does not require a-priori knowledge of input sources or their propagation.
- Prior work may yield different simplification results when simplifying multiple traces, which makes merging traces into a CFG difficult. Pushan simplifies the CFG directly, so it does not need to reconstruct it.
- Pushan implements more simplifications (S2, S3), as well as obfuscator-specific simplifications (S4).

## 7 Decompilation

Pushan takes the simplified CFG from the previous stage and decompiles the entire CFG using a customized open-source binary decompiler. We discuss key steps in this section.

Identifying function boundaries. Most binary decompilers only decompile a function at a time. However, the function boundaries are unclear in obfuscated binaries, especially the function return sites, as there are many fake call and return statements that do not jump to or return from any functions. Additionally, some obfuscators will rewrite call instructions into jmp instructions to further obfuscate the control flow. While most bogus call and return instructions are removed during the simplification stage, there still remain some jump or return statements that actually transfer control flows. To address this, Pushan rewrites return statements and jump statements that go to functions inside the unobfuscated code of the binary into call statements.

Enhancing stack pointer tracking. Decompilers usually assume that specific registers (e.g., rsp on X86-64) are always stack pointers. This assumption does not always hold with obfuscated binaries, where rsp can be repurposed to hold generic values, causing the decompiler to fail to track or recover stack variables. Obfuscators may also insert code to conduct unconventional arithmetic operations, such as Negation, Xor, or MBA expressions, on stack pointer registers. This also curtails the stack pointer tracking that decompilers perform. Figure 6 shows such an example. We enhanced the open-source decompiler to discover the actual stack pointer registers and added support in stack pointer tracking for unconventional arithmetic operations and simplification rules.

[⬇](data:text/plain;base64,bm90KG5vdChyc3ApKzB4MTgpID09PiByc3AtMHgxOA==)

not(not(rsp)+0x18) ==\> rsp-0x18

Figure 6: An example of using an unconventional operation, Negation, when computing stack pointer offsets.

## 8 Evaluation

We first evaluate the effectiveness and correctness of Pushan on a diverse set of binaries for which we have the ground-truth (original source code or CFG). Our experiments include analyzing the deobfuscation and decompilation output (Section 8.3), comparing the deobfuscated CFGs to the original CFGs and quantifying their similarity (Section 8.4), and validating the semantic correctness of the deobfuscated code (Section 8.5). We then show with a case study that Pushan can achieve logic recovery using deobfuscated and decompiled code from a malware sample (Section 8.6). Lastly, we evaluate the effectiveness of Pushan on custom virtualization-based obfuscation implementations in binaries from Capture-the-Flag (CTF) competitions, for which we do not have ground truth (Section 8.7).

### 8.1 Dataset

To thoroughly evaluate Pushan, we constructed a dataset comprising multiple program categories. It includes six Windows malware samples used in prior work [^48], four open-source projects, four hand-crafted binaries, five challenges from Capture the Flag (CTF) competitions with custom VM implementations, 1,000 Tigress-generated virtualized binaries, and a real-world VMProtect-obfuscated executable.

Real malware. Our dataset includes six Windows malware samples (source code available) used in prior work [^48]. The malware contain typical malicious behaviors, e.g., backdoors and spreaders, demonstrating Pushan’s intended use case of malware analysis. The original versions of the samples totaled 1,125 instructions (see Table 2), which expanded to 531,790 instructions under VMProtect and over 5 million under Themida. For comparison, the 1993 remake of Doom contains under 4 million instructions.

Open-source software. We selected one function each from four widely used libraries—zlib (gz\_read), curl (glob\_url), libpng (png\_decompress\_chunk), and SDL (ClosePhysicalCamera). These cover reading bytes from a file, URL parsing, decompressing data, and device event handling, respectively.

Synthetic samples. We created four synthetic test binaries to evaluate obfuscation scenarios not covered by the malware samples. These include: 1) if-cond, which contains a simple input-dependent conditional jump, 2) hash, which implements the motivating example in Listing 2(a), 3) const-loop, which features complex loops that challenge DSE techniques, and 4) huffman for comparability to prior work.

Custom VMs from CTFs. We included five CTF challenges with bespoke virtualization-based obfuscation to test Pushan’s generalizability. These challenges all implement *custom* VM architectures, and Pushan was able to successfully deobfuscate all of them. In one of these challenges, the flag value was visible directly in the decompiled result, demonstrating Pushan’s ability to recover high-level semantics even from heavily obfuscated, custom virtual machines.

![Refer to caption](https://arxiv.org/html/2603.18355v1/x13.png)

(a) [^48]

Large-scale correctness dataset. For Tigress, we used the random function generator to produce $1,000$ hash functions, which we then obfuscated using virtualization along with the following configurations:

- VM-1: Stack-based VM with switch-case dispatch.
- VM-2: Opaque predicates, duplicate opcodes, direct dispatch, super operators, and additional obfuscations.
- VM-3: Virtualization with bogus functions, implicit flows, and opaque predicates.

Tigress operates at the source level, so we compiled the obfuscated source code to generate the final obfuscated binaries.

A real VM-obfuscated sample. Lastly, we evaluated Pushan on a real-world VMProtect-obfuscated binary. Pushan successfully recovered the logic of obfuscated functions, allowing us to determine the true nature of the binary.

### 8.2 Experiment Environment and Design

We ran all experiments on a Kubernetes cluster with 2.30GHz Intel Xeon CPUs, allocating up to 80GB of RAM per sample. We selected two popular commercial binary obfuscators: VMProtect 3.5.0 <sup>1</sup> and Themida 3.1.1.0. Both obfuscators offer virtualization-based obfuscation and other protections; for our evaluation, we disabled all but virtualization-based obfuscation. All our Themida-obfuscated samples use the Fish VM variant. To assess generalizability across different VM configurations, we also tested two samples each with the Tiger and Dolphin VM variants. In all cases, Pushan achieved the same CFG similarity scores across variants.

Each VMProtect and Themida sample in our dataset was compiled with and without the respective obfuscator SDKs, resulting in three binaries per sample: one original (used as ground truth) and two obfuscated binaries.

We implement a prototype of Pushan on angr [^39]. Our prototype mainly works with VEX IR during CFG recovery and simplification, then transitions to angr IL (AIL) for decompilation. Our heuristic-based VPC finder automatically identifies the VPC for VMProtect, Themida, and Tigress. For CTF challenges, we manually specify the VPC locations.

Comparison to prior work. Yadegari et al. [^48] did not fully released their tool. Upon contacting them, we learned that the concolic execution component of their tool is not publicly available. Instead, they only released the final CFGs for some of the samples. These CFGs consist solely of the graph structure, without any accompanying deobfuscated code, which is insufficient for accurately comparing similarities. VMHunt [^46] provides source code but lacks runnable samples, test binaries, or documentation needed for reproducing their results. Salwan’s framework [^35] targeting Tigress binaries is available and functional. We use it as a baseline for evaluating our approach on the Tigress binaries of our dataset.

Table 2: Evaluation results for open source software, malware and synthetic programs showing the impact of virtualization-based obfuscation. VMProtect and Themida expand binaries by several orders of magnitude. CFG similarity is measured using our enhanced graph edit distance metric, showing high CFG similarity across all samples.

<table><tr><td rowspan="2">Program</td><td rowspan="2">Function</td><td colspan="3">Instructions</td><td>LoC</td><td colspan="2">DLoC</td><td colspan="2">Similarity on VMP</td><td colspan="2">Similarity on TH</td></tr><tr><td>Orig</td><td>VMP</td><td>TH</td><td>Orig</td><td>VMP</td><td>TH</td><td>Pushan</td><td>Yadegari</td><td>Pushan</td><td>Yadegari</td></tr><tr><td>zlib</td><td>gz_read</td><td>188</td><td>302,697</td><td>669,613</td><td>70</td><td>417</td><td>162</td><td>100%</td><td>–</td><td>100%</td><td>–</td></tr><tr><td>curl</td><td>glob_url</td><td>133</td><td>169,925</td><td>704,548</td><td>42</td><td>137</td><td>73</td><td>86%</td><td>–</td><td>76%</td><td>–</td></tr><tr><td>libpng</td><td>png_decompress_chunk</td><td>274</td><td>378,108</td><td>1,027,454</td><td>134</td><td>472</td><td>154</td><td>69%</td><td>–</td><td>47%</td><td>–</td></tr><tr><td>sdl</td><td>ClosePhysicalCamera</td><td>139</td><td>200,077</td><td>831,575</td><td>50</td><td>367</td><td>305</td><td>81%</td><td>–</td><td>100%</td><td>–</td></tr><tr><td>netsky</td><td>main</td><td>150</td><td>162,140</td><td>679,448</td><td>33</td><td>146</td><td>123</td><td>96%</td><td>33%</td><td>96%</td><td>19%</td></tr><tr><td>hunatcha</td><td>InfectDrives</td><td>99</td><td>50,999</td><td>791,110</td><td>22</td><td>51</td><td>25</td><td>100%</td><td>30%</td><td>100%</td><td>23%</td></tr><tr><td>cairuh</td><td>kazaa_spread</td><td>186</td><td>142,148</td><td>1,466,296</td><td>28</td><td>147</td><td>118</td><td>100%</td><td>–</td><td>93%</td><td>–</td></tr><tr><td>blaster</td><td>blaster_spreader</td><td>140</td><td>99,389</td><td>773,785</td><td>64</td><td>130</td><td>87</td><td>92%</td><td>49%</td><td>100%</td><td>–</td></tr><tr><td>newstar</td><td>InfectExes</td><td>81</td><td>33,760</td><td>489,129</td><td>18</td><td>40</td><td>22</td><td>100%</td><td>53%</td><td>100%</td><td>18%</td></tr><tr><td>newstar</td><td>Backdoor</td><td>116</td><td>43,354</td><td>848,283</td><td>31</td><td>27</td><td>48</td><td>100%</td><td>–</td><td>100%</td><td>–</td></tr><tr><td>huffman</td><td>create_huffman_codes</td><td>205</td><td>106,001</td><td>851,284</td><td>30</td><td>241</td><td>148</td><td>82%</td><td>33%</td><td>92%</td><td>31%</td></tr><tr><td>hash</td><td>main</td><td>51</td><td>59,976</td><td>273,381</td><td>12</td><td>75</td><td>40</td><td>100%</td><td>–</td><td>100%</td><td>–</td></tr><tr><td>if-cond</td><td>main</td><td>15</td><td>37,951</td><td>163,950</td><td>6</td><td>11</td><td>13</td><td>100%</td><td>–</td><td>100%</td><td>–</td></tr><tr><td>const-loop</td><td>main</td><td>23</td><td>43,354</td><td>61,943</td><td>5</td><td>53</td><td>17</td><td>100%</td><td>–</td><td>100%</td><td>–</td></tr></table>

DLoC: Decompiled Lines of Code (LoC) after Pushan’s deobfuscation. Similarity: CFG similarity score computed using enhanced GED. Orig: Instructions / Lines of Code (LoC) in the *original*, unobfuscated binary. VMP: VMProtect. TH: Themida.

### 8.3 Effectiveness

To show that Pushan handles real-world malware and aids reverse engineering, we analyzed multiple aspects of decompilation.

Comparison against original source code. Table 2 compares lines of decompiled code against source code for programs whose original code is available. Some binaries, such as huffman, show significant line expansion due to obfuscated conditional branch representation. VMProtect, for instance, replaces conditional jumps (jz, jle) with flag bit calculations. This spreads condition checks across multiple instructions that our semantics-preserving transformations cannot simplify to the original form. Resolving this requires mapping instruction sequences back to original conditional jumps. We leave it as future work as it does not impact our core technique.

For Tigress samples (Table 4), the line count increase stems from limited code-level simplifications rather than control-flow complexity. Pushan outputs one arithmetic operation per line for Tigress, while the original source combines multiple operations per line. This increases line count despite equivalent underlying logic.

![Refer to caption](https://arxiv.org/html/2603.18355v1/x16.png)

Figure 8: Time taken by different stages of Pushan. Time for sdl-Themida is excluded from graph due to scale. (Symbolization: 512.72, Simplification: 109.52, Decompilation: 4.59)

Runtime performance. Figure 8 shows the runtime breakdown by stage. Themida-obfuscated binaries take longer to analyze because they contain more instructions. Pushan’s performance scales with binary size and the number of constant-guarded nested loops, requiring one symbolization run per such condition. Our largest sample, huffman (Themida), contained 851,284 instructions and took 10 hours to analyze. Other large samples—hash (Themida, 273,381 instructions) and huffman (VMProtect, 106,001 instructions)—completed in under 4 and 2 hours, respectively.

Table 3: CTF Challenge Analysis. DLoC = lines of decompiled code. “API” indicates whether the recovered CFG contained the API trace from execution. “Writeup” indicates whether the recovered CFG matched functionality described in publicly available CTF writeups.

| Challenge | DLoC | API | Writeup |
| --- | --- | --- | --- |
| reduced-reduced-instruction-set-1 | 158 | ✓ | ✓ |
| Discount VMProtect | 86 | ✓ | ✓ |
| simple-vm | 110 | ✓ | ✓ |
| Highly Optimized | 167 | ✓ | ✓ |
| vmwhere1 | 1768 | ✓ | ✓ |

### 8.4 Correctness: CFG Similarity

We first measure the graph edit distance (GED) of our deobfuscated CFG to the original CFG. Previous work [^48] utilized the Hu GED algorithm [^21] to measure the approximate similarity of their graphs. We found this GED estimation algorithm inapplicable for two reasons. First, the Hu algorithm relies on the presence of x86 instructions to improve its results by matching opcodes—Pushan does not produce x86 instructions. Second, the Hu algorithm often incorrectly reports identical graphs as different. For interested readers, it reported a non-zero distance when comparing two identical 16-node graphs, as shown in Figure 11 in Appendix.

For more accurate CFG measurement, we extended the CFGED algorithm by Basque et al. [^5] to handle addressless graphs. The CFGED algorithm relies on a partial mapping of nodes across two CFGs, commonly collected by matching the addresses of node pairs. After obfuscation and subsequent deobfuscation, this address association is lost. Instead, we automatically created a mapping using information from the CFG blocks. To do this, we extended the discovRE [^17] block-similarity algorithm. First, we matched all nodes with the same function calls. When multiple nodes match, we select pairs at the same distance from the graph’s root. After this initial set of mappings, we ran the discovRE algorithm to match any nodes more than 60% similar. We manually validated that all of these mappings were correct on all of our samples, and will release our tooling. To further ensure correctness, we evaluated the effectiveness of our extended CFGED algorithm on CFGs used to evaluate CFGED in previous work [^5]. This set consisted of 491 unique function pairs across optimized and unoptimized binaries from Coreutils. Of the 491 pairs, our algorithm had the exact score on 389 pairs (79%), while the Hu algorithm was exact on 36 pairs (7%). Additionally, our algorithm introduced an average similarity error of 3% while the Hu algorithm introduced 22%.

For CTF challenges lacking ground truth, we cannot perform graph edit distance matching. Instead, we approximate similarity by collecting an API trace from a single execution and verifying whether our recovered CFG can produce the same API sequence through DFS traversal.

Results. Table 2 shows the normalized similarity score produced by our extended CFGED algorithm. We normalized our GED score as described in prior work [^48].

Malware samples: Pushan generated isomorphic CFGs for four of six samples, with near-isomorphic results for huffman and netsky. The differences stem from redundant if-else branches that Pushan’s simplification does not eliminate.

We evaluated the artifacts from prior work [^48] using our extended CFGED algorithm. As Table 2 shows, Pushan outperforms Yadegari’s across all released artifacts. The best similarity score Yadegari et al. achieved was 53%, whereas Pushan consistently achieves significantly higher scores.

Open-source programs: Pushan generated isomorphic graphs for both zlib and sdl. For curl, the recovered CFGs closely match the original structure, with only minor simplifications remaining. The libpng similarity score is lower due to Pushan’s aggressive pruning of semantically empty nodes. Despite this, the recovered CFGs preserve overall structure and semantic correctness.

![Refer to caption](https://arxiv.org/html/2603.18355v1/x17.png)

Figure 9: Histogram comparing CFG similarity produced by Salwan and PUSHAN over 647 common samples.

Tigress: Pushan generated isomorphic graphs for 982 of 1,000 Tigress samples, as detailed in Table 4. When evaluating Salwan’s tool [^35] on the same dataset, only 647 samples completed within three days. As illustrated in Figure 9, when comparing CFG similarity on these 647 common samples, Pushan significantly outperforms Salwan’s tool—achieving 643 isomorphic graphs compared to only Salwan’s 68.

Overall, Pushan restored isomorphic CFGs for 999 of 1,028 VM-obfuscated targets across all obfuscators.

Table 4: Tigress Deobfuscation and Decompilation Results across three VM configurations. LoC = lines of code. “Verified” indicates successful semantic validation.

<table><tr><td>Metric</td><td>VM-1</td><td>VM-2</td><td>VM-3</td></tr><tr><td colspan="4">Deobfuscation Results</td></tr><tr><td>Total Files</td><td>334</td><td>333</td><td>333</td></tr><tr><td>Succeeded</td><td>330</td><td>329</td><td>329</td></tr><tr><td>Failed</td><td>4</td><td>4</td><td>4</td></tr><tr><td>Success Rate</td><td>98.80%</td><td>98.80%</td><td>98.80%</td></tr><tr><td>Total Time</td><td>1397.94 hr</td><td>2523.97 hr</td><td>1525.01 hr</td></tr><tr><td>Average Time</td><td>4.19 hr</td><td>7.58 hr</td><td>4.58 hr</td></tr><tr><td colspan="4">Verification Results</td></tr><tr><td>Files Processed</td><td>330</td><td>329</td><td>328</td></tr><tr><td>Succeeded</td><td>318</td><td>320</td><td>318</td></tr><tr><td>Failed</td><td>12</td><td>9</td><td>10</td></tr><tr><td>Success Rate</td><td>96.36%</td><td>97.26%</td><td>96.95%</td></tr><tr><td>Total Time</td><td>1430.73 hr</td><td>1335.43 hr</td><td>1717.03 hr</td></tr><tr><td>Average Time</td><td>4.34 hr</td><td>4.06 hr</td><td>5.23 hr</td></tr><tr><td colspan="4">Decompilation Quality</td></tr><tr><td>Decompiled Files</td><td>330</td><td>329</td><td>329</td></tr><tr><td>Avg. LoC (Original)</td><td>187</td><td>185</td><td>188</td></tr><tr><td>Avg. LoC (Obfuscated)</td><td>4824</td><td>4686</td><td>5166</td></tr><tr><td>Avg. LoC (Decompiled)</td><td>692</td><td>739</td><td>698</td></tr><tr><td>Max Lines (Original)</td><td>555</td><td>604</td><td>516</td></tr><tr><td>Max Lines (Obfuscated)</td><td>13619</td><td>13246</td><td>12827</td></tr><tr><td>Max Lines (Decompiled)</td><td>2172</td><td>2506</td><td>2273</td></tr><tr><td colspan="4">CFG Similarity</td></tr><tr><td>100% Similarity (Count/Total)</td><td>328 / 330</td><td>326 / 329</td><td>328 / 329</td></tr></table>

### 8.5 Correctness: Semantic Equivalence

We evaluate Pushan’s correctness using Tigress-generated programs because they compute hash functions, which provide a simple, deterministic mapping from inputs to outputs. This enables automated validation through output comparison—if the deobfuscated program produces the same hash value as the original for a given input, behavioral equivalence is guaranteed.

We evaluated semantic correctness on Tigress samples using input/output testing on the recovered VEX IR. Since Tigress programs compute hash functions, we tested each sample with 100 distinct inputs and compared the deobfuscated VEX IR outputs against the original binary.

We present our results in Table 4. The recovered IR produced correct outputs in nearly all successful deobfuscation cases. Specifically, 956 of 1,000 Tigress samples passed all 100 input/output tests, demonstrating that Pushan reliably preserves functional behavior. In some cases, decompilation failed while CFG-level verification succeeded.

### 8.6 Analyzing A Real Binary via Code Reuse

We analyzed a VMProtect-obfuscated malware sample obtained in the wild. According to VirusTotal, 28 out of 72 antivirus engines flagged this sample as malicious [^41], revealing a wide disagreement among them. From reversing the non-obfuscated logic in this binary, we found that it uses a VM-obfuscated function to decrypt an embedded AutoIt script. However, attackers may have also implemented malicious behaviors in the obfuscated function. We must fully deobfuscate this function to determine whether the binary is malicious or not.

Pushan took a total of 85 minutes to deobfuscate and decompile the obfuscated function. The final pseudo-code (476 lines) correctly reflected the complete control flow, revealing no additional malicious behaviors other than conducting integer operations inside two loops.

We provided the pseudocode output to Claude (Opus 4.6) with instructions to produce a simplified, recompilable, and semantically equivalent C implementation. Notably, we gave the model only Pushan’s decompiled pseudo-code, without access to the original binary, disassembly, or any auxiliary analysis tools. Claude reduced the 476-line function to approximately 30 lines of recompilable C, inferring that the function is “a pseudo-random number generator wrapper with hash-based seeding.” This reduced function allowed us to extract the embedded AutoIt script. We then realized that the main feature of this script was patching another commercial utility, DiskGenius, to potentially bypass its license checks if the host machine is not using Simplified or Traditional Chinese codepages. This allows us to conclude that the binary is a crack, which is not inherently malicious but may be used for software piracy.

We note that while it is possible to extract the the embedded AutoIt script by debugging the binary and bypassing potential runtime protections (e.g., anti-debugging checks), dynamic analysis cannot reveal hidden behaviors in the VM-obfuscated function. This highlights the necessity of static deobfuscation and decompilation of Pushan.

### 8.7 Extensibility: Decompiling Custom VMs

Without ground-truth source code for CTF challenges, we validated correctness through API trace matching and comparison with public write-ups. All five challenges matched both API traces and write-up descriptions (Table 3). In one challenge (Listing [B. CTF Challenge](#Ax2 "B. CTF Challenge ‣ Pushan: Trace-Free Deobfuscation of Virtualization-Obfuscated Binaries"), appendix), the decompiled output directly revealed embedded flag values in conditional branches.

CFG similarity. For all CTF challenges, we successfully reproduced the observed API call sequence by traversing the recovered CFG, confirming at least one correct execution path. We also manually verified that each recovered CFG contained the functionality described in public write-ups.

## 9 Discussion

Pushan does not yet simplify complex or obfuscated arithmetic expressions such as MBA expressions. Without simplifying away obfuscated expressions, the decompilation output of Pushan may have a simplified control flow, but its semantics can still be hard to understand. Existing solutions (e.g., MBA-Blast) simplify many types of MBA expressions. LOKI [^36] primarily uses MBA expressions to obfuscate the semantics of handlers, without focusing on obfuscating the VM structure itself. As Pushan does not support MBA simplification, we do not compare against these works.

Obfuscators can attack the symbolization process of Pushan by adding malformed control flows that result in the incorrect symbolization of actual constants. This could cause Pushan to generate a deobfuscated CFG with missing branches or spurious branches that are not present in the original program. We can improve the Pushan prototype by tracking the constant values more accurately: Avoiding merging symbolic variables to TOP and instead introducing a value domain where values are guarded by their path predicates. This way Pushan can split these merged values back to their original values and prevent incorrect symbolization.

Although Pushan is more scalable than deobfuscation solutions that rely on full-trace DSE, the current prototype of Pushan is still too slow due to the reliance on theorem provers to simplify MBA expressions to constants. Integrating existing MBA simplification techniques would greatly speed up Pushan by avoiding excessive use of the solver.

## 10 Related Work

Virtualization deobfuscation. Kochberger et al. [^24] provide a systematization of various VM deobfuscation techniques based on extracted artifacts, analysis efforts, degree of automation, and generalizability. Beyond the works on automated deobfuscation studied in Section 2, Liang et al. [^26] propose to use symbolic execution to identify handler semantics. However, this comes with the pitfalls of using symbolic execution for deobfuscation that Pushan avoids. Similar to other works, SEEAD [^40] proposes dynamic taint analysis to identify control dependencies in obfuscated code, combined with aggressive path pruning. This increases performance but comes with the risk of missing paths.

#### MBA Deobfuscation

Orthogonal to our approach, various techniques focus on the simplification of MBA expressions, including techniques such as: (a) Pattern matching [^18] [^8], which relies on existing knowledge, limiting their scope; (b) Program synthesis [^9] [^14] [^25] [^29] generates simpler equivalent expressions but doesn’t guarantee correctness; (c) Algebraic methods [^27] [^33] [^34] that are based on the property that two semantically equivalent n-bit input variables are aligned for 1-bit input variables, which is effective for linear MBA expressions; (d) Deep learning [^19], which takes a novel approach by training models to deobfuscate MBA expressions. Additionally, Arybo [^20] employs the Bit-Blast method, simplifying arithmetic expressions to bit-level symbolic expressions, best suited for small expressions because of high-performance cost.

## 11 Conclusion

Pushan is a scalable technique for deobfuscating and decompiling virtualization-obfuscated binaries. Building on the concept of VPC-sensitive CFG recovery, Pushan allows for the recovery of complete, pre-obfuscation CFGs without relying on user input that covers all branches of the obfuscated program or performing DSE on a sufficient number of traces and finding user input. The experiments show that Pushan can recover the CFGs of the original, unobfuscated programs with a high level of similarity and output decompiled code that can enable advanced malware analysis with LLMs.

## Ethical Considerations

This work aims to advance defensive security capabilities through improved malware analysis.

#### Stakeholders

We identify three stakeholders, malware analysts, companies relying on virtualization-obfuscation for legitimate purposes, and society in general.

#### Impact

Our work has both a positive and negative impact.

*Positive Impact:* Our work helps malware analysts to analyze protected malware at scale, as manual reverse engineering is time-consuming, error-prone, and does not scale to the volume of obfuscated malware encountered in practice. Helping to identify malware enables timely mitigation, thus benefitting society in general.

*Negative Impact:* Malicious actors could likewise use our code to target benign code obfuscated by companies to protect their intellectual property, prevent cheating in online games, or use it for Digital Rights Management (DRM) applications.

#### Mitigations

To avoid harm, we conducted all experiments on publicly available datasets and malware samples from public sources. Our analysis of the VMProtect-obfuscated sample revealed it to be a software crack rather than intentional malware. No human subjects or sensitive data were involved in our research, ensuring we respect persons. Ultimately, we cannot prevent misuse of our tool by malicious actors.

#### Justification for Research

We believe the benefits to defenders significantly outweigh potential harms. Virtualization-based obfuscation is widely used for legitimate purposes such as protecting intellectual property and preventing game piracy, but is also heavily employed by malware authors. Our work primarily benefits security analysts who need to analyze protected malware at scale, as manual reverse engineering is time-consuming, error-prone, and does not scale to the volume of obfuscated malware encountered in practice. We believe that publication of our research benefits the security community by enabling more effective analysis of protected malware, which is essential for developing defenses against evolving threats.

## Acknowledgments

This work was supported by the Advanced Research Projects Agency for Health (ARPA-H) under Contract No. SP4701-23-C-0074, the National Science Foundation (NSF) under Grants No. 2232915 and 2146568, and the Office of Naval Research (ONR) under Grant No. N00014-23-1-2563. We also gratefully acknowledge the generous support of the U.S. Department of Defense.

## References

## A. The Original and Deobfuscated CFGs of Some Samples

Figures 10 and 11 provide a visual comparison between the original and the deobfuscated CFGs of three samples.

![Refer to caption](https://arxiv.org/html/2603.18355v1/x18.png)

(a) The CFG of the VMProtect-obfuscated huffman program. Cropped for clarity.

![Refer to caption](https://arxiv.org/html/2603.18355v1/x21.png)

(a) The CFG of the Themida-obfuscated Hunatcha program.

[⬇](data:text/plain;base64,dDIgPSBHRVQ6STMyKGVheCkKdDAgPSBBZGQzMih0MiwgMHgwMDAwMDAwMSkKdDMgPSBBZGQzMih0MCwgMHgwMDAwMDAwMik=)

t2 = GET:I32(eax)

t0 = Add32(t2, 0x00000001)

t3 = Add32(t0, 0x00000002)

(a) Before arithmetic simplification.

[⬇](data:text/plain;base64,dDIgPSBHRVQ6STMyKGVheCkKCnQzID0gQWRkMzIodDIsIDB4MDAwMDAwMDMp)

t2 = GET:I32(eax)

t3 = Add32(t2, 0x00000003)

(b) After arithmetic simplification.

[⬇](data:text/plain;base64,cHVzaCBhZGRyCnJldA==)

push addr

ret

(c) Before push retn simplification.

[⬇](data:text/plain;base64,am1wIGFkZHI=)

jmp addr

(d) After push retn simplification.

[⬇](data:text/plain;base64,dDI5ID0gQWRkNjQodDEyLDB4ZmZmZmZmZmZmZmZmZmU4MCkKU1RsZSh0MjkpID0gdDI3Ci4uLgp0MzEgPSBBZGQ2NCh0MjMsMHhmZmZmZmZmZmZmZmZmZTgwKQp0MzMgPSBMRGxlOkk2NCh0MzEp)

t29 = Add64(t12,0xfffffffffffffe80)

STle(t29) = t27

...

t31 = Add64(t23,0xfffffffffffffe80)

t33 = LDle:I64(t31)

(e) Redundant stack-based data movement.

[⬇](data:text/plain;base64,dDI5ID0gQWRkNjQodDEyLDB4ZmZmZmZmZmZmZmZmZmU4MCkKU1RsZSh0MjkpID0gdDI3Ci4uLgp0MzEgPSBBZGQ2NCh0MjMsMHhmZmZmZmZmZmZmZmZmZTgwKQp0MzMgPSB0Mjc=)

t29 = Add64(t12,0xfffffffffffffe80)

STle(t29) = t27

...

t31 = Add64(t23,0xfffffffffffffe80)

t33 = t27

(f) After eliminating redundant stack-based data movement.

Figure 12: Examples of semantics-preserving simplifications.

## B. CTF Challenge

\[tb\]

[⬇](data:text/plain;base64,Y21wID0gMTg4NTU2NjA1NCAtIGlucHV0OyAgLy8gInBjdGYiDQppZiAoIWNtcCkgcmV0dXJuOw0KLy8gLi4uIG9taXR0ZWQgY29kZSAuLi4NCmNtcCA9IDIwNzEzNTg4MTUgLSBpbnB1dDsgIC8vICJ2bV97Ig0KaWYgKCFjbXApIHJldHVybjsNCi8vIC4uLiBvbWl0dGVkIGNvZGUgLi4uDQpjbXAgPSAxOTE1OTc1MjY5IC0gaW5wdXQ7ICAvLyAicjN2ZSINCmlmICghY21wKSByZXR1cm47DQovLyAuLi4gb21pdHRlZCBjb2RlIC4uLg0KY21wID0gMTkyMDE1MjQyNSAtIGlucHV0OyAgLy8gInJzM2kiDQppZiAoIWNtcCkgcmV0dXJuOw0KLy8gLi4uIG9taXR0ZWQgY29kZSAuLi4NCmNtcCA9IDE4NTAxNzExODUgLSBpbnB1dDsgIC8vICJuR18xIg0KaWYgKCFjbXApIHJldHVybjsNCi8vIC4uLiBvbWl0dGVkIGNvZGUgLi4uDQpjbXAgPSAxOTM1NjM1NTcwIC0gaW5wdXQ7ICAvLyAic190ciINCmlmICghY21wKSByZXR1cm47DQovLyAuLi4gb21pdHRlZCBjb2RlIC4uLg0KY21wID0gODI4NTk5MTYxIC0gaW5wdXQ7ICAgLy8gIjFja3kiDQppZiAoIWNtcCkgcmV0dXJuOw0KLy8gLi4uIG9taXR0ZWQgY29kZSAuLi4NCmNtcCA9IDIxMDAzMTAwNjQgLSBpbnB1dDsgIC8vICJ9MDAwIg0KaWYgKCFjbXApIHJldHVybjsNCg==)

cmp = 1885566054 - input; // "pctf"

if (!cmp) return;

//... omitted code...

cmp = 2071358815 - input; // "vm\_{"

if (!cmp) return;

//... omitted code...

cmp = 1915975269 - input; // "r3ve"

if (!cmp) return;

//... omitted code...

cmp = 1920152425 - input; // "rs3i"

if (!cmp) return;

//... omitted code...

cmp = 1850171185 - input; // "nG\_1"

if (!cmp) return;

//... omitted code...

cmp = 1935635570 - input; // "s\_tr"

if (!cmp) return;

//... omitted code...

cmp = 828599161 - input; // "1cky"

if (!cmp) return;

//... omitted code...

cmp = 2100310064 - input; // "}000"

if (!cmp) return;

Listing.2 Decompiled output from a CTF challenge implementing a custom VM. Each constant maps to a 4-character segment of the flag, which can be directly recovered by inspecting the arithmetic conditions.

## C. Pushan Deobfuscation Output of The Real-world Sample

\[tb\]

[⬇](data:text/plain;base64,ZXh0ZXJuIGNoYXIgZ183ZmY3NGRiNWYxZTU7CmV4dGVybiBjaGFyIGdfN2ZmNzRkYjVmNzA1OwpleHRlcm4gY2hhciBnXzdmZjc0ZGI1ZmYxYTsKCmxvbmcgVk1fMSh1bnNpZ25lZCBsb25nIGEwLCB1bnNpZ25lZCBpbnQgYTEpCnsgICAKICAgIC4KICAgIC4KICAgIC4KICAgIC4KCiAgICB2NDQgPSAwOwogICAgdjQzID0gdjI1OwogICAgdjcgPSAqKChpbnQgKikmdjQzKTsKICAgIHY4ID0gMDsKICAgIHY0MiA9IDggKyB2OTsKICAgIHYxOSA9IHY0MjsKICAgIHYxNSA9IHYxOTsKICAgIHYyNCA9IDB4N2ZmNjBkYTcwMDAwOwogICAgdjYgPSB0bXBfMTAzNTsKICAgIHY1ID0gdjk7CiAgICB2OSA9IHYxOTsKICAgIHYxOSA9IDE3OwogICAgdjIgPSAqKChsb25nIGxvbmcgKikmdjcpOwogICAgdjIzID0gdjEwOwogICAgdjcgPSB2MTU7CiAgICB2MTcgPSB0bXBfMTA3MDsKICAgIHYxMCA9IHYyMjsKICAgIHY0NyA9IDQzNTMwODA1MzsgICAgCiAgICAuCiAgICAuCiAgICAuCiAgICAuCiAgICB2MTkgPSB2MzY7CiAgICB2MzYgPSB2MjQgKyA2ODsKICAgIHYxMyA9IHYzNjsKICAgIHYxNCA9IDA7CiAgICBtZW1tb3ZlKHYxOSwgdjE4LCAqKChsb25nIGxvbmcgKikmdjEzKSk7CiAgICB2MTMgPSB2MjA7CiAgICB2MTkgPSB2MTg7CiAgICB2MTggPSAwOwogICAgdjYgPSAxNDQgKyB2MTM7CiAgICB2OTEgPSAxOwogICAgdjkyID0gKHYxOCA+PiAyMSA9PSAxID8gMSA6IDApOwogICAgdjkzID0gKHYxOCA+PiAxOCA9PSAxID8gMSA6IDApOwogICAgbWVtbW92ZSh2NiwgdjE5LCA2OCk7CiAgICB2NSA9IDA7CiAgICB2NDAgPSB2MTM7CiAgICB2MzMgPSB2NTsKICAgIHYxOCA9IDk7CiAgICBkbwogICAgewogICAgICAgIHY1MCA9IDQgfCB2OTEgJiAweDQwMCB8IHY5MiAqIDB4MjAwMDAwICYgMHgyMDAwMDAgfCB2OTMgKiAweDQwMDAwICYgMHg0MDAwMDsKICAgICAgICB2MzUgPSB2MTg7CiAgICAgICAgdjM0ID0gdjMzOwogICAgICAgIHY5MSA9ICh2MzQgPj4gMTAgPT0gMSA/IC0xIDogMSk7CiAgICAgICAgdjkyID0gKHYzNCA+PiAyMSA9PSAxID8gMSA6IDApOwogICAgICAgIHY5MyA9ICh2MzQgPj4gMTggPT0gMSA/IDEgOiAwKTsKICAgICAgICB2OTQgPSBwcm5nKHY0MCk7CiAgICAgICAgdjIxID0gMDsKICAgICAgICB2MTIgPSB2OTQ7CiAgICAgICAgdjE4ID0gdjQwOwogICAgICAgIHYxOSA9IDA7CiAgICAgICAgdjIwID0gLTEgKyB2MzU7CiAgICAgICAgdjI0ID0gKDEgJiB2MjEpICsgKC0yICYgdjE5KTsKICAgICAgICB2MjEgPSB+KH4odjI0KSAmIC0xNykgJiB+KDE2ICYgfih+KHYyNCkgJiB+KCgxICYgdjIxKSArICgtMiAmIHYxOSkpKSk7CiAgICAgICAgdjUwID0gKigobG9uZyBsb25nICopKChjaGFyICopJjwweDRlNmY2ZTY1MzEzNDMwMzczMDMwMzEzMzM2MzkzMzM5MzkzOTMyMzBbaXNfMTg5XXxTdGFjayBicC0xNiwgMSBCPiArICgofih2MjEpICYgNjQpID4+IDMpKSk7CiAgICAgICAgdjI0ID0gdjUwOwogICAgICAgIHY0OSA9IHY1MDsKICAgICAgICB2NDkgPSB+KCooKGxvbmcgbG9uZyAqKSZ2NDkpKTsKICAgICAgICB2NTAgPSAqKChpbnQgKikoKGNoYXIgKikmdjQ5ICsgNCkpICYgKGludCl2NDk7CiAgICAgICAgdjQ5ID0gMjQ3Mjc0NDAyOwogICAgICAgIHY0OSA9IH4oKigobG9uZyBsb25nICopJnY0OSkpOwogICAgICAgIHY1MCA9ICooKGludCAqKSgoY2hhciAqKSZ2NDkgKyA0KSkgJiAtMjQ3Mjc0NDAzOwogICAgICAgIHY0OSA9IC0yNDcyNzQ0MDM7CiAgICAgICAgdjQ4ID0gdjI0OwogICAgICAgIHY0OCA9IH4oKigobG9uZyBsb25nICopJnY0OCkpOwogICAgICAgIHY0OSA9IDI0NzI3NDQwMiAmIChpbnQpdjQ4OwogICAgICAgIHY0OSA9IH4oKigobG9uZyBsb25nICopJnY0OSkpOwogICAgICAgIHY1MCA9ICooKGludCAqKSgoY2hhciAqKSZ2NDkgKyA0KSkgJiAoaW50KXY0OTsKICAgICAgICB2MTMgPSB2OTEgJiAweDQwMCB8IHY5MiAqIDB4MjAwMDAwICYgMHgyMDAwMDAgfCB2OTMgKiAweDQwMDAwICYgMHg0MDAwMDsKICAgICAgICB2MzMgPSB2MjE7CiAgICAgICAgdjMyID0gdjEzOwogICAgICAgIHYyNyA9IHY1MDsKICAgICAgICB2OTUgPSAoaW50KXYyNyArIDB4MTAwMDAwMDAwOwogICAgICAgIHY5NiA9ICooKGNoYXIgKikoKGludCl2MjcgKyAxNDA2OTkwNjI2OTc5ODUpKTsKICAgICAgICAuCiAgICAgICAgLgogICAgICAgIC4KICAgICAgICAuCgogICAgfSB3aGlsZSAoKCgoKCgoKCZnXzdmZjc0ZGI1ZmYxYSlbX19ST1JfXyhfX1JPTF9fKCooKGNoYXIgKikoKGludCl2MjcgKyAxNDA2OTkwNjI2OTgwMTcpKSAtICgoY2hhcil2MCAtIDEzMyAtIChjaGFyKXYxMDIpLCA1KSAtIDMzLCA0KV0gJiAtMHhmZjAwZmYwMGZmMDEwMCkgPj4gOCB8ICgmZ183ZmY3NGRiNWZmMWEpW19fUk9SX18oX19ST0xfXygqKChjaGFyICopKChpbnQpdjI3ICsgMTQwNjk5MDYyNjk4MDE3KSkgLSAoKGNoYXIpdjAgLSAxMzMgLSAoY2hhcil2MTAyKSwgNSkgLSAzMywgNCldIDw8IDggJiAtMHhmZjAwZmYwMGZmMDEwMCkgJiAtMHhmZmZmMDAwMTAwMDApID4+IDE2IHwgMHg0MDBlMDAwMDAwMDAwMDAwKSAmIC0weDEwMDAwMDAwMCkgPj4gMzIgfCAweDEwMDAwMDAwMCkgKyAweDdmZjYwZGE3MDAwMCA9PSAxNDA3MDAxMzc0MjA1NDkpOwogICAgdjUwID0gMDsKICAgICooKHVuc2lnbmVkIGxvbmcgKikmdjUwWzg4XSkgPSB2MTI7CiAgICByZXR1cm4gKGxvbmcgbG9uZyl2NTBbODhdOwp9Cg==)

extern char g\_7ff74db5f1e5;

extern char g\_7ff74db5f705;

extern char g\_7ff74db5ff1a;

long VM\_1(unsigned long a0, unsigned int a1)

{

.

.

.

.

v44 = 0;

v43 = v25;

v7 = \*((int \*)&v43);

v8 = 0;

v42 = 8 + v9;

v19 = v42;

v15 = v19;

v24 = 0x7ff60da70000;

v6 = tmp\_1035;

v5 = v9;

v9 = v19;

v19 = 17;

v2 = \*((long long \*)&v7);

v23 = v10;

v7 = v15;

v17 = tmp\_1070;

v10 = v22;

v47 = 435308053;

.

.

.

.

v19 = v36;

v36 = v24 + 68;

v13 = v36;

v14 = 0;

memmove(v19, v18, \*((long long \*)&v13));

v13 = v20;

v19 = v18;

v18 = 0;

v6 = 144 + v13;

v91 = 1;

v92 = (v18 \>\> 21 == 1? 1: 0);

v93 = (v18 \>\> 18 == 1? 1: 0);

memmove(v6, v19, 68);

v5 = 0;

v40 = v13;

v33 = v5;

v18 = 9;

do

{

v50 = 4 | v91 & 0x400 | v92 \* 0x200000 & 0x200000 | v93 \* 0x40000 & 0x40000;

v35 = v18;

v34 = v33;

v91 = (v34 \>\> 10 == 1? -1: 1);

v92 = (v34 \>\> 21 == 1? 1: 0);

v93 = (v34 \>\> 18 == 1? 1: 0);

v94 = prng(v40);

v21 = 0;

v12 = v94;

v18 = v40;

v19 = 0;

v20 = -1 + v35;

v24 = (1 & v21) + (-2 & v19);

v21 = ~(~(v24) & -17) & ~(16 & ~(~(v24) & ~((1 & v21) + (-2 & v19))));

v50 = \*((long long \*)((char \*)&<0x4e6f6e6531343037303031333639333939393230\[is\_189\]|Stack bp-16, 1 B\> + ((~(v21) & 64) \>\> 3)));

v24 = v50;

v49 = v50;

v49 = ~(\*((long long \*)&v49));

v50 = \*((int \*)((char \*)&v49 + 4)) & (int)v49;

v49 = 247274402;

v49 = ~(\*((long long \*)&v49));

v50 = \*((int \*)((char \*)&v49 + 4)) & -247274403;

v49 = -247274403;

v48 = v24;

v48 = ~(\*((long long \*)&v48));

v49 = 247274402 & (int)v48;

v49 = ~(\*((long long \*)&v49));

v50 = \*((int \*)((char \*)&v49 + 4)) & (int)v49;

v13 = v91 & 0x400 | v92 \* 0x200000 & 0x200000 | v93 \* 0x40000 & 0x40000;

v33 = v21;

v32 = v13;

v27 = v50;

v95 = (int)v27 + 0x100000000;

v96 = \*((char \*)((int)v27 + 140699062697985));

.

.

.

.

} while ((((((((&g\_7ff74db5ff1a)\[\_\_ROR\_\_(\_\_ROL\_\_(\*((char \*)((int)v27 + 140699062698017)) - ((char)v0 - 133 - (char)v102), 5) - 33, 4)\] & -0xff00ff00ff0100) \>\> 8 | (&g\_7ff74db5ff1a)\[\_\_ROR\_\_(\_\_ROL\_\_(\*((char \*)((int)v27 + 140699062698017)) - ((char)v0 - 133 - (char)v102), 5) - 33, 4)\] << 8 & -0xff00ff00ff0100) & -0xffff00010000) \>\> 16 | 0x400e000000000000) & -0x100000000) \>\> 32 | 0x100000000) + 0x7ff60da70000 == 140700137420549);

v50 = 0;

\*((unsigned long \*)&v50\[88\]) = v12;

return (long long)v50\[88\];

}

Listing.3 Pushan’s deobfuscated output (truncated) for the real-world sample [^41].

## D. Claude’s Simplified Output of the Real-world Sample

\[tb\]

[⬇](data:text/plain;base64,I2luY2x1ZGUgPHN0cmluZy5oPg0KI2luY2x1ZGUgPHN0ZGludC5oPg0KDQovLyBFeHRlcm5hbCBQUk5HIGZ1bmN0aW9uIChwcm92aWRlZCBlbHNld2hlcmUgaW4gdGhlIGJpbmFyeSkNCmV4dGVybiB1aW50NjRfdCBwcm5nKHVpbnQ2NF90IHN0YXRlKTsNCg0KbG9uZyBWTV8xKHVuc2lnbmVkIGxvbmcgYTAsIHVuc2lnbmVkIGludCBhMSkgew0KICAgIHVpbnQ4X3QgKmJ1ZiA9ICh1aW50OF90ICopYTA7DQogICAgdWludDMyX3QgY291bnQgPSBhMTsNCg0KICAgIC8vIFBoYXNlIDE6IEZpbGwgYnVmZmVyIHdpdGggbXVsdGlwbGljYXRpdmUgaGFzaCBzZXF1ZW5jZQ0KICAgIHVpbnQzMl90ICpvdXQgPSAodWludDMyX3QgKilidWY7DQogICAgdWludDMyX3QgdmFsID0gY291bnQ7DQogICAgZm9yIChpbnQgaSA9IDA7IGkgPCAxNzsgaSsrKSB7DQogICAgICAgIHZhbCA9IDE0MDM2MzA4NDJ1ICogdmFsIC0gMjsNCiAgICAgICAgLy8gVGhlIE5PVC9BTkQgcGF0dGVybiBjb2xsYXBzZXMgdG86IHZhbCA9IHZhbCAod2l0aCBwb3RlbnRpYWwgdHJ1bmNhdGlvbikNCiAgICAgICAgLy8gZWZmZWN0aXZlbHk6IHZhbCA9ICh1aW50MzJfdCkofih1aW50NjRfdCl2YWwpICYgaGlnaDMyID0+IGp1c3Qga2VlcHMgdmFsDQogICAgICAgIHZhbCA9IHZhbDsgLy8gb2JmdXNjYXRlZCBpZGVudGl0eSBhZnRlciBzaW1wbGlmaWNhdGlvbg0KICAgICAgICAqb3V0KysgPSB2YWw7DQogICAgfQ0KDQogICAgLy8gUGhhc2UgMjogbWVtbW92ZSA2OCBieXRlcyB3aXRoaW4gdGhlIGJ1ZmZlcg0KICAgIG1lbW1vdmUoYnVmICsgNzYsIGJ1ZiwgNjgpOw0KICAgIG1lbW1vdmUoYnVmICsgMTQ0LCBidWYsIDY4KTsNCg0KICAgIC8vIFBoYXNlIDM6IFBSTkcgbG9vcA0KICAgIHVpbnQ2NF90IHN0YXRlID0gKHVpbnQ2NF90KSh1aW50cHRyX3QpYnVmOw0KICAgIHVpbnQ2NF90IHJlc3VsdCA9IDA7DQogICAgZm9yIChpbnQgaSA9IDk7IGkgPiAwOyBpLS0pIHsNCiAgICAgICAgcmVzdWx0ID0gcHJuZyhzdGF0ZSk7DQogICAgfQ0KDQogICAgLy8gU3RvcmUgYW5kIHJldHVybiBmaW5hbCBQUk5HIHJlc3VsdA0KICAgICoodWludDY0X3QgKikoYnVmICsgODgpID0gcmVzdWx0Ow0KICAgIHJldHVybiAobG9uZylyZXN1bHQ7DQp9)

#include <string.h\>

#include <stdint.h\>

// External PRNG function (provided elsewhere in the binary)

extern uint64\_t prng(uint64\_t state);

long VM\_1(unsigned long a0, unsigned int a1) {

uint8\_t \*buf = (uint8\_t \*)a0;

uint32\_t count = a1;

// Phase 1: Fill buffer with multiplicative hash sequence

uint32\_t \*out = (uint32\_t \*)buf;

uint32\_t val = count;

for (int i = 0; i < 17; i++) {

val = 1403630842u \* val - 2;

// The NOT/AND pattern collapses to: val = val (with potential truncation)

// effectively: val = (uint32\_t)(~(uint64\_t)val) & high32 =\> just keeps val

val = val; // obfuscated identity after simplification

\*out++ = val;

}

// Phase 2: memmove 68 bytes within the buffer

memmove(buf + 76, buf, 68);

memmove(buf + 144, buf, 68);

// Phase 3: PRNG loop

uint64\_t state = (uint64\_t)(uintptr\_t)buf;

uint64\_t result = 0;

for (int i = 9; i \> 0; i--) {

result = prng(state);

}

// Store and return final PRNG result

\*(uint64\_t \*)(buf + 88) = result;

return (long)result;

}

Listing.4 Claude’s simplified version of Pushan’s output for the real-world sample.

[^1]: Cecília RO Assis, Rodrigo S Miani, Murillo G Carneiro, and Kil JB Park. A Comparative Analysis of Classifiers in the Recognition of Packed Executables. In IEEE International Conference on Tools with Artificial Intelligence (ICTAI). IEEE, 2019.

[^2]: Musard Balliu, Mads Dam, and Gurvan Le Guernic. Encover: Symbolic Exploration for Information Flow Security. In IEEE Computer Security Foundations Symposium (CSF), 2012.

[^3]: Sebastian Banescu, Christian Collberg, Vijay Ganesh, Zack Newsham, and Alexande r Pretschner. Code Obfuscation against Symbolic Execution Attacks. In Annual Computer Security Applications Conference (ACSAC), 2016.

[^4]: Sébastien Bardin, Robin David, and Jean-Yves Marion. Backward-bounded DSE: Targeting Infeasibility Questions on Obfuscated Codes. In IEEE Symposium on Security and Privacy (S&P). IEEE, 2017.

[^5]: Zion Leonahenahe Basque, Ati Priya Bajaj, Wil Gibbs, Jude O’Kain, Derron Miao, Tiffany Bao, Adam Doupé, Yan Shoshitaishvili, and Ruoyu Wang. Ahoy SAILR! There is no Need to DREAM of C: A Compiler-aware Structuring Algorithm for Binary Decompilation. In USENIX Security Symposium, 2024.

[^6]: Zion Leonahenahe Basque, Samuele Doria, Ananta Soneji, Wil Gibbs, Adam Doupé, Yan Shoshitaishvili, Eleonora Losiouk, Ruoyu Wang, and Simone Aonzo. Decompiling the synergy: An empirical study of human–llm teaming in software reverse engineering. In The Proceedings of the Network and Distributed System Security Symposium (NDSS 26), 2026.

[^7]: Eva-Maria C Behner, Steffen Enders, and Elmar Padilla. Sok: No goto, no cry? the fairy tale of flawless control-flow structuring. In 2025 IEEE 10th European Symposium on Security and Privacy (EuroS&P), pages 411–431. IEEE, 2025.

[^8]: Fabrizio Biondi, Sébastien Josse, Axel Legay, and Thomas Sirvent. Effectiveness of Synthesis in Concolic Deobfuscation. Computers & Security, 70:500–515, 2017.

[^9]: Tim Blazytko, Moritz Contag, Cornelius Aschermann, and Thorsten Holz. Syntia: Synthesizing the Semantics of Obfuscated Code. In USENIX Security Symposium, 2017.

[^10]: Marcus Botacin, Lucas Galante, Paulo de Geus, and André Grégio. RevEngE is a Dish Served Cold: Debug-oriented Malware Decompilation and Reassembly. In Reversing and Offensive-oriented Trends Symposium, 2019.

[^11]: Christian Collberg, Clark Thomborson, and Douglas Low. A Taxonomy of Obfuscating Transformations. Technical report, Department of Computer Science, The University of Auckland, New Zealand, 1997.

[^12]: Christian Collberg, Clark Thomborson, and Douglas Low. Manufacturing Cheap, Resilient, and Stealthy Opaque Constructs. In ACM Symposium on Principles of Programming Languages (POPL), 1998.

[^13]: Kevin Coogan, Gen Lu, and Saumya Debray. Deobfuscation of Virtualization-obfuscated Software: a Semantics-based Approach. In ACM Conference on Computer and Communications Security (CCS), 2011.

[^14]: Robin David, Luigi Coniglio, and Mariano Ceccato. Qsynth–A Program Synthesis based Approach for Binary Code Deobfuscation. In Workshop on Binary Analysis Research (BAR), 2020.

[^15]: Robert BK Dewar. Indirect Threaded Code. Communications of the ACM, 18(6):330–331, 1975.

[^16]: Steffen Enders, Eva-Maria C. Behner, Niklas Bergmann, Mariia Rybalka, Elmar Padilla, Er Xue Hui, Henry Low, and Nicholas Sim. dewolf: Improving decompilation by leveraging user surveys. In Proceedings 2023 Workshop on Binary Analysis Research, BAR 2023. Internet Society, 2023. URL: [http://dx.doi.org/10.14722/bar.2023.23001](http://dx.doi.org/10.14722/bar.2023.23001), [doi:10.14722/bar.2023.23001](https://doi.org/10.14722/bar.2023.23001).

[^17]: Sebastian Eschweiler, Khaled Yakdan, Elmar Gerhards-Padilla, et al. Discovre: Efficient Cross-architecture Identification of Bugs in Binary Code. In Symposium on Network and Distributed System Security (NDSS), 2016.

[^18]: Ninon Eyrolles, Louis Goubin, and Marion Videau. Defeating MBA-based Obfuscation. In International Workshop on Software PROtection (SPRO), 2016.

[^19]: Weijie Feng, Binbin Liu, Dongpeng Xu, Qilong Zheng, and Yun Xu. Neureduce: Reducing Mixed Boolean-Arithmetic Expressions by Recurrent Neural Network. In Conference on Empirical Methods in Natural Language Processing (EMNLP), 2020.

[^20]: Adrien Guinet, Ninon Eyrolles, and Marion Videau. Arybo: Manipulation, Canonicalization and Identification of Mixed Boolean-Arithmetic Symbolic Expressions. In GreHack, 2016.

[^21]: Xin Hu, Tzi-cker Chiueh, and Kang G Shin. Large-scale Malware Indexing using Function-Call Graphs. In ACM Conference on Computer and Communications Security (CCS), 2009.

[^22]: Kaspersky. The number of the year: Kaspersky detected half a million malicious files daily in 2025, 2026. [https://www.kaspersky.com/about/press-releases/the-number-of-the-year-kaspersky-detected-half-a-million-malicious-files-daily-in-2025](https://www.kaspersky.com/about/press-releases/the-number-of-the-year-kaspersky-detected-half-a-million-malicious-files-daily-in-2025).

[^23]: Johannes Kinder. Towards Static Analysis of Virtualization-obfuscated Binaries. In Working Conference on Reverse Engineering (WCRE). IEEE, 2012.

[^24]: Patrick Kochberger, Sebastian Schrittwieser, Stefan Schweighofer, Peter Kieseberg, and Edgar Weippl. Sok: Automatic Deobfuscation of Virtualization-protected Applications. In International Conference on Availability, Reliability and Security (ARES), 2021.

[^25]: Jaehyung Lee and Woosuk Lee. Simplifying Mixed Boolean-Arithmetic Obfuscation by Program Synthesis and Term Rewriting. In ACM Conference on Computer and Communications Security (CCS), 2023.

[^26]: Mingyue Liang, Zhoujun Li, Qiang Zeng, and Zhejun Fang. Deobfuscation of Virtualization-obfuscated Code through Symbolic Execution and Compilation Optimization. In International Conference on Information and Communications Security (ICICS). Springer, 2018.

[^27]: Binbin Liu, Junfu Shen, Jiang Ming, Qilong Zheng, Jing Li, and Dongpeng Xu. MBA-Blast: Unveiling and Simplifying Mixed Boolean-Arithmetic Obfuscation. In USENIX Security Symposium, 2021.

[^28]: Alessandro Mantovani, Simone Aonzo, Yanick Fratantonio, and Davide Balzarotti. Re-mind: a first look inside the mind of a reverse engineer. In 31st USENIX Security Symposium (USENIX Security 22), pages 2727–2745, 2022.

[^29]: Grégoire Menguy, Sébastien Bardin, Richard Bonichon, and Cauim de Souza Lima. Search-based Local Black-box Deobfuscation: Understand, Improve and Mitigate. In ACM Conference on Computer and Communications Security (CCS), 2021.

[^30]: Mathilde Ollivier, Sébastien Bardin, Richard Bonichon, and Jean-Yves Marion. How to Kill Symbolic Deobfuscation for Free (or: Unleashing the Potential of Path-oriented Protections). In Annual Computer Security Applications Conference (ACSAC), 2019.

[^31]: Oreans Technologies, 2024. [https://www.oreans.com/Themida.php](https://www.oreans.com/Themida.php).

[^32]: Ian Piumarta and Fabio Riccardi. Optimizing Direct Threaded Code by Selective Inlining. In ACM SIGPLAN Conference on Programming Language Design and Implementation (PLDI), 1998.

[^33]: Benjamin Reichenwallner and Peter Meerwald-Stadler. Efficient Deobfuscation of Linear Mixed Boolean-Arithmetic Expressions. In ACM Workshop on Research on Offensive and Defensive Techniques in the Context of Man At The End (MATE) Attacks, 2022.

[^34]: Benjamin Reichenwallner and Peter Meerwald-Stadler. Simplification of General Mixed Boolean-Arithmetic Expressions: GAMBA. In IEEE European Symposium on Security and Privacy Workshops (EuroS&PW), 2023.

[^35]: Jonathan Salwan, Sébastien Bardin, and Marie-Laure Potet. Symbolic Deobfuscation: From Virtualized Code Back to the Original. In International Conference on Detection of Intrusions and Malware, and Vulnerability Assessment (DIMVA), pages 372–392. Springer, 2018.

[^36]: Moritz Schloegel, Tim Blazytko, Moritz Contag, Cornelius Aschermann, Julius Basler, Thorsten Holz, and Ali Abbasi. Loki: Hardening Code Obfuscation against Automated Attacks. In USENIX Security Symposium, 2022.

[^37]: Toshiki Seto, Akito Monden, Zeynep Yücel, and Yuichiro Kanzaki. On Preventing Symbolic Execution Attacks by Low Cost Obfuscation. In IEEE/ACIS International Conference on Software Engineering, Artificial Intelligence, Networking and Parallel/Distributed Computing (SNPD). IEEE, 2019.

[^38]: Monirul Sharif, Andrea Lanzi, Jonathon Giffin, and Wenke Lee. Automatic Reverse Engineering of Malware Emulators. In IEEE Symposium on Security and Privacy (S&P). IEEE, 2009.

[^39]: Yan Shoshitaishvili, Ruoyu Wang, Christopher Salls, Nick Stephens, Mario Polino, Andrew Dutcher, John Grosen, Siji Feng, Christophe Hauser, Christopher Kruegel, et al. SoK:(State of) the Art of War: Offensive Techniques in Binary Analysis. In IEEE Symposium on Security and Privacy (S&P). IEEE, 2016.

[^40]: Zhanyong Tang, Kaiyuan Kuang, Lei Wang, Chao Xue, Xiaoqing Gong, Xiaojiang Chen, Dingyi Fang, Jie Liu, and Zheng Wang. Seead: A Semantic-based Approach for Automatic Binary Code De-obfuscation. In IEEE Trustcom/BigDataSE/ICESS. IEEE, 2017.

[^41]: VirusTotal, 2026. [https://www.virustotal.com/gui/file/47ae162c83cfc2302f795774aa19fb5090817362781643224157e285244eb295](https://www.virustotal.com/gui/file/47ae162c83cfc2302f795774aa19fb5090817362781643224157e285244eb295).

[^42]: VMProtect Software. VMProtect Software, 2024. [https://vmpsoft.com](https://vmpsoft.com/).

[^43]: Daniel Votipka, Mary Nicole Punzalan, Seth M Rabin, Yla Tausczik, and Michelle L Mazurek. An investigation of online reverse engineering community discussions in the context of ghidra. In 2021 IEEE European Symposium on Security and Privacy (EuroS&P), pages 1–20. IEEE, 2021.

[^44]: Daniel Votipka, Seth Rabin, Kristopher Micinski, Jeffrey S Foster, and Michelle L Mazurek. An observational investigation of reverse $\{$ Engineers’ $\}$ processes. In 29th USENIX Security Symposium (USENIX Security 20), pages 1875–1892, 2020.

[^45]: Zhi Wang, Jiang Ming, Chunfu Jia, and Debin Gao. Linear Obfuscation to Combat Symbolic Execution. In European Symposium on Research in Computer Security (ESORICS). Springer, 2011.

[^46]: Dongpeng Xu, Jiang Ming, Yu Fu, and Dinghao Wu. VMHunt: A Verifiable Approach to Partially-virtualized Binary Code Simplification. In ACM Conference on Computer and Communications Security (CCS), 2018.

[^47]: Hui Xu, Yangfan Zhou, Yu Kang, Fengzhi Tu, and Michael Lyu. Manufacturing Resilient Bi-Opaque Predicates against Symbolic Execution. In Conference on Dependable Systems and Networks (DSN), 2018.

[^48]: Babak Yadegari, Brian Johannesmeyer, Ben Whitely, and Saumya Debray. A Generic Approach to Automatic Deobfuscation of Executable Code. In IEEE Symposium on Security and Privacy (S&P). IEEE, 2015.

[^49]: Khaled Yakdan, Sergej Dechand, Elmar Gerhards-Padilla, and Matthew Smith. Helping Johnny to Analyze Malware: A Usability-optimized Decompiler and Malware Analysis User Study. In IEEE Symposium on Security and Privacy (S&P). IEEE, 2016.

[^50]: Naiqian Zhang, Dongpeng Xu, Jiang Ming, Jun Xu, and Qiaoyan Yu. Inspecting Virtual Machine Diversification Inside Virtualization Obfuscation. In IEEE Symposium on Security and Privacy (S&P), 2025.

[^51]: Yongxin Zhou, Alec Main, Yuan X Gu, and Harold Johnson. Information Hiding in Software with Mixed Boolean-Arithmetic Transforms. In International Workshop on Information Security Applications. Springer, 2007.