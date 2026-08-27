---
title: "Aldair Maihuiri — Security Research"
description: "Binary reverse engineering, malware analysis and exploit development by Gino Aldair Maihuiri Romero. LockBit analysis, crackme writeups, YARA rules, ptrace tooling in Rust, and three technical books in progress on malware analysis and code obfuscation."
author: Aldair Maihuiri
---
# Aldair Maihuiri — Security Research
**Gino Aldair Maihuiri Romero**
My specialization is binary reverse engineering, malware analysis,
and exploit development — at the assembly and debugger level,
on Linux ELF and Windows PE binaries.
Here is what that looks like in practice:
- Reversed LockBit's string obfuscation mechanism (affine cipher, stack strings,
  dynamic API resolution) — documented in a public writeup and a book in progress
- Wrote YARA detection rules for LockBit and SolarisLoader, published on YARAhub
- Built 5 original crackmes targeting specific obfuscation techniques, solved and
  documented each one with full assembly analysis in English and Spanish
- Implemented ptrace tooling in Rust: Zero Flag hijacking and SSP bypass via
  stack canary manipulation
- Working toward OSED (EXP-301) — building Linux exploit development proficiency
  from a Windows RE background
Systems engineering student · Lima, Peru
---
## Books in progress
Technical books written alongside active research. Reserved — not yet published.
**LockBit Ransomware — Complete Static and Dynamic Analysis**
Full dissection of a LockBit sample: string obfuscation via affine cipher,
dynamic API resolution, unreachable code blocks introduced by PGO, anomalous
constructs in the decryption routine, and 54 inaccessible blocks identified
across the binary. The decryption scripts, full function analysis, and complete
11-block breakdown are reserved for this book.
**The Art of Obfuscation**
A technical study of code obfuscation techniques — from stack strings and XOR
encoding to dynamic API resolution and anti-debug primitives. Grounded in
real malware samples and purpose-built crackmes designed to isolate each technique.
**[Reserved]**
Third book in progress. Title and subject withheld pending publication.
---
## Malware analysis
- **[LockBit String Deobfuscation — Affine Cipher DLL Loading](lockbit-string-deobfuscation)**
  Public teaser: how LockBit encrypts DLL names on the stack to evade IAT
  detection, the affine cipher reversed step by step, and a Python script
  replicating the decryption. The decryption scripts, full function analysis,
  and the complete 11-block breakdown are reserved for the book
  *LockBit Ransomware — Complete Static and Dynamic Analysis*.
---
## Cryptography research
- **[DES-M — Structural Modification of DES S-boxes: Reference Implementation, Differential Analysis, and Preliminary Study of Language Model Behavior](DES-M/des-m-en)**
  ([versión en español](DES-M/des-m))
  Ground-up DES implementation in Python, verified against FIPS 46-3 and pycryptodome.
  Construction of DES-M, a custom S-box variant, with full differential analysis (DDT)
  and Algebraic Normal Form of all eight original S-boxes. Includes an empirical
  evaluation of four LLMs (ChatGPT, Gemini, DeepSeek, Qwen) under black-box, gray-box,
  and white-box conditions — with a methodological finding on model confabulation
  during cryptographic verification tasks.
---
## Ghidra: obfuscated binaries
A training series distinct from the crackmes below: these are already-obfuscated
Windows PE32+ binaries, solved through pure static analysis in Ghidra — no execution
during analysis, only cross-references, the decompiler, and the raw memory view.
Each level isolates one obfuscation technique, building on the ones before it.
- **[Level 1 — String Encryption](Ghidra-obfuscated/ghidra-obfuscated-level1-en)**
  ([versión en español](Ghidra-obfuscated/ghidra-obfuscated-level1))
  A PE32+ crackme that hides its password and result messages from a surface-level
  strings scan: the prompt is assembled byte by byte in memory instead of referenced
  as a literal, the real password is copied through a chain of heap buffers instead
  of compared directly, and both output messages are single-byte XOR–encrypted.
  Solved end to end by following cross-references from a known CRT import (`strcmp`)
  to the validation logic, then decoding the encrypted buffers in Python.
- **[Level 2 — Control Flow Obfuscation](Ghidra-obfuscated/ghidra-obfuscated-level2-en)**
  ([versión en español](Ghidra-obfuscated/ghidra-obfuscated-level2))
  A PE32+ crackme that reuses the same opaque predicate — a constant, always-true
  condition with the algebraic form of the Pythagorean theorem — as a guard for
  three separate dead branches, each one a copy of the real validation logic with
  the result inverted. The password itself isn't a fixed string but the solution
  to a modular equation (a weighted sum of the input reduced to a single byte),
  which has no unique answer, so solving it means generating a valid input and
  confirming it against the real binary rather than extracting an embedded literal.
- **[Level 3 — Indirection](Ghidra-obfuscated/ghidra-obfuscated-level3-en)**
  ([versión en español](Ghidra-obfuscated/ghidra-obfuscated-level3))
  A PE32+ crackme that splits password validation across two chained helper
  functions joined by an AND — a length check and a content check kept
  completely separate — and builds the reference password byte by byte in
  memory at runtime, including a 32-bit little-endian integer, instead of
  storing it as a literal string anywhere in the binary.
- **[Level 4 — Virtual Tables and Hash Validation](Ghidra-obfuscated/ghidra-obfuscated-level4-en)**
  ([versión en español](Ghidra-obfuscated/ghidra-obfuscated-level4))
  A PE32+ crackme compiled in C++ that dispatches validation through a factory
  table, builds objects with their own vtable at runtime, and validates the
  password by comparing its 32-bit FNV-1a hash against a constant — with a
  second object, reachable through the same table, whose only method always
  returns false. Solved with an SMT solver (Z3) once the hash algorithm and
  its constants were recognized.
- **[Level 5 — The Final Level](Ghidra-obfuscated/ghidra-obfuscated-level5-en)**
  ([versión en español](Ghidra-obfuscated/ghidra-obfuscated-level5))
  A synthesis level combining techniques from the previous four — dynamic
  password construction, an opaque predicate, vtable dispatch, a hand-rolled
  comparison avoiding `strcmp` — with two new elements: runtime code
  relocation to executable memory (with no real effect against static
  analysis) and a debugger check that genuinely blocks the success path.
- **[Level 6 — State Machine and Binary Payload Delivery](Ghidra-obfuscated/ghidra-obfuscated-level6-en)**
  ([versión en español](Ghidra-obfuscated/ghidra-obfuscated-level6))
  A PE32+ crackme that validates its password through a custom state machine
  of bit rotations and hash-like constants, fed by a stack buffer overflow
  that spreads the ten input bytes across separately named local variables.
  Breaking the algorithm with Z3 was only half the problem: the solution key
  contains non-printable bytes that neither a keyboard nor a naive shell pipe
  can deliver intact to a Windows binary running under Wine.
- **[Level 7 — Mixed Boolean-Arithmetic and Dynamic Shellcode](Ghidra-obfuscated/ghidra-obfuscated-level7-en)**
  ([versión en español](Ghidra-obfuscated/ghidra-obfuscated-level7))
  A PE32+ crackme that hides a standard FNV-1a hash behind mixed
  boolean-arithmetic identities (OR/AND standing in for XOR, XOR plus carry
  standing in for addition), and hides the comparison's target value inside a
  shellcode fragment the binary itself assembles and decrypts into executable
  memory before invoking it. Solved with a meet-in-the-middle search instead
  of an SMT solver, after catching two self-made errors — a corrupted byte
  reconstruction and a miscalculated hex constant — by verifying results
  against the real binary rather than trusting the math alone.
---
## Crackme writeups
| Crackme | Technique demonstrated |
|---|---|
| CM01 | Dynamic analysis with GDB · calling convention · x86-64 |
| CM02 | Disassembly · integer comparison · live patching via ptrace in Rust |
| CM03 | XOR obfuscation · instruction stream encoding |
| CM04 | Stack string construction · movb per character · same primitive as LockBit |
| CM05 | Custom comparison loop · transformation · stack canary · SSP bypass via ptrace |
- **[Crackme 01 — Hardcoded strcmp with GDB](crackmes/cm1-strcmp)**
  ([versión en español](crackmes/cm1-strcmp-es))
- **[Crackme 02 — Numeric Serial: Deduction by Disassembly and Live Patching with Rust](crackmes/cm2-numeric)**
- **[Crackme 03 — XOR Stack Strings: Ciphertext Embedded in the Instruction Stream](crackmes/cm3-xor)**
  ([versión en español](crackmes/cm3-xor-es))
- **[Crackme 04 — Pure Stack Strings: Ten movb Instructions That strings Cannot See](crackmes/cm4-stackstring)**
  ([versión en español](crackmes/cm4-stackstring-es))
- **[Crackme 05 — Transform Before Compare: The First Crackme Without strcmp](crackmes/cm5-transform)**
  ([versión en español](crackmes/cm5-transform-es))
All challenge binaries: [github.com/GinoMaihuiri/Crackmes](https://github.com/AldairMaihuiri-svchost/Crackmes)
---
## Tooling
Custom ptrace instrumentation, binary patchers, and analysis scripts built alongside
the crackme research. Each tool targets a specific low-level technique.
- **[cm2 ptrace patcher — Zero Flag Hijacking](https://github.com/GinoMaihuiri/Crackmes/tree/main/Tooling/cm2_patcher)**
  Rust process that forces "Serial válido" with any input by manipulating EFLAGS
  directly via ptrace — CPU state manipulation, no binary modification.
- **[cm5 Stack Canary Corruption via ptrace](https://github.com/AldairMaihuiri-svchost/Crackmes/blob/main/Tooling/cm5_corrupting_stack_canary/cm5_Stack%20Canary%20Corruption%20via%20ptrace.rs)**
  Corrupts the GCC stack canary after it is stored. Demonstrates SSP detection behavior.
- **[cm5 Stack Canary Bypass via ptrace](https://github.com/AldairMaihuiri-svchost/Crackmes/blob/main/Tooling/cm5_corrupting_stack_canary/Stack%20Canary%20Bypass%20via%20ptrace.rs)**
  Restores the canary before the check fires — stack and %rdx. SSP bypassed,
  process exits cleanly.
👉 [All tooling](https://github.com/AldairMaihuiri-svchost/Crackmes/tree/main/Tooling)
---
## Detection engineering
- YARA rules published on [YARAhub](https://yaraify.abuse.ch/user/51747/)
---
## Elsewhere
[GitHub](https://github.com/AldairMaihuiri-svchost) ·
[LinkedIn](https://www.linkedin.com/in/AldairMaihuiri) ·
[X](https://x.com/AldairMaihuiri) ·
[YARAify](https://yaraify.abuse.ch/user/51747/)
---
© 2026 Gino Aldair Maihuiri Romero
