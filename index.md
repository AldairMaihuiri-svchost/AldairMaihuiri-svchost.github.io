---
title: "Aldair Maihuiri — Security Research"
description: "Malware analysis and red team development by Gino Aldair Maihuiri Romero. YARA rules, LockBit analysis, loader/infostealer/clipper analysis, ransomware simulation, crackme writeups, and red team tooling."
author: Aldair Maihuiri
---
# Aldair Maihuiri — Security Research

Systems Engineering student (3rd cycle).

Malware analysis and red team development at the assembly and debugger level, on Linux ELF and Windows PE binaries.

📂 [Source code and YARA rules on GitHub](https://github.com/AldairMaihuiri-svchost/AldairMaihuiri-svchost.github.io)

Here is what that looks like in practice:

- Wrote 5 YARA detection rules covering LockBit, SolarisLoader, observed downloaders, and an x64 loader with infostealer and cryptocurrency clipper, published on YARAhub
- Reversed LockBit's string obfuscation mechanism (affine cipher, stack strings, dynamic API resolution) — documented in a public writeup
- Statically analyzed a configurable x64 loader that reconstructs and injects an embedded DLL, with anti-VM checks, HTTPS C2 configuration, a cryptocurrency clipper, screen capture, and second-stage execution
- Series of modules on Red Teaming — Ransomware Simulation and Mitigation: reproducing architecture, cryptographic schemes (AES-256, ChaCha20-Poly1305, RSA-OAEP, Multi-Master ECDH), key generation and custody, file enumeration, concurrency and I/O on Windows, and metadata formats, to drive defensive engineering and mitigation strategies
- Documented code obfuscation techniques through the official Ghidra training materials
- Built 5 original crackmes targeting specific obfuscation techniques, solved and documented each one with full assembly analysis in English and Spanish
- Developed red team tooling

Systems engineering student · Lima, Peru

---
## 🔍 YARA Rules

Detection rules I write from my malware analysis work, published on YARAhub (abuse.ch). They are live on YARAify in *hunting* mode.

| Rule | Published (UTC) | Matches |
|---|---|---|
| `SH_Downloader_Vcimanagement_Observed` | 202x-10-03 | 0 |
| `SH_Downloader_MultiArch_Svc_Hunt` | 202x-10-03 | 0 |
| `SolarisLoader_concatenated_api_dynamic_resolution` | 202x-10-03 | 0 |
| `LockBit_mw_resolve_api_call_pattern` | 202x-10-03 | 1 |
| `ConfigurableLoaderInfostealer_custom_decoder_embedded_dll` | 202x-10-04 | 0 |

### Details

- **SolarisLoader**: detects the loader through a table of concatenated API names and a hardcoded identifier. The binary has no import table and resolves its APIs at runtime.
- **LockBit**: detects the dynamic API resolution pattern from the LockBit sample I analyzed.
- **SH_Downloader_***: rules for observed downloaders (the `Vcimanagement` variant and a multi-architecture variant).
- **ConfigurableLoaderInfostealer**: detects the outer loader by combining two sample-specific artifacts: the custom 64-symbol decoder alphabet and a static fragment of the encoded internal DLL blob. It is a signature for this loader, not a generic infostealer rule.
---
## Malware analysis
- **[LockBit Ransomware — Static Reverse Engineering Writeup](/lockbit-ransomware-analysis/)**

  The technical research, reverse engineering, analysis, reasoning, scripting, and writing were carried out entirely by me. Large Language Models (LLMs) were used solely to correct spelling and grammatical errors.
  I hope you enjoy reading it as much as I enjoyed writing it.

  Greetings,
  Sv-chost

- **[Configurable Loader, Infostealer and Cryptocurrency Clipper — Static Reverse Engineering Writeup](analisisdemalwarestealerloader/writeup_loader_infostealer_en)**
  ([versión en español](analisisdemalwarestealerloader/writeup_loader_infostealer))
  Static reverse engineering of a configurable x64 loader that decodes, decompresses, and reconstructs an embedded DLL and injects it into a remote process. The DLL       performs anti-VM checks, receives HTTPS C2 configuration (obfuscated with XOR `0xA2`), and, depending on that configuration, enables a cryptocurrency clipper, screen    capture, browser and application data collection, registry queries, and second-stage execution. Not confirmed as a coinminer. Includes the companion YARA rule.

  The write-up was prepared from malware-analysis notes and reviewed technical evidence. A Large Language Model assisted with translation, structure, and copy-editing;    the author reviewed the final text and is responsible for its publication.

- **[LockBit String Deobfuscation — Affine Cipher DLL Loading](lockbit-string-deobfuscation)**
  Public teaser: how LockBit encrypts DLL names on the stack to evade IAT detection, the affine cipher reversed step by step, and a Python script replicating the decryption. The decryption scripts, full function analysis, and the complete 11-block breakdown are reserved for the write-up *LockBit Ransomware — Complete Static and Dynamic Analysis*.
---
## Red team tools and sources
Red team tooling and source code from my work, available in the repository:

- 🔧 **[Red teamer tools](https://github.com/AldairMaihuiri-svchost/AldairMaihuiri-svchost.github.io/tree/main/Red%20teamer%20tools)**
  Source code and red team tools, alongside the site material.
- 📂 [Full repository — AldairMaihuiri-svchost.github.io](https://github.com/AldairMaihuiri-svchost/AldairMaihuiri-svchost.github.io/tree/main)
---
(… the rest of the index stays the same: Red Teaming — Ransomware Simulation and Mitigation, Cryptography research, Ghidra: obfuscated binaries, Crackme writeups, Tooling, Detection engineering, Elsewhere)
---
## Red Teaming — Ransomware Simulation and Mitigation
A series focused on reproducing real-world ransomware techniques and tactics in a
controlled environment, aimed at strengthening detection, response, and mitigation
strategies from the defensive side.

- **[Module 1: Introduction](Ransomware/Ransomware-Modulo1-en)**
  ([versión en español](Ransomware/Ransomware-Modulo1))
  How ransomware is built — fundamentals and basic architecture before moving into
  simulation and mitigation.

- **[Module 2: Cryptographic Algorithms](Ransomware/Ransomware-Modulo2-en)**
  ([versión en español](Ransomware/Ransomware-Modulo2))
  The cryptographic toolkit behind modern encryption schemes — AES-256, ChaCha20-Poly1305, 
  RSA-OAEP, ECDH (Multi-Master Pattern), HKDF, and CSPRNG implementations.

- **[Module 3: Key Generation](Ransomware/Ransomware-Modulo3-en)**
  ([versión en español](Ransomware/Ransomware-Modulo3))
  Key hierarchies, CSPRNG, per-file and per-session ECDH, HKDF, domain separation,
  nonces, public-key formats, and the cryptographic key life cycle.

- **[Module 4: File Enumeration and Selection](Ransomware/Ransomware-Modulo4-en)**
  ([versión en español](Ransomware/Ransomware-Modulo4))
  How file traversal works in Windows: roots, selection rules, error handling, coverage metrics, and hands-on labs with        temporary test data.
  
- **[Module 5: Concurrency and I/O in Windows](Ransomware/Ransomware-Modulo5-en)**  
  ([versión en español](Ransomware/Ransomware-Modulo5))  
  Threads, bounded queues, synchronization, synchronous and overlapped I/O, memory-mapped files, and hands-on labs for         Windows 11.

- **[Module 6: Concurrent Processing Pipeline](Ransomware/Ransomware-Modulo6-en)**  
  ([versión en español](Ransomware/Ransomware-Modulo6))  
  How enumeration and processing connect through bounded queues, controlled failures, shutdown, recovery, and reproducible     Windows 11 labs.

- **[Module 7: Key Custody and Recovery](Ransomware/Ransomware-Modulo7-en)**  
  ([versión en español](Ransomware/Ransomware-Modulo7))  
  How cryptographic material is held, exposed, and reconstructed: key lifetimes, metadata, recovery failures, and a            reproducible lab with synthetic data.

- **[Module 8: Ransom Notes and Coercive Communication](Ransomware/Ransomware-Modulo8-en)**
  ([versión en español](Ransomware/Ransomware-Modulo8))
  How ransom messages present claims, identifiers, deadlines, and threats — with a practical method for separating             psychological pressure from verified evidence.

- **[Module 9: Metadata Formats and Recovery](Ransomware/Ransomware-Modulo9-en)**
  ([versión en español](Ransomware/Ransomware-Modulo9))
  Footer design, versioning, parsing, integrity checks, and interrupted writes, explored through a reproducible synthetic-     format lab.

- **[Module 10: Logical Fragmentation and Asynchronous I/O](Ransomware/Ransomware-Modulo10-en)**
  ([versión en español](Ransomware/Ransomware-Modulo10))
  Partial and intermittent processing as an analytical model — byte-range selection, planned versus completed coverage,        IOCP, failures, and read-only Windows 11 experiments.
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
All challenge binaries: [github.com/AldairMaihuiri-svchost/Crackmes](https://github.com/AldairMaihuiri-svchost/Crackmes)
---
## Tooling
Custom ptrace instrumentation, binary patchers, and analysis scripts built alongside
the crackme research. Each tool targets a specific low-level technique.
- **[cm2 ptrace patcher — Zero Flag Hijacking](https://github.com/AldairMaihuiri-svchost/Crackmes/tree/main/Tooling/cm2_patcher)**
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
