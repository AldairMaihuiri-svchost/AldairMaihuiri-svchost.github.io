---
title: "Aldair Maihuiri — Security Research"
description: "Malware analysis, reverse engineering and detection engineering by Gino Aldair Maihuiri Romero. 45 YARA rules, LockBit and loader/infostealer analysis, Ghidra and crackme writeups, and Rust tooling."
author: Aldair Maihuiri
---

# Aldair Maihuiri (Sv-chost)

**Malware analysis · Reverse engineering · Detection engineering**

Systems Engineering student (3rd cycle) · Lima, Peru · Member of the **Carnival Threads** research group

**Looking for:** remote junior roles in malware analysis, reverse engineering, detection engineering, or low-level programming (Rust / Python).
**Contact:** [axlaldair6@gmail.com](mailto:axlaldair6@gmail.com) · [LinkedIn](https://www.linkedin.com/in/AldairMaihuiri) · [GitHub](https://github.com/AldairMaihuiri-svchost)
**Languages:** Spanish (native) · English (technical reading; writing with translation tools)

I analyze Windows PE and Linux ELF malware at the assembly and debugger level, then turn the findings into public detections and technical writeups, in English and Spanish.

---

## At a glance

- **45 YARA rules** published on [YARAhub](https://yaraify.abuse.ch/user/51747/), covering AgentTesla, XWorm, Formbook, MassLogger, PhantomStealer, Cobalt Strike PowerShell loaders, PHP webshells, LockBit, SolarisLoader, and ATM malware
- Rules with **real-world matches** in YARAify scans, including AgentTesla PowerShell loaders, PurgeRoster JScript loaders, and LockBit
- Static reverse-engineering writeups on **LockBit** and on an **x64 loader with infostealer and cryptocurrency clipper**
- **7 obfuscated binaries** solved through pure static analysis in Ghidra
- **5 original crackmes** with full assembly analysis, plus custom **Rust ptrace tooling**
- **10-module series** on ransomware simulation and mitigation, written for defensive engineering

| Area | Tools and skills |
|---|---|
| Detection engineering | YARA |
| Reverse engineering | Ghidra, x64dbg, GDB, x86-64 assembly |
| Programming | Python, Rust |
| Analysis automation | Z3 |
| Targets | Windows PE, Linux ELF |

---

## Featured work

- **[LockBit string deobfuscation and static analysis](lockbit-ransomware-analysis/)**: affine cipher, stack strings, and dynamic API resolution, reversed and documented step by step.
- **[Configurable loader, infostealer and clipper](analisisdemalwarestealerloader/writeup_loader_infostealer_en)**: x64 loader that reconstructs and injects an embedded DLL, with anti-VM checks, HTTPS C2 configuration, and a companion YARA rule.
- **[45 YARA rules on YARAhub](https://yaraify.abuse.ch/user/51747/)**: detections grouped by malware family, several already matching real samples.

---

## Malware analysis

- **[LockBit Ransomware — Static Reverse Engineering Writeup](lockbit-ransomware-analysis/)**

  The technical research, reverse engineering, analysis, reasoning, scripting, and writing were carried out entirely by me. Large Language Models (LLMs) were used solely to correct spelling and grammatical errors.

- **[Configurable Loader, Infostealer and Cryptocurrency Clipper — Static Reverse Engineering Writeup](analisisdemalwarestealerloader/writeup_loader_infostealer_en)** ([versión en español](analisisdemalwarestealerloader/writeup_loader_infostealer))

  Static reverse engineering of a configurable x64 loader that decodes, decompresses, and reconstructs an embedded DLL and injects it into a remote process. The DLL performs anti-VM checks, receives HTTPS C2 configuration (obfuscated with XOR `0xA2`), and, depending on that configuration, enables a cryptocurrency clipper, screen capture, browser and application data collection, registry queries, and second-stage execution. Not confirmed as a coinminer. Includes the companion YARA rule.

  Prepared from my malware-analysis notes and reviewed technical evidence. A Large Language Model assisted with translation, structure, and copy-editing; I reviewed the final text and am responsible for its publication.

- **[LockBit String Deobfuscation — Affine Cipher DLL Loading](lockbit-string-deobfuscation)**

  Public teaser: how LockBit encrypts DLL names on the stack to evade IAT detection, the affine cipher reversed step by step, and a Python script replicating the decryption. The decryption scripts, full function analysis, and the complete 11-block breakdown are reserved for the in-progress writeup *LockBit Ransomware — Complete Static and Dynamic Analysis*.

---

## Red team tools and sources

Source code and tooling from my work, available in the repository:

- **[Red teamer tools](https://github.com/AldairMaihuiri-svchost/AldairMaihuiri-svchost.github.io/tree/main/Red%20teamer%20tools)**
- [Full repository — AldairMaihuiri-svchost.github.io](https://github.com/AldairMaihuiri-svchost/AldairMaihuiri-svchost.github.io/tree/main)

---

## Detection engineering

45 YARA rules published on [YARAhub](https://yaraify.abuse.ch/user/51747/) (all in Hunting status), grouped by what they detect.

| Group | Rules | Rule names |
|---|---|---|
| Loaders and ransomware (PE) | 6 | `LockBit_mw_resolve_api_call_pattern`, `SolarisLoader_concatenated_api_dynamic_resolution`, `ConfigurableLoaderInfostealer_custom_decoder_embedded_dll`, `SH_Downloader_Vcimanagement_Observed`, `SH_Downloader_MultiArch_Svc_Hunt`, `RegPhantom_Obfuscated_Kernel_Manual_PE_Loader` |
| PowerShell and Batch | 16 | AgentTesla loaders (`AgentTesla_PowerShell_AESManaged_InMemory_Loader`, `AgentTesla_PS_SecureLoader_Config_84de969f`, `AgentTesla_PowerShell_Base64_AES_Wrapper`, `AgentTesla_Loader_PowerShell_AES`), Cobalt Strike PowerShell loaders (`CobaltStrike_PS_AMSI_Reflection_Obfuscated`, `CobaltStrike_PS_Decimal_Base64_XOR_Loader`, `CobaltStrike_PS_Obfuscated_Memory_PE_Loader`), Batch/PowerShell hybrids (`Hybrid_BatchPS_Hex59_Strict_a85fc7e`, `BatchPS_SelfRead_HexScriptBlock_a85fc7e`, `BatchPS_Base64_XOR_GZip_Stage_a85fc7e`), and stagers and crypters (`PS_Adobe_AES_Staged_Downloader_b3fc3415`, `PS_XOR_Embedded_DotNet_Loader_1590912d`, `PS_Arithmetic_AMSI_XOR_IEX_Stager`, `BetterXencrypt_PowerShell_Crypter_Source`, `PS_x_txt_Repeating_XOR_Decoder_42e79f3e`, `PS_TLS12_Randomized_URL_Downloader_Fragment_42db2fb8`) |
| JScript, VBScript and Node.js | 14 | `JS_WSH_SRWDNQEVXCMRPCBL_Strict_Variant`, `JS_WSH_Unicode2603_COM_Dropper_cacb33f8`, `JS_WSH_OMCABJPEHNLUOYSR_Strict_Variant`, `JS_WSH_Unicode2600_Hidden_Execution_8315f56a`, `JS_ToyCipher_Base161_Crypto_Stager_37200092`, `JS_PurgeRoster_Scheduled_Task_Persistence_37200092`, `JS_WSH_PurgeRoster_PowerShell_Loader_37200092`, `XWorm_Dropper_VBScript_AES`, `JS_Loader_Downloader_flocmaterials_powershell`, `Chainscript_NodeJS_RemoteShell_Backdoor`, `Formbook_Dropper_JScript_PowerShell_WMI`, `Spy_Loader_JScript_Registry_Fileless`, `PhantomStealer_Dropper_JScript_LuaJIT_Loader`, `MassLogger_Dropper_JScript_LuaJIT_Loader` |
| PHP webshells | 6 | `PHP_SelfReading_Zlib_Eval_Hunting`, `PHP_E75_Packed_Strict`, `PHP_WSO_MultiCapability_Decoded`, `PHP_SelfExtracting_Marker_Zlib_Webshell_Strict`, `PHP_SelfExtracting_Marker_Zlib_Webshell_Hunting`, `PHP_Obfuscated_Multicapability_Webshell_Decoded` |
| ATM and smartcards | 3 | `ATM_CSCCNG_Dispenser_NoToken`, `ATM_Associated_Realtek_Audio_Driver2_Watchdog`, `SmartCard_AllInOne_GlobalPlatform_EMV_Tool` |

Highlighted rules:

- **SolarisLoader**: detects the loader through a table of concatenated API names and a hardcoded identifier. The binary has no import table and resolves its APIs at runtime.
- **LockBit**: detects the dynamic API resolution pattern from the LockBit sample I analyzed.
- **`SH_Downloader_*`**: rules for observed downloaders (the `Vcimanagement` variant and a multi-architecture variant).
- **ConfigurableLoaderInfostealer**: detects the outer loader by combining two sample-specific artifacts: the custom 64-symbol decoder alphabet and a static fragment of the encoded internal DLL blob. It is a signature for this loader, not a generic infostealer rule.

---

## Ghidra: obfuscated binaries

A training series distinct from the crackmes below: these are already-obfuscated Windows PE32+ binaries, solved through pure static analysis in Ghidra — no execution during analysis, only cross-references, the decompiler, and the raw memory view. Each level isolates one obfuscation technique, building on the ones before it.

- **[Level 1 — String Encryption](Ghidra-obfuscated/ghidra-obfuscated-level1-en)** ([versión en español](Ghidra-obfuscated/ghidra-obfuscated-level1))

  A PE32+ crackme that hides its password and result messages from a surface-level strings scan: the prompt is assembled byte by byte in memory instead of referenced as a literal, the real password is copied through a chain of heap buffers instead of compared directly, and both output messages are single-byte XOR-encrypted. Solved end to end by following cross-references from a known CRT import (`strcmp`) to the validation logic, then decoding the encrypted buffers in Python.

- **[Level 2 — Control Flow Obfuscation](Ghidra-obfuscated/ghidra-obfuscated-level2-en)** ([versión en español](Ghidra-obfuscated/ghidra-obfuscated-level2))

  A PE32+ crackme that reuses the same opaque predicate — a constant, always-true condition with the algebraic form of the Pythagorean theorem — as a guard for three separate dead branches, each one a copy of the real validation logic with the result inverted. The password itself isn't a fixed string but the solution to a modular equation (a weighted sum of the input reduced to a single byte), which has no unique answer, so solving it means generating a valid input and confirming it against the real binary rather than extracting an embedded literal.

- **[Level 3 — Indirection](Ghidra-obfuscated/ghidra-obfuscated-level3-en)** ([versión en español](Ghidra-obfuscated/ghidra-obfuscated-level3))

  A PE32+ crackme that splits password validation across two chained helper functions joined by an AND — a length check and a content check kept completely separate — and builds the reference password byte by byte in memory at runtime, including a 32-bit little-endian integer, instead of storing it as a literal string anywhere in the binary.

- **[Level 4 — Virtual Tables and Hash Validation](Ghidra-obfuscated/ghidra-obfuscated-level4-en)** ([versión en español](Ghidra-obfuscated/ghidra-obfuscated-level4))

  A PE32+ crackme compiled in C++ that dispatches validation through a factory table, builds objects with their own vtable at runtime, and validates the password by comparing its 32-bit FNV-1a hash against a constant — with a second object, reachable through the same table, whose only method always returns false. Solved with an SMT solver (Z3) once the hash algorithm and its constants were recognized.

- **[Level 5 — The Final Level](Ghidra-obfuscated/ghidra-obfuscated-level5-en)** ([versión en español](Ghidra-obfuscated/ghidra-obfuscated-level5))

  A synthesis level combining techniques from the previous four — dynamic password construction, an opaque predicate, vtable dispatch, a hand-rolled comparison avoiding `strcmp` — with two new elements: runtime code relocation to executable memory (with no real effect against static analysis) and a debugger check that genuinely blocks the success path.

- **[Level 6 — State Machine and Binary Payload Delivery](Ghidra-obfuscated/ghidra-obfuscated-level6-en)** ([versión en español](Ghidra-obfuscated/ghidra-obfuscated-level6))

  A PE32+ crackme that validates its password through a custom state machine of bit rotations and hash-like constants, fed by a stack buffer overflow that spreads the ten input bytes across separately named local variables. Breaking the algorithm with Z3 was only half the problem: the solution key contains non-printable bytes that neither a keyboard nor a naive shell pipe can deliver intact to a Windows binary running under Wine.

- **[Level 7 — Mixed Boolean-Arithmetic and Dynamic Shellcode](Ghidra-obfuscated/ghidra-obfuscated-level7-en)** ([versión en español](Ghidra-obfuscated/ghidra-obfuscated-level7))

  A PE32+ crackme that hides a standard FNV-1a hash behind mixed boolean-arithmetic identities (OR/AND standing in for XOR, XOR plus carry standing in for addition), and hides the comparison's target value inside a shellcode fragment the binary itself assembles and decrypts into executable memory before invoking it. Solved with a meet-in-the-middle search instead of an SMT solver, after catching two self-made errors — a corrupted byte reconstruction and a miscalculated hex constant — by verifying results against the real binary rather than trusting the math alone.

---

## Crackme writeups

| Crackme | Technique demonstrated |
|---|---|
| CM01 | Dynamic analysis with GDB · calling convention · x86-64 |
| CM02 | Disassembly · integer comparison · live patching via ptrace in Rust |
| CM03 | XOR obfuscation · instruction stream encoding |
| CM04 | Stack string construction · movb per character · same primitive as LockBit |
| CM05 | Custom comparison loop · transformation · stack canary · SSP bypass via ptrace |

- **[Crackme 01 — Hardcoded strcmp with GDB](crackmes/cm1-strcmp)** ([versión en español](crackmes/cm1-strcmp-es))
- **[Crackme 02 — Numeric Serial: Deduction by Disassembly and Live Patching with Rust](crackmes/cm2-numeric)**
- **[Crackme 03 — XOR Stack Strings: Ciphertext Embedded in the Instruction Stream](crackmes/cm3-xor)** ([versión en español](crackmes/cm3-xor-es))
- **[Crackme 04 — Pure Stack Strings: Ten movb Instructions That strings Cannot See](crackmes/cm4-stackstring)** ([versión en español](crackmes/cm4-stackstring-es))
- **[Crackme 05 — Transform Before Compare: The First Crackme Without strcmp](crackmes/cm5-transform)** ([versión en español](crackmes/cm5-transform-es))

All challenge binaries: [github.com/AldairMaihuiri-svchost/Crackmes](https://github.com/AldairMaihuiri-svchost/Crackmes)

---

## Tooling

Custom ptrace instrumentation, binary patchers, and analysis scripts (Rust and Python) built alongside the crackme research. Each tool targets a specific low-level technique.

- **[cm2 ptrace patcher — Zero Flag Hijacking](https://github.com/AldairMaihuiri-svchost/Crackmes/tree/main/Tooling/cm2_patcher)**

  Rust process that forces "Serial válido" with any input by manipulating EFLAGS directly via ptrace — CPU state manipulation, no binary modification.

- **[cm5 Stack Canary Corruption via ptrace](https://github.com/AldairMaihuiri-svchost/Crackmes/blob/main/Tooling/cm5_corrupting_stack_canary/cm5_Stack%20Canary%20Corruption%20via%20ptrace.rs)**

  Corrupts the GCC stack canary after it is stored. Demonstrates SSP detection behavior.

- **[cm5 Stack Canary Bypass via ptrace](https://github.com/AldairMaihuiri-svchost/Crackmes/blob/main/Tooling/cm5_corrupting_stack_canary/Stack%20Canary%20Bypass%20via%20ptrace.rs)**

  Restores the canary before the check fires — stack and `%rdx`. SSP bypassed, process exits cleanly.

[All tooling](https://github.com/AldairMaihuiri-svchost/Crackmes/tree/main/Tooling)

---

## Cryptography research

- **[DES-M — Structural Modification of DES S-boxes: Reference Implementation, Differential Analysis, and Preliminary Study of Language Model Behavior](DES-M/des-m-en)** ([versión en español](DES-M/des-m))

  Ground-up DES implementation in Python, verified against FIPS 46-3 and pycryptodome. Construction of DES-M, a custom S-box variant, with full differential analysis (DDT) and Algebraic Normal Form of all eight original S-boxes. Includes an empirical evaluation of four LLMs (ChatGPT, Gemini, DeepSeek, Qwen) under black-box, gray-box, and white-box conditions — with a methodological finding on model confabulation during cryptographic verification tasks.

---

## Methodology

Analysis, reverse engineering, and scripting are my own work. Where a language model helped with spelling, translation, copy-editing, or structure, the corresponding writeup says so. Everything here is public, so errors can be found and reported: if you spot one, open an issue or contact me.

## About

I am a student and self-taught researcher. I publish what I analyze because understanding how threats are built is the first step to defending against them. [Read more about my approach](about).

---

## Elsewhere

[axlaldair6@gmail.com](mailto:axlaldair6@gmail.com) · [GitHub](https://github.com/AldairMaihuiri-svchost) · [LinkedIn](https://www.linkedin.com/in/AldairMaihuiri) · [X](https://x.com/AldairMaihuiri) · [YARAify](https://yaraify.abuse.ch/user/51747/)

---

© 2026 Gino Aldair Maihuiri Romero

This site is open source. [Improve this page](https://github.com/AldairMaihuiri-svchost/AldairMaihuiri-svchost.github.io/edit/main/index.md).
