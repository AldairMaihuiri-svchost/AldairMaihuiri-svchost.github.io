---
---
title: "Aldair Maihuiri — Security Research"
description: "Reverse engineering, malware analysis and binary exploitation by Gino Aldair Maihuiri Romero. LockBit analysis, crackme writeups, YARA rules, ptrace tooling in Rust, and three technical books in progress on malware analysis and code obfuscation."
author: Aldair Maihuiri
---
---

# Aldair Maihuiri — Security Research

**Gino Aldair Maihuiri Romero** — systems engineering student and self-directed
security researcher.
Focused on **reverse engineering, malware analysis, and exploit development**.
Currently analyzing LockBit ransomware internals and working toward OSED (EXP-301).

---

## Books in progress

Technical books written alongside active research. Reserved — not yet published.

**LockBit Ransomware — Complete Static and Dynamic Analysis**
Full dissection of a LockBit sample: string obfuscation via affine cipher,
dynamic API resolution, unreachable code blocks introduced by PGO, anomalous
constructs in the decryption routine, and 54 inaccessible blocks identified
across the binary. Documents the full analysis methodology from first strings
to function-level understanding.

**The Art of Obfuscation**
A technical study of code obfuscation techniques — from stack strings and XOR
encoding to dynamic API resolution and anti-debug primitives. Grounded in
real malware samples and purpose-built crackmes designed to isolate each
technique.

**[Reserved]**
Third book in progress. Title and subject withheld pending publication.

## Malware analysis

- **[LockBit String Deobfuscation — Affine Cipher DLL Loading](lockbit-string-deobfuscation)**
  Public teaser: how LockBit encrypts DLL names on the stack to evade IAT
  detection, the affine cipher reversed step by step, and a Python script
  replicating the decryption. The decryption scripts, full function analysis,
  and the complete 11-block breakdown are reserved for the book
  *LockBit Ransomware — Complete Static and Dynamic Analysis*.

---

## Crackme writeups

- **[Crackme 01 — Hardcoded strcmp with GDB](crackmes/cm1-strcmp)**
  ([versión en español](crackmes/cm1-strcmp-es))
- **[Crackme 02 — Numeric Serial: Deduction by Disassembly and Live Patching with Rust](crackmes/cm2-numeric)**
- **[Crackme 03 — XOR Stack Strings: Ciphertext Embedded in the Instruction Stream](crackmes/cm3-xor)**
  ([versión en español](crackmes/cm3-xor-es))
- **[Crackme 04 — Pure Stack Strings: Ten movb Instructions That strings Cannot See](crackmes/cm4-stackstring)**
  ([versión en español](crackmes/cm4-stackstring-es))
- **[Crackme 05 — Transform Before Compare: The First Crackme Without strcmp](crackmes/cm5-transform)**
  ([versión en español](crackmes/cm5-transform-es))

All challenge binaries: [github.com/GinoMaihuiri/Crackmes](https://github.com/GinoMaihuiri/Crackmes)

---

## Tooling

Custom ptrace instrumentation, binary patchers, and analysis scripts built alongside
the crackme research. Each tool targets a specific low-level technique.

- **[cm2 ptrace patcher — Zero Flag Hijacking](https://github.com/GinoMaihuiri/Crackmes/tree/main/Tooling/cm2_patcher)**
- **[cm5 Stack Canary Corruption via ptrace](https://github.com/GinoMaihuiri/Crackmes/blob/main/Tooling/cm5_corrupting_stack_canary/cm5_Stack%20Canary%20Corruption%20via%20ptrace.rs)**
- **[cm5 Stack Canary Bypass via ptrace](https://github.com/GinoMaihuiri/Crackmes/blob/main/Tooling/cm5_corrupting_stack_canary/Stack%20Canary%20Bypass%20via%20ptrace.rs)**

👉 [All tooling](https://github.com/GinoMaihuiri/Crackmes/tree/main/Tooling)

---

## Detection engineering

- YARA rules published on [YARAhub](https://yaraify.abuse.ch/user/51747/)

---

## Elsewhere

[GitHub](https://github.com/GinoMaihuiri) ·
[LinkedIn](https://www.linkedin.com/in/AldairMaihuiri) ·
[X](https://x.com/AldairMaihuiri) ·
[YARAify](https://yaraify.abuse.ch/user/51747/)

---

© 2026 Gino Aldair Maihuiri Romero
