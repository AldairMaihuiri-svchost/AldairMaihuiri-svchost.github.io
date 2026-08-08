---
title: "Aldair Maihuiri — Security Research"
description: "Reverse engineering, malware analysis and exploit development writeups by Gino Aldair Maihuiri Romero."
author: Aldair Maihuiri
---

# Aldair Maihuiri — Security Research

**Gino Aldair Maihuiri Romero** — systems engineering student and self-directed
security researcher.

Focused on **reverse engineering, malware analysis, and exploit development**.
Currently analyzing LockBit ransomware internals and working toward OSED (EXP-301).

---

## Malware analysis

- **[LockBit String Deobfuscation — Affine Cipher DLL Loading](lockbit-string-deobfuscation)**
  How LockBit encrypts DLL names on the stack to evade IAT detection, the affine
  cipher reversed step by step, and a Python script replicating the decryption.

---

## Crackme writeups

- **[Crackme 01 — Hardcoded strcmp with GDB](crackmes/cm1-strcmp)**
  ([versión en español](crackmes/cm1-strcmp-es))
  Finding a hardcoded password through the x86_64 calling convention, plus a look at
  the AVX2 glibc strcmp implementation and the full assembly decision flow.

- **[Crackme 02 — Numeric Serial: Deduction by Disassembly and Live Patching with Rust](crackmes/cm2-numeric)**
  Serial deduced from the cmpl opcode via GDB, then bypassed entirely with a Rust
  ptrace patcher — CPU state manipulation via Zero Flag.

- **[Crackme 03 — XOR Stack Strings: Ciphertext Embedded in the Instruction Stream](crackmes/cm3-xor)**
  ([versión en español](crackmes/cm3-xor-es))
  XOR-encrypted password stored as immediate values in the instruction stream,
  decrypted to the stack at runtime before strcmp.

All challenge binaries: [github.com/GinoMaihuiri/Crackmes](https://github.com/GinoMaihuiri/Crackmes)

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
