# Hi, I'm Aldair Maihuiri 👋

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

**5 crackme writeups · 2 YARA rules on YARAhub · 2 ptrace tools in Rust**
**Malware analyzed: LockBit (PE32) · SolarisLoader (PE64)**
**Platforms: Linux ELF · Windows PE · x86-64**

Systems engineering student · Lima, Peru

---

### Books in progress

Technical books written alongside active research. Reserved — not yet published.

- *LockBit Ransomware — Complete Static and Dynamic Analysis* — reserved
- *The Art of Obfuscation* — reserved
- *[Reserved]* — title withheld

---

### Writeups & research

- [LockBit String Deobfuscation — Affine Cipher DLL Loading](https://ginomaihuiri.github.io/lockbit-string-deobfuscation)
- [Crackme 01 — Hardcoded strcmp with GDB](https://ginomaihuiri.github.io/crackmes/cm1-strcmp)
- [Crackme 02 — Numeric Serial: Deduction by Disassembly and Live Patching with Rust](https://ginomaihuiri.github.io/crackmes/cm2-numeric)
- [Crackme 03 — XOR Stack Strings: Ciphertext Embedded in the Instruction Stream](https://ginomaihuiri.github.io/crackmes/cm3-xor)
- [Crackme 04 — Pure Stack Strings: Ten movb Instructions That strings Cannot See](https://ginomaihuiri.github.io/crackmes/cm4-stackstring)
- [Crackme 05 — Transform Before Compare: The First Crackme Without strcmp](https://ginomaihuiri.github.io/crackmes/cm5-transform)

---

### Projects

- [Crackmes](https://github.com/GinoMaihuiri/Crackmes) — Original crackme challenges with solutions and tooling
  - [Tooling/](https://github.com/GinoMaihuiri/Crackmes/tree/main/Tooling) — ptrace patchers and binary instrumentation in Rust

---

### Profiles

[YARAify](https://yaraify.abuse.ch/user/51747/) · [LinkedIn](https://www.linkedin.com/in/AldairMaihuiri) · [X](https://x.com/AldairMaihuiri) · [MalwareBazaar](https://bazaar.abuse.ch/user/51747/)
