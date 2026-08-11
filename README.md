# Crackmes — Gino Aldair Maihuiri Romero

Original crackme challenges written by **Gino Aldair Maihuiri Romero** (Aldair Maihuiri).
Each challenge targets a specific reverse engineering technique — starting from
hardcoded comparisons and progressing toward obfuscated checks, custom algorithms,
and anti-debug protections.

Built for anyone learning RE who wants deliberate, focused practice on one concept
at a time.

---

⚠️ **The `solutions/` folder contains source code.** Open it only after attempting
the challenge — it spoils the answer.

---

## Challenges

| Name | Level | Technique | Platform | Writeup |
|---|---|---|---|---|
| cm1_strcmp | 1 | Hardcoded strcmp | Linux x86_64 (ELF) | [Writeup](https://ginomaihuiri.github.io/crackmes/cm1-strcmp) |
| cm2_numeric | 1 | Numeric serial + live patching via ptrace | Linux x86_64 (ELF) | [Writeup](https://ginomaihuiri.github.io/crackmes/cm2-numeric) |
| cm3_xor | 1 | XOR encrypted immediates in instruction stream | Linux x86_64 (ELF) | [Writeup](https://ginomaihuiri.github.io/crackmes/cm3-xor) |
| cm4_stackstring | 1 | Pure stack strings — movb per character | Linux x86_64 (ELF) | [Writeup](https://ginomaihuiri.github.io/crackmes/cm4-stackstring) |
| cm5_transform | 1 | Custom transformation loop + SSP bypass | Linux x86_64 (ELF) | [Writeup](https://ginomaihuiri.github.io/crackmes/cm5-transform) |

---

## Tooling

Custom ptrace instrumentation and binary patchers built alongside the challenges.

| Tool | Technique | Target |
|---|---|---|
| [cm2 ptrace patcher](Tooling/cm2_patcher/) | Zero Flag Hijacking via ptrace | cm2_numeric |
| [cm5 Stack Canary Corruption](Tooling/cm5_corrupting_stack_canary/) | SSP corruption — crash demonstration | cm5_transform |
| [cm5 Stack Canary Bypass](Tooling/cm5_corrupting_stack_canary/) | SSP bypass — canary restore before check | cm5_transform |

---

## How to run

```bash
cd <challenge_folder>
chmod +x crackme
./crackme
```

## Suggested tools

GDB · Ghidra · objdump · strings · Rust (for tooling)

---

## Writeups

Detailed solutions with full assembly analysis in English and Spanish:
[ginomaihuiri.github.io/crackmes](https://ginomaihuiri.github.io/crackmes/)

---

## Author

**Gino Aldair Maihuiri Romero** — security researcher
[Blog](https://ginomaihuiri.github.io) · [GitHub](https://github.com/GinoMaihuiri) · [LinkedIn](https://www.linkedin.com/in/AldairMaihuiri) · [X](https://x.com/AldairMaihuiri)

---

© 2026 Gino Aldair Maihuiri Romero. Challenges are free to use for learning purposes.
