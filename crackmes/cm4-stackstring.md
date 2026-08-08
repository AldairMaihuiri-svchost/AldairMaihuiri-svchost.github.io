---
title: "Crackme 04 — Pure Stack Strings: Ten movb Instructions That strings Cannot See"
description: "Solving cm4_stackstring: static analysis failure with strings, GDB resolution via strcmp, full movb sequence disassembly, static byte recovery, and the compiler behavior that makes this technique work — the same primitive found in real malware."
author: Aldair Maihuiri
date: 2026-08-07
---

🇪🇸 [Leer en español](https://ginomaihuiri.github.io/crackmes/cm4-stackstring-es)

# Crackme 04 — Pure Stack Strings: Ten movb Instructions That strings Cannot See

**Author:** Aldair Maihuiri
**Date:** August 7, 2026
**Binary:** cm4_stackstring (ELF 64-bit, PIE, not stripped)
**Tools:** GDB, objdump, strings
**Tags:** `crackme` `reverse-engineering` `gdb` `x86_64` `stack-strings` `obfuscation`

---

© 2026 Aldair Maihuiri. All rights reserved.
You may share this writeup with attribution. Reproduction without permission is prohibited.

---

## Initial recon

```
$ chmod +x ./crackme
$ file ./crackme

./crackme: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV),
dynamically linked,
interpreter /lib64/ld-linux-x86-64.so.2,
BuildID[sha1]=6b8b7a7d8e684085ef2e94674ed5aef131a39d46,
for GNU/Linux 4.4.0, with debug_info, not stripped
```

ELF 64-bit, PIE, not stripped. The crackme announces its technique immediately:

```
╔══════════════════════════════════════════════
║ Nivel 1 · CM04  [*       ]
║ Stack string
╠══════════════════════════════════════════════
║ La clave se construye caracter a caracter en la pila.
╚══════════════════════════════════════════════

Contrasena : hackme
[-] Nope.
```

"The key is built character by character on the stack." The name and the description
together tell us exactly what to expect in the disassembly.

---

## Static analysis: where strings completely fails

```
$ strings ./crackme | head -50
```

Relevant output:

```
strcmp
fgets
strlen
getenv
NO_COLOR
La clave se construye caracter a caracter en la pila.
Stack string
Contrasena :
Excelente! Flag encontrado.
```

The password is completely absent from the `strings` output. Not partially visible
like cm3's `cd}v` — invisible entirely.

In cm3, the XOR-encrypted bytes were stored as a 32-bit immediate in a single `movl`
instruction, which made four consecutive printable bytes appear in the binary. Here,
each character is stored by a separate `movb` instruction. Between each `movb` and
the next, there are instruction encoding bytes — opcode, ModR/M, displacement — that
break any contiguous printable sequence. `strings` has nothing to find.

This is **pure stack string construction**: the password is assembled in the stack
frame one byte at a time, with no contiguous representation anywhere in the binary.

---

## Identifying imported functions

```
$ objdump -T ./crackme | grep -i "strcmp\|atoi\|strtol\|scanf\|strtoul\|memcmp"

0000000000000000  DF *UND*  0000000000000000 (GLIBC_2.2.5) strcmp
```

`strcmp` confirmed. Same resolution strategy as cm1 and cm3: the password is fully
assembled on the stack before `strcmp` is called. By the time we reach the comparison,
all characters are in place.

---

## GDB — quick resolution

```
$ gdb ./crackme

(gdb) break strcmp
Breakpoint 1 at 0x1090

(gdb) run
```

```
╔══════════════════════════════════════════════
║ Nivel 1 · CM04  [*       ]
║ Stack string
╠══════════════════════════════════════════════
║ La clave se construye caracter a caracter en la pila.
╚══════════════════════════════════════════════

Contrasena : hackme

Breakpoint 1, 0x00007ffff7d73210 in ?? () from /usr/lib/libc.so.6
```

All ten characters are already assembled on the stack:

```
(gdb) x/s $rdi
0x7fffffffe4b0: "hackme"

(gdb) x/s $rsi
0x7fffffffe4a6: "flag_2024"
```

`$rdi` holds the user input. `$rsi` holds the assembled password: **`flag_2024`**.

### Verification

```
(gdb) run
Contrasena: flag_2024

Breakpoint 1, 0x00007ffff7d73210 in ?? () from /usr/lib/libc.so.6

(gdb) continue

  [+] Excelente! Flag encontrado.
```

---

## Deep analysis — the movb sequence

The quick resolution found the password. The deeper question is: how exactly does
the binary construct it? `disassemble main` reveals the full sequence.

```
(gdb) break main
(gdb) run
(gdb) disassemble main
```

After `read_input`, the password construction begins immediately:

```asm
main+86:  call  read_input

; --- Stack string construction: one movb per character ---
main+91:  movb  $0x66, -0x11a(%rbp)   ; pw[0] = 0x66
main+98:  movb  $0x6c, -0x119(%rbp)   ; pw[1] = 0x6c
main+105: movb  $0x61, -0x118(%rbp)   ; pw[2] = 0x61
main+112: movb  $0x67, -0x117(%rbp)   ; pw[3] = 0x67
main+119: movb  $0x5f, -0x116(%rbp)   ; pw[4] = 0x5f
main+126: movb  $0x32, -0x115(%rbp)   ; pw[5] = 0x32
main+133: movb  $0x30, -0x114(%rbp)   ; pw[6] = 0x30
main+140: movb  $0x32, -0x113(%rbp)   ; pw[7] = 0x32
main+147: movb  $0x34, -0x112(%rbp)   ; pw[8] = 0x34
main+154: movb  $0x00, -0x111(%rbp)   ; pw[9] = null terminator

; --- Load pointers and call strcmp ---
main+161: lea   -0x11a(%rbp), %rdx    ; rdx → pw (assembled password)
main+168: lea   -0x110(%rbp), %rax    ; rax → input (user input)
main+175: mov   %rdx, %rsi            ; 2nd arg: pw
main+178: mov   %rax, %rdi            ; 1st arg: input
main+181: call  strcmp@plt

; --- Decision ---
main+186: test  %eax, %eax
main+188: jne   main+212              ; if not equal → print_err
main+190: lea   ...                   ; → print_ok
```

### Why there is no loop

Compare with cm3: there, the XOR decryption required iterating over the encrypted
bytes — hence the `do/while` loop with a counter at `-0x120(%rbp)`. Here there is
no encryption and no decryption. Each character is written directly to its final
position. No iteration needed — the compiler generates one instruction per character.

This is the structural distinction between the two techniques:

| | cm3_xor | cm4_stackstring |
|---|---|---|
| Storage in binary | Encrypted immediates | Plaintext immediates |
| Loop? | Yes — XOR decryption loop | No — direct writes |
| Instructions per character | 1 XOR iteration | 1 `movb` |
| Key | `0x13` | None |

### Stack layout after construction

The nine characters plus the null terminator occupy ten consecutive bytes:

```
Address        Byte   ASCII
-0x11a(%rbp)   0x66   'f'   ← pw[0]  start of password
-0x119(%rbp)   0x6c   'l'   ← pw[1]
-0x118(%rbp)   0x61   'a'   ← pw[2]
-0x117(%rbp)   0x67   'g'   ← pw[3]
-0x116(%rbp)   0x5f   '_'   ← pw[4]
-0x115(%rbp)   0x32   '2'   ← pw[5]
-0x114(%rbp)   0x30   '0'   ← pw[6]
-0x113(%rbp)   0x32   '2'   ← pw[7]
-0x112(%rbp)   0x34   '4'   ← pw[8]
-0x111(%rbp)   0x00   '\0'  ← pw[9]  explicit null terminator
```

The null terminator at `main+154` is written explicitly with its own `movb`
instruction — there is no loop condition that would place it automatically.

---

## Static recovery — no execution required

With the bytes extracted directly from the disassembly:

| Offset | Address | Byte | ASCII |
|---|---|---|---|
| `main+91` | `-0x11a` | `0x66` | `f` |
| `main+98` | `-0x119` | `0x6c` | `l` |
| `main+105` | `-0x118` | `0x61` | `a` |
| `main+112` | `-0x117` | `0x67` | `g` |
| `main+119` | `-0x116` | `0x5f` | `_` |
| `main+126` | `-0x115` | `0x32` | `2` |
| `main+133` | `-0x114` | `0x30` | `0` |
| `main+140` | `-0x113` | `0x32` | `2` |
| `main+147` | `-0x112` | `0x34` | `4` |
| `main+154` | `-0x111` | `0x00` | `\0` |

Password recovered statically: **`flag_2024`**.

---

## Why the compiler generates individual movb instructions

Understanding this requires knowing how C compilers handle local arrays.

When a string is defined as a **string literal** in C — `"flag_2024"` — the compiler
places it in the `.rodata` section as a contiguous sequence of bytes. `strings` finds
it immediately.

When the same characters are assigned **individually to a local array**, the compiler
translates each assignment to a separate write to the stack. There is no string literal
anywhere — just individual byte-sized immediate values embedded inside separate machine
instructions. Between each `movb $0x66, addr` and `movb $0x6c, next_addr`, there are
encoding bytes that break any contiguous printable sequence.

The CPU assembles the complete string in memory at runtime, one byte at a time.
`strings` never sees it because it only reads the static content of the file — not
what gets built in memory during execution.

This is a source-level decision that has a direct and profound effect on static
analysis. The runtime behavior is identical. The static visibility is completely different.

---

## Connection to real-world malware

This technique is not theoretical. During my analysis of a LockBit ransomware sample,
I documented the same pattern: DLL names constructed one byte at a time on the stack
using individual `MOV BYTE PTR` instructions, never existing as contiguous strings in
the binary.

The comparison across the progression from this crackme series to LockBit:

| | cm4_stackstring | LockBit |
|---|---|---|
| Instructions | `movb` per character | `mov byte ptr` per character |
| Characters in plaintext? | Yes | No — XOR-encrypted before storage |
| Loop? | No | No |
| Null terminator | Explicit `movb $0x0` | Produced by the cipher design |
| Visible with `strings`? | No | No |
| IAT entry | `strcmp` visible | No imports visible |

cm4 is the **base pattern** — plain bytes, no encryption. LockBit takes the same
structural approach but adds a per-string affine cipher on top: the bytes stored by
the `mov byte ptr` instructions are ciphertext, not plaintext. The decryption loop
runs immediately after the construction, before the string is used.

Understanding cm4 makes the LockBit analysis easier to reason about: it separates
the stack construction pattern from the encryption layer, showing that they are
two independent techniques that happen to be combined.

---

## cm1 / cm2 / cm3 / cm4 — progression

| Aspect | CM1 | CM2 | CM3 | CM4 |
|---|---|---|---|---|
| Key function | `strcmp` | `atoi` | `strcmp` | `strcmp` |
| Secret location | `.rodata` | `cmpl` opcode | `movl`/`movb` (encrypted) | `movb` (plaintext) |
| Visible with `strings`? | Yes | No | Partially | No |
| Loop? | — | — | Yes (XOR) | No |
| Static recovery | Trivial | Read immediate | Extract + XOR | Read `movb` values |
| New concept | Calling convention | Integer comparison | XOR obfuscation | Stack string construction |

---

*Part of a crackme writeup series covering progressively harder binaries — from
hardcoded comparisons to obfuscated checks, custom hash functions, and anti-debug
techniques.*

*Challenge binaries: [github.com/GinoMaihuiri/Crackmes](https://github.com/GinoMaihuiri/Crackmes)*

*All writeups: [ginomaihuiri.github.io](https://ginomaihuiri.github.io)*

---

© 2026 Aldair Maihuiri. All rights reserved.
Sharing with attribution is welcome. Unauthorized reproduction is prohibited.
