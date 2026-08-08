---
title: "Crackme 03 — XOR Stack Strings: Ciphertext Embedded in the Instruction Stream"
description: "Solving cm3_xor: static analysis with strings, GDB resolution via strcmp breakpoint, full XOR loop disassembly, manual decryption without execution, and connection to real-world malware obfuscation."
author: Aldair Maihuiri
date: 2026-08-07
---

🇪🇸 [Leer en español](https://ginomaihuiri.github.io/crackmes/cm3-xor-es)

# Crackme 03 — XOR Stack Strings: Ciphertext Embedded in the Instruction Stream

**Author:** Aldair Maihuiri
**Date:** August 7, 2026
**Binary:** cm3_xor (ELF 64-bit, PIE, not stripped)
**Tools:** GDB, objdump, strings, Python 3
**Tags:** `crackme` `reverse-engineering` `gdb` `x86_64` `xor` `obfuscation` `stack-strings`

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
BuildID[sha1]=4f6bf934d0834c622552d31faa6a140065a6dabc,
for GNU/Linux 4.4.0, with debug_info, not stripped
```

ELF 64-bit, PIE, not stripped. The crackme itself announces the challenge:

```
╔══════════════════════════════════════════════
║ Nivel 1 · CM03  [*       ]
║ XOR decode
╠══════════════════════════════════════════════
║ La clave esta cifrada. Aplica XOR para revelarla.
╚══════════════════════════════════════════════

Contrasena : AAAABBBCCCDDD
[-] Password incorrecto.
```

"The key is encrypted. Apply XOR to reveal it." The crackme is telling us exactly what
to look for — a XOR decryption routine somewhere before the comparison.

---

## Static analysis: what strings reveals and what it hides

```
$ strings ./crackme
```

Selected relevant output:

```
strcmp
fgets
strlen
getenv
decoded
cd}v
La clave esta cifrada. Aplica XOR para revelarla.
XOR decode
Contrasena :
Password correcto!
Password incorrecto.
```

Three observations that define the analysis strategy before opening GDB:

**`strcmp` is present** — the binary compares strings. Same family as cm1. The
`break strcmp` approach will work.

**`decoded` appears as a symbol** — this is the name of a variable or buffer in the
source code. Not stripped, so the debug symbols confirm there is a decoding step: the
password is stored encrypted and decoded at runtime before the comparison. `strings`
cannot show us the real password — it will be on the stack, built at execution time.

**`cd}v` appears** — this looks like random garbage, but it is not. In ASCII:
`'c'=0x63`, `'d'=0x64`, `'}'=0x7d`, `'v'=0x76`. These are the first four encrypted
bytes of the password, visible because they happen to be printable characters embedded
inside a `movl` instruction in the `.text` section. The fifth byte (`0x77`) lives in a
separate `movb` instruction, so `strings` does not see them as a contiguous sequence.

The password is not in `.rodata` — it is hardcoded as immediate values in the
instruction stream, decrypted to the stack at runtime. `strings` almost reveals it,
but not quite.

---

## Identifying imported functions

```
$ objdump -T ./crackme | grep -i "strcmp\|atoi\|strtol\|scanf\|strtoul"

0000000000000000  DF *UND*  0000000000000000 (GLIBC_2.2.5) strcmp
```

`strcmp` confirmed. Same approach as cm1: the decryption happens before `strcmp` is
called. By the time the strings reach the comparison, the XOR has already run and the
plaintext is sitting on the stack.

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
║ Nivel 1 · CM03  [*       ]
║ XOR decode
╠══════════════════════════════════════════════
║ La clave esta cifrada. Aplica XOR para revelarla.
╚══════════════════════════════════════════════

Contrasena : crackme3

Breakpoint 1, 0x00007ffff7d73210 in ?? () from /usr/lib/libc.so.6
```

The XOR decryption already ran. Both strings are in memory, in plaintext:

```
(gdb) x/s $rdi
0x7fffffffe4c0: "crackme3"

(gdb) x/s $rsi
0x7fffffffe4ba: "pwned"
```

`$rdi` holds the user input. `$rsi` holds the decrypted password: **`pwned`**.

### Verification

```
(gdb) run
Serial: pwned

Breakpoint 1, 0x00007ffff7d73210 in ?? () from /usr/lib/libc.so.6

(gdb) continue

  [+] Password correcto!
```

---

## Deep analysis — the XOR loop in assembly

The quick resolution found the password. The deeper question is: how does the binary
decrypt it? The disassembly of `main` reveals the full mechanism.

```
$ gdb ./crackme

(gdb) break main
(gdb) run
(gdb) disassemble main
```

The relevant section:

```asm
; --- Encrypted bytes loaded as immediate values into the stack ---
main+91:  movl  $0x767d6463, -0x11b(%rbp)   ; 4 bytes: 63 64 7d 76 (little-endian)
main+101: movb  $0x77, -0x117(%rbp)          ; 1 byte:  77

; --- Counter initialized ---
main+108: movl  $0x0, -0x120(%rbp)           ; i = 0
main+118: jmp   main+163                     ; jump to condition check

; --- Loop body ---
main+120: mov   -0x120(%rbp), %eax           ; eax = i
main+126: cltq                               ; sign-extend eax to rax (for memory indexing)
main+128: movzbl -0x11b(%rbp,%rax,1), %eax  ; eax = encrypted[i] (zero-extended byte)
main+136: xor   $0x13, %eax                 ; eax = encrypted[i] XOR 0x13
main+139: mov   %eax, %edx                  ; edx = decrypted byte
main+141: mov   -0x120(%rbp), %eax           ; eax = i
main+147: cltq                               ; sign-extend to rax
main+149: mov   %dl, -0x116(%rbp,%rax,1)    ; decoded[i] = decrypted byte

main+156: addl  $0x1, -0x120(%rbp)          ; i++

; --- Loop condition ---
main+163: cmpl  $0x4, -0x120(%rbp)          ; i <= 4 ?
main+170: jle   main+120                    ; if yes, loop
```

### Instruction-by-instruction breakdown

**`main+91 — movl $0x767d6463, -0x11b(%rbp)`**

Stores 4 bytes as a 32-bit little-endian immediate into the stack. Little-endian means
the least significant byte is stored at the lowest address:

```
Address     Value
-0x11b      0x63    ← LSB
-0x11a      0x64
-0x119      0x7d
-0x118      0x76    ← MSB
```

**`main+101 — movb $0x77, -0x117(%rbp)`**

Stores the fifth byte immediately after. The full encrypted buffer is now on the stack:

```
-0x11b: 0x63
-0x11a: 0x64
-0x119: 0x7d
-0x118: 0x76
-0x117: 0x77
```

These are the same bytes `strings` partially detected as `cd}v`. The fifth (`0x77='w'`)
was in a separate instruction, breaking the printable sequence.

**`main+108 — movl $0x0, -0x120(%rbp)`**

Initializes the loop counter `i` to 0. The counter lives at a separate stack location,
8 bytes below the encrypted buffer.

**`main+118 — jmp main+163`**

Jumps to the condition check first. This is a **bottom-checking loop** — the condition
is evaluated at the end of each iteration, not at the start. Equivalent in C to a
`for (i=0; i<=4; i++)` that checks the condition at the bottom.

**`main+120 — mov -0x120(%rbp), %eax`**

Loads the current counter value into `%eax` for use as an array index.

**`main+126 — cltq`**

Converts `%eax` (32-bit) to `%rax` (64-bit) by sign extension. Memory addressing on
x86-64 requires 64-bit registers for the index. Without this, the upper 32 bits of
`%rax` might contain garbage from a previous operation. `cltq` ensures the index is
clean.

**`main+128 — movzbl -0x11b(%rbp,%rax,1), %eax`**

Loads one byte from `encrypted[i]` and zero-extends it to 32 bits.

The address calculation: `-0x11b + %rbp + %rax * 1`. When `i=0`, this is exactly
`-0x11b(%rbp)` — the start of the encrypted buffer. As `i` increments, it walks
through each byte.

`movzbl` (move zero-byte-long) is important: it loads a single byte and fills the
upper bits of `%eax` with zeros. The alternative, `movb`, would leave the upper bits
undefined after the XOR.

**`main+136 — xor $0x13, %eax`**

The XOR instruction. `0x13` is the key — a single byte applied to every character.
XOR has a fundamental property that makes it useful for simple obfuscation:

```
encrypt:  plaintext  XOR key = ciphertext
decrypt:  ciphertext XOR key = plaintext
```

The same operation encrypts and decrypts. Applying XOR twice with the same key
returns the original value. No separate encrypt/decrypt functions needed.

**`main+149 — mov %dl, -0x116(%rbp,%rax,1)`**

Stores the decrypted byte into a separate buffer (`decoded`), 5 bytes above the
encrypted one in the stack frame. `%dl` is the low byte of `%edx`, which holds the
decrypted value.

**`main+163 — cmpl $0x4, -0x120(%rbp)` / `main+170 — jle main+120`**

Loop condition: continue while `i <= 4`. Five iterations total (0, 1, 2, 3, 4) —
matching the 5 characters of `pwned`.

After the loop, `main+172` writes a null terminator, completing the decoded string.
Then the pointer to the decoded buffer goes into `%rsi`, the user input into `%rdi`,
and `strcmp` is called.

---

## Manual decryption — no execution required

With the key (`0x13`) and the encrypted bytes extracted statically from the
disassembly, the password can be recovered without running the binary.

**Encrypted bytes in memory order:**

| Index | Address | Encrypted byte | XOR key | Result (dec) | Result (ASCII) |
|---|---|---|---|---|---|
| 0 | `-0x11b` | `0x63` | `0x13` | 112 | `p` |
| 1 | `-0x11a` | `0x64` | `0x13` | 119 | `w` |
| 2 | `-0x119` | `0x7d` | `0x13` | 110 | `n` |
| 3 | `-0x118` | `0x76` | `0x13` | 101 | `e` |
| 4 | `-0x117` | `0x77` | `0x13` | 100 | `d` |

**Python verification:**

```python
encrypted = [0x63, 0x64, 0x7d, 0x76, 0x77]
key = 0x13

decrypted = [chr(b ^ key) for b in encrypted]
print(''.join(decrypted))
# Output: pwned
```

The password recovered purely from static analysis, without executing the binary once.

---

## Connection to real-world malware

This technique is not academic. During my analysis of a LockBit ransomware sample,
I found the same primitive: DLL names encrypted with a per-string affine cipher,
stored as immediate values in `MOV BYTE PTR` instructions on the stack, decrypted at
runtime before being passed to a dynamic API resolver.

The structural pattern is identical to what this crackme demonstrates:

| Step | cm3_xor | LockBit |
|---|---|---|
| Storage | Immediate values in `movl`/`movb` | Immediate values in `mov byte ptr` |
| Location | Stack (local variable) | Stack (local variable) |
| Key | Single byte `0x13` | Per-string affine cipher (key + multiplier) |
| Decryption | Runtime, before `strcmp` | Runtime, before API resolution |
| Visible with `strings`? | Partially (as garbage) | No |
| IAT / import | `strcmp` visible | No imports visible |

LockBit goes further — each string uses its own key and multiplier, and the API is
resolved dynamically to keep it out of the IAT entirely. But the foundational idea
is the same: **encrypted immediates on the stack, decrypted just before use**.

Understanding this pattern in a controlled crackme environment builds the intuition
needed to recognize and reverse it when it appears in real malware.

---

## cm1 / cm2 / cm3 — progression

| Aspect | CM1 (strcmp) | CM2 (numeric) | CM3 (xor) |
|---|---|---|---|
| Key function | `strcmp` | `atoi` | `strcmp` |
| Secret type | Plaintext in `.rodata` | Immediate in `cmpl` opcode | Encrypted immediates in `movl`/`movb` |
| Visible with `strings`? | Yes — fully | No | Partially — as ciphertext garbage |
| Breakpoint strategy | `break strcmp` → `x/s $rsi` | `break atoi` → `x/10i $rip` | `break strcmp` → `x/s $rsi` |
| Static recovery | Trivial | Read the `cmpl` immediate | Extract bytes + key → XOR |
| New concept | Calling convention | Integer comparison, atoi behavior | XOR obfuscation, instruction stream encoding |

---

*Part of a crackme writeup series covering progressively harder binaries — from
hardcoded comparisons to obfuscated checks, custom hash functions, and anti-debug
techniques.*

*Challenge binaries: [github.com/GinoMaihuiri/Crackmes](https://github.com/GinoMaihuiri/Crackmes)*

*All writeups: [ginomaihuiri.github.io](https://ginomaihuiri.github.io)*

---

© 2026 Aldair Maihuiri. All rights reserved.
Sharing with attribution is welcome. Unauthorized reproduction is prohibited.
