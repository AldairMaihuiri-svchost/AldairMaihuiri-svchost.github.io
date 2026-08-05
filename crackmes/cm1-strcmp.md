---
title: "Crackme 01 — Hardcoded strcmp: Finding the Password with GDB"
description: "Step-by-step writeup of cm1_strcmp: initial recon, GDB breakpoints, x86_64 calling convention, AVX2 strcmp internals, and full assembly flow analysis."
author: Aldair Maihuiri
date: 2026-08-02
---

# Crackme 01 — Hardcoded strcmp: Finding the Password with GDB

**Author:** Aldair Maihuiri  
**Date:** August 2, 2026  
**Binary:** cm1_strcmp (ELF 64-bit, not stripped)  
**Tools:** GDB, file, chmod  
**Tags:** `crackme` `reverse-engineering` `gdb` `x86_64` `strcmp` `elf`

---

© 2026 Gino Maihuiri. All rights reserved.  
You may share this writeup with attribution. Reproduction without permission is prohibited.

---

## Initial recon

Before opening any binary in a debugger, the first step is running `file` on it.
This gives us the architecture, whether it is stripped or not, and whether it links dynamically or statically:

```
$ file ./crackme

./crackme: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV),
dynamically linked,
interpreter /lib64/ld-linux-x86-64.so.2,
BuildID[sha1]=b4784a7ce15cbbec0e4411e0179fb8eb4959548c,
for GNU/Linux 4.4.0, with debug_info, not stripped
```

ELF 64-bit, dynamically linked, and **not stripped** — meaning debug symbols are present.
Function names like `main` and `strcmp` will appear directly in the debugger without any
additional work. In later crackmes it will be worth checking whether the binary is stripped
before proceeding; here it is not necessary.

---

## Opening in GDB — permission error

```
$ gdb ./crackme
(gdb) break main
Breakpoint 1 at 0x1721: file crackme.c, line 5.
(gdb) run
```

This produced a common error when working with binaries downloaded or cloned from a repository:

```
/bin/bash: line 1:
/home/house/Cracmes-main/nivel1/cm1_strcmp/crackme: Permission denied
❌ During startup program exited with code 126.
```

The file had no execute permission. The fix:

```
$ chmod +x ./crackme
```

Worth keeping in mind every time you clone a repository that contains binaries.

---

## First execution

With permissions corrected:

```
$ gdb ./crackme
(gdb) run
```

```
╔══════════════════════════════════════════════
║ Level 1 · CM01 [* ]
║ Hardcoded strcmp
╠══════════════════════════════════════════════
║ A guardian compares your key directly with strcmp.
╚══════════════════════════════════════════════

Password: asdasd
```

The crackme tells us exactly where to look: **hardcoded strcmp**.

---

## What is strcmp?

`strcmp` stands for **STRing CoMPare**. It is a standard C function that compares two strings
character by character and returns an integer indicating the difference:

```c
int strcmp(const char *s1, const char *s2);
```

| Return value | Meaning | Assembly conditional |
|---|---|---|
| 0 | Strings are **equal** ✅ | `test eax, eax` → `je` (jump if zero) |
| < 0 | s1 < s2 | `js`/`jl` — rare in practice |
| > 0 | s1 > s2 | `jg` — rare; compilers use `je`/`jne` |

**Golden rule: if strcmp returns 0, the strings are identical.** Everything that follows
revolves around that zero.

### Simplified internal implementation

```c
int strcmp(const char *s1, const char *s2) {
    while (*s1 && (*s1 == *s2)) {
        s1++;
        s2++;
    }
    return *(unsigned char *)s1 - *(unsigned char *)s2;
}
```

This is the baseline logic. The actual glibc implementation is heavily optimized — we will
see it in assembly shortly.

---

## Setting a breakpoint on strcmp

This time the breakpoint goes on `strcmp` directly, not on `main`. The crackme already
told us it uses strcmp, so we skip straight to the comparison instead of stepping through
the whole program from the start:

| Breakpoint | When it fires | What you see |
|---|---|---|
| `break main` | Program start, before the password prompt | Program just begins |
| `break strcmp` | Exact moment of the comparison | Both strings (your input and the correct one) |

Why not always use `break strcmp` on every crackme? Because in more advanced ones, strcmp
is obfuscated, called indirectly, or not used at all. That is the normal case — exposing
a sensitive comparison through a plainly named library call is an obvious weak point.

```
(gdb) break strcmp
(gdb) run
```

We enter `Hola` as the password to advance execution to the comparison point:

```
╔══════════════════════════════════════════════
║ Level 1 · CM01 [* ]
║ Hardcoded strcmp
╠══════════════════════════════════════════════
║ A guardian compares your key directly with strcmp.
╚══════════════════════════════════════════════

Password: Hola

Breakpoint 1, 0x00007ffff7d73210 in ?? () from /usr/lib/libc.so.6
```

The debugger stopped exactly when strcmp was about to execute.

---

## Arguments in x86_64

In 64-bit architecture, function arguments are passed in registers rather than on the stack.
This is a performance decision made when processors moved from 32 to 64 bits:

| System | 1st argument | 2nd argument | GDB command |
|---|---|---|---|
| 32-bit (x86) | `$esp+4` | `$esp+8` | `x/s $esp+4` |
| 64-bit (x86_64) | `rdi` | `rsi` | `x/s $rsi` |

### Why RDI and RSI?

`RDI` (Destination Index) and `RSI` (Source Index) were originally designed for string
manipulation instructions in the 8086 (1978): `movsb`, `stosb`, `lodsb`, `rep movs`, `scasb`.
In those instructions RSI points to the source and RDI to the destination.

Their use for passing the first two function arguments is a modern convention from the
**System V AMD64 ABI**, decided when the 64-bit ISA was designed (~2003). It is not universal:
on Windows x64 the convention is different — `RCX`/`RDX` are used for the first two arguments.
Linux chose `RDI`/`RSI` specifically because the string instructions had fallen out of use,
leaving those registers effectively free.

For `strcmp`: **RDI holds your input, RSI holds the correct password.**

Full argument register table for x86_64:

| Argument | Register | Typical use |
|---|---|---|
| 1st | rdi | First parameter |
| 2nd | rsi | Second parameter |
| 3rd | rdx | Third parameter |
| 4th | rcx | Fourth parameter |
| 5th | r8 | Fifth parameter |
| 6th | r9 | Sixth parameter |
| 7th+ | Stack (`$rsp`) | When more than 6 arguments |

---

## Finding the password

```
(gdb) x/s $rdi
0x7fffffffe490: "Hola"

(gdb) x/s $rsi
0x5555555562cf: "s3cr3t0"
```

**The password is `s3cr3t0`.** We found it without reading a single line of assembly —
by stopping execution at the exact moment of the comparison and reading the registers directly.

---

## Why does the address not change between runs?

One would expect ASLR to randomize the address of strcmp on every execution, yet
`0x7ffff7d73210` appears identical across runs. The reason is not that ASLR is disabled
on the system — **GDB disables ASLR by default for the process it is debugging.** This is
a debugger convenience, not an OS property.

The address `0x7ffff7...` is the classic signature of libc loaded with ASLR off under GDB.
With ASLR active you would see a completely different base on each run.

Within a single execution, all libc functions have fixed relative offsets from that base.
This is the primitive that powers **ret2libc attacks**: if you can leak a single libc pointer,
you can calculate the address of any other function by subtracting its known offset.

---

## The AVX2 strcmp implementation

```
(gdb) x/20i $rip

=> 0x7ffff7d73210:  endbr64
   0x7ffff7d73214:  vpxor   %xmm15,%xmm15,%xmm15
   0x7ffff7d73219:  mov     %edi,%eax
   0x7ffff7d7321b:  or      %esi,%eax
   0x7ffff7d7321d:  shl     $0x14,%eax
   0x7ffff7d73220:  cmp     $0xf8000000,%eax
   0x7ffff7d73225:  ja      0x7ffff7d73550
   0x7ffff7d7322b:  vmovdqu (%rdi),%ymm0
   0x7ffff7d7322f:  vpcmpeqb (%rsi),%ymm0,%ymm1
   0x7ffff7d73233:  vpcmpeqb %ymm0,%ymm15,%ymm2
   0x7ffff7d73237:  vpandn  %ymm1,%ymm2,%ymm1
   0x7ffff7d7323b:  vpmovmskb %ymm1,%ecx
   0x7ffff7d7323f:  inc     %ecx
   0x7ffff7d73241:  je      0x7ffff7d732a0
   0x7ffff7d73243:  tzcnt   %ecx,%ecx
   0x7ffff7d73247:  movzbl  (%rdi,%rcx,1),%eax
   0x7ffff7d7324b:  movzbl  (%rsi,%rcx,1),%ecx
   0x7ffff7d7324f:  sub     %ecx,%eax
   0x7ffff7d73251:  vzeroupper
   0x7ffff7d73254:  ret
```

This is not the byte-by-byte loop from the simplified implementation. This is the
**glibc AVX2 implementation of strcmp**, comparing 32 bytes at once using SIMD instructions:

| Address | Instruction | Meaning |
|---|---|---|
| `0x...3210` | `endbr64` | CET security — marks valid jump target |
| `0x...3214` | `vpxor %xmm15,%xmm15,%xmm15` | Zero out ymm15 (all bytes = 0) |
| `0x...3219` | `mov %edi,%eax` | Copy s1 address to eax for page-boundary check |
| `0x...321b` | `or %esi,%eax` | OR with s2 address (combines high bits of both pointers) |
| `0x...321d` | `shl $0x14,%eax` | Shift to isolate bits indicating proximity to page boundary |
| `0x...3220` | `cmp $0xf8000000,%eax` | Check if either pointer is within 32 bytes of a 4KB page boundary |
| `0x...3225` | `ja 0x...3550` | If page-crossing risk, jump to safe fallback |
| `0x...322b` | `vmovdqu (%rdi),%ymm0` | Load 32 bytes of s1 into ymm0 |
| `0x...322f` | `vpcmpeqb (%rsi),%ymm0,%ymm1` | Compare 32 bytes of s2 against s1 byte-by-byte |
| `0x...3233` | `vpcmpeqb %ymm0,%ymm15,%ymm2` | Find null bytes in s1 |
| `0x...3237` | `vpandn %ymm1,%ymm2,%ymm1` | ymm1 = (NOT ymm2) AND ymm1 → marks equal non-null bytes |
| `0x...323b` | `vpmovmskb %ymm1,%ecx` | Extract one bit per byte → 32-bit mask in ecx |
| `0x...323f` | `inc %ecx` | If all 32 bytes matched and no null, ecx was 0xFFFFFFFF → inc makes it 0 |
| `0x...3241` | `je 0x...32a0` | ZF=1 → all 32 bytes equal and no null: jump to process next 32-byte block |
| `0x...3243` | `tzcnt %ecx,%ecx` | Count trailing zeros → position of first divergent byte |
| `0x...3247` | `movzbl (%rdi,%rcx,1),%eax` | Load s1 byte at first divergence position |
| `0x...324b` | `movzbl (%rsi,%rcx,1),%ecx` | Load s2 byte at first divergence position |
| `0x...324f` | `sub %ecx,%eax` | Subtract → strcmp return value |
| `0x...3251` | `vzeroupper` | Clear YMM registers (avoid transition penalty) |
| `0x...3254` | `ret` | Return |

---

## Back to main with `finish`

```
(gdb) finish

Run till exit from #0 0x00007ffff7d73210 in ?? () from /usr/lib/libc.so.6
0x000055555555578a in main () at crackme.c:12
12          if (strcmp(input, "s3cr3t0") == 0) {
```

We are now at the exact comparison point in `main`. Ten instructions decide everything:

```
=> 0x55555555578a <main+116>: test   %eax,%eax
   0x55555555578c <main+118>: jne    0x5555555557a4 <main+142>
   0x55555555578e <main+120>: lea    0xb42(%rip),%rax    # "Access granted"
   0x555555555795 <main+127>: mov    %rax,%rdi
   0x555555555798 <main+130>: call   0x55555555560c <print_ok>
   0x55555555579d <main+135>: mov    $0x0,%eax
   0x5555555557a2 <main+140>: jmp    0x5555555557b8 <main+162>
   0x5555555557a4 <main+142>: lea    0xb42(%rip),%rax    # "Access denied"
   0x5555555557ab <main+149>: mov    %rax,%rdi
   0x5555555557ae <main+152>: call   0x555555555691 <print_err>
```

### Execution flow

```
1. test %eax, %eax  →  eax == 0?
│
├── YES (eax == 0, strings match)
│   2. jne does NOT jump
│   3. lea "Access granted" → rax
│   4. mov rax → rdi
│   5. call print_ok
│   6. mov $0x0, %eax      (return 0)
│   7. jmp to end
│
└── NO (eax != 0, strings differ)
    2. jne JUMPS to 0x...57a4
    8. lea "Access denied" → rax
    9. mov rax → rdi
   10. call print_err
```

### Instruction-by-instruction breakdown

**1 — `test %eax, %eax`** (2 bytes: `85 c0`)  
Logical AND of eax with itself. Result is discarded, but flags are updated.
If eax == 0 → ZF = 1. Equivalent to `if (strcmp(...) == 0)` in C.

**2 — `jne 0x...57a4`** (2 bytes: `75 16`)  
Jump if Not Equal — fires when ZF = 0 (strings differ). Jump offset:
`0x...578c + 2 + 0x16 = 0x...57a4`. Confirmed.

**3 — `lea 0xb42(%rip), %rax`** (7 bytes: `48 8d 05 42 0b 00 00`)  
Loads the address of the "Access granted" string. RIP-relative addressing:
RIP points to the **next** instruction at the time of calculation.
`0x...578e + 7 = 0x...5795`, then `0x...5795 + 0xb42 = 0x...62d7`.

Verification:
```
(gdb) x/s 0x5555555562d7
0x5555555562d7: "Access granted"
```

**4 — `mov %rax, %rdi`** (3 bytes: `48 89 c7`)  
Moves the message address into rdi — first argument register for the upcoming call.

**5 — `call 0x...560c <print_ok>`** (5 bytes: `e8 6f fe ff ff`)  
Calls `print_ok`. Pushes the return address (`0x...579d`) onto the stack and jumps.
Relative offset: `0x...5798 + 5 + 0xfffffe6f = 0x...560c`. Confirmed.

**6 — `mov $0x0, %eax`** (5 bytes: `b8 00 00 00 00`)  
Sets the return value of `main` to 0 (success).

**7 — `jmp 0x...57b8`** (5 bytes: `e9 11 00 00 00`)  
Unconditional jump to the end of `main`, skipping the error branch.
`0x...57a2 + 5 + 0x11 = 0x...57b8`. Confirmed.

**8 — `lea 0xb42(%rip), %rax`** (7 bytes: `48 8d 05 42 0b 00 00`) — error branch  
Same principle, different target. `0x...57a4 + 7 = 0x...57ab`,
then `0x...57ab + 0xb42 = 0x...62ed`.

Verification:
```
(gdb) x/s 0x5555555562ed
0x5555555562ed: "Access denied"
```

**9 — `mov %rax, %rdi`** (3 bytes: `48 89 c7`)  
Moves the error message address into rdi for the call to `print_err`.

**10 — `call 0x...5691 <print_err>`** (5 bytes: `e8 de fe ff ff`)  
Calls `print_err`. `0x...57ae + 5 + 0xfffffede = 0x...5691`. Confirmed.

### Full summary table

| Address | Bytes (hex) | Instruction | Registers | Size | What it does |
|---|---|---|---|---|---|
| `0x...578a` | `85 c0` | `test %eax,%eax` | eax, flags | 2 | Check eax == 0 |
| `0x...578c` | `75 16` | `jne 0x...57a4` | flags | 2 | Jump if eax != 0 |
| `0x...578e` | `48 8d 05 42 0b 00 00` | `lea 0xb42(%rip),%rax` | rip, rax | 7 | Address of "Access granted" |
| `0x...5795` | `48 89 c7` | `mov %rax,%rdi` | rax, rdi | 3 | Prepare success message |
| `0x...5798` | `e8 6f fe ff ff` | `call print_ok` | rip, rsp | 5 | Call success function |
| `0x...579d` | `b8 00 00 00 00` | `mov $0x0,%eax` | rax | 5 | return 0 |
| `0x...57a2` | `e9 11 00 00 00` | `jmp 0x...57b8` | rip | 5 | Jump to end |
| `0x...57a4` | `48 8d 05 42 0b 00 00` | `lea 0xb42(%rip),%rax` | rip, rax | 7 | Address of "Access denied" |
| `0x...57ab` | `48 89 c7` | `mov %rax,%rdi` | rax, rdi | 3 | Prepare error message |
| `0x...57ae` | `e8 de fe ff ff` | `call print_err` | rip, rsp | 5 | Call error function |

---

## Notes

**`test` vs `cmp`**  
`test %eax, %eax` and `cmp $0, %eax` produce the same flags, but:
`test` is a logical AND — `cmp` is a subtraction. `test` is marginally faster
and is the standard idiom for checking whether a value is zero.

**`lea` vs `mov`**  
`lea` computes an address and stores it without accessing memory — no page fault risk.
`mov` reads from or writes to memory. `lea` is frequently used for pointer arithmetic
that does not require a memory dereference.

**`call` and the stack**  
`call` pushes the return address onto the stack before jumping. The corresponding `ret`
pops it and jumps back.

---

## Final verification

Kill the current process, run again with the correct password, confirm the `jne` does not
fire:

```
(gdb) kill
(gdb) run

Password: s3cr3t0

Breakpoint 1, 0x00007ffff7d73210 in ?? () from /usr/lib/libc.so.6

(gdb) finish
0x000055555555578a in main () at crackme.c:12
12          if (strcmp(input, "s3cr3t0") == 0) {

(gdb) stepi
0x000055555555578c   12    if (strcmp(input, "s3cr3t0") == 0) {

(gdb) stepi
13      print_ok("Correct! Well done.");
```

`jne` did not jump. Execution went straight to line 13 — `print_ok`.

**Crackme 1 solved.** The password was hardcoded in the binary, passed directly as the
second argument to `strcmp`, and visible by inspecting `$rsi` at the exact moment of
the comparison.

---

*Part of an ongoing crackme writeup series covering progressively harder binaries —
from hardcoded comparisons to obfuscated checks, custom hash functions, and anti-debug techniques.*

*All writeups: [ginomaihuiri.github.io](https://ginomaihuiri.github.io)*

---

© 2026 Aldair Maihuiri. All rights reserved.  
Sharing with attribution is welcome. Unauthorized reproduction is prohibited.
