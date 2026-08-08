---
title: "Crackme 05 — Transform Before Compare: The First Crackme Without strcmp"
description: "Solving cm5_transform: no comparison function in the IAT, length gate via strlen, custom transformation loop with lea arithmetic, unsigned char overflow analysis, GDB live verification, stack canary corruption and SSP bypass via ptrace in Rust."
author: Aldair Maihuiri
date: 2026-08-07
---

🇪🇸 [Leer en español](https://ginomaihuiri.github.io/crackmes/cm5-transform-es)

# Crackme 05 — Transform Before Compare: The First Crackme Without strcmp

**Author:** Aldair Maihuiri
**Date:** August 7, 2026
**Binary:** cm5_transform (ELF 64-bit, PIE, not stripped)
**Tools:** GDB, objdump, strings, Rust (nix crate)
**Tags:** `crackme` `reverse-engineering` `gdb` `x86_64` `transformation` `custom-comparison` `stack-canary` `ptrace`

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
BuildID[sha1]=7ed4c1480c09bad96fd6e42d38a45689f95b6aca,
for GNU/Linux 4.4.0, with debug_info, not stripped
```

ELF 64-bit, PIE, not stripped. The crackme announces its mechanism:

```
╔══════════════════════════════════════════════
║ Nivel 1 · CM05  [*       ]
║ Transform
╠══════════════════════════════════════════════
║ Cada caracter es transformado antes de comparar.
╚══════════════════════════════════════════════
```

"Each character is transformed before comparing." The program does not compare the
input directly — it applies a transformation to each character first, then compares
the result. This changes the entire analysis strategy.

---

## Static analysis — strings partially reveals the transformed values

```
$ strings ./crackme | head -50
```

Relevant output:

```
hwfh
hprj
Cada caracter es transformado antes de comparar.
Transform
Contrasena :
```

Two strings stand out: `hwfh` and `hprj`. They are not the password — they are the
**transformed expected values**, already processed through whatever function the
program applies to the input. Recognizing this distinction early is what separates
a shallow reading from a productive analysis.

Together they form an 8-byte sequence: `68 77 66 68 68 70 72 6a`. The password has
7 characters. The overlap comes from how two 32-bit `movl` instructions store values
on the stack — more on this in the disassembly section.

---

## Identifying imported functions — the critical absence

```
$ objdump -T ./crackme | grep -i "strcmp\|atoi\|strtol\|scanf\|strtoul\|memcmp\|strncmp"
```

No output.

**There is no string comparison function anywhere in the import table.** `strcmp`,
`memcmp`, `strncmp` — none of them. For the previous crackmes, the strategy was
`break strcmp` and read the registers. That approach is gone. The binary performs
its comparison manually inside `main` using a custom loop. The disassembly is the
only path forward.

---

## GDB — disassembling main

```
$ gdb ./crackme

(gdb) break main
Breakpoint 1 at 0x1711: file crackme.c, line 5.

(gdb) run
Breakpoint 1, main () at crackme.c:5

(gdb) disassemble main
```

The full disassembly divides into five sections.

### Section 1 — Stack canary (main+11 to main+24)

```asm
main+11:  mov  %fs:0x28, %rax       ; load canary from thread-local storage
main+20:  mov  %rax, -0x8(%rbp)     ; store canary on the stack
main+24:  xor  %eax, %eax
```

This is the first crackme in this series where GCC's **stack protection** (SSP) is
active. GCC (GNU Compiler Collection) is the compiler that translates C source code
into the binary — it inserts the canary mechanism automatically when compiling with
`-fstack-protector`, which modern Linux distributions enable by default.

At function entry, a random value called the **canary** is loaded from thread-local
storage (`%fs:0x28`) and stored just below the saved frame pointer. At function exit,
the stored value is compared against the original. If anything has modified it,
`__stack_chk_fail` is called and the program aborts before returning.

Two design details are worth noting. First, the canary is **randomized on every
execution** — generated when the process starts and stored in TLS. An attacker who
wants to bypass this check needs to know the current value, which changes each time.
Second, its **least significant byte is always `0x00`**: GCC forces this so that
string-based overflows (which stop at a null byte) cannot silently overwrite the
canary. We will see both properties confirmed when we test this mechanism after the
resolution.

### Section 2 — Expected values loaded on the stack (main+91 to main+111)

```asm
main+91:  movl  $0x68667768, -0x117(%rbp)
main+101: movl  $0x6a727068, -0x114(%rbp)
main+111: movl  $0x7, -0x11c(%rbp)
```

Two `movl` instructions storing the expected (transformed) values as 32-bit
little-endian immediates. In memory:

```
First movl  ($0x68667768) → 68 77 66 68
Second movl ($0x6a727068) → 68 70 72 6a
```

Both write to consecutive addresses with a one-byte overlap at `-0x114`. The
resulting buffer in memory order:

```
Address     Byte
-0x117      0x68    ← expected[0]
-0x116      0x77    ← expected[1]
-0x115      0x66    ← expected[2]
-0x114      0x68    ← expected[3]
-0x113      0x70    ← expected[4]
-0x112      0x72    ← expected[5]
-0x111      0x6a    ← expected[6]
```

Seven bytes. The third instruction — `movl $0x7` — confirms the program expects
exactly **7 characters**. This is why `strings` showed `hwfh` and `hprj`: the ASCII
representations of the 4-byte chunks written by each `movl`.

### Section 3 — Length check (main+121 to main+164)

```asm
main+121: lea   -0x110(%rbp), %rax
main+131: call  strlen@plt             ; eax = strlen(input)
main+136: cmp   %eax, -0x11c(%rbp)    ; compare strlen(input) with 7
main+142: je    main+166               ; if equal, proceed
main+154: call  print_err              ; "Longitud incorrecta."
main+164: jmp   main+280
```

The program validates the input length **before** entering the comparison loop.
If `strlen(input) != 7`, it prints "Longitud incorrecta." and exits immediately.
This also reveals the password length for static analysis: **7 characters**.

### Section 4 — Transformation and comparison loop (main+166 to main+258)

```asm
; Counter initialization
main+166: movl  $0x0, -0x120(%rbp)     ; i = 0
main+176: jmp   main+246               ; jump to condition (bottom-checking loop)

; Loop body
main+178: mov   -0x120(%rbp), %eax     ; eax = i
main+184: cltq                         ; sign-extend eax to rax
main+186: movzbl -0x110(%rbp,%rax,1), %eax  ; eax = input[i]
main+194: lea   0x5(%rax), %edx        ; edx = input[i] + 5  ← transformation
main+197: mov   -0x120(%rbp), %eax     ; eax = i (reload)
main+203: cltq
main+205: movzbl -0x117(%rbp,%rax,1), %eax  ; eax = expected[i]
main+213: cmp   %al, %dl              ; compare expected[i] with (input[i] + 5)
main+215: je    main+239              ; if equal, continue
main+227: call  print_err
main+237: jmp   main+280

; Counter increment and condition
main+239: addl  $0x1, -0x120(%rbp)    ; i++
main+246: mov   -0x120(%rbp), %eax
main+252: cmp   -0x11c(%rbp), %eax    ; compare i with 7
main+258: jl    main+178              ; if i < 7, loop back
```

**The transformation** at `main+194`: `lea 0x5(%rax), %edx`.

`lea` (Load Effective Address) is used here as pure arithmetic — it computes
`source + 5` and stores the result in the destination without accessing memory and
without modifying the source register. The compiler chooses `lea` over `add` because
it achieves `destination = source + immediate` in a single instruction with no side
effects on the source.

**The comparison** at `main+213` compares `%al` (expected[i]) with `%dl`
(input[i] + 5). If they differ, the program exits immediately.

**The loop condition** at `main+258` uses `jl` (signed less than) — runs while
`i < 7`, covering indices 0 through 6: seven comparisons for seven characters.

### Section 5 — Stack canary check (main+280 to main+301)

```asm
main+280: mov  -0x8(%rbp), %rdx       ; load stored canary into %rdx
main+284: sub  %fs:0x28, %rdx        ; subtract TLS canary from %rdx
main+293: je   main+300              ; if zero, return normally
main+295: call __stack_chk_fail      ; if non-zero, abort
main+300: leave
main+301: ret
```

The canary stored at function entry is verified here. If the subtraction produces
zero, the function returns normally. Any discrepancy triggers `__stack_chk_fail`.

---

## Understanding `(unsigned char)` — arithmetic types and overflow

The GDB debug symbols reveal the exact comparison expression:

```
Breakpoint 1, main () at crackme.c:20
20      if ((unsigned char)(input[i] + 5) != expected[i]) {
```

The cast `(unsigned char)` is a deliberate design decision.

When C evaluates `input[i] + 5`, the compiler **promotes** the `char` to `int`
before performing the addition. The result is a 32-bit integer. For most printable
ASCII characters this is harmless. But consider a character with ASCII value 252:

```
252 + 5 = 257
```

In binary, 257 requires 9 bits: `1 0000 0001`. A byte holds only 8. The ninth bit
has nowhere to go — it is discarded, and the result becomes `0000 0001 = 1`.

This is **integer overflow**: the value wraps around. Think of an odometer with only
3 digits: after 999 comes 000, not 1000. A byte behaves the same way, with a limit
of 255.

**The difference between `signed char` and `unsigned char`:**

A `signed char` reserves its highest bit (bit 7) as a sign bit, giving a range of
-128 to 127. An `unsigned char` uses all 8 bits for magnitude, giving 0 to 255.
By removing the special role of the sign bit, overflow becomes a clean, predictable
truncation — the extra bits are simply dropped, giving the result modulo 256.

The cast `(unsigned char)` makes this explicit:

```c
(unsigned char)(input[i] + 5)
```

It instructs the compiler: "take only the 8 low-order bits of this result." The
operation becomes equivalent to `(input[i] + 5) % 256`. The comparison is always
well-defined, regardless of the input value.

In this crackme, the password consists of standard lowercase ASCII (range 97–122).
Adding 5 produces values between 102 and 127 — no overflow is possible in practice.
The cast is defensive: it makes the intent explicit without relying on implicit
compiler behavior.

---

## Live verification in GDB

```
(gdb) break *main+194
Breakpoint 1 at 0x17c8: file crackme.c, line 20.

(gdb) run
Contrasena : crackme

Breakpoint 1, main () at crackme.c:20
20      if ((unsigned char)(input[i] + 5) != expected[i]) {

(gdb) print $rax
$1 = 99
```

`%rax` = 99 = `'c'` (ASCII 0x63).

```
(gdb) stepi

(gdb) print $edx
$2 = 104
```

`%edx` = 104 = `'h'` (ASCII 0x68). `'c' (99) + 5 = 104 = 'h'` = `expected[0]`.
Transformation confirmed live.

---

## Static recovery — no execution required

`password[i] = expected[i] - 5`:

| Index | Address | Expected byte | − 5 | Decimal | ASCII |
|---|---|---|---|---|---|
| 0 | `-0x117` | `0x68` | `0x63` | 99 | `c` |
| 1 | `-0x116` | `0x77` | `0x72` | 114 | `r` |
| 2 | `-0x115` | `0x66` | `0x61` | 97 | `a` |
| 3 | `-0x114` | `0x68` | `0x63` | 99 | `c` |
| 4 | `-0x113` | `0x70` | `0x6b` | 107 | `k` |
| 5 | `-0x112` | `0x72` | `0x6d` | 109 | `m` |
| 6 | `-0x111` | `0x6a` | `0x65` | 101 | `e` |

**Password: `crackme`** — recovered entirely from static analysis.

```python
expected = [0x68, 0x77, 0x66, 0x68, 0x70, 0x72, 0x6a]
print(''.join(chr(b - 5) for b in expected))
# Output: crackme
```

```
$ ./crackme
Contrasena : crackme
[+] Password valido!
```

---

## Post-resolution: Stack Canary — Corruption and Bypass via ptrace

Having resolved the crackme, the stack canary is the natural next subject. The same
ptrace primitive from cm2 can probe its behavior directly from outside the process.
Two scenarios, two Rust programs.

First, extracting the offsets needed:

```
$ objdump -d ./crackme | grep -A5 "fs:0x28"

    1711:  64 48 8b 04 25 28 00    mov    %fs:0x28,%rax
    171a:  48 89 45 f8             mov    %rax,-0x8(%rbp)     ← canary store offset

$ objdump -d ./crackme | grep -A2 "stack_chk_fail"

    181e:  48 8b 55 f8             mov    -0x8(%rbp),%rdx     ← loads canary into rdx
    1822:  64 48 2b 14 25 28 00    sub    %fs:0x28,%rdx        ← canary check offset
    182b:  74 05                   je     1832
    182d:  e8 2e f8 ff ff          call   1060 <__stack_chk_fail@plt>
```

Canary store: offset `0x171a`. Canary check: offset `0x1822`.

### Scenario 1 — Corrupting the canary

The script places a breakpoint at offset `0x171a`, lets the store execute via
single-step, reads the canary value from `rbp - 8`, overwrites it with
`0xDEADBEEFCAFEBABE`, and resumes. When execution reaches the check, the comparison
fails and `__stack_chk_fail` is called.

```
[*] load base         : 0x55e0a7a0b000
[*] canary store at   : 0x55e0a7a0c71a
[*] rbp               : 0x7fffb1681c10
[*] canary on stack at: 0x7fffb1681c08
[*] canary value      : 0x8964659be4698200
[*] canary corrupted with 0xDEADBEEFCAFEBABE
[*] resuming — expect stack smashing detected...

  Contrasena : crackme
  [+] Password valido!
*** stack smashing detected ***: terminated
```

Three observations:

**The canary is randomized.** Running the program again produces a completely
different value — an attacker cannot hardcode it.

**The low byte is always `0x00`.** Both `0x...698200` and `0x...b68f00` end in `00`.
GCC forces this to stop string-based overflows, which terminate at null bytes, from
silently overwriting the canary.

**The program printed "Password valido!" before crashing.** The canary check fires
at function exit, not during execution. Password validation succeeded — the crash is
entirely about stack integrity, independent of program logic.

**Script — Scenario 1:**

`Cargo.toml` (same for both scenarios):

```toml
[package]
name = "cm5_canary"
version = "0.1.0"
edition = "2021"

[dependencies]
nix = { version = "0.29", features = ["ptrace", "process", "signal"] }
```

`src/main.rs`:

```rust
use nix::sys::ptrace;
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{fork, ForkResult, execv, Pid};
use std::ffi::CString;
use std::fs;

// Offset of the canary store: main+20 — mov %rax, -0x8(%rbp)
const CANARY_STORE_OFFSET: u64 = 0x171a;

fn get_load_base(pid: i32) -> u64 {
    let maps = fs::read_to_string(format!("/proc/{}/maps", pid)).unwrap();
    for line in maps.lines() {
        if line.contains("crackme") {
            let base = line.split('-').next().unwrap();
            return u64::from_str_radix(base, 16).unwrap();
        }
    }
    panic!("load base not found");
}

fn run_tracer(child: Pid) {
    waitpid(child, None).expect("initial waitpid failed");

    let base = get_load_base(child.as_raw());
    let store_addr = base + CANARY_STORE_OFFSET;
    println!("[*] load base         : {:#x}", base);
    println!("[*] canary store at   : {:#x}", store_addr);

    // Breakpoint at the canary store instruction
    let orig_store = ptrace::read(child, store_addr as *mut _).expect("peek failed");
    ptrace::write(child, store_addr as *mut _, (orig_store & !0xff) | 0xCC)
        .expect("poke failed");

    ptrace::cont(child, None).expect("cont failed");

    match waitpid(child, None).expect("waitpid failed") {
        WaitStatus::Stopped(_, _) => {
            let mut regs = ptrace::getregs(child).expect("getregs failed");
            regs.rip -= 1;
            ptrace::write(child, store_addr as *mut _, orig_store as i64)
                .expect("restore failed");
            ptrace::setregs(child, regs).expect("setregs failed");

            // Single-step to execute the store
            ptrace::step(child, None).expect("step failed");
            waitpid(child, None).ok();

            // Read rbp to find canary address
            let regs = ptrace::getregs(child).expect("getregs failed");
            let canary_addr = regs.rbp - 8;
            let canary_value = ptrace::read(child, canary_addr as *mut _)
                .expect("read canary failed");

            println!("[*] rbp               : {:#x}", regs.rbp);
            println!("[*] canary on stack at: {:#x}", canary_addr);
            println!("[*] canary value      : {:#x}", canary_value as u64);

            // Corrupt the canary
            ptrace::write(child, canary_addr as *mut _, 0xDEADBEEFCAFEBABEu64 as i64)
                .expect("corrupt failed");
            println!("[*] canary corrupted with 0xDEADBEEFCAFEBABE");
            println!("[*] resuming — expect stack smashing detected...");

            ptrace::cont(child, None).expect("final cont failed");
            waitpid(child, None).ok();
        }
        other => println!("unexpected: {:?}", other),
    }
}

fn main() {
    match unsafe { fork() }.expect("fork failed") {
        ForkResult::Child => {
            ptrace::traceme().expect("traceme failed");
            let path = CString::new("./crackme").unwrap();
            execv(&path, &[] as &[CString]).expect("execv failed");
        }
        ForkResult::Parent { child } => {
            run_tracer(child);
        }
    }
}
```

### Scenario 2 — Bypassing the SSP

Restoring only the stack is not enough. Looking at the check sequence:

```asm
main+280: mov  -0x8(%rbp), %rdx    ← loads (corrupted) canary from stack into %rdx
main+284: sub  %fs:0x28, %rdx      ← our breakpoint fires HERE
main+293: je   main+300
main+295: call __stack_chk_fail
```

By the time our breakpoint at `0x1822` fires, `main+280` has already executed —
`%rdx` already holds the corrupted value `0xDEADBEEFCAFEBABE`. Both the stack
location and `%rdx` must be restored to the original canary value, or the subtraction
will not produce zero.

The bypass: two breakpoints (store and check), read the original canary, corrupt it,
then at the check restore both the stack location and `%rdx`.

```
[*] load base         : 0x5569c68b8000
[*] canary store at   : 0x5569c68b971a
[*] canary check at   : 0x5569c68b9822
[*] rbp               : 0x7ffe26143400
[*] canary on stack at: 0x7ffe261433f8
[*] canary value      : 0x6d89dc5a86b68f00
[*] canary corrupted with 0xDEADBEEFCAFEBABE
  [+] Password valido!
[*] canary restored on stack and in %rdx
[*] done — process exited cleanly, no crash
```

No crash. The SSP check passed cleanly.

**Script — Scenario 2:**

```rust
use nix::sys::ptrace;
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{fork, ForkResult, execv, Pid};
use std::ffi::CString;
use std::fs;

const CANARY_STORE_OFFSET: u64 = 0x171a;
const CANARY_CHECK_OFFSET: u64 = 0x1822;

fn get_load_base(pid: i32) -> u64 {
    let maps = fs::read_to_string(format!("/proc/{}/maps", pid)).unwrap();
    for line in maps.lines() {
        if line.contains("crackme") {
            let base = line.split('-').next().unwrap();
            return u64::from_str_radix(base, 16).unwrap();
        }
    }
    panic!("load base not found");
}

fn run_tracer(child: Pid) {
    waitpid(child, None).expect("initial waitpid failed");

    let base = get_load_base(child.as_raw());
    let store_addr = base + CANARY_STORE_OFFSET;
    let check_addr = base + CANARY_CHECK_OFFSET;
    println!("[*] load base         : {:#x}", base);
    println!("[*] canary store at   : {:#x}", store_addr);
    println!("[*] canary check at   : {:#x}", check_addr);

    // Breakpoint 1 — canary store
    let orig_store = ptrace::read(child, store_addr as *mut _).expect("peek store failed");
    ptrace::write(child, store_addr as *mut _, (orig_store & !0xff) | 0xCC)
        .expect("poke store failed");

    // Breakpoint 2 — canary check
    let orig_check = ptrace::read(child, check_addr as *mut _).expect("peek check failed");
    ptrace::write(child, check_addr as *mut _, (orig_check & !0xff) | 0xCC)
        .expect("poke check failed");

    ptrace::cont(child, None).expect("cont failed");

    // Breakpoint 1 fires: canary store
    match waitpid(child, None).expect("waitpid bp1 failed") {
        WaitStatus::Stopped(_, _) => {
            let mut regs = ptrace::getregs(child).expect("getregs bp1 failed");
            regs.rip -= 1;
            ptrace::write(child, store_addr as *mut _, orig_store as i64)
                .expect("restore store failed");
            ptrace::setregs(child, regs).expect("setregs bp1 failed");
            ptrace::step(child, None).expect("step failed");
            waitpid(child, None).ok();

            let regs = ptrace::getregs(child).expect("getregs after step failed");
            let canary_addr = regs.rbp - 8;
            let canary_original = ptrace::read(child, canary_addr as *mut _)
                .expect("read canary failed");

            println!("[*] rbp               : {:#x}", regs.rbp);
            println!("[*] canary on stack at: {:#x}", canary_addr);
            println!("[*] canary value      : {:#x}", canary_original as u64);

            ptrace::write(child, canary_addr as *mut _, 0xDEADBEEFCAFEBABEu64 as i64)
                .expect("corrupt canary failed");
            println!("[*] canary corrupted with 0xDEADBEEFCAFEBABE");

            ptrace::cont(child, None).expect("cont to check failed");

            // Breakpoint 2 fires: canary check
            match waitpid(child, None).expect("waitpid bp2 failed") {
                WaitStatus::Stopped(_, _) => {
                    let mut regs = ptrace::getregs(child).expect("getregs bp2 failed");
                    regs.rip -= 1;
                    ptrace::write(child, check_addr as *mut _, orig_check as i64)
                        .expect("restore check failed");

                    // Restore canary on stack
                    ptrace::write(child, canary_addr as *mut _, canary_original)
                        .expect("restore stack canary failed");

                    // Restore %rdx — main+280 already loaded the corrupted value into it
                    // before our breakpoint fired at main+284.
                    regs.rdx = canary_original as u64;

                    println!("[*] canary restored on stack and in %rdx");
                    ptrace::setregs(child, regs).expect("setregs bp2 failed");
                    ptrace::cont(child, None).expect("final cont failed");
                    waitpid(child, None).ok();
                    println!("[*] done — process exited cleanly, no crash");
                }
                other => println!("unexpected at check: {:?}", other),
            }
        }
        other => println!("unexpected at store: {:?}", other),
    }
}

fn main() {
    match unsafe { fork() }.expect("fork failed") {
        ForkResult::Child => {
            ptrace::traceme().expect("traceme failed");
            let path = CString::new("./crackme").unwrap();
            execv(&path, &[] as &[CString]).expect("execv failed");
        }
        ForkResult::Parent { child } => {
            run_tracer(child);
        }
    }
}
```

**What this demonstrates about SSP's actual security model:**

The stack canary is not a guarantee against all attacks — it is a guarantee against
uninformed ones. Its threat model assumes the attacker does not know the canary value.
If an attacker has a way to read process memory (an information leak vulnerability,
or process-level access as demonstrated here with ptrace), the canary can be read,
the overflow can happen, and the canary can be restored before the check fires.

Real bypass techniques in exploits follow the same pattern: leak the canary first,
corrupt the stack, overwrite the canary location with the leaked value before the
function returns. The null byte defense mitigates leaking via `printf` format strings
or string functions, but not via arbitrary read primitives.

Understanding the mechanism — not just that it exists, but how it works at the
instruction level — is what allows reasoning about when it holds and when it does not.

---

## Connection to real-world malware and the cm4/cm5 progression

In the context of this crackme series, cm4 and cm5 together represent the two layers
that LockBit combines in its obfuscation:

**cm4** demonstrates the **structural pattern**: building strings byte by byte with
individual `movb` instructions, so the data never exists as a contiguous sequence in
the binary. LockBit does exactly this for its DLL names.

**cm5** demonstrates the **obfuscation layer**: applying a transformation to the data
before storing it, so the stored value is not the plaintext. In cm5 the transformation
is a simple addition (`+5`). LockBit uses a per-string affine cipher — significantly
harder to invert without the parameters, but structurally identical: the binary stores
the transformed value, not the original.

LockBit applies both simultaneously: the bytes written by the `MOV BYTE PTR`
instructions are ciphertext, and a decryption loop runs immediately after construction.
Understanding cm4 and cm5 as separate concepts makes the combined mechanism in real
malware easier to decompose during analysis.

---

## cm1 / cm2 / cm3 / cm4 / cm5 — progression

| Aspect | CM1 | CM2 | CM3 | CM4 | CM5 |
|---|---|---|---|---|---|
| Key function | `strcmp` | `atoi` | `strcmp` | `strcmp` | **none** |
| Comparison | Library | Library | Library | Library | **manual loop** |
| Secret location | `.rodata` | `cmpl` opcode | Encrypted `movl` | Plaintext `movb` | Transformed `movl` |
| Length check | No | No | No | No | **Yes — strlen** |
| Transformation | None | None | XOR 0x13 | None | **+5 per char** |
| Visible with `strings`? | Yes | No | Partially | No | Partially (transformed) |
| Stack canary | No | No | No | No | **Yes** |
| New concept | Calling convention | Integer comparison | XOR obfuscation | Stack strings | Custom loop, transformation, canary, SSP bypass |

---

*Part of a crackme writeup series covering progressively harder binaries.*

*Challenge binaries: [github.com/GinoMaihuiri/Crackmes](https://github.com/GinoMaihuiri/Crackmes)*
*Tooling: [github.com/GinoMaihuiri/Crackmes/tree/main/tooling](https://github.com/GinoMaihuiri/Crackmes/tree/main/tooling)*
*All writeups: [ginomaihuiri.github.io](https://ginomaihuiri.github.io)*

---

© 2026 Aldair Maihuiri. All rights reserved.
Sharing with attribution is welcome. Unauthorized reproduction is prohibited.
