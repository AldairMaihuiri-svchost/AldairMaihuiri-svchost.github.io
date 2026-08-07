---
title: "Crackme 02 — Numeric Serial: Deduction by Disassembly and Live Patching with Rust"
description: "Solving cm2_numeric: atoi behavior, reading cmpl with GDB, deducing the serial from the instruction, and implementing live patching via ptrace in Rust."
author: Aldair Maihuiri
date: 2026-08-07
---

[Leer en español](https://ginomaihuiri.github.io/crackmes/cm2-numeric-es)

# Crackme 02 — Numeric Serial: Deduction by Disassembly and Live Patching with Rust

**Author:** Aldair Maihuiri
**Date:** August 7, 2026
**Binary:** cm2_numeric (ELF 64-bit, PIE, not stripped)
**Tools:** GDB, objdump, Rust (nix crate)
**Tags:** `crackme` `reverse-engineering` `gdb` `x86_64` `atoi` `ptrace` `rust` `live-patching`

---

© 2026 Aldair Maihuiri. All rights reserved.
You may share this writeup with attribution. Reproduction without permission is prohibited.

---

## Initial recon

```
$ file ./crackme

./crackme: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV),
dynamically linked,
interpreter /lib64/ld-linux-x86-64.so.2,
BuildID[sha1]=78322b7005129073b4dd2da6e3b1fea092930383,
for GNU/Linux 4.4.0, with debug_info, not stripped
```

ELF 64-bit, dynamically linked, not stripped. The **PIE** flag (Position Independent
Executable) is the most important detail here: the OS assigns a random load base on
every execution. No address seen in GDB or in the disassembly is fixed on disk — every
runtime address is `load_base + file_offset`. This becomes critical when we implement
the live patcher.

---

## Identifying imported functions

Before opening the debugger, we check which external functions the binary uses:

```
$ objdump -T ./crackme | grep -i "strcmp\|atoi\|strtol\|sscanf\|scanf"

0000000000000000  DF *UND*  0000000000000000 (GLIBC_2.2.5) atoi
```

One result: `atoi`. This function converts a string to an integer:

```c
int atoi(const char *str);
```

Its behavior defines the entire crackme logic:

- Reads characters from the start as long as they are digits.
- Stops at the first non-digit character and returns what it has accumulated.
- If the first character is not a digit, returns 0 immediately.

The program does **not compare strings** — it compares integers. This is the key
difference from cm1, which used `strcmp`:

| | CM1 (strcmp) | CM2 (atoi) |
|---|---|---|
| Key function | `strcmp` | `atoi` |
| Secret type | String in `.rodata` | Immediate value in opcode |
| Visible with `strings`? | Yes | No |
| Useful breakpoint | `break strcmp` | `break atoi` |

The cm1 secret was a string in the data segment — visible to any string-extraction
tool. The cm2 secret is embedded inside the `cmp` instruction as an immediate operand.
It does not exist as a separate data object in the binary: it is part of the code.

---

## GDB analysis

### Strategy

Same logic as cm1: set the breakpoint at the function that processes the input (`atoi`),
let it run to completion with `finish`, and inspect the instructions that follow inside
`main`. The secret is there.

```
$ gdb ./crackme

(gdb) break atoi
Breakpoint 1 at 0x10a0

(gdb) run
```

```
╔══════════════════════════════════════════════
║ Nivel 1 · CM02  [*       ]
║ Serial numerico
╠══════════════════════════════════════════════
║ Solo un numero desbloquea el sistema.
╚══════════════════════════════════════════════

Serial: 99999

Breakpoint 1, 0x00007ffff7c3f780 in atoi () from /usr/lib/libc.so.6
```

The debugger stopped inside `atoi`, before the function does its work. `finish` runs it
to completion and returns to `main`:

```
(gdb) finish

Run till exit from #0  0x00007ffff7c3f780 in atoi ()
   from /usr/lib/libc.so.6
0x0000555555555780 in main () at crackme.c:12
12      int val = atoi(input);
```

We are now at `main+106`. The instructions that follow make the decision:

```
(gdb) x/10i $rip

=> 0x555555555780 <main+106>: mov    %eax,-0x114(%rbp)
   0x555555555786 <main+112>: cmpl   $0x539,-0x114(%rbp)
   0x555555555790 <main+122>: jne    0x5555555557a8 <main+146>
   0x555555555792 <main+124>: lea    0xb23(%rip),%rax        # 0x5555555562bc
   0x555555555799 <main+131>: mov    %rax,%rdi
   0x55555555579c <main+134>: call   0x55555555560c <print_ok>
   0x5555555557a1 <main+139>: mov    $0x0,%eax
   0x5555555557a6 <main+144>: jmp    0x5555555557bc <main+166>
   0x5555555557a8 <main+146>: lea    0xb1c(%rip),%rax        # 0x5555555562cb
   0x5555555557af <main+153>: mov    %rax,%rdi
```

### Instruction-by-instruction breakdown

**`main+106 — mov %eax, -0x114(%rbp)`**

In AT&T syntax, source comes first and destination second. This instruction **moves**
the content of `%eax` **into** the memory location `-0x114(%rbp)`.

`%eax` holds the return value of `atoi` — the integer just converted. `-0x114(%rbp)`
is the stack address where the compiler placed the local variable `val`. The stack
frame grows downward from `%rbp`, so local variables live at negative offsets:

```
[%rbp]              ← base of main's stack frame
...
[%rbp - 0x114]      ← variable "val" ← atoi return value stored here
```

This instruction is the assembly translation of `val = atoi(input)`.

**`main+112 — cmpl $0x539, -0x114(%rbp)`**

The serial is here.

The `l` suffix specifies 32-bit operands (the size of an `int`). The instruction
internally computes `val - 0x539` and updates the processor flags without modifying
either operand. If the result is zero, the Zero Flag (ZF) is set to 1.

`$0x539` is the immediate operand — the correct value, embedded directly inside the
instruction's bytes. It does not exist anywhere else in the binary as a data object.
`strings` will not find it.

```
(gdb) print 0x539
$1 = 1337
```

**The serial is 1337.**

**`main+122 — jne 0x5555555557a8`**

Jump if Not Equal: jumps if ZF=0, meaning the values differed. The jump target
(`main+146`) is the error branch. If it does not jump (val == 1337), execution falls
through to `main+124` and reaches `print_ok`.

### Full decision flow

```
atoi(input) → val

cmpl $1337, val → ZF = (val == 1337) ? 1 : 0

│
├── ZF = 1 → jne does NOT jump → print_ok → "Serial válido"
│
└── ZF = 0 → jne JUMPS        → print_err → "Serial inválido"
```

This structure is identical to cm1 (`test eax, eax → jne`). The function that produces
the value changes; the decision mechanics do not.

### Verification

```
(gdb) run

Serial: 1337

Breakpoint 1, 0x00007ffff7c3f780 in atoi () from /usr/lib/libc.so.6

(gdb) continue

  [+] Serial valido!
```

---

## Post-resolution: atoi behavior with non-numeric input

With the crackme solved, we investigate how the program responds to inputs that are not
pure numbers. The underlying question: if `atoi` returns 0 for any input starting with
a letter, and the correct serial were 0, any non-numeric input would pass validation.
That would be a real design bug — and reasoning this way is exactly what moves from
solving crackmes to finding vulnerabilities.

To read the `atoi` return value at the exact moment it is available, we take advantage
of the position we land in after `finish`: at `main+106`, before the `mov` executes.
At that instant, the `atoi` result lives only in `%eax` — the return register.

```
(gdb) run
Serial: HolaMaihuiri

Breakpoint 1, 0x00007ffff7c3f780 in atoi () from /usr/lib/libc.so.6

(gdb) finish
0x0000555555555780 in main () at crackme.c:12
12      int val = atoi(input);

(gdb) print $eax
$2 = 0
```

`atoi("HolaMaihuiri")` returns 0. The first character is a letter, no digits are accumulated.

`stepi` executes the `mov` so the value is written to memory, letting us verify
both sides agree:

```
(gdb) stepi
13      if (val == 0x539) {

(gdb) x/d $rbp - 0x114
0x7fffffffe4ac: 0
```

`x/d` examines the address `rbp - 0x114` and interprets its content as a signed decimal
integer. It matches `%eax`. Full behavior table:

| Input | atoi return | Passes? | Why |
|---|---|---|---|
| `1337` | 1337 | ✅ | Exact match |
| `HolaMaihuiri` | 0 | ❌ | First character is not a digit |
| `123HolaMaihuiri` | 123 | ❌ | Stops at 'H', returns accumulated value |
| `1337abc` | 1337 | ✅ | Stops at 'a', already accumulated 1337 |

The last case is the most interesting: `1337abc`, `1337!!!`, `1337anything` all pass
validation. `atoi` stops at the first non-digit and returns whatever it has accumulated.
It does not raise an error or return -1 — it silently drops the rest. In a real-world
context, this lenient parsing can become an input manipulation vector.

---

## Extracting the jne offset

For the live patcher we need the **file offset of the `jne`**, not the runtime address
— which changes on every execution due to PIE. `objdump` operates on the file on disk
and gives us exactly that:

```
$ objdump -d ./crackme | grep -A2 "cmpl.*0x539"

    1786:   81 bd ec fe ff ff 39    cmpl   $0x539,-0x114(%rbp)
    178d:   05 00 00
    1790:   75 16                   jne    17a8 <main+0x92>
```

| File offset | Bytes | Instruction |
|---|---|---|
| `0x1786` | `81 bd ec fe ff ff 39 05 00 00` | `cmpl $0x539, -0x114(%rbp)` |
| `0x1790` | `75 16` | `jne 17a8` |

The `jne` is at file offset `0x1790`. Its runtime address is `load_base + 0x1790`.
The tracer process must resolve that base before it can intervene.

---

## Live patching with Rust and ptrace

### Concept

The resolution above found the serial by reading the binary. This phase does not look
for the serial at all — it bypasses the comparison entirely.

The technique is **CPU state manipulation via ptrace**: we intervene in the internal
state of the processor at the exact moment of the decision, without touching the binary
on disk.

The plan:

1. A Rust process attaches to the crackme as a tracer via `ptrace`.
2. It writes `0xCC` (`int3`) at the `jne` address — this is how a CPU-level breakpoint works.
3. When the process stops at that breakpoint, it modifies one bit in `EFLAGS`: the Zero
   Flag (ZF), bit 6.
4. It restores the original `jne` byte and corrects `RIP`.
5. On resume, the `jne` reads ZF=1, interprets the comparison as successful, and does
   not jump.
6. "Serial válido" with any input.

### Why ptrace

`ptrace` is the kernel syscall that GDB is built on. Every breakpoint, every `stepi`,
every register read in this writeup went through `ptrace`. Here we use it directly,
without any intermediary.

`ptrace` has no "set breakpoint" request. A breakpoint is constructed: write `0xCC` at
the target address with `POKEDATA`, the CPU generates an interrupt when it executes it,
the kernel notifies the tracer. GDB does exactly this every time you type `break`. Here
we do it manually.

### Project structure

```
$ cargo new cm2_patcher
$ cd cm2_patcher
```

`Cargo.toml`:

```toml
[package]
name = "cm2_patcher"
version = "0.1.0"
edition = "2021"

[dependencies]
nix = { version = "0.29", features = ["ptrace", "process", "signal"] }
```

### Source code

`src/main.rs`:

```rust
use nix::sys::ptrace;
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{fork, ForkResult, execv, Pid};
use std::ffi::CString;
use std::fs;

// jne file offset, extracted with objdump
const JNE_OFFSET: u64 = 0x1790;

/// Reads /proc/<pid>/maps to resolve the binary's load base address.
/// Required because the binary is PIE: the base is randomized on every execution.
fn get_load_base(pid: i32) -> u64 {
    let maps = fs::read_to_string(format!("/proc/{}/maps", pid)).unwrap();
    for line in maps.lines() {
        if line.contains("crackme") {
            let base = line.split('-').next().unwrap();
            return u64::from_str_radix(base, 16).unwrap();
        }
    }
    panic!("load base not found in /proc/{}/maps", pid);
}

fn run_tracer(child: Pid) {
    // Wait for the child to stop after execv
    // The kernel automatically stops the tracee when it calls execv
    waitpid(child, None).expect("initial waitpid failed");

    // Compute the runtime address of the jne
    let base = get_load_base(child.as_raw());
    let jne_addr = base + JNE_OFFSET;
    println!("[*] load base : {:#x}", base);
    println!("[*] jne at    : {:#x}", jne_addr);

    // PEEKDATA: read the 8-byte word at jne_addr
    // Save the original value so we can restore it later
    let original = ptrace::read(child, jne_addr as *mut _)
        .expect("PEEKDATA failed");

    // Replace the low byte with 0xCC (int3)
    // The upper 7 bytes are preserved with the & !0xff mask
    let with_bp = (original & !0xff) | 0xCC;
    ptrace::write(child, jne_addr as *mut _, with_bp as i64)
        .expect("POKEDATA (breakpoint) failed");
    println!("[*] breakpoint placed at jne (0xCC)");

    // CONT: resume — the crackme will prompt for the serial
    ptrace::cont(child, None).expect("cont failed");

    // Wait for the process to stop when it executes the 0xCC
    match waitpid(child, None).expect("waitpid failed") {
        WaitStatus::Stopped(_, _) => {
            println!("[*] breakpoint hit — forcing ZF=1");

            // GETREGS: read all registers from the stopped process
            let mut regs = ptrace::getregs(child).expect("GETREGS failed");

            // Force ZF = 1 in EFLAGS (bit 6, mask 0x40)
            // The jne will read ZF=1 and interpret the comparison as "equal"
            regs.eflags |= 0x40;

            // RIP correction:
            // When the CPU executes 0xCC, RIP advances one byte past the breakpoint.
            // We step it back so that on resume the CPU executes the original jne.
            regs.rip -= 1;

            // Restore the original jne byte (remove the 0xCC)
            ptrace::write(child, jne_addr as *mut _, original as i64)
                .expect("POKEDATA (restore) failed");

            // SETREGS: write the modified registers back to the process
            ptrace::setregs(child, regs).expect("SETREGS failed");

            // CONT: resume — the jne reads ZF=1 and does not jump
            ptrace::cont(child, None).expect("final cont failed");
            waitpid(child, None).ok();
            println!("[*] done");
        }
        other => println!("unexpected stop status: {:?}", other),
    }
}

fn main() {
    match unsafe { fork() }.expect("fork failed") {
        ForkResult::Child => {
            // The child offers itself to be traced by its parent
            ptrace::traceme().expect("TRACEME failed");
            // Replace the process image with the crackme
            let path = CString::new("./crackme").unwrap();
            execv(&path, &[] as &[CString]).expect("execv failed");
        }
        ForkResult::Parent { child } => {
            run_tracer(child);
        }
    }
}
```

### ptrace calls reference

| Call | Internal request | What it does |
|---|---|---|
| `ptrace::traceme()` | `PTRACE_TRACEME` | Child tells the kernel to accept being traced by its parent |
| `waitpid` | — | Parent waits for the tracee to stop |
| `ptrace::read` | `PTRACE_PEEKDATA` | Reads an 8-byte word from the tracee's memory |
| `ptrace::write` | `PTRACE_POKEDATA` | Writes an 8-byte word to the tracee's memory |
| `ptrace::cont` | `PTRACE_CONT` | Resumes tracee execution |
| `ptrace::getregs` | `PTRACE_GETREGS` | Reads all registers from the tracee |
| `ptrace::setregs` | `PTRACE_SETREGS` | Writes all registers back to the tracee |

### Why RIP -= 1

When the CPU executes `0xCC` at address `jne_addr`, RIP points to the byte immediately
after — `jne_addr + 1`. Resuming without correction would execute whatever is at that
position, skipping the `jne` entirely.

`rip -= 1` brings it back to `jne_addr`. Since we restore the original byte before
resuming, the CPU executes the real `jne` (`75 16`) with ZF=1 already set in `eflags`
and does not jump.

### Build

```
$ cargo build

   Compiling cm2_patcher v0.1.0
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 4.24s
```

### Test

The crackme binary must be in the same directory as the patcher:

```
$ cp ../crackme .
$ ./target/debug/cm2_patcher
```

```
╔══════════════════════════════════════════════
║ Nivel 1 · CM02  [*       ]
║ Serial numerico
╠══════════════════════════════════════════════
║ Solo un numero desbloquea el sistema.
╚══════════════════════════════════════════════

  Serial     : HolaMaihuiri

[*] load base : 0x555555554000
[*] jne at    : 0x555555555790
[*] breakpoint placed at jne (0xCC)
[*] breakpoint hit — forcing ZF=1
  [+] Serial valido!
[*] done
```

Any input — letters, arbitrary numbers, symbols — produces "Serial válido".

The binary on disk was not modified.
The serial was never consulted.
The internal CPU state was intervened at the exact moment of the decision.

---

## cm1 vs cm2 — comparison

| Aspect | CM1 (strcmp) | CM2 (numeric) |
|---|---|---|
| Key function | `strcmp` | `atoi` |
| Secret type | String in `.rodata` | Immediate in `cmpl` opcode |
| Visible with `strings`? | Yes | No |
| How to find it | `break strcmp` → `x/s $rsi` | `break atoi` → `finish` → `x/10i $rip` |
| Relevant return value | Pointer to string | Integer in `%eax` |
| Extra technique | — | Live patching via ptrace in Rust |
| What was manipulated | — | EFLAGS — Zero Flag (ZF) |

---

*Part of a crackme writeup series covering progressively harder binaries — from
hardcoded comparisons to obfuscated checks, custom hash functions, and anti-debug
techniques.*

*Challenge binaries available at
[github.com/GinoMaihuiri/Crackmes](https://github.com/GinoMaihuiri/Crackmes)*

*All writeups: [ginomaihuiri.github.io](https://ginomaihuiri.github.io)*

---

© 2026 Aldair Maihuiri. All rights reserved.
Sharing with attribution is welcome. Unauthorized reproduction is prohibited.
