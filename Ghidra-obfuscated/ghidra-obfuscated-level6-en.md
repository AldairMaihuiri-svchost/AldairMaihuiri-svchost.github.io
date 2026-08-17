---
title: "Ghidra vs. Obfuscated Binaries — Level 6: State Machine and Binary Payload Delivery"
description: "Sixth level of the Ghidra reverse-engineering training series on obfuscated binaries. A PE32+ crackme that validates its password through a state machine of bit rotations and hash-like constants, fed by a stack buffer overflow that spreads the ten input bytes across separate local variables. Breaking the algorithm with Z3 was only half the problem: the solution key contains non-printable bytes that neither a keyboard nor a naive Wine pipe can deliver intact."
author: Aldair Maihuiri
---

# Ghidra vs. Obfuscated Binaries — Level 6: State Machine and Binary Payload Delivery

**Gino Aldair Maihuiri Romero**

([versión en español](ghidra-obfuscated-level6)) · ([Level 1](ghidra-obfuscated-level1-en)) · ([Level 2](ghidra-obfuscated-level2-en)) · ([Level 3](ghidra-obfuscated-level3-en)) · ([Level 4](ghidra-obfuscated-level4-en)) · ([Level 5](ghidra-obfuscated-level5-en))

This level calls for a different kind of understanding than the previous five, and I want to be precise about in what sense it does. It isn't the hardest binary to read in the series — the validation function fits on a single screen, and there are no vtables, no factory tables, no C++ involved. But it's the first one where finding the correct algorithm and solving it mathematically isn't enough to finish the job. The key the binary demands turned out to be a sequence of ten raw bytes, several of them outside the printable character range, and getting those exact bytes to arrive intact at the standard input of a Windows executable running under Wine ended up being as real a problem as the cryptanalysis itself. That final stretch — delivery engineering, not algorithm-breaking — is the part most worth documenting carefully here, because it's where I stumbled the most.

Same setup as always: Linux, a Windows PE32+ binary, static analysis in Ghidra first, verification with Wine at the end.

---

## Reconnaissance and a direct hit

This time I went straight to `Defined Strings` from the start, skipping `strncmp` and any C++ detour entirely. I found `"Password: "` at `140004050`, with a single reference to `FUN_140001580`. That function is the crackme's entire logic:

```c
undefined8
FUN_140001580(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4)
{
  uint uVar1;
  char cVar2;
  FILE *pFVar3;
  char *pcVar4;
  size_t sVar5;
  uint local_4c;
  byte local_48 [4];
  byte local_44;
  undefined1 local_43;
  undefined1 local_42;
  byte local_41;
  byte local_40;
  byte local_3f;

  FUN_140001820();
  FUN_140002a40("Password: ",param_2,param_3,param_4);
  pFVar3 = (FILE *)__acrt_iob_func(1);
  fflush(pFVar3);
  pFVar3 = (FILE *)__acrt_iob_func(0);
  pcVar4 = fgets((char *)local_48,0x40,pFVar3);
  if (pcVar4 != (char *)0x0) {
    sVar5 = strcspn((char *)local_48,"\n");
    local_48[sVar5] = 0;
    sVar5 = strlen((char *)local_48);
    local_4c = 0;
    cVar2 = '\0';
    do {
      switch(cVar2) {
      case '\0':
        if ((int)sVar5 == 10) {
          local_4c = 0x1234abcd;
          cVar2 = '\x01';
        }
        else {
          cVar2 = '\x06';
        }
        break;
      case '\x01':
        local_4c = local_4c ^ ((uint)local_48[0] << 0x18 | (uint)local_48[1] << 0x10);
        local_4c = local_4c << 7 | local_4c >> 0x19;
        cVar2 = '\x02';
        break;
      case '\x02':
        uVar1 = local_4c + (uint)local_48[2] * 0x1337 + (uint)local_48[3] * 0xbeef ^ (uint)local_44;
        local_4c = uVar1 >> 3 | uVar1 << 0x1d;
        cVar2 = '\x03';
        break;
      case '\x03':
        local_4c = (local_4c ^ CONCAT11(local_43,local_42)) * 0x1000193 ^ (uint)local_41;
        cVar2 = '\x04';
        break;
      case '\x04':
        local_4c = local_4c + (uint)local_40 * 7 + (uint)local_3f * 0xd;
        local_4c = local_4c ^ local_4c >> 0x10;
        cVar2 = (local_4c != 0xeb42f0aa) + '\x05';
        break;
      case '\x05':
        puts("[+] Correcto!");
        return 0;
      default:
        puts("[-] Incorrecto.");
        return 1;
      }
    } while( true );
  }
  return 1;
}
```

A single jump from the string put me in front of the entire validation. This level's complexity isn't in getting here — it's in what's inside.

## The buffer Ghidra sees incorrectly on purpose

The first thing that stands out is the local variable signature:

```c
uint local_4c;
byte local_48 [4];
byte local_44;
undefined1 local_43;
undefined1 local_42;
byte local_41;
byte local_40;
byte local_3f;
```

`local_48` is declared as a 4-byte array, but the read is `fgets((char *)local_48,0x40,pFVar3)` — up to 64 bytes. And the length check demands `sVar5 == 10`, exactly ten characters. That's more than fits in the 4 bytes Ghidra assigned to `local_48`.

The explanation lies in how the local variables are laid out on the stack: `local_48`, `local_44`, `local_43`, `local_42`, `local_41`, `local_40`, and `local_3f` are contiguous, consecutive addresses in memory — the hex names practically give it away: 0x48, 0x44, 0x43, 0x42, 0x41, 0x40, 0x3f, each one byte closer to the top of the stack than the previous one. When `fgets` writes ten bytes starting at `local_48`, the first four land inside the declared array, and the remaining six spill over onto the neighboring variables, one at a time:

```
local_48[0..3]  → input bytes 0-3
local_44        → byte 4
local_43        → byte 5
local_42        → byte 6
local_41        → byte 7
local_40        → byte 8
local_3f        → byte 9
```

Ghidra isn't wrong to declare `local_48` as 4 bytes — that's the only amount of memory the compiler reserved under that name — what's happening is that the rest of the ten-byte buffer lives spread across variables Ghidra named separately because it never saw a ten-byte array declaration in the original source. The program as a whole, though, does treat those seven names as a single contiguous buffer, and understanding the validation means doing the same: reading `local_48[0]`, `local_48[1]`, `local_48[2]`, `local_48[3]`, `local_44`, `local_43`, `local_42`, `local_41`, `local_40`, `local_3f` as input bytes 0 through 9, in that order.

## The state machine

The `switch` inside the `do { } while(true)` implements a six-step state machine, driven by `cVar2`. Each state consumes a pair of input bytes and transforms a 32-bit accumulator, `local_4c`, starting at `0x1234abcd`:

- **State 0** — checks the length is exactly 10; if not, it jumps straight to the default state (failure).
- **State 1** — combines bytes 0 and 1 with a positional XOR (`byte0 << 24 | byte1 << 16`) against the accumulator, and rotates the result left by 7 bits.
- **State 2** — multiplies byte 2 by `0x1337` and byte 3 by `0xbeef`, adds both products to the accumulator, XORs with byte 4, and rotates the result right by 3 bits.
- **State 3** — concatenates bytes 5 and 6 into a 16-bit value (`CONCAT11` in Ghidra's notation: first argument as the high byte, second as the low byte), XORs against the accumulator, multiplies the whole thing by `0x1000193` — the standard FNV-1a prime, though the full structure here isn't a generic FNV-1a anymore, it's the author's own mix — and XORs with byte 7.
- **State 4** — multiplies byte 8 by 7 and byte 9 by `0xd`, adds both to the accumulator, XORs the result against itself shifted right by 16 bits, and compares the final value against the constant `0xeb42f0aa`.
- **State 5 / default** — prints the success or error message based on that comparison's result.

This isn't a published, recognizable hash algorithm like level 4's FNV-1a — it borrows one of its constants, but the mix of rotations, multiplications by arbitrary constants (`0x1337`, `0xbeef`, `7`, `0xd`), and positional XORs is a construction of the crackme author's own. That doesn't change the solving strategy: it's still a chain of operations that are individually reversible, just chained in a way that isn't worth unwinding by hand term by term.

## Solving with Z3

With six steps of bit mixing, rotations, and constant products, setting up the inverse equation by hand is exactly the kind of work an SMT solver handles better than a person. I modeled the password's ten bytes as symbolic 8-bit variables, reproduced each state of the machine as an operation on those variables, and asked Z3 to find an assignment that made the final accumulator equal `0xeb42f0aa`.

The first attempt found no solution, and the reason was a precision detail that's easy to miss when translating C to Z3: in the original code, `local_4c` is `uint` — unsigned — so its right shifts (`>>`) are logical, filling with zeros. Z3's `>>` operator on a `BitVec`, by contrast, is arithmetic by default: it preserves the most significant bit as if it were a sign bit. For the rotations and the final shift in state 4, that produces a different result from the real binary as soon as the high bit is set to 1. The fix is to use `LShR` (*logical shift right*) instead of `>>` everywhere the C code operates on an unsigned integer.

With that fix, the script did find a solution — but an impractical one: it contained a `0x00` byte in one of the middle positions. The binary reads input with `fgets` and measures its length with `strlen`, and `strlen` stops at the first null byte. A password with a `0x00` in the middle doesn't measure ten bytes to `strlen`, no matter how many real bytes were actually written — state 0's length check would fail before ever reaching the state machine. I added the constraint `p != 0` for every symbolic byte and solved again.

```python
from z3 import *

password = [BitVec(f'p_{i}', 8) for i in range(10)]

def rol(val, r):
    return (val << r) | LShR(val, (32 - r))

def ror(val, r):
    return LShR(val, r) | (val << (32 - r))

local_4c = BitVecVal(0x1234abcd, 32)

# Estado 1
part1 = ZeroExt(24, password[0]) << 24 | ZeroExt(24, password[1]) << 16
local_4c = local_4c ^ part1
local_4c = rol(local_4c, 7)

# Estado 2
p2 = ZeroExt(24, password[2]) * 0x1337
p3 = ZeroExt(24, password[3]) * 0xbeef
p4 = ZeroExt(24, password[4])
uVar1 = local_4c + p2 + p3 ^ p4
local_4c = ror(uVar1, 3)

# Estado 3
concat_5_6 = ZeroExt(24, password[5]) << 8 | ZeroExt(24, password[6])
p7 = ZeroExt(24, password[7])
local_4c = (local_4c ^ concat_5_6) * 0x1000193 ^ p7

# Estado 4
p8 = ZeroExt(24, password[8])
p9 = ZeroExt(24, password[9])
local_4c = local_4c + p8 * 7 + p9 * 0xd
local_4c = local_4c ^ LShR(local_4c, 16)

s = Solver()
s.add(local_4c == 0xeb42f0aa)

# Sin bytes nulos: strlen() cortaría la cadena antes de tiempo
for p in password:
    s.add(p != 0)

if s.check() == sat:
    m = s.model()
    raw_bytes = bytes([m[p].as_long() for p in password])
    print(f"[+] Clave en hexadecimal: {raw_bytes.hex()}")
else:
    print("[-] No hay solución.")
```

I kept the script's own comments in Spanish, exactly as I wrote them at the time. This time it returned a consistent result:

```
[+] Clave en hexadecimal: c941426d6aae414da5e1
```

Before trusting the result, I rewrote the full state machine in plain Python — no Z3, with the concrete ten bytes already in hand — to confirm it actually produces `0xeb42f0aa`. The math checks out: `c9 41 42 6d 6a ae 41 4d a5 e1` goes through all four states and lands exactly on the expected value.

## The real obstacle: getting raw bytes to a Windows binary

With the key mathematically confirmed, the problem should have ended there. It didn't. `c941426d6aae414da5e1` is hexadecimal — the readable representation of ten bytes, several of which don't correspond to any character you can type from a keyboard (`0xc9`, `0xae`, `0xa5`, `0xe1` aren't printable ASCII). Trying to type or paste that string directly into `wine crackme.exe`'s prompt doesn't send the bytes `0xc9 0x41 0x42...` — it sends the literal text characters `c`, `9`, `4`, `1`, `4`, `2`..., a completely different input, more than ten bytes long, and not the binary sequence the state machine expects at all.

The first attempt to fix this was generating the raw bytes from Python and piping them through a standard Linux pipe: `python get_key.py | wine crackme.exe`. It failed with a Wine error entirely unrelated to the crackme's logic: `Application could not be started, or no application associated with the specified file` / `ShellExecuteEx failed: File not found`. Wine wasn't interpreting the pipe as standard input to the Windows process the way I expected.

The second attempt automated everything from Python using `subprocess`, launching `wine crackme.exe` as a child process and feeding it the bytes through its `stdin` directly via `communicate(input=raw_bytes)`. This did sidestep the shell-pipe issue, but it still failed — and the cause, this time, was more mundane: the script wasn't running in the same directory where `crackme.exe` actually lived, so Wine simply couldn't find the executable. Copying the binary into the script's working directory fixed that particular error, but by then I'd decided that automating the full execution wasn't what I actually wanted — I just needed the key in a form I could enter myself, by hand, under my own control.

The solution that finally worked was simpler than any of the previous attempts: generate the raw bytes with a single line of Python and pipe them directly to Wine, no intermediate scripts, no extra automation:

```bash
python -c "import sys; sys.stdout.buffer.write(bytes.fromhex('c941426d6aae414da5e1'))" | wine crackme.exe
```

```
Password: [+] Correcto!
```

Ten exact bytes, written as raw binary to Python's standard output, piped directly as Wine's standard input — never passing through a terminal's text interpretation at any point along the way.

## Analysis summary

This level cleanly separates two skills that in previous levels usually got solved with the same tool:

- **A buffer scattered across separately named variables.** A 4-byte `local_48`, followed by six 1-byte variables, contiguous on the stack, together form the real ten-byte buffer the state machine consumes. Recognizing that Ghidra names separately what the program treats as a single array is the first piece of the puzzle.
- **A state machine with its own bit-mixing, not a recognizable hash.** Rotations, multiplications by arbitrary constants, and positional XORs chained across four steps — solvable with Z3 the same way level 4's FNV-1a hash was, but without the advantage of recognizing standard constants from a published algorithm.
- **The `LShR` versus `>>` detail in Z3.** An arithmetic shift instead of a logical one on a variable that's `unsigned` in C produces a different equation than the real one, and the solver simply finds no solution — not because the model's structure is wrong, but because one specific operation doesn't reflect the original data type's exact semantics.
- **Narrowing the search space using the program's context, not just the algorithm.** The `p != 0` constraint doesn't come from the state machine itself — it comes from knowing the binary uses `fgets` followed by `strlen`, a fact that only shows up a few lines earlier in the same function, and that any mathematically valid solution containing a null byte would have violated in practice.
- **Finding the mathematically correct key isn't the same as being able to enter it.** When the solution is a sequence of non-printable bytes, the problem stops being cryptanalysis and becomes input engineering: how to get those exact bytes, without any text-encoding or shell-interpretation alteration, to arrive intact at the target process.

This level's lesson isn't in any single step — it's in the nature of its two halves: the first is a math problem a solver handles in seconds; the second is a systems problem — how a raw byte travels from a Python script to the `stdin` of a Windows binary running on a compatibility layer — that has no automatic shortcut and has to be solved by hand, one error at a time.

---

© 2026 Gino Aldair Maihuiri Romero
