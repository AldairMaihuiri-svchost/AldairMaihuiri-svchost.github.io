---
title: "Ghidra vs. Obfuscated Binaries — Level 7: Mixed Boolean-Arithmetic and Dynamic Shellcode"
description: "Seventh level of the Ghidra reverse-engineering training series on obfuscated binaries. A PE32+ crackme that hides a standard FNV-1a hash behind mixed boolean-arithmetic identities (OR/AND instead of XOR, XOR plus carry instead of addition), and hides the comparison's target value inside a shellcode fragment the binary itself assembles and decrypts into executable memory before invoking it."
author: Aldair Maihuiri
---

# Ghidra vs. Obfuscated Binaries — Level 7: Mixed Boolean-Arithmetic and Dynamic Shellcode

**Gino Aldair Maihuiri Romero**

([versión en español](ghidra-obfuscated-level7)) · ([Level 1](ghidra-obfuscated-level1-en)) · ([Level 2](ghidra-obfuscated-level2-en)) · ([Level 3](ghidra-obfuscated-level3-en)) · ([Level 4](ghidra-obfuscated-level4-en)) · ([Level 5](ghidra-obfuscated-level5-en)) · ([Level 6](ghidra-obfuscated-level6-en))

This binary's folder is named `nivel7_mba`, and the acronym already hints at what's coming: mixed boolean-arithmetic obfuscation, a technique that doesn't encrypt or hide data — it rewrites simple operations, an XOR here, an addition there, as combinations of other operations that are mathematically equivalent but visually unrecognizable. This level stacks that technique on top of another one I'd already seen in level 6: the real validation doesn't live in the main function, it lives in a shellcode fragment the binary itself assembles and decrypts into executable memory before calling it. Between the two layers, I ended up making and then catching two mistakes of my own during the analysis, and both are documented here exactly as they happened, because they teach as much as the final result does.

Same setup as always: Linux, a Windows PE32+ binary, static analysis in Ghidra first, verification with Wine at the end.

---

## Reconnaissance and a direct hit

```
$ file crackme.exe
crackme.exe: PE32+ executable for MS Windows 5.02 (console), x86-64 (stripped to external PDB), 10 sections
```

I went straight to `Defined Strings`, skipping `strncmp` and any C++ detour, same as level 6. I found `"Password: "` at `14000406e`, with a single reference to `FUN_140002c20`. That function holds the crackme's entire orchestration logic.

## The main function: shellcode assembled in memory

```c
undefined8
FUN_140002c20(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4)
{
  uint uVar1;
  int iVar2;
  FILE *pFVar3;
  char *pcVar4;
  size_t sVar5;
  code *lpBaseAddress;
  longlong lVar6;
  HANDLE hProcess;
  DWORD flProtect;
  byte local_58 [72];

  FUN_1400016e0();
  FUN_140002900("Password: ",param_2,param_3,param_4);
  pFVar3 = (FILE *)__acrt_iob_func(1);
  fflush(pFVar3);
  pFVar3 = (FILE *)__acrt_iob_func(0);
  pcVar4 = fgets((char *)local_58,0x40,pFVar3);
  if (pcVar4 != (char *)0x0) {
    sVar5 = strcspn((char *)local_58,"\n");
    flProtect = 0x40;
    local_58[sVar5] = 0;
    uVar1 = FUN_140001580(local_58);
    lpBaseAddress = VirtualAlloc((LPVOID)0x0,0xe,0x3000,flProtect);
    if (lpBaseAddress != (code *)0x0) {
      *(undefined8 *)lpBaseAddress = 0xfc839cdb73089b8;
      lVar6 = 8;
      do {
        lpBaseAddress[lVar6] = (code)((&DAT_140004090)[lVar6] ^ 0x5a);
        lVar6 = lVar6 + 1;
      } while (lVar6 != 0xe);
      hProcess = GetCurrentProcess();
      FlushInstructionCache(hProcess,lpBaseAddress,0xe);
      iVar2 = (*lpBaseAddress)(uVar1);
      pcVar4 = "[-] Incorrecto.";
      if (iVar2 != 0) {
        pcVar4 = "[+] Correcto!";
      }
      puts(pcVar4);
      return 0;
    }
    puts("[-] Error interno.");
  }
  return 1;
}
```

The prompt, the read, and trimming the newline are the usual. What follows is the interesting part: the user's input never gets compared against anything directly here. Instead, it goes through `FUN_140001580` to produce a numeric value (`uVar1`), a page of executable memory gets reserved with `VirtualAlloc` (14 bytes, flags `0x3000` and `0x40` = `PAGE_EXECUTE_READWRITE`, the same pattern I'd already seen in level 5), 14 bytes of machine code get assembled into that page — 8 bytes written directly as a constant, 6 more decrypted with XOR against `0x5a` from `DAT_140004090` — the instruction cache gets flushed, and only then is that memory block invoked as if it were a function, passing `uVar1` as its only argument. That call's result decides the final message.

Two separate questions, then: what `FUN_140001580` does to the password, and what exactly the shellcode compares once assembled.

## Untangling the mixed boolean-arithmetic

```c
uint FUN_140001580(byte *param_1)
{
  byte bVar1;
  int iVar2;
  uint uVar3;
  uint uVar4;
  uint local_20;

  bVar1 = *param_1;
  local_20 = 0x811c9dc5;
  while (bVar1 != 0) {
    param_1 = param_1 + 1;
    iVar2 = (local_20 | bVar1) - (local_20 & bVar1);
    uVar3 = iVar2 * 0x1000000;
    uVar4 = iVar2 * 0x193;
    local_20 = (uVar3 ^ uVar4) + (uVar3 & uVar4) * 2;
    bVar1 = *param_1;
  }
  return local_20;
}
```

At first glance this doesn't look like anything recognizable, but every line is a disguised mathematical identity. I untangled them one at a time.

**The first line**, `iVar2 = (local_20 | bVar1) - (local_20 & bVar1)`, is a XOR written as OR minus AND. It checks out bit by bit: at any position where both bits match (00 or 11), OR and AND give the same value and the subtraction gives 0 — which is also what XOR gives at that position. At any position where the bits differ (01 or 10), OR gives 1 and AND gives 0, so the subtraction gives 1 — again, the same as XOR. No borrows propagate between positions because OR is never smaller than AND at any individual bit. The identity is exact: `(A | B) - (A & B) = A ^ B`.

**The last line**, `local_20 = (uVar3 ^ uVar4) + (uVar3 & uVar4) * 2`, is the inverse identity: an addition disguised as XOR plus carry. XORing two numbers gives their sum while ignoring carries between positions, and the AND multiplied by 2 reintroduces exactly those carries, shifted one position to the left where they belong. The identity `A + B = (A ^ B) + 2·(A & B)` is also exact, with no need to iterate it.

With both disguises stripped away, what's left is:

```
iVar2 = local_20 ^ current_byte
local_20 = (iVar2 * 0x1000000) + (iVar2 * 0x193)
         = iVar2 * (0x1000000 + 0x193)
```

Here I stopped to add the constant carefully, because this is exactly the kind of step where it's easy to slip in an extra digit without noticing while adding two hex numbers of different lengths in your head. `0x1000000` is seven hex digits; `0x193` is three. Aligned by the least significant digit:

```
  1000000
+     193
---------
  1000193
```

`0x1000000 + 0x193 = 0x1000193` — seven digits, not eight. And that value, `0x1000193`, is exactly the standard prime constant of the **32-bit FNV-1a** algorithm (`0x01000193`, with the leading zero not changing the value). `local_20`'s initial value, `0x811c9dc5`, is also FNV-1a's standard offset basis, sitting there undisguised. With that confirmed, `FUN_140001580` is nothing more than textbook FNV-1a, with its XOR step and its addition step rewritten through boolean identities so they wouldn't be recognizable at a glance in the decompiler.

## Why recognizing the algorithm isn't enough

FNV-1a is a one-way hash function — there's no way to algebraically solve for which string produced a given final value; the only option is to search for a string that reproduces it. And searching requires the target value, which doesn't appear anywhere in `FUN_140002c20` or `FUN_140001580`: the result of `uVar1` simply gets passed as an argument to the shellcode, and it's the shellcode — assembled at runtime, not before — that knows what to compare it against.

So the next step isn't mathematical yet. It's reconstructing the shellcode by hand, without running anything, and disassembling it.

## Reconstructing the shellcode, and the first mistake

The code writes the shellcode's first 8 bytes directly as a 64-bit constant:

```c
*(undefined8 *)lpBaseAddress = 0xfc839cdb73089b8;
```

To know what bytes end up in memory, you have to remember that x86-64 stores integers little-endian: the value's least significant byte goes at the lowest address. `0xfc839cdb73089b8` has 15 hex digits, so it needs padding to 16 with a leading zero: `0x0fc839cdb73089b8`. Grouping two digits at a time from the most significant end: `0f c8 39 cd b7 30 89 b8`. Reversing that order to get the memory sequence (from lowest address to highest): `b8 89 30 b7 cd 39 c8 0f`.

The remaining six bytes come from a loop:

```c
lVar6 = 8;
do {
  lpBaseAddress[lVar6] = (code)((&DAT_140004090)[lVar6] ^ 0x5a);
  lVar6 = lVar6 + 1;
} while (lVar6 != 0xe);
```

The index `lVar6` starts at 8, so the first byte read is `(&DAT_140004090)[8]` — that is, address `DAT_140004090 + 8 = 140004098`, not `DAT_140004090` itself. I went to that address in Ghidra's memory listing:

```
                             DAT_140004098                                   XREF[1]:     FUN_140002c20:140002ce0(R)
       140004098 ce              undefined1 CEh
                             DAT_140004099                                   XREF[1]:     FUN_140002c20:140002ce0(R)
       140004099 9a              undefined1 9Ah
       14000409a 55              ??         55h    U
       14000409b ec              ??         ECh
       14000409c 9a              ??         9Ah
       14000409d 99              ??         99h
```

Six bytes: `ce 9a 55 ec 9a 99`. Applying XOR with `0x5a` to each: `94 c0 0f b6 c0 c3`.

The first time I assembled the full 14-byte block, I made a transcription mistake: instead of using the first 8 bytes I'd just correctly calculated (`b8 89 30 b7 cd 39 c8 0f`), I ended up writing a completely different sequence that didn't correspond to anything real. Disassembling that wrong sequence gave it away immediately: after a first instruction that looked reasonable, everything else fell apart into instructions that made no sense in this context — a flag manipulation, a comparison against the stack pointer — none of which fit a simple 14-byte comparison block. A correctly reconstructed 14-byte shellcode has to disassemble cleanly, instruction after instruction, with nothing left over or missing at the end. When that doesn't happen, the reconstruction is wrong, not the disassembler.

I rebuilt the block with the correct bytes:

```
b8 89 30 b7 cd 39 c8 0f 94 c0 0f b6 c0 c3
```

And this time the disassembly was clean, complete, with no bytes left over:

```
mov eax, 0xcdb73089
cmp eax, ecx
sete al
movzx eax, al
ret
```

Five instructions, `5 + 2 + 3 + 3 + 1 = 14` bytes exactly. `ECX` is the register where the Windows x64 calling convention places the first integer argument — in this case, `uVar1`, the hash computed by `FUN_140001580`. The entire shellcode boils down to: load the constant `0xcdb73089`, compare it against the input's hash, and return 1 if they match.

## Solving the hash — and the second mistake

With the algorithm identified as standard FNV-1a and the target confirmed as `0xcdb73089`, all that was left was finding a string that produces that exact hash. Instead of reaching for an SMT solver like in levels 4 and 6, I set this one up with a different technique: **meet-in-the-middle**. FNV-1a has a property that makes it especially well-suited for this — every step is `state = (state XOR byte) × prime`, and since the prime is odd, the multiplication is invertible modulo 2³². That means, given a final state and a sequence of bytes, you can recover the state before those bytes without needing to guess them: just multiply by the prime's modular inverse and XOR with the known byte, in reverse.

The strategy: split the candidate password into a front half and a back half. For the front half, compute forward the state resulting from every possible combination of characters, starting from the standard offset basis. For the back half, compute backward — inverting each step — what intermediate state *would need to exist* for continuing forward with that combination of characters to land exactly on the target hash. If some front combination and some back combination produce the same intermediate state, those two halves together form a valid password. Instead of exploring the tens of billions of full combinations, you only need to generate each half's combinations separately — far fewer — and look for the match.

The first attempt with this technique returned a password. I tested it against the real binary and it failed. I went back over the whole equation, step by step, and found the problem: I'd used `0x10000193` as the multiplier in the search script — the same extra-digit mistake in the hex addition that I'd almost made while simplifying `FUN_140001580` by hand, and that this time did slip through when I typed the constant into the code. The solver found a string that was mathematically consistent with that wrong equation, but a wrong equation has nothing to do with the real binary, no matter how "correctly" the solver runs and returns a result. I fixed the constant to `0x1000193` and ran the search again.

Before trusting the result this time, I checked it two independent ways: with the simplified FNV-1a formula, and with the mixed boolean-arithmetic formula exactly as it appears in the binary, with no simplification at all, byte by byte. Both matched each other and matched the target `0xcdb73089`.

## Verification

```
[house@archlinux nivel7_mba]$ wine crackme.exe
Password: hVZd8L
[+] Correcto!
[house@archlinux nivel7_mba]$
```

Confirmed — after two failed rounds, each for a different reason, and each one caught before being trusted without checking.

## Analysis summary

This level combines two genuinely distinct layers of obfuscation, and solving it taught as much from my own mistakes as from the binary itself:

- **Mixed boolean-arithmetic hiding a standard algorithm.** `FUN_140001580` doesn't invent any new operation — it rewrites XOR as OR-minus-AND and addition as XOR-plus-twice-the-AND, two exact bit-level identities that, once recognized, reveal the whole thing as textbook FNV-1a. The obfuscation is in the disguise, not the substance.
- **Shellcode assembled in executable memory that has to be reconstructed, not just decrypted.** Unlike level 1's simple XOR decoding, here two different byte sources have to be combined correctly — a 64-bit constant read little-endian, and a decryption loop that starts at an offset that isn't obvious at a glance — before there's anything to disassemble at all.
- **A clean disassembly is its own validation.** When the byte reconstruction is wrong, the disassembler doesn't fail silently — it produces instructions that don't fit, or leaves stray bytes at the end. That signal is as useful as any other clue in the binary.
- **A solver returning a result doesn't confirm the setup was right.** The first password found was mathematically correct for the equation I gave the solver — it's just that the equation had a miscalculated constant. Verifying the result against the real binary, not just against the equation itself, is what exposed the error.
- **The same hex-arithmetic mistake threatens in two separate places.** The slip of adding one digit too many to `0x1000000 + 0x193` could have happened either while simplifying the function by hand or while typing the constant into the search script — and it very nearly happened in the first spot, and actually did happen in the second. Worth double-checking the arithmetic at either point.

This level's lesson, beyond the specific technique, is that neither recognizing the correct algorithm nor having a working search tool guarantees a correct result — every constant translated by hand, from binary to paper or from paper to code, is a place where a silent error can creep in, and the only real defense is checking the final result against the actual system, not just against the analysis's own internal logic.

---

© 2026 Gino Aldair Maihuiri Romero
