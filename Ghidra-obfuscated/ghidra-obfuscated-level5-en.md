---
title: "Ghidra vs. Obfuscated Binaries — Level 5: The Final Level"
description: "Fifth and final level of the Ghidra reverse-engineering training series on obfuscated binaries. A PE32+ crackme combining techniques from the previous four levels — dynamic password construction, an opaque predicate, vtable dispatch, a hand-rolled comparison avoiding strcmp — with two new elements: runtime code relocation to executable memory and a debugger check that actually blocks analysis."
author: Aldair Maihuiri
---

# Ghidra vs. Obfuscated Binaries — Level 5: The Final Level

**Gino Aldair Maihuiri Romero**

([versión en español](ghidra-obfuscated-level5)) · ([Level 1](ghidra-obfuscated-level1-en)) · ([Level 2](ghidra-obfuscated-level2-en)) · ([Level 3](ghidra-obfuscated-level3-en)) · ([Level 4](ghidra-obfuscated-level4-en))

This binary's folder is named `nivel5_boss`, and as soon as I started unraveling it, it was clear why: it doesn't bring one new technique and stop there — it gathers pieces from the previous four levels into a single function and adds two elements the series hadn't seen before. It was the longest one to understand out of all five, and there were stretches where I struggled to place which piece matched which already-known technique — but that's exactly why I moved faster than if it had been the first time seeing each one: recognizing a pattern I'd already solved before saves time, even when the combination as a whole is new.

Same setup as always: Linux, a Windows PE32+ binary, static analysis in Ghidra first, verification with Wine at the end.

---

## Initial reconnaissance

```
$ file crackme.exe
crackme.exe: PE32+ executable for MS Windows 5.02 (console), x86-64 (stripped to external PDB), 10 sections
```

Same profile as the previous four levels.

## A detour I recognized right away this time

I went to `strncmp`'s references and landed on this:

```
140015300
strncmp
JMP qword ptr [->API-MS-WIN-CRT-STRING-L1-1-0.DLL::strncmp]
COMPUTED_JUMP
140015300
strncmp
JMP qword ptr [->API-MS-WIN-CRT-STRING-L1-1-0.DLL::strncmp]
THUNK
1400298d0
PTR_strncmp_1400298d0
addr API-MS-WIN-CRT-STRING-L1-1-0.DLL::strncmp
DATA
```

And the function calling it was, byte for byte, the same one I'd already analyzed in level 4: `FUN_14000c740`, the C++ mangled-name detection and parsing routine (checking for the `_Z` and `_GLOBAL_` prefixes from the Itanium ABI). This time I didn't need to reread it in full — I recognized it as soon as I saw the `if ((*param_1 == '_') && (param_1[1] == 'Z'))` at the start. Hanging off it was another function, `FUN_140001600`, acting as the node constructor for the demangler's parsing tree: it validates each token against bitmasks, checks that an internal buffer's capacity isn't exceeded, and stores each processed character into a 32-byte structure. It's the parser's internal machinery, not the validation — the same conclusion I'd reached about this code in level 4, applied faster here.

Instead of continuing to dig down that path like I did the first time I ran into this demangler, this time I went straight to `Defined Strings` looking for the password prompt. That was the right call: it got me to the real function in a single jump.

## The main function

```c
undefined8 FUN_14001ce70(undefined8 param_1,ulonglong param_2,undefined8 param_3,undefined8 param_4)
{
  undefined8 uVar1;
  undefined8 uVar2;
  undefined8 uVar3;
  undefined8 uVar4;
  undefined8 uVar5;
  undefined8 uVar6;
  undefined8 uVar7;
  int iVar8;
  int iVar9;
  BOOL BVar10;
  FILE *pFVar11;
  char *pcVar12;
  size_t sVar13;
  undefined8 *_Memory;
  code *lpBaseAddress;
  HANDLE hProcess;
  longlong *plVar14;
  code *pcVar15;
  uint uVar16;
  ulonglong uVar17;
  char local_58 [64];

  FUN_14000da10();
  FUN_14000f6c0((byte *)"Password: ",param_2,param_3,param_4);
  pFVar11 = (FILE *)__acrt_iob_func(1);
  fflush(pFVar11);
  pFVar11 = (FILE *)__acrt_iob_func(0);
  pcVar12 = fgets(local_58,0x40,pFVar11);
  if (pcVar12 == (char *)0x0) {
    return 1;
  }
  sVar13 = strcspn(local_58,"\n");
  local_58[sVar13] = '\0';
  _Memory = malloc(0xb);
  *_Memory = 0x3062347264316867;
  *(undefined2 *)(_Memory + 1) = 0x7373;
  *(undefined1 *)((longlong)_Memory + 10) = 0;
  lpBaseAddress = VirtualAlloc((LPVOID)0x0,0x100,0x3000,0x40);
  pcVar15 = FUN_140001580;
  if (lpBaseAddress != (code *)0x0) {
    *(undefined8 *)(lpBaseAddress + 0xc0) = 0x20400000000;
    *(undefined8 *)(lpBaseAddress + 200) = 0xc9854d7374c88548;
    *(undefined8 *)(lpBaseAddress + 0xd0) = 0x3b41284a8b413e74;
    *(undefined8 *)(lpBaseAddress + 0xd8) = 0x83c16348347d2c4a;
    *(undefined8 *)(lpBaseAddress + 0xe0) = 0x34905e0c14801c1;
    *(undefined8 *)(lpBaseAddress + 0xe8) = 0x440c7482042;
    *(undefined8 *)(lpBaseAddress + 0xf0) = 0x1089284a89410000;
    *(undefined8 *)(lpBaseAddress + 0xf8) = 0x1848894c1040894c;
    uVar17 = 0;
    do {
      uVar16 = (int)uVar17 + 0x40;
      uVar1 = *(undefined8 *)(uVar17 + 0x140001588);
      uVar2 = *(undefined8 *)(&DAT_140001590 + uVar17);
      uVar3 = *(undefined8 *)(&UNK_140001598 + uVar17);
      uVar4 = *(undefined8 *)(uVar17 + 0x1400015a0);
      uVar5 = *(undefined8 *)(uVar17 + 0x1400015a8);
      uVar6 = *(undefined8 *)(uVar17 + 0x1400015b0);
      uVar7 = *(undefined8 *)(&UNK_1400015b8 + uVar17);
      *(undefined8 *)(lpBaseAddress + uVar17) = *(undefined8 *)(FUN_140001580 + uVar17);
      *(undefined8 *)(lpBaseAddress + uVar17 + 8) = uVar1;
      *(undefined8 *)(lpBaseAddress + uVar17 + 0x10) = uVar2;
      *(undefined8 *)(lpBaseAddress + uVar17 + 0x10 + 8) = uVar3;
      *(undefined8 *)(lpBaseAddress + uVar17 + 0x20) = uVar4;
      *(undefined8 *)(lpBaseAddress + uVar17 + 0x20 + 8) = uVar5;
      *(undefined8 *)(lpBaseAddress + uVar17 + 0x30) = uVar6;
      *(undefined8 *)(lpBaseAddress + uVar17 + 0x30 + 8) = uVar7;
      uVar17 = (ulonglong)uVar16;
    } while (uVar16 < 0xc0);
    hProcess = GetCurrentProcess();
    FlushInstructionCache(hProcess,lpBaseAddress,0x100);
    pcVar15 = lpBaseAddress;
  }
  plVar14 = (longlong *)FUN_14001c9b0(0x10);
  *plVar14 = (longlong)&PTR_FUN_140021aa0;
  iVar8 = DAT_14001e020;
  iVar9 = DAT_14001e01c;
  plVar14[1] = (longlong)pcVar15;
  if (iVar8 * iVar8 + iVar9 * DAT_14001e01c == DAT_14001e018 * DAT_14001e018) {
    BVar10 = IsDebuggerPresent();
    if (BVar10 != 0) {
      (*(code *)((undefined8 *)*plVar14)[2])(plVar14);
      free(_Memory);
      pcVar12 = "[-] Incorrecto.";
      goto LAB_14001d05b;
    }
    uVar16 = (**(code **)*plVar14)(plVar14,local_58,_Memory,10);
  }
  else {
    iVar9 = FUN_14001c160((longlong)plVar14,local_58,_Memory,10);
    uVar16 = (uint)(iVar9 == 0);
  }
  (**(code **)(*plVar14 + 0x10))(plVar14);
  free(_Memory);
  pcVar12 = "[+] Correcto!";
  if (uVar16 == 0) {
    pcVar12 = "[-] Incorrecto.";
  }
LAB_14001d05b:
  puts(pcVar12);
  return 0;
}
```

It's the longest function in the series, and recognizing which part matched which already-seen technique was what let me make progress. I broke it down piece by piece.

## Building the password in memory — again

```c
_Memory = malloc(0xb);
*_Memory = 0x3062347264316867;
*(undefined2 *)(_Memory + 1) = 0x7373;
*(undefined1 *)((longlong)_Memory + 10) = 0;
```

Same technique as level 3: the reference password isn't a string in the binary — it's assembled byte by byte into a buffer reserved with `malloc`. I reconstructed the bytes in little-endian:

- `0x3062347264316867` (8 bytes): `67 68 31 64 72 34 62 30` → `g h 1 d r 4 b 0` → `"gh1dr4b0"`.
- `0x7373` (2 bytes, starting at offset 8): `73 73` → `s s` → `"ss"`.
- Null terminator at offset 10.

Joining everything: **`gh1dr4b0ss`**, ten characters. And read as leetspeak (1→i, 4→a, 0→o): **"ghidraboss"**. The binary's folder name turned out to literally be the password again — the same trick I'd already run into with "indirect" in level 3.

## Code that copies itself into executable memory

```c
lpBaseAddress = VirtualAlloc((LPVOID)0x0,0x100,0x3000,0x40);
pcVar15 = FUN_140001580;
if (lpBaseAddress != (code *)0x0) {
  ...
  uVar17 = 0;
  do {
    ...
    *(undefined8 *)(lpBaseAddress + uVar17) = *(undefined8 *)(FUN_140001580 + uVar17);
    ...
  } while (uVar16 < 0xc0);
  hProcess = GetCurrentProcess();
  FlushInstructionCache(hProcess,lpBaseAddress,0x100);
  pcVar15 = lpBaseAddress;
}
```

This is new in the series: the program reserves a memory page with `VirtualAlloc` using flags `0x3000` (`MEM_COMMIT | MEM_RESERVE`) and `0x40` (`PAGE_EXECUTE_READWRITE`), copies 0xC0 (192) bytes from `FUN_140001580`'s address into that freshly reserved memory in 8-byte chunks, and calls `FlushInstructionCache` to make sure the CPU sees the newly written code. At the end, `pcVar15` ends up pointing to that copy in executable memory instead of to the original function — but only if `VirtualAlloc` succeeded; if it fails, `pcVar15` stays pointing at the usual static `FUN_140001580`.

Going through the copy loop carefully, I didn't find any transformation of the bytes — no XOR, no addition, nothing. It's a straight, byte-for-byte copy of `FUN_140001580`'s body into the new memory region. And that matters for the analysis: since Ghidra can already decompile `FUN_140001580` at its original static location — which I did further down — this runtime relocation doesn't hide anything at all from static analysis. Whether the program ends up executing the copy in memory or the original, the code is bit-for-bit identical. It's a technique that in other contexts would work against patching or hooking tools that target a fixed address, but it doesn't add anything against a purely static analysis like the one I've been doing throughout this series.

## The opaque predicate, again

```c
iVar8 = DAT_14001e020;
iVar9 = DAT_14001e01c;
plVar14[1] = (longlong)pcVar15;
if (iVar8 * iVar8 + iVar9 * DAT_14001e01c == DAT_14001e018 * DAT_14001e018) {
```

The same Pythagorean algebraic shape from level 2 — sum of two squares equal to a third, with three global constants. Unlike that level, I didn't get around to dumping the actual values of `DAT_14001e020`, `DAT_14001e01c`, and `DAT_14001e018` from memory here, so I can't confirm with certainty that this condition always holds, or fully rule out the `else` branch. I'm documenting this as an open unknown instead of assuming it behaves the same way as level 2 without having checked.

## An object with a vtable — and a debugger check that actually matters

If the condition holds, the code builds an object with a vtable (same technique as level 4: `FUN_14001c9b0(0x10)` allocates the object, `&PTR_FUN_140021aa0` is its vtable, `plVar14[1]` stores a pointer to the validation function — either the original or the copy, depending on whether `VirtualAlloc` succeeded) and, before invoking anything, calls `IsDebuggerPresent()`:

```c
BVar10 = IsDebuggerPresent();
if (BVar10 != 0) {
  (*(code *)((undefined8 *)*plVar14)[2])(plVar14);
  free(_Memory);
  pcVar12 = "[-] Incorrecto.";
  goto LAB_14001d05b;
}
uVar16 = (**(code **)*plVar14)(plVar14,local_58,_Memory,10);
```

This is a real defensive measure, not decoration. If the program detects it's running under a debugger, it jumps straight to cleaning up the object and printing "Incorrect" without even calling the comparison method — whatever password was typed doesn't matter, the result is already decided. Looking back, following the suggestion to set a breakpoint inside this function to watch the password get processed live — which is exactly what had come up as an alternative path while analyzing the demangler — wouldn't have worked without first neutralizing this check. I ended up solving the whole level without ever opening a debugger, so this trap never actually triggered against me, but it's worth noting that it's there.

If there's no debugger, the vtable's first method — the real comparison function — gets called, passing it the object, the user's input, the reference password, and the length `10`.

There's an alternative branch I didn't fully explore: if the Pythagorean predicate were false, the code instead calls `FUN_14001c160` directly, bypassing both the vtable and the debugger check. I don't have that function's code or confirmation of whether that branch is reachable in practice, so I'm flagging it as a loose thread rather than guessing what it does.

## The real comparison, without `strcmp`

```c
bool FUN_140001580(longlong param_1,longlong param_2,longlong param_3)
{
  longlong lVar1;

  if (param_3 != 0) {
    lVar1 = 0;
    do {
      if (*(char *)(param_1 + lVar1) != *(char *)(param_2 + lVar1)) {
        return false;
      }
      lVar1 = lVar1 + 1;
    } while (param_3 != lVar1);
  }
  if (*(char *)(param_1 + param_3) != '\0') {
    return false;
  }
  return *(char *)(param_2 + param_3) == '\0';
}
```

The level 3 idea again: avoid a named `strcmp`/`strncmp` that would show up easily in cross-references, and hand-write the comparison instead. It walks both strings character by character up to the given length (`10`), and if they mismatch at any point, it cuts short and returns false. At the end of the loop, it also explicitly checks that both strings end exactly at position 10 with a null byte — making sure the input has exactly that length, not just that the first ten characters happen to match.

## Verification

```
[house@archlinux nivel5_boss]$ file crackme.exe
crackme.exe: PE32+ executable for MS Windows 5.02 (console), x86-64 (stripped to external PDB), 10 sections
[house@archlinux nivel5_boss]$ wine crackme.exe
Password: gh1dr4b0ss
[+] Correcto!
[house@archlinux nivel5_boss]$
```

Confirmed.

## Analysis summary

This level doesn't introduce one dominant technique of its own — it works as a synthesis of the whole series, with two genuinely new additions:

- **Techniques recognized from previous levels.** Building the password in memory (level 3), an opaque predicate in Pythagorean form (level 2), vtable dispatch (level 4), and a hand-rolled comparison without a named `strcmp`/`strncmp` (level 3). Recognizing each one immediately, instead of analyzing them from scratch again, is what made a level that would otherwise have been overwhelming actually manageable.
- **Runtime code relocation to executable memory — with no real effect against static analysis.** The program copies its own validation function into a region reserved with `VirtualAlloc`, but since it's a byte-for-byte copy with no transformation, it doesn't hide anything Ghidra couldn't already show at the original static location.
- **A debugger check that actually works.** Unlike level 2's dead branches, this `IsDebuggerPresent()` genuinely blocks the success path if the binary runs under a debugger — the first defensive measure in the series that would have interfered with a dynamic approach.
- **One loose thread, documented as such.** I didn't confirm the actual values behind this level's Pythagorean predicate, nor did I analyze the alternate branch (`FUN_14001c160`) taken if that condition were false. It's noted as an open question instead of an unsupported claim.

The series' closing lesson: past a certain point, solving an obfuscated binary stops being about recognizing one isolated technique and becomes about recognizing several at once, layered on top of each other, and knowing in what order to untangle them. That pattern recognition — built level by level over this series — is what turned the longest level into something solvable instead of overwhelming.

---

© 2026 Gino Aldair Maihuiri Romero
