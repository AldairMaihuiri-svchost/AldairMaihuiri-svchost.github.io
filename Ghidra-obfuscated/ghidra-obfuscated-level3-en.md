---
title: "Ghidra vs. Obfuscated Binaries — Level 3: Indirection"
description: "Third level of the Ghidra reverse-engineering training series on obfuscated binaries. A PE32+ crackme that splits password validation across two chained helper functions joined by an AND — a length check and a content check kept separate — and builds the reference password byte by byte in memory instead of storing it as a literal."
author: Aldair Maihuiri
---

# Ghidra vs. Obfuscated Binaries — Level 3: Indirection

**Gino Aldair Maihuiri Romero**

([versión en español](ghidra-obfuscated-level3)) · ([Level 1](ghidra-obfuscated-level1-en)) · ([Level 2](ghidra-obfuscated-level2-en))

The previous two levels hid the password in two different ways: encrypting it (level 1) or burying the validation logic under dead branches and a reused opaque predicate (level 2). This third one uses a technique different from both: the comparison itself isn't encrypted or wrapped in false branches — it's **split across two separate functions**, chained by a logical condition, and the reference password doesn't exist as a string anywhere in the binary; it gets assembled byte by byte in memory right before the comparison. The folder name, `nivel3_indirect`, describes the mechanism exactly: instead of a direct `strcmp` against a literal, there's a chain of indirections you have to follow all the way through to understand what's being compared and against what.

Same setup as the previous levels: Linux, a Windows PE32+ binary, static analysis in Ghidra first, verification with Wine at the end.

---

## Initial reconnaissance

```
$ file crackme.exe
crackme.exe: PE32+ executable for MS Windows 5.02 (console), x86-64 (stripped to external PDB), 10 sections
```

Same profile as the previous two.

## A detour that's starting to feel familiar

I went straight to `API-MS-WIN-CRT-STRING-L1-1-0.DLL` looking for `strncmp`, and checked its references:

```
140008498    strncmp    JMP qword ptr [->API-MS-WIN-CRT-STRING-L1-1-0.DLL::strncmp]    COMPUTED_JUMP
140008498    strncmp    JMP qword ptr [->API-MS-WIN-CRT-STRING-L1-1-0.DLL::strncmp]    THUNK
14000f538    PTR_strncmp_14000f538    addr API-MS-WIN-CRT-STRING-L1-1-0.DLL::strncmp    DATA
```

Looking up the reference to `8498` led me to:

```
14000258c    CALL API-MS-WIN-CRT-STRING-L1-1-0.DLL::strncmp    UNCONDITIONAL_CALL
```

And, like in the previous level, this wasn't the crackme's logic:

```c
/* WARNING: Enum "SectionFlags": Some values do not have unique names */
IMAGE_SECTION_HEADER * FUN_140002510(char *param_1)
{
  int iVar1;
  size_t sVar2;
  IMAGE_SECTION_HEADER *_Str1;
  uint uVar3;

  sVar2 = strlen(param_1);
  if (sVar2 < 9) {
    uVar3 = 0;
    _Str1 = &IMAGE_SECTION_HEADER_140000188;
    do {
      iVar1 = strncmp(_Str1->Name,param_1,8);
      if (iVar1 == 0) {
        return _Str1;
      }
      uVar3 = uVar3 + 1;
      _Str1 = _Str1 + 1;
    } while (uVar3 < 10);
  }
  return (IMAGE_SECTION_HEADER *)0x0;
}
```

It's the same PE section-header lookup function that already showed up in level 2 — shifted in address because this is a different binary, but identical logic. At this point in the series I already recognize the memory pattern: when I follow `strncmp` and this block shows up, I know I'm in internal startup code, not validation, and it's time to look elsewhere. Worth documenting again here because it's useful to see it repeat — the first time was a finding, the second time is already a recognizable signature of the base binary these crackmes are built on.

## Pivoting through the strings — with a notable difference

I went to `Defined Strings` looking for the success message, same as in the previous levels. I found `[+] Correcto!` at `14000a050`:

```
                             s_[+]_Correcto!_14000a050                       XREF[2]:     FUN_140008680:1400086fe(*),
                                                                                          FUN_140008680:140008721(*)
       14000a050 5b 2b 5d        ds         "[+] Correcto!"
                 20 43 6f
                 72 72 65
```

Only two cross-references, not five like in level 2. Just from that I can already tell this level doesn't reuse the same predicate as a guard for dead branches — the obfuscation here is going to come from somewhere else. With `FUN_140008680` identified as the target function, I went straight to the decompiler.

## The validation function

```c
undefined8 FUN_140008680(undefined8 param_1,ulonglong param_2,undefined8 param_3,undefined8 param_4)
{
  bool bVar1;
  FILE *pFVar2;
  char *pcVar3;
  size_t sVar4;
  undefined7 extraout_var;
  undefined7 extraout_var_00;
  undefined8 uVar5;
  char *pcVar6;
  char *_Str;
  char local_48 [64];

  FUN_1400016e0();
  FUN_1400028c0((byte *)"Password: ",param_2,param_3,param_4);
  pFVar2 = (FILE *)__acrt_iob_func(1);
  fflush(pFVar2);
  pFVar2 = (FILE *)__acrt_iob_func(0);
  pcVar3 = fgets(local_48,0x40,pFVar2);
  if (pcVar3 == (char *)0x0) {
    uVar5 = 1;
  }
  else {
    sVar4 = strcspn(local_48,"\n");
    pcVar6 = &DAT_14000e0a0;
    pcVar3 = local_48;
    local_48[sVar4] = '\0';
    _Str = "[-] Incorrecto.";
    FUN_1400015d0();
    bVar1 = FUN_1400015a0(pcVar3,pcVar6);
    if (((int)CONCAT71(extraout_var,bVar1) != 0) &&
       (bVar1 = FUN_140001580(local_48,&DAT_14000e0a0), (int)CONCAT71(extraout_var_00,bVar1) != 0))
    {
      _Str = "[+] Correcto!";
    }
    puts(_Str);
    uVar5 = 0;
  }
  return uVar5;
}
```

Unlike the previous two levels, there's no `strcmp` visible directly inside this function. Validation is split across two calls chained with an AND: `FUN_1400015a0(pcVar3, pcVar6)` first, and only if that returns true, `FUN_140001580(local_48, &DAT_14000e0a0)` afterward. Both have to return true for `_Str` to switch to `"[+] Correcto!"`. Before drawing conclusions, I went into each one.

## Taking apart the two validation functions

**The first one — a length check, not a content check:**

```c
bool FUN_1400015a0(char *param_1,char *param_2)
{
  size_t sVar1;
  size_t sVar2;

  sVar1 = strlen(param_1);
  sVar2 = strlen(param_2);
  return sVar1 == sVar2;
}
```

This function doesn't compare the content of the two strings — only their lengths. `param_1` is the user's input, `param_2` is a pointer to `DAT_14000e0a0`, whose contents I didn't know yet at this point. This is the level's first layer of indirection: the condition you have to satisfy first isn't "the password is correct," it's "the password has the right length" — a separate check that, read in isolation in the decompiler without seeing the function that calls it, doesn't make clear what's actually being verified.

**Going to see what's inside `DAT_14000e0a0`:**

```
                             DAT_14000e0a0                                   XREF[3]:     FUN_1400015d0:1400015d6(W),
                                                                                          FUN_140008680:1400086d8(*),
                                                                                          FUN_140008680:14000870e(*)
       14000e0a0                 ??         ??
```

No visible value directly — but the first cross-reference, tagged with `(W)`, caught my attention right away. A `W` in Ghidra usually flags a write to that address, meaning something, at some point in the program, writes to `DAT_14000e0a0` at runtime instead of the value already being there since the binary was compiled. I went to `FUN_1400015d0` to confirm it.

**The function that builds the reference password, byte by byte:**

```c
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */
void FUN_1400015d0(void)
{
  _DAT_14000e0a0 = 0x31646e31;
  uRam000000014000e0a4 = 0x3372;
  DAT_14000e0a6 = 99;
  uRam000000014000e0a7 = 0x74;
  DAT_14000e0a8 = 0;
  return;
}
```

Not what I expected to find, but it was clear as soon as I read it: this function builds the real password inside memory, at the moment it gets called, instead of it already existing as a ready-made string in the binary's data section. It's the same idea I'd already seen with the `"Password: "` prompt in level 1 — assembling bytes directly instead of referencing a literal — but applied this time to the password itself, not just to decorative text.

I reconstructed the string byte by byte, keeping in mind that x86-64 stores integers in memory in little-endian order:

- `_DAT_14000e0a0 = 0x31646e31` — four bytes. In memory, from least to most significant: `31 6e 64 31`. In ASCII: `1`, `n`, `d`, `1` → `"1nd1"`.
- `uRam000000014000e0a4 = 0x3372` — two bytes: `72 33` → `r`, `3` → `"r3"`.
- `DAT_14000e0a6 = 99` — one byte, `0x63` → `c`.
- `uRam000000014000e0a7 = 0x74` — one byte → `t`.
- `DAT_14000e0a8 = 0` — null terminator.

Joining everything in memory-address order: `1nd1` + `r3` + `c` + `t` = **`1nd1r3ct`** — which, read as leetspeak, spells "indirect." The binary's folder name wasn't a coincidence: the password itself is the level's name.

Before I had the full reconstruction, I tested pasting just the first fragment by hand into the terminal:

```
[house@archlinux nivel3_indirect]$ wine crackme.exe
Password: 1ed1
[-] Incorrecto.
```

(That first attempt has a small typo compared to the exact reconstructed value, `1nd1` — but the result doesn't change either way: it was only an eight-character fragment, incomplete regardless, so rejection was expected in any case.) With the full string:

```
Password: 1nd1r3ct
[+] Correcto!
[house@archlinux nivel3_indirect]$
```

## Back to the second function, to close the analysis

With the password already confirmed, I went back to `FUN_140001580` to understand exactly what the second half of the AND does — the part that actually decides whether the content matches:

```c
bool FUN_140001580(char *param_1,char *param_2)
{
  int iVar1;

  iVar1 = strcmp(param_1,param_2);
  return iVar1 == 0;
}
```

Here it finally is: a plain old `strcmp`, wrapped in a function that only returns true or false instead of exposing `strcmp`'s raw integer result directly. This is the level's second layer of indirection: it isn't enough to know that a `strcmp` exists somewhere — you have to know it only runs if the earlier length check already passed, and that its boolean result is the second operand of an AND whose first operand lives in a completely different function.

## Analysis summary

This level doesn't repeat level 1's encryption or level 2's dead branches — it introduces a technique of its own:

- **Validation split across two functions chained by AND.** Instead of a single `strcmp` visible in the main function, the comparison is split between one function that only checks length and another that only checks content, and both have to return true. Reading either one in isolation, without seeing who calls them and in what order, doesn't reveal the full logic.
- **Password built in memory, not stored as a literal.** `DAT_14000e0a0` doesn't exist as a string in the compiled binary — it's assembled byte by byte, including a 32-bit integer interpreted in little-endian, right before the comparison. Spotting the XREF tagged with `(W)` was the clue that led straight to the constructing function.
- **A detour that's already recognizable.** The PE section-lookup function that showed up as a dead end in level 2 appeared again here, in the same spot in the analysis flow. Worth learning to recognize it quickly instead of re-investigating it from scratch every time.

The central lesson of this level is that following a single function to the end isn't enough when the logic is deliberately split across several. You have to reconstruct the full call chain — who calls whom, with what arguments, and under what condition — before you can claim to have understood the complete validation.

---

© 2026 Gino Aldair Maihuiri Romero
