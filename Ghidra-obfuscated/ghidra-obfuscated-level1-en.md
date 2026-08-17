---
title: "Ghidra vs. Obfuscated Binaries — Level 1: String Encryption"
description: "First level of a Ghidra reverse-engineering training series on obfuscated binaries. Pure static analysis of a PE32+ crackme that hides its password and messages through in-memory string construction and single-byte XOR encryption, solved without ever running the binary."
author: Aldair Maihuiri
---

# Ghidra vs. Obfuscated Binaries — Level 1: String Encryption

**Gino Aldair Maihuiri Romero**

([versión en español](ghidra-obfuscated-level1))

This is the first entry in a training series that's different from my previous crackmes. Those used my own ELF binaries, with no deliberate obfuscation, built to practice specific reversing primitives: string comparison, ptrace patching, stack canaries. Here the goal changes: these are already-obfuscated Windows PE32+ binaries, and the question isn't "how does this primitive work" anymore — it's "what does a real obfuscation technique look like once I open it in Ghidra, and how do I take it apart using only the decompiler and the raw memory view, without relying on running the binary even once."

That restriction isn't arbitrary: I run Linux, and these crackmes are native Windows binaries. I could run them under Wine, but for this training I decided not to during analysis. The goal is for the solution to come entirely from static analysis in Ghidra. Only afterward, in a separate Windows environment, do I verify that the password I found is correct. If you're reading this document, that verification has already happened.

---

## Initial reconnaissance

The first thing, as always before opening any binary in Ghidra, is to check what I'm dealing with using `file`:

```
$ file crackme.exe
crackme.exe: PE32+ executable for MS Windows 5.02 (console), x86-64 (stripped to external PDB), 10 sections
```

A console PE32+ executable, x86-64, with debug symbols stripped out to an external PDB I don't have. Ten sections. Nothing unusual yet — this is the standard way a Windows release binary gets shipped.

With the binary loaded in Ghidra, my usual next stop is the **Defined Strings** window, because in an unobfuscated crackme it's often enough to just read the success message, the error message, or even the password in plain text right there. I found none of those three here. What I did find was `strcmp`, and that's a useful signal on its own: if the binary compares something with `strcmp`, there's a validation branch somewhere in the code, and that branch is my target.

## From the string to the function

With `strcmp` as an entry point, I went to the **Symbol Tree** to find where that reference comes from. I found it imported from `API-MS-WIN-CRT-STRING-L1-1-0.DLL`, one of the Windows Universal CRT forwarder DLLs — the binary doesn't ship its own `strcmp`, it imports it from the system. Checking the references to that entry gave me this:

```
140008480    strcmp    JMP qword ptr [->API-MS-WIN-CRT-STRING-L1-1-0.DLL::strcmp]    COMPUTED_JUMP
140008480    strcmp    JMP qword ptr [->API-MS-WIN-CRT-STRING-L1-1-0.DLL::strcmp]    THUNK
14000f528    PTR_strcmp_14000f528    float * API-MS-WIN-CRT-STRING-L1-1-0.DLL::strcmp    DATA
```

`140008480` is the thunk: the jump that redirects any call to `strcmp` to the real DLL. What I need isn't the thunk itself, but who calls it. Checking the references to that address gave me exactly one:

```
140008761        CALL API-MS-WIN-CRT-STRING-L1-1-0.DLL::strcmp    UNCONDITIONAL_CALL
```

That address, `140008761`, falls inside a function. I went there in the decompiler and found the entire validation logic of the crackme in one place.

## The validation function

```c
undefined8
FUN_140008680(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4)
{
  int iVar1;
  undefined8 *_Memory;
  FILE *pFVar2;
  char *pcVar3;
  undefined8 uVar4;
  size_t sVar5;
  ulonglong *_Str;
  char local_68 [16];
  char local_58 [72];

  FUN_1400016d0();
  _Memory = malloc(0xb);
  *(undefined2 *)(_Memory + 1) = 0x203a;
  *_Memory = 0x64726f7773736150;
  *(undefined1 *)((longlong)_Memory + 10) = 0;
  FUN_1400028a0(&DAT_14000a050,(ulonglong)_Memory,param_3,param_4);
  pFVar2 = (FILE *)__acrt_iob_func(1);
  fflush(pFVar2);
  free(_Memory);
  pFVar2 = (FILE *)__acrt_iob_func(0);
  pcVar3 = fgets(local_58,0x40,pFVar2);
  uVar4 = 1;
  if (pcVar3 != (char *)0x0) {
    sVar5 = strcspn(local_58,"\n");
    local_58[sVar5] = '\0';
    pcVar3 = malloc(10);
    builtin_strncpy(pcVar3,"0bfu5c4t3",10);
    strncpy(local_68,pcVar3,0xf);
    free(pcVar3);
    iVar1 = strcmp(local_58,local_68);
    if (iVar1 == 0) {
      _Str = FUN_140001580((ulonglong *)&DAT_14000a068,0xd);
    }
    else {
      _Str = FUN_140001580((ulonglong *)&DAT_14000a058,0xf);
    }
    puts((char *)_Str);
    free(_Str);
    uVar4 = 0;
  }
  return uVar4;
}
```

Worth reading this one carefully, because the first two obfuscation techniques of this series are already here, and neither one touches the password directly — they touch how the strings around it get built.

**The first technique** is building the `"Password: "` prompt without it existing as a literal anywhere. Instead of a direct reference to a string, the code reserves 11 bytes with `malloc` and assembles the text by writing raw bytes into memory: `0x64726f7773736150` is the string `"Passwor"` followed by a `d`, encoded little-endian inside that 64-bit integer, and `0x203a` is the final two bytes `": "`. That's why `Defined Strings` didn't show anything useful — the string doesn't exist as such in the binary; it's assembled at runtime, byte by byte, inside an integer.

**The second** is how the string the user's input gets compared against is built. The code doesn't compare directly against a literal — it reserves memory with `malloc(10)`, copies `"0bfu5c4t3"` into it with `builtin_strncpy`, copies that buffer into a local variable with `strncpy`, and frees the original buffer. The net result is exactly `strcmp(user_input, "0bfu5c4t3")`, but getting there means following three copy operations instead of reading a literal. This is weak obfuscation compared to what comes next: the password still shows up in plain text in the decompiler, just not in the strings view. For this training level that's already a solid lesson — obfuscation doesn't need to be strong to do its job of complicating an automated scan or a surface-level read.

With this I already have the password: **`0bfu5c4t3`**.

## The success message, XOR-encrypted

The interesting part comes after the comparison. When `strcmp` returns 0, the code doesn't call `puts` with a literal — it calls a function, `FUN_140001580`, passing it a pointer to `DAT_14000a068` and a length of `0xd` (13 bytes). I went to look at that function:

```c
ulonglong * FUN_140001580(ulonglong *param_1,ulonglong param_2)
{
  ulonglong *puVar1;
  ulonglong uVar2;

  puVar1 = malloc(param_2 + 1);
  *puVar1 = *param_1 ^ 0x5a5a5a5a5a5a5a5a;
  uVar2 = 8;
  do {
    *(byte *)((longlong)puVar1 + uVar2) = *(byte *)((longlong)param_1 + uVar2) ^ 0x5a;
    uVar2 = uVar2 + 1;
  } while (uVar2 < param_2);
  *(undefined1 *)((longlong)puVar1 + param_2) = 0;
  return puVar1;
}
```

This is a single-byte XOR decryptor, with one compiler quirk: the first 8 bytes get decrypted in a single shot as a 64-bit integer against the mask `0x5a5a5a5a5a5a5a5a` (which is just the key `0x5a` repeated eight times), and the rest of the buffer is processed byte by byte in a loop. It's the same operation in both cases — a XOR against `0x5a` — the compiler just optimized the first block by grouping eight single-byte XORs into one 8-byte XOR.

With that clear, all I'm missing is the encrypted content. I went to `DAT_14000a068` in Ghidra's memory view:

```
                             DAT_14000a068                                   XREF[1]:     FUN_140008680:14000879c(*)
       14000a068 01              ??         01h
       14000a069 71              ??         71h    q
       14000a06a 07              ??         07h
       14000a06b 7a              ??         7Ah    z
       14000a06c 19              ??         19h
       14000a06d 35              ??         35h    5
       14000a06e 28              ??         28h    (
       14000a06f 28              ??         28h    (
       14000a070 3f              ??         3Fh    ?
       14000a071 39              ??         39h    9
       14000a072 2e              ??         2Eh    .
       14000a073 35              ??         35h    5
       14000a074 7b              ??         7Bh    {
       14000a075 00              ??         00h
       14000a076 00              ??         00h
       14000a077 00              ??         00h
```

Thirteen useful bytes before the zero padding, exactly the `0xd` length passed to the function. I take them into Python to apply the same XOR the binary does:

```
>>> # Encrypted bytes obtained from Ghidra (DAT_14000a068, length 0xd / 13 bytes)
... encrypted_bytes = [0x01, 0x71, 0x07, 0x7a, 0x19, 0x35, 0x28, 0x28, 0x3f, 0x39, 0x2e, 0x35, 0x7b]
...
... # Apply XOR with 0x5a to each byte and convert to characters
... decrypted_text = "".join([chr(b ^ 0x5a) for b in encrypted_bytes])
...
... print(f"Decrypted message: {decrypted_text}")
...
Decrypted message: [+] Correcto!
```

The success message is `[+] Correcto!` — the crackme's own text stays in Spanish; I only translate it here as part of the writeup narration.

## The error message, same mechanism

When `strcmp` doesn't return 0, the code calls the same `FUN_140001580` function, this time with `&DAT_14000a058` and a length of `0xf` (15 bytes). It's the same decryptor I already analyzed above — worth noting because it's a reasonable design choice by the crackme's author: reusing a single decryption routine for both messages instead of duplicating the logic.

In my opinion, if the goal was genuine obfuscation, it would have made more sense to encrypt the password itself instead of (or in addition to) the output messages — an attacker who only needs the password can ignore this whole layer. But as a Ghidra training exercise it does its job well: it forces you to work with data that doesn't show up as readable text in any automated strings view, which is exactly the skill I want to practice at this level.

The encrypted content in `DAT_14000a058`:

```
                             DAT_14000a058                                   XREF[1]:     FUN_140008680:14000876f(*)
       14000a058 01              ??         01h
       14000a059 77              ??         77h    w
       14000a05a 07              ??         07h
       14000a05b 7a              ??         7Ah    z
       14000a05c 13              ??         13h
       14000a05d 34              ??         34h    4
       14000a05e 39              ??         39h    9
       14000a05f 35              ??         35h    5
       14000a060 28              ??         28h    (
       14000a061 28              ??         28h    (
       14000a062 3f              ??         3Fh    ?
       14000a063 39              ??         39h    9
       14000a064 2e              ??         2Eh    .
       14000a065 35              ??         35h    5
       14000a066 74              ??         74h    t
       14000a067 00              ??         00h
```

Same script, different data:

```
>>> error_bytes = [0x01, 0x77, 0x07, 0x7a, 0x13, 0x34, 0x39, 0x35, 0x28, 0x28, 0x3f, 0x39, 0x2e, 0x35, 0x74]
... error_message = "".join([chr(b ^ 0x5a) for b in error_bytes])
... print(error_message)
...
[-] Incorrecto.
```

## Analysis summary

The entire crackme gets solved without running the binary even once, relying on only three Ghidra tools: cross-reference listings to get from a known import (`strcmp`) to the function that uses it, the decompiler to read the validation logic, and the raw memory view to extract the encrypted bytes the decompiler doesn't automatically translate into text.

- **Password**: `0bfu5c4t3` — visible in plain text in the decompiler, hidden only from a surface-level read of `Defined Strings` because it's assembled through in-memory copies instead of a direct reference.
- **Obfuscation technique identified**: runtime string construction (the prompt) and single-byte XOR encryption with key `0x5a` (both result messages).
- **Decryption mechanism**: a single function reused for both messages, with the compiler quirk of grouping the XOR of the first 8 bytes into one 64-bit operation.

The central lesson of this first level isn't the strength of the obfuscation — a single-byte XOR breaks with one line of Python once you have the key and the buffer — it's the working habit: when `Defined Strings` gives you nothing, the next step isn't to give up or run the binary blind, it's to follow cross-references from a known API all the way to the logic that uses it, and from there to the raw data the decompiler doesn't interpret on its own.

---

© 2026 Gino Aldair Maihuiri Romero
