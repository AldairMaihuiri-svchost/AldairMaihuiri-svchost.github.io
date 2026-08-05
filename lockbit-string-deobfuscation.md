# LockBit String Deobfuscation: Reversing Affine Cipher DLL Loading with Ghidra

**Author:** Gino Aldair Maihuiri Romero  
**Date:** August 2026  
**Sample type:** LockBit ransomware (32-bit PE)  
**Tools:** Ghidra, Python 3  
**Tags:** `malware-analysis` `reverse-engineering` `lockbit` `ghidra` `obfuscation` `affine-cipher`

---

© 2026 Gino Aldair Maihuiri Romero. All rights reserved.  
This writeup is an excerpt from an in-progress full technical analysis of a LockBit ransomware sample.  
You may share this post with attribution. Reproduction of substantial portions without permission is prohibited.

---

## Overview

One of the first anti-analysis techniques LockBit employs is the deliberate absence of visible API imports.
A standard Windows executable lists the external functions it needs in its Import Address Table (IAT),
making it trivial for an analyst — or an antivirus — to see which DLLs and functions the binary uses.
LockBit avoids this entirely: its DLL names are stored encrypted on the stack and resolved dynamically
at runtime, so the IAT reveals nothing useful.

This post documents the encryption scheme used in one specific function I renamed `mw_stack_strings`,
walks through the decryption of the first string block in detail, and provides a Python script that
replicates the algorithm exactly as Ghidra decompiles it.

---

## The function: `mw_stack_strings`

After initial triage and loading the sample into Ghidra, one function stood out immediately: it
loads a total of **11 DLLs** required for the malware to operate. Eight of them are decrypted inline
using a visible `do/while` loop with an affine transformation. The remaining three delegate
decryption to auxiliary subfunctions whose internal algorithm is still under analysis.

The function signature as Ghidra decompiles it:

```c
void __fastcall mw_stack_strings(int param_1)
```

The `__fastcall` calling convention is worth noting: it passes the first argument in `ECX` rather
than pushing it onto the stack, which is a compiler optimization for speed. More relevant for
analysis: it is the same convention used throughout the binary, consistent with MSVC compilation
with Profile-Guided Optimization (PGO) enabled — something confirmed separately by PE metadata.

---

## Dynamic API resolution: why there is no `CALL LoadLibraryA`

Before looking at the decryption itself, it is important to understand *why* LockBit bothers
encrypting these strings at all.

In a normally compiled binary, loading a DLL looks like this in the disassembly:

```asm
push offset aKernel32dll   ; "kernel32.dll"
call LoadLibraryA
```

The string `kernel32.dll` is visible in the binary's data section, and `LoadLibraryA` appears
in the IAT. Any antivirus scanning the import table sees it immediately.

In `mw_stack_strings`, neither of those things is true. The DLL names exist in the binary
as encrypted byte arrays, and the API calls go through an intermediary I named `mw_resolve_api`.
What the disassembly shows is not `CALL LoadLibraryA` but `CALL EAX` — a call to a register
whose value was computed at runtime.

Ghidra represents this pattern as:

```c
code *pcVar2;
pcVar2 = (code *)mw_resolve_api(key, 0xf, 0x439c7e33, 4);
iVar3 = (*pcVar2)(local_47);
```

The type `code *` is Ghidra's way of marking a pointer whose target is executable code but
whose exact function signature cannot be determined statically. `pcVar2` does not point to
`mw_resolve_api` — it holds the *return value* of `mw_resolve_api`, which is the runtime address
of the actual API function. Then `(*pcVar2)(local_47)` dereferences and calls it.

This is the evasion in action: no named API call, no IAT entry, nothing for a signature scanner
to match against.

---

## The encryption scheme: affine cipher per string

Each of the eight inline blocks follows the same structure:

1. A byte array is initialized on the stack with hardcoded encrypted values.
2. A `do/while` loop applies an affine transformation to each byte in place.
3. The decrypted string — now sitting directly on the active stack frame — is passed to the resolved API.

### First block in detail

```c
local_48 = 0;
local_47[0]  = 0x14;
local_47[1]  = 9;
local_47[2]  = 0x36;
local_47[3]  = 0x59;
local_47[4]  = 9;
local_47[5]  = 0x2b;
local_47[6]  = 2;
local_47[7]  = 0x6a;
local_47[8]  = 0xe;
local_47[9]  = 0x71;
local_47[10] = 0x2b;
local_47[11] = 0x2b;
local_47[12] = 99;      // <-- this is the key

uVar15 = 0;
do {
    bVar1 = local_47[uVar15];
    local_47[uVar15] = (byte)(((int)((99 - (uint)bVar1) * 0xb) % 0x7f + 0x7f) % 0x7f);
    uVar15 = uVar15 + 1;
} while (uVar15 < 0xd);
```

**Buffer initialization.** `local_48 = 0` writes a null byte immediately before `local_47` on
the stack. Because these two variables are physically contiguous, this null acts as the string
terminator for whatever gets decrypted into `local_47` — a structure prepared in advance.

The 13 encrypted bytes follow (`[0]` through `[12]`). The last value, `99` (decimal), is the
**encryption key for this block specifically**. This is a pattern worth memorizing: in every
inline block, the last byte of the buffer equals the key used in the loop, and applying the
formula to that key always produces `0x00` — the null terminator.

**The decryption formula.** Each byte is transformed by:

```
new_byte = ((key - original_byte) × multiplier) mod 127
```

With parameters for this block:
- Key (`k`): `99`
- Multiplier (`a`): `0x0b` (11 decimal)
- Modulus: `0x7f` (127 decimal)

This is a classical **affine cipher** — a generalization of the Caesar cipher where, in addition
to a shift, there is a multiplicative factor that makes the transformation harder to reverse by
inspection. The key defines the shift; the multiplier scrambles the byte space.

**Why `(x % 127 + 127) % 127`?** The expression `(key - original_byte)` can produce a negative
result when `original_byte > key`. For example:

```
original_byte = 0x71 (113 decimal)
99 - 113 = -14
-14 × 11 = -154
```

In pure modular arithmetic, `-154 mod 127 = 100`. But C's `%` operator with negative operands
is implementation-defined — on most modern compilers it yields `-27`, not `100`. Storing `-27`
in a `byte` produces undefined behavior.

The double-modulo idiom fixes this:

```
Step 1: -154 % 127 = -27      (potentially negative)
Step 2: -27 + 127  = 100      (force into positive range)
Step 3: 100 % 127  = 100      (correct if Step 1 was already positive)
```

Step 3 handles the symmetric case: if Step 1 produced a positive value greater than 126,
adding 127 would push it out of range, and the final modulo brings it back. The result is
always in `[0, 126]`.

The malware author needs this specifically because all Windows DLL name characters (`k`, `e`,
`r`, `n`, `e`, `l`, `3`, `2`, `.`, `d`, `l`, `l`) have ASCII values in `[46, 122]` — entirely
within `[0, 127]`. The cipher is designed over this space, guaranteeing that decrypted bytes
are always valid printable ASCII. A result outside this range would produce garbage, the DLL
load would fail, and the malware would crash at startup.

**Resolution and invocation.**

```c
pcVar2 = (code *)mw_resolve_api(99 - (uint)bVar1, 0xf, 0x439c7e33, 4);
iVar3  = (*pcVar2)(local_47);
```

After the loop, `bVar1` holds the last processed byte — which is `99` (the key). So the first
argument to `mw_resolve_api` is `99 - 99 = 0`. This is consistent across all eight inline blocks:
by design, the first argument is always `0` when the loop terminates correctly.

The other arguments (`0xf`, `0x439c7e33`, `4`) are identical across all eleven calls.
`0x439c7e33` is a strong candidate for an internal module hash or identifier used by the resolver.
Their exact roles will be confirmed when `mw_resolve_api` is analyzed separately.

---

## Verification: Python script

The following script replicates the algorithm exactly as Ghidra decompiles it.
No assumptions — the formula is copied verbatim from the pseudocode:

```python
def decrypt_block(encrypted_bytes, key, multiplier):
    """
    Replicates the affine transformation from mw_stack_strings:
    new_byte = ((key - original_byte) * multiplier % 0x7f + 0x7f) % 0x7f
    """
    result = bytearray()
    for b in encrypted_bytes:
        new_byte = ((key - b) * multiplier % 0x7f + 0x7f) % 0x7f
        result.append(new_byte)
    return result


# Block 1 — local_47
# Encrypted bytes as seen in Ghidra (positions [0] through [12])
encrypted = [0x14, 0x09, 0x36, 0x59, 0x09, 0x2b, 0x02, 0x6a,
             0x0e, 0x71, 0x2b, 0x2b, 99]
key         = 99    # last byte of the buffer = loop key
multiplier  = 0x0b  # constant visible in the loop

result = decrypt_block(encrypted, key, multiplier)
print(bytes(result))
# Output: b'kernel32.dll\x00'
```

The trailing `\x00` confirms the null-terminator pattern: the last encrypted byte (`99`) applied
to the formula produces exactly `0`, closing the string correctly for any Win32 API function
that expects a null-terminated character array.

---

## What this tells us about the remaining blocks

There are 11 blocks in total. Eight follow this exact inline pattern with different keys and
multipliers. The other three delegate decryption to auxiliary subfunctions
(`FUN_00401c40`, `FUN_00401be0`, `FUN_00401b80`) — their internal algorithm differs and is
covered in the full analysis.

The structure of the block-final section also reveals that all 11 loads follow this pattern:

```c
if (iVarN != 0) {
    FUN_00401730(iVarN);
}
```

Checking the return value against `0` (NULL) is the standard Win32 pattern for handle and
pointer validation — confirming that whatever `mw_resolve_api` returns is a handle or pointer,
not an arithmetic result. The full analysis of `mw_resolve_api` and what `FUN_00401730` does
with these handles is part of the extended work.

---

## Summary

LockBit's string obfuscation in `mw_stack_strings` is a disciplined implementation of three
layered techniques:

- **Stack strings:** DLL names are never stored as plaintext in the data section; they materialize on the active stack frame at runtime.
- **Affine cipher per block:** each string uses its own key and multiplier, so there is no single decryption key that unlocks everything at once.
- **Dynamic API resolution:** the resolved DLL handle is immediately passed through `mw_resolve_api`, keeping any named API out of the import table.

The combination makes static signature detection ineffective: nothing in the IAT, nothing in
plaintext in the binary. The encrypted bytes blend into numeric constants. Reconstruction
requires recognizing the pattern, extracting the key from the last buffer byte, and applying
the affine formula — which is exactly what this post documents.

---

*This writeup is an excerpt. The complete analysis — including all 11 DLL blocks, the
`mw_resolve_api` internals, dynamic validation, and the full decryption table — is part of a
longer technical work in progress.*

*If you found this useful or have corrections, reach out on GitHub.*

---

© 2026 Gino Aldair Maihuiri Romero. All rights reserved.  
Unauthorized reproduction of this content, in whole or in substantial part, is prohibited.  
Sharing with attribution is welcome.
