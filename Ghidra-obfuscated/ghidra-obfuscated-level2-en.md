---
title: "Ghidra vs. Obfuscated Binaries — Level 2: Control Flow Obfuscation"
description: "Second level of the Ghidra reverse-engineering training series on obfuscated binaries. A PE32+ crackme that reuses the same opaque predicate as a guard for several dead branches with inverted logic, validating the password through a weighted sum modulo 256 with no unique solution."
author: Aldair Maihuiri
---

# Ghidra vs. Obfuscated Binaries — Level 2: Control Flow Obfuscation

**Gino Aldair Maihuiri Romero**

([versión en español](ghidra-obfuscated-level2)) · ([Level 1](ghidra-obfuscated-level1-en))

This is the second level of the series. In the first one the obfuscation was in how the strings were built — the challenge was finding where the password lived once `Defined Strings` gave nothing useful. Here the challenge changes shape: the password itself isn't encrypted, it's protected by a mathematical validation with no unique solution, and the code around it is deliberately duplicated to include branches that look valid but never execute. The binary's folder name, `nivel2_ctrlflow`, already hints at where this goes, and once inside the decompiler the reason becomes clear.

Same as the previous level, I run Linux and the binary is a Windows PE32+, so the analysis is entirely static in Ghidra. The difference from level 1 is that this time I did end up installing Wine, for a reason I explain later that is, itself, part of this level's lesson.

---

## Initial reconnaissance

The usual first step:

```
$ file crackme.exe
crackme.exe: PE32+ executable for MS Windows 5.02 (console), x86-64 (stripped to external PDB), 10 sections
```

Same profile as level 1: console PE32+, x86-64, symbols stripped to an external PDB, ten sections. Nothing different yet at the format level.

## From the string to the function — and a first dead end

I went straight to the imports. In `API-MS-WIN-CRT-STRING-L1-1-0.DLL` this time I found `strncmp` instead of `strcmp` — the length-bounded variant. Checking its references:

```
140008410    strncmp    JMP qword ptr [->API-MS-WIN-CRT-STRING-L1-1-0.DLL::strncmp]    COMPUTED_JUMP
140008410    strncmp    JMP qword ptr [->API-MS-WIN-CRT-STRING-L1-1-0.DLL::strncmp]    THUNK
14000f528    PTR_strncmp_14000f528    addr API-MS-WIN-CRT-STRING-L1-1-0.DLL::strncmp    DATA
```

The thunk in the decompiler:

```c
int __cdecl strncmp(char *_Str1,char *_Str2,size_t _MaxCount)

{
  int iVar1;

                    /* WARNING: Could not recover jumptable at 0x000140008410. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  iVar1 = strncmp(_Str1,_Str2,_MaxCount);
  return iVar1;
}
```

So far, almost identical to level 1: a comparison between two strings. I went looking for who calls that thunk and found exactly one reference:

```
1400024ec        CALL API-MS-WIN-CRT-STRING-L1-1-0.DLL::strncmp    UNCONDITIONAL_CALL
```

But the function that address led me to wasn't what I expected:

```c
IMAGE_SECTION_HEADER * FUN_140002470(char *param_1)

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

This isn't the crackme's logic. It's a function that walks the ten section headers of the PE itself (`IMAGE_SECTION_HEADER`) looking for one by name — typical of startup code or internal binary utilities, not password validation. Worth documenting as exactly what it is: a dead end, and a concrete lesson for this level. In level 1 there was only one call to `strcmp` in the whole binary, so following the reference was direct. Here `strncmp` has several possible callers and not all of them lead where you expect. The right API doesn't guarantee the right site — you have to read what the function does before assuming it's the one you're after.

## Pivoting through the result strings

With the `strncmp` path exhausted as a direct lead, I switched strategy and went to `Defined Strings` to look for the result messages, same as in level 1. I found `[+] Correcto!` at `14000a050`. I went to that address to check its references, and this is where the first real hint that `ctrlflow` isn't a coincidence showed up:

```
                             s_[+]_Correcto!_14000a050                       XREF[5]:     FUN_140008600:14000870e(*),
                                                                                          FUN_140008600:140008757(*),
                                                                                          FUN_140008600:14000876b(*),
                                                                                          FUN_140008600:14000878f(*),
                                                                                          FUN_140008600:140008796(*)
       14000a050 5b 2b 5d        ds         "[+] Correcto!"
                 20 43 6f
                 72 72 65
```

Five cross-references to the same success string, all inside a single function, `FUN_140008600`. In an unobfuscated binary, a success message gets printed from exactly one point in the code. Seeing it referenced five times inside a single function is the first footprint that the control flow in there isn't linear — further down, reading the full function, it becomes clear exactly why.

To confirm I was in the right function, I also searched for the `"Password: "` string:

```
                             s_Password:_14000a06e                           XREF[1]:     FUN_140008600:14000860a(*)
       14000a06e 50 61 73        ds         "Password: "
                 73 77 6f
                 72 64 3a
```

A single reference, also inside `FUN_140008600`. With both the prompt and the success message pointing to the same function, there's no doubt: that's where the full validation logic lives. The problem is that, unlike level 1, this function doesn't read top to bottom cleanly.

## The full validation function

```c
undefined8 FUN_140008600(undefined8 param_1,ulonglong param_2,undefined8 param_3,undefined8 param_4)
{
  byte bVar1;
  FILE *pFVar2;
  char *pcVar3;
  undefined8 uVar4;
  size_t sVar5;
  byte *pbVar6;
  int iVar7;
  int iVar8;
  byte local_48 [64];

  FUN_140001650();
  FUN_140002820((byte *)"Password: ",param_2,param_3,param_4);
  pFVar2 = (FILE *)__acrt_iob_func(1);
  fflush(pFVar2);
  pFVar2 = (FILE *)__acrt_iob_func(0);
  pcVar3 = fgets((char *)local_48,0x40,pFVar2);
  uVar4 = 1;
  if (pcVar3 != (char *)0x0) {
    sVar5 = strcspn((char *)local_48,"\n");
    local_48[sVar5] = 0;
    if (DAT_140009018 * DAT_140009018 + DAT_140009014 * DAT_140009014 ==
        DAT_140009010 * DAT_140009010) {
      sVar5 = strlen((char *)local_48);
      if (sVar5 == 8) {
        pbVar6 = local_48;
        iVar8 = 0;
        iVar7 = 0;
        do {
          bVar1 = *pbVar6;
          iVar7 = iVar7 + 1;
          pbVar6 = pbVar6 + 1;
          iVar8 = iVar8 + (uint)bVar1 * iVar7;
        } while (iVar7 != 8);
        if (DAT_140009018 * DAT_140009018 + DAT_140009014 * DAT_140009014 ==
            DAT_140009010 * DAT_140009010) {
          pcVar3 = "[+] Correcto!";
          if ((char)iVar8 != '*') {
            pcVar3 = "[-] Incorrecto.";
          }
        }
        else {
          pcVar3 = "[-] Incorrecto.";
          if ((char)iVar8 != '*') {
            pcVar3 = "[+] Correcto!";
          }
        }
      }
      else if (DAT_140009014 * DAT_140009014 + DAT_140009018 * DAT_140009018 ==
               DAT_140009010 * DAT_140009010) {
        pcVar3 = "[-] Incorrecto.";
      }
      else {
        pcVar3 = "[+] Correcto!";
      }
      puts(pcVar3);
      uVar4 = 0;
    }
    else {
      puts("[+] Correcto!");
      uVar4 = 0;
    }
  }
  return uVar4;
}
```

The first time I read this it didn't add up: there were too many branches for logic that, as I'd figured out, was just "weighted sum modulo 256 equals 42." The reason is that the author didn't write that logic once — they wrote it once correctly and, around it, planted copies with the logic inverted, all guarded by the same condition.

## Breaking down the validation

**Input.** Nothing unusual: `"Password: "` gets printed, input is read with `fgets` into a 64-byte buffer, and the trailing newline is trimmed with `strcspn`.

**The predicate that decides everything.** The first real condition in the code is:

```c
DAT_140009018 * DAT_140009018 + DAT_140009014 * DAT_140009014 == DAT_140009010 * DAT_140009010
```

Three global variables, with no dependency on user input whatsoever. The algebraic form is that of the Pythagorean theorem — the sum of two squares equal to a third. I didn't pull the raw bytes from those three addresses the way I did with the encrypted buffers in level 1, so I can't state with certainty that the values are 3, 4, and 5; what I can state, because it follows from the code's own structure and is confirmed by the binary's actual behavior, is that this condition always holds. These are global constants that nothing in the function ever modifies, so the comparison's result is fixed from the moment the program starts. This is an opaque predicate in the strict sense: a condition that, in theory, an analyst would have to evaluate at runtime, but that in practice is a constant the compiler — or the obfuscator — refuses to resolve ahead of time.

**The outer `else` trap.** Right below that predicate sits an `else` that literally says:

```c
else {
  puts("[+] Correcto!");
  uVar4 = 0;
}
```

Read in isolation, this seems to say "if the predicate is false, the program prints success without checking anything else" — which, if reachable, would be a trivial way to skip all validation. But it isn't reachable: since the predicate is always true, this `else` is dead code. It's the first of several branches of this kind in the function, and its purpose isn't to run — it's to appear as a tempting possibility to anyone reading quickly, or to an analysis tool that fails to prove the predicate is constant.

**Fixed length.** Inside the true branch (the only reachable one), the code requires the input to be exactly 8 characters:

```c
sVar5 = strlen((char *)local_48);
if (sVar5 == 8) { ... }
```

**The weighted sum.** The crackme's actual core. Each of the 8 input bytes is walked, multiplied by its position (starting at 1), and accumulated:

```c
pbVar6 = local_48;
iVar8 = 0;
iVar7 = 0;
do {
  bVar1 = *pbVar6;
  iVar7 = iVar7 + 1;
  pbVar6 = pbVar6 + 1;
  iVar8 = iVar8 + (uint)bVar1 * iVar7;
} while (iVar7 != 8);
```

In mathematical notation:

```
iVar8 = (c0×1) + (c1×2) + (c2×3) + (c3×4) + (c4×5) + (c5×6) + (c6×7) + (c7×8)
```

where each `c_i` is the ASCII value of the character at that position.

**The same predicate again, with the inverted logic sitting right next to it.** Right after the loop, the code re-evaluates the exact same Pythagorean condition:

```c
if (DAT_140009018 * DAT_140009018 + DAT_140009014 * DAT_140009014 ==
    DAT_140009010 * DAT_140009010) {
  pcVar3 = "[+] Correcto!";
  if ((char)iVar8 != '*') {
    pcVar3 = "[-] Incorrecto.";
  }
}
else {
  pcVar3 = "[-] Incorrecto.";
  if ((char)iVar8 != '*') {
    pcVar3 = "[+] Correcto!";
  }
}
```

The true branch (always reached) is the real logic: it defaults to success and reverts to failure if `(char)iVar8` doesn't match `'*'` — the cast to `char` keeps the least significant byte of the sum, i.e. the result modulo 256. The full winning condition is: the weighted sum, reduced to a single byte, has to be exactly 42, the ASCII value of `'*'`.

The `else` branch is the most interesting part of this level: it isn't just dead code, it's an **inverted copy** of the real logic. It defaults to failure and reverts to success if `(char)iVar8` doesn't match `'*'` — the exact opposite of the live branch. This isn't an author's oversight: it's a deliberate replica of the validation logic with the result flipped, placed behind a condition that never holds. If someone tried to patch the binary by flipping this condition's jump by hand without realizing the predicate is constant, they'd end up activating a check that accepts exactly the passwords that should fail and rejects the ones that should pass.

**The same pattern, a third time, for the wrong length.** If the input isn't 8 characters, the code doesn't simply print "Incorrect" directly — it re-evaluates the Pythagorean predicate again (with the addition operands in a different order, algebraically identical) before deciding the message:

```c
else if (DAT_140009014 * DAT_140009014 + DAT_140009018 * DAT_140009018 ==
         DAT_140009010 * DAT_140009010) {
  pcVar3 = "[-] Incorrecto.";
}
else {
  pcVar3 = "[+] Correcto!";
}
```

The reachable branch correctly prints "Incorrect" when the length isn't 8. The final `else` — also dead — is another trap: it would print "[+] Correcto!" for a wrong-length password, something that never happens because the predicate guarding it is never false.

**On the five references to the success string.** Counting the reconstructed source code, `"[+] Correcto!"` appears four times as a literal: in the dead outer `else`, in the live branch of the final check, in the dead inverted branch of that same check, and in the dead branch of the wrong-length case. Ghidra reported five cross-references. I can't confirm with certainty what the fifth corresponds to without disassembling instruction by instruction, but it's consistent with the compiler — or the obfuscation pass — having generated a duplicate load of the string's address at one of those jumps, something common when a function's control flow gets restructured or artificially duplicated. I'm documenting the discrepancy instead of forcing it to line up: four confirmed occurrences in the source code, five cross-references observed in Ghidra.

## Why this has no unique solution

Regardless of the dead branches, the logic that actually executes is clear: the sum of each password character multiplied by its position (1 to 8), reduced to a single byte, has to equal exactly 42. This is different from the previous level. In level 1 the password was a fixed string embedded in the binary — I only had to find it. Here there's no reference string: the validation is a modular equation, and a modulo-256 equation with eight free variables almost certainly has many solutions. I'm not extracting a password from the binary; I'm generating one that satisfies the equation.

To check this on paper before automating it: if I arbitrarily picked the first seven characters as `AAAAAAA` (seven `A`s, each with ASCII value 65), the partial sum for positions 1 through 7 would be:

```
65×1 = 65
65×2 = 130
65×3 = 195
65×4 = 260
65×5 = 325
65×6 = 390
65×7 = 455
partial sum = 1820
```

And it would just take picking the eighth character so that `1820 + (c7 × 8)` equals 42 modulo 256 — there's more than one value of `c7` in the printable ASCII range that can satisfy that, depending on how the modular arithmetic falls.

## Generating a valid password

Instead of solving the equation by hand for one specific case, I wrote a script that tries random combinations of seven characters and searches, for each one, which eighth character completes the equation:

```python
import random


def encontrar_contrasena():
  print("[*] Buscando una contraseña válida de 8 caracteres...")

  while True:
    # 1. Elegimos 7 caracteres aleatorios (letras mayúsculas de la A a la Z)
    chars = [chr(random.randint(65, 90)) for _ in range(7)]

    # 2. Calculamos la suma ponderada de los primeros 7 (letra * posición del 1 al 7)
    suma_parcial = sum(ord(c) * (i + 1) for i, c in enumerate(chars))

    # 3. Probamos qué carácter (del espacio 32 al 126 ASCII) completa la ecuación
    for ascii_val in range(32, 127):
      # Multiplicamos el 8º carácter por su posición (8)
      total = suma_parcial + (ascii_val * 8)

      # Verificamos si cumple la condición del módulo 256 == 42
      if total % 256 == 42:
        password = "".join(chars) + chr(ascii_val)
        print(f"\n[+] ¡Contraseña válida encontrada: {password}!")
        print(f"    - Suma ponderada total: {total}")
        print(f"    - Residuo (total % 256): {total % 256}")
        return password


# Ejecutar la función
encontrar_contrasena()
```

```
[*] Buscando una contraseña válida de 8 caracteres...

[+] ¡Contraseña válida encontrada: JSSSZGO,!
    - Suma ponderada total: 2602
    - Residuo (total % 256): 42
'JSSSZGO,'
>>>
```

I kept the script's own comments and print statements in Spanish, exactly as I wrote them at the time — this is what actually ran.

It's worth checking the result by hand, because it's a good way to confirm I understood the binary's logic correctly rather than just trusting the script's output. With `J=74, S=83, S=83, S=83, Z=90, G=71, O=79, ,=44`:

```
74×1 + 83×2 + 83×3 + 83×4 + 90×5 + 71×6 + 79×7 + 44×8
= 74 + 166 + 249 + 332 + 450 + 426 + 553 + 352
= 2602
```

`2602 mod 256 = 42`, exactly `'*'`. The math checks out.

## Verification

Since this password doesn't come from an encrypted string inside the binary but from solving an equation, the only way to confirm the reasoning about the validation logic was correct is to test it against the real binary. That's why I installed Wine this time — I wanted to confirm in an environment where the PE actually runs, not just on paper:

```
[house@archlinux nivel2_ctrlflow]$ wine crackme.exe
Password: JSSSZGO,
[+] Correcto!
```

Confirmed.

## Analysis summary

This level introduces ideas that weren't present in level 1:

- **An opaque predicate reused as a guard, not as decoration.** The same Pythagorean condition — constant, always true, with no dependency on the input — gets evaluated three times inside the function, and every time it appears it guards a pair of branches: one live with the correct logic, one dead with the logic inverted. It isn't an isolated decorative condition; it's the structural mechanism holding up the function's entire obfuscation.
- **Dead branches with inverted logic, not just junk code.** The three unreachable branches in this function aren't random noise — they reproduce the real logic with the result exactly flipped. That makes them active traps for anyone who tries to patch the binary or reason about the control flow without first proving the predicate is constant.
- **A mismatch between the reference count and the reconstructed source.** Four occurrences of the success string in the pseudocode, five cross-references in Ghidra. Documenting that gap without forcing it to match is part of honest analysis — it's additional evidence that the control flow was tampered with, even though I didn't reconstruct the assembly to explain the exact missing reference.
- **Validation with no unique solution.** Unlike a comparison against a fixed password, the success condition is a modular equation with multiple valid solutions. Solving the crackme isn't extracting a string — it's understanding the equation, generating any input that satisfies it, and verifying it by running the real binary, because there's no single "correct" answer you can just read off the binary.

And a lesson that already showed up in level 1 and gets confirmed more strongly here: following a known API (`strncmp`) to its first caller doesn't guarantee reaching the crackme's logic. You have to read what that function does before taking it at face value, and if it doesn't fit, keep looking through another route — in this case, through the result strings.

---

© 2026 Gino Aldair Maihuiri Romero
