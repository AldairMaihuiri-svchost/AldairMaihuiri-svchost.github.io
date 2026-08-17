---
title: "Ghidra vs. Obfuscated Binaries — Level 4: Virtual Tables and Hash Validation"
description: "Fourth level of the Ghidra reverse-engineering training series on obfuscated binaries. A PE32+ crackme compiled in C++ that dispatches validation through a factory table, builds objects with their own vtable at runtime, and validates the password by comparing its 32-bit FNV-1a hash against a constant — with a second object, reachable through the same table, whose only method always returns false."
author: Aldair Maihuiri
---

# Ghidra vs. Obfuscated Binaries — Level 4: Virtual Tables and Hash Validation

**Gino Aldair Maihuiri Romero**

([versión en español](ghidra-obfuscated-level4)) · ([Level 1](ghidra-obfuscated-level1-en)) · ([Level 2](ghidra-obfuscated-level2-en)) · ([Level 3](ghidra-obfuscated-level3-en))

This was the longest level to solve in the series so far, and I'll say it plainly: even though I'd already worked with vtables before, this time it took me a good while to get my bearings during the analysis, and at some point I stopped documenting the process step by step because I was focused on understanding what was actually happening. What follows is the full reconstruction of that analysis — the path I did document as I went, plus the rest rebuilt from the decompiler captures and the reasoning I was applying at the time, now ordered so it reads cleanly.

The binary is compiled in C++ and uses real polymorphism: a table of "factory" functions that builds one of two possible objects depending on an index variable, each object with its own virtual table (vtable), and the real validation method invoked through that vtable instead of showing up as a direct call. Unlike the previous levels, there isn't a single path from `strncmp` or from the strings to the logic — you have to cross several layers of object-oriented indirection, and one of the two possible routes doesn't lead anywhere at all.

Same setup as always: Linux, a Windows PE32+ binary, static analysis in Ghidra first, verification with Wine at the end.

---

## Initial reconnaissance

```
$ file crackme.exe
crackme.exe: PE32+ executable for MS Windows 5.02 (console), x86-64 (stripped to external PDB), 10 sections
```

Same profile as the previous three levels.

## A different starting point — and two longer dead ends

With malware I usually go straight to the `.text` section looking for the logic, so I tried that same approach here. I didn't find anything obvious right away, but I did find an empty function:

```c
void FUN_140001000(void)
{
  return;
}
```

I followed its references to `FUN_140001020`, a long function that looked promising at first glance — until I read it fully and recognized the pattern: it's the Microsoft Visual C++ CRT startup routine for a 64-bit executable (the equivalent of `mainCRTStartup`). There's the synchronization lock for thread-safe initialization (`DAT_1400280b0` with `LOCK`/`Sleep`), the registration of an unhandled exception handler via `SetUnhandledExceptionFilter`, the call to `_set_invalid_parameter_handler(FUN_140001000)` — which is exactly the empty function that led me here, a handler that does nothing — and the final processing of command-line arguments with `malloc` and `memcpy`. None of this is the crackme's logic; it's code the compiler generates for any C/C++ executable, and by this point in the series I already recognize the general shape of a CRT startup as soon as I see it, even though I'd never read one in full before.

I moved on to `strncmp`. This time the listing entry looked different from the previous levels:

```
140015300
strncmp
JMP qword ptr [->API-MS-WIN-CRT-STRING-L1-1-0.DLL::strncmp]
INDIRECTION
```

Tagged as `INDIRECTION` instead of `THUNK`/`COMPUTED_JUMP` like in levels 2 and 3 — a difference in how Ghidra classifies the jump, not something that changed how I followed it. The reference led me to `FUN_14000c740`, a function considerably longer than anything I'd seen in the previous levels. Reading it through to the end, this wasn't the validation either: it's a routine that detects and parses C++ mangled names — it checks whether a string starts with the `_Z` prefix from the Itanium ABI, or with `_GLOBAL_` followed by the suffixes used by global constructors and destructors (`_GLOBAL__I_`, `_GLOBAL__D_`), and from there breaks down the structure of the name. It's C++ runtime support code — probably related to RTTI or exception handling — and it shows up here, in a crackme that hadn't had this kind of code before, precisely because this binary actually uses classes and real polymorphism. It's the first hint, even before reaching the validation, that this level was going to revolve around object-oriented C++.

Two longer dead ends than in the previous levels, but with the same lesson as always: if a function doesn't touch the user's input or the result message, it isn't the validation, no matter how long or interesting it looks.

## Pivoting through the strings

I went to `Defined Strings` looking for `"Password: "`, and its references led me straight to the real entry function:

```c
undefined8 FUN_14001ced0(undefined8 param_1,ulonglong param_2,undefined8 param_3,undefined8 param_4)
{
  char cVar1;
  FILE *pFVar2;
  char *pcVar3;
  size_t sVar4;
  longlong *plVar5;
  undefined8 uVar6;
  char local_58 [72];

  FUN_14000da10();
  FUN_14000f6c0((byte *)"Password: ",param_2,param_3,param_4);
  pFVar2 = (FILE *)__acrt_iob_func(1);
  fflush(pFVar2);
  pFVar2 = (FILE *)__acrt_iob_func(0);
  pcVar3 = fgets(local_58,0x40,pFVar2);
  if (pcVar3 == (char *)0x0) {
    uVar6 = 1;
  }
  else {
    sVar4 = strcspn(local_58,"\n");
    local_58[sVar4] = '\0';
    plVar5 = (longlong *)(*(code *)(&PTR_FUN_14001f080)[DAT_14001e010])();
    cVar1 = (**(code **)*plVar5)(plVar5,local_58);
    (**(code **)(*plVar5 + 0x10))(plVar5);
    pcVar3 = "[-] Incorrecto.";
    if (cVar1 != '\0') {
      pcVar3 = "[+] Correcto!";
    }
    puts(pcVar3);
    uVar6 = 0;
  }
  return uVar6;
}
```

The prompt, the `fgets`, and trimming the newline are identical to the previous levels. What changes completely is the validation part — there's no `strcmp` or direct comparison here at all, just three lines of compiled C++ that took some careful unpacking:

```c
plVar5 = (longlong *)(*(code *)(&PTR_FUN_14001f080)[DAT_14001e010])();
cVar1 = (**(code **)*plVar5)(plVar5,local_58);
(**(code **)(*plVar5 + 0x10))(plVar5);
```

**The first line** calls a function selected from within a table — `PTR_FUN_14001f080` is the base address of an array of function pointers, and `DAT_14001e010` is the index that decides which one gets executed. That selected function acts as a factory: it builds an object in memory and returns a pointer to it (`plVar5`).

**The second line** is the polymorphic call itself. `*plVar5` reads the object's first field, which in C++ is the address of its vtable; `*(code **)*plVar5` takes the first pointer from that vtable; and the final call executes that method, passing it the object itself (`plVar5`, the implicit `this`) and the entered password (`local_58`). The boolean result lands in `cVar1`.

**The third line** calls the method at offset `+0x10` of the vtable — almost certainly the object's destructor, freeing the memory the factory allocated.

With that understood, it was clear the path didn't end here: I needed to go see what was inside `PTR_FUN_14001f080`, since that's where it's decided which object gets built and, therefore, which validation logic runs.

## The factory table

```
                             PTR_FUN_14001f080                               XREF[1]:     FUN_14001ced0:14001cf35(*)
       14001f080 b0 15 00        addr       FUN_1400015b0
                 40 01 00
                 00 00
                             PTR_FUN_14001f088                               XREF[1]:     FUN_14001ced0:14001cf3c(R)
       14001f088 80 15 00        addr       FUN_140001580
                 40 01 00
                 00 00
```

Two entries: index 0 points to `FUN_1400015b0`, index 1 points to `FUN_140001580`. I never checked in memory what value `DAT_140028010` actually holds at runtime, so I can't state upfront which route the program takes by default — what I did instead was review both factories to understand what each one builds, and let the final result (the password verified against the real binary) confirm which route actually mattered.

## Index 0 — an object that can never succeed

```c
void FUN_1400015b0(void)
{
  undefined8 *puVar1;

  puVar1 = (undefined8 *)FUN_14001ca10(8);
  *puVar1 = &PTR_FUN_140021af0;
  return;
}
```

This factory reserves 8 bytes — exactly the size of one pointer — and fills them with the address of a vtable, `PTR_FUN_140021af0`. It's the simplest possible object in C++: it has no data of its own, only its vtable pointer. I went to look at that table:

```
                             PTR_FUN_140021af0                               XREF[2]:     FUN_1400015b0:1400015be(*),
                                                                                          FUN_1400015b0:1400015c5(*)
       140021af0 c0 c1 01        addr       FUN_14001c1c0
                 40 01 00
                 00 00
```

(Two cross-references, both inside `FUN_1400015b0` itself — I couldn't pin down what exactly the second one corresponds to without disassembling instruction by instruction; I'm documenting it the same way I did with a similar gap in level 2, without forcing it to line up.)

A single entry, pointing to `FUN_14001c1c0`. And there, both in the listing and in the decompiler, I found the shortest function in the whole series so far:

```c
undefined8 FUN_14001c1c0(void)
{
  return 0;
}
```

An `XOR EAX,EAX` in the assembly, which in C is equivalent to `return 0`. If the program takes the index-0 route, the object it builds has a single method, and that method ignores the password parameter entirely and always returns false. It isn't a dead branch like the ones in level 2 — it's perfectly reachable if `DAT_14001e010` equals 0 — but it functionally plays the same role: a validation that can never succeed, no matter what gets typed. A decoy object, expressed in C++'s own vocabulary instead of in control-flow branches.

## Index 1 — the real object

```c
void FUN_140001580(void)
{
  undefined8 *puVar1;

  puVar1 = (undefined8 *)FUN_14001ca10(0x18);
  *puVar1 = &PTR_FUN_140021ac0;
  *(undefined4 *)(puVar1 + 1) = 0x19884f5c;
  puVar1[2] = 8;
  return;
}
```

This factory reserves considerably more room — 0x18 (24) bytes instead of 8 — because the object it builds has its own state beyond the vtable pointer: a 4-byte value, `0x19884f5c`, stored right after the vtable pointer, and a second value, `8`, stored right after that. Without having seen the validation method yet, I could already guess what those two fields were: some kind of signature or target value, and an expected password length.

This object's vtable:

```
                             PTR_FUN_140021ac0                               XREF[2]:     FUN_140001580:14000158e(*),
                                                                                          FUN_140001580:140001595(*)
       140021ac0 40 c1 01        addr       FUN_14001c140
                 40 01 00
                 00 00
```

(Same situation with the two cross-references inside the constructor function itself — documenting it without fully explaining it, same as the previous one.)

One entry, pointing to `FUN_14001c140`. This is the real validation.

## The validation algorithm: 32-bit FNV-1a

```c
bool FUN_14001c140(longlong param_1,byte *param_2)
{
  byte bVar1;
  size_t sVar2;
  uint uVar3;
  bool bVar4;

  sVar2 = strlen((char *)param_2);
  bVar4 = false;
  if (sVar2 == *(size_t *)(param_1 + 0x10)) {
    uVar3 = 0x811c9dc5;
    bVar1 = *param_2;
    while (bVar1 != 0) {
      param_2 = param_2 + 1;
      uVar3 = (uVar3 ^ bVar1) * 0x1000193;
      bVar1 = *param_2;
    }
    bVar4 = *(uint *)(param_1 + 8) == uVar3;
  }
  return bVar4;
}
```

`param_1` is the object (`this`), `param_2` is the entered password. It first compares the input's length against `*(param_1 + 0x10)` — the field the factory had initialized to `8`. If the length doesn't match, it returns false immediately without touching the rest of the algorithm.

If the length is correct, it enters the loop: it starts with `uVar3 = 0x811c9dc5` and, for each byte of the input, computes `uVar3 = (uVar3 XOR byte) * 0x1000193`. I recognized this structure right away — the initial value `0x811c9dc5` and the multiplier `0x1000193` are the standard constants for **32-bit FNV-1a** (Fowler–Noll–Vo, variant *a*, where the XOR happens before the multiplication in each iteration). At the end of the loop, it compares the result against `*(param_1 + 8)` — the field the factory had initialized to `0x19884f5c`.

The level's full rule: the password has to be exactly 8 characters long, and the 32-bit FNV-1a hash of those 8 characters has to be exactly `0x19884f5c`.

## Why this doesn't get solved by direct deduction

Unlike the weighted sum from level 2, a hash like FNV-1a can't be inverted with simple algebra. Every byte of the input reshapes the hash's internal state in a way that depends on everything that came before it — there's no linear equation to isolate. The two practical ways to solve this are pure brute force (unworkable for 8 printable characters: the search space is too large to try one by one in reasonable time) or framing the problem as logical constraints and letting a solver handle it. I went with the second option, using Z3, Microsoft's SMT (*Satisfiability Modulo Theories*) solving library.

The idea is to model each of the password's 8 characters as an 8-bit symbolic variable, constrain those variables to a reasonable range of printable characters, reproduce the exact same FNV-1a loop found in the binary but with symbolic variables instead of concrete values, and ask Z3 to find an assignment of the 8 variables that makes the resulting hash equal `0x19884f5c`.

```python
from z3 import *

def solve_fnv_hash():
    # Crear el solver SMT
    s = Solver()

    # Definir 8 variables de 8 bits (representan cada carácter de la contraseña)
    password_chars = [BitVec(f'c_{i}', 8) for i in range(8)]

    # Restringir los caracteres a un conjunto imprimible común (letras y números: a-z, A-Z, 0-9)
    for c in password_chars:
        s.add(Or(
            And(c >= ord('a'), c <= ord('z')),
            And(c >= ord('A'), c <= ord('Z')),
            And(c >= ord('0'), c <= ord('9'))
        ))

    # Constantes oficiales del algoritmo FNV-1a de 32 bits
    h = BitVecVal(0x811c9dc5, 32)
    prime = BitVecVal(0x1000193, 32)

    # Replicar exactamente el bucle FNV-1a que encontramos en el binario
    for c in password_chars:
        c_32 = ZeroExt(24, c)  # Expandir el byte a 32 bits
        h = (h ^ c_32) * prime

    # El hash objetivo extraído del crackme (0x19884f5c)
    target_hash = 0x19884f5c
    s.add(h == target_hash)

    # Resolver el sistema de ecuaciones
    if s.check() == sat:
        model = s.model()
        password = "".join([chr(model[c].as_long()) for c in password_chars])
        print(f"\n[+] ¡Contraseña encontrada con éxito!: {password}")
    else:
        print("\n[-] No se encontró solución con el conjunto de caracteres actual.")

if __name__ == "__main__":
    print("[*] Buscando la contraseña para el hash FNV-1a...")
    solve_fnv_hash()
```

I kept the script's own comments and print statements in Spanish, exactly as I wrote them at the time. On Arch Linux, installing `z3-solver` with `pip` requires a virtual environment because of the externally-managed-environment policy (PEP 668), so I installed it inside a `venv` instead of trying to install it system-wide.

## Verification

```
[house@archlinux nivel4_vtable]$ wine crackme.exe
Password: KiutOCpz
[+] Correcto!
[house@archlinux nivel4_vtable]$
```

Before calling this closed, I computed the FNV-1a hash of `KiutOCpz` myself to confirm it matches the value extracted from the binary, not just what the solver returned:

```
h = 0x811c9dc5
for each byte of "KiutOCpz": h = (h XOR byte) * 0x1000193  (mod 2^32)
final result: 0x19884f5c
```

It matches the constant from `FUN_140001580` exactly. The math checks out.

## Analysis summary

This level introduces the most different kind of obfuscation in the series so far, built on the language itself rather than on assembly-level tricks:

- **Dispatch through a factory table.** Instead of a direct call to the validation function, the program picks between two constructor routines using a runtime index, and each one builds a different object.
- **Real polymorphism (vtables).** The validation method never shows up as a named call in the decompiler — it gets invoked through the object's vtable's first pointer, which means manually tracing the object, its vtable, and the concrete method before seeing a single line of the real algorithm.
- **A decoy object with the same spirit as a dead branch.** The index-0 object is functionally equivalent to level 2's dead branches — a validation that can never succeed — but expressed as a method that ignores its input rather than as an unreachable condition.
- **Non-invertible hash validation.** Unlike level 2's weighted sum, an FNV-1a hash doesn't get solved with direct algebra. It took recognizing the algorithm's constants, modeling the problem as symbolic constraints, and using an SMT solver to find a valid input instead of deriving one by hand.
- **More C++ runtime support code to filter through.** This level's two dead ends — the CRT startup and the mangled-name detection routine — are longer than in previous levels because a binary using classes and vtables drags along more C++ runtime infrastructure before reaching the author's own code.

The underlying lesson, beyond the specific technique: when the obfuscation leans on the language's own paradigm instead of on low-level tricks, you have to reconstruct the higher-level semantics — which object is which, which vtable belongs to it, which method is actually being invoked — before the concrete algorithm makes any sense at all. Getting a little lost along the way, like I did here, is a normal part of that process.

---

© 2026 Gino Aldair Maihuiri Romero
