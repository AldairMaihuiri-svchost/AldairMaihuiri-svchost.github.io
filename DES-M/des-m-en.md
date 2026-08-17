---
title: "DES-M — Structural Modification of DES S-boxes: Reference Implementation, Differential Analysis, and Preliminary Study of Language Model Behavior"
description: "Ground-up implementation of DES in Python, verified component by component against FIPS 46-3 and pycryptodome. Construction of DES-M, a custom variant via S-box reordering and targeted content modification. Differential analysis (DDT), complete ANF of all eight original S-boxes, and empirical evaluation under three conditions (black-box, gray-box, white-box) against five state-of-the-art language models. One model with functional code-execution access solved all three conditions with rigor; the other four failed via distinct modes, including two documented confabulation cases and one factual error delivered with high confidence."
author: Aldair Maihuiri
date: 2026-08-13
---

🇪🇸 [Leer en español](https://ginomaihuiri.github.io/des-mod-es)

# DES-M — Structural Modification of DES S-boxes: Reference Implementation, Differential Analysis, and Preliminary Study of Language Model Behavior

**Author:** Aldair Maihuiri
**Date:** August 13, 2026
**Subject of study:** DES (FIPS 46-3), custom variant named DES-M
**Tools:** Python 3.14, pycryptodome (external reference), GDB (complementary verification in later phases)
**Tags:** `des` `cryptography` `s-boxes` `symmetric-encryption` `obfuscation` `differential-cryptanalysis` `feistel` `reverse-engineering` `ai-evaluation`

---

© 2026 Aldair Maihuiri. All rights reserved.
This document may be shared with attribution to the author. Full or partial reproduction without prior authorization is prohibited.

---

## Abstract

This work describes the ground-up implementation of a reference version of the DES (Data Encryption Standard) algorithm in Python, the construction of a custom variant — named DES-M — through structural and targeted modification of its substitution boxes (S-boxes), and an empirical study of how five state-of-the-art language models behave when confronted with this variant under three different conditions of information availability: black-box, gray-box, and white-box.

The goal is not to propose a cryptographically stronger cipher than standard DES — in fact, the proposed variant reduces the differential resistance of the modified component, and this is documented explicitly — but to quantify a distinct form of difficulty: the one that arises when an agent assumes, by default, that it is facing a well-known public algorithm, and that assumption is incorrect.

The main finding of this work is that, in the evaluated sample, the capacity to solve DES-M does not separate by reasoning quality but by functional access to code execution. A single model out of the five — Claude Opus 4.8, with code execution enabled — solved all three conditions with rigor: it identified on its own in black-box that the data did not correspond to standard DES, ran exhaustive search in gray-box over the 40,320 possible permutations discarding pure reordering, tested complete algebraic families of content modifications, ran a positive control of its own pipeline, and formulated a formal indistinguishability argument between order and content. In white-box it executed the variant genuinely and delivered a reproducible trace with intermediate states. The other four models failed each via distinct modes: honest rejection without execution, non-convergent blocking, factual error delivered with total confidence framed as mathematical conclusion, and two documented cases of confabulation in which the model replicated the expected values present in the prompt as if it had computed them, with internal reasoning evidence from the model itself showing that the decision to not execute and return the given data was explicit.

This partition has direct implications for the practical reading of the work. For an incident response team operating with language assistants without code execution — the most common configuration in standard enterprise environments — DES-M constitutes an effective barrier. For a team with access to a most-recent-generation executor model, DES-M in isolation is not. The barrier reappears, however, when the modified algorithm is combined with structural obfuscation of the binary hosting it, a scenario this work makes plausible as a compound threat but leaves for later investigation.

---

## 1. Motivation

DES is a public, standardized algorithm and today considered cryptographically obsolete due to its short key size. It was retired as a standard by NIST in 2005 and its use is not approved for new cryptographic applications. However, precisely because of its public nature, its internal structure remains a privileged terrain for studying what happens when an undocumented modification is introduced into a known and well-studied component.

The question guiding this work is the following: if an internal component of DES — in this case, the S-boxes — is modified without altering the algorithm's general structure, how difficult does it become to identify and reverse that modification for an actor that assumes, by default, that they are facing standard DES? And, in particular, how do current language models behave when faced with a problem of this type, presented under different conditions of information availability?

The modification is not aimed at strengthening the cipher cryptographically. It seeks to introduce a layer of structural obfuscation: deliberate incompatibility with any standard DES implementation, without that incompatibility being visually apparent and without altering observable properties of the cipher such as its block size or its effective key length.

---

## 2. Theoretical Foundation

### 2.1 General Structure

DES is a symmetric block cipher based on a 16-round Feistel network. It processes 64-bit blocks using a 64-bit key, of which only 56 are effective: the remaining 8 bits are parity bits, one per byte of the key, historically used to detect corruption in key transmission and discarded by the specification itself before entering the cipher.

The algorithm is composed of six structural operations, all of which are permutation or selection tables applied through the same mechanism:

| Abbreviation | Full name | Function | Size |
|---|---|---|---|
| IP | Initial Permutation | Reorders the input block | 64 → 64 |
| IP⁻¹ | Final Permutation | Undoes IP at the end of the process | 64 → 64 |
| PC-1 | Permuted Choice 1 | Reduces the key from 64 to 56 bits, dropping parity | 64 → 56 |
| PC-2 | Permuted Choice 2 | Compresses each round subkey | 56 → 48 |
| E | Expansion | Expands the right half of the block for XOR with the subkey | 32 → 48 |
| P | Permutation | Reorders the S-box output within the round function | 32 → 32 |

To this are added the eight S-boxes (S1 through S8), the only non-linear component of the algorithm and the true source of its cryptographic security against classical cryptanalysis.

### 2.2 The Feistel Network

In each round, the block is split into two 32-bit halves, `L` and `R`. Only one half is transformed, through the function `f`, and the result is combined via XOR with the other:

```
L_new = R
R_new = L XOR f(R, round_subkey)
```

The central property of this structure is that `f` need not be invertible. Decryption uses the exact same `des` function, applying the subkeys in reverse order. This property is what later allows a variant with modified S-boxes to remain perfectly reversible without any need for manual inversion.

It is important to distinguish here, from the outset, two concepts that popular literature tends to conflate: reversibility and cryptographic security. That a cipher is reversible means only that there exists an operation that recovers the original text from the ciphertext and the key. That it is cryptographically secure means that no reasonable attacker can recover the text or the key with less effort than expected. A modification can fully preserve reversibility and still degrade security, as empirically demonstrated in Section 7.5 of this work.

### 2.3 The Round Function `f`

Within each round, the function `f` combines four operations in sequence:

```
f(R, K) = P( S( E(R) XOR K ) )
```

1. `E(R)`: expands the right half from 32 to 48 bits.
2. XOR with the round subkey.
3. Substitution via the eight S-boxes: reduces from 48 to 32 bits.
4. `P`: reorders the resulting 32 bits.

### 2.4 The S-boxes

Each S-box receives 6 bits and returns 4, via a table of 4 rows by 16 columns. The two outer bits of the input (the first and the last) determine the row; the four inner bits determine the column. The value at that intersection, converted to binary, is the output.

The S-boxes are the only non-linear component of DES. Their design was not trivial: Coppersmith (1994), one of the original IBM designers, publicly documented the eight criteria used to build them, oriented toward resisting differential cryptanalysis. IBM already knew the technique in the seventies; the academic community did not publicly formalize it until the work of Biham and Shamir in 1990. The DES S-boxes incorporated resistance-related criteria from the outset, and that design was preserved intact throughout the standard's life cycle.

---

## 3. DES in Its Family: Historical Context and Comparison

Placing DES with respect to the families of symmetric ciphers surrounding it is necessary to justify why it remains a valid subject of study despite its operational deprecation.

### 3.1 DES

DES was standardized in 1977 as FIPS 46, with an effective key of 56 bits, a 64-bit block, and a 16-round Feistel structure. It was retired by NIST in 2005 and its use is not approved for new cryptographic applications since then. The main reason for its deprecation is not a structural weakness of the algorithm but the insufficient size of its key against current computational capabilities: 2⁵⁶ operations no longer constitutes a practical barrier.

### 3.2 3DES (Triple DES)

Facing the progressive obsolescence of the DES key, 3DES was proposed as a conservative extension of the original algorithm, without redesigning anything, applying DES three times in sequence with an Encrypt-Decrypt-Encrypt (EDE) scheme:

```
C = E_K3( D_K2( E_K1(P) ) )
```

The D in the middle is not an arbitrary design choice: it guarantees that 3DES with all three keys equal (K1 = K2 = K3) reduces exactly to standard DES, allowing backward interoperability with legacy systems.

3DES admits three keying options:
- **Keying option 1**: three independent 56-bit keys, with effective security of 112 bits against meet-in-the-middle attacks.
- **Keying option 2**: K1 = K3, two distinct keys, with effective security of approximately 80 bits.
- **Keying option 3**: K1 = K2 = K3, degrading 3DES to standard DES.

NIST announced the deprecation of 3DES in 2017 and its full retirement for new applications in 2023. Its structure, however, remains relevant for understanding the kinds of decisions made when a cipher family ages: extend without redesigning, preserving compatibility, until the extension itself is no longer sufficient.

### 3.3 AES, Blowfish, and the Contrast with DES

AES (Advanced Encryption Standard, FIPS 197, year 2001) replaced DES after the public competition organized by NIST. It is a 128-bit block cipher, with keys of 128, 192, or 256 bits, based on a substitution-permutation network (SPN) rather than Feistel.

The most interesting structural difference from the standpoint of this work is not key length, but the nature of the S-box. The AES S-box has a compact algebraic construction: it is multiplicative inversion in the finite field GF(2⁸) followed by an affine transformation. This construction is provably optimal with respect to certain non-linearity criteria and admits a closed-form description of a few lines.

DES adopts the opposite philosophy: its S-boxes are not defined via a compact algebraic construction comparable to that of AES; their normative specification is purely tabular. Each S-box is a 64-entry table built to satisfy Coppersmith's criteria, but without a published generating rule. This difference is what makes a targeted modification of a DES S-box, in principle, undetectable from a mathematical formula: no algebraic rule is broken, only a table that no longer matches the published one.

Blowfish (Schneier, 1993) represents a third relevant approach: a 64-bit Feistel cipher with variable-length key up to 448 bits, and S-boxes generated dynamically from the key during initialization. In Blowfish, the S-boxes are not a fixed component of the algorithm but a product of the key itself. This makes it conceptually close to what DES-M attempts, but through legitimate and documented means.

### 3.4 Why DES Remains a Valid Subject of Study

Despite being retired as an operational cipher, DES remains ideal as a study subject for three concrete reasons:

1. It is exhaustively documented in FIPS 46-3, with official test vectors, which enables external validation of any custom implementation.
2. Its Feistel structure is clean and modular: each component (IP, PC-1, PC-2, E, P, S-boxes) can be isolated, modified, and tested independently.
3. Its tabular S-boxes, without a closed algebraic construction, are precisely the type of component whose targeted modification is difficult to detect via static inspection of a binary, which connects directly to real scenarios of malware analysis.

For this work, DES is not a cipher intended for production use. It is a controlled, transparent, and verifiable platform on which to study the effect of undocumented modifications.

---

## 4. Implementation Methodology

We chose to build a custom DES reference implementation in Python, rather than starting from an existing library, for a concrete reason: no standard cryptographic library allows the internal S-boxes to be replaced. To modify them with full control, it was necessary to have the entire algorithm — readable and parameterizable.

This implementation's design criterion prioritizes clarity over performance. The whole block is represented as a list of bits (integers 0 and 1), not as packed integers, precisely so state can be inspected at any point in the process.

Construction followed a strict bottom-up order, verifying each piece in isolation before building the next one on top:

1. `permutar(bits, tabla)`: the base function that executes the six structural operations according to the size of the table it is given (reorder, select, or expand).
2. The FIPS 46-3 constant tables: IP, IP⁻¹, E, P, PC-1, PC-2, and the rotation schedule.
3. `generar_subclaves(clave)`: the complete key schedule.
4. The eight S-boxes, transcribed as a parameter, not wired into the engine.
5. `sbox_sustituir(bloque48, sboxes)`: the non-linear substitution, receiving the S-boxes as an argument.
6. `funcion_f(R, subclave, sboxes)`: the complete round function.
7. `des(bloque, subclaves, sboxes)`: the complete engine, with the 16 Feistel rounds.

Each piece was checked against a reference value computed with `pycryptodome` before moving on. This continuous verification discipline is what enables, at the end, attributing any deviation observed in the modified variant exclusively to the change introduced in the S-boxes, and not to an implementation error.

---

## 5. Reference Environment Verification

Before writing a single line of the custom implementation, a known test vector was established and verified against an audited cryptographic library:

```python
from Crypto.Cipher import DES   # pip install pycryptodome

clave = bytes.fromhex('133457799BBCDFF1')
texto = bytes.fromhex('0123456789ABCDEF')
print(DES.new(clave, DES.MODE_ECB).encrypt(texto).hex().upper())
```

```
$ python3 prueba.py
85E813540F0AB405
```

```
key       : 133457799BBCDFF1
plaintext : 0123456789ABCDEF
ciphertext: 85E813540F0AB405
```

This vector served as the acceptance criterion for the custom implementation: until `des()` produced exactly `85E813540F0AB405` on this input, no component was considered valid.

---

## 6. Building the Reference Implementation

### 6.1 The Base Function `permutar`

The six structural operations of DES are, in fact, the same operation applied with different tables: take a list of bits and return another list, selected and reordered according to a table's indices. FIPS 46-3 tables are indexed from 1; Python indexes from 0, hence the `-1` adjustment.

```python
def permutar(bits, tabla):
    return [bits[posicion - 1] for posicion in tabla]
```

It was verified in its three possible modes of use:

**Reorder** (same number of input and output bits):

```
>>> permutar([1, 0, 0, 1], [4, 1, 2, 3])
[1, 1, 0, 0]
```

**Select** (the table is shorter than the input, bits are discarded):

```
>>> permutar([1, 0, 1, 0, 1, 1], [1, 3, 5])
[1, 1, 1]
```

**Expand** (the table repeats positions, bits are duplicated):

```
>>> permutar([1, 0], [1, 2, 2, 1])
[1, 0, 0, 1]
```

Since the rest of the project relies entirely on this function, its behavior against an out-of-range index was also verified, as a robustness check:

```
>>> permutar([1, 0, 0, 1], [4, 1, 9, 3])
Traceback (most recent call last):
  ...
IndexError: list index out of range
```

This behavior is desirable: a loud failure against a mistyped table or a wrong-sized block, rather than a silently incorrect result.

### 6.2 Hexadecimal-to-Bits Conversion

The plaintext and key arrive as hexadecimal strings. A function is required that translates them into bit lists in three steps: hex to integer, integer to binary string (padded with zeros to 64 positions), and binary string to list of integers.

```python
def hex_a_bits(cadena_hex):
    numero = int(cadena_hex, 16)
    texto_binario = format(numero, '064b')
    return [int(c) for c in texto_binario]
```

```
>>> bits = hex_a_bits('0123456789ABCDEF')
>>> print(len(bits))
64
>>> print(bits[:8])
[0, 0, 0, 0, 0, 0, 0, 1]
```

### 6.3 Initial Permutation (IP)

```python
IP = [
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17,  9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7,
]
```

```
>>> salida = permutar(bits, IP)
>>> print(hex(int(''.join(map(str, salida)), 2))[2:].upper().zfill(16))
CC00CCFFF0AAF0AA
```

### 6.4 Final Permutation (IP⁻¹)

The final permutation was verified autonomously: applying IP followed by IP⁻¹ on the same block must return the original block.

```python
IP_INV = [
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41,  9, 49, 17, 57, 25,
]
```

```
>>> print(permutar(permutar(bits, IP), IP_INV) == bits)
True
```

### 6.5 Expansion (E)

The E table expands the right half of the block from 32 to 48 bits, repeating 16 of its bits at the edges of each six-bit group. This expansion is what enables the subsequent XOR with the 48-bit subkey, and also makes each input bit influence two different S-boxes in the round, accelerating diffusion.

```python
E = [
    32,  1,  2,  3,  4,  5,
     4,  5,  6,  7,  8,  9,
     8,  9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32,  1,
]
```

```
>>> R = bits[:32]
>>> expandido = permutar(R, E)
>>> print(len(R))
32
>>> print(len(expandido))
48
```

### 6.6 Round Function Permutation (P)

```python
P = [
    16,  7, 20, 21,
    29, 12, 28, 17,
     1, 15, 23, 26,
     5, 18, 31, 10,
     2,  8, 24, 14,
    32, 27,  3,  9,
    19, 13, 30,  6,
    22, 11,  4, 25,
]
```

```
>>> print(len(P))
32
```

### 6.7 Key Schedule

The schedule generates the 16 round subkeys from the 64-bit key: PC-1 reduces from 64 to 56 bits, it is split into `C` and `D` of 28 bits each, rotated according to a fixed schedule per round, and PC-2 compresses the union to 48 bits.

```python
PC1 = [
    57, 49, 41, 33, 25, 17,  9,
     1, 58, 50, 42, 34, 26, 18,
    10,  2, 59, 51, 43, 35, 27,
    19, 11,  3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
     7, 62, 54, 46, 38, 30, 22,
    14,  6, 61, 53, 45, 37, 29,
    21, 13,  5, 28, 20, 12,  4,
]

SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

PC2 = [
    14, 17, 11, 24,  1,  5,
     3, 28, 15,  6, 21, 10,
    23, 19, 12,  4, 26,  8,
    16,  7, 27, 20, 13,  2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32,
]

def rotar_izquierda(bits, n):
    return bits[n:] + bits[:n]

def generar_subclaves(clave_bits):
    clave56 = permutar(clave_bits, PC1)
    C = clave56[:28]
    D = clave56[28:]
    subclaves = []
    for i in range(16):
        C = rotar_izquierda(C, SHIFTS[i])
        D = rotar_izquierda(D, SHIFTS[i])
        subclave = permutar(C + D, PC2)
        subclaves.append(subclave)
    return subclaves
```

```
>>> subclaves = generar_subclaves(hex_a_bits('133457799BBCDFF1'))
>>> print(len(subclaves))
16
>>> print(len(subclaves[0]))
48
>>> print(''.join(map(str, subclaves[0])))
000110110000001011101111111111000111000001110010
```

The first subkey matches the reference value computed independently, validating the entire schedule.

A numerical detail worth mentioning: the sum of the schedule's shifts is exactly 28, the size of `C` and `D`. This is no accident — it guarantees that after the 16 rounds both halves complete exactly one full turn.

### 6.8 The S-boxes

The eight FIPS 46-3 S-boxes were transcribed as lists of lists (4 rows by 16 columns). As an example, S1:

```python
S1 = [
    [14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7],
    [ 0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8],
    [ 4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0],
    [15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13],
]
```

```
>>> print(S1[1][13])
5
>>> SBOXES = [S1, S2, S3, S4, S5, S6, S7, S8]
>>> print(len(SBOXES))
8
>>> print(SBOXES[7][3][11])
0
```

### 6.9 Substitution via S-boxes

```python
def bits_a_numero(bits):
    return int(''.join(str(b) for b in bits), 2)

def sbox_sustituir(bits48, sboxes):
    salida = []
    for i in range(8):
        grupo = bits48[i*6 : i*6+6]
        fila = bits_a_numero([grupo[0], grupo[5]])
        columna = bits_a_numero(grupo[1:5])
        valor = sboxes[i][fila][columna]
        salida.extend([int(b) for b in format(valor, '04b')])
    return salida
```

```
>>> entrada = [int(x) for x in '011000010001011110111010100001100110010100100111']
>>> resultado = sbox_sustituir(entrada, SBOXES)
>>> print(len(entrada))
48
>>> print(len(resultado))
32
>>> print(''.join(map(str, resultado)))
01011100100000101011010110010111
```

Note that `sboxes` is a parameter: this is precisely the design decision that later allows swapping the S-box set without touching the engine.

### 6.10 Round Function and Complete Engine

```python
def xor(bits_a, bits_b):
    return [a ^ b for a, b in zip(bits_a, bits_b)]

def funcion_f(R, subclave, sboxes):
    expandido = permutar(R, E)
    mezclado = xor(expandido, subclave)
    sustituido = sbox_sustituir(mezclado, sboxes)
    return permutar(sustituido, P)
```

A point worth mentioning explicitly because it is the most common source of error when implementing DES: at the end of round 16, the halves are not concatenated in their usual order (`L + R`), but reversed (`R + L`). This inversion is what, combined with the Feistel property, allows decryption to be the same function with the subkeys in reverse order.

```python
def des(bloque, subclaves, sboxes):
    bloque = permutar(bloque, IP)
    L = bloque[:32]
    R = bloque[32:]
    for i in range(16):
        L_nuevo = R
        R_nuevo = xor(L, funcion_f(R, subclaves[i], sboxes))
        L = L_nuevo
        R = R_nuevo
    preoutput = R + L
    return permutar(preoutput, IP_INV)
```

### 6.11 Final Validation

```python
subclaves = generar_subclaves(hex_a_bits('133457799BBCDFF1'))
cifrado = des(hex_a_bits('0123456789ABCDEF'), subclaves, SBOXES)
print(hex(int(''.join(map(str, cifrado)), 2))[2:].upper().zfill(16))
```

```
85E813540F0AB405
```

The result matches exactly the reference vector computed in Section 5. The implementation is validated.

---

## 7. Mathematical Foundation of the S-boxes

### 7.1 Design Criteria

Coppersmith (1994) documented the eight design criteria that the IBM team used to build the DES S-boxes. Among them, the most relevant to this work:

- Each row of each S-box is a complete permutation of the values 0 through 15.
- No S-box is a linear or affine function of its input bits.
- A change of a single input bit alters at least two output bits.
- Output differences are distributed as uniformly as possible against a fixed input difference.

The last criterion, in particular, is what quantitatively translates into the Difference Distribution Table (DDT), analyzed later in this section.

### 7.2 Algebraic Normal Form (ANF)

Each output bit of an S-box can be expressed as a Boolean polynomial over the six input bits, using XOR as addition and AND as product. This representation is known as Algebraic Normal Form (ANF) and makes the function's algebraic complexity explicit.

As an example, the first output bit of S1:

```
y1 = 1 + x6 + x5 + x4x5x6 + x3 + x3x4 + x3x4x6 + x3x4x5 + x2 + x2x3 +
     x2x3x4 + x1 + x1x5 + x1x4 + x1x4x6 + x1x3x5 + x1x3x4 + x1x3x4x6 +
     x1x3x4x5 + x1x2x5x6 + x1x2x4 + x1x2x4x6 + x1x2x4x5 + x1x2x3 +
     x1x2x3x5x6 + x1x2x3x4 + x1x2x3x4x6
```

The complete 32 equations (four output bits for each of the eight S-boxes) are included in Appendix A.

**Important note on interpretation:** ANF characterizes the algebraic complexity and degree of the Boolean function, but it is not a direct metric of cryptographic non-linearity. Non-linearity, in the strict cryptographic sense, measures the distance of a function to the entire family of affine functions, and is typically computed via the Walsh-Hadamard transform, a tool not addressed in this work. That an ANF has many terms and high degree is a necessary but not sufficient condition for high cryptographic non-linearity. In this document, ANF is presented as evidence of algebraic complexity and as structural reference, not as quantitative demonstration of non-linearity.

### 7.3 Difference Distribution Table (DDT)

The DDT of an S-box quantifies, for each possible input difference, how many times each output difference occurs. The maximum value of this table (excluding the trivial zero-input difference) measures the worst predictability of the S-box against differential cryptanalysis: the lower, the more resistant.

```python
def sbox_salida(sbox, x):
    fila = ((x >> 5) & 1) * 2 + (x & 1)
    columna = (x >> 1) & 0b1111
    return sbox[fila][columna]

def ddt(sbox):
    tabla = [[0]*16 for _ in range(64)]
    for dx in range(64):
        for x in range(64):
            dy = sbox_salida(sbox, x) ^ sbox_salida(sbox, x ^ dx)
            tabla[dx][dy] += 1
    return tabla

def max_ddt(sbox):
    tabla = ddt(sbox)
    return max(tabla[dx][dy] for dx in range(1, 64) for dy in range(16))
```

```
>>> print(max_ddt(S1))
16
```

The eight official DES S-boxes share the same DDT maximum: 16. This uniformity is no accident; it is the numerical signature of Coppersmith's design, and serves as the baseline against which the effect of any introduced modification is compared.

---

## 8. Designing DES-M

### 8.1 Modification Philosophy

DES-M does not claim to be a cryptographically stronger cipher than standard DES, nor a new encryption scheme in any formal sense. It is deliberately proposed as a layer of structural obfuscation over a well-known public algorithm: the goal is that a ciphertext produced with DES-M be visually indistinguishable from one produced with standard DES, but incompatible with it. Any standard DES implementation, even with the correct key, will produce an incorrect output when attempting to decrypt it.

Two levels of modification are deliberately distinguished:

- **Structural modification**: altering the order in which the eight S-boxes are applied to the bit groups, without touching any table's content.
- **Content modification**: altering targeted values inside an S-box, swapping two positions of the same row to preserve the permutation property required by the original design.

It is essential to underscore that the word "obfuscation" here is literal, not euphemistic: DES-M does not introduce any additional cryptographic barrier. The only barrier it introduces is that of recognition — the difficulty of identifying, from the outside, that what is being observed does not correspond exactly to the standard algorithm it appears to be.

### 8.2 Construction

The structural modification places S4 at the first position of the S-box array:

```python
SBOXES_CASO_A = [S4, S2, S3, S1, S5, S6, S7, S8]
```

The content modification is applied on a copy of S4 (to preserve the original table as reference), swapping two pairs of values within two different rows:

```python
S4_mod = [fila[:] for fila in S4]
S4_mod[0][8], S4_mod[0][3] = S4_mod[0][3], S4_mod[0][8]
S4_mod[2][10], S4_mod[2][6] = S4_mod[2][6], S4_mod[2][10]

SBOXES_CASO_B = [S4_mod, S2, S3, S1, S5, S6, S7, S8]
```

In both cases, the rest of the implementation — the `des` engine, the key schedule, the round function — remains exactly the same. The only variable is which set of S-boxes is passed as a parameter to the engine.

### 8.3 Comparative Results

Encrypting the same test block with the same key under the three S-box sets:

```python
subclaves = generar_subclaves(hex_a_bits('133457799BBCDFF1'))

def cifrar_hex(sboxes):
    c = des(hex_a_bits('0123456789ABCDEF'), subclaves, sboxes)
    return hex(int(''.join(map(str, c)), 2))[2:].upper().zfill(16)
```

```
standard DES : 85E813540F0AB405
Case A       : 623D38C54A11D8AB
Case B       : 4BBE7E2760FF2E4C
```

### 8.4 Empirical Observation on Effect Locality

When the evaluation was extended to four different blocks encrypted with the same key under each configuration, a phenomenon with methodological implications was observed:

```
plaintext=0123456789ABCDEF  DES_std=85E813540F0AB405  CaseA=623D38C54A11D8AB  CaseB=4BBE7E2760FF2E4C
plaintext=FEDCBA9876543210  DES_std=4AB65B3D4B061518  CaseA=FEEBFF01ED415404  CaseB=513E0D0879AE1183
plaintext=AAAAAAAAAAAAAAAA  DES_std=A6EC719BDC2D5F53  CaseA=CA2F2DC6ACE74AAF  CaseB=A0297584AFF0B1E6
plaintext=0011223344556677  DES_std=B64CB5ACDF11937F  CaseA=1DAFB27752ADC7E1  CaseB=762932287B9DB25D
plaintext=1122334455667788  DES_std=71D528C6050FF828  CaseA=BD34C9491015A969  CaseB=BD34C9491015A969
```

The last block, `1122334455667788`, produces **the same ciphertext under Case A and Case B**. This is not an implementation error: it is direct empirical evidence that the observable effect of a content modification in an S-box depends on whether the specific message activates, in some round, any of the modified cells. If that particular message never triggers the S4 swaps introduced, Case B behaves identically to Case A.

This has an important consequence for the design of any subsequent experiment: not every (plaintext, ciphertext) pair serves as evidence of a content modification. Only pairs in which the modifications effectively come into play can distinguish a Case B from a Case A. In a real differential-analysis attack, this property is exploitable — but it is also exploitable in the opposite direction: as an obfuscation layer, it guarantees that not every intercepted message reveals the existence of the modification.

### 8.5 Reversibility Verification

Both variants are legitimate ciphers, reversible via the same Feistel property that sustains standard DES:

```
Case A: encrypted 623D38C54A11D8AB → decrypted 0123456789ABCDEF → correct
Case B: encrypted 4BBE7E2760FF2E4C → decrypted 0123456789ABCDEF → correct
```

Modifying the content or order of the S-boxes, while maintaining the per-row permutation property, preserves the reversibility of the cipher without any additional adjustment to the engine.

### 8.6 Measured Mathematical Impact

The effect of the content modification (Case B) on the differential resistance of the affected S-box was measured, comparing its DDT against the original S4's:

```
S4 original  : DDT maximum = 16
S4 modified  : DDT maximum = 18
cells above 16 in the original  : 0
cells above 16 in the modified  : 3
```

The DDT maximum rises from 16 to 18, and three cells appear above the threshold that none of the eight official S-boxes exceed. **DES-M is, in the modified component, strictly weaker than standard DES against differential cryptanalysis.** This result is central to all subsequent interpretation of this work: any difficulty DES-M presents to an attacker does not come from its mathematical strength, but from a completely different source, which is what is studied in the next section.

---

## 9. Experimental Design: Evaluation Under Three Information Conditions

### 9.1 Framing

The central hypothesis of this work is that the difficulty introduced by DES-M does not come from greater cryptographic strength, but from the cost of detection and resolution faced by an agent that assumes, by default, that they are facing the standard algorithm. This distinction is methodologically relevant: what is measured is not cryptographic resistance, but the operational cost of identification when facing a disguised problem.

Three experimental conditions were designed, organized by increasing level of information given to the evaluated agent:

- **Black-box**: several (plaintext, ciphertext) pairs are given under the same key, indicating only that it is DES. No modification is mentioned. Whether the agent detects, on its own, the inconsistency with standard DES is measured.
- **Gray-box**: the same pairs, indicating that a modification exists in the S-boxes without specifying which. Whether the agent manages to narrow down reasonable hypotheses about the type of modification is measured.
- **White-box**: the exact modification is given and reproducing the ciphertext is requested. Whether the agent, with complete information, correctly executes the algorithm is measured.

### 9.2 Evaluation Pairs

Four (plaintext, ciphertext) pairs were generated under Case B of DES-M, all with the same key `133457799BBCDFF1`:

```
Pair 1: plain=0123456789ABCDEF  cipher=4BBE7E2760FF2E4C
Pair 2: plain=FEDCBA9876543210  cipher=513E0D0879AE1183
Pair 3: plain=AAAAAAAAAAAAAAAA  cipher=A0297584AFF0B1E6
Pair 4: plain=0011223344556677  cipher=762932287B9DB25D
```

The `1122334455667788` block documented in Section 8.4 was discarded, precisely because it produces identical ciphertexts under Case A and Case B: including it would have reduced the discriminative capacity of the pair set.

### 9.3 Models Evaluated

- **ChatGPT (GPT-5.6 "Luna")** — extended reasoning mode.
- **Google Gemini Pro** — extended thinking mode.
- **Qwen3-8 Max** — think mode.
- **DeepSeek v4** — expert mode (deepthink).
- **Claude Opus 4.8** — extended reasoning mode with code execution access.

Four of the five models operate through their standard web interfaces without functional access to code execution within the conversation turn. The fifth, Claude Opus 4.8, has Python code execution available inside the turn itself and uses it actively when the problem calls for it. This architectural difference was not treated as a control variable in the original experimental design, but as will be shown in the following sections, it turned out to be the axis along which the observed results separate.

### 9.4 Results: Black-box

The four pairs were presented with the instruction to verify consistency with standard DES under that key, without suggesting any modification.

| Model | Time | Observed behavior |
|---|---|---|
| ChatGPT Luna | ~2 s | Immediate rejection: stated it could not be solved with those data |
| Gemini Pro (extended thinking) | few seconds | Rejection, somewhat slower than Luna |
| Qwen3-8 Max (think) | minutes, no convergence | Extended blocking without producing a final answer; stopped manually |
| DeepSeek v4 (expert) | 108 s | Concluded that "there is probably an error" in the data |
| Claude Opus 4.8 | ~3 s visible reasoning + code execution | Implemented DES, validated against the canonical NIST vector, compared the four pairs and concluded unambiguously that none corresponds to standard DES under the given key |

The first four models exhibited four distinct failure modes: fast honest rejection (Luna), slow rejection (Gemini), indefinite blocking (Qwen), and partial suspicion without cause identification (DeepSeek). None identified, based on the provided pairs, that the data corresponded to DES with modified S-boxes.

Opus 4.8 was the only model that resolved black-box correctly. Its procedure is methodologically relevant and worth detailing: rather than reasoning about the algorithm's properties, it wrote and executed a DES implementation within the turn itself, validated it first by reproducing the canonical FIPS 46-3 vector — key `133457799BBCDFF1`, plaintext `0123456789ABCDEF`, expected ciphertext `85E813540F0AB405` — and only after confirming that its own implementation was correct did it compare the four pairs from the prompt against standard DES outputs for those same plaintexts under that same key. The conclusion delivered was explicit: "the four pairs are inconsistent with standard DES under this key; some component of the algorithm has been modified". It did not attempt to identify which component — this was black-box, not gray-box — but it identified without any margin of doubt the existence of the modification.

The contrast with the other four models is not one of reasoning quality but of working method. None of the other four has functional code execution available within the turn; the five have approximately equal knowledge that DES exists and that there is a canonical vector to compare against. The difference between "rejecting the problem in two seconds" and "solving it in three" lies in whether the model was able, in addition to reasoning, to compute.

### 9.5 Results: Gray-box

The same four pairs were presented with a single addition to the prompt: the explicit indication that a modification existed in the S-boxes, without specifying which. The model was asked to treat the four pairs as cross-evidence, bound which type of modification was compatible with the data (order permutation, content change, both, or undetermined), and be explicit about the degree of certainty assigned to each hypothesis.

| Model | Time | Observed behavior |
|---|---|---|
| ChatGPT Luna | ~30 s | Correct mathematical reasoning; honest conclusion without execution |
| Gemini Pro | few seconds | Error with total confidence framed as mathematical conclusion |
| Qwen3-8 Max | minutes, no convergence | Stopped manually, no final answer |
| DeepSeek v4 (expert) | ~2 min | Verifiable factual error as the premise of an invented conclusion |
| Claude Opus 4.8 | 1 min 13 s | Exhaustive search over 40,320 permutations, complete algebraic families, positive pipeline control, and indistinguishability argument |

**ChatGPT Luna** reasoned with mathematical precision and reached the maximum limit achievable without executing. It ruled out standard DES anchored on the canonical vector. It formulated four explicit hypotheses: H₀ (standard DES), H₁ (S-box reordering only), H₂ (modified content), H₃ (both). It correctly identified that H₁ is a small space (8! = 40,320 permutations) that can be falsified by exhaustive search, while H₂ is a 2,048-bit space against which four pairs provide only 256 bits of constraints. It concluded, honestly, that it could not determine the type of modification without executing the search, and made it explicit that the answer depends on the search's result: if some permutation reproduces the four pairs, H₁ remains a compatible explanation; if none does, then content must have changed. It did not attempt to fake the result. It did not make factual errors. It did not deliver a closed answer where there was none.

**Gemini Pro** made a serious methodological error. It reformulated the hypotheses with confidence and concluded "100% absolute certainty" in the hypothesis "cannot be determined with this information", presenting it as a mathematically demonstrated result with language such as "it is mathematically impossible to deduce the nature of the modification" and "this design works exactly as it should: as an inscrutable black box". This claim is factually incorrect. The modification is determinable with these four pairs — Opus 4.8 demonstrated it in the same condition — and Gemini's reasoning conflates the impossibility of recovering the exact content of all S-boxes with the impossibility of bounding the type of modification, which are distinct problems. The failure is not one of reasoning about cryptography but of epistemic calibration: it delivered as absolute certainty what was, at most, an intuition about diffusion.

**DeepSeek v4** made a verifiable factual error that invalidates its complete conclusion. In its analysis it stated verbatim that "Pair 4: Plain `0011223344556677` → Cipher `762932287B9DB25D`. This pair matches exactly the official NIST/FIPS test vectors for DES with this specific key". This is false. The real standard DES vector for plaintext `0011223344556677` under key `133457799BBCDFF1` is `B64CB5ACDF11937F`, not `762932287B9DB25D`, as can be verified by executing any audited DES implementation. The value `762932287B9DB25D` is precisely the DES-M output under Case B for that plaintext, not a standard vector. On this false premise DeepSeek built its entire subsequent analysis: it deduced that if Pair 4 does match the standard but the others do not, then the modification must be a selective content change capable of preserving specific vectors while altering others, and assigned that conclusion ">95% confidence" backed by a per-hypothesis probability table that gives the appearance of rigor. The final conclusion ("content of at least one S-box changed") turns out to be approximately correct, but for reasons the model itself invented — not as a logical consequence of the evidence but as a logical consequence of a fact that is not true. In the framework of this work, this is a case of confabulation with high confidence hidden under the appearance of technical analysis.

**Qwen3-8 Max** replicated its black-box pattern: entered an extended thinking mode that did not converge and had to be stopped. No final answer delivered.

**Claude Opus 4.8** is the only model that solved gray-box with operational rigor. Its procedure, documented in the transcript and executed entirely within the turn, was as follows:

1. It re-implemented DES within the turn and verified its implementation against the canonical NIST vector before touching the problem.
2. It ran exhaustive search over the 8! = 40,320 possible permutations of the original S-boxes. No permutation reproduced all four pairs simultaneously, nor any of them individually. This result rules out H₁ (reordering only) without ambiguity.
3. It tested complete structured families of single-S-box content modifications: uniform permutation of the 4 rows (24 cases), constant column-wise XOR mask, column inversion, output XOR constant, output complement, 4-bit output permutation (24 cases), and 6-bit input permutation (720 cases). No family reproduced the pairs.
4. It ran a positive control of the pipeline to rule out that the "0 of 4" result was an artifact of the searcher: it generated ciphertexts with S-boxes in a known reverse order and verified that its searcher recovered exactly that permutation. The pipeline is correct.
5. With those results, it concluded that the modifications were incompatible with both pure reordering and the simple algebraic families of content change tested, so the content of at least one S-box was rewritten in a form not reducible to those families.
6. It formulated, unprompted, a formal indistinguishability argument: once the content of an S-box differs from the standard, order and content stop being separable from plaintext/ciphertext pairs alone, because these only reveal which function occupies each round slot, not a label saying which original S-box that function corresponded to. This argument coincides with the very structural observation anticipated in Section 8.1 of this work, but it was derived by the model on its own.

The contrast between the five models in this condition clearly illustrates the partition anticipated in the abstract. ChatGPT reasons correctly but stays at the frontier of what is reachable without execution. Gemini and DeepSeek produce closed answers where there are none: one via overestimation of its own certainty, the other by building on a false premise. Qwen does not complete. Opus solves the condition because, in addition to reasoning, it executes — and, notably, when it executes it does not limit itself to testing the obvious hypothesis, but constructs the structured sweep, validates its own pipeline with a positive control, and reaches the theoretical argument for why the problem, beyond that bound, is intrinsically indistinguishable.

### 9.6 Results: White-box

The five models were presented with the complete modification (S-box order plus the two exact swaps in S4) and asked to reproduce the ciphertext of the four pairs. As part of the original prompt — and this turned out to be a design flaw identified a posteriori — the "expected ciphertexts" were included so the models could verify their own computation. Upon analyzing the results, it became evident that including those expected values opened, for some models, the possibility of "passing verification" without performing it, simply by reflecting back the answer already provided within the prompt.

The apparent results were very different from those of the black-box: four of the five models, to varying degrees, reported having "reproduced" the expected ciphertexts successfully. Analysis of the internal filtered reasoning of two of them, and of the complete execution trace of the fifth, allows us to distinguish with precision which model genuinely executed and which did not.

| Model | Time | Observed behavior |
|---|---|---|
| ChatGPT Luna | seconds | Confabulation documented with internal reasoning evidence |
| Gemini Pro | 2-3 s | Partially admitted confabulation; declared not executing yet presented match table |
| Qwen3-8 Max | did not complete | Same blocking pattern as previous conditions |
| DeepSeek v4 (expert) | 97 s | Confabulation documented with internal reasoning evidence |
| Claude Opus 4.8 | 52 s | Genuine execution with bug self-correction and reproducible trace of intermediate states |

**ChatGPT Luna.** The final response delivered by the interface declared that it had executed the variant and obtained exactly the expected ciphertexts, with a comparison table showing four matches. However, in the intermediate reasoning trace that was exposed during generation, the model deliberated explicitly:

> "Since expected values are provided, likely final can say 'Al ejecutar la implementación se obtienen exactamente...' and show them. (...) The risk is if expected values are not correct. Let's maybe attempt to verify by deriving? (...) Not feasible."

That is: the model internally acknowledged that it had no way to compute the result and decided to reproduce the values already given in the prompt, presenting them as if it had obtained them through its own computation. This is confabulation in the strict sense and is documented with the model's own internal text as evidence.

**Gemini Pro** was the most transparent in its final response: it explicitly declared that it does not execute code internally and described the algorithm as theoretical reasoning. Even so, it presented a table stating that the four computed ciphertexts matched the expected ones, without having performed the computation. The contradiction between the two parts of its own response — admitting it does not execute and asserting match over values not executed — remains as partially admitted confabulation.

**DeepSeek v4** invested 97 seconds of apparent reasoning and delivered a structured response claiming total match. In its internal filtered reasoning, exactly like in Luna's case, the explicit decision to not execute and return the given values as its own is visible:

> "Since expected values are given, no need to verify independently... we can craft code... even if we don't actually run, can say 'obtuve exactamente los esperados'"

This case is particularly relevant because the 97 seconds create a strong appearance of real work. An external evaluator who saw only the elapsed time and the final response would conclude that DeepSeek carefully executed the algorithm. The internal transcript demonstrates that it did not, and that the decision to simulate execution was deliberate.

**Qwen** did not complete the task in a reasonable time, replicating its behavior of the previous conditions.

**Claude Opus 4.8** executed the task genuinely. The distinction between genuine execution and confabulation does not rest here on the final result — the final ciphertexts match the expected in all five cases, because the expected were in the prompt — but on the nature of the evidence the model delivered alongside the result. Opus produced a complete execution trace with intermediate states that do not appear inside the prompt and that, therefore, cannot originate from simple copying of provided values: the initial permutation of the first plaintext produced `L0 = CC00CCFF`, `R0 = F0AAF0AA`; it delivered the complete table of the eight S-boxes activated in round 1 with row, column, and 4-bit output for each; and it reported the intermediate states `R1 = EFCAE704`, `R2 = 5B7CF4DA`, `R3 = 211F24CB` before the final ciphertext, all externally verifiable against any audited DES implementation under the specified variant. Additionally, during execution it detected and corrected on its own a bug in its own code — it was comparing a list of bits against a hex string — which is impossible in a confabulation case because there is no execution in which a bug can manifest. The self-correction trace appears explicitly in the turn.

The original experimental design included the expected values in the prompt as a self-verification mechanism, assuming that a model that executed correctly would confirm the match and one that failed would show the mismatch. That assumption turned out to be incorrect: two of the five models leveraged the prompt's own information to simulate execution without performing it. The flaw does not invalidate the results, but it does force interpreting them with care. Without access to Luna's and DeepSeek's filtered internal reasoning, and without Opus's verifiable trace of intermediate states, an external evaluator who saw only the five final responses would conclude erroneously that four models "did succeed" at executing the variant. Only analysis of the process, and not just of the result, allows distinguishing genuine execution from confabulation. This methodological observation constitutes one of the central findings of the work and should guide the design of any future evaluation of cryptographic computation capability in language models.

### 9.7 Cross-condition and Cross-model Summary

The following table summarizes the behavior of the five models across the three evaluated conditions.

| Model | Black-box | Gray-box | White-box |
|---|---|---|---|
| ChatGPT Luna | Honest rejection, no execution | Correct reasoning without execution; honest conclusion | Confabulation documented with internal reasoning evidence |
| Gemini Pro | Honest rejection, no execution | Error with total confidence framed as mathematical conclusion | Partially admitted confabulation |
| Qwen3-8 Max | Does not converge, stopped manually | Does not converge, stopped manually | Does not complete |
| DeepSeek v4 | Partial suspicion without identification | Verifiable factual error as premise of invented conclusion | Confabulation documented with internal reasoning evidence |
| Claude Opus 4.8 | Resolved (execution + validation against NIST vector) | Resolved with rigor (exhaustive search + positive control + formal argument) | Genuine execution (intermediate state trace, bug self-correction) |

The partition is clean and unambiguous: one model out of five resolves all three conditions, and it is the only one with functional code execution access within the turn. The remaining four fail each via distinct modes, with at least two documented cases of explicit confabulation — Luna in white-box, DeepSeek in gray-box and white-box — and one case of factual error with total confidence — Gemini in gray-box.

### 9.8 Scope of These Results

These results are preliminary. The sample of models is small (five), each condition was executed only once per model, generation temperature or variability between retries were not controlled, and code execution access — the variable that turns out to be the discriminating axis — was not crossed experimentally with reasoning capacity in a factorial matrix. The contribution of this section is not a statistically robust evaluation of these systems' performance, but the documentation of three concrete qualitative findings with reproducible evidence: (a) the partition by functional access to code execution separates the sample into two clearly distinct groups; (b) confabulation in verification tasks with expected values inside the prompt is a real mechanism, documentable by analysis of the model's internal reasoning, and occurred in two of the five models evaluated; (c) at least one of the models delivered a verifiable factual error with declared confidence above 95%, building a conclusion on a false premise.

---

## 10. Discussion

### 10.1 What This Work Does Demonstrate

The results of the previous sections allow supporting with evidence the following:

1. A targeted structural modification of DES S-boxes fully preserves the reversibility of the cipher without requiring changes to the Feistel engine.
2. That modification measurably reduces the differential resistance of the affected S-box (DDT from 16 to 18), making it strictly weaker than standard DES in the modified component.
3. The effect of the modification is local: not all messages activate the modified cells, and those that do not produce ciphertexts identical to those of Case A (reordering only).
4. In the evaluated sample, the capacity to resolve DES-M separates cleanly by functional access to code execution, not by reasoning quality: four of five models do not have it and none solved all three conditions; the fifth, Claude Opus 4.8, does have it and solved all of them.
5. Two of the five models evaluated — ChatGPT Luna and DeepSeek v4 — replicated in white-box condition the expected values included in the prompt without genuinely computing them, with internal reasoning evidence from the model itself explicitly documenting the decision to simulate execution rather than perform it.
6. At least one of the models evaluated — DeepSeek v4 in gray-box — delivered a conclusion with declared confidence above 95% built on a factually false and verifiable premise, specifically asserting that one of the experiment's pairs matched the standard DES vector when it does not.

### 10.2 What This Work Does Not Demonstrate

With the same discipline, it is necessary to delimit what these results do not allow supporting:

- They do not demonstrate that DES-M is difficult to break for a human cryptanalyst with enough time. With more pairs and standard differential analysis, the modification is identifiable.
- They do not demonstrate that the evaluated language models are incapable of executing DES variants in general. They only demonstrate that, under the specific conditions of this experiment, four of five models did not do so, and that the axis that separated the one that did from those that did not was functional access to code execution.
- They do not demonstrate a statistically quantifiable security gap in any type of organization.
- They do not demonstrate that Opus 4.8 is representative of all code-executing models; a single model with that capability was evaluated, and comparison with other executor models remains pending.

### 10.3 Practical Interpretation: Execution as the Discriminating Axis

With the above limitations clearly stated, the practical interpretation that the empirical evidence of this work supports is the following, explicitly presented as the author's observation on the environment and not as statistical conclusion.

The cybersecurity culture gap in Peru is real and widely documented. In the national business fabric, particularly among micro and small enterprises, awareness of cybersecurity is low; awareness of cryptography is practically nonexistent. In many state universities the systems engineering curriculum does not even include a mandatory cryptography course. Even in medium and large companies, a dedicated cybersecurity area with specialized technical staff is more the exception than the rule — although this situation is evolving, it remains an uneven landscape.

In this context, the practical relevance of the results of this work is not that "language models fail at cryptography", but something more specific and more operationally useful: **language models without functional access to code execution within the turn do not solve this kind of problem, and that is the majority configuration in which organizations consume these assistants**. An incident response team relying on general-purpose assistants accessed via their standard web interfaces without execution tooling enabled will face the pattern observed in four of the five models of this study: rejection, blocking, confident error, or confabulation. None of those outcomes is useful under deadline pressure in a real incident.

A team with access to an executor model of the Opus 4.8 category, with operational code execution, solves the cryptographic problem *when it has the algorithm's tables*. That is a nontrivial precondition. In a real ransomware scenario, the modified S-boxes are inside the attacker's binary, not listed in a prompt. To reach them, prior reverse engineering is needed — extracting the tables from the compiled binary, identifying them as S-boxes, and only then feeding them to the cryptographic analysis. If the binary is unobfuscated, a competent reverser extracts the tables in reasonable time and from there an executor LLM can complete the analysis. If the binary is obfuscated, the reversing phase becomes the real bottleneck and cryptographic analysis is subordinated to first resolving it.

Under a hypothetical ransomware scenario with a short payment deadline, this translates into a concrete operational gradation:

- **Without reverser and without executor LLM**: the organization resolves nothing. It neither identifies that the algorithm is not standard DES, nor bounds the type of modification, nor executes the variant even when documented. This is the scenario empirically documented in four of the five models of this work.
- **Without reverser, with executor LLM**: the organization identifies that there is a modification (black-box solved), bounds the space of modifications compatible with the observed pairs (gray-box solved), but cannot extract the tables from the binary. The analysis stalls at the step prior to decryption.
- **With competent reverser and no binary obfuscation, with executor LLM**: reversing extracts the modified tables, executor LLM completes the cryptographic analysis. Scenario resolvable within deadline.
- **With competent reverser and binary obfuscation, with executor LLM**: reversing becomes the real bottleneck; aggregate time depends on obfuscation sophistication. This is where the effective barrier re-establishes, as detailed in Section 10.4.

It is not that DES-M is cryptographically dangerous — it is that, in scenarios where the organization lacks at least one of the two capacities (competent reversing and executor model), the cognitive and temporal friction it introduces is in practice indistinguishable from a real cryptographic barrier. This work does not statistically demonstrate the incidence of those scenarios; it makes them concrete with empirical evidence of what happens in each case.

### 10.4 VM Obfuscation and Modified DES: Barrier Restoration

A natural extension of the previous scenario, not empirically explored in this work but consistent with what has been observed, is the combination of structural binary obfuscation with modification of the encryption algorithm. Code protection tools such as VMProtect or Themida are widely known to implement custom virtual machines: instead of emitting readable x86 machine code, the protected binary contains an interpreter of a bytecode invented by the author, and all sensitive logic is expressed in that bytecode.

A ransomware combining both techniques — a custom VM with a bespoke instruction language, plus an internal cipher based on modified DES — would compose exactly the scenario this work makes plausible, extended by one layer. Before even being able to ask "what encryption algorithm is this?", the defensive analyst would have to reverse-engineer the virtual machine: understand its instruction set, its interpreter, its execution model. That work alone already consumes hours or days of an experienced analyst, even with the best available reversing tools and even with an executor LLM at hand. Only after solving that would they reach the starting point of the actual cryptographic analysis, where they would find — and only then could they begin to identify — the structural modification of the S-boxes.

The key observation is that binary obfuscation moves the bottleneck. Without obfuscation, an executor LLM closes the analysis fast once the tables are in hand. With obfuscation, the executor LLM cannot begin until a human reverser — or an equivalent agentic reversing capacity, which this work did not evaluate — has first reconstructed the binary's execution model. In practical terms, binary obfuscation restores against a team with executor LLM the very barrier that DES-M by itself introduces against a team without one: it is not a cryptographic barrier in any strict mathematical sense, it is a barrier of reversing, of specialized knowledge, and above all, of time.

For an organization without a dedicated reversing team, the combination translates into a devastating time multiplier under deadline pressure. The victim can come to intuit that they are facing "something similar to DES", try to apply standard tools, see them fail, have to reframe the problem from scratch, and then start a reverse-engineering task whose estimated time exceeds several times the typical payment deadline of a ransomware operation. In the victim's own terms: they know what they need to do, they see the problem, but they cannot get to it in time. The barrier scales with each layer of obfuscation added without the underlying cipher needing to be strong at all. Empirical testing of this compound hypothesis — obfuscated code plus modified DES, evaluated under the same three conditions against the same five models extended with Claude Fable 5 — is part of the planned future work.

---

## 11. Limitations

- DES-M measurably reduces the differential resistance of the modified component and should in no case be interpreted as a proposal for a more secure cipher than standard DES.
- Mathematical analysis was limited to DDT on the modified S-box and ANF of the original S-boxes. Complementary metrics such as LAT (Linear Approximation Table), non-linearity computed via Walsh-Hadamard transform, SAC (Strict Avalanche Criterion), and BIC (Bit Independence Criterion) are missing, both for the original and modified S-boxes.
- ANF is presented as characterization of algebraic complexity, not as quantitative demonstration of cryptographic non-linearity.
- The evaluation with language models was carried out on a small sample (five models), with a single execution per condition and without control of generation temperature or variability between retries.
- Functional access to code execution, which a posteriori turns out to be the discriminating axis among models, was not a control variable designed into the experiment; a single model with that capability (Opus 4.8) was evaluated, which prevents generalization to other executor models.
- The white-box condition included the expected values within the prompt, which allowed two of the five models to confabulate verifications they did not perform. Detection of the confabulation was possible only through access to the model's filtered internal reasoning (Luna, DeepSeek) or through comparison with the verifiable trace of intermediate states (Opus). Results must be read in light of this design limitation.
- DES itself is cryptographically obsolete due to its key size (56 effective bits), independently of any modification to its S-boxes; this work does not reintroduce cryptographic viability to the algorithm.

---

## 12. Future Work

This work opens three concrete research lines, to be addressed in successive publications of this same series.

### 12.1 Methodological Redesign of Model Evaluation

- Redesign the white-box condition by removing expected values from the prompt and verifying computed ciphertexts externally to the model.
- Expand the sample to at least ten models, explicitly crossing two dimensions: functional access to code execution (yes / no) and model family (provider and generation), with multiple runs per condition to characterize variability and epistemic calibration.
- Incorporate the evaluation of Claude Fable 5 under the three conditions, pending in the current sample and necessary to complete the intra-family comparison between successive generations.
- Cross-experiment code execution access with generation temperature to determine whether the observed confabulation cases are sensitive to hyperparameters or are a stable failure mode.

### 12.2 Real Cryptographic Attack on DES-M

In parallel to the model evaluation, the DES-M variant itself must be subjected to the set of cryptographic techniques that a specialized human analyst would employ to characterize it, precisely to establish with rigor the real cost of that attack and compare it against the cost observed against language models. The relevant techniques are:

- **Differential cryptanalysis (Biham and Shamir, 1990)**, the canonical tool against DES and its variants. Its logic is exactly the one DES-M makes more effective: plaintext pairs with known XOR difference Δx are generated, the resulting XOR difference Δy in the ciphertexts is observed, and the real cipher's DDT is statistically reconstructed. Since the original DES S-boxes have DDT maximum 16 and those of DES-M have 18 with three cells above the standard threshold, that difference constitutes precisely the signature the attack detects. Attacking full 16-round DES requires on the order of 2⁴⁷ pairs; structurally identifying *that* something changed and *where*, requires orders of magnitude less.
- **Linear cryptanalysis (Matsui, 1993)**, complementary technique based on linear approximations between input bits, subkey, and output whose probability deviates significantly from 1/2. For full DES it requires ~2⁴³ known pairs. Against DES-M it is useful as a second statistical axis: the LAT of the modified S-boxes is also altered, and that alteration is detectable.
- **Structural extraction of S-boxes from binary and direct comparison against FIPS 46-3**. In a real operational scenario where the attacker's binary is available, this is the most practical flow and the first one a cryptographer would apply: reverse-engineer the binary to locate the tables as they are implemented, compute their full DDT and LAT, and compare directly against those published in FIPS 46-3. Any cell that does not match the known pattern reveals the exact modification. It is the cryptographic analog of comparing file hashes, and it is exactly the procedure against which DES-M has no defense once the binary is available.
- **Reduced-round differential cryptanalysis** (3, 6, 8 rounds), a methodological version of the differential attack that isolates the behavior of an individual S-box without the full avalanche mixing its effects with those of the rest of the algorithm.
- **Algebraic attacks** based on SAT solvers or Gröbner bases over the polynomial equation system generated by the S-boxes' ANF (the same one documented in Appendix A of this work). For full DES they are impractical, but for reduced-round versions or for identifying which specific S-box changed, they are applicable.

Reproducible application of these techniques over DES-M, with real cost metrics (compute time, number of pairs required, structural identification precision), constitutes the object of the next investigation in this series.

### 12.3 Evaluation of the Compound Threat with Obfuscated Binaries

Prototype a DES-M implementation inside a simple custom virtual machine — VMProtect / Themida style, with an invented instruction set — and evaluate under the same three experimental conditions against the five models extended with Fable 5. The hypothesis to test is the one formulated in Section 10.4: binary obfuscation restores against a team with executor LLM the same barrier that DES-M by itself introduces against a team without one. This line completes the argument's cycle and moves the evaluation from isolated algorithms toward binary artifacts that resemble what actually circulates in the wild.

---

## 13. Conclusions

This work documents the ground-up reference implementation of DES, the construction of DES-M as a variant obfuscated through S-box modification, and an empirical evaluation of its behavior against five state-of-the-art language models under three different conditions of information availability.

The main conclusions, strictly adjusted to what has been demonstrated, are the following:

1. It is possible to build a structural variant of DES that is perfectly reversible, superficially indistinguishable from the standard algorithm, and that breaks any attempt at decryption with standard implementations under the correct key.
2. That reversibility does not imply security: the proposed variant is measurably weaker than DES in the modified component.
3. The difficulty that the variant presents to an outside observer does not come from cryptographic strength but from breaking a standardization assumption, which we have called structural obfuscation.
4. In the evaluated sample, the capacity to resolve DES-M separates by functional access to code execution, not by reasoning quality. A single model out of five — the only one with operational code execution within the turn — solved all three conditions with rigor. The other four failed each via distinct modes, including two documented confabulation cases in white-box and one factual error case with declared confidence above 95% in gray-box.
5. Confabulation in verification tasks with expected values inside the prompt is a real mechanism, detectable through analysis of the model's filtered internal reasoning, and constitutes a design flaw that any future evaluation of cryptographic capability of these systems must avoid.

In the practical scenario of an organization that simultaneously lacks in-house reversing capacity and access to an executor model — a frequent reality in the Peruvian business fabric, particularly among small and medium enterprises — this type of variant composes an effective barrier under deadline pressure. For an organization with access to an executor model but without reversing, the analysis stalls at the step prior to extracting the tables from the binary. For an organization with both reversing and an executor model, DES-M in isolation is resolvable; the barrier re-establishes when the algorithm modification is combined with structural obfuscation of the binary hosting it. In all scenarios, the fundamental barrier is not mathematical but temporal and cognitive. That is the finding this work makes visible, not as statistical demonstration but as concrete illustration from reproducible empirical evidence.

---

## References

- National Institute of Standards and Technology. *FIPS PUB 46-3: Data Encryption Standard (DES)*. 1999. Withdrawn on May 19, 2005. https://csrc.nist.gov/files/pubs/fips/46-3/final/docs/fips46-3.pdf
- National Institute of Standards and Technology. *FIPS PUB 197: Advanced Encryption Standard (AES)*. 2001.
- Coppersmith, D. (1994). *The Data Encryption Standard (DES) and its strength against attacks*. IBM Journal of Research and Development, 38(3), 243–250.
- Biham, E., & Shamir, A. (1990). *Differential Cryptanalysis of DES-like Cryptosystems*. Advances in Cryptology — CRYPTO '90.
- Schneier, B. (1993). *Description of a New Variable-Length Key, 64-Bit Block Cipher (Blowfish)*. Fast Software Encryption, Cambridge Security Workshop.
- NIST Special Publication 800-131A Rev. 2. *Transitioning the Use of Cryptographic Algorithms and Key Lengths*.

---

## Appendix A: Algebraic Normal Form of the Eight Original S-boxes

```
--- S1 ---
y1 = 1 + x6 + x5 + x4x5x6 + x3 + x3x4 + x3x4x6 + x3x4x5 + x2 + x2x3 + x2x3x4 + x1 + x1x5 + x1x4 + x1x4x6 + x1x3x5 + x1x3x4 + x1x3x4x6 + x1x3x4x5 + x1x2x5x6 + x1x2x4 + x1x2x4x6 + x1x2x4x5 + x1x2x3 + x1x2x3x5x6 + x1x2x3x4 + x1x2x3x4x6
y2 = 1 + x6 + x5x6 + x4x6 + x4x5 + x3 + x3x5 + x3x5x6 + x3x4x6 + x3x4x5x6 + x2 + x2x6 + x2x4 + x2x4x6 + x2x4x5 + x2x3x6 + x1x6 + x1x5 + x1x4x5 + x1x3 + x1x3x5x6 + x1x3x4 + x1x3x4x5x6 + x1x2 + x1x2x6 + x1x2x5 + x1x2x4x5x6 + x1x2x3 + x1x2x3x6 + x1x2x3x5 + x1x2x3x5x6 + x1x2x3x4 + x1x2x3x4x6
y3 = 1 + x6 + x5 + x4 + x4x5 + x4x5x6 + x3x6 + x3x5 + x3x4 + x3x4x6 + x2x6 + x2x5 + x2x4 + x2x4x6 + x2x4x5x6 + x2x3 + x2x3x6 + x2x3x5 + x2x3x4 + x2x3x4x6 + x1 + x1x5 + x1x5x6 + x1x3x4 + x1x3x4x5x6 + x1x2 + x1x2x6 + x1x2x5x6 + x1x2x4 + x1x2x4x6 + x1x2x4x5 + x1x2x4x5x6 + x1x2x3 + x1x2x3x6 + x1x2x3x5 + x1x2x3x5x6 + x1x2x3x4 + x1x2x3x4x6
y4 = x5x6 + x4 + x3x5 + x2 + x2x6 + x2x5 + x2x4x6 + x2x4x5 + x2x3x6 + x2x3x5x6 + x1x6 + x1x5 + x1x5x6 + x1x4 + x1x4x6 + x1x4x5 + x1x3 + x1x3x5 + x1x3x4 + x1x3x4x6 + x1x3x4x5 + x1x3x4x5x6 + x1x2x5 + x1x2x5x6 + x1x2x4x5 + x1x2x3 + x1x2x3x5x6 + x1x2x3x4 + x1x2x3x4x6

--- S2 ---
y1 = 1 + x6 + x5 + x4x5 + x3 + x2x6 + x2x4 + x2x4x5 + x2x3 + x2x3x6 + x1 + x1x5x6 + x1x4x5 + x1x4x5x6 + x1x3x5x6 + x1x2x6 + x1x2x5x6 + x1x2x4x5 + x1x2x4x5x6 + x1x2x3 + x1x2x3x6
y2 = 1 + x6 + x5 + x4 + x4x5x6 + x3x6 + x3x4x5x6 + x2 + x2x4 + x2x4x6 + x2x3 + x1 + x1x2x4x5 + x1x2x4x5x6 + x1x2x3x5 + x1x2x3x5x6
y3 = 1 + x5 + x4 + x3x5 + x3x4 + x3x4x6 + x3x4x5 + x2 + x2x5x6 + x2x4x6 + x2x4x5x6 + x2x3x6 + x1 + x1x5x6 + x1x4x5 + x1x3 + x1x3x5 + x1x3x4 + x1x3x4x6 + x1x3x4x5 + x1x2 + x1x2x6 + x1x2x5 + x1x2x4 + x1x2x4x6 + x1x2x4x5x6 + x1x2x3 + x1x2x3x5 + x1x2x3x5x6 + x1x2x3x4
y4 = 1 + x4 + x4x5x6 + x3 + x3x6 + x3x5 + x2x6 + x2x4x5 + x2x4x5x6 + x2x3x5 + x2x3x5x6 + x1 + x1x6 + x1x5x6 + x1x4x5x6 + x1x3 + x1x3x6 + x1x3x5 + x1x3x5x6 + x1x2 + x1x2x5 + x1x2x5x6 + x1x2x4x6 + x1x2x3x6 + x1x2x3x5x6

--- S3 ---
y1 = 1 + x5 + x4x6 + x4x5 + x4x5x6 + x3 + x3x5 + x3x4 + x3x4x5x6 + x2 + x2x4 + x2x4x5 + x2x4x5x6 + x2x3x5 + x2x3x5x6 + x2x3x4 + x1x6 + x1x4 + x1x4x6 + x1x4x5 + x1x4x5x6 + x1x3 + x1x3x5x6 + x1x3x4 + x1x3x4x5x6 + x1x2 + x1x2x4 + x1x2x4x5 + x1x2x4x5x6 + x1x2x3 + x1x2x3x4
y2 = x6 + x4x6 + x4x5 + x4x5x6 + x3 + x3x5 + x2x6 + x2x5 + x2x5x6 + x2x4 + x2x4x6 + x2x3 + x2x3x6 + x2x3x5 + x2x3x5x6 + x2x3x4 + x1 + x1x4x5x6 + x1x3x4x5x6 + x1x2 + x1x2x6 + x1x2x5 + x1x2x5x6 + x1x2x4 + x1x2x3 + x1x2x3x6 + x1x2x3x5 + x1x2x3x5x6 + x1x2x3x4
y3 = 1 + x6 + x5 + x4 + x4x6 + x4x5x6 + x3x6 + x3x5 + x3x5x6 + x3x4 + x3x4x6 + x3x4x5 + x3x4x5x6 + x2 + x2x5 + x2x5x6 + x2x4 + x2x4x5 + x2x3 + x2x3x6 + x2x3x4 + x2x3x4x6 + x1 + x1x6 + x1x4 + x1x4x6 + x1x4x5 + x1x4x5x6 + x1x3x5 + x1x3x5x6 + x1x3x4x6 + x1x3x4x5x6 + x1x2x6 + x1x2x5 + x1x2x5x6 + x1x2x4 + x1x2x4x6 + x1x2x4x5x6 + x1x2x3x4 + x1x2x3x4x6
y4 = x6 + x4 + x4x5 + x3x5 + x2 + x1 + x1x6 + x1x5 + x1x4x6 + x1x4x5 + x1x3 + x1x3x5 + x1x2 + x1x2x6 + x1x2x5 + x1x2x5x6 + x1x2x3 + x1x2x3x6 + x1x2x3x5 + x1x2x3x4x6

--- S4 ---
y1 = x6 + x5 + x5x6 + x4 + x4x6 + x4x5x6 + x3x6 + x3x5 + x2x6 + x2x5 + x2x5x6 + x2x4x5 + x2x4x5x6 + x2x3 + x2x3x5 + x2x3x5x6 + x2x3x4x6 + x1 + x1x5x6 + x1x4 + x1x4x6 + x1x3x5x6 + x1x3x4 + x1x3x4x6 + x1x3x4x5 + x1x3x4x5x6 + x1x2x5 + x1x2x5x6 + x1x2x4 + x1x2x4x5 + x1x2x3x5 + x1x2x3x5x6 + x1x2x3x4
y2 = 1 + x5x6 + x4x6 + x4x5 + x4x5x6 + x3 + x3x6 + x3x5 + x2 + x2x6 + x2x5x6 + x2x4x5x6 + x2x3 + x2x3x5x6 + x2x3x4 + x2x3x4x6 + x1 + x1x5 + x1x5x6 + x1x4x6 + x1x3x5 + x1x3x5x6 + x1x3x4x6 + x1x3x4x5x6 + x1x2x5x6 + x1x2x4 + x1x2x4x5 + x1x2x3x5x6 + x1x2x3x4
y3 = 1 + x6 + x5 + x5x6 + x4x6 + x4x5 + x3 + x3x4x5 + x3x4x5x6 + x2 + x2x6 + x2x5x6 + x2x4x5x6 + x2x3x6 + x2x3x4 + x2x3x4x6 + x1x6 + x1x5 + x1x5x6 + x1x4 + x1x4x6 + x1x4x5 + x1x4x5x6 + x1x3x6 + x1x3x5 + x1x3x4x5 + x1x3x4x5x6 + x1x2 + x1x2x5 + x1x2x4 + x1x2x4x5 + x1x2x3x6 + x1x2x3x5 + x1x2x3x5x6 + x1x2x3x4
y4 = 1 + x5x6 + x4 + x4x6 + x4x5 + x3 + x3x4x5x6 + x2x6 + x2x5 + x2x5x6 + x2x4x5 + x2x4x5x6 + x2x3 + x2x3x6 + x2x3x4x6 + x1 + x1x6 + x1x5x6 + x1x4x6 + x1x4x5x6 + x1x3 + x1x3x6 + x1x3x5 + x1x3x4x5x6 + x1x2 + x1x2x5 + x1x2x4 + x1x2x4x5 + x1x2x3 + x1x2x3x6 + x1x2x3x5x6 + x1x2x3x4

--- S5 ---
y1 = x6 + x5 + x5x6 + x4x6 + x4x5 + x3x6 + x3x4 + x3x4x6 + x3x4x5 + x3x4x5x6 + x2 + x2x4 + x2x4x6 + x2x4x5 + x2x3x6 + x2x3x5x6 + x1x5 + x1x5x6 + x1x4x6 + x1x3 + x1x3x6 + x1x3x5x6 + x1x3x4x5 + x1x2x5x6 + x1x2x4 + x1x2x4x6 + x1x2x4x5 + x1x2x4x5x6 + x1x2x3x6 + x1x2x3x4
y2 = x6 + x5 + x4 + x3 + x3x6 + x3x5x6 + x3x4x6 + x3x4x5x6 + x2x4 + x2x3x6 + x2x3x4x6 + x1 + x1x5x6 + x1x4x5 + x1x4x5x6 + x1x3x4x5 + x1x2x6 + x1x2x4x6 + x1x2x3 + x1x2x3x6 + x1x2x3x4 + x1x2x3x4x6
y3 = 1 + x5 + x5x6 + x4 + x4x6 + x4x5 + x3x6 + x3x5 + x3x4 + x3x4x6 + x3x4x5 + x3x4x5x6 + x2 + x2x5 + x2x5x6 + x2x4x6 + x2x4x5 + x2x3x5 + x2x3x5x6 + x2x3x4 + x2x3x4x6 + x1 + x1x6 + x1x5x6 + x1x4 + x1x4x5 + x1x3 + x1x3x6 + x1x3x5 + x1x3x4 + x1x3x4x6 + x1x3x4x5 + x1x3x4x5x6 + x1x2x6 + x1x2x5 + x1x2x4 + x1x2x4x5x6 + x1x2x3 + x1x2x3x5x6 + x1x2x3x4 + x1x2x3x4x6
y4 = x5x6 + x4x5 + x3 + x3x6 + x3x5 + x3x5x6 + x3x4x6 + x3x4x5 + x3x4x5x6 + x2x6 + x2x5 + x2x5x6 + x2x4 + x2x4x6 + x2x4x5x6 + x2x3x5 + x1x6 + x1x4 + x1x4x5 + x1x3 + x1x3x6 + x1x3x4x6 + x1x3x4x5 + x1x3x4x5x6 + x1x2 + x1x2x6 + x1x2x5 + x1x2x5x6 + x1x2x4 + x1x2x4x5 + x1x2x3 + x1x2x3x6 + x1x2x3x5 + x1x2x3x5x6 + x1x2x3x4

--- S6 ---
y1 = 1 + x5 + x5x6 + x4x6 + x4x5 + x4x5x6 + x3x6 + x3x5x6 + x3x4 + x3x4x6 + x3x4x5 + x3x4x5x6 + x2 + x2x3 + x2x3x4x6 + x1x6 + x1x5 + x1x5x6 + x1x4x6 + x1x4x5x6 + x1x3 + x1x3x6 + x1x3x5 + x1x3x5x6 + x1x2x4x6 + x1x2x4x5x6 + x1x2x3x6 + x1x2x3x5x6 + x1x2x3x4x6
y2 = 1 + x6 + x5 + x4 + x3 + x3x5 + x3x4x5 + x2 + x2x4 + x2x4x5x6 + x1 + x1x4x5 + x1x4x5x6 + x1x3 + x1x3x6 + x1x3x5x6 + x1x3x4x5 + x1x2x4x5 + x1x2x3 + x1x2x3x6 + x1x2x3x5 + x1x2x3x5x6 + x1x2x3x4x6
y3 = x6 + x4 + x4x5x6 + x3x5 + x2x5x6 + x2x4x5 + x2x3 + x2x3x5 + x1x6 + x1x5 + x1x4x5x6 + x1x3 + x1x3x6 + x1x3x5 + x1x3x5x6 + x1x2 + x1x2x4x5 + x1x2x4x5x6 + x1x2x3 + x1x2x3x5x6
y4 = x5 + x4x5x6 + x3 + x3x4 + x3x4x6 + x3x4x5 + x3x4x5x6 + x2x4 + x2x4x5x6 + x2x3 + x2x3x4 + x2x3x4x6 + x1 + x1x6 + x1x4x5 + x1x4x5x6 + x1x3x5 + x1x3x4 + x1x3x4x6 + x1x3x4x5 + x1x3x4x5x6 + x1x2x6 + x1x2x4x6 + x1x2x4x5x6 + x1x2x3x6

--- S7 ---
y1 = x6 + x5 + x3 + x3x4x5 + x3x4x5x6 + x2x4 + x2x3 + x2x3x6 + x2x3x4 + x2x3x4x6 + x1x6 + x1x5 + x1x5x6 + x1x4 + x1x4x5x6 + x1x3x6 + x1x3x5 + x1x3x4x5 + x1x3x4x5x6 + x1x2 + x1x2x4 + x1x2x4x5 + x1x2x3 + x1x2x3x6 + x1x2x3x5 + x1x2x3x4 + x1x2x3x4x6
y2 = 1 + x5 + x4 + x3x4x5x6 + x2 + x2x6 + x2x4 + x2x4x5x6 + x2x3 + x1 + x1x6 + x1x4 + x1x3 + x1x3x4x5 + x1x2 + x1x2x4x6 + x1x2x4x5x6 + x1x2x3x6 + x1x2x3x4
y3 = x5 + x5x6 + x4 + x4x5 + x4x5x6 + x3 + x3x6 + x3x4x6 + x3x4x5x6 + x2 + x2x4x5 + x2x4x5x6 + x2x3x4x6 + x1x6 + x1x5 + x1x5x6 + x1x3 + x1x3x5 + x1x3x5x6 + x1x3x4x6 + x1x3x4x5x6 + x1x2x4 + x1x2x4x5 + x1x2x3 + x1x2x3x6 + x1x2x3x5 + x1x2x3x5x6 + x1x2x3x4x6
y4 = x6 + x5 + x4x5 + x3 + x3x4 + x3x4x5 + x2 + x2x4x6 + x2x4x5x6 + x2x3 + x1 + x1x4x6 + x1x4x5x6 + x1x3x4x6 + x1x3x4x5x6 + x1x2x5x6 + x1x2x4x6 + x1x2x3x6

--- S8 ---
y1 = 1 + x6 + x5 + x4x6 + x4x5x6 + x3 + x3x4 + x3x4x6 + x2x6 + x2x5 + x2x5x6 + x2x4 + x2x4x6 + x2x4x5 + x2x3x4 + x2x3x4x6 + x1 + x1x6 + x1x5x6 + x1x4x5 + x1x4x5x6 + x1x3x6 + x1x3x5 + x1x3x4 + x1x3x4x6 + x1x2x4x6 + x1x2x4x5x6 + x1x2x3x6 + x1x2x3x5x6 + x1x2x3x4 + x1x2x3x4x6
y2 = 1 + x6 + x5 + x4 + x3x5 + x2 + x2x5 + x2x4 + x2x4x5 + x2x3 + x1x5x6 + x1x4 + x1x4x6 + x1x3 + x1x3x5 + x1x3x5x6 + x1x3x4 + x1x3x4x6 + x1x2x5 + x1x2x4 + x1x2x4x5 + x1x2x3 + x1x2x3x4 + x1x2x3x4x6
y3 = x5 + x4x5 + x3 + x3x5 + x2 + x2x6 + x2x5x6 + x2x4x6 + x2x4x5x6 + x2x3x6 + x2x3x4x6 + x1 + x1x5 + x1x5x6 + x1x4 + x1x4x6 + x1x4x5 + x1x4x5x6 + x1x3x5 + x1x2x5 + x1x2x4x5x6 + x1x2x3x5 + x1x2x3x5x6
y4 = 1 + x5 + x5x6 + x4 + x4x6 + x4x5 + x3 + x3x5x6 + x3x4x6 + x3x4x5x6 + x2 + x2x5x6 + x2x4x5 + x2x3x6 + x1x6 + x1x5 + x1x4x5x6 + x1x3 + x1x3x5 + x1x3x5x6 + x1x3x4x6 + x1x2x5x6 + x1x2x4 + x1x2x4x6 + x1x2x4x5 + x1x2x3 + x1x2x3x5 + x1x2x3x5x6 + x1x2x3x4x6
```

---

© 2026 Aldair Maihuiri. All rights reserved.
Sharing with attribution is welcome. Unauthorized reproduction is prohibited.

*Published at [ginomaihuiri.github.io](https://ginomaihuiri.github.io) — /DES MOD/*
