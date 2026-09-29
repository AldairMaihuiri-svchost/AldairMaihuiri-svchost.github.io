---
title: "Ransomware Red Teaming — Module 3: Key Generation"
description: "Key hierarchies, CSPRNGs, ECDH, HKDF, domain separation, public-key formats, and the life cycle of cryptographic material."
author: Aldair Maihuiri
---

# Module 03 — Key Generation Algorithms

In [Module 02](Ransomware-Modulo2-en), we examined encryption and key agreement algorithms. Here we follow cryptographic material through its life cycle: where it comes from, what each value does, how it is derived, and what information must be retained to make an experiment reproducible. The next module covers file enumeration; for now, we use only laboratory inputs selected in advance.

An architecture can use sound algorithms and still fail because it generates predictable secrets, confuses a public key with a private key, reuses a nonce, or loses a derivation parameter. Key generation is therefore best studied as a complete protocol rather than an isolated call to a random number generator.

## 3.1 Vocabulary and scope

| Term | Meaning | Secret? | Relevant property |
| --- | --- | --- | --- |
| Entropy | Uncertainty in the source feeding a generator | Depends on the source | Cannot be inferred from the number of output bytes |
| CSPRNG | Generator suitable for cryptographic purposes | Its internal state is secret | Unpredictable output and correct state management |
| ECDH private key | Scalar used in a key agreement | Yes | Protection and limited lifetime |
| ECDH public key | Point associated with the private key | No | Correct format and validation on import |
| Shared secret | Result of the ECDH agreement | Yes | Input to a KDF, not automatically a key for every purpose |
| PRK / OKM | Intermediate material / HKDF output | Yes | Length, context, and separation of uses |
| Working key | Key intended for a specific operation | Yes | Must not be reused for another purpose |
| Salt | KDF input | Usually no | Must be reproduced if it was used in derivation |
| Nonce | Number used once within a particular scheme | Usually no | Must satisfy the uniqueness rule for the scheme and key |
| IV | Initialization value for a mode | Usually no | Requirements depend on the mode |
| Session or file ID | Label distinguishing instances | No | Stable identity and unambiguous encoding |

The nominal length of a key does not measure the entropy of its source. Thirty-two bytes obtained from a predictable timestamp are not equivalent to a 256-bit key produced by a CSPRNG. A key, salt, and nonce are not interchangeable merely because all three are represented as bytes.

In the sections below, **master key pair** means the persistent pair in the model, **ephemeral pair** means a pair created for a particular agreement, and **working key** means output assigned to an operation on data. These are roles, not mandatory variable names or a single implementation recipe.

## 3.2 From entropy to keying material

`rand()`, `srand(time(NULL))`, a PID, the system time, and timing counters are not adequate sources of keys on their own. A system CSPRNG is intended to produce bytes that cannot practically be predicted from observed output. On Windows, the relevant interface is `BCryptGenRandom` with `BCRYPT_USE_SYSTEM_PREFERRED_RNG`; elsewhere, a maintained library typically exposes the operating system's cryptographic generator. [1]

Four separate questions help review a generation step:

1. Who supplies the randomness, and what happens if the call fails?
2. How many bytes does the object require: a scalar, salt, nonce, or identifier?
3. Does the object have additional requirements, such as belonging to a curve's scalar range or being unique for a given key?
4. Will the value be stored, published, or reconstructed later?

A curve library should generate scalars through its own API or accept a compatible cryptographic source. Taking 32 arbitrary bytes and treating them as a P-256 private key overlooks the scalar-range requirement. CSPRNG output addresses unpredictability; it does not automatically settle format, identity, or lifetime.

**Random and unique are different requirements.** An identifier can be unique without being secret. A randomly generated nonce can collide even when each individual output appears unpredictable. A nonce policy depends on the algorithm, the number of operations, and the key under which it is used. Under RFC 8439, a 96-bit ChaCha20-Poly1305 nonce must not repeat with the same key. [2]

## 3.3 Dependency map

The design studied here starts with a master pair and compares two ways to obtain working keys. The master public key is available to the side initiating the agreement; the master private key remains under the control of the side that must reconstruct it later. Both sides need exactly the same public derivation parameters.

```text
master pair: private M / public M
                         │
                         ├── A: new ephemeral pair for each input
                         │       └── ECDH → HKDF → working key A_i
                         │
                         └── B: one ephemeral pair per session
                                 └── ECDH → session material
                                            └── HKDF with stable ID → key B_i
```

| Material | Model A: per input | Model B: per session | Kept publicly? |
| --- | --- | --- | --- |
| Master private key | One for the set of exercises | Same | No |
| Master public key | Same | Same | Yes |
| Ephemeral private key | A new one per input | A new one per session | No |
| Ephemeral public key | Different for each input | Shared within that session | Yes, with its scope identified |
| ECDH secret | Different for each input | Shared within the session | No |
| Working key | Different for each input | Different according to input context | No |
| Input ID | Useful as context | Required to distinguish derivations | Yes, if reconstruction is needed |

An ephemeral public key cannot stand in for a private key in ECDH. Nor can we say that the session private key is “encrypted with the master public key” when the described flow is an ECDH agreement. One side combines *its own private key* with *the other side's public key*. The other side does the converse, and the results match. Key transport or wrapping would be a different protocol.

## 3.4 What ECDH does

Let `G` be the curve's base point. If one side holds private key `a` and publishes `A = a·G`, while the other holds `b` and publishes `B = b·G`, both can calculate the same point:

```text
side A:  a·B = a·(b·G) = (a·b)·G
side B:  b·A = b·(a·G) = (a·b)·G
```

The equality explains the agreement, not the encoding of a final key. Libraries define how the ECDH result is represented and how points are validated; the protocol must also specify the KDF and its parameters. Knowing `A` and `B` is not equivalent to knowing `a` or `b`. ECDH does not encrypt a message by itself. NIST SP 800-56A Rev. 3 documents key-establishment schemes based on elliptic curves and Diffie–Hellman. [3]

In both models, the master pair represents one side and an ephemeral pair represents the other. A basic test confirms that both sides obtain the same agreement material **before** deriving keys. If they do not, check the curve, public-key format, validation, and implementation first; a KDF cannot fix an incorrectly specified agreement.

## 3.5 Architecture A: one ephemeral agreement per input

Module 02 introduces this model through a per-file ephemeral pair. Here we examine its key generation. For every input `i`, an independent ephemeral pair is created; its private key and the master public key produce `Z_i`. The corresponding ephemeral public key allows the holder of the master private key to reproduce that agreement.

```text
Input 01: (e_priv_01, e_pub_01) → Z_01 → HKDF → K_01
Input 02: (e_priv_02, e_pub_02) → Z_02 → HKDF → K_02
Input 03: (e_priv_03, e_pub_03) → Z_03 → HKDF → K_03
```

For N inputs, this means **N ephemeral pairs and N ECDH agreements**, as well as N derivations. A public key for each input identifies its corresponding agreement. Failure to preserve one input's public information affects the reconstruction of that input, even if the others retain their parameters.

Independence does not justify saying that exposure of any working key can never affect other data: the *material exposed* must be specified. Exposing `K_01` has a different scope from exposing the master private key. Exposing a session secret in model B has a different scope from exposing a single working key. The outcome also depends on whether keys or contexts were reused.

> **Question:** How many “keys per input” are involved? At least an ephemeral pair and a derived working key. They serve different purposes. The public key is not secret, and the ECDH secret should not be confused with the working key.

## 3.6 Architecture B: one agreement per session, separate derivations

Here a single ephemeral pair is generated for a session. Agreement with the master public key produces `Z_s`. Session material is established from `Z_s`, and a different, stable context for each input yields `K_01`, `K_02`, and so on.

```text
session ephemeral pair + master public key → Z_s
Z_s + session salt → HKDF-Extract → PRK_s
PRK_s + context(input 01) → HKDF-Expand → K_01
PRK_s + context(input 02) → HKDF-Expand → K_02
PRK_s + context(input 03) → HKDF-Expand → K_03
```

**One ECDH operation per session does not imply an identical key for every file.** Different `info` values distinguish the derivations. Conversely, the same `PRK`, `info`, and output length produce the same result: HKDF is deterministic. The salt need not be secret, but its exact value must be available for reconstruction.

| Aspect | A: ECDH per input | B: ECDH per session |
| --- | --- | --- |
| Ephemeral pairs for N inputs | N | 1 |
| ECDH agreements | N | 1 |
| Working-key derivations | N | N |
| Ephemeral public key | Changes for each input | Shared within the session |
| Context distinguishing inputs | Recommended and explicit | Essential |
| Scope of a compromised intermediate secret | Corresponding input | Corresponding session |
| Public parameters to preserve | Parameters for each input | Session and per-input parameters |

This table describes an architecture, not a performance measurement. Actual costs depend on the platform, cryptographic provider, storage, and number of inputs. A hybrid RSA scheme can reuse an existing public key: it need not generate a new RSA pair for every file. An ECDH comparison should therefore not count full RSA key-pair generation for every input. A valid benchmark must identify the operations measured and the hardware used.

## 3.7 HKDF-SHA-256: extract and expand

RFC 5869 separates HKDF into two operations. **Extract** takes a `salt` and `IKM` (input keying material) and produces a `PRK`; **Expand** takes the `PRK`, `info`, and length `L` and produces `OKM`. With SHA-256, the hash output is 32 bytes and the maximum expansion length is `255 × 32` bytes. [4]

```text
PRK  = HMAC-SHA-256(salt, IKM)

T(0) = empty string
T(1) = HMAC-SHA-256(PRK, T(0) || info || 0x01)
T(2) = HMAC-SHA-256(PRK, T(1) || info || 0x02)
...
OKM  = first L bytes of T(1) || T(2) || ...
```

Argument order matters. Applying `HMAC(secret, info)` and then a custom operation does not make the result HKDF merely because it produces bytes. Two implementations, for example in C and Rust, will match only if their algorithm, inputs, and parameter encodings match. Nor is calling `BCRYPT_KDF_HASH` sufficient to claim HKDF: the operation and its parameters must match the specification. Windows `BCryptDeriveKey` supports several KDFs and parameters; the function name alone does not fix the hash or the complete protocol. [5]

### Domain separation

`info` binds a derivation to its context. For example, the conceptual labels `course/mod03/input-key/v1` and `course/mod03/metadata-key/v1` represent different uses. Simply concatenating strings without defining their boundaries is insufficient: `ab || c` and `a || bc` produce the same bytes. A specification can use fixed-length fields or length prefixes, and can include a protocol version, algorithm, session ID, and input ID. Every participant must encode these in the same way.

An example encoding contract that does not use paths as identities:

```text
info = versioned_label || session_id[16] || input_id[16]
```

Fixed-length byte IDs make the result unambiguous. The protocol must define how they are generated, where they are retained, and what happens if an ID repeats within a session. A file-system path is a fragile context: renaming or moving a file can prevent the derivation from being reproduced. Two paths that look alike are not necessarily encoded or normalized to the same UTF-8 bytes.

### Salt versus `info`

The salt feeds the extraction phase; `info` distinguishes uses during expansion. A random salt helps separate instances sharing input material, but it does not replace a per-input ID when the same PRK is expanded multiple times. If a salt is used, its value must be available later. RFC 5869 specifies a default when the salt is omitted, but implementations must not silently disagree about which convention they follow. [4]

## 3.8 Reproducible test vector

RFC 5869 test case A.1 exercises HKDF-SHA-256 with fixed inputs. Since these values are published, **they are not production keys**; their purpose is to catch encoding, argument-order, and length errors. The complete expected output appears in the official reference. [4]

```text
IKM  = 0b repeated 22 times
salt = 000102030405060708090a0b0c
info = f0f1f2f3f4f5f6f7f8f9
L    = 42 bytes

Expected PRK:
077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5

Expected OKM:
3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf
34007208d5b887185865
```

The following program verifies **only this public HKDF vector**. It does not open files, traverse directories, or encrypt data:

```python
import hashlib
import hmac


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    hash_len = hashlib.sha256().digest_size
    if not 0 <= length <= 255 * hash_len:
        raise ValueError("length outside the RFC 5869 range")
    previous = b""
    result = bytearray()
    for counter in range(1, (length + hash_len - 1) // hash_len + 1):
        previous = hmac.new(
            prk, previous + info + bytes([counter]), hashlib.sha256
        ).digest()
        result.extend(previous)
    return bytes(result[:length])


ikm = bytes.fromhex("0b" * 22)
salt = bytes.fromhex("000102030405060708090a0b0c")
info = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
expected_prk = bytes.fromhex(
    "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
)
expected_okm = bytes.fromhex(
    "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
    "34007208d5b887185865"
)

prk = hkdf_extract(salt, ikm)
okm = hkdf_expand(prk, info, 42)
assert prk == expected_prk
assert okm == expected_okm
print("RFC 5869, test case A.1: PASS")
```

Exercise: change one byte of `info` and observe that `OKM` changes; restore the official value and confirm `PASS`. The same vector can also be implemented with a C or Rust library and the 42 bytes compared. The comparison is meaningful only if both implementations use precisely the `IKM`, `salt`, `info`, SHA-256, and `L` from test case A.1.

## 3.9 Nonces, IVs, salts, and identifiers

Module 02 covers CBC, CTR, and ChaCha20-Poly1305. Their auxiliary values do not follow a single universal rule:

| Mode or function | Value | Size in the course example | What to check |
| --- | --- | --- | --- |
| AES-CBC | IV | 16 bytes, the AES block size | Unpredictability and protocol format; CBC without authentication does not detect malicious changes |
| AES-CTR | Initial counter / nonce | Defined by the particular construction | Do not reuse the counter stream under the same key or allow counter overflow |
| RFC 8439 ChaCha20-Poly1305 | Nonce | 12 bytes | Uniqueness per key; the output includes a 16-byte tag |
| HKDF | Salt | Defined by the protocol | Exact reproducibility during reconstruction |
| HKDF context | ID | Defined by the protocol | Stable identity and unambiguous encoding |

The Poly1305 tag authenticates the message and associated data according to the AEAD format. CRC32 only detects some accidental errors; it cannot replace the tag. Storing a nonce in public metadata does not reveal the key, but reusing the **key + nonce** pair in ChaCha20-Poly1305 violates the scheme's requirement. [2]

The phrase “ChaCha20 nonce” should distinguish the stream cipher from the authenticated ChaCha20-Poly1305 scheme. This module identifies where the values come from and how they are distinguished; the encryption design and complete tag handling belong to their dedicated modules.

## 3.10 P-256 public-key serialization

The same P-256 public point `(X, Y)` can be carried in different formats. The uncompressed SEC1 form is `0x04 || X[32] || Y[32]`: **65 bytes**. A Windows CNG `BCRYPT_ECCPUBLIC_BLOB` has a `BCRYPT_ECCKEY_BLOB` header with two `ULONG` fields followed by `X[32] || Y[32]`: **72 bytes** for P-256. CNG uses big-endian coordinates. Seventy-two bytes describes that specific blob, not a universal P-256 public-key size. [6][7]

| Representation | Structure | Uncompressed P-256 size |
| --- | --- | ---: |
| SEC1 | `0x04 || X || Y` | 65 bytes |
| CNG ECC public blob | `dwMagic || cbKey || X || Y` | 72 bytes |

Conversion must interpret the header, check type and length, extract the coordinates, and validate the point with the receiving library. Changing an array size from 72 to 65 bytes does not perform a conversion. An exported private blob should not automatically be treated as a standard key file either: its format, protection at rest, and destination are separate decisions.

Before attributing a C/Rust mismatch to HKDF, compare stages: curve → public representation → ECDH agreement → `IKM` → `salt` → `PRK` → `info` → `OKM`. Secret values at these stages should be observed only in an isolated test environment and removed from any logs that will be published.

## 3.11 Key lifetime and exposure scope

A key exists for a period of time. Its creation, use, retention, and disposal must be distinguished:

| Object | When it is needed | Risk of retaining it longer than necessary |
| --- | --- | --- |
| Master private key | For agreement on the master side | Compromise of all material under that pair |
| Per-input ephemeral private key | During its agreement | Exposure of that input's agreement |
| Session ephemeral private key | During the session agreement | Exposure of that session's agreement |
| Shared secret / session PRK | While deriving dependent keys | May affect the session's derivations |
| Working key | During its assigned use | Exposure of data protected by that key |
| Public parameters | During reconstruction and verification | Their loss can make the protocol impossible to reproduce |

Destroying a library *handle*, overwriting a buffer, and deleting a file are different operations. Overwriting an application-owned buffer does not guarantee the absence of internal copies, logs, dumps, or paged material. `SecureZeroMemory` and `zeroize` help shorten the lifetime of copies controlled by the application; they do not promise complete forensic erasure. The description and implementation must agree on when an ephemeral private key is actually destroyed: retaining it in a context until final cleanup is not the same as destroying it immediately after agreement.

Exposure must be described precisely: `K_01` is not `PRK_s`, and `PRK_s` is not the master private key. Domain separation limits accidental reuse, but it does not make every output independent of a compromised parent value.

## 3.12 Public parameters and this module's boundaries

Reproducing a calculation requires a complete specification, not just an algorithm name. At minimum, document the version, curve and public-key representation, agreement method, KDF and hash, salt, context labels and their encoding, stable IDs, output length, and rules for auxiliary values. Depending on the mechanism that processes data, a nonce, algorithm identifiers, and, with AEAD, the tag and AAD definition will also be needed.

This section identifies **cryptographic dependencies**; it does not define a binary footer structure. Module 09 covers its format and sizes; Module 07 covers protecting or transporting key material where applicable; Module 14 covers the complete reverse operation. This division makes Key Generation precise without assuming a final file format already exists.

A session public key should not be named `encrypted_keys`: it is not a set of encrypted keys. A `DWORD` for `orig_size` limits the field to 32 bits. When the file format is designed, the original size will require an explicit representation that accommodates large files. CRC32 does not establish authenticity.

## 3.13 Lab A: observe independent agreements

Prepare three test inputs with known names: `sample01.txt`, `sample02.bin`, and `sample03.dat`. Comparing keys does not require opening or modifying their content. The exercise performs a separate agreement for each input using the same master public key, records the three ephemeral public keys, and verifies the result on both sides of each agreement.

| Input | Ephemeral pair | ECDH result | HKDF context | Expected result |
| --- | --- | --- | --- | --- |
| `sample01.txt` | New | `Z_01` | Stable ID 01 | `K_01` |
| `sample02.bin` | New | `Z_02` | Stable ID 02 | `K_02` |
| `sample03.dat` | New | `Z_03` | Stable ID 03 | `K_03` |

For each input, record the identifier, a fingerprint of the ephemeral public key, the length of the agreement material, and confirmation that both sides obtain the same value. Compare the working keys in memory and report `equal` or `different`, without publishing their bytes. Substituting another input's public key should change the agreement or fail contextual identity checks: the exercise examines dependencies rather than encrypting a file.

**Result to explain:** the three public keys and three agreements will normally differ; each new pair requires generation and an ECDH operation. An unexpected match calls for checking what was reused. Three samples cannot establish a statistical security claim: the exercise tests the logical flow, not CSPRNG quality.

## 3.14 Lab B: one session, three contexts

Use the same three input labels, but now with one ephemeral session public key and a single ECDH secret. First confirm that both sides agree. Then derive a session PRK using a fixed salt **only for this lab comparison**. Form three `info` values with the same structure and different input IDs, and compare the three 32-byte outputs.

```text
same session + same salt + same IKM → same PRK
PRK + info(01) → K_01
PRK + info(02) → K_02
PRK + info(03) → K_03
```

Repeating `info(01)` must reproduce `K_01` exactly. Changing only the visible name of `sample01.txt` must not change the key when the context uses a stable ID independent of the path. Changing the ID must produce a different output. This demonstrates the practical difference between using an input's identity and its current location as context.

The student's results table can record `same/different` for the PRK and keys. There is no need to print the shared secret, PRK, or keys. To validate a custom implementation, first pass the official vector in Section 3.8, then compare lab results with an independent library.

## 3.15 Errors to recognize when reviewing an implementation

| Symptom | Possible cause | Check |
| --- | --- | --- |
| Two languages derive different keys | Public-key formats, ECDH representation, or HKDF parameters differ | Compare each stage separately |
| A key changes after an input is renamed | A path was used as context | Use a documented stable ID |
| Two inputs produce the same key | Repeated `info` or ID, or reused base material | Inspect encoding, not just length |
| “HKDF” fails the RFC vector | Extract and Expand reversed or custom expansion | Check HMAC, counter, and length |
| A 65-byte value cannot be imported as a CNG blob | SEC1 and CNG have different headers | Convert and validate the point |
| A supposedly new nonce repeats under the same key | Uniqueness is not tracked across operations | Check key and nonce scope |
| CRC passes although data was modified | CRC does not authenticate | Verify the AEAD tag |
| A comment says a private key is “destroyed,” but its context retains it | Described and actual lifetimes differ | Identify the last use and remaining copies |

## 3.16 Review questions

1. Why can an ephemeral public key be disclosed without disclosing its private key?
2. How does an ECDH secret differ from a 32-byte working key?
3. How many agreements are performed for three inputs in model A? In model B?
4. What is the scope of exposure if `K_01` is lost? What changes if the session PRK is lost?
5. Why do the same PRK and `info` produce the same HKDF output?
6. Which information must match byte for byte to reproduce a derivation?
7. Why is a file name not always a good cryptographic identity?
8. Must a salt remain secret? Must it be available to repeat HKDF?
9. How does nonce uniqueness differ from key unpredictability?
10. Why can 65 and 72 bytes represent the same P-256 point?
11. Does ECDH alone authenticate the identity of the other side?
12. Why can CRC32 not replace a Poly1305 tag?
13. What does an HKDF test vector prove, and what does it not prove about the complete system?
14. Why is measuring RSA key-pair generation for each file not necessarily representative of a hybrid RSA scheme?

## Module 03 Summary

Key generation involves selecting a cryptographic source, defining roles and scopes, agreeing on a secret when two key pairs are involved, deriving material with a specified KDF, separating uses with unambiguous contexts, preserving the public parameters needed later, and limiting the lifetime of secret material. **Per-input ECDH** and **per-session ECDH with per-input derivation** are distinct models; each needs its own description of key and metadata scope.

The outcome of this module is a verifiable specification and two observations with known inputs. File discovery belongs to the next chapter. Material transport, the final footer, and full reconstruction are covered in the modules identified in the index.

**Next**: Module 04 — File Enumeration Algorithm

## Technical references

1. Microsoft Learn, [BCryptGenRandom](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptgenrandom).
2. IETF, [RFC 8439: ChaCha20 and Poly1305 for IETF Protocols](https://www.rfc-editor.org/rfc/rfc8439.html), Sections 2.8 and 2.8.1.
3. NIST, [SP 800-56A Rev. 3: Pair-Wise Key-Establishment Schemes](https://csrc.nist.gov/pubs/sp/800/56/a/r3/final).
4. IETF, [RFC 5869: HMAC-based Extract-and-Expand Key Derivation Function](https://www.rfc-editor.org/rfc/rfc5869.html), Section 2 and Appendix A.1.
5. Microsoft Learn, [BCryptDeriveKey](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptderivekey).
6. IETF, [RFC 5480: Elliptic Curve Cryptography Subject Public Key Information](https://www.rfc-editor.org/rfc/rfc5480.html), Section 2.2.
7. Microsoft Learn, [BCRYPT_ECCKEY_BLOB](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_ecckey_blob).

---

© 2026 Aldair Maihuiri. All rights reserved. Sharing with attribution to the author is permitted. Reproduction without prior authorization is prohibited.
