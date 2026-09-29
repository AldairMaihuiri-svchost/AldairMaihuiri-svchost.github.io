---
title: "Ransomware Red Teaming — Module 2: Cryptographic Algorithms"
description: "AES, ChaCha20-Poly1305, RSA-OAEP, ECDH, HKDF, and random generation: properties, limits, sample analysis, and laboratory verification."
author: Aldair Maihuiri
---

# Module 02 — Cryptographic algorithms

This module examines cryptographic components that may appear in a ransomware incident. Its purpose is to identify the role of each component, the data an analyst needs to reconstruct a scheme, and the conclusions that a particular sample can support. **An algorithm does not define an entire family:** different versions, platforms, and configurations may use different constructions.

The examples distinguish a **primitive** (AES, ChaCha20, RSA, or an ECDH operation), a **mode or construction** (CBC, CTR, ChaCha20-Poly1305, RSA-OAEP), and a **protocol** (how keys and parameters are generated, derived, stored, and recovered). A sound primitive within an incomplete protocol can leave files unrecoverable or information exposed.

The reference specifications include [NIST SP 800-38A](https://csrc.nist.gov/pubs/sp/800/38/a/final), [RFC 8439](https://www.rfc-editor.org/rfc/rfc8439.html), [RFC 8017](https://www.rfc-editor.org/rfc/rfc8017.html), [RFC 7748](https://www.rfc-editor.org/rfc/rfc7748.html), and [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869.html). Analyses of real ransomware families are cited alongside the observations they support.

## 2.1 Symmetric cryptography — AES

AES is a block cipher with a **128-bit block size**. AES-256 means that its key is **256 bits** long, not that its blocks are 256 bits long. Processing data of varying lengths requires a mode of operation. CBC and CTR address that requirement in different ways; on their own they provide confidentiality, **not authentication**. [NIST, FIPS 197](https://csrc.nist.gov/pubs/fips/197/final) · [NIST SP 800-38A](https://csrc.nist.gov/pubs/sp/800/38/a/final).

| Property | AES-256-CBC | AES-256-CTR |
| --- | --- | --- |
| Unit processed by AES | 16-byte data blocks | 16-byte counter blocks that produce a stream to combine with the data |
| Data length | The final block must be padded, for example with PKCS#7 | Arbitrary lengths can be processed without padding |
| Initial parameter | 16-byte IV | Initial counter block and an increment rule; the format must be defined |
| Critical condition when reusing a key | The IV must satisfy the mode's requirements, including unpredictability for CBC | No counter block may be repeated under the same key |
| Integrity | Not built in | Not built in |
| Decryption | Requires the original key and IV and correct handling of padding | Applies the stream generated from the same key and counter blocks again |

### AES-256-CBC

CBC combines each plaintext block with the preceding ciphertext block before applying AES. The first block uses the IV. A suitable IV therefore prevents two messages with the same opening and key from necessarily producing the same first ciphertext block. The IV **is not a secret key**: it is retained with the data needed for decryption. Its value must come from a cryptographic generator and meet the mode's requirements. [NIST SP 800-38A](https://csrc.nist.gov/pubs/sp/800/38/a/final).

With PKCS#7, even a message whose length is already a multiple of 16 receives a full block of padding. The increase per file is **1 to 16 bytes**, before any application header or metadata. An implementation can work in chunks and finish the padding at the end: **CBC does not require loading the entire file into memory** or knowing the final size at the start of every operation.

The limitation that matters most in analysis is the lack of authentication. Decryption that produces bytes and accepts the padding does not prove that the contents are authentic. Differences between padding errors and other processing errors should not be exposed to an outside party. When examining a sample that uses CBC, the analyst should also determine whether it has a separate integrity mechanism and how that mechanism is verified.

**Reading a Windows CNG example:** to interpret a call to `BCryptEncrypt`, inspect the AES algorithm, the mode set through `BCRYPT_CHAINING_MODE`, key length, IV, `BCRYPT_BLOCK_PADDING` setting, queried output size, and return status. The API may modify the IV buffer while chaining; the original IV must be retained if another process needs to repeat the operation. Seeing `BCRYPT_AES_ALGORITHM` alone does not establish that the implementation is correct. [Microsoft: `BCryptEncrypt`](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptencrypt).

**Checks with test data:** lengths of zero, 15, 16, and 17 bytes; a round trip using the same original IV; rejection of an undersized output buffer; and handling of truncated or altered ciphertext. An unexpected result calls for inspection of both the padding and API status rather than an immediate assumption that the key is wrong.

### AES-CTR

CTR encrypts counter blocks with AES and combines the resulting stream with the data. The same procedure therefore transforms plaintext into ciphertext and ciphertext back into plaintext without padding. Its essential requirement is that **no counter block be repeated under the same key**, either within a message or across messages. Reusing the stream exposes relationships between plaintexts. CTR also does not detect changes to ciphertext. [NIST SP 800-38A](https://csrc.nist.gov/pubs/sp/800/38/a/final).

The expression “12-byte nonce + 4-byte counter” describes **one possible format**, not the universal definition of AES-CTR. Each protocol must specify field sizes, byte order, initial value, block limit, and how the initial counter block is retained. RFC 3686 defines an IPsec construction with its own fields; citing its initial counter without adopting the rest of its format can be misleading. [RFC 3686](https://www.rfc-editor.org/rfc/rfc3686.html).

An analyst may see AES in ECB mode used in CNG **solely to obtain the AES output for a counter block**. That observation does not mean the data itself is encrypted in ECB: the analyst must trace the composition of the counter and how its output is combined with the data. Before calling that code “CTR,” check exact field lengths, uniqueness of the initial block, detection of counter overflow, and any integrity protection. A manual composition has more opportunities for error than a construction provided by a reviewed library.

**Comparison with CBC:** CTR accepts arbitrary data lengths; CBC needs special treatment of the final block. This difference does not establish a fixed speed. Performance depends on processor instructions, the library, parallelism, chunk size, and the cost of reading and writing data.

## 2.2 ChaCha20 and ChaCha20-Poly1305

ChaCha20 is a stream cipher. Its IETF variant uses a **32-byte key**, a **12-byte nonce**, and a 32-bit block counter. Its output is combined with data to encrypt or decrypt it. **ChaCha20 alone does not authenticate the data.** RFC 8439 specifies little-endian word order and a finite counter space; converting integer words to bytes without defining that order is not portable. [RFC 8439, Sections 2.3 and 2.4](https://www.rfc-editor.org/rfc/rfc8439.html).

ChaCha20-Poly1305 adds authentication: it produces ciphertext and a **16-byte tag** and can authenticate associated data (AAD) without encrypting it. In the RFC 8439 construction, one ChaCha20 block generates a one-time Poly1305 key; the stream used for the data begins at the counter value specified by the standard. Decryption must verify the tag and reject a modified message. Code that only implements the *quarter round* and combines bytes with a stream **does not implement ChaCha20-Poly1305**. [RFC 8439, Section 2.8](https://www.rfc-editor.org/rfc/rfc8439.html).

| Element | ChaCha20 | ChaCha20-Poly1305 |
| --- | --- | --- |
| Confidentiality | Yes, when the key and nonce are used correctly | Yes |
| Authentication | No | Yes, through a Poly1305 tag |
| Ciphertext size | Same as the plaintext | Same as the plaintext, plus the tag if stored together |
| Associated data | Not part of the primitive | Can be authenticated without being encrypted |
| Repeated key and nonce | Repeats the stream | Repeats both the stream and the authenticator's one-time key |

The nonce must be **unique for every operation under a given key**. Its generation and tracking belong to the protocol, not to an isolated encryption call. A random 96-bit nonce can be evaluated for a bounded number of uses, but saying only “generate one at random” leaves out how many messages share a key and how collisions are avoided. If each file has a different key, that assumption must be stated explicitly. [RFC 8439, security considerations](https://www.rfc-editor.org/rfc/rfc8439.html).

**Reading a Rust example using the `chacha20poly1305` library:** its `encrypt` operation returns encrypted bytes and a tag according to the library's interface; `decrypt` checks the tag and reports failure if it does not match. To interpret a sample or lab format, document the key, nonce, any AAD, field order, and where the tag is stored. A footer listing only “public key + nonce” would be incomplete if the ciphertext did not include the tag elsewhere. [`chacha20poly1305` documentation](https://docs.rs/chacha20poly1305/latest/chacha20poly1305/).

**What has been observed:** SentinelLabs documented BlackCat/ALPHV configurations supporting **AES and ChaCha20**; another analysis described a choice related to the availability of AES acceleration on the platform examined. That does not prove all BlackCat variants use ChaCha20-Poly1305, nor does it justify attributing the same design rationale to Akira. An Akira analysis documents ChaCha20 and RSA protection of keys in certain samples; ChaCha20 must be distinguished from the full authenticated construction. [SentinelLabs: BlackCat](https://www.sentinelone.com/labs/blackcat-ransomware-highly-configurable-rust-driven-raas-on-the-prowl-for-victims/) · [SentinelLabs: observed selection](https://www.sentinelone.com/labs/crimeware-trends-ransomware-developers-turn-to-intermittent-encryption-to-evade-detection/) · [Trend Micro: Akira](https://www.trendaisecurity.com/en-us/resources-insights/deep-research/ransomware-spotlight-akira).

ChaCha20 can perform well without AES acceleration. Its actual advantage over AES depends on the CPU, whether the instructions are available in the virtualized environment, the library, and the workload. The presence of VMware ESXi or Linux **does not establish** that AES-NI is disabled, and no single GB/s figure represents all these configurations.

## 2.3 RSA — public-key cryptography

RSA-OAEP encrypts a short value with a public key so that the holder of the corresponding private key can recover it under the chosen protocol. It does not efficiently process large files on its own. The public key, its size, the OAEP hash algorithm, and any optional label are parameters that must match on both sides.

For RSAES-OAEP, RFC 8017 sets the limit at `mLen ≤ k − 2hLen − 2`. With a 2048-bit RSA key (`k = 256` bytes) and SHA-256 (`hLen = 32` bytes), the maximum is **190 plaintext bytes per operation**. A 32-byte symmetric key fits within that limit. The corresponding RSA output is 256 bytes before any additional metadata. These figures apply to this example, not to every key size, hash, or padding scheme. [RFC 8017, Section 7.1.1](https://www.rfc-editor.org/rfc/rfc8017.html#section-7.1.1).

| Observed element | Question for the analyst |
| --- | --- |
| Public key or CNG blob | Are its size, exponent, modulus, and representation known? |
| OAEP parameters | Which hash and label does each side use? |
| RSA output | Does it protect a data key, a session secret, or another short value? |
| Associated metadata | How is the key or entry to which it belongs identified? |
| Private side | Is there evidence of where the private key is held, or is only the public side visible? |

A `BCRYPT_RSAKEY_BLOB` structure followed by an exponent and modulus **is not a PEM-to-CNG-blob conversion**: such a conversion would require parsing the input format, validating lengths, and building the representation required by the API. A structure declaration is therefore a **format description**, not an import function.

PKCS#1 v1.5 and OAEP are distinct schemes. Bleichenbacher-type attacks exploit a padding-validity oracle under specific conditions; it would be wrong to claim that every use of PKCS#1 v1.5 always reveals the plaintext, or that OAEP rules out every implementation flaw. Errors, response times, and subsequent checks are part of what must be assessed in a recovery program. [RFC 8017](https://www.rfc-editor.org/rfc/rfc8017.html).

**Security strength:** the bit length of an RSA key is not directly comparable to that of an elliptic-curve key. NIST estimates approximately **112 bits** of security strength for RSA-2048 and **128 bits** for 256-bit ECC; this is more informative than saying “2048 versus 256, equally secure.” [NIST SP 800-57, Part 1](https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final).

## 2.4 ECDH — X25519 and P-256

ECDH is a **secret agreement**, not an operation that directly encrypts files or keys. Each side combines its private key with the other side's public key. If the corresponding pairs and the same curve are used, both sides obtain a shared secret from which working key material can be derived. X25519 and ECDH using P-256 have different formats and interfaces; a public key for one curve cannot automatically be interpreted as a key for the other. [RFC 7748](https://www.rfc-editor.org/rfc/rfc7748.html) · [Microsoft: Diffie-Hellman keys](https://learn.microsoft.com/en-us/windows/win32/seccrypto/diffie-hellman-keys).

The ECDH output must feed a derivation specified from end to end. An application that applies SHA-256 to the secret in Rust and `BCRYPT_KDF_HASH` in Windows has not demonstrated compatibility: even if both outputs are 32 bytes long, **the functions may return different values**. `BCRYPT_KDF_HASH` is not another name for HKDF. When a sample uses a particular KDF, the analyst needs to reconstruct its inputs and compare its output against a known test value. [Microsoft: `BCryptDeriveKey`](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptderivekey).

With X25519, consider the case where a public value leads to an all-zero shared secret. RFC 7748 permits detecting that result and aborting; protocols that require the check must perform it. A private variable going out of scope is also insufficient evidence that its bytes have been wiped from memory: **the end of a variable's lifetime and verifiable erasure are different properties**. [RFC 7748, Section 6](https://www.rfc-editor.org/rfc/rfc7748.html#section-6).

### Conceptual model with an ephemeral pair per entry

In this course, **Multi-Master Pattern (MMP)** names the model examined below; the name does not establish that a real ransomware family implements precisely this protocol. Module 3 covers key generation and lifetime, and a later module examines the footer format.

| Conceptual stage | Data or relationship to verify |
| --- | --- |
| Configuration | A persistent public key exists, and its curve and format are known |
| Each entry | A different ephemeral pair is observed, or there is evidence of distinct derivation |
| Agreement | The ephemeral private key and persistent public key produce the secret for that entry |
| Derivation | The KDF, salt, context, and output length are identified |
| Encryption | The symmetric algorithm, IV or nonce, any tag, and their relationship to the data are recorded |
| Recovery | The other side needs its private key, the ephemeral public key, and all protocol parameters |

An ephemeral public key can be stored in the footer without revealing the shared secret merely by being public. However, **storing that public key alone is insufficient** if the format also requires an IV, nonce, tag, identifiers, or derivation parameters. In CNG, an exported P-256 public key includes a header and coordinates; it is not the same length as a raw 32-byte X25519 public key. [Microsoft: `BCRYPT_ECCPUBLIC_BLOB`](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptexportkey) · [RFC 7748](https://www.rfc-editor.org/rfc/rfc7748.html).

Local agreement with an already available public key **can** take place without network traffic during that stage. This says nothing about whether the full intrusion involved communication: initial access, exfiltration, negotiation, or distribution of tools may occur at other times. Nor does it mean that only one entity can recover data in every circumstance; copies, implementation errors, material found during the incident, or seized keys change the assessment of a particular case.

### Ephemeral pair per entry versus session secret

A pair per entry separates the agreement material for different entries. A session secret can yield distinct keys through a KDF with unique contexts, but exposure of the base secret may compromise every value derived from it. The distinction depends on **which material is exposed and how long it exists**; a design's security cannot be established by counting key pairs without examining storage, derivation, authentication, and recovery.

## 2.5 HKDF — deriving key material

HKDF, defined in RFC 5869, has two stages: **Extract** takes the initial keying material (IKM) and a salt to obtain an intermediate pseudorandom key (PRK); **Expand** uses that PRK, context information (`info`), and a requested length to produce output keying material (OKM). The salt and `info` are not treated as secrets. When no salt is provided, RFC 5869 specifies a string of zero bytes equal in length to the hash output. [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869.html).

`PRK = HMAC-SHA-256(salt, IKM)`

`T(1) = HMAC-SHA-256(PRK, info || 0x01)`

`T(2) = HMAC-SHA-256(PRK, T(1) || info || 0x02)`

The concatenated `T(i)` values are truncated to the requested length. With SHA-256, the RFC 5869 maximum is **255 × 32 = 8,160 bytes**. A manual implementation with a fixed-size array for `info` must check its length and every operation; a one-byte counter cannot be extended without limit, either. The [Appendix A test vectors](https://www.rfc-editor.org/rfc/rfc5869.html#appendix-A) provide independent results without relying on a ransomware sample.

Deriving, for example, 32 bytes for a key and 16 for an IV makes sense only if **the entire protocol** specifies the curve, shared-secret representation, salt, `info`, lengths, relationship among entries, and IV-uniqueness conditions. Derivation alone does not ensure that the requirements of CBC, CTR, or ChaCha20-Poly1305 are met. Separate contexts can also be used for different functions; their names must match on both sides.

Windows documentation distinguishes `BCRYPT_KDF_HASH` from `BCRYPT_KDF_HKDF`. For `BCryptDeriveKey` operating on an agreed secret, Microsoft states that HKDF support begins with **Windows 10**. The availability of a derivation API in an earlier version does not establish support for this particular HKDF option. [Microsoft: `BCryptDeriveKey`](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptderivekey) · [Microsoft: `BCryptKeyDerivation`](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptkeyderivation).

**Verification exercise:** use the IKM, salt, `info`, and length from an RFC 5869 vector and compare the PRK and OKM byte for byte. If two libraries disagree, inspect encodings, lengths, and KDF selection before attributing the difference to ECDH.

## 2.6 Cryptographically secure random generation (CSPRNG)

The security of keys, IVs, and nonces depends on how they are obtained and on the rules of each mode. A general-purpose pseudorandom generator such as `rand()` or `Math.random()` is not a cryptographic source for key generation. A CBC IV must meet that mode's unpredictability requirement; CTR and ChaCha20-Poly1305 require, above all, that critical inputs not repeat under a given key.

On Windows, Microsoft recommends `BCryptGenRandom` with `BCRYPT_USE_SYSTEM_PREFERRED_RNG`. Its status must be checked **before the bytes are used**. “System-preferred generator” does not prescribe one internal mechanism across all versions or imply that no other cryptographic API is appropriate. In Rust, an interface to the system generator must likewise handle availability and errors according to the library version in use. [Microsoft: `BCryptGenRandom`](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptgenrandom) · [Microsoft SDL: recommendations](https://learn.microsoft.com/en-us/security/engineering/cryptographic-recommendations).

| Material | Question before use |
| --- | --- |
| Symmetric key | Does it come from a cryptographic source or a specified derivation? |
| CBC IV | Does it meet the unpredictability requirement, and is it retained for recovery? |
| Initial CTR block | Could any counter block repeat under the same key? |
| ChaCha20-Poly1305 nonce | How is uniqueness per operation under that key ensured? |
| Ephemeral private key | How was it generated, and what evidence exists about its lifetime? |

**Historical case:** analyses of Petya in 2016 describe flaws in its own key scheme and its use of **Salsa20**, which aided research and recovery tools. This does not demonstrate that Petya seeded `rand()` with a timestamp or that AES was being attacked. A specific case should be presented in terms of the flaw actually observed by researchers. [Malwarebytes Labs: Petya](https://www.malwarebytes.com/blog/news/2016/04/petya-ransomware) · [Securelist: Petya](https://securelist.com/petya-the-two-in-one-trojan/74609/).

## 2.7 Comparing performance without isolated figures

There is no universal GB/s figure for AES-CTR, AES-CBC, or ChaCha20-Poly1305. Throughput of the **primitive in memory** and the time to **process a file** measure different things. The latter includes reads, writes, authentication, chunking, library calls, and file system behavior. PKCS#7 padding adds between 1 and 16 bytes per file; by itself, it cannot explain a difference of hundreds of MB/s.

At a minimum, a reproducible benchmark must document:

1. CPU model, available AES acceleration, and whether the test runs on the host or in a VM.
2. Operating system, library, version, compiler, and relevant settings.
3. Data size and type, number of repetitions, and warm-up procedure.
4. What is measured: an in-memory transformation alone or reads, writes, and authentication as well.
5. Metric and spread: elapsed time, median, range, and volume actually processed.

| Situation | Reasonable inference | Limit of the inference |
| --- | --- | --- |
| Hardware-accelerated AES is available | It can perform very well with a suitable implementation | CPU brand alone does not establish a specific speed |
| ChaCha20 runs in software | It can be competitive without AES instructions | It will not always outperform accelerated AES |
| Data is stored on disk or transmitted over a network | I/O may dominate total time | An in-memory test does not represent the entire incident |
| A variant encrypts only portions of a file | It processes fewer bytes than full encryption | Its elapsed time should not be compared as though it protected the same volume |

SentinelLabs documented BlackCat samples that selected between AES and ChaCha20 according to available acceleration. The example illustrates why measurements need context rather than a speed table applied to every family. [SentinelLabs](https://www.sentinelone.com/labs/crimeware-trends-ransomware-developers-turn-to-intermittent-encryption-to-evade-detection/).

## 2.8 Verification and code-reading practice

The following exercises use **test buffers in memory**. Their purpose is to verify properties of the constructions and learn how to read calls to them; no isolated test establishes that a real sample uses the same protocol.

### Experiment A — identify what the CBC IV contributes

Take two test messages with an identical first block, encrypt them with the same key and **different IVs**, and compare the first ciphertext blocks. Repeat with the **same IV**. In the second test, matching key, IV, and first input block should produce a matching first ciphertext block. This does not mean that the entirety of both messages is identical. Record the IV, input and output lengths, and padding policy; retain copies of the IVs if the API modifies them during processing. [NIST SP 800-38A](https://csrc.nist.gov/pubs/sp/800/38/a/final).

### Experiment B — observe stream reuse in CTR

For two test byte sequences encrypted with the same CTR stream, the identity `C₁ ⊕ C₂ = P₁ ⊕ P₂` holds. It shows why repeating a counter block under one key exposes information without “breaking AES.” The exercise concerns this algebraic property and should conclude by identifying the fields an analyst would need to find in a real format. Do not transfer this conclusion directly to CBC: repeating its IV has different effects.

### Experiment C — distinguish encryption from authentication

Use a ChaCha20-Poly1305 library to transform a short test message, retain any AAD, and confirm that decryption returns the original. Then change one byte of the ciphertext, tag, or AAD: each change should result in an authentication failure. If an interface returns “ciphertext + tag” in one buffer, record its size and determine where the tag is stored before interpreting the format. RFC 8439 test vectors provide an independent reference. [RFC 8439](https://www.rfc-editor.org/rfc/rfc8439.html).

### Experiment D — check HKDF against a standard

**Test case 1** in Appendix A of RFC 5869 uses SHA-256, 22 bytes of `0b` as IKM, salt `000102030405060708090a0b0c`, `info = f0f1f2f3f4f5f6f7f8f9`, and a **42-byte** output. The PRK begins with `077709362c2e32df` and the OKM with `3cb25f25faacd57a`. Compare **all** bytes published in the RFC, not merely these prefixes. The exercise detects errors in length, ordering, and concatenation in an HKDF implementation. [RFC 5869, Appendix A.1](https://www.rfc-editor.org/rfc/rfc5869.html#appendix-A.1).

### What to require of a C or Rust example

| Aspect | Minimum check before calling it functional |
| --- | --- |
| Block type | A `c` block contains C; a `rust` block contains Rust; pseudocode is labeled accordingly |
| Dependencies | Required library versions and features are stated with the example |
| Input | Exact key, IV, nonce, and buffer sizes, and known test data |
| Output | Queried or expected size, tag location, and necessary metadata |
| Errors | Every API result checked and resources released on failure as well as success |
| Cryptographic contract | Unambiguous mode and KDF, including the applicable uniqueness requirement |
| Verification | Published vector and round-trip test, plus a modified-input case that must fail |

A fragment listing `BCryptOpenAlgorithmProvider`, `BCryptGenerateSymmetricKey`, and `BCryptEncrypt` without checking sizes, statuses, and cleanup describes **calls**, not a finished implementation. In Rust, a function returning `Vec<u8>` also does not say whether a tag is included or how errors are reported: consult the library contract and retain that information when documenting a sample. [Microsoft: `BCryptEncrypt`](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptencrypt) · [RustCrypto: `chacha20poly1305`](https://docs.rs/chacha20poly1305/latest/chacha20poly1305/).

## Module 02 summary

| Construction | Role | Condition to check |
| --- | --- | --- |
| AES-256-CBC | Block-based confidentiality with padding | Suitable IV, lengths, and integrity protection if required by the application |
| AES-256-CTR | Confidentiality through counter blocks | No repeated counter block under the same key; separate integrity protection |
| ChaCha20 | Stream-based confidentiality | Key and nonce used without repeating the stream |
| ChaCha20-Poly1305 | Authenticated encryption | Unique nonce under the key and verification of the tag |
| RSA-OAEP | Public-key protection of short values | Maximum size, hash, label, and corresponding key |
| ECDH P-256 / X25519 | Secret agreement | Matching curve, format, validation, and KDF |
| HKDF-SHA256 | Context-bound derivation | IKM, salt, `info`, length, and test vectors |
| CSPRNG | Cryptographic random material | Checked result and rules for using the generated material |

Module 3 covers key generation, derivation, exposure, and lifetime in greater depth. A later module examines footer formats and recovery; neither can be inferred solely from the choice of an algorithm.

Xtra:

- **Explain the difference between a block cipher in CBC mode (AES-CBC) and stream-based encryption (AES-CTR, ChaCha20). Why does CBC require padding while CTR and ChaCha20 do not?**

- **What exactly happens if the same IV and key are reused for two different files under CBC?**

- **What happens if the same nonce and key are reused in ChaCha20-Poly1305?**

- **Why is the parameter called a “nonce” in ChaCha20 and an “IV” in CBC? Is this merely terminology, or is there a functional difference?**

- **In the MMP (Multi-Master Pattern) scheme with ephemeral ECDH per file:**
  - How many keys are generated for each file?
  - Which key is destroyed immediately, and why?
  - What is stored in the file's footer, and why is it safe to store it there?

- **The module says that the MMP scheme generates no network traffic during encryption:**
  - Which network IOCs would an EDR or SOC look for if there is no C2 traffic during encryption?
  - Which other artifacts (disk, memory, registry) might reveal the behavior?
  - How might an attacker minimize those artifacts?


**Next**: Module 03 — Key generation algorithms (master key, session key, per-file key)

---

© 2026 Aldair Maihuiri. All rights reserved. Sharing with attribution to the author is permitted. Reproduction without prior authorization is prohibited.
