/* ============================================================
 * Capacidad 01/15 — Decodificación y LZ de blobs
 * Función C : DecodeAndExpandBlob
 * Dirección : 0x14000738d   · Nodo N1   · Confianza: Alta
 * ------------------------------------------------------------
 * Rutina de dos etapas [confirmado]:
 *   1) Decodifica un stream de seis bits usando un alfabeto propio
 *      de 64 símbolos y una tabla de sustitución de 256 entradas
 *      derivada de una clave de un byte.
 *   2) Expande el resultado con un descompresor LZ77/LZSS.
 * Es la base sobre la que se reconstruye la DLL interna.
 *   Alfabeto (64): offset de archivo 0xA3018.
 *   Fragmento del blob de DLL: offset de archivo 0x1E990.
 * ============================================================
 */

#include "00_tipos_comunes.h"

#define ALPHABET_LEN     64
#define SBOX_LEN         256
#define LZ_MIN_LEN       4                 /* longitud mínima de una referencia */
#define LZ_LEN_MASK      0x1Fu             /* 5 bits de longitud extra -> 4..35 */
#define LZ_OFFSET_SHIFT  5                 /* offset hacia atrás en 11 bits */
#define LZ_EXPECTED_MAX  (16u * 1024u * 1024u)  /* límite de seguridad del expandido */

/* Alfabeto de 64 símbolos (offset de archivo 0xA3018) [confirmado]. */
static const uint8_t ALPHABET[ALPHABET_LEN] =
    "_VpGTo62f8%:!rYaDg.K30IvE~$*QeRAL|>-h]#ynw?lZ5dz9<jFJCUOHsSuc1t^";

/* ------------------------------------------------------------------
 * Construye un S-box de 256 entradas indexado por el alfabeto:
 *   sbox[ALPHABET[i]] = (i - key) & 0x3F
 * La clave `key` de un byte pliega el alfabeto (sustitución).
 * ------------------------------------------------------------------ */
static void BuildKeyedDecodeTable(uint8_t sbox[SBOX_LEN], uint8_t key)
{
    for (uint32_t i = 0; i < SBOX_LEN; i++)
        sbox[i] = 0;
    for (uint32_t i = 0; i < ALPHABET_LEN; i++)
        sbox[ALPHABET[i]] = (uint8_t)((i - key) & 0x3Fu);
}

/* ------------------------------------------------------------------
 * Etapa 1: empaqueta símbolos de 6 bits en bytes (3 bytes por cada
 * 4 símbolos). Lee el valor de sustitución de cada símbolo a través
 * del S-box y lo acumula en un registro de bits.
 * ------------------------------------------------------------------ */
static size_t Decode6BitStream(const uint8_t *sbox,
                               const uint8_t *in, size_t in_len,
                               uint8_t *out, size_t out_cap)
{
    uint32_t acc  = 0;
    int      bits = 0;
    size_t   n    = 0;

    for (size_t i = 0; i < in_len; i++) {
        acc   = (acc << 6) | (uint32_t)sbox[in[i]];
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (n >= out_cap)
                return n;
            out[n++] = (uint8_t)((acc >> bits) & 0xFFu);
            acc &= (bits == 0) ? 0u : ((1u << bits) - 1u);
        }
    }
    return n;
}

/* ------------------------------------------------------------------
 * Etapa 2: expansión LZ77/LZSS [confirmado].
 * Por cada bit de la bandera (MSB -> LSB):
 *   1 = literal (1 byte literal)
 *   0 = referencia hacia atrás: offset de 11 bits + longitud 4..35.
 * El par de la referencia se lee little-endian:
 *   longitud = (par & 0x1F) + 4 ;  offset = par >> 5.
 * ------------------------------------------------------------------ */
static bool ExpandLz(const uint8_t *src, size_t src_len,
                     uint8_t *dst, size_t dst_cap, size_t *out_len)
{
    size_t  sp    = 0, dp = 0;
    uint8_t flags = 0;
    int     bits  = 0;

    while (sp < src_len) {
        if (bits == 0) {
            flags = src[sp++];
            bits  = 8;
        }

        bool literal = (flags & 0x80u) != 0;   /* bit más significativo */
        flags = (uint8_t)(flags << 1);
        bits--;

        if (literal) {
            if (dp >= dst_cap)
                return false;
            dst[dp++] = src[sp++];
            continue;
        }

        /* Referencia hacia atrás: necesita 2 bytes. */
        if (sp + 1 >= src_len)
            return false;
        uint16_t pair   = (uint16_t)((uint16_t)src[sp] | ((uint16_t)src[sp + 1] << 8));
        size_t   len    = (size_t)(pair & LZ_LEN_MASK) + LZ_MIN_LEN;
        size_t   offset = (size_t)(pair >> LZ_OFFSET_SHIFT);
        sp += 2;

        if (offset == 0 || offset > dp)        /* referencia inválida hacia atrás */
            return false;
        size_t back = dp - offset;
        if (dp + len > dst_cap)
            return false;

        for (size_t k = 0; k < len; k++)
            dst[dp + k] = dst[back + k];       /* copia solapada, byte a byte */
        dp += len;
    }

    *out_len = dp;
    return true;
}

/* ------------------------------------------------------------------
 * 0x14000738d — API pública del loader.
 * Decodifica `blob` (6 bits -> bytes) y expande el LZ resultante.
 * ------------------------------------------------------------------ */
bool DecodeAndExpandBlob(const EncodedBlob *blob, ExpandedBlob *out)
{
    if (blob == NULL || out == NULL || blob->encoded == NULL)
        return false;

    uint8_t sbox[SBOX_LEN];
    BuildKeyedDecodeTable(sbox, blob->key);

    /* Etapa 1: capacidad del stream intermedio (3/4 de la entrada). */
    size_t   stage1_cap = (blob->encoded_len * 3) / 4 + 1;
    uint8_t *stage1 = (uint8_t *)HeapAlloc(GetProcessHeap(), 0, stage1_cap);
    if (stage1 == NULL)
        return false;

    size_t mid_len = Decode6BitStream(sbox, blob->encoded, blob->encoded_len,
                                      stage1, stage1_cap);

    /* Etapa 2: expansión LZ sobre un buffer de salida acotado. */
    out->data = (uint8_t *)HeapAlloc(GetProcessHeap(), 0, LZ_EXPECTED_MAX);
    if (out->data == NULL) {
        HeapFree(GetProcessHeap(), 0, stage1);
        return false;
    }

    bool ok = ExpandLz(stage1, mid_len, out->data, LZ_EXPECTED_MAX, &out->size);
    HeapFree(GetProcessHeap(), 0, stage1);

    if (!ok) {
        HeapFree(GetProcessHeap(), 0, out->data);
        out->data = NULL;
        out->size = 0;
        return false;
    }
    return true;
}
