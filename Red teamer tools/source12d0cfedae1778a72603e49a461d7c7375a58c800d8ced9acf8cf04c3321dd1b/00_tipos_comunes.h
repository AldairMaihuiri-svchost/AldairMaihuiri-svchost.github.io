/* ============================================================
 * 00_tipos_comunes.h — tipos, constantes y prototipos compartidos
 * Reconstrucción analítica en C del loader configurable +
 * infostealer + clipper de criptomonedas (15 capacidades).
 *
 * SHA-256 muestra : 12d0cfedae1778a72603e49a461d7c7375a58c800d8ced9acf8cf04c3321dd1b
 * PE x64 con DLL interna reconstruida (MD5 71589459b8c1f7444cb6955d051d2e57)
 *
 * Convención de este documento:
 *   [confirmado]   = relación observada estáticamente en el binario.
 *   [condicionado] = depende de la configuración entregada por el C2.
 *   Las API "peligrosas" se describen como pasos de comportamiento,
 *   no como invocaciones reutilizables listas para su uso.
 * ============================================================
 */
#ifndef RECONSTRUCCION_TIPOS_COMUNES_H
#define RECONSTRUCCION_TIPOS_COMUNES_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <stdio.h>
#include <windows.h>

/* ------------------------------------------------------------------
 * Constantes verificadas en la muestra
 * ------------------------------------------------------------------ */
#define C2_XOR_KEY         0xA2u                 /* XOR de la respuesta C2 [confirmado] */
#define C2_MAX_ELEMENT     0x400000u             /* límite por elemento de configuración */
#define SCREENSHOT_TAG     0x8000000000000004ULL /* etiqueta interna de captura  [confirmado] */
#define NET_TYPE_BMP       0x06u                 /* tipo de red del paquete BMP [confirmado] */
#define CLIPPER_POLL_MS    600u                  /* sondeo del portapapeles [confirmado] */
#define BEACON_INTERVAL_MS 30000u                /* intervalo de beacon (configurable) */

/* ------------------------------------------------------------------
 * Primitivas de buffer y blob
 * ------------------------------------------------------------------ */
typedef struct {
    uint8_t *data;
    size_t   len;
    size_t   cap;
} ByteBuffer;

/* Blob codificado con el alfabeto propio de 64 símbolos (CAP 1). */
typedef struct {
    const uint8_t *encoded;      /* blob codificado (6 bits/símbolo) */
    size_t         encoded_len;
    uint8_t        key;          /* clave de un byte de la tabla de sustitución */
} EncodedBlob;

/* Blob ya decodificado y descomprimido (CAP 1). */
typedef struct {
    uint8_t *data;               /* salida descomprimida */
    size_t   size;
} ExpandedBlob;

/* ------------------------------------------------------------------
 * Red
 * ------------------------------------------------------------------ */
typedef struct {
    const wchar_t *host;         /* host dinámico: se toma del contexto, no fijado */
    uint16_t       port;         /* 443 (HTTPS) */
} RemoteEndpoint;

/* ------------------------------------------------------------------
 * Configuración en tiempo de ejecución (base DLL 0x18007de68)
 * Offsets observados: downloads +0x00, registry +0x18 (entradas 0x60),
 * apps +0x30 (entradas 0x70), wallets[10] +0x48..+0x120, flags +0x138.
 * ------------------------------------------------------------------ */
typedef struct {
    wchar_t url[MAX_PATH];        /* URL de descarga entregada por el C2 */
    wchar_t local_path[MAX_PATH]; /* ruta local de descarga */
    wchar_t args[128];            /* argumentos opcionales de ejecución */
} DownloadTask;                   /* [condicionado] */

typedef struct {
    DownloadTask *items;
    size_t        count;
} TaskList;                       /* +0x00 de la configuración */

typedef struct {
    uint32_t hive;                /* raíz: HKLM / HKCU / HKU / HKCR / HKCC */
    wchar_t  subkey[128];         /* subclave a abrir */
    wchar_t  value_name[64];      /* nombre de valor a leer */
} RegistryQueryItem;              /* entradas de 0x60 bytes */

typedef struct {
    RegistryQueryItem *items;
    size_t             count;
} RegistryQueryList;              /* +0x18 de la configuración */

typedef struct {
    uint32_t kind;                /* APP_DISCORD / APP_STEAM / APP_ROBLOX */
    wchar_t  path[MAX_PATH];      /* ruta base de la aplicación */
    wchar_t  marker[64];          /* marcador / valor auxiliar por app */
} AppTarget;                      /* entradas de 0x70 bytes */

typedef struct {
    AppTarget *items;
    size_t     count;
} AppTargetList;                  /* +0x30 de la configuración */

typedef struct {
    bool    is_set;
    wchar_t destination[96];      /* destino de sustitución del clipper */
} WalletReplacement;              /* wallets[10] +0x48..+0x120 */

typedef struct {
    TaskList          downloads;  /* +0x00 */
    RegistryQueryList registry;   /* +0x18 */
    AppTargetList     apps;       /* +0x30 */
    WalletReplacement wallets[10];/* +0x48 */
    uint8_t           task_flags; /* +0x138: flags que activan cada módulo */
} RuntimeConfig;

/* ------------------------------------------------------------------
 * Cola concurrente de resultados (mutex + señal)
 * ------------------------------------------------------------------ */
typedef enum {
    MSG_EXTENSION_METADATA = 0,   /* centinela: se descarta en el drenaje */
    MSG_APP_OR_REGISTRY    = 1,
    MSG_BROWSER_DATA       = 3,
    MSG_SCREENSHOT         = 4    /* etiqueta interna 0x8000000000000004 */
} MessageKind;

typedef struct {
    MessageKind kind;
    uint64_t    tag;              /* 0x8000000000000000 | kind ; 0 = centinela */
    ByteBuffer  payload;
} TypedMessage;

typedef struct {
    TypedMessage *items;
    size_t        count;
} MessageBatch;

typedef struct Channel {
    CRITICAL_SECTION   lock;      /* exclusión mutua */
    CONDITION_VARIABLE signal;    /* señal al controlador */
    TypedMessage      *items;
    size_t             count;
    size_t             cap;
} Channel;

typedef struct {
    Channel        queue;         /* cola interna de resultados */
    RuntimeConfig  cfg;           /* configuración entregada por el C2 */
    RemoteEndpoint endpoint;      /* host/puerto dinámicos */
    volatile bool  running;       /* bandera de vida de los workers */
} RuntimeContext;

/* ------------------------------------------------------------------
 * Prototipos compartidos (una definición por capacidad)
 * ------------------------------------------------------------------ */
/* CAP 1 — Decodificación y LZ de blobs */
bool DecodeAndExpandBlob(const EncodedBlob *blob, ExpandedBlob *out);

/* CAP 2 — Reconstrucción PE e inyección DLL */
void LaunchInternalDllInRemoteProcess(void);

/* CAP 3 — Inicialización y creación de controlador */
BOOL            APIENTRY MalwareDllMain(HMODULE module, DWORD reason, void *reserved);
RuntimeContext *CreateRuntimeContext(void);
void            DestroyRuntimeContext(RuntimeContext *ctx);
bool            StartDetachedWorker(LPTHREAD_START_ROUTINE routine, RuntimeContext *ctx);

/* CAP 4 — Orquestación de red y workers */
void ControllerMain(void *raw_ctx);
void DispatchConfiguredTasks(RuntimeContext *ctx, const RuntimeConfig *cfg);
bool WorkerShouldRun(void);
void CleanupAndExitWorker(RuntimeContext *ctx);

/* CAP 5 — Anti VM y anti sandbox */
bool IsVirtualizedOrSandboxed(void);

/* CAP 6 — C2 HTTPS y exfiltración */
bool SendHttpsPost(const RemoteEndpoint *ep, const wchar_t *verb,
                   const wchar_t *path, uint16_t port,
                   const ByteBuffer *request, ByteBuffer *response);

/* CAP 7 — Serialización de solicitudes HTTP */
bool       RefreshRuntimeConfig(RuntimeContext *ctx, RuntimeConfig *cfg);
bool       SerializeAndSubmitHttpJob(RuntimeContext *ctx, const MessageBatch *batch);
bool       ParseAndApplyConfig(ByteBuffer cfg_blob, RuntimeConfig *cfg);
ByteBuffer SerializeMessageBatch(const MessageBatch *batch);
ByteBuffer PackVariant(uint8_t type, uint64_t len, const ByteBuffer payload);
void       XorBufferInPlace(ByteBuffer buf, uint8_t key);

/* CAP 8 — Clipper de wallets */
void ClipboardReplacementWorker(RuntimeContext *ctx);

/* CAP 9 — Descarga y ejecución secundaria */
void ProcessDownloadTasks(const TaskList *tasks, Channel *channel);

/* CAP 10 — Captura de pantalla */
void CaptureScreenAndQueue(Channel *channel);

/* CAP 11 — Inventario de registro */
void CollectRegistryValues(const RegistryQueryList *list, Channel *channel);

/* CAP 12 — Robo de datos de aplicaciones */
void CollectApplicationArtifacts(const AppTargetList *apps, Channel *channel);

/* CAP 13 — Robo de artefactos Chromium */
void CollectChromiumArtifacts(Channel *channel);

/* CAP 14 — Robo de artefactos Firefox */
void CollectFirefoxArtifacts(Channel *channel);

/* CAP 15 — Cola interna de resultados */
void QueueTypedMessage(Channel *queue, MessageKind kind, ByteBuffer payload);
void ControllerDrainAndSend(Channel *queue, RuntimeContext *ctx);

/* Estado de vida global de los workers (definido en CAP 3). */
extern volatile bool g_worker_running;

#endif /* RECONSTRUCCION_TIPOS_COMUNES_H */
