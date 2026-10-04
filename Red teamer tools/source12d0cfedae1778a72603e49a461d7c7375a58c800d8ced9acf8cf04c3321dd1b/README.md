# Reconstrucción en C — 15 capacidades

Loader configurable + infostealer + clipper de criptomonedas. Reconstrucción
analítica en C separada en un archivo por capacidad, limpia y coherente entre
sí (tipos y prototipos compartidos en `00_tipos_comunes.h`).

SHA-256 muestra: `12d0cfedae1778a72603e49a461d7c7375a58c800d8ced9acf8cf04c3321dd1b`
PE x64 con DLL interna reconstruida (MD5 `71589459b8c1f7444cb6955d051d2e57`)

## Índice de las 15 capacidades

| Archivo | Capacidad | Función C | Dirección | Nodo | Confianza |
|---|---|---|---|---|---|
| `01_decodificacion_lz_blobs.c` | Decodificación y LZ de blobs | `DecodeAndExpandBlob` | `0x14000738d` | N1 | Alta |
| `02_reconstruccion_pe_inyeccion_dll.c` | Reconstrucción PE e inyección DLL | `LaunchInternalDllInRemoteProcess` | `0x14000a73d` | N1 | Alta |
| `03_inicializacion_controlador.c` | Inicialización y creación de controlador | `MalwareDllMain` | `0x18001bf79` | N2 | Alta |
| `04_orquestacion_red_workers.c` | Orquestación de red y workers | `ControllerMain` | `0x180057ace` | N2/N3 | Alta |
| `05_anti_vm_sandbox.c` | Anti VM y anti sandbox | `IsVirtualizedOrSandboxed` | `0x180047f22` | N2 | Media |
| `06_c2_https_exfiltracion.c` | C2 HTTPS y exfiltración | `SendHttpsPost` | `0x180009d00` | N3/N5 | Alta |
| `07_serializacion_http.c` | Serialización de solicitudes HTTP | `SerializeAndSubmitHttpJob` | `0x1800248a7` | N3/N5 | Alta |
| `08_clipper_wallets.c` | Clipper de wallets | `ClipboardReplacementWorker` | `0x18001e022` | N4 | Alta |
| `09_descarga_ejecucion.c` | Descarga y ejecución secundaria | `ProcessDownloadTasks` | `0x18001c54f` | N4 | Alta |
| `10_captura_pantalla.c` | Captura de pantalla | `CaptureScreenAndQueue` | `0x1800310c5` | N4 | Alta |
| `11_inventario_registro.c` | Inventario de registro | `CollectRegistryValues` | `0x1800226d` | N4 | Media |
| `12_robo_apps.c` | Robo de datos de aplicaciones | `CollectApplicationArtifacts` | `0x18003bb9c` | N4 | Media-alta |
| `13_robo_chromium.c` | Robo de artefactos Chromium | `CollectChromiumArtifacts` | `0x18002d2eb` | N4 | Media-alta |
| `14_robo_firefox.c` | Robo de artefactos Firefox | `CollectFirefoxArtifacts` | `0x180007110` | N4 | Media-alta |
| `15_cola_resultados.c` | Cola interna de resultados | `QueueTypedMessage` | `0x18000ecbf` | N5 | Alta |

## Convenciones de reconstrucción

- **`[confirmado]`** = relación observada estáticamente en el binario.
- **`[condicionado]`** = depende de la configuración entregada por el C2.
- Las API "peligrosas" se describen como **pasos de comportamiento**, no como
  invocaciones reutilizables listas para su uso.
- Los buffers, direcciones y valores del C2 se representan con tipos abstractos.
- Las capacidades **1 y 2** (loader) están ancladas al decompilado real
  (`decompile.c`, direcciones `0x140xxxxxx`), con el alfabeto, las claves de
  blob y el algoritmo LZ verificados.
- Las capacidades **3 a 15** (DLL interna, `0x180xxxxxx`) reconstruyen a nivel
  de código el análisis estático ya validado (direcciones, offsets, API y
  formato de mensajes).

## Datos verificados de la muestra

| Indicador | Valor |
|---|---|
| SHA-256 muestra | `12d0cfed…1dd1b` |
| MD5 PE reconstruida | `71589459b8c1f7444cb6955d051d2e57` |
| Alfabeto decodificador (64) | `_VpGTo62f8%:!rYaDg.K30IvE~$*QeRAL\|>-h]#ynw?lZ5dz9<jFJCUOHsSuc1t^` |
| Blob cabeceras | VA `0x14001f590` · 0x1d3 bytes · clave 0x77 |
| Blob secciones | VA `0x140022fb7` · 0x80c61 bytes · clave 0x0e |
| Blob auxiliar | VA `0x140022771` · 0x1a7 bytes · clave 0xe9 |
| XOR respuesta C2 | 0xA2 |
| Límite elemento configuración | 0x400000 |
| Máscara OpenProcess | 0x1FFFFF |
| Etiqueta cola captura | 0x8000000000000004 · tipo de red 0x06 · len64 LE |
| Regla YARA | `../ConfigurableLoaderInfostealer_custom_decoder.yar` |

## Cómo leer los archivos

1. `00_tipos_comunes.h` define los tipos compartidos (buffers, blobs,
   configuración, cola, mensajes) y los prototipos de las 15 capacidades.
2. Cada `NN_*.c` es autocontenido: incluye el encabezado común, define sus
   helpers locales (marcados `static`) y expone la función principal de la
   capacidad.
3. El flujo completo es: `03` (DllMain) → `04` (ControllerMain) → `05` (anti-VM)
   → `07`/`06` (C2/config) → `08..14` (módulos) → `15` (cola y exfiltración).

Documento fuente consolidado: `../Reconstruccion_decompile_limpio_15_capacidades.docx`
y `../Reconstruccion_C_analitica_loader_infostealer_mapa.docx`.
