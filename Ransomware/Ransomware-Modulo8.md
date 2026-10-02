---
title: "Ransomware Red Teaming — Módulo 8: Notas de rescate y comunicación coercitiva"
description: "Análisis de notas, identificadores, canales visuales, evidencia y práctica con registros sintéticos en Windows 11."
author: Aldair Maihuiri
---

# Módulo 08 — Notas de rescate y comunicación coercitiva

Una nota de rescate es un artefacto de comunicación producido durante una operación de extorsión. Puede informar sobre archivos supuestamente cifrados, presentar un identificador, ofrecer una vía de contacto y anunciar plazos o consecuencias. Cada una de esas frases expresa **lo que afirma su emisor**; el documento por sí solo no demuestra que los datos fueron extraídos, que existe una herramienta de recuperación o que un plazo se cumplirá.

El [Módulo 07](Ransomware-Modulo7) distinguió secretos, metadatos públicos y recuperación verificable. Aquí se estudia cómo un mensaje puede referirse a un identificador de sesión sin ser el propio protocolo criptográfico. El [Módulo 04](Ransomware-Modulo4) explicó que descubrir una carpeta no prueba que se procesaran sus archivos; encontrar una nota en ella tampoco demuestra que todos sus archivos fueron transformados. Los [Módulos 05](Ransomware-Modulo5) y [06](Ransomware-Modulo6) aportan los estados de trabajo necesarios para interpretar cuándo se creó cada artefacto.

La práctica analiza **avisos sintéticos** y su relación con evidencias locales. No publica mensajes, no cambia el escritorio y no contacta a nadie. Su objetivo es separar afirmaciones, observaciones e inferencias, además de reconocer errores en ejemplos de código para Windows 11.

## 8.1 Funciones del mensaje y límites de la evidencia

| Elemento observable | Función posible para el emisor | Qué puede comprobar un analista |
| --- | --- | --- |
| Declaración de cifrado | Comunicar un supuesto impacto | Comparar archivos originales y resultados, estados de trabajo y operaciones observadas. |
| ID de sesión o víctima | Vincular mensaje y registro | Comprobar su formato y si coincide con metadatos del ejercicio. |
| Canal de contacto | Proponer una vía de negociación | Registrar literalmente su presencia; no asumir que responde o pertenece a un grupo concreto. |
| Plazo o aumento anunciado | Reducir el tiempo de decisión | Identificar la amenaza y su contexto; no inferir una ejecución automática. |
| Amenaza de publicación | Añadir presión reputacional | Buscar evidencia independiente de extracción o divulgación. |
| Oferta de prueba de recuperación | Intentar establecer credibilidad | Distinguir oferta, prueba recibida y recuperación efectiva de datos autorizados. |
| Instrucciones de no modificar archivos | Condicionar la respuesta | Comprobar si tienen base técnica en el formato observado. |

Estas funciones pueden combinarse o faltar por completo. La ausencia de una nota tampoco demuestra ausencia de transformación: la ejecución pudo interrumpirse antes de crearla, el mensaje pudo guardarse en otra ubicación o el analista pudo no tener acceso al sitio. MITRE ATT&CK documenta la creación de notas y otras modificaciones como posibles observaciones relacionadas con cifrado de datos para impacto; su presencia necesita correlación temporal y técnica. [MITRE ATT&CK T1486](https://attack.mitre.org/techniques/T1486/).

### Presión psicológica: qué analizar

Un plazo, una amenaza de publicación o un mensaje personalizado buscan modificar decisiones bajo incertidumbre. El análisis riguroso describe el **mecanismo de presión** y la evidencia de su uso, sin repetir como hechos las promesas o amenazas del emisor. La presión puede recaer en personal técnico, dirección, atención al público o personas cuyos datos se mencionan. El caso Jigsaw del Módulo 01 permite comparar cómo se representa la pérdida progresiva ante una persona con las amenazas de divulgación o interrupción dirigidas a una organización.

Conviene anotar por separado: destinatario, reclamación, consecuencia anunciada, plazo, dato utilizado para hacerla creíble y respuesta que el mensaje intenta provocar. La forma de coacción puede permanecer reconocible aunque cambien los algoritmos y las plataformas. El documento tampoco debe convertirse en una atribución automática: una plantilla puede copiarse, adaptarse o reutilizarse.

## 8.2 Muestras documentadas y atribución

Al usar una nota de una familia conocida, el módulo publicable debe identificar **fuente, fecha, variante y alcance**. Una transcripción «estilo LockBit» es un ejemplo editorial, no una nota auténtica. CISA y otras agencias han documentado muestras y artefactos de LockBit 3.0; cualquier comparación con una muestra real debe enlazar el informe específico y diferenciar citas, paráfrasis y campos añadidos para enseñanza. [CISA/FBI/MS-ISAC: LockBit 3.0](https://www.cisa.gov/sites/default/files/2023-03/aa23-075a-stop-ransomware-lockbit.pdf).

| Nivel de evidencia | Ejemplo | Conclusión prudente |
| --- | --- | --- |
| Texto coincidente | Una frase o título aparece en dos notas | Coincidencia de texto; puede ser una copia. |
| Formato coincidente | Identificadores y disposición similares | Hipótesis de plantilla común que necesita más muestras. |
| Artefactos corroborados | Nota, archivo, proceso y tiempos vinculados | Esa secuencia ocurrió en el caso observado. |
| Atribución de familia | Coinciden múltiples rasgos técnicos documentados | Atribución con incertidumbre y alternativas expresas. |

Para comparar familias, elegiría dos o tres avisos de informes primarios y construiría una matriz de campos y variantes. No atribuiría sin fuente tasas de pago, preferencias de nombres de archivo ni tácticas exclusivas. Los textos extensos de terceros se resumirían y citarían en lugar de copiarlos enteros.

## 8.3 Identificadores: texto, bytes y correlación

Un `session_id` de 16 bytes puede representarse en hexadecimal o Base64; una pública ECDH serializada de 72 bytes también puede codificarse en Base64. **Son objetos diferentes.** La longitud de la cadena impresa, una vez conocida su codificación, puede ayudar a formular una hipótesis, pero no demuestra por sí sola cuál de los dos se usó. Hay que observar de dónde se obtiene el valor y con qué campo del footer o registro coincide.

| Objeto | Función | Consecuencia de confundirlo |
| --- | --- | --- |
| ID opaco de sesión | Buscar un expediente o vincular registros | Un ID repetido o cambiado puede unir víctimas distintas o dividir una misma sesión. |
| Pública efímera | Repetir un acuerdo con la privada correspondiente | Suponer que es solo un ID puede ocultar una dependencia de reconstrucción. |
| Dirección de contacto | Canal declarado por el emisor | No acredita identidad ni disponibilidad. |
| Huella de una muestra | Distinguir archivos de análisis | No equivale al ID que muestra una nota. |

Una nota que usa un ID creado antes de guardar el footer puede permanecer visible aunque la operación de escritura posterior haya fallado. Por eso el informe ha de registrar la relación **nota ↔ registro ↔ entradas verificadas** y explicitar qué enlaces faltan. El análisis no necesita visitar direcciones incluidas en el mensaje.

## 8.4 Superficies de presentación en Windows 11

**Texto plano.** Un `.txt` puede aparecer en carpetas procesadas, escritorio o una ubicación común. Hay que inspeccionar nombre, contenido, codificación, marcas de tiempo y resultado de escritura. Usar `CREATE_ALWAYS` significa que una ejecución repetida puede sobrescribir una nota anterior. Comprobar que `WriteFile` devolvió éxito y cuántos bytes escribió importa tanto como haber calculado un ID. Una función de formato que devuelve un valor negativo ante truncamiento nunca debe convertirlo sin validación en una longitud de escritura.

**Escritorio.** El fondo puede actuar como aviso visual y como artefacto de investigación. Dibujar en un contexto GDI no crea automáticamente un archivo BMP: la creación, el guardado y la selección de la imagen son pasos distintos. `SystemParametersInfoW(SPI_SETDESKWALLPAPER)` opera sobre una ruta y un contexto de usuario; la apariencia observada puede depender de sesión, política y configuración. Para hallar el escritorio del usuario en código nuevo, Microsoft recomienda `SHGetKnownFolderPath` y `FOLDERID_Desktop`; las API basadas en `CSIDL` permanecen por compatibilidad. [Microsoft: Known Folders](https://learn.microsoft.com/en-us/windows/win32/shell/known-folders); [SystemParametersInfoW](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-systemparametersinfow).

**HTA.** Una aplicación HTML ejecutada por `mshta.exe` es un artefacto diferente de una página HTML estática. Puede incluir scripts y operaciones sobre archivos o registro. El ejemplo con VBScript requiere contexto histórico: Microsoft ha anunciado su retirada y una fase como característica opcional en Windows. Una clase de Windows 11 debe analizar HTA como formato y superficie de ejecución heredados, y usar una vista HTML inerte para mostrar contenido de prueba. No hace falta ejecutarlo para clasificar sus campos. [Microsoft: estado de VBScript](https://learn.microsoft.com/en-us/windows/whats-new/deprecated-features-resources#vbscript).

### Distribución, duplicados y permisos

Una lista de directorios contigua no garantiza deduplicación global. Un programa que solo compara con `lastDir` evita escribir dos veces seguidas en una carpeta, pero no reconoce que se volvió a ella después de otras. Un arreglo fijo para miles de rutas puede agotar la pila y alcanzar su capacidad antes de cubrir el conjunto. Las letras de unidad que devuelve `GetLogicalDrives` tampoco representan todas las rutas UNC o ubicaciones montadas, como se vio en el Módulo 04.

Para analizar distribución, comparar **directorios observados**, **escrituras intentadas**, **escrituras completas** y **notas verificadas**. Un directorio puede rechazar la creación por permisos, desaparecer o estar fuera del alcance autorizado. La cifra de notas no debe presentarse como cifra de archivos afectados.

## 8.5 Laboratorio: mensajes sintéticos y evidencia

El programa siguiente utiliza Python 3 y su biblioteca estándar. Funciona en Windows 11 con `py -3 lab_modulo8.py`. Crea tres registros ficticios en un directorio temporal que se elimina al terminar. Los términos `encryption` y `publication` son **afirmaciones dentro del ejercicio**, no acciones realizadas por el programa. No hay direcciones de contacto ni cambios de interfaz del sistema.

```python
"""Synthetic notice analysis. Writes only inside a temporary directory."""
import json
import tempfile
from pathlib import Path

FIXTURES = [
    {"id": "S-101", "channel": "text", "claims": ["encryption", "publication"],
     "observed": ["notice_found"], "label": "A"},
    {"id": "S-101", "channel": "desktop", "claims": ["encryption"],
     "observed": ["notice_found", "image_file_found"], "label": "B"},
    {"id": "S-202", "channel": "text", "claims": ["publication"],
     "observed": ["notice_found"], "label": "C"},
]

def check(item):
    required = {"id", "channel", "claims", "observed", "label"}
    if set(item) != required or not isinstance(item["id"], str):
        raise ValueError("BAD_SCHEMA")
    if not isinstance(item["claims"], list) or not isinstance(item["observed"], list):
        raise ValueError("BAD_SCHEMA")
    unsupported = sorted(set(item["claims"]) - set(item["observed"]))
    return item["id"], item["channel"], unsupported

with tempfile.TemporaryDirectory(prefix="module8_") as directory:
    root = Path(directory)
    for item in FIXTURES:
        (root / (item["label"] + ".json")).write_text(
            json.dumps(item, ensure_ascii=False), encoding="utf-8")
    for path in sorted(root.glob("*.json")):
        record = json.loads(path.read_text(encoding="utf-8"))
        session, channel, unsupported = check(record)
        print(path.stem, session, channel, "CLAIMS_WITHOUT_LOCAL_PROOF", unsupported)
    changed = json.loads((root / "A.json").read_text(encoding="utf-8"))
    changed.pop("id")
    try:
        check(changed)
    except ValueError as exc:
        print("Incomplete record:", exc)
```

Los registros A y B comparten un ID, pero eso solo establece una coincidencia textual en esta colección. En los tres casos, las afirmaciones sobre cifrado o publicación carecen de prueba local dentro de los registros. El cuarto resultado muestra que, si falta el ID, la correlación se rechaza. El código no pretende detectar malware: enseña a redactar una conclusión proporcional a los datos.

### Variaciones para repetir el experimento

1. Añade un cuarto registro con otro `label` y el ID `S-101`; compara agrupación por ID con agrupación por canal.
2. Sustituye el `id` de B por `S-202`. ¿Qué hipótesis sobre la relación entre A y B deja de sostenerse?
3. Registra por separado un archivo temporal de prueba con un resumen conocido y un campo `observed` verificable; explica por qué una nota, aun coincidente, no sustituye la comparación de datos.
4. Incluye marcas de tiempo ficticias para «nota creada», «entrada examinada» y «resultado verificado». Ordenarlas no autoriza a inventar un evento que no fue observado.

| Caso | Afirmación | Evidencia local | Relación con ID | Límite de la conclusión |
| --- | --- | --- | --- | --- |
| A | Cifrado y publicación | Nota presente | S-101 | No se ha demostrado ni cifrado ni publicación. |
| B | Cifrado | Nota e imagen de prueba presentes | S-101 | Dos avisos pueden referirse al mismo ID sin probar el impacto. |
| C | Publicación | Nota presente | S-202 | La amenaza declarada requiere corroboración externa autorizada. |

## 8.6 Cronología, procedencia y contradicciones

La comunicación no tiene por qué coincidir con el estado técnico de una operación. Para documentar un caso, construir una cronología con tiempos **observados** y su fuente: adquisición de la nota, marca de creación del archivo, registro de intento de escritura, confirmación del resultado, adquisición de una imagen y verificación de una entrada concreta. Conviene guardar zona horaria, resolución del reloj y posible desfase entre equipos. Una marca de tiempo de un archivo copiado puede corresponder a la copia; no debe tratarse automáticamente como la hora de su primera aparición.

| Observación | Interpretación posible | Comprobación pendiente |
| --- | --- | --- |
| Dos notas tienen el mismo ID y distinto texto | Cambió la plantilla, hubo reintento o se reutilizó el ID | Comparar hashes, fechas fiables y metadatos de la sesión. |
| Hay nota en una carpeta sin resultado verificado | Se escribió antes, se abortó después o se omitieron archivos | Revisar estados, errores y cobertura de enumeración. |
| Existe una imagen en disco y no aparece en pantalla | Selección fallida, otra sesión de usuario o política del sistema | Separar creación del archivo de activación visual. |
| La nota afirma que existe una copia externa | Puede ser una amenaza sin extracción comprobada | Correlacionar, con autorización, registros de transferencia y fuentes independientes. |

Una contradicción aparente no se resuelve escogiendo la explicación más llamativa. Por ejemplo, una nota obtenida a las 12:10, un archivo de salida con hora de modificación 12:08 y una captura del escritorio de las 12:14 permiten ordenar **esas tres observaciones**. No prueban cuándo comenzó el trabajo, cuántas entradas terminaron ni si alguien recibió el aviso a las 12:08. En el informe se registran alternativas, evidencia que podría discriminarlas y datos que no estarán disponibles.

El método de adquisición también importa. Conserva una copia de trabajo, su hash, la ruta de origen y el modo de obtención. Para texto, registra bytes, codificación aparente y normalización de saltos de línea; una búsqueda por cadena puede pasar por alto UTF-16 o texto generado dentro de una imagen. Para un HTML o HTA, inspeccionar el archivo estático no equivale a ejecutar scripts. Para una captura, los píxeles muestran lo visible en esa sesión y ese instante, mientras que el archivo subyacente permite examinar propiedades no visibles. Se deben separar contenido, representación y comportamiento.

**Ejercicio de interpretación.** Supón cuatro datos ficticios: A y B comparten `S-101`; B contiene `image_file_found`; una entrada asociada a `S-101` figura solo como `attempted`; y C declara publicación con `S-202`. Redacta dos frases de hallazgo: una sobre coincidencia de identificadores y otra sobre el resultado de la entrada. La primera puede afirmar que A y B muestran el mismo texto de ID. La segunda solo puede afirmar que hay un intento registrado. La declaración de C no aporta evidencia de publicación. Repite el ejercicio cambiando B a `S-202` y observa qué relación deja de estar justificada.

## 8.7 Informe y preguntas Xtra

Una ficha de análisis debe conservar: procedencia, fecha y variante de la muestra; copia y resumen de la nota; codificación; campos extraídos; ubicaciones y tiempos observados; correlaciones con otros artefactos; afirmaciones sin corroborar; y grado de certeza. Describir una técnica de coacción exige atención a quienes reciben el mensaje y a la incertidumbre que introduce, además de leer sus bytes.

## Xtra:

1. ¿Qué relación tendría que demostrar un operador entre el ID de una nota y el material de sesión para evitar asociar la comunicación con otra ejecución?
2. ¿Qué pierde un esquema si publica una nota antes de confirmar el estado de los resultados a los que se refiere?
3. Si la amenaza de divulgar datos aparece en una nota, ¿qué evidencia faltaría para distinguir presión comunicativa de una extracción confirmada?
4. ¿Qué cambia en la interpretación cuando dos notas comparten texto, pero sus identificadores y artefactos técnicos no coinciden?
5. ¿Cómo influye la elección de varios canales visuales en la posibilidad de correlacionar avisos de una misma sesión?
6. ¿Por qué una nota creada en cada carpeta no demuestra que todos los archivos de esas carpetas se procesaron?
7. ¿Qué decisión operativa queda expuesta si una plantilla guarda la pública efímera en vez de un ID opaco?
8. ¿Qué tendría que ocurrir para que un plazo anunciado en el mensaje se reflejara en un cambio verificable del estado de la operación?

## Resumen del módulo 08

Una nota comunica reclamaciones y puede ejercer presión; su presencia no comprueba las reclamaciones. Los identificadores deben relacionarse con el registro y los archivos observados sin confundirlos con claves públicas. En Windows 11, texto, fondos de pantalla y HTA presentan contratos y artefactos distintos. El laboratorio ofrece un método reproducible para separar mensaje, evidencia y límite de inferencia.

## Referencias técnicas

- [MITRE ATT&CK T1486: Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/).
- [CISA/FBI/MS-ISAC: LockBit 3.0](https://www.cisa.gov/sites/default/files/2023-03/aa23-075a-stop-ransomware-lockbit.pdf).
- [Microsoft: Known Folders](https://learn.microsoft.com/en-us/windows/win32/shell/known-folders).
- [Microsoft: SystemParametersInfoW](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-systemparametersinfow).
- [Microsoft: recursos sobre la retirada de VBScript](https://learn.microsoft.com/en-us/windows/whats-new/deprecated-features-resources#vbscript).

© 2026 Aldair Maihuiri. Todos los derechos reservados. Se permite compartir con atribución al autor. La reproducción sin autorización previa está prohibida.
