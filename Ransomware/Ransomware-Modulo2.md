---
title: "Ransomware Red Teaming — Módulo 2: Algoritmos Criptográficos"
description: "AES, ChaCha20-Poly1305, RSA-OAEP, ECDH, HKDF y generación aleatoria: propiedades, límites, análisis de muestras y verificación en laboratorio."
author: Aldair Maihuiri
---

# Módulo 02 — Algoritmos criptográficos

Este módulo estudia las piezas criptográficas que pueden aparecer en un incidente de ransomware. Su objetivo es reconocer qué función cumple cada una, qué datos necesita un análisis para reconstruir el esquema y qué conclusiones pueden sostenerse a partir de una muestra. **Una familia no queda definida por un algoritmo:** distintas versiones, plataformas y configuraciones pueden utilizar construcciones diferentes.

En los ejemplos se distingue entre **primitiva** (AES, ChaCha20, RSA o una operación ECDH), **modo o construcción** (CBC, CTR, ChaCha20-Poly1305, RSA-OAEP) y **protocolo** (cómo se generan, derivan, guardan y recuperan claves y parámetros). Una primitiva correcta dentro de un protocolo incompleto puede dejar archivos irrecuperables o información expuesta.

La documentación de referencia incluye [NIST SP 800-38A](https://csrc.nist.gov/pubs/sp/800/38/a/final), [RFC 8439](https://www.rfc-editor.org/rfc/rfc8439.html), [RFC 8017](https://www.rfc-editor.org/rfc/rfc8017.html), [RFC 7748](https://www.rfc-editor.org/rfc/rfc7748.html) y [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869.html). Los análisis de familias reales se citan junto a cada observación.

## 2.1 Criptografía simétrica — AES

AES es un cifrador de bloques de **128 bits**. AES-256 indica que la clave tiene **256 bits**, no que el bloque mida 256 bits. Para procesar datos de longitud variable se necesita un modo de operación. CBC y CTR resuelven ese problema de formas distintas; por sí solos proporcionan confidencialidad, **no autenticación**. [NIST, FIPS 197](https://csrc.nist.gov/pubs/fips/197/final) · [NIST SP 800-38A](https://csrc.nist.gov/pubs/sp/800/38/a/final).

| Propiedad | AES-256-CBC | AES-256-CTR |
| --- | --- | --- |
| Unidad que procesa AES | Bloques de 16 bytes | Bloques contador de 16 bytes que generan un flujo para combinar con los datos |
| Longitud del dato | Requiere completar el último bloque, por ejemplo con PKCS#7 | Puede tratar una longitud arbitraria sin relleno |
| Parámetro inicial | IV de 16 bytes | Bloque inicial y regla de incremento del contador; el formato debe definirse |
| Condición crítica al reutilizar una clave | El IV debe cumplir las condiciones del modo, incluida la imprevisibilidad para CBC | Ningún bloque contador debe repetirse bajo la misma clave |
| Integridad | No incorporada | No incorporada |
| Descifrado | Requiere la clave y el IV originales, más el tratamiento correcto del relleno | Aplica de nuevo el flujo generado por la misma clave y los mismos bloques contador |

### AES-256-CBC

CBC combina cada bloque de texto claro con el bloque cifrado anterior antes de aplicar AES. El primer bloque utiliza el IV. Por eso, un IV apropiado impide que dos mensajes con el mismo comienzo y la misma clave tengan necesariamente el mismo primer bloque cifrado. El IV **no es una clave secreta**: se conserva junto con los datos necesarios para el descifrado. Su valor debe proceder de un generador criptográfico y cumplir las condiciones del modo. [NIST SP 800-38A](https://csrc.nist.gov/pubs/sp/800/38/a/final).

Con PKCS#7, incluso un mensaje cuya longitud ya es múltiplo de 16 recibe un bloque completo de relleno. El aumento por archivo es de **1 a 16 bytes**, antes de cualquier cabecera o metadato propio de la aplicación. Una implementación puede trabajar por fragmentos y completar el relleno al final: **CBC no exige cargar todo el archivo en memoria** ni conocer desde el principio el tamaño final de cada operación.

El límite que más importa para el análisis es la ausencia de autenticación. Un descifrado que produzca bytes y acepte el relleno no demuestra que el contenido sea auténtico. Tampoco conviene revelar a un tercero diferencias entre errores de relleno y otros errores de procesamiento. Si se estudia una muestra que usa CBC, hay que identificar además si dispone de una protección de integridad separada y cómo se verifica.

**Lectura de un ejemplo Windows CNG:** para interpretar una llamada a `BCryptEncrypt` se comprueban el algoritmo AES, el modo configurado con `BCRYPT_CHAINING_MODE`, la longitud de la clave, el IV, la opción `BCRYPT_BLOCK_PADDING`, el tamaño consultado para la salida y el código de retorno. La API puede modificar el búfer del IV durante el encadenamiento; el IV original debe conservarse si otro proceso necesita repetir la operación. No se puede inferir una implementación correcta observando solo el identificador `BCRYPT_AES_ALGORITHM`. [Microsoft: `BCryptEncrypt`](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptencrypt).

**Comprobaciones con datos de prueba:** longitud cero, 15, 16 y 17 bytes; ida y vuelta con el mismo IV original; rechazo de un búfer de salida demasiado pequeño; manejo de un texto cifrado truncado o alterado. Un resultado inesperado requiere inspeccionar tanto el relleno como el estado de la llamada, no atribuirlo de inmediato a una clave equivocada.

### AES-CTR

CTR cifra bloques contador con AES y combina el flujo resultante con los datos. Por eso el mismo procedimiento transforma texto claro en cifrado y viceversa, y no necesita relleno. La propiedad indispensable es que **ningún bloque contador se repita con la misma clave**, ni dentro de un mensaje ni entre mensajes. Reutilizar el flujo revela relaciones entre los textos claros. CTR tampoco detecta cambios en el texto cifrado. [NIST SP 800-38A](https://csrc.nist.gov/pubs/sp/800/38/a/final).

La expresión «nonce de 12 bytes + contador de 4 bytes» describe **un formato posible**, no la definición universal de AES-CTR. Cada protocolo debe fijar tamaño, orden de bytes, valor inicial, límite de bloques y forma de conservar el bloque inicial. RFC 3686 define una construcción para IPsec con campos propios; citar su contador inicial sin adoptar el resto del formato puede inducir a error. [RFC 3686](https://www.rfc-editor.org/rfc/rfc3686.html).

En CNG puede observarse AES en modo ECB usado **solamente para obtener la salida AES de un bloque contador**. Esa observación no significa que los datos se estén cifrando en ECB: hay que seguir la composición del contador y la combinación de la salida con los datos. Antes de llamar a ese código «CTR», el analista debe comprobar longitud exacta de los campos, unicidad del bloque inicial, detección del desbordamiento y protección de integridad si existe. La combinación manual tiene más lugares donde equivocarse que una construcción suministrada por una biblioteca revisada.

**Comparación con CBC:** CTR permite procesar longitudes arbitrarias; CBC necesita el tratamiento del último bloque. De esa diferencia no se deduce una velocidad fija. El rendimiento depende de instrucciones del procesador, biblioteca, paralelismo, tamaño del fragmento y costo de lectura y escritura.

## 2.2 ChaCha20 y ChaCha20-Poly1305

ChaCha20 es un cifrador de flujo. Su variante IETF utiliza una clave de **32 bytes**, un *nonce* de **12 bytes** y un contador de bloques de 32 bits. El resultado se combina con los datos para cifrar o descifrar. **ChaCha20 solo no autentica los datos.** RFC 8439 especifica las palabras en orden *little-endian* y limita el espacio del contador; una transcripción de palabras enteras a bytes sin definir ese orden no es portable. [RFC 8439, secciones 2.3 y 2.4](https://www.rfc-editor.org/rfc/rfc8439.html).

ChaCha20-Poly1305 añade autenticación: produce texto cifrado y una **etiqueta de 16 bytes**, y puede autenticar datos asociados (AAD) que no se cifran. En la construcción de RFC 8439, un bloque de ChaCha20 sirve para obtener la clave de un solo uso de Poly1305; el flujo destinado a los datos comienza con el contador definido por el estándar. El descifrado debe verificar la etiqueta y rechazar un mensaje modificado. Un bloque de código que solo implemente el *quarter round* y combine bytes con un flujo **no implementa ChaCha20-Poly1305**. [RFC 8439, sección 2.8](https://www.rfc-editor.org/rfc/rfc8439.html).

| Elemento | ChaCha20 | ChaCha20-Poly1305 |
| --- | --- | --- |
| Confidencialidad | Sí, si clave y *nonce* se usan correctamente | Sí |
| Autenticación | No | Sí, mediante etiqueta Poly1305 |
| Tamaño del texto cifrado | Igual al del texto claro | Igual al del texto claro, más la etiqueta si se guarda concatenada |
| Datos asociados | No forma parte de la primitiva | Pueden autenticarse sin cifrarse |
| Reutilización de clave y *nonce* | Repite el flujo | Repite el flujo y la clave de un solo uso del autenticador |

El *nonce* debe ser **único para cada operación bajo la misma clave**. Su generación y control pertenecen al protocolo, no a la función de cifrado aislada. Un *nonce* aleatorio de 96 bits puede evaluarse para un número acotado de usos, pero escribir «se genera al azar» sin especificar cuántos mensajes comparten clave ni cómo se evitan colisiones deja incompleta la explicación. Si hay una clave distinta por archivo, ese supuesto debe constar expresamente. [RFC 8439, consideraciones de seguridad](https://www.rfc-editor.org/rfc/rfc8439.html).

**Lectura de un ejemplo Rust con la biblioteca `chacha20poly1305`:** la operación `encrypt` entrega los bytes cifrados junto con la etiqueta según la interfaz de la biblioteca; `decrypt` comprueba esa etiqueta y comunica un fallo si no coincide. Para interpretar una muestra o un formato de laboratorio se documentan la clave, el *nonce*, los AAD cuando existan, el orden de los campos y dónde se conserva la etiqueta. El *footer* que solo enumerase «clave pública + nonce» estaría incompleto si el texto cifrado no incluyera la etiqueta en otro lugar. [Documentación de `chacha20poly1305`](https://docs.rs/chacha20poly1305/latest/chacha20poly1305/).

**Qué se ha observado:** SentinelLabs documentó que BlackCat/ALPHV admite configuraciones con **AES y ChaCha20**, y otro análisis describió una elección relacionada con la disponibilidad de aceleración AES en la plataforma examinada. Eso no prueba que todas sus variantes utilicen ChaCha20-Poly1305 ni permite atribuir el mismo criterio a Akira. Un análisis de Akira documenta ChaCha20 y protección de claves mediante RSA en determinadas muestras; hay que distinguir ChaCha20 de la construcción autenticada completa. [SentinelLabs: BlackCat](https://www.sentinelone.com/labs/blackcat-ransomware-highly-configurable-rust-driven-raas-on-the-prowl-for-victims/) · [SentinelLabs: selección observada](https://www.sentinelone.com/labs/crimeware-trends-ransomware-developers-turn-to-intermittent-encryption-to-evade-detection/) · [Trend Micro: Akira](https://www.trendaisecurity.com/en-us/resources-insights/deep-research/ransomware-spotlight-akira).

ChaCha20 puede rendir bien cuando no hay aceleración AES. La ventaja concreta frente a AES depende de la CPU, de si las instrucciones están disponibles en el entorno virtualizado, de la biblioteca y del tipo de trabajo. La presencia de VMware ESXi o Linux **no demuestra** que AES-NI esté desactivado, y ninguna cifra única de GB/s representa todas esas configuraciones.

## 2.3 RSA — criptografía de clave pública

RSA-OAEP permite cifrar un valor corto con una clave pública para que el titular de la privada correspondiente pueda recuperarlo conforme al protocolo elegido. No procesa por sí solo archivos grandes de forma eficiente. La clave pública, su tamaño, el algoritmo hash de OAEP y cualquier etiqueta opcional forman parte de los parámetros que deben coincidir en ambos extremos.

Para RSAES-OAEP, RFC 8017 fija el límite `mLen ≤ k − 2hLen − 2`. Con una clave RSA de 2048 bits (`k = 256` bytes) y SHA-256 (`hLen = 32` bytes), el máximo es **190 bytes de texto claro por operación**. Una clave simétrica de 32 bytes cabe en ese límite. La salida RSA correspondiente ocupa 256 bytes antes de añadir metadatos. Son cifras de este ejemplo, no de cualquier clave, hash o relleno. [RFC 8017, sección 7.1.1](https://www.rfc-editor.org/rfc/rfc8017.html#section-7.1.1).

| Elemento observado | Pregunta de análisis |
| --- | --- |
| Clave pública o blob CNG | ¿Se conoce su tamaño, exponente, módulo y representación? |
| Parámetros OAEP | ¿Qué hash y qué etiqueta utiliza cada lado? |
| Salida RSA | ¿Protege una clave de datos, un secreto de sesión u otro valor corto? |
| Metadatos asociados | ¿Cómo se identifica la clave o la entrada a la que pertenece? |
| Lado privado | ¿Hay evidencia de dónde se conserva, o solo se observa la parte pública? |

Una estructura `BCRYPT_RSAKEY_BLOB` seguida de exponente y módulo **no es una conversión de PEM a un blob CNG**: esa conversión exigiría analizar el formato de entrada, validar longitudes y construir la representación exigida por la API. Por ello, una simple declaración de estructura se presenta como **descripción de formato**, no como función de importación.

PKCS#1 v1.5 y OAEP son esquemas distintos. Los ataques de tipo Bleichenbacher explotan un oráculo de validez de relleno bajo condiciones concretas; no se debe afirmar que cualquier uso de PKCS#1 v1.5 permita recuperar siempre el texto claro ni que OAEP vuelva imposible todo error de implementación. En un programa de recuperación se evalúan errores, tiempos de respuesta y comprobaciones posteriores como partes de la superficie de análisis. [RFC 8017](https://www.rfc-editor.org/rfc/rfc8017.html).

**Fuerza de seguridad:** el número de bits de una clave RSA no se compara directamente con el de una clave de curva elíptica. NIST estima alrededor de **112 bits** de fuerza para RSA-2048 y **128 bits** para ECC de 256 bits; esa comparación es más informativa que «2048 frente a 256, igual de seguro». [NIST SP 800-57, parte 1](https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final).

## 2.4 ECDH — X25519 y P-256

ECDH es un **acuerdo de secreto**, no una operación que cifre directamente archivos o claves. Cada lado combina su clave privada con la clave pública del otro. Si se usan pares correspondientes y la misma curva, ambos obtienen un secreto compartido del que se deriva material de trabajo. X25519 y ECDH con P-256 tienen formatos e interfaces diferentes; una clave pública de una curva no se interpreta automáticamente como la de la otra. [RFC 7748](https://www.rfc-editor.org/rfc/rfc7748.html) · [Microsoft: acuerdo de claves](https://learn.microsoft.com/en-us/windows/win32/seccrypto/diffie-hellman-keys).

La salida de ECDH debe integrarse en una derivación especificada de extremo a extremo. Una aplicación que aplique SHA-256 al secreto en Rust y `BCRYPT_KDF_HASH` en Windows no ha demostrado compatibilidad: aunque las dos salidas tengan 32 bytes, **sus funciones pueden producir resultados distintos**. `BCRYPT_KDF_HASH` tampoco es sinónimo de HKDF. Cuando una muestra use una KDF concreta, el analista tendrá que reconstruir sus entradas y compararlas con un valor de prueba conocido. [Microsoft: `BCryptDeriveKey`](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptderivekey).

Para X25519, hay que considerar el caso en que un valor público dé lugar a un secreto compartido compuesto íntegramente por ceros. RFC 7748 permite detectar ese resultado y abortar; los protocolos que lo exigen deben verificarlo. Tampoco basta con que una variable privada deje de estar en alcance para afirmar que sus bytes fueron borrados de la memoria: **fin de vida de una variable y borrado verificable son propiedades diferentes**. [RFC 7748, sección 6](https://www.rfc-editor.org/rfc/rfc7748.html#section-6).

### Modelo conceptual con par efímero por entrada

En el curso, **Multi-Master Pattern (MMP)** designa el modelo que se analizará a continuación; el nombre no demuestra que una familia real implemente exactamente este protocolo. El Módulo 3 desarrollará la generación y vida de las claves, y un módulo posterior detallará el formato del *footer*.

| Fase conceptual | Dato o relación que interesa verificar |
| --- | --- |
| Configuración | Existe una clave pública persistente y se conoce la curva y su formato |
| Cada entrada | Se observa un par efímero diferente o evidencia de una derivación diferenciada |
| Acuerdo | La clave privada efímera y la pública persistente producen el secreto que corresponde a esa entrada |
| Derivación | Se identifican KDF, *salt*, contexto y longitud de salida |
| Cifrado | Se registran algoritmo simétrico, IV o *nonce*, etiqueta si existe y relación con los datos |
| Recuperación | El otro lado necesita su clave privada, la pública efímera y todos los parámetros requeridos por el protocolo |

Una clave pública efímera en el *footer* puede ser pública sin revelar por ello el secreto compartido. Sin embargo, **no basta con guardar solo esa clave pública** si el formato también necesita un IV, *nonce*, etiqueta, identificadores o parámetros de derivación. En CNG, la representación exportada de una clave pública P-256 incluye cabecera y coordenadas; no tiene la misma longitud que una clave pública X25519 cruda de 32 bytes. [Microsoft: `BCRYPT_ECCPUBLIC_BLOB`](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptexportkey) · [RFC 7748](https://www.rfc-editor.org/rfc/rfc7748.html).

El acuerdo local con una clave pública ya disponible **puede** realizarse sin tráfico de red durante esa fase. No permite concluir que la intrusión completa haya carecido de comunicaciones: acceso inicial, exfiltración, negociación o distribución de herramientas pueden suceder en otros momentos. Tampoco implica que únicamente una entidad pueda recuperar los datos en todas las circunstancias; copias, fallos de implementación, material hallado durante el incidente o claves incautadas cambian el análisis del caso concreto.

### Par efímero por entrada y secreto por sesión

Un par por entrada separa el material de acuerdo de distintas entradas. Un secreto por sesión puede dar lugar a claves distintas mediante una KDF con contextos únicos, pero la exposición del secreto base puede comprometer todos los valores derivados de él. La diferencia depende de **qué material se expone y cuánto tiempo existe**; no se demuestra la seguridad de un diseño contando pares de claves sin examinar su almacenamiento, derivación, autenticación y recuperación.

## 2.5 HKDF — derivación de material de clave

HKDF, definido en RFC 5869, consta de dos fases: **Extract** toma el material inicial (IKM) y un *salt* y obtiene una clave seudorrandom intermedia (PRK); **Expand** usa esa PRK, información de contexto (`info`) y una longitud solicitada para obtener el material final (OKM). El *salt* y `info` no se tratan como secretos. Cuando no hay *salt*, RFC 5869 especifica un valor de ceros de longitud igual a la salida del hash. [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869.html).

`PRK = HMAC-SHA-256(salt, IKM)`

`T(1) = HMAC-SHA-256(PRK, info || 0x01)`

`T(2) = HMAC-SHA-256(PRK, T(1) || info || 0x02)`

La concatenación de los `T(i)` se trunca a la longitud solicitada. Con SHA-256, el máximo de RFC 5869 es **255 × 32 = 8160 bytes**. Una implementación manual que use un arreglo fijo para `info` debe validar su longitud y cada llamada; un contador de un byte tampoco puede ampliarse indefinidamente. Los [vectores de prueba del apéndice A](https://www.rfc-editor.org/rfc/rfc5869.html#appendix-A) permiten verificar un resultado sin depender de un caso de ransomware.

Derivar, por ejemplo, 32 bytes para una clave y 16 para un IV solo tiene sentido si **todo el protocolo** fija la curva, el formato del secreto, *salt*, `info`, longitudes, relación entre entradas y condiciones de unicidad del IV. La derivación por sí sola no asegura que se cumplan las reglas de CBC, CTR o ChaCha20-Poly1305. También pueden emplearse contextos separados para funciones distintas; los nombres de esos contextos deben coincidir en ambos lados.

La documentación de Windows distingue `BCRYPT_KDF_HASH` y `BCRYPT_KDF_HKDF`. En el caso de `BCryptDeriveKey` sobre un secreto acordado, Microsoft sitúa la compatibilidad con HKDF desde **Windows 10**. Que una API de derivación esté disponible en una versión anterior no significa que esa variante concreta de HKDF también lo esté. [Microsoft: `BCryptDeriveKey`](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptderivekey) · [Microsoft: `BCryptKeyDerivation`](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptkeyderivation).

**Ejercicio de verificación:** con IKM, *salt*, `info` y longitud tomados de un vector de RFC 5869, comparar PRK y OKM byte por byte. Si dos bibliotecas producen valores diferentes, inspeccionar codificación, longitudes y selección de KDF antes de atribuir la diferencia a ECDH.

## 2.6 Generación aleatoria criptográfica (CSPRNG)

La seguridad de claves, IV y *nonces* depende de cómo se obtienen y de las reglas específicas de cada modo. Un generador seudorrandom general, como `rand()` o `Math.random()`, no sustituye una fuente criptográfica para generar claves. Un IV de CBC debe satisfacer el requisito de imprevisibilidad de ese modo; CTR y ChaCha20-Poly1305 exigen, ante todo, que no se repitan las entradas críticas bajo una misma clave.

En Windows, Microsoft recomienda `BCryptGenRandom` con `BCRYPT_USE_SYSTEM_PREFERRED_RNG`. La función devuelve un estado que hay que comprobar **antes de utilizar los bytes**. «Generador preferido del sistema» no fija para todas las versiones un único mecanismo interno ni significa que sea la única API criptográfica apropiada. En Rust, una interfaz al generador del sistema también debe tratar su disponibilidad y los errores de acuerdo con la versión de la biblioteca usada. [Microsoft: `BCryptGenRandom`](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptgenrandom) · [Microsoft SDL: recomendaciones](https://learn.microsoft.com/en-us/security/engineering/cryptographic-recommendations).

| Material | Pregunta antes de usarlo |
| --- | --- |
| Clave simétrica | ¿Proviene de una fuente criptográfica o de una derivación especificada? |
| IV de CBC | ¿Cumple las reglas de imprevisibilidad y se conserva para recuperar el mensaje? |
| Bloque inicial de CTR | ¿Puede repetirse algún bloque contador con la misma clave? |
| *Nonce* de ChaCha20-Poly1305 | ¿Cómo se garantiza que sea único por operación bajo esa clave? |
| Clave privada efímera | ¿Cómo se generó y qué evidencia hay de su ciclo de vida? |

**Caso histórico:** el análisis de Petya de 2016 trata fallos de su propio esquema de clave y de su uso de **Salsa20**, que facilitaron investigaciones y herramientas de recuperación. No constituye una demostración de que Petya sembrara `rand()` con una marca temporal ni de que estuviera atacándose AES. Un caso concreto debe presentarse por el fallo que los investigadores observaron. [Malwarebytes Labs: Petya](https://www.malwarebytes.com/blog/news/2016/04/petya-ransomware) · [Securelist: Petya](https://securelist.com/petya-the-two-in-one-trojan/74609/).

## 2.7 Comparar rendimiento sin cifras aisladas

No hay una cifra universal de GB/s para AES-CTR, AES-CBC o ChaCha20-Poly1305. El rendimiento de la **primitiva en memoria** y el tiempo de **procesar un archivo** miden cosas distintas. En el segundo intervienen lectura, escritura, autenticación, fragmentos, llamadas a bibliotecas y sistema de archivos. El relleno PKCS#7 añade entre 1 y 16 bytes por archivo; por sí solo no explica una diferencia de cientos de MB/s.

Para publicar un *benchmark* reproducible se deben documentar, como mínimo:

1. Modelo de CPU, aceleración AES disponible y si la prueba corre en anfitrión o VM.
2. Sistema operativo, biblioteca, versión, compilador y opciones relevantes.
3. Tamaño y tipo de datos, número de repeticiones y calentamiento.
4. Qué se mide: solo transformación en memoria o también lectura, escritura y autenticación.
5. Métrica y dispersión: tiempo total, mediana, rango y volumen efectivamente procesado.

| Situación | Inferencia razonable | Límite de la inferencia |
| --- | --- | --- |
| AES con aceleración de hardware disponible | Puede rendir muy bien con una implementación adecuada | No se deduce una velocidad específica de la marca de CPU |
| ChaCha20 implementado en software | Puede ofrecer rendimiento competitivo sin instrucciones AES | No siempre superará a AES acelerado |
| Datos almacenados en disco o red | La E/S puede dominar el tiempo total | Una prueba de memoria no representa el incidente completo |
| Variante que cifra solo partes del archivo | Procesa menos bytes que el cifrado completo | No debe compararse su tiempo como si protegiera el mismo volumen |

SentinelLabs documentó en muestras de BlackCat una elección entre AES y ChaCha20 según la aceleración disponible. Es un ejemplo de por qué las mediciones necesitan contexto, no una tabla de velocidades aplicable a todas las familias. [SentinelLabs](https://www.sentinelone.com/labs/crimeware-trends-ransomware-developers-turn-to-intermittent-encryption-to-evade-detection/).

## 2.8 Práctica de verificación y lectura de código

Los siguientes ejercicios emplean **búferes de prueba en memoria**. El objetivo es comprobar propiedades de las construcciones y aprender a leer sus llamadas; ninguna prueba aislada demuestra que una muestra real use el mismo protocolo.

### Experimento A — identificar lo que aporta el IV de CBC

Tomar dos mensajes de prueba cuyo primer bloque sea idéntico, cifrarlos con la misma clave y con **IV diferentes**, y comparar los primeros bloques cifrados. Repetir después con el **mismo IV**. Lo esperado en la segunda prueba es que el primer bloque cifrado sea igual cuando coinciden clave, IV y primer bloque de entrada. El resultado no significa que todo el contenido de ambos mensajes sea idéntico. Registrar IV, longitud de entrada, longitud de salida y política de relleno; usar copias de los IV si la API los modifica durante la operación. [NIST SP 800-38A](https://csrc.nist.gov/pubs/sp/800/38/a/final).

### Experimento B — observar reutilización del flujo en CTR

Con dos secuencias de bytes de prueba y un mismo flujo de CTR, se cumple la identidad `C₁ ⊕ C₂ = P₁ ⊕ P₂`. Esta relación muestra por qué repetir un bloque contador bajo una misma clave expone información sin que sea necesario «romper AES». El ejercicio se limita a la propiedad algebraica y debe terminar con una explicación de qué campos tendría que identificar el analista en un formato real. No confundir esta conclusión con CBC: allí la reutilización de IV tiene efectos diferentes.

### Experimento C — distinguir cifrado de autenticación

Con una biblioteca de ChaCha20-Poly1305, transformar un mensaje corto de prueba, conservar los AAD si se emplean y confirmar que el descifrado devuelve el original. Cambiar después un byte del texto cifrado, de la etiqueta o de los AAD: cada modificación debe producir un fallo de autenticación. En una interfaz que devuelve «texto cifrado + etiqueta» en un solo búfer, registrar el tamaño y verificar dónde se encuentra la etiqueta antes de interpretar el formato. Los vectores de RFC 8439 sirven de referencia independiente. [RFC 8439](https://www.rfc-editor.org/rfc/rfc8439.html).

### Experimento D — verificar HKDF contra un estándar

El **caso de prueba 1** del apéndice A de RFC 5869 usa SHA-256, IKM de 22 bytes `0b`, *salt* `000102030405060708090a0b0c`, `info = f0f1f2f3f4f5f6f7f8f9` y salida de **42 bytes**. La PRK empieza por `077709362c2e32df` y la OKM por `3cb25f25faacd57a`. La comparación debe ser de **todos** los bytes publicados en el RFC, no solo de estos prefijos. Este ejercicio detecta errores de longitud, orden y concatenación en una implementación de HKDF. [RFC 5869, apéndice A.1](https://www.rfc-editor.org/rfc/rfc5869.html#appendix-A.1).

### Qué exigir de un ejemplo en C o Rust

| Aspecto | Comprobación mínima antes de presentarlo como funcional |
| --- | --- |
| Tipo de bloque | Un bloque `c` contiene C; un bloque `rust` contiene Rust; el pseudocódigo se identifica como tal |
| Dependencias | Versiones y características necesarias de la biblioteca indicadas junto al ejemplo |
| Entrada | Tamaños exactos de clave, IV, *nonce* y búfer, y datos de prueba conocidos |
| Salida | Tamaño consultado o esperado, ubicación de etiqueta y metadatos necesarios |
| Errores | Resultados de cada API comprobados y recursos liberados también al fallar |
| Contrato criptográfico | Modo y KDF escritos sin ambigüedad, incluida la unicidad requerida |
| Verificación | Vector publicado y prueba de ida y vuelta, más un caso alterado que debe fallar |

Un fragmento que enumera `BCryptOpenAlgorithmProvider`, `BCryptGenerateSymmetricKey` y `BCryptEncrypt` sin comprobar tamaños, estados y limpieza describe **llamadas**, no una implementación terminada. En Rust, que una función retorne `Vec<u8>` tampoco dice si contiene una etiqueta o cómo informa un error: se consulta el contrato de la biblioteca y se conserva esa información al documentar la muestra. [Microsoft: `BCryptEncrypt`](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptencrypt) · [RustCrypto: `chacha20poly1305`](https://docs.rs/chacha20poly1305/latest/chacha20poly1305/).

## Resumen Módulo 02

| Construcción | Función | Condición que debe comprobarse |
| --- | --- | --- |
| AES-256-CBC | Confidencialidad por bloques con relleno | IV apropiado, longitud y protección de integridad si la aplicación la requiere |
| AES-256-CTR | Confidencialidad mediante bloques contador | Ningún bloque contador repetido bajo la misma clave; integridad separada |
| ChaCha20 | Confidencialidad de flujo | Clave y *nonce* usados sin repetir el flujo |
| ChaCha20-Poly1305 | Cifrado autenticado | *Nonce* único bajo la clave y verificación de la etiqueta |
| RSA-OAEP | Protección de valores cortos con clave pública | Tamaño máximo, hash, etiqueta y clave correspondiente |
| ECDH P-256 / X25519 | Acuerdo de secreto | Curva, formato, validaciones y KDF coincidentes |
| HKDF-SHA256 | Derivación con contexto | IKM, *salt*, `info`, longitud y vectores de prueba |
| CSPRNG | Obtención de material aleatorio criptográfico | Resultado comprobado y reglas de uso del material generado |

El Módulo 3 profundiza en generación, derivación, exposición y vida de las claves. Un módulo posterior examinará el formato del *footer* y la recuperación; ninguno de los dos se deduce solo de elegir un algoritmo.

Xtra:

- **Explica la diferencia entre un cifrado de bloque (AES-CBC) y un cifrado de stream (AES-CTR, ChaCha20). ¿Por qué CBC requiere padding y CTR/ChaCha20 no?**

- **¿Qué pasa exactamente si reutilizas el mismo IV + la misma key en dos archivos distintos con CBC?**

- **¿Qué pasa si reutilizas el mismo nonce + la misma key en ChaCha20-Poly1305?**

- **¿Por qué en ChaCha20 se llama "nonce" y en CBC se llama "IV"? ¿Es solo terminología o hay una diferencia funcional?**

- **En el esquema MMP (Multi-Master Pattern) con ECDH efímero por archivo:**
  - ¿Cuántas claves se generan por archivo?
  - ¿Qué clave se destruye inmediatamente y por qué?
  - ¿Qué se guarda en el footer del archivo y por qué es seguro guardarlo ahí?

- **El módulo dice que el MMP no genera tráfico de red durante el cifrado:**
  - ¿Qué IOCs de red buscaría un EDR/SOC para detectar ransomware si no hay C2 durante el cifrado?
  - ¿Qué otros artefactos (disco, memoria, registro) podrían delatar el comportamiento?
  - ¿Cómo podría un atacante minimizar esos artefactos?


**Siguiente**: Módulo 03 — Algoritmos de generación de claves (master key, session key, per-file key)

---

© 2026 Aldair Maihuiri. Todos los derechos reservados. Se permite compartir con atribución al autor. La reproducción sin autorización previa está prohibida.
