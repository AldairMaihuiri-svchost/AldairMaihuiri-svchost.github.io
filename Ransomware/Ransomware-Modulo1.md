---
title: "Ransomware Red Teaming — Módulo 1: Introducción"
description: "Conceptos, casos documentados, arquitectura general y entorno de análisis para el curso."
author: Aldair Maihuiri
---

# Módulo 01 — Introducción al curso de ransomware (Red Team)

Este curso examina la arquitectura de familias reales, la reproducción controlada de ciertos comportamientos con datos de prueba y su análisis para detección y mitigación. Los nombres de componentes que aparecen en este capítulo describen funciones observables; no todas las familias emplean la misma estructura ni el mismo esquema criptográfico.

## 1.1 ¿Qué es el ransomware?

El ransomware es software malicioso empleado para exigir un pago mediante la interrupción del acceso a datos o sistemas. El cifrado de archivos es una forma común de producir ese efecto. En campañas de extorsión relacionadas también se amenaza con publicar datos robados, con o sin cifrado en el incidente estudiado. Conviene distinguir el **programa** que bloquea datos, la **operación** que compromete una organización y la **extorsión** que aprovecha el acceso obtenido. [CISA: Ransomware Guide](https://www.cisa.gov/stopransomware/ransomware-guide).

La enumeración de archivos, el robo de información, la interferencia con la recuperación y la nota de rescate son comportamientos posibles. Ninguno de ellos, por sí solo, define todas las muestras. Tampoco existe un algoritmo de cifrado único para todo el ransomware.

### Familias reales de referencia

| Familia o variante | Referencia temporal | Aspecto documentado | Fuente |
| --- | --- | --- | --- |
| WannaCry / WannaCrypt | Brote de 2017 | Propagación mediante una vulnerabilidad SMB corregida previamente | [Microsoft Security](https://www.microsoft.com/en-us/security/blog/2017/05/12/wannacrypt-ransomware-worm-targets-out-of-date-systems/) |
| REvil / Sodinokibi | Análisis de 2020 | Operación RaaS y uso de Curve25519, Salsa20 y otros componentes en las muestras estudiadas | [Intel 471](https://www.intel471.com/blog/revil-ransomware-as-a-service-an-analysis-of-a-ransomware-affiliate-operation) |
| Conti | Variantes analizadas desde 2020 | Evolución del mecanismo de cifrado entre muestras y protección de material mediante RSA | [SentinelLabs](https://www.sentinelone.com/labs/conti-unpacked-understanding-ransomware-development-as-a-response-to-detection/) |
| LockBit 3.0 | Aparición en 2022 | Variante de una operación RaaS con afiliados | [CISA y socios](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-165a) |
| BlackCat / ALPHV | Identificado desde 2021 | Familia escrita en Rust y ofrecida mediante RaaS | [MITRE ATT&CK](https://attack.mitre.org/software/S1068/) |
| Akira | Aviso actualizado en 2025 | En las muestras descritas, esquema híbrido que combina ChaCha20 y RSA; las variantes pueden diferir | [FBI y socios, aviso conjunto](https://www.fbi.gov/file-repository/cyber-alerts/stopransomware-akira-ransomware.pdf) |
| Jigsaw | Documentado en 2016 | Cuenta regresiva, borrado periódico de archivos cifrados y amenaza asociada al reinicio en las variantes estudiadas | [ESET, análisis de 2016](https://www.welivesecurity.com/la-es/2016/04/15/jigsaw-ransomware-mas-agresivo-nuevas-capacidades/) |
| AvosLocker | Identificado en 2021; aviso actualizado en 2023 | Operación RaaS con incidentes en Windows, Linux y entornos VMware ESXi | [FBI y CISA, AA23-284A](https://www.cisa.gov/sites/default/files/2023-10/aa23-284a-joint-csa-stopransomware-avoslocker-ransomware-update.pdf) |
| EvilQuest / ThiefQuest | Analizado desde 2020 | Malware para macOS que reúne cifrado, exfiltración y espionaje | [SentinelLabs, investigación](https://www.sentinelone.com/blog/evilquest-a-new-macos-malware-rolls-ransomware-spyware-and-data-theft-into-one/) |

La columna temporal indica un brote, una aparición o la fecha de un análisis, según la fila; **no** establece el periodo completo de actividad. Del mismo modo, la descripción de una muestra no debe extenderse automáticamente a todas las variantes de su familia.

### Tres casos para estudiar el impacto y la respuesta

#### Jigsaw: una cuenta regresiva que busca gobernar la decisión

Jigsaw merece atención por algo más que el cifrado. Los análisis de 2016 describen una ventana con la imagen de *Saw*, un contador visible y el borrado de archivos cifrados por intervalos si no se paga. ESET observó además una amenaza asociada a detener el proceso o reiniciar el equipo. Esta combinación hace que cada minuto parezca costoso y presenta acciones habituales de contención como si fueran peligrosas. Son comportamientos documentados para las variantes analizadas; no son reglas de todo ransomware llamado Jigsaw. [ESET](https://www.welivesecurity.com/la-es/2016/04/15/jigsaw-ransomware-mas-agresivo-nuevas-capacidades/) · [Check Point Research](https://blog.checkpoint.com/research/jigsaw-ransomware-decryption/).

El mecanismo de coacción se entiende en tres planos. **Urgencia:** el contador reduce el tiempo que la persona cree tener para comprobar lo ocurrido. **Pérdida progresiva:** la posibilidad de que desaparezcan archivos antes de terminar la evaluación convierte la espera en una fuente de angustia. **Temor a intervenir:** la advertencia sobre el reinicio intenta desalentar la búsqueda de ayuda y las medidas de contención. La imagen de terror refuerza el tono amenazante, pero el núcleo del caso es la relación entre tiempo, pérdida y decisión bajo presión. Esta lectura describe la intención aparente del mensaje; no permite medir por sí sola lo que sintió cada víctima.

Para una persona, la amenaza puede recaer sobre fotografías, trabajo o documentos cuyo valor no se expresa en dinero. En una empresa, el mismo recurso puede precipitar decisiones antes de verificar copias, alcance y continuidad del servicio: el equipo de respuesta trabaja mientras responsables de negocio y personas afectadas exigen certezas que todavía no existen. El daño observado en un caso concreto requiere evidencia; aquí se explica **por qué** la interfaz y las amenazas buscan influir en el comportamiento humano. Una cuenta regresiva en pantalla tampoco demuestra que el atacante pueda cumplir todas sus promesas.

La tecnología cambia: un caso posterior puede presionar con publicación de datos, interrupción de servicios o contacto con terceros en vez de borrar archivos cada hora. Lo que persiste es el intento de trasladar el control de la decisión al atacante mediante urgencia, incertidumbre y temor a una pérdida mayor. Las capas de presión pueden acumularse; por eso el análisis defensivo debe separar el estado técnico verificable de lo que afirma la nota de rescate, preservar evidencia y coordinar la respuesta antes de convertir una amenaza en un hecho supuesto. La existencia de herramientas de recuperación para **algunas** variantes de Jigsaw ilustra por qué conviene comprobar la muestra específica. [Check Point Research](https://blog.checkpoint.com/research/jigsaw-ransomware-decryption/) · [CISA, guía de respuesta](https://www.cisa.gov/stopransomware/ransomware-guide).

#### AvosLocker: una operación más amplia que el ejecutable

AvosLocker permite estudiar la distancia entre una **familia de malware** y una **operación con afiliados**. El aviso conjunto del FBI y CISA, actualizado el 11 de octubre de 2023 con hallazgos de investigaciones hasta mayo de ese año, reúne indicadores, tácticas, técnicas y métodos de detección. Describe compromisos en sectores de infraestructura crítica y en entornos Windows, Linux y VMware ESXi. Ese alcance importa porque un incidente puede afectar estaciones y también la capa que sostiene múltiples máquinas virtuales. [FBI y CISA, AA23-284A](https://www.cisa.gov/sites/default/files/2023-10/aa23-284a-joint-csa-stopransomware-avoslocker-ransomware-update.pdf).

En una muestra Linux examinada por VMware, el componente dirigido a ESXi detenía máquinas virtuales antes del cifrado y empleaba Salsa20 y RSA. Son detalles de **esa variante**, no una receta universal de AvosLocker. El caso enseña a correlacionar señales de acceso, uso de herramientas, afectación de hipervisores y extorsión, sin reducir toda la investigación a identificar el archivo cifrador. Para la defensa, el aviso actualizado es un punto de partida fechado: los indicadores concretos se contrastan con la evidencia del entorno y no se asumen vigentes para cualquier incidente futuro. [VMware Threat Research](https://blogs.vmware.com/security/2022/09/esxi-targeting-ransomware-the-threats-that-are-after-your-virtual-machines-part-1.html).

#### EvilQuest: cuando el rescate no explica todo el daño

EvilQuest, también llamado ThiefQuest, muestra por qué el nombre de una familia no agota sus capacidades. Los investigadores observaron en macOS cifrado de archivos, búsqueda y salida de datos, y funciones de *keylogging*. La ventana de alerta podía cerrarse mientras el equipo seguía en uso: recuperar el acceso a un archivo no bastaría para descartar exposición de datos o credenciales. [SentinelOne, análisis de capacidades](https://www.sentinelone.com/blog/evilquest-a-new-macos-malware-rolls-ransomware-spyware-and-data-theft-into-one/).

Su rutina de cifrado también es un caso útil para estudiar límites de una implementación. SentinelLabs encontró una construcción propia, en parte relacionada con RC2 y sin el esquema de clave pública que se esperaría en muchas familias; publicó una herramienta de descifrado para las muestras investigadas. Esa posibilidad de recuperación no elimina la necesidad de investigar el espionaje y la posible extracción de información. El punto analítico es doble: **ni todo cifrador sigue la misma arquitectura, ni resolver el cifrado resuelve automáticamente el incidente**. [SentinelLabs, análisis de la rutina](https://www.sentinelone.com/labs/breaking-evilquest-reversing-a-custom-macos-ransomware-file-encryption-routine/).

### Cómo evolucionó la extorsión

Una cronología útil distingue **observaciones fechadas** de **fechas de invención**. La expansión de RaaS, el robo de datos, el cifrado parcial y los objetivos de virtualización se solaparon; no nacieron todos en años sucesivos. Como referencias concretas: CISA documentó afectación de máquinas ESXi por BlackMatter en 2021, y el aviso sobre Cl0p/MOVEit de 2023 describe el uso de una vulnerabilidad para sustraer datos de MOVEit Transfer. [CISA: BlackMatter](https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-291a) · [CISA: Cl0p/MOVEit](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-158a).

**Por qué importa distinguir cifrado y filtración:** una copia de seguridad puede permitir restaurar datos, pero no deshace la exposición de información sustraída. A su vez, no toda filtración implica una multa automática. En la Unión Europea, el artículo 83 del GDPR establece límites máximos y criterios para determinadas infracciones; la autoridad competente evalúa cada caso. [GDPR, artículo 83](https://eur-lex.europa.eu/eli/reg/2016/679/oj/eng).

## 1.2 Consideraciones legales y éticas

### Marco legal y autorización

La calificación jurídica depende de los hechos, la jurisdicción, la finalidad y la existencia de autorización. No corresponde asignar una pena única a «desarrollar, poseer o usar» una herramienta. En Perú, la [Ley N.° 30096 y sus modificatorias](https://www.gob.pe/institucion/congreso-de-la-republica/normas-legales/239569-30096) abordan delitos que afectan datos y sistemas informáticos. Para un ejercicio profesional, se debe definir por escrito el alcance autorizado, las máquinas, los datos, la duración y las condiciones de cierre.

Como comparación internacional, el [Código Penal español, artículos 264 y siguientes](https://www.boe.es/buscar/act.php?id=BOE-A-1995-25444) distingue daño a datos, obstaculización de sistemas y conductas relacionadas; el [Computer Misuse Act británico](https://www.legislation.gov.uk/ukpga/1990/18/contents) contiene tipos distintos. Las sanciones dependen del supuesto aplicable. Estos textos sirven para orientar la lectura del marco legal, no para sustituir una evaluación del caso concreto.

### Uso del conocimiento en el curso

- **Red Team:** comprender componentes y documentar pruebas autorizadas.
- **Análisis de malware:** observar muestras, extraer indicadores y explicar su comportamiento.
- **Defensa:** contrastar señales con controles de detección y recuperación.
- **Laboratorio académico:** trabajar con máquinas y datos preparados para el ejercicio.

### Reglas del laboratorio

| Aspecto | Condición de trabajo |
| --- | --- |
| Datos | Usar exclusivamente archivos de prueba creados para el curso y conservar originales verificables |
| Alcance | Identificar por escrito las VM y carpetas del ejercicio antes de ejecutarlo |
| Red | Especificar si una VM está desconectada o pertenece a una red virtual; comprobar la conectividad real |
| Recuperación | Disponer de una instantánea y de copias independientes de los datos de prueba |
| Evidencia | Registrar la muestra, versión, hora, resultados y límites de la observación |

**Una red `host-only` no equivale a desconectar el adaptador.** Puede permitir comunicación con el anfitrión y con otras VM de esa red. Cuando una práctica necesite intercambio entre dos VM, se documentará esa topología y se verificará qué sistemas pueden comunicarse. Una instantánea ayuda a restaurar una VM, pero no reemplaza la copia de los archivos originales.

### Entorno de análisis

```text
Equipo anfitrión: sistema de trabajo y copias de los datos de prueba
VM principal: Windows con soporte vigente para las prácticas actuales
VM adicional: solo cuando el ejercicio requiera observar otro sistema
Carpeta de laboratorio: datos creados expresamente para cada práctica
Herramientas: monitor de procesos, depurador y capturas según el objetivo
```

Windows 10 terminó su soporte general el 14 de octubre de 2025; puede conservarse como objetivo heredado de análisis cuando el ejercicio lo exija, con las condiciones de aislamiento correspondientes. [Microsoft: Windows 10 release information](https://learn.microsoft.com/en-us/windows/release-health/release-information).

## 1.3 Arquitectura general

En algunas familias se distinguen tres funciones. Pueden implementarse como programas separados o estar organizadas de otra manera; el esquema sirve para reconocer responsabilidades al analizar una muestra.

| Función | Pregunta que responde el análisis |
| --- | --- |
| **Builder** o configuración | ¿Qué parámetros se incorporaron a la muestra examinada? |
| **Componente de impacto** o *locker* | ¿Qué recursos observa o modifica durante la ejecución? |
| **Herramienta de recuperación** o *decryptor* | ¿Qué material y metadatos necesita para invertir el efecto? |

La operación completa puede incluir acceso inicial, ejecución, selección de datos, impacto y extorsión; no todo ello forma parte del mismo binario. La relación entre grupo, desarrollador y afiliado tampoco se deduce de tres nombres de componentes. En una investigación se debe separar lo que **hizo la muestra** de lo que **se atribuye a una campaña**.

La documentación del curso seguirá esta división: los algoritmos se estudian en el Módulo 2; la generación y el ciclo de vida de claves, en el Módulo 3; la enumeración de entradas, en el Módulo 4. Más adelante se examinarán el formato de metadatos, la reconstrucción y las señales de detección. Así, esta introducción no presupone que todas las familias generan un par efímero al inicio ni que conservan la misma información en cada archivo.

> **Qué puede inferirse de un binario capturado:** la presencia de una clave pública no implica que la privada esté disponible en él. Tampoco prueba, por sí sola, que el proceso inverso sea imposible: el resultado depende de la implementación, del material expuesto durante la ejecución y de otras fuentes de recuperación. En 2024, las autoridades obtuvieron claves de infraestructura incautada de LockBit para ayudar a víctimas. [Departamento de Justicia de EE. UU.](https://www.justice.gov/archives/opa/pr/us-and-uk-disrupt-lockbit-ransomware-variant).

## 1.4 Esquemas criptográficos: vista general

Un esquema híbrido combina un mecanismo adecuado para procesar datos con otro destinado a establecer o proteger el material de clave. En el curso aparecen **dos caminos conceptuales**:

| Camino | Papel del mecanismo asimétrico | Relación con la clave de trabajo |
| --- | --- | --- |
| RSA-OAEP | Cifrar un valor corto mediante una clave pública | El titular de la privada correspondiente puede recuperarlo, según el protocolo definido |
| ECDH + KDF | Establecer un secreto compartido entre dos pares | Una KDF deriva material de trabajo a partir del acuerdo y sus parámetros |

ECDH **no cifra directamente** la clave de un archivo. El Módulo 3 desarrolla por separado ECDH efímero por entrada y ECDH por sesión con derivación por entrada. En ambos casos hay que identificar qué valores son secretos, cuáles son públicos y qué parámetros se requieren para reproducir una derivación. El formato definitivo de esos metadatos corresponde al módulo de footer.

RSA tampoco es un modo adecuado para procesar por sí solo un archivo grande. RFC 8017 fija para RSAES-OAEP el límite `mLen ≤ k − 2hLen − 2`; con RSA-2048 (`k = 256` bytes) y SHA-256 (`hLen = 32` bytes), el máximo es **190 bytes por operación**. Esta cifra depende del esquema y del hash; no debe confundirse con límites de otros rellenos. [RFC 8017, sección 7.1.1](https://www.rfc-editor.org/rfc/rfc8017.html#section-7.1.1).

El rendimiento del tratamiento de datos depende de hardware, tamaño de archivo, modo y biblioteca; cifras de GB/s solo tienen sentido junto con un método de medición. AES-CBC, AES-CTR y ChaCha20-Poly1305 también tienen reglas diferentes para IV, nonce, integridad y autenticación. El Módulo 2 trata esos algoritmos; el Módulo 3 separa claves, acuerdos y parámetros de derivación.

## 1.5 C y Rust en el curso

Ambos lenguajes permiten estudiar interfaces del sistema y bibliotecas criptográficas. La elección afecta al modo de gestionar memoria, dependencias y llamadas externas, pero **no cambia las propiedades matemáticas** de RSA, ECDH o HKDF.

| Aspecto | C | Rust |
| --- | --- | --- |
| Gestión de memoria | Requiere disciplina explícita del programador | El código seguro aporta garantías; `unsafe` y FFI requieren revisión |
| Interoperabilidad con Windows | Mediante encabezados y bibliotecas de la plataforma | Mediante enlaces o bibliotecas que exponen las API de Windows |
| Dependencias | Compilador, encabezados y bibliotecas elegidas | Toolchain y dependencias declaradas por proyecto |
| Rendimiento y tamaño | Dependen de implementación y opciones de compilación | También dependen de implementación y opciones de compilación |
| Análisis de binarios | Influyen compilador y optimizaciones | También influyen compilador y optimizaciones |

En este módulo introductorio basta con comprobar las herramientas instaladas. Los comandos de construcción, las versiones de dependencias y los ejemplos completos se documentarán junto al ejercicio que los utilice, con un sistema operativo y un proyecto de prueba especificados.

```sh
rustc --version
cargo --version
x86_64-w64-mingw32-gcc --version
```

La última línea aplica solo si se eligió esa cadena de compilación cruzada. No constituye un requisito para todos los equipos ni instala dependencias.

## 1.6 Herramientas del entorno de análisis

| Herramienta | Uso en una práctica documentada |
| --- | --- |
| Process Monitor (ProcMon) | Observar operaciones sobre procesos, archivos y registro |
| Administrador de tareas u otra herramienta de procesos | Consultar procesos, hilos y recursos visibles |
| x64dbg y Ghidra | Analizar un binario de laboratorio a nivel dinámico y estático |
| Wireshark | Observar el tráfico de la red virtual cuando esa práctica lo requiera |
| Autoruns | Revisar puntos de inicio automático cuando el caso los incluya |

Una herramienta indica lo que **observó en una configuración concreta**. La ausencia de tráfico en una captura no demuestra por sí sola que una familia nunca utilice red; la ausencia de un artefacto de persistencia tampoco establece que todas sus variantes carezcan de él. La muestra, el entorno y la ventana de observación forman parte del resultado.

## Resumen Módulo 01

- Ransomware, operación de intrusión y extorsión relacionada son conceptos conectados, pero distintos.
- Las familias cambian entre variantes; una tabla técnica debe identificar su fuente y alcance.
- Jigsaw muestra cómo una amenaza de pérdida creciente y un contador pueden presionar a la víctima; ese patrón humano reaparece bajo otras formas de extorsión.
- AvosLocker ilustra el alcance de una operación con afiliados y afectación de entornos virtualizados; EvilQuest obliga a investigar robo de datos y espionaje aun cuando se pueda recuperar el cifrado.
- El cifrado simétrico procesa datos; RSA-OAEP y ECDH + KDF cumplen funciones diferentes respecto del material de clave.
- Las funciones de configuración, impacto y recuperación ayudan a organizar el análisis sin imponer una estructura universal.
- Una práctica necesita entradas conocidas, alcance autorizado, topología de red explícita y evidencia reproducible.

Xtra:

- ¿por qué el cifrado híbrido (AES + RSA/ECDH) es superior a usar únicamente RSA o únicamente AES en un ransomware. ¿Qué problema concreto resuelve cada algoritmo y qué pasaría si eliminaras uno de los dos.?
- En el flujo del locker, ¿por qué se cifra primero la file_key con la master_pubkey y no al revés? ¿Qué implicaciones de seguridad tendría invertir el orden?
- identifique diferencias entre WannaCry (2017) , LockBit 3.0 (2022) , Jigsaw (2016) en términos de:
Vector de propagación
Algoritmos criptográficos usados
Modelo de negocio (¿RaaS o no?)
Velocidad de cifrado

**Siguiente**: Módulo 02 — Algoritmos criptográficos (AES, ChaCha20, RSA, ECDH)

---

© 2026 Aldair Maihuiri. Todos los derechos reservados. Se permite compartir con atribución al autor. La reproducción sin autorización previa está prohibida.
