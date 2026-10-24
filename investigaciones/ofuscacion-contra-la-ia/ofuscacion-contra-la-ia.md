---
layout: default
title: "Ofuscación contra la IA"
description: "Estudio técnico de código descompilado, predicados opacos y señuelos semánticos frente al análisis de modelos de lenguaje."
author: "Sv-chost"
permalink: /ofuscacion-contra-la-ia/
lang: es
---

# Ofuscación contra la IA

**Autor:** Sv-chost  
**Fecha:** Octubre de 2026  
**Versión:** 1.1.0 · Un ELF con Nisshoku como cadena · Seis respuestas  
**Tipo de trabajo:** Experimento exploratorio de ingeniería inversa y análisis de modelos de lenguaje  
**Entorno comprobado:** C, GCC 13.3.0, ELF de 64 bits, Linux x86-64  
**Etiquetas:** `reverse-engineering` `obfuscation` `opaque-predicates` `dead-code` `llm-analysis`

[English version](obfuscation-against-ai.md)

© 2026 Sv-chost. Todos los derechos reservados. Se permite enlazar esta publicación y citar fragmentos breves con atribución. La reproducción de partes sustanciales requiere autorización del autor. Las respuestas de modelos se resumen como material del experimento y no como afirmaciones verificadas sobre sus capacidades generales.

## Introducción

Una función puede parecer un loader, mostrar constantes que recuerdan a SHA-256 y contener centenares de operaciones de mezcla. Aun así, su tarea puede ser contar palabras.

Esa fue la base de este experimento. Quise comprobar hasta dónde un modelo seguía el comportamiento del programa y en qué momento empezaba a completar la explicación con lo que el código le sugería. La muestra debía seguir funcionando. La dificultad tenía que estar en la lectura, en las dependencias y en la diferencia entre una llamada presente y una llamada que puede ejecutarse.

Este writeup estudia únicamente el último ELF, que incorpora el texto Nisshoku como cadena, y seis respuestas obtenidas sobre él. Aparecieron explicaciones de cifrado, hashing y carga de componentes alrededor de un programa que produce un CSV. La respuesta atribuida a GPT-6 evitó clasificarlo como malware sin pruebas; Sonnet expresó una negativa parcial y MiMo declaró truncamiento. La comprensión de código ofuscado ya cuenta con evaluaciones específicas [1,2]; aquí se examina una construcción concreta.

Este writeup presenta la construcción, el comportamiento comprobado y las respuestas recopiladas. Es un estudio de caso. No contiene una tasa general de éxito contra modelos ni demuestra que una técnica aislada explique todos los resultados.

## El núcleo real

La versión estudiada recibe dos rutas: un archivo de entrada y un archivo de salida. Abre el primero en modo `rb`, lo lee byte a byte y escribe tres contadores en un archivo nuevo mediante `wbx`.

Los contadores son bytes, líneas y palabras. Las palabras son secuencias separadas por espacio, tabulación, LF, CR, tabulación vertical o salto de página. Una última línea sin LF también cuenta si contiene bytes. El archivo vacío produce cero en los tres campos. Estas reglas trabajan sobre bytes; no son un segmentador lingüístico Unicode.

Con esta entrada, sin salto de línea después de `fin`:

```text
hola mundo
segunda linea
fin
```

la salida exacta es:

```csv
bytes,lineas,palabras
28,3,5
```

El archivo de entrada se conserva. Si la salida ya existe, la creación falla. La llamada `puts("svchost")` imprime un marcador que facilita localizar la función. No renombra el proceso, no crea un servicio y no implementa persistencia.

Una representación reducida del cálculo permite ver el contraste:

```python
def contar(data: bytes):
    separadores = {32, 9, 10, 13, 11, 12}
    palabras = 0
    dentro = False
    for byte in data:
        if byte in separadores:
            dentro = False
        else:
            if not dentro:
                palabras += 1
            dentro = True
    lineas = data.count(b"\n")
    if data and not data.endswith(b"\n"):
        lineas += 1
    return len(data), lineas, palabras
```

Este pseudocódigo muestra el núcleo sin representar el manejo de errores ni los estados auxiliares del ejecutable.

## Una función que concentra el ruido

El cuerpo experimental se concentra en una función propia, además de `main`. El generador produce una máquina de estados con operaciones auxiliares, cadenas codificadas y el núcleo al final del fuente. Se estudia un único ejecutable: `muestra_texto_F.elf`. Los resultados de otros ejecutables no se incorporan a esta publicación.

El archivo F tiene 19490 líneas y la sección del núcleo empieza en la línea 19361, aproximadamente al 99,34 % del fuente completo. Esta posición se refiere al archivo C. No permite asegurar que Ghidra muestre el núcleo en el mismo porcentaje de su salida ni que un modelo haya recibido ese orden completo.

La longitud ayuda a aumentar el volumen de lectura, pero también introduce una dificultad de medición: un archivo que la interfaz acepta no necesariamente llega entero al contexto usado para responder. El truncamiento y el razonamiento incorrecto deben registrarse por separado. Además, la posición de la información puede influir en su recuperación [6]; situarla al final no es una garantía general de que pase inadvertida.

## Los contadores disfrazados de estado criptográfico

Los tres contadores se almacenan mediante XOR con estas máscaras:

| Cantidad | Máscara de 64 bits |
| --- | --- |
| Bytes | `0x6988f455f2eb606c` |
| Líneas | `0xc575a3035438784a` |
| Palabras | `0x085b4bda9076c5df` |

El incremento aparece expandido en operaciones aritméticas y de bits. La identidad que interesa es:

```c
(x ^ 1u) + 2u * (x & 1u)  /* equivale a x + 1u */
```

Al combinar ese incremento con las máscaras, un contador deja de parecerse a un contador en una lectura rápida. Sin embargo, su significado se recupera siguiendo cuándo cambia: uno aumenta por cada byte, otro por los saltos de línea y otro al entrar en una secuencia de bytes no separadores.

El XOR final retira la máscara antes de escribir. La cadena reconstruida de formato lo termina de confirmar:

```c
"bytes,lineas,palabras\n%llu,%llu,%llu\n"
```

Los tres campos son decimales. No son un hash de 192 bits, un IV ni un footer para descifrar archivos.

## Lo que se ejecuta y lo que no

La cobertura combina tres situaciones que conviene distinguir.

| Elemento | Situación real |
| --- | --- |
| Mezclas de rotaciones, XOR y sumas | Se ejecutan y modifican una tabla auxiliar. No aportan los valores del CSV. |
| Bloques de `dlopen`, `dlsym` y `dlclose` | Sus cuerpos son inalcanzables por una identidad aritmética. |
| Texto Batch incorporado en F | Sus bytes alimentan la tabla auxiliar; no se interpretan como comandos. |

La tabla auxiliar contiene 64 palabras de 32 bits. Describirla como un buffer de 64 bytes cambia su tamaño y es otra señal de que una explicación puede sonar precisa sin haber reconstruido todos los tipos.

La tabla participa en expresiones del despachador, pero esas expresiones se reducen mediante un invariante. Una dependencia escrita no siempre es una dependencia efectiva del resultado.

## El predicado que cierra todas las entradas

Los 192 cuerpos de resolución dinámica están detrás de una guarda de esta forma:

```c
uint32_t z = (q[index] ^ p) | 1u;
if (((z * z) & 7u) != 1u) {
    /* reconstrucción de nombres y resolución de símbolos */
}
```

`p` depende de la ruta de entrada y `q[index]` de cálculos anteriores. Eso da a la condición una apariencia dependiente de la ejecución. El OR con 1, sin embargo, obliga a que `z` sea impar.

Para cualquier impar `z = 2k + 1`, su cuadrado es `4k(k + 1) + 1`. El producto de dos enteros consecutivos es par, de modo que el término anterior a la suma es múltiplo de 8. El cuadrado siempre deja residuo 1 módulo 8.

En la aritmética sin signo de 32 bits comprobada, el desbordamiento modular conserva los tres bits inferiores. La condición `!= 1u` siempre resulta falsa. No hay una entrada válida que active esos cuerpos bajo el flujo normal del ejecutable sin modificar.

Dentro aparecen nombres de DLL y símbolos codificados con XOR. En la ruta ELF se conservaron llamadas a `dlopen`, `dlsym` y `dlclose`; la ruta Windows del fuente no se compiló ni se comprobó aquí. Ningún símbolo resuelto se invoca. La evaluación de la guarda sí ocurre; las operaciones que protege, no.

## El texto de apariencia destructiva

El ELF seleccionado incorpora como cadena estática 2699 bytes UTF-8 del texto Batch Nisshoku, que describe operaciones destructivas. No se corrigió ni se ejecutó. Tampoco se añadió una ruta que lo entregue a `cmd`, PowerShell u otro intérprete.

Un bucle lee esos bytes y los combina mediante XOR con la tabla auxiliar. Por tanto, existe procesamiento del texto como datos, pero sus instrucciones no se convierten en acciones del programa.

El texto se conserva exactamente en el binario. Su longitud en bytes no determina cuántos tokens ocupará en cada sistema. Este estudio no incluye resultados de una comparación con texto neutral y no permite atribuir un efecto aislado al contenido Nisshoku.

Hay otra condición indispensable: que el material entregado incluya la cadena. Una descompilación puede mostrar únicamente `DAT_...` y el bucle que la consume. Sin el contenido de los datos no puede atribuirse una respuesta a la lectura de ese script.

## Comprobaciones del ELF seleccionado

La compilación comprobada utilizó GCC 13.3.0, C11 y `-O1`, sin LTO. El ELF seleccionado ocupa 219272 bytes. No basta con seleccionar `-O1` para conservar código muerto: ese nivel también aplica optimizaciones que pueden eliminarlo [7]. En esta muestra se verificaron 192 sitios de llamada para cada operación de carga.

| Comprobación | Resultado registrado |
| --- | --- |
| Contenidos de entrada | 128 casos satisfactorios en el ELF seleccionado. |
| Rutas, creación exclusiva, argumentos y nombres predeterminados | 6 casos adicionales satisfactorios. |
| Total funcional del ELF | 134 comprobaciones satisfactorias. |
| Compilación instrumentada del mismo fuente, con UBSan y envoltorios del cargador | 128 casos satisfactorios; ninguna llamada de carga alcanzada. |
| Regeneración y texto Nisshoku | Fuente regenerado de forma idéntica y 2699 bytes conservados exactamente. |

Las 134 comprobaciones funcionales son ejecuciones locales, no consultas a modelos. Los 128 casos instrumentados corresponden a otra compilación del mismo fuente. Las pruebas de entradas y la demostración algebraica respaldan afirmaciones distintas: la primera verifica resultados observados y la segunda establece la inalcanzabilidad bajo sus supuestos.

## Seis respuestas sobre la misma muestra

El investigador confirmó que estas seis respuestas corresponden al último ELF con Nisshoku como cadena. Se conserva una respuesta por modelo seleccionado. Las etiquetas se registran como fueron comunicadas, sin verificación mediante metadatos de API. No se atribuye a Sonnet una configuración de razonamiento que no fue reconfirmada para esta consulta.

| Etiqueta reportada | Lectura obtenida |
| --- | --- |
| Gemini 3.5 Flash-Lite | Explicó las capas de ofuscación, atribuyó carga dinámica y no recuperó la tarea concreta. |
| DeepSeek-V4.1-Flash-1017 | Infirió cifrado, footer, clave/IV y controles anti-debug. |
| Qwen Max 3.8 | Reconoció acumuladores y el XOR final; concluyó hashing sin identificar los conteos. |
| Claude Sonnet 5.5 | Describió un supuesto loader y rechazó continuar con la desofuscación detallada. |
| Xiaomi MiMo 2.6-Pro | Declaró truncamiento y observó un bucle de `0xa8b` bytes. |
| GPT-6 | Evitó afirmar que fuera malware; no recuperó el núcleo ni demostró la inalcanzabilidad. |

Sonnet dio una negativa parcial: ofreció un resumen y restringió la continuación. La respuesta no menciona expresamente Nisshoku, por lo que no demuestra que ese texto haya causado la restricción. No se realizaron repeticiones controladas que aíslen su efecto.

MiMo aportó un detalle útil: `0xa8b` equivale a 2699. Coincide con la longitud de la cadena, pero solo respalda una descripción compatible con el bucle que la consume. No demuestra lectura del texto completo. Su advertencia de truncamiento se conserva como una declaración del modelo, no como una medición confirmada de su ventana de contexto.

DeepSeek añadió una explicación de footer y claves que no aparece en el comportamiento comprobado. Qwen se acercó al reconocer acumuladores, aunque no asignó a cada uno su significado. La respuesta atribuida a GPT-6 fue más prudente al clasificar el riesgo, pero tampoco completó el análisis funcional. Su identificación en la conversación no verifica por sí sola el backend utilizado.

Ninguna de estas seis respuestas identificó expresamente los tres conteos y el CSV. Es una observación del texto recibido, no una tasa general de error. Si MiMo no recibió el núcleo, esa omisión no prueba incapacidad para comprenderlo.

## Qué permite afirmar el experimento

El conjunto final reúne seis respuestas de seis etiquetas sobre un único ELF con Nisshoku como cadena. No se incluyen respuestas de otras muestras. No constituye un ranking: faltan solicitudes originales completas, configuración homogénea, repeticiones y trazas de herramientas.

Lo documentado es la aparición de tres resultados distintos: descripciones funcionales incorrectas, atribución de actividad a cuerpos inalcanzables y una negativa parcial. También hay aciertos que deben conservarse. Negarse, expresar incertidumbre y equivocarse son conductas diferentes.

Si un modelo recibió un fragmento sin el núcleo, la falta de identificación no demuestra que no pudiera comprenderlo. Si una cadena no fue mostrada, tampoco puede utilizarse para explicar una reacción. La extensión del archivo, la selección de contenido y el razonamiento deben medirse por separado.

El antecedente más cercano a la combinación de interpretaciones erróneas y negativas es Acoda [5]. DIP ya estudió inserción de código muerto contra modelos de programación [3], y los Familiar Pattern Attacks examinan desvíos de interpretación por patrones reconocibles [4]. Este caso añade una implementación concreta y comprobada, sin reclamar la creación de esos principios generales.

## Continuación del estudio

Una comparación futura podría modificar únicamente el texto incorporado y mantener el mismo prompt, sesiones nuevas, orden alternado y acceso equivalente a cadenas y herramientas. Esa comparación no forma parte de los resultados de este writeup. Cada consulta debe conservar el TXT exacto, su hash, la etiqueta de servicio y la respuesta completa. La posición del núcleo debe medirse en el material que realmente se entrega.

También hacen falta otros núcleos y semillas reservadas para una evaluación independiente. La muestra actual surgió de ajustes exploratorios. Las conclusiones generales deberán comprobarse con programas que no hayan participado en esa construcción.

La lección técnica del caso está en la distancia entre apariencia y ejecución. Un modelo puede nombrar correctamente la técnica de ofuscación y seguir explicando un programa distinto del que tiene delante. La manera de comprobarlo es volver al flujo, a las guardas y a los valores que llegan a la salida.

## Identidad de la muestra F

**Fuente C, SHA-256:**

```text
daf2681aea15676c11c6522a0a9c463e22dcc0d7c02f97fcfd4dc21354ab85fc
```

**ELF F, SHA-256:**

```text
4e23d560aaa13e0ed64bf0d8aea65ae5e5d9b8d4aba68be4dd9301d42c41ef57
```

Estos hashes identifican los artefactos construidos. No identifican los documentos enviados en las interacciones ya recopiladas. Los materiales locales se conservan para continuar la investigación; este writeup no afirma que todos estén publicados junto a la página.

## Cómo citar este writeup

Sv-chost. (2026). *Ofuscación contra la IA* (versión 1.1.0). Writeup técnico: estudio de un ELF con texto Nisshoku inerte y seis respuestas de modelos de lenguaje.

La versión en inglés es una traducción del mismo estudio. Para una cita verificable, añade la URL del archivo publicado y el enlace permanente al commit o a la versión que consultaste. Se incluyen `CITATION.cff` y `CITATION.bib` como apoyo. No se asigna DOI ni se presenta este writeup como artículo ya publicado en una revista.

## Referencias

[1] Fang et al. (2024). [Large Language Models for Code Analysis: Do LLMs Really Do Their Job?](https://www.usenix.org/conference/usenixsecurity24/presentation/fang). USENIX Security, 829–846.

[2] Swindle et al. (2024). [Evaluation of Large Language Models on Code Obfuscation (Student Abstract)](https://ojs.aaai.org/index.php/AAAI/article/view/30517). AAAI, 38(21), 23664–23666. DOI: 10.1609/aaai.v38i21.30517.

[3] Na, Choi y Lee (2023). [DIP: Dead code Insertion based Black-box Attack for Programming Language Model](https://aclanthology.org/2023.acl-long.430/). ACL, 7777–7791. DOI: 10.18653/v1/2023.acl-long.430.

[4] Bernstein et al. (2026). [Trust Me, I Know This Function: Hijacking LLM Static Analysis using Bias](https://www.ndss-symposium.org/ndss-paper/trust-me-i-know-this-function-hijacking-llm-static-analysis-using-bias/). NDSS.

[5] Rao et al. (2026). [Acoda: Adversarial Code Obfuscation for Defending against LLM-based Analysis](https://arxiv.org/abs/2606.11755). Versión arXiv:2606.11755v1. DOI: 10.48550/arXiv.2606.11755.

[6] Liu et al. (2024). [Lost in the Middle: How Language Models Use Long Contexts](https://aclanthology.org/2024.tacl-1.9/). TACL, 12, 157–173. DOI: 10.1162/tacl_a_00638.

[7] GNU Project. [Options That Control Optimization](https://gcc.gnu.org/onlinedocs/gcc/Optimize-Options.html). Documentación oficial de GCC, consultada en octubre de 2026.

**Nota de transparencia:** se utilizó asistencia generativa en la construcción de la muestra y en la preparación del texto. La publicación distingue las comprobaciones locales de las interpretaciones de las respuestas. La revisión final corresponde al autor.
