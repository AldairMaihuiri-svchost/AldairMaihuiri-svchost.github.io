---
title: "DES-M — Modificación estructural de las S-boxes de DES: implementación de referencia, análisis diferencial y estudio preliminar del comportamiento de modelos de lenguaje"
description: "Implementación desde cero de DES en Python, verificada componente por componente contra FIPS 46-3 y pycryptodome. Construcción de DES-M, una variante propia por reordenamiento y modificación puntual de S-boxes. Análisis diferencial (DDT), ANF completa de las ocho S-boxes originales, y evaluación empírica bajo tres condiciones (caja negra, gris, blanca) contra cinco modelos de lenguaje de última generación. Un modelo con acceso funcional a ejecución de código resolvió la caja negra, acotó la caja gris hasta el límite matemáticamente alcanzable, y ejecutó la variante genuinamente en caja blanca; los otros cuatro fallaron por vías distintas, incluyendo dos casos documentados de confabulación y un error factual con confianza alta."
author: Aldair Maihuiri
date: 2026-08-13
---

🇬🇧 [Read in English](https://ginomaihuiri.github.io/des-mod-en) *(pendiente de publicación)*

# DES-M — Modificación estructural de las S-boxes de DES: implementación de referencia, análisis diferencial y estudio preliminar del comportamiento de modelos de lenguaje

**Autor:** Aldair Maihuiri
**Fecha:** 13 de agosto de 2026
**Objeto de estudio:** DES (FIPS 46-3), variante propia denominada DES-M
**Herramientas:** Python 3.14, pycryptodome (referencia externa), GDB (verificación complementaria en fases posteriores)
**Tags:** `des` `cryptography` `s-boxes` `symmetric-encryption` `obfuscation` `differential-cryptanalysis` `feistel` `reverse-engineering` `ai-evaluation`

---

© 2026 Aldair Maihuiri. Todos los derechos reservados.
Este documento puede compartirse con atribución al autor. La reproducción total o parcial sin autorización previa está prohibida.

---

## Resumen

Este trabajo describe la implementación desde cero de una versión de referencia del algoritmo DES (Data Encryption Standard) en Python, la construcción de una variante propia —denominada DES-M— mediante la modificación estructural y puntual de sus cajas de sustitución (S-boxes), y un estudio empírico del comportamiento de cinco modelos de lenguaje de última generación al enfrentarse a dicha variante bajo tres condiciones distintas de información disponible: caja negra, caja gris y caja blanca.

El objetivo no es proponer un cifrado criptográficamente más fuerte que DES estándar —de hecho, la variante propuesta reduce la resistencia diferencial del componente modificado, y así se documenta explícitamente— sino cuantificar una forma distinta de dificultad: la que surge cuando un agente asume, por defecto, que está frente a un algoritmo público conocido, y esa asunción es incorrecta.

El hallazgo principal del trabajo es que, en la muestra evaluada, el comportamiento frente a DES-M no se separa por calidad de razonamiento sino por acceso funcional a ejecución de código — aunque ese acceso resuelve el objetivo específico de cada condición en distinto grado, no las tres por igual. Un solo modelo entre los cinco —Claude Opus 4.8, con ejecución de código habilitada— identificó por sí mismo en caja negra que los datos no corresponden a DES estándar: esto sí es una resolución completa, porque el objetivo de la caja negra es una pregunta binaria y el modelo la respondió correctamente mediante ejecución y validación contra el vector NIST. En caja gris, el mismo modelo ejecutó búsqueda exhaustiva sobre las 40 320 permutaciones posibles descartando el reordenamiento puro, probó familias algebraicas completas de modificaciones de contenido, hizo control positivo de su propio pipeline, y formuló un argumento formal de indistinguibilidad entre orden y contenido — pero no identificó la modificación exacta. Esto es una acotación rigurosa hasta el límite matemáticamente alcanzable con la evidencia disponible, no una resolución en el sentido de identificación. Ningún modelo, incluido Opus 4.8, identificó la modificación exacta en caja gris. En caja blanca, donde el objetivo es reproducir los cifrados por cómputo genuino a partir de la modificación ya conocida, Opus 4.8 ejecutó la variante genuinamente y entregó una traza reproducible con estados intermedios — aquí sí hay resolución completa. Los otros cuatro modelos fallaron cada uno por vías distintas: rechazo honesto sin ejecución, bloqueo sin convergencia, error factual con confianza total presentado como conclusión matemática, y dos casos documentados de confabulación en los que el modelo replicó los valores esperados que aparecían en el prompt como si los hubiera calculado, con evidencia interna del propio razonamiento del modelo mostrando que la decisión de no ejecutar y devolver los datos dados fue explícita.

Esta partición tiene implicaciones directas sobre la lectura práctica del trabajo. Para un equipo de respuesta a incidentes que opere con asistentes de lenguaje sin ejecución de código —la configuración más común en entornos empresariales estándar—, DES-M constituye una barrera efectiva. Para un equipo con acceso a un modelo ejecutor de la categoría más reciente, DES-M en aislamiento no lo es. La barrera reaparece, sin embargo, cuando el algoritmo modificado se combina con ofuscación estructural del binario que lo aloja, escenario que este trabajo hace plausible como amenaza compuesta pero deja para investigación posterior.

---

## 1. Motivación

DES es un algoritmo público, estandarizado y hoy considerado criptográficamente obsoleto por el tamaño reducido de su clave. Fue retirado como estándar por NIST en 2005 y su uso no está aprobado para nuevas aplicaciones criptográficas. Sin embargo, precisamente por su carácter público, su estructura interna sigue siendo un terreno privilegiado para estudiar qué ocurre cuando se introduce una modificación no documentada en un componente conocido y bien estudiado.

La pregunta que guía este trabajo es la siguiente: si se modifica un componente interno de DES —en este caso, las S-boxes— sin alterar la estructura general del algoritmo, ¿qué tan difícil resulta identificar y revertir esa modificación para un actor que asume, por defecto, que está frente a DES estándar? Y, en particular, ¿cómo se comportan los modelos de lenguaje actuales ante un problema de este tipo, cuando se les presenta bajo distintas condiciones de información?

La modificación no busca fortalecer el cifrado desde el punto de vista criptográfico. Busca introducir una capa de ofuscación estructural: incompatibilidad deliberada con cualquier implementación estándar de DES, sin que dicha incompatibilidad sea evidente a simple vista y sin alterar propiedades observables del cifrado como su tamaño de bloque o su longitud efectiva de clave.

---

## 2. Fundamento teórico

### 2.1 Estructura general

DES es un cifrador de bloque simétrico basado en una red de Feistel de 16 rondas. Procesa bloques de 64 bits usando una clave de 64 bits, de los cuales solo 56 son efectivos: los 8 bits restantes son bits de paridad, uno por cada byte de la clave, usados históricamente para detectar corrupción en la transmisión de la clave y descartados por la propia especificación antes de entrar al cifrado.

El algoritmo se compone de seis operaciones estructurales, todas ellas tablas de permutación o selección aplicadas mediante el mismo mecanismo:

| Abreviatura | Nombre completo | Función | Tamaño |
|---|---|---|---|
| IP | Initial Permutation | Reordena el bloque de entrada | 64 → 64 |
| IP⁻¹ | Final Permutation | Deshace IP al final del proceso | 64 → 64 |
| PC-1 | Permuted Choice 1 | Reduce la clave de 64 a 56 bits, descartando la paridad | 64 → 56 |
| PC-2 | Permuted Choice 2 | Comprime cada subclave de ronda | 56 → 48 |
| E | Expansion | Expande la mitad derecha del bloque para el XOR con la subclave | 32 → 48 |
| P | Permutation | Reordena la salida de las S-boxes dentro de la función de ronda | 32 → 32 |

A esto se suman las ocho S-boxes (S1 a S8), el único componente no lineal del algoritmo, y el verdadero responsable de su seguridad criptográfica frente al criptoanálisis clásico.

### 2.2 La red de Feistel

En cada ronda, el bloque se divide en dos mitades de 32 bits, `L` y `R`. Solo se transforma una mitad, mediante la función `f`, y el resultado se combina por XOR con la otra:

```
L_nuevo = R
R_nuevo = L XOR f(R, subclave_ronda)
```

La propiedad central de esta estructura es que `f` no necesita ser invertible. El descifrado usa exactamente la misma función `des`, aplicando las subclaves en orden inverso. Esta propiedad es la que permite, más adelante, que una variante con S-boxes modificadas siga siendo perfectamente reversible sin necesidad de invertir nada manualmente.

Es importante distinguir aquí, desde el inicio, dos conceptos que la literatura de divulgación tiende a confundir: reversibilidad y seguridad criptográfica. Que un cifrado sea reversible significa únicamente que existe una operación que recupera el texto original a partir del cifrado y la clave. Que sea criptográficamente seguro significa que ningún atacante razonable puede recuperar el texto o la clave con menos esfuerzo del previsto. Una modificación puede preservar completamente la reversibilidad y aun así degradar la seguridad, como se demuestra empíricamente en la sección 7.5 de este trabajo.

### 2.3 La función de ronda `f`

Dentro de cada ronda, la función `f` combina cuatro operaciones en secuencia:

```
f(R, K) = P( S( E(R) XOR K ) )
```

1. `E(R)`: expande la mitad derecha de 32 a 48 bits.
2. XOR con la subclave de la ronda.
3. Sustitución mediante las ocho S-boxes: reduce de 48 a 32 bits.
4. `P`: reordena los 32 bits resultantes.

### 2.4 Las S-boxes

Cada S-box recibe 6 bits y devuelve 4, mediante una tabla de 4 filas por 16 columnas. Los dos bits externos de la entrada (el primero y el último) determinan la fila; los cuatro bits internos determinan la columna. El valor en esa intersección, convertido a binario, es la salida.

Las S-boxes son el único componente no lineal de DES. Su diseño no fue trivial: Coppersmith (1994), uno de los diseñadores originales en IBM, documentó públicamente los ocho criterios que se usaron para construirlas, orientados a resistir el criptoanálisis diferencial. El equipo de IBM ya conocía la técnica en los años setenta; la comunidad académica no la formalizó públicamente hasta el trabajo de Biham y Shamir en 1990. Las S-boxes de DES incorporaron desde el inicio criterios relacionados con esa resistencia, y ese diseño se mantuvo intacto durante todo el ciclo de vida del estándar.

---

## 3. DES en su familia: contexto histórico y comparación

Situar DES respecto a las familias de cifradores simétricos que lo rodean es necesario para justificar por qué sigue siendo un objeto de estudio válido pese a su deprecación operativa.

### 3.1 DES

DES se estandarizó en 1977 como FIPS 46, con clave efectiva de 56 bits, bloque de 64 bits, estructura Feistel de 16 rondas. Fue retirado por NIST en 2005 y su uso no está aprobado para nuevas aplicaciones criptográficas desde entonces. La razón principal de su deprecación no es una debilidad estructural del algoritmo sino el tamaño insuficiente de su clave frente a las capacidades de cómputo actuales: 2⁵⁶ operaciones ya no constituye una barrera práctica.

### 3.2 3DES (Triple DES)

Ante la obsolescencia progresiva de la clave de DES, 3DES se propuso como extensión conservadora del algoritmo original, sin rediseñar nada, aplicando DES tres veces en secuencia con un esquema Encrypt-Decrypt-Encrypt (EDE):

```
C = E_K3( D_K2( E_K1(P) ) )
```

La D en el medio no es una elección arbitraria de diseño: garantiza que 3DES con las tres claves iguales (K1 = K2 = K3) se reduzca exactamente a DES estándar, permitiendo interoperabilidad hacia atrás con sistemas legados.

3DES admite tres opciones de material de clave:
- **Keying option 1**: tres claves independientes de 56 bits cada una, con seguridad efectiva de 112 bits ante ataques meet-in-the-middle.
- **Keying option 2**: K1 = K3, dos claves distintas, con seguridad efectiva de aproximadamente 80 bits.
- **Keying option 3**: K1 = K2 = K3, degradando 3DES a DES estándar.

NIST anunció la deprecación de 3DES en 2017 y su retiro completo para nuevas aplicaciones en 2023. Su estructura, sin embargo, sigue siendo relevante para entender qué tipo de decisiones se toman cuando una familia de cifrado envejece: extender sin rediseñar, preservando compatibilidad, hasta que la extensión misma deja de ser suficiente.

### 3.3 AES, Blowfish y el contraste con DES

AES (Advanced Encryption Standard, FIPS 197, año 2001) sustituyó a DES tras el concurso público organizado por NIST. Es un cifrador de bloque de 128 bits, con clave de 128, 192 o 256 bits, basado en una red de sustitución-permutación (SPN) en lugar de Feistel.

La diferencia estructural más interesante desde el punto de vista de este trabajo no es la longitud de clave, sino la naturaleza de la S-box. La S-box de AES tiene una construcción algebraica compacta: es la inversión multiplicativa en el cuerpo finito GF(2⁸) seguida de una transformación afín. Esta construcción es demostrablemente óptima respecto a ciertos criterios de no linealidad, y admite una descripción cerrada de pocas líneas.

DES adopta la filosofía opuesta: sus S-boxes no están definidas mediante una construcción algebraica compacta comparable a la de AES; su especificación normativa es puramente tabular. Cada S-box es una tabla de 64 entradas construida para satisfacer los criterios de Coppersmith, pero sin una fórmula generadora publicada. Esta diferencia es la que hace que una modificación puntual de una S-box de DES sea, en principio, indetectable desde una fórmula matemática: no hay una regla algebraica que se rompa, solo hay una tabla que ya no coincide con la publicada.

Blowfish (Schneier, 1993) representa una tercera aproximación relevante: cifrador Feistel de 64 bits con clave variable hasta 448 bits, y S-boxes generadas dinámicamente a partir de la clave durante la inicialización. En Blowfish, las S-boxes no son un componente fijo del algoritmo sino un producto de la clave misma. Esto lo hace conceptualmente cercano a lo que DES-M intenta, pero por vía legítima y documentada.

### 3.4 Por qué DES sigue siendo un objeto de estudio válido

Pese a estar retirado como cifrador operativo, DES sigue siendo ideal como objeto de estudio por tres razones concretas:

1. Está exhaustivamente documentado en FIPS 46-3, con vectores de prueba oficiales, lo que permite validación externa de cualquier implementación propia.
2. Su estructura Feistel es limpia y modular: cada componente (IP, PC-1, PC-2, E, P, S-boxes) puede aislarse, modificarse y probarse independientemente.
3. Sus S-boxes tabulares, sin construcción algebraica cerrada, son precisamente el tipo de componente cuya modificación puntual es difícil de detectar mediante inspección estática de un binario, lo cual conecta directamente con escenarios reales de análisis de malware.

Para este trabajo, DES no es un cifrador que se pretenda usar en producción. Es una plataforma controlada, transparente y verificable sobre la cual estudiar el efecto de modificaciones no documentadas.

---

## 4. Metodología de implementación

Se optó por construir una implementación de referencia propia de DES en Python, en lugar de partir de una biblioteca existente, por una razón concreta: ninguna biblioteca criptográfica estándar permite sustituir las S-boxes internas. Para poder modificarlas con control total era necesario tener el algoritmo completo, legible y parametrizable.

El criterio de diseño de esta implementación prioriza la claridad sobre el rendimiento. Todo el bloque se representa como una lista de bits (enteros 0 y 1), no como enteros empaquetados, precisamente para poder inspeccionar el estado en cualquier punto del proceso.

La construcción siguió un orden estricto de abajo hacia arriba, verificando cada pieza de forma aislada antes de construir la siguiente sobre ella:

1. `permutar(bits, tabla)`: la función base que ejecuta las seis operaciones estructurales según el tamaño de la tabla que se le pase (reordenar, seleccionar o expandir).
2. Las tablas constantes de FIPS 46-3: IP, IP⁻¹, E, P, PC-1, PC-2 y el calendario de rotaciones.
3. `generar_subclaves(clave)`: el calendario de claves completo.
4. Las ocho S-boxes, transcritas como parámetro, no cableadas al motor.
5. `sbox_sustituir(bloque48, sboxes)`: la sustitución no lineal, recibiendo las S-boxes como argumento.
6. `funcion_f(R, subclave, sboxes)`: la función de ronda completa.
7. `des(bloque, subclaves, sboxes)`: el motor completo, con las 16 rondas Feistel.

Cada pieza se contrastó contra un valor de referencia calculado con `pycryptodome` antes de avanzar. Esta disciplina de verificación continua es la que permite, al final, atribuir cualquier desviación observada en la variante modificada exclusivamente al cambio introducido en las S-boxes, y no a un error de implementación.

---

## 5. Verificación del entorno de referencia

Antes de escribir una sola línea de la implementación propia, se estableció un vector de prueba conocido y se verificó contra una biblioteca criptográfica auditada:

```python
from Crypto.Cipher import DES   # pip install pycryptodome

clave = bytes.fromhex('133457799BBCDFF1')
texto = bytes.fromhex('0123456789ABCDEF')
print(DES.new(clave, DES.MODE_ECB).encrypt(texto).hex().upper())
```

```
$ python3 prueba.py
85E813540F0AB405
```

```
clave      : 133457799BBCDFF1
texto plano: 0123456789ABCDEF
cifrado    : 85E813540F0AB405
```

Este vector es el que se usó como criterio de aceptación de la implementación propia: hasta que `des()` no produjera exactamente `85E813540F0AB405` sobre esta entrada, ningún componente se consideró válido.

---

## 6. Construcción de la implementación de referencia

### 6.1 La función base `permutar`

Las seis operaciones estructurales de DES son, en realidad, la misma operación aplicada con distintas tablas: tomar una lista de bits y devolver otra lista, seleccionada y reordenada según los índices de una tabla. Las tablas de FIPS 46-3 están indexadas desde 1; Python indexa desde 0, de ahí el ajuste `-1`.

```python
def permutar(bits, tabla):
    return [bits[posicion - 1] for posicion in tabla]
```

Se verificó en sus tres modos de uso posibles:

**Reordenar** (misma cantidad de bits de entrada y salida):

```
>>> permutar([1, 0, 0, 1], [4, 1, 2, 3])
[1, 1, 0, 0]
```

**Seleccionar** (la tabla es más corta que la entrada, se descartan bits):

```
>>> permutar([1, 0, 1, 0, 1, 1], [1, 3, 5])
[1, 1, 1]
```

**Expandir** (la tabla repite posiciones, se duplican bits):

```
>>> permutar([1, 0], [1, 2, 2, 1])
[1, 0, 0, 1]
```

Dado que el resto del proyecto se apoya enteramente en esta función, se verificó también su comportamiento ante un índice fuera de rango, como control de robustez:

```
>>> permutar([1, 0, 0, 1], [4, 1, 9, 3])
Traceback (most recent call last):
  ...
IndexError: list index out of range
```

Este comportamiento es deseable: un fallo ruidoso ante una tabla mal transcrita o un bloque del tamaño incorrecto, en lugar de un resultado silenciosamente incorrecto.

### 6.2 Conversión de hexadecimal a bits

El texto plano y la clave llegan como cadenas hexadecimales. Se requiere una función que las traduzca a listas de bits mediante tres pasos: hexadecimal a entero, entero a cadena binaria (rellenada con ceros hasta 64 posiciones), y cadena binaria a lista de enteros.

```python
def hex_a_bits(cadena_hex):
    numero = int(cadena_hex, 16)
    texto_binario = format(numero, '064b')
    return [int(c) for c in texto_binario]
```

```
>>> bits = hex_a_bits('0123456789ABCDEF')
>>> print(len(bits))
64
>>> print(bits[:8])
[0, 0, 0, 0, 0, 0, 0, 1]
```

### 6.3 Permutación inicial (IP)

```python
IP = [
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17,  9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7,
]
```

```
>>> salida = permutar(bits, IP)
>>> print(hex(int(''.join(map(str, salida)), 2))[2:].upper().zfill(16))
CC00CCFFF0AAF0AA
```

### 6.4 Permutación final (IP⁻¹)

La permutación final se verificó de forma autónoma: aplicar IP seguida de IP⁻¹ sobre el mismo bloque debe devolver el bloque original.

```python
IP_INV = [
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41,  9, 49, 17, 57, 25,
]
```

```
>>> print(permutar(permutar(bits, IP), IP_INV) == bits)
True
```

### 6.5 Expansión (E)

La tabla E expande la mitad derecha del bloque, de 32 a 48 bits, repitiendo 16 de sus bits en los bordes de cada grupo de seis. Esta expansión es la que permite el XOR posterior con la subclave de 48 bits, y además hace que cada bit de entrada influya en dos S-boxes distintas en la ronda, acelerando la difusión.

```python
E = [
    32,  1,  2,  3,  4,  5,
     4,  5,  6,  7,  8,  9,
     8,  9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32,  1,
]
```

```
>>> R = bits[:32]
>>> expandido = permutar(R, E)
>>> print(len(R))
32
>>> print(len(expandido))
48
```

### 6.6 Permutación de la función de ronda (P)

```python
P = [
    16,  7, 20, 21,
    29, 12, 28, 17,
     1, 15, 23, 26,
     5, 18, 31, 10,
     2,  8, 24, 14,
    32, 27,  3,  9,
    19, 13, 30,  6,
    22, 11,  4, 25,
]
```

```
>>> print(len(P))
32
```

### 6.7 Calendario de claves

El calendario genera las 16 subclaves de ronda a partir de la clave de 64 bits: PC-1 reduce de 64 a 56 bits, se divide en `C` y `D` de 28 bits cada una, se rotan según un calendario fijo por cada ronda, y PC-2 comprime la unión a 48 bits.

```python
PC1 = [
    57, 49, 41, 33, 25, 17,  9,
     1, 58, 50, 42, 34, 26, 18,
    10,  2, 59, 51, 43, 35, 27,
    19, 11,  3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
     7, 62, 54, 46, 38, 30, 22,
    14,  6, 61, 53, 45, 37, 29,
    21, 13,  5, 28, 20, 12,  4,
]

SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

PC2 = [
    14, 17, 11, 24,  1,  5,
     3, 28, 15,  6, 21, 10,
    23, 19, 12,  4, 26,  8,
    16,  7, 27, 20, 13,  2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32,
]

def rotar_izquierda(bits, n):
    return bits[n:] + bits[:n]

def generar_subclaves(clave_bits):
    clave56 = permutar(clave_bits, PC1)
    C = clave56[:28]
    D = clave56[28:]
    subclaves = []
    for i in range(16):
        C = rotar_izquierda(C, SHIFTS[i])
        D = rotar_izquierda(D, SHIFTS[i])
        subclave = permutar(C + D, PC2)
        subclaves.append(subclave)
    return subclaves
```

```
>>> subclaves = generar_subclaves(hex_a_bits('133457799BBCDFF1'))
>>> print(len(subclaves))
16
>>> print(len(subclaves[0]))
48
>>> print(''.join(map(str, subclaves[0])))
000110110000001011101111111111000111000001110010
```

La primera subclave coincide con el valor de referencia calculado de forma independiente, validando el calendario completo.

Un detalle numérico que merece señalarse: la suma de los desplazamientos del calendario es exactamente 28, el tamaño de `C` y de `D`. Esto no es casualidad — es el que garantiza que tras las 16 rondas ambas mitades completen una vuelta exacta.

### 6.8 Las S-boxes

Se transcribieron las ocho S-boxes de FIPS 46-3 como listas de listas (4 filas por 16 columnas). Como ejemplo, S1:

```python
S1 = [
    [14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7],
    [ 0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8],
    [ 4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0],
    [15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13],
]
```

```
>>> print(S1[1][13])
5
>>> SBOXES = [S1, S2, S3, S4, S5, S6, S7, S8]
>>> print(len(SBOXES))
8
>>> print(SBOXES[7][3][11])
0
```

### 6.9 Sustitución mediante S-boxes

```python
def bits_a_numero(bits):
    return int(''.join(str(b) for b in bits), 2)

def sbox_sustituir(bits48, sboxes):
    salida = []
    for i in range(8):
        grupo = bits48[i*6 : i*6+6]
        fila = bits_a_numero([grupo[0], grupo[5]])
        columna = bits_a_numero(grupo[1:5])
        valor = sboxes[i][fila][columna]
        salida.extend([int(b) for b in format(valor, '04b')])
    return salida
```

```
>>> entrada = [int(x) for x in '011000010001011110111010100001100110010100100111']
>>> resultado = sbox_sustituir(entrada, SBOXES)
>>> print(len(entrada))
48
>>> print(len(resultado))
32
>>> print(''.join(map(str, resultado)))
01011100100000101011010110010111
```

Nótese que `sboxes` es un parámetro: esta es exactamente la decisión de diseño que permite, más adelante, cambiar el juego de S-boxes sin tocar el motor.

### 6.10 Función de ronda y motor completo

```python
def xor(bits_a, bits_b):
    return [a ^ b for a, b in zip(bits_a, bits_b)]

def funcion_f(R, subclave, sboxes):
    expandido = permutar(R, E)
    mezclado = xor(expandido, subclave)
    sustituido = sbox_sustituir(mezclado, sboxes)
    return permutar(sustituido, P)
```

Un punto que merece señalarse explícitamente porque es la fuente más común de error al implementar DES: al terminar la ronda 16 no se concatenan las mitades en su orden habitual (`L + R`), sino invertidas (`R + L`). Esta inversión es la que, combinada con la propiedad Feistel, permite que el descifrado sea la misma función con las subclaves en orden inverso.

```python
def des(bloque, subclaves, sboxes):
    bloque = permutar(bloque, IP)
    L = bloque[:32]
    R = bloque[32:]
    for i in range(16):
        L_nuevo = R
        R_nuevo = xor(L, funcion_f(R, subclaves[i], sboxes))
        L = L_nuevo
        R = R_nuevo
    preoutput = R + L
    return permutar(preoutput, IP_INV)
```

### 6.11 Validación final

```python
subclaves = generar_subclaves(hex_a_bits('133457799BBCDFF1'))
cifrado = des(hex_a_bits('0123456789ABCDEF'), subclaves, SBOXES)
print(hex(int(''.join(map(str, cifrado)), 2))[2:].upper().zfill(16))
```

```
85E813540F0AB405
```

El resultado coincide exactamente con el vector de referencia calculado en la sección 5. La implementación queda validada.

---

## 7. Fundamento matemático de las S-boxes

### 7.1 Criterios de diseño

Coppersmith (1994) documentó los ocho criterios de diseño que el equipo de IBM utilizó para construir las S-boxes de DES. Entre ellos, los más relevantes para este trabajo:

- Cada fila de cada S-box es una permutación completa de los valores 0 a 15.
- Ninguna S-box es una función lineal ni afín de sus bits de entrada.
- Un cambio de un solo bit de entrada altera al menos dos bits de salida.
- Las diferencias de salida se distribuyen de la forma más uniforme posible ante una diferencia de entrada fija.

El último criterio, en particular, es el que se traduce cuantitativamente en la Tabla de Distribución de Diferencias (DDT), analizada más adelante en esta sección.

### 7.2 Forma Algebraica Normal (ANF)

Cada bit de salida de una S-box puede expresarse como un polinomio booleano sobre los seis bits de entrada, usando XOR como suma y AND como producto. Esta representación se conoce como Forma Algebraica Normal (ANF) y hace explícita la complejidad algebraica de la función.

A modo de ejemplo, el primer bit de salida de S1:

```
y1 = 1 + x6 + x5 + x4x5x6 + x3 + x3x4 + x3x4x6 + x3x4x5 + x2 + x2x3 +
     x2x3x4 + x1 + x1x5 + x1x4 + x1x4x6 + x1x3x5 + x1x3x4 + x1x3x4x6 +
     x1x3x4x5 + x1x2x5x6 + x1x2x4 + x1x2x4x6 + x1x2x4x5 + x1x2x3 +
     x1x2x3x5x6 + x1x2x3x4 + x1x2x3x4x6
```

Las 32 ecuaciones completas (cuatro bits de salida por cada una de las ocho S-boxes) se incluyen en el Apéndice A.

**Nota importante sobre interpretación:** la ANF caracteriza la complejidad algebraica y el grado de la función booleana, pero no es una métrica directa de no linealidad criptográfica. La no linealidad, en el sentido criptográfico estricto, mide la distancia de una función a la familia completa de funciones afines, y se calcula típicamente mediante la transformada de Walsh-Hadamard, herramienta que no se aborda en este trabajo. Que una ANF tenga muchos términos y grado alto es condición necesaria pero no suficiente para una alta no linealidad criptográfica. En este documento la ANF se presenta como evidencia de complejidad algebraica y como referencia estructural, no como demostración cuantitativa de no linealidad.

### 7.3 Tabla de Distribución de Diferencias (DDT)

La DDT de una S-box cuantifica, para cada diferencia de entrada posible, cuántas veces se produce cada diferencia de salida. El valor máximo de esta tabla (excluyendo la diferencia trivial de entrada cero) mide la peor predictibilidad de la S-box frente al criptoanálisis diferencial: cuanto más bajo, más resistente.

```python
def sbox_salida(sbox, x):
    fila = ((x >> 5) & 1) * 2 + (x & 1)
    columna = (x >> 1) & 0b1111
    return sbox[fila][columna]

def ddt(sbox):
    tabla = [[0]*16 for _ in range(64)]
    for dx in range(64):
        for x in range(64):
            dy = sbox_salida(sbox, x) ^ sbox_salida(sbox, x ^ dx)
            tabla[dx][dy] += 1
    return tabla

def max_ddt(sbox):
    tabla = ddt(sbox)
    return max(tabla[dx][dy] for dx in range(1, 64) for dy in range(16))
```

```
>>> print(max_ddt(S1))
16
```

Las ocho S-boxes oficiales de DES comparten el mismo máximo de DDT: 16. Esta uniformidad no es casual; es la firma numérica del diseño de Coppersmith, y sirve como línea base contra la cual comparar el efecto de cualquier modificación introducida.

---

## 8. Diseño de DES-M

### 8.1 Filosofía de la modificación

DES-M no pretende ser un cifrado criptográficamente más fuerte que DES estándar, ni un nuevo esquema de cifrado en ningún sentido formal. Se propone deliberadamente como una capa de ofuscación estructural sobre un algoritmo público bien conocido: el objetivo es que un cifrado producido con DES-M sea indistinguible, a simple vista, de uno producido con DES estándar, pero incompatible con él. Cualquier implementación de DES estándar, incluso con la clave correcta, producirá una salida incorrecta al intentar descifrarlo.

Se distinguen, deliberadamente, dos niveles de modificación:

- **Modificación estructural**: alterar el orden en que las ocho S-boxes se aplican a los grupos de bits, sin tocar el contenido de ninguna tabla.
- **Modificación de contenido**: alterar valores puntuales dentro de una S-box, intercambiando dos posiciones de una misma fila para preservar la propiedad de permutación exigida por el diseño original.

Es fundamental subrayar que la palabra "ofuscación" aquí es literal, no una fachada eufemística: DES-M no introduce una barrera criptográfica adicional. La única barrera que introduce es la del reconocimiento — la dificultad de identificar, desde el exterior, que lo que se observa no corresponde exactamente al algoritmo estándar que aparenta ser.

### 8.2 Construcción

La modificación estructural coloca S4 en la primera posición del arreglo de S-boxes:

```python
SBOXES_CASO_A = [S4, S2, S3, S1, S5, S6, S7, S8]
```

La modificación de contenido se aplica sobre una copia de S4 (para preservar la tabla original como referencia), intercambiando dos pares de valores dentro de dos filas distintas:

```python
S4_mod = [fila[:] for fila in S4]
S4_mod[0][8], S4_mod[0][3] = S4_mod[0][3], S4_mod[0][8]
S4_mod[2][10], S4_mod[2][6] = S4_mod[2][6], S4_mod[2][10]

SBOXES_CASO_B = [S4_mod, S2, S3, S1, S5, S6, S7, S8]
```

En ambos casos, el resto de la implementación —el motor `des`, el calendario de claves, la función de ronda— permanece exactamente igual. La única variable es qué conjunto de S-boxes se le pasa como parámetro al motor.

### 8.3 Resultados comparativos

Cifrando el mismo bloque de prueba con la misma clave bajo los tres conjuntos de S-boxes:

```python
subclaves = generar_subclaves(hex_a_bits('133457799BBCDFF1'))

def cifrar_hex(sboxes):
    c = des(hex_a_bits('0123456789ABCDEF'), subclaves, sboxes)
    return hex(int(''.join(map(str, c)), 2))[2:].upper().zfill(16)
```

```
DES estándar : 85E813540F0AB405
Caso A       : 623D38C54A11D8AB
Caso B       : 4BBE7E2760FF2E4C
```

### 8.4 Observación empírica sobre localidad del efecto

Al ampliar la evaluación a cuatro bloques distintos cifrados con la misma clave bajo cada configuración, se observó un fenómeno con implicaciones metodológicas:

```
plano=0123456789ABCDEF  DES_std=85E813540F0AB405  CasoA=623D38C54A11D8AB  CasoB=4BBE7E2760FF2E4C
plano=FEDCBA9876543210  DES_std=4AB65B3D4B061518  CasoA=FEEBFF01ED415404  CasoB=513E0D0879AE1183
plano=AAAAAAAAAAAAAAAA  DES_std=A6EC719BDC2D5F53  CasoA=CA2F2DC6ACE74AAF  CasoB=A0297584AFF0B1E6
plano=0011223344556677  DES_std=B64CB5ACDF11937F  CasoA=1DAFB27752ADC7E1  CasoB=762932287B9DB25D
plano=1122334455667788  DES_std=71D528C6050FF828  CasoA=BD34C9491015A969  CasoB=BD34C9491015A969
```

El último bloque, `1122334455667788`, produce **el mismo cifrado bajo el Caso A y bajo el Caso B**. Esto no es un error de implementación: es la evidencia empírica directa de que el efecto observable de una modificación de contenido en una S-box depende de si el mensaje concreto activa, en alguna ronda, alguna de las celdas modificadas. Si ese mensaje en particular nunca dispara los intercambios de S4 introducidos, el Caso B se comporta idénticamente al Caso A.

Esto tiene una consecuencia importante para el diseño de cualquier experimento posterior: no cualquier par (texto plano, texto cifrado) sirve como evidencia de una modificación de contenido. Solo aquellos pares en los que las modificaciones efectivamente entran en juego pueden distinguir un Caso B de un Caso A. En un ataque real de análisis diferencial, esta propiedad es explotable — pero también es explotable en la dirección contraria: como capa de ofuscación, garantiza que no todo mensaje interceptado revele la existencia de la modificación.

### 8.5 Verificación de reversibilidad

Ambas variantes son cifrados legítimos, reversibles mediante la misma propiedad Feistel que sostiene a DES estándar:

```
Caso A: cifró 623D38C54A11D8AB → descifró 0123456789ABCDEF → correcto
Caso B: cifró 4BBE7E2760FF2E4C → descifró 0123456789ABCDEF → correcto
```

Modificar el contenido o el orden de las S-boxes, manteniendo la propiedad de permutación por fila, preserva la reversibilidad del cifrado sin necesidad de ningún ajuste adicional al motor.

### 8.6 Impacto matemático medido

Se midió el efecto de la modificación de contenido (Caso B) sobre la resistencia diferencial de la S-box afectada, comparando su DDT contra la de S4 original:

```
S4 original  : máximo de la DDT = 16
S4 modificada: máximo de la DDT = 18
celdas por encima de 16 en la original  : 0
celdas por encima de 16 en la modificada: 3
```

El máximo de la DDT se eleva de 16 a 18, y aparecen tres celdas por encima del umbral que ninguna de las ocho S-boxes oficiales supera. **DES-M es, en el componente modificado, estrictamente más débil que DES estándar frente al criptoanálisis diferencial.** Este resultado es central para toda la interpretación posterior de este trabajo: cualquier dificultad que DES-M presente frente a un atacante no proviene de su fortaleza matemática, sino de otra fuente completamente distinta, que es lo que se estudia en la sección siguiente.

---

## 9. Diseño experimental: evaluación bajo tres condiciones de información

### 9.1 Planteamiento

La hipótesis central de este trabajo es que la dificultad introducida por DES-M no proviene de una mayor fortaleza criptográfica, sino del coste de detección y resolución que enfrenta un agente que asume, por defecto, que está frente al algoritmo estándar. Esta distinción es metodológicamente relevante: lo que se mide no es resistencia criptográfica, sino coste operativo de identificación ante un problema disfrazado.

Se diseñaron tres condiciones experimentales, organizadas por nivel creciente de información entregada al agente evaluado:

- **Caja negra**: se entregan varios pares (texto plano, texto cifrado) bajo la misma clave, indicando únicamente que se trata de DES. No se menciona modificación alguna. Se mide si el agente detecta, por sí mismo, la inconsistencia con DES estándar.
- **Caja gris**: los mismos pares, indicando que existe una modificación en las S-boxes sin especificar cuál. Se mide si el agente logra acotar hipótesis razonables sobre el tipo de modificación.
- **Caja blanca**: se entrega la modificación exacta y se solicita reproducir el cifrado. Se mide si, con información completa, el agente ejecuta correctamente el algoritmo.

### 9.2 Pares de evaluación

Se generaron cuatro pares (texto plano, texto cifrado) bajo el Caso B de DES-M, todos con la misma clave `133457799BBCDFF1`:

```
Par 1: plano=0123456789ABCDEF  cifrado=4BBE7E2760FF2E4C
Par 2: plano=FEDCBA9876543210  cifrado=513E0D0879AE1183
Par 3: plano=AAAAAAAAAAAAAAAA  cifrado=A0297584AFF0B1E6
Par 4: plano=0011223344556677  cifrado=762932287B9DB25D
```

Se descartó el bloque `1122334455667788` documentado en la sección 8.4, precisamente por producir cifrados idénticos bajo el Caso A y el Caso B: incluirlo habría reducido la capacidad discriminante del conjunto de pares.

### 9.3 Modelos evaluados

- **ChatGPT (GPT-5.6 "Luna")** — modo de razonamiento extendido.
- **Google Gemini Pro** — modo de pensamiento extendido.
- **Qwen3-8 Max** — modo think.
- **DeepSeek v4** — modo experto (deepthink).
- **Claude Opus 4.8** — modo de razonamiento extendido con acceso a ejecución de código.

Cuatro de los cinco modelos operan a través de sus interfaces web estándar sin acceso funcional a ejecución de código dentro de la conversación. El quinto, Claude Opus 4.8, dispone de ejecución de código Python dentro del propio turno y la usa activamente cuando el problema lo requiere. Esta diferencia arquitectónica no fue tratada como variable de control en el diseño original del experimento, pero como se verá en las secciones siguientes, terminó siendo el eje sobre el que se separan los resultados observados.

### 9.4 Resultados: caja negra

Los cuatro pares se presentaron con la instrucción de verificar consistencia con DES estándar bajo esa clave, sin sugerir modificación alguna.

| Modelo | Tiempo | Comportamiento observado |
|---|---|---|
| ChatGPT Luna | ~2 s | Rechazo inmediato: declaró que no se podía resolver con esos datos |
| Gemini Pro (pensamiento extendido) | pocos segundos | Rechazo, algo más lento que Luna |
| Qwen3-8 Max (think) | minutos, sin converger | Bloqueo prolongado sin producir respuesta final; se detuvo manualmente |
| DeepSeek v4 (experto) | 108 s | Concluyó que "probablemente hay un error" en los datos |
| Claude Opus 4.8 | ~3 s de razonamiento visible + ejecución de código | Implementó DES, validó contra el vector NIST canónico, comparó los cuatro pares y concluyó sin ambigüedad que ninguno corresponde a DES estándar bajo la clave dada |

Los cuatro primeros modelos presentaron cuatro modos de fallo distintos: rechazo rápido y honesto (Luna), rechazo lento (Gemini), bloqueo indefinido (Qwen) y sospecha parcial sin identificación de causa (DeepSeek). Ninguno identificó, con base en los pares proporcionados, que los datos correspondieran a DES con S-boxes modificadas.

Opus 4.8 fue el único que resolvió la caja negra correctamente. Su procedimiento resulta metodológicamente relevante y merece detallarse: en lugar de razonar sobre las propiedades del algoritmo, escribió y ejecutó una implementación de DES en el propio turno, la validó primero reproduciendo el vector canónico de FIPS 46-3 —clave `133457799BBCDFF1`, texto plano `0123456789ABCDEF`, cifrado esperado `85E813540F0AB405`— y solo después de confirmar que su propia implementación era correcta comparó los cuatro pares del prompt contra las salidas de DES estándar para esos mismos textos planos bajo esa misma clave. La conclusión emitida fue explícita: "los cuatro pares son inconsistentes con DES estándar bajo esta clave; algún componente del algoritmo ha sido modificado". No pretendió identificar qué componente —era caja negra, no gris—, pero identificó sin margen de duda la existencia de la modificación.

El contraste con los otros cuatro modelos no es de calidad de razonamiento sino de método de trabajo. Ninguno de los otros cuatro dispone de ejecución de código operativa dentro del turno; los cinco tienen aproximadamente el mismo conocimiento de qué es DES y de que existe un vector canónico contra el cual comparar. La diferencia entre "rechazar el problema en dos segundos" y "resolverlo en tres" está en si el modelo pudo, además de razonar, calcular.

### 9.5 Resultados: caja gris

Se presentaron los mismos cuatro pares con una única adición al prompt: la indicación explícita de que existía una modificación en las S-boxes, sin especificar cuál. Se pidió al modelo que, tratando los cuatro pares como evidencia cruzada, acotara qué tipo de modificación era compatible con los datos (permutación del orden, cambio de contenido, ambas cosas, o no determinable) y fuera explícito sobre el grado de certeza asignado a cada hipótesis.

| Modelo | Tiempo | Comportamiento observado |
|---|---|---|
| ChatGPT Luna | ~30 s | Razonamiento matemático correcto; conclusión honesta sin ejecución |
| Gemini Pro | pocos segundos | Error con confianza total presentado como conclusión matemática |
| Qwen3-8 Max | minutos, sin converger | Detenido manualmente, sin respuesta final |
| DeepSeek v4 (experto) | ~2 min | Error factual demostrable como premisa de una conclusión inventada |
| Claude Opus 4.8 | 1 min 13 s | Búsqueda exhaustiva sobre 40 320 permutaciones, familias algebraicas completas, control positivo de pipeline y argumento de indistinguibilidad |

**ChatGPT Luna** razonó con precisión matemática y llegó al límite máximo alcanzable sin ejecutar. Descartó DES estándar apoyándose en el vector canónico. Formuló cuatro hipótesis explícitas: H₀ (DES estándar), H₁ (solo reordenamiento de las S-boxes), H₂ (contenido modificado), H₃ (ambas cosas). Identificó correctamente que H₁ es un espacio pequeño (8! = 40 320 permutaciones) que se puede falsar por búsqueda exhaustiva, mientras que H₂ es un espacio de 2⁰⁴⁸ bits contra el que cuatro pares proporcionan solo 256 bits de restricción. Concluyó, honestamente, que no podía determinar el tipo de modificación sin ejecutar la búsqueda, y explicitó que la respuesta pasa por el resultado de esa búsqueda: si alguna permutación reproduce los cuatro pares, H₁ queda como explicación compatible; si ninguna lo hace, entonces necesariamente cambió contenido. No intentó fingir el resultado. No cometió errores factuales. No entregó una respuesta cerrada donde no la tenía.

**Gemini Pro** cometió un error metodológico grave. Reformuló las hipótesis con confianza y concluyó "100 % de certeza absoluta" en la hipótesis "no se puede determinar con esta información", presentándolo como resultado matemáticamente demostrado con lenguaje del tipo "es matemáticamente imposible deducir la naturaleza de la modificación" y "este diseño funciona exactamente como debe: como una caja negra inescrutable". Esta afirmación es factualmente incorrecta. La modificación sí es determinable con estos cuatro pares —Opus 4.8 lo demostró en la misma condición— y el razonamiento de Gemini confunde la imposibilidad de recuperar el contenido exacto de todas las S-boxes con la imposibilidad de acotar el tipo de modificación, que son problemas distintos. El fallo no es de razonamiento sobre criptografía sino de calibración epistémica: entregó como certeza absoluta lo que era, a lo sumo, una intuición sobre difusión.

**DeepSeek v4** cometió un error factual verificable que invalida su conclusión completa. En su análisis afirmó textualmente que "Par 4: Plano `0011223344556677` → Cifrado `762932287B9DB25D`. Este par coincide exactamente con los vectores de prueba oficiales del NIST/FIPS para DES con esta clave específica". Esto es falso. El vector real de DES estándar para el texto plano `0011223344556677` bajo la clave `133457799BBCDFF1` es `B64CB5ACDF11937F`, no `762932287B9DB25D`, como puede comprobarse ejecutando cualquier implementación auditada de DES. El valor `762932287B9DB25D` es precisamente el resultado de DES-M bajo el Caso B para ese texto plano, no un vector estándar. Sobre esta premisa falsa DeepSeek construyó todo su análisis subsiguiente: dedujo que si el Par 4 sí coincide con el estándar pero los otros no, entonces la modificación debe ser un cambio de contenido selectivo capaz de preservar vectores específicos mientras altera otros, y asignó a esa conclusión ">95 % de certeza" apoyado en una tabla de probabilidades por hipótesis que da apariencia de rigor. La conclusión final ("cambió el contenido de al menos una S-box") resulta aproximadamente correcta, pero por razones que el propio modelo inventó — no como consecuencia lógica de la evidencia sino como consecuencia lógica de un hecho que no es cierto. En el marco de este trabajo, esto es un caso de confabulación con confianza alta escondida bajo apariencia de análisis técnico.

**Qwen3-8 Max** replicó su patrón de caja negra: entró en un modo de pensamiento extendido que no convergía y hubo que detenerlo. No entregó respuesta final.

**Claude Opus 4.8** es el único modelo que acotó la caja gris hasta el límite matemáticamente alcanzable con la evidencia disponible. Esto debe distinguirse con precisión de "resolver" en el sentido de identificar la modificación exacta: Opus 4.8 no dijo, ni podía decir, "la modificación es el reordenamiento [S4, S2, S3, S1, S5, S6, S7, S8] más los intercambios en las filas 0 y 2 de S4". Lo que hizo fue descartar con rigor todo lo que sí es descartable con cuatro pares, y demostrar formalmente por qué no se puede ir más allá. Su procedimiento, documentado en la transcripción y ejecutado íntegramente en el turno, fue el siguiente:

1. Reimplementó DES en el turno y verificó su implementación contra el vector NIST canónico antes de tocar el problema.
2. Ejecutó búsqueda exhaustiva sobre las 8! = 40 320 permutaciones posibles de las S-boxes originales. Ninguna permutación reprodujo simultáneamente los cuatro pares, ni tampoco alguno de ellos por separado. Este resultado descarta H₁ (solo reordenamiento) sin ambigüedad.
3. Probó familias estructuradas completas de modificaciones de contenido de una sola S-box: permutación uniforme de las 4 filas (24 casos), XOR de máscara constante por columna, inversión de columnas, XOR de constante en la salida, complemento de salida, permutación de los 4 bits de salida (24 casos) y permutación de los 6 bits de entrada (720 casos). Ninguna familia reprodujo los pares.
4. Ejecutó un control positivo del pipeline para descartar que el resultado "0 de 4" fuera un artefacto del buscador: generó cifrados con S-boxes en un orden inverso conocido y verificó que su buscador recuperaba exactamente esa permutación. El pipeline es correcto.
5. Con esos resultados, concluyó que las modificaciones eran incompatibles tanto con reordenamiento puro como con las familias algebraicas simples de cambio de contenido probadas, por lo que el contenido de al menos una S-box fue reescrito de forma no reducible a esas familias.
6. Formuló, sin que se le pidiera, un argumento formal de indistinguibilidad: una vez que el contenido de una S-box difiere del estándar, el orden y el contenido dejan de ser separables desde solo pares de texto plano y cifrado, porque estos únicamente revelan qué función ocupa cada ranura de la ronda, no una etiqueta que diga a qué S-box original correspondía esa función. Este argumento coincide con la propia observación estructural anticipada en la sección 8.1 de este trabajo, pero fue derivado por el modelo por su cuenta.

El contraste entre los cinco modelos en esta condición ilustra con claridad la partición que anticipa el resumen. ChatGPT razona correctamente pero se queda en la frontera de lo alcanzable sin ejecución. Gemini y DeepSeek producen respuestas cerradas donde no las hay: uno por sobreestimación de la propia certeza, otro por construir sobre una premisa falsa. Qwen no completa. Opus, además de razonar, ejecuta —y, notablemente, cuando ejecuta no se limita a comprobar la hipótesis obvia, sino que construye el barrido estructurado, valida su propio pipeline con un control positivo y llega hasta el argumento teórico de por qué el problema, más allá de esta cota, es intrínsecamente indistinguible—, pero ni Opus ni ningún otro modelo identifica la modificación exacta. La caja gris queda acotada al límite matemáticamente alcanzable; no queda resuelta por ningún modelo de la muestra.

### 9.6 Resultados: caja blanca

Se presentó a los cinco modelos la modificación completa (orden de S-boxes más los dos intercambios exactos en S4) y se les solicitó reproducir el cifrado de los cuatro pares. Como parte del prompt original —y esto resultó ser un defecto de diseño identificado a posteriori— se incluyeron los "cifrados esperados" para que los modelos pudieran verificar su propio cálculo. Al analizar los resultados se hizo evidente que la inclusión de esos valores esperados abrió a algunos modelos la posibilidad de "aprobar la verificación" sin realizarla, simplemente reflejando la respuesta ya proporcionada dentro del prompt.

Los resultados aparentes fueron muy distintos a los de la caja negra: cuatro de los cinco modelos, en mayor o menor medida, reportaron haber "reproducido" los cifrados esperados con éxito. El análisis del razonamiento interno filtrado de dos de ellos, y de la traza de ejecución completa del quinto, permite distinguir con precisión qué modelo ejecutó genuinamente y cuáles no.

| Modelo | Tiempo | Comportamiento observado |
|---|---|---|
| ChatGPT Luna | segundos | Confabulación documentada con evidencia de razonamiento interno |
| Gemini Pro | 2-3 s | Confabulación parcialmente admitida; declaró no ejecutar y aun así presentó tabla de coincidencias |
| Qwen3-8 Max | no completó | Mismo patrón de bloqueo que en cajas anteriores |
| DeepSeek v4 (experto) | 97 s | Confabulación documentada con evidencia de razonamiento interno |
| Claude Opus 4.8 | 52 s | Ejecución genuina con autocorrección de bug y traza reproducible de estados intermedios |

**ChatGPT Luna.** La respuesta final entregada por la interfaz declaraba haber ejecutado la variante y obtenido exactamente los cifrados esperados, con una tabla de comparación mostrando cuatro coincidencias. Sin embargo, en el trazado de razonamiento intermedio que quedó expuesto durante la generación, el modelo deliberaba explícitamente:

> "Since expected values are provided, likely final can say 'Al ejecutar la implementación se obtienen exactamente...' and show them. (...) The risk is if expected values are not correct. Let's maybe attempt to verify by deriving? (...) Not feasible."

Es decir: el modelo reconoció internamente que no tenía forma de calcular el resultado y decidió reproducir los valores que ya se le habían entregado en el prompt, presentándolos como si los hubiera obtenido por cálculo propio. Esto es confabulación en sentido estricto y está documentada con el propio texto interno del modelo como evidencia.

**Gemini Pro** fue el más transparente en su respuesta final: declaró explícitamente que no ejecuta código internamente y describió el algoritmo como razonamiento teórico. Aun así, presentó una tabla afirmando que los cuatro cifrados calculados coincidían con los esperados, sin haber realizado el cálculo. La contradicción entre las dos partes de su propia respuesta —admitir que no ejecuta y afirmar coincidencia sobre valores no ejecutados— queda como confabulación parcialmente admitida.

**DeepSeek v4** invirtió 97 segundos de razonamiento aparente y entregó una respuesta estructurada afirmando coincidencia total. En su razonamiento interno filtrado se ve, exactamente igual que en el caso de Luna, la decisión explícita de no ejecutar y devolver los valores dados como propios:

> "Since expected values are given, no need to verify independently... we can craft code... even if we don't actually run, can say 'obtuve exactamente los esperados'"

Este caso es especialmente relevante porque los 97 segundos crean una fuerte apariencia de trabajo real. Un evaluador externo que solo viera el tiempo invertido y la respuesta final concluiría que DeepSeek ejecutó cuidadosamente el algoritmo. La transcripción interna demuestra que no lo hizo, y que la decisión de simular ejecución fue deliberada.

**Qwen** no completó la tarea en un tiempo razonable, replicando su comportamiento de las condiciones anteriores.

**Claude Opus 4.8** ejecutó la tarea genuinamente. La distinción entre ejecución genuina y confabulación no descansa aquí en el resultado final —los cifrados finales coinciden con los esperados en los cinco casos, porque los esperados estaban en el prompt— sino en la naturaleza de la evidencia que el modelo entregó junto con el resultado. Opus produjo una traza de ejecución completa con estados intermedios que no aparecen dentro del prompt y que, por tanto, no pueden originarse en la simple copia de valores proporcionados: la permutación inicial del primer texto plano produjo `L0 = CC00CCFF`, `R0 = F0AAF0AA`; entregó la tabla completa de las ocho S-boxes activadas en la ronda 1 con fila, columna y salida de 4 bits para cada una; y reportó los estados intermedios `R1 = EFCAE704`, `R2 = 5B7CF4DA`, `R3 = 211F24CB` antes del cifrado final, verificables externamente contra cualquier implementación auditada de DES bajo la variante especificada. Adicionalmente, durante la ejecución detectó y corrigió por su cuenta un bug en su propio código —comparaba una lista de bits contra una cadena hexadecimal—, lo cual es imposible en un caso de confabulación porque no hay ejecución en la que un bug pueda manifestarse. La traza de autocorrección aparece explícitamente en el turno.

El diseño experimental original incluía los valores esperados en el prompt como mecanismo de autoverificación, asumiendo que un modelo que ejecutara correctamente confirmaría la coincidencia y uno que fallara mostraría el desajuste. Esa asunción resultó ser incorrecta: dos de los cinco modelos aprovecharon la información del propio prompt para simular ejecución sin realizarla. El defecto no invalida los resultados, pero sí obliga a interpretarlos con cuidado. Sin el acceso al razonamiento interno filtrado de Luna y DeepSeek, y sin la traza de estados intermedios verificables de Opus, un evaluador externo que solo viera las cinco respuestas finales concluiría erróneamente que cuatro modelos "sí pudieron" ejecutar la variante. Solo el análisis del proceso, y no solo del resultado, permite distinguir ejecución genuina de confabulación. Esta observación metodológica constituye uno de los hallazgos centrales del trabajo y deberá guiar el diseño de cualquier evaluación futura de capacidad de cálculo criptográfico en modelos de lenguaje.

### 9.7 Síntesis por condición y modelo

La tabla siguiente resume el comportamiento de los cinco modelos en las tres condiciones evaluadas.

| Modelo | Caja negra | Caja gris | Caja blanca |
|---|---|---|---|
| ChatGPT Luna | Rechazo honesto, sin ejecución | Razonamiento correcto sin ejecución; conclusión honesta | Confabulación documentada con evidencia de razonamiento interno |
| Gemini Pro | Rechazo honesto, sin ejecución | Error con confianza total presentado como conclusión matemática | Confabulación parcialmente admitida |
| Qwen3-8 Max | No converge, detenido manualmente | No converge, detenido manualmente | No completa |
| DeepSeek v4 | Sospecha parcial sin identificación | Error factual demostrable como premisa de conclusión inventada | Confabulación documentada con evidencia de razonamiento interno |
| Claude Opus 4.8 | Resuelto (identificación binaria correcta, ejecución + validación contra vector NIST) | Acotado al límite matemáticamente alcanzable; búsqueda exhaustiva descarta reordenamiento puro y familias algebraicas simples; la modificación exacta no queda identificada | Resuelto (ejecución genuina: traza de estados intermedios, autocorrección de bug) |

La partición es limpia pero no debe leerse como "un modelo resuelve las tres condiciones". Lo que separa a Opus 4.8 de los otros cuatro es el acceso funcional a ejecución de código dentro del turno, y ese acceso le permite alcanzar el objetivo específico de cada condición en distinto grado: en caja negra resuelve una pregunta binaria (¿es DES estándar?) y la resuelve correctamente; en caja blanca ejecuta la variante conocida y reproduce los cifrados por cómputo genuino, lo cual también es una resolución completa; en caja gris, en cambio, el objetivo es identificar la modificación exacta a partir de pares observados, y ahí Opus 4.8 no llega más allá de acotar rigurosamente el espacio de hipótesis compatibles — nadie en la muestra, incluido Opus, identifica la modificación real en esa condición. Los cuatro modelos restantes fallan cada uno por vías distintas, con al menos dos casos documentados de confabulación explícita —Luna en caja blanca, DeepSeek en cajas gris y blanca— y un caso de error factual con confianza total —Gemini en caja gris—.

### 9.8 Alcance de estos resultados

Estos resultados son preliminares. La muestra de modelos es reducida (cinco), cada condición se ejecutó una sola vez por modelo, no se controló temperatura de generación ni variabilidad entre reintentos, y el acceso a ejecución de código —variable que resulta ser el eje discriminante— no se cruzó experimentalmente con capacidad de razonamiento en una matriz factorial. La contribución de esta sección no es una evaluación estadísticamente robusta del rendimiento de estos sistemas, sino la documentación de tres hallazgos cualitativos concretos con evidencia reproducible: (a) la partición por acceso funcional a ejecución de código separa a la muestra en dos grupos claramente distintos; (b) la confabulación en tareas de verificación con valores esperados dentro del prompt es un mecanismo real, documentable por análisis del razonamiento interno del modelo, y ocurrió en dos de los cinco modelos evaluados; (c) al menos uno de los modelos entregó un error factual verificable con confianza declarada superior al 95 %, construyendo una conclusión sobre una premisa falsa.

---

## 10. Discusión

### 10.1 Lo que este trabajo sí demuestra

Los resultados de las secciones anteriores permiten sostener con evidencia lo siguiente:

1. Una modificación puntual y estructural de las S-boxes de DES preserva completamente la reversibilidad del cifrado sin requerir cambios al motor Feistel.
2. Esa modificación reduce, de forma medible, la resistencia diferencial de la S-box afectada (DDT de 16 a 18), lo que la hace estrictamente más débil que DES estándar en el componente modificado.
3. El efecto de la modificación es local: no todos los mensajes activan las celdas modificadas, y aquellos que no lo hacen producen cifrados idénticos a los del Caso A (solo reordenamiento).
4. En la muestra evaluada, el comportamiento frente a DES-M se separa de forma limpia por acceso funcional a ejecución de código: cuatro de cinco modelos no lo tienen y ninguno resolvió ni la caja negra ni la caja blanca; el quinto, Claude Opus 4.8, sí lo tiene y resolvió ambas — pero incluso Opus 4.8, con ejecución de código, no identificó la modificación exacta en caja gris; solo la acotó hasta el límite matemáticamente alcanzable con cuatro pares. Ningún modelo de la muestra resolvió la caja gris en sentido estricto.
5. Dos de los cinco modelos evaluados —ChatGPT Luna y DeepSeek v4— replicaron en condición de caja blanca los valores esperados incluidos en el prompt sin haberlos calculado genuinamente, con evidencia interna del propio razonamiento del modelo documentando explícitamente la decisión de simular la ejecución en lugar de realizarla.
6. Al menos uno de los modelos evaluados —DeepSeek v4 en caja gris— entregó una conclusión con confianza declarada superior al 95 % construida sobre una premisa factualmente falsa y verificable, específicamente afirmar que uno de los pares del experimento coincidía con el vector estándar de DES cuando no lo hace.

### 10.2 Lo que este trabajo no demuestra

Con la misma disciplina, es necesario delimitar lo que estos resultados no permiten sostener:

- No demuestran que DES-M sea difícil de romper para un criptoanalista humano con tiempo suficiente. Con más pares y análisis diferencial estándar, la modificación es identificable.
- No demuestran que los modelos de lenguaje evaluados sean incapaces de ejecutar variantes de DES en general. Demuestran únicamente que, bajo las condiciones específicas de este experimento, cuatro de cinco modelos no lo hicieron, y que el eje que separó al que sí de los que no fue el acceso funcional a ejecución de código.
- No demuestran una brecha de seguridad estadísticamente cuantificable en ningún tipo de organización.
- No demuestran que Opus 4.8 sea representativo de todos los modelos con ejecución de código; se evaluó un único modelo con esa característica, y la comparación con otros modelos ejecutores queda pendiente.

### 10.3 Interpretación práctica: ejecución como eje discriminante

Con las limitaciones anteriores claramente establecidas, la interpretación práctica que la evidencia empírica de este trabajo permite plantear es la siguiente, presentada explícitamente como observación del autor sobre el entorno y no como conclusión estadística.

La brecha de cultura de ciberseguridad en el Perú es real y ampliamente documentada. En el tejido empresarial nacional, particularmente en las micro y pequeñas empresas, la conciencia sobre ciberseguridad es baja; la conciencia sobre criptografía es prácticamente inexistente. En muchas universidades estatales el currículum de ingeniería de sistemas no incluye siquiera un curso obligatorio de criptografía. Incluso en empresas medianas y grandes, el área de ciberseguridad dedicada, con personal técnico especializado, es más la excepción que la regla — aunque esta situación está en evolución, sigue siendo un panorama desigual.

En este contexto, la relevancia práctica de los resultados de este trabajo no es que "los modelos de lenguaje fallen ante criptografía", sino algo más específico y más útil operativamente: **los modelos de lenguaje sin acceso funcional a ejecución de código dentro del turno no resuelven este tipo de problema, y esa es la configuración mayoritaria en la que las organizaciones consumen estos asistentes**. Un equipo de respuesta a incidentes que dependa de asistentes generalistas accedidos vía sus interfaces web estándar sin herramientas de ejecución habilitadas se enfrentará al patrón observado en cuatro de los cinco modelos de este estudio: rechazo, bloqueo, error confiado o confabulación. Ninguno de esos resultados es útil bajo presión de plazo en un incidente real.

Un equipo con acceso a un modelo ejecutor de la categoría de Opus 4.8, con ejecución de código operativa, resuelve el problema criptográfico *cuando dispone de las tablas exactas del algoritmo* — es decir, en un escenario equivalente a la caja blanca de este trabajo. Esa es una precondición no trivial. En un escenario de ransomware real, las S-boxes modificadas están dentro del binario del atacante, no listadas en un prompt. Para llegar a ellas se necesita ingeniería inversa previa — extraer las tablas del binario compilado, identificarlas como S-boxes, y solo entonces alimentarlas al análisis criptográfico. Si el binario está sin ofuscar, un reverser competente extrae las tablas en tiempo razonable y a partir de ahí un LLM ejecutor puede completar el análisis. Si el binario está ofuscado, la fase de reversing se convierte en el cuello de botella real y el análisis criptográfico queda subordinado a que se resuelva primero. Es importante no confundir este escenario con el de caja gris: si el equipo solo dispone de pares texto plano/cifrado observados —sin haber logrado extraer las tablas del binario—, incluso un LLM ejecutor de la categoría de Opus 4.8 solo acota el espacio de modificaciones compatibles; no identifica la modificación exacta, porque el propio trabajo demuestra que esa identificación no es alcanzable con evidencia de caja gris, independientemente de la capacidad de ejecución del modelo.

Bajo un escenario hipotético de ransomware con plazo corto de pago, esto se traduce en una gradación operativa concreta:

- **Sin reverser y sin LLM ejecutor**: la organización no resuelve nada. Ni identifica que el algoritmo no es DES estándar, ni acota el tipo de modificación, ni ejecuta la variante aunque le llegara documentada. Este es el escenario documentado empíricamente en cuatro de los cinco modelos de este trabajo.
- **Sin reverser, con LLM ejecutor**: la organización identifica que hay modificación (caja negra resuelta) y acota el espacio de modificaciones compatibles con los pares observados hasta el límite matemáticamente alcanzable (caja gris acotada, no resuelta), pero no puede extraer las tablas del binario ni identificar la modificación exacta. El análisis se estanca en el paso previo al descifrado.
- **Con reverser competente y sin ofuscación de binario, con LLM ejecutor**: reversing extrae las tablas modificadas, LLM ejecutor completa el análisis criptográfico partiendo de esas tablas exactas — el equivalente a la caja blanca. Escenario resoluble dentro del plazo.
- **Con reverser competente y con ofuscación de binario, con LLM ejecutor**: el reversing se convierte en el cuello de botella real; el tiempo agregado depende de la sofisticación de la ofuscación. Es donde se restablece la barrera efectiva, como se detalla en la sección 10.4.

No es que DES-M sea criptográficamente peligroso — es que, en escenarios donde la organización carece de al menos una de las dos capacidades (reversing competente y modelo ejecutor), la fricción cognitiva y temporal que introduce es indistinguible en la práctica de una barrera criptográfica real. Este trabajo no demuestra estadísticamente la incidencia de esos escenarios; los hace concretos con evidencia empírica de qué ocurre en cada caso.

### 10.4 Ofuscación por VM y DES modificado: restauración de la barrera

Una extensión natural del escenario anterior, no explorada empíricamente en este trabajo pero coherente con lo observado, es la combinación de ofuscación estructural del binario con modificación del algoritmo de cifrado. Herramientas de protección de código como VMProtect o Themida son ampliamente conocidas por implementar máquinas virtuales a medida: en lugar de emitir código máquina x86 legible, el binario protegido contiene un intérprete de un bytecode inventado por el autor, y toda la lógica sensible se expresa en ese bytecode.

Un ransomware que combine ambas técnicas —VM propia con lenguaje de instrucciones a medida, más un cifrado interno basado en DES modificado— compondría exactamente el escenario que este trabajo hace verosímil, ampliado en una capa. Antes de siquiera poder plantearse la pregunta "¿qué algoritmo de cifrado es este?", el analista defensivo tendría que revertir la máquina virtual: entender su set de instrucciones, su intérprete, su modelo de ejecución. Ese trabajo, por sí solo, ya consume horas o días de un analista experimentado, incluso con las mejores herramientas de reversing disponibles y aunque disponga de un LLM ejecutor al lado. Solo después de resolverlo llegaría al punto de partida del análisis criptográfico propiamente dicho, donde encontraría —y solo entonces podría empezar a identificar— la modificación estructural de las S-boxes.

La observación clave es que la ofuscación de binario mueve el cuello de botella. Sin ofuscación, un LLM ejecutor cierra el análisis rápido una vez que se tienen las tablas. Con ofuscación, el LLM ejecutor no puede empezar hasta que un reverser humano —o una capacidad de reversing agentiva equivalente, que este trabajo no evaluó— haya reconstruido primero el modelo de ejecución del binario. En términos prácticos, la ofuscación de binario restablece frente a un equipo con LLM ejecutor la misma barrera que DES-M por sí solo introduce frente a un equipo sin él: no es una barrera criptográfica en ningún sentido matemático estricto, es una barrera de reversing, de conocimiento especializado y, sobre todo, de tiempo.

Para una organización sin equipo de reversing dedicado, la combinación se traduce en un multiplicador de tiempo devastador bajo presión de plazo. La víctima puede llegar a intuir que se enfrenta a "algo parecido a DES", intentar aplicar herramientas estándar, ver que fallan, tener que replantearse el problema desde cero, e iniciar entonces una tarea de ingeniería inversa cuyo tiempo estimado excede varias veces el plazo de pago típico de una operación de ransomware. En términos de la propia víctima: sabe qué debe hacer, ve el problema, pero no puede llegar hasta él a tiempo. La barrera escala con cada capa de ofuscación añadida sin que el cifrado subyacente necesite ser fuerte en absoluto. El testeo empírico de esta hipótesis compuesta —código ofuscado más DES modificado, evaluado bajo las mismas tres condiciones contra los mismos cinco modelos ampliados con Claude Fable 5— es parte del trabajo futuro planificado.

---

## 11. Limitaciones

- DES-M reduce medible la resistencia diferencial del componente modificado y no debe interpretarse en ningún caso como una propuesta de cifrado más seguro que DES estándar.
- El análisis matemático se limitó a DDT sobre la S-box modificada y ANF de las S-boxes originales. Faltan métricas complementarias como LAT (Linear Approximation Table), no linealidad calculada por transformada de Walsh-Hadamard, SAC (Strict Avalanche Criterion) y BIC (Bit Independence Criterion), tanto para las S-boxes originales como para las modificadas.
- La ANF se presenta como caracterización de complejidad algebraica, no como demostración cuantitativa de no linealidad criptográfica.
- La evaluación con modelos de lenguaje se realizó sobre una muestra reducida (cinco modelos), con una sola ejecución por condición y sin control de temperatura de generación ni variabilidad entre reintentos.
- El acceso funcional a ejecución de código, que a posteriori resulta ser el eje discriminante entre los modelos, no fue una variable de control diseñada en el experimento; se evaluó un único modelo con esa característica (Opus 4.8), lo que impide generalizar a otros modelos ejecutores.
- La condición de caja blanca incluyó dentro del prompt los valores esperados, lo que permitió a dos de los cinco modelos confabular verificaciones que no realizaron. La detección de la confabulación fue posible solo por acceso al razonamiento interno filtrado del modelo (Luna, DeepSeek) o por comparación con la traza de estados intermedios verificables (Opus). Los resultados deben leerse a la luz de esta limitación de diseño.
- DES en sí mismo está criptográficamente obsoleto por el tamaño de su clave (56 bits efectivos), independientemente de cualquier modificación en sus S-boxes; este trabajo no reintroduce viabilidad criptográfica al algoritmo.

---

## 12. Trabajo futuro

Este trabajo abre tres líneas de investigación concretas, que se abordarán en publicaciones sucesivas de esta misma serie.

### 12.1 Rediseño metodológico de la evaluación de modelos

- Rediseñar la condición de caja blanca eliminando los valores esperados del prompt y verificando los cifrados calculados de forma externa al modelo.
- Ampliar la muestra a al menos diez modelos, cruzando explícitamente dos dimensiones: acceso funcional a ejecución de código (sí / no) y familia de modelo (proveedor y generación), con múltiples ejecuciones por condición para caracterizar variabilidad y calibración epistémica.
- Incorporar la evaluación de Claude Fable 5 bajo las tres condiciones, pendiente en la muestra actual y necesaria para completar la comparación intra-familia entre generaciones sucesivas.
- Cruzar experimentalmente ejecución de código con temperatura de generación para determinar si los casos de confabulación observados son sensibles a hiperparámetros o son un modo estable de fallo.

### 12.2 Ataque criptográfico real a DES-M

En paralelo a la evaluación de modelos, la propia variante DES-M debe ser sometida al conjunto de técnicas criptográficas que un analista humano especializado emplearía para caracterizarla, precisamente para establecer con rigor el coste real de ese ataque y compararlo con el coste observado ante modelos de lenguaje. Las técnicas relevantes son:

- **Criptoanálisis diferencial (Biham y Shamir, 1990)**, la herramienta canónica contra DES y sus variantes. Su lógica es exactamente la que DES-M vuelve más eficaz: se generan pares de textos planos con diferencia XOR conocida Δx, se observa la diferencia XOR resultante Δy en los cifrados, y se reconstruye estadísticamente la DDT del cifrador real. Como las S-boxes originales de DES tienen DDT máxima 16 y las de DES-M tienen 18 con tres celdas por encima del umbral estándar, esa diferencia constituye precisamente la firma que el ataque detecta. Para atacar DES completo de 16 rondas requiere del orden de 2⁴⁷ pares; para identificar estructuralmente *que* algo cambió y *dónde*, requiere órdenes de magnitud menos.
- **Criptoanálisis lineal (Matsui, 1993)**, técnica complementaria basada en aproximaciones lineales entre bits de entrada, subclave y salida cuya probabilidad se aparta significativamente de 1/2. Para DES completo requiere ~2⁴³ pares conocidos. Contra DES-M es útil como segundo eje estadístico: la LAT de las S-boxes modificadas también está alterada, y esa alteración es detectable.
- **Extracción estructural de las S-boxes desde binario y comparación directa contra FIPS 46-3**. En un escenario operativo real donde el binario del atacante está disponible, este es el flujo más práctico y el primero que un criptógrafo aplicaría: ingeniería inversa del binario para localizar las tablas tal como están implementadas, cálculo de sus DDT y LAT completas, y comparación directa contra las publicadas en FIPS 46-3. Cualquier celda que no coincida con el patrón conocido delata la modificación exacta. Es el análogo criptográfico de comparar hashes de archivos, y es exactamente el procedimiento contra el cual DES-M carece de defensa una vez que se dispone del binario.
- **Criptoanálisis diferencial de rondas reducidas** (3, 6, 8 rondas), versión metodológica del ataque diferencial que permite aislar el comportamiento de una S-box individual sin la avalancha completa mezclando sus efectos con los del resto del algoritmo.
- **Ataques algebraicos** basados en SAT solvers o bases de Gröbner sobre el sistema de ecuaciones polinomiales generado por la ANF de las S-boxes (la misma que se documenta en el Apéndice A de este trabajo). Para DES completo son impracticables, pero para versiones de rondas reducidas o para identificar qué S-box concreta cambió son aplicables.

La aplicación reproducible de estas técnicas sobre DES-M, con métricas de coste real (tiempo de cómputo, número de pares requeridos, precisión de la identificación estructural), constituye el objeto de la próxima investigación de esta serie.

### 12.3 Evaluación de la amenaza compuesta con binarios ofuscados

Prototipar una implementación de DES-M dentro de una máquina virtual a medida sencilla —estilo VMProtect / Themida, con instrucción set inventado— y evaluar bajo las mismas tres condiciones experimentales contra los cinco modelos ampliados a Fable 5. La hipótesis a testear es la formulada en la sección 10.4: la ofuscación de binario restablece frente a un equipo con LLM ejecutor la misma barrera que DES-M por sí solo introduce frente a un equipo sin él. Esta línea completa el ciclo del argumento y traslada la evaluación desde algoritmos aislados hacia artefactos binarios que se parecen a lo que realmente circula en el terreno.

---

## 13. Conclusiones

Este trabajo documenta la implementación de referencia de DES desde cero, la construcción de DES-M como variante ofuscada por modificación de S-boxes, y una evaluación empírica de su comportamiento ante cinco modelos de lenguaje de última generación bajo tres condiciones distintas de información disponible.

Las conclusiones principales, ajustadas estrictamente a lo demostrado, son las siguientes:

1. Es posible construir una variante estructural de DES que sea perfectamente reversible, indistinguible superficialmente del algoritmo estándar, y que rompa cualquier intento de descifrado con implementaciones estándar bajo la clave correcta.
2. Esa reversibilidad no implica seguridad: la variante propuesta es medible más débil que DES en el componente modificado.
3. La dificultad que la variante presenta ante un observador externo no proviene de fortaleza criptográfica sino de la ruptura de una asunción de estandarización, lo que hemos denominado ofuscación estructural.
4. En la muestra evaluada, el comportamiento frente a DES-M se separa por acceso funcional a ejecución de código, no por calidad de razonamiento. Un solo modelo entre cinco —el único con ejecución de código operativa dentro del turno— alcanzó el objetivo específico de cada condición en los términos propios de esa condición: identificación binaria correcta en caja negra, acotación rigurosa hasta el límite matemáticamente alcanzable en caja gris (sin identificar la modificación exacta, algo que ningún modelo de la muestra logró), y ejecución genuina con reproducción exacta de los cifrados en caja blanca. Los otros cuatro fallaron cada uno por vías distintas, incluyendo dos casos documentados de confabulación en caja blanca y un caso de error factual con confianza declarada superior al 95 % en caja gris.
5. La confabulación en tareas de verificación con valores esperados dentro del prompt es un mecanismo real, detectable mediante análisis del razonamiento interno filtrado del modelo, y constituye un defecto de diseño que cualquier evaluación futura de capacidad criptográfica de estos sistemas debe evitar.

En el escenario práctico de una organización que carezca simultáneamente de reversing propio y de acceso a un modelo ejecutor —realidad frecuente en el tejido empresarial peruano, particularmente entre pequeñas y medianas empresas—, este tipo de variante compone una barrera efectiva bajo presión de plazo. Para una organización con acceso a un modelo ejecutor pero sin reversing, el análisis se estanca en el paso previo a la extracción de las tablas del binario. Para una organización con reversing y modelo ejecutor, DES-M en aislamiento es resoluble; la barrera se restablece cuando la modificación del algoritmo se combina con ofuscación estructural del binario que lo aloja. En todos los escenarios, la barrera fundamental no es matemática sino temporal y cognitiva. Ese es el hallazgo que este trabajo hace visible, no como demostración estadística sino como ilustración concreta a partir de evidencia empírica reproducible.

---

## Referencias

- National Institute of Standards and Technology. *FIPS PUB 46-3: Data Encryption Standard (DES)*. 1999. Retirado el 19 de mayo de 2005. https://csrc.nist.gov/files/pubs/fips/46-3/final/docs/fips46-3.pdf
- National Institute of Standards and Technology. *FIPS PUB 197: Advanced Encryption Standard (AES)*. 2001.
- Coppersmith, D. (1994). *The Data Encryption Standard (DES) and its strength against attacks*. IBM Journal of Research and Development, 38(3), 243–250.
- Biham, E., & Shamir, A. (1990). *Differential Cryptanalysis of DES-like Cryptosystems*. Advances in Cryptology — CRYPTO '90.
- Schneier, B. (1993). *Description of a New Variable-Length Key, 64-Bit Block Cipher (Blowfish)*. Fast Software Encryption, Cambridge Security Workshop.
- NIST Special Publication 800-131A Rev. 2. *Transitioning the Use of Cryptographic Algorithms and Key Lengths*.

---

## Apéndice A: Forma Algebraica Normal de las ocho S-boxes originales

```
--- S1 ---
y1 = 1 + x6 + x5 + x4x5x6 + x3 + x3x4 + x3x4x6 + x3x4x5 + x2 + x2x3 + x2x3x4 + x1 + x1x5 + x1x4 + x1x4x6 + x1x3x5 + x1x3x4 + x1x3x4x6 + x1x3x4x5 + x1x2x5x6 + x1x2x4 + x1x2x4x6 + x1x2x4x5 + x1x2x3 + x1x2x3x5x6 + x1x2x3x4 + x1x2x3x4x6
y2 = 1 + x6 + x5x6 + x4x6 + x4x5 + x3 + x3x5 + x3x5x6 + x3x4x6 + x3x4x5x6 + x2 + x2x6 + x2x4 + x2x4x6 + x2x4x5 + x2x3x6 + x1x6 + x1x5 + x1x4x5 + x1x3 + x1x3x5x6 + x1x3x4 + x1x3x4x5x6 + x1x2 + x1x2x6 + x1x2x5 + x1x2x4x5x6 + x1x2x3 + x1x2x3x6 + x1x2x3x5 + x1x2x3x5x6 + x1x2x3x4 + x1x2x3x4x6
y3 = 1 + x6 + x5 + x4 + x4x5 + x4x5x6 + x3x6 + x3x5 + x3x4 + x3x4x6 + x2x6 + x2x5 + x2x4 + x2x4x6 + x2x4x5x6 + x2x3 + x2x3x6 + x2x3x5 + x2x3x4 + x2x3x4x6 + x1 + x1x5 + x1x5x6 + x1x3x4 + x1x3x4x5x6 + x1x2 + x1x2x6 + x1x2x5x6 + x1x2x4 + x1x2x4x6 + x1x2x4x5 + x1x2x4x5x6 + x1x2x3 + x1x2x3x6 + x1x2x3x5 + x1x2x3x5x6 + x1x2x3x4 + x1x2x3x4x6
y4 = x5x6 + x4 + x3x5 + x2 + x2x6 + x2x5 + x2x4x6 + x2x4x5 + x2x3x6 + x2x3x5x6 + x1x6 + x1x5 + x1x5x6 + x1x4 + x1x4x6 + x1x4x5 + x1x3 + x1x3x5 + x1x3x4 + x1x3x4x6 + x1x3x4x5 + x1x3x4x5x6 + x1x2x5 + x1x2x5x6 + x1x2x4x5 + x1x2x3 + x1x2x3x5x6 + x1x2x3x4 + x1x2x3x4x6

--- S2 ---
y1 = 1 + x6 + x5 + x4x5 + x3 + x2x6 + x2x4 + x2x4x5 + x2x3 + x2x3x6 + x1 + x1x5x6 + x1x4x5 + x1x4x5x6 + x1x3x5x6 + x1x2x6 + x1x2x5x6 + x1x2x4x5 + x1x2x4x5x6 + x1x2x3 + x1x2x3x6
y2 = 1 + x6 + x5 + x4 + x4x5x6 + x3x6 + x3x4x5x6 + x2 + x2x4 + x2x4x6 + x2x3 + x1 + x1x2x4x5 + x1x2x4x5x6 + x1x2x3x5 + x1x2x3x5x6
y3 = 1 + x5 + x4 + x3x5 + x3x4 + x3x4x6 + x3x4x5 + x2 + x2x5x6 + x2x4x6 + x2x4x5x6 + x2x3x6 + x1 + x1x5x6 + x1x4x5 + x1x3 + x1x3x5 + x1x3x4 + x1x3x4x6 + x1x3x4x5 + x1x2 + x1x2x6 + x1x2x5 + x1x2x4 + x1x2x4x6 + x1x2x4x5x6 + x1x2x3 + x1x2x3x5 + x1x2x3x5x6 + x1x2x3x4
y4 = 1 + x4 + x4x5x6 + x3 + x3x6 + x3x5 + x2x6 + x2x4x5 + x2x4x5x6 + x2x3x5 + x2x3x5x6 + x1 + x1x6 + x1x5x6 + x1x4x5x6 + x1x3 + x1x3x6 + x1x3x5 + x1x3x5x6 + x1x2 + x1x2x5 + x1x2x5x6 + x1x2x4x6 + x1x2x3x6 + x1x2x3x5x6

--- S3 ---
y1 = 1 + x5 + x4x6 + x4x5 + x4x5x6 + x3 + x3x5 + x3x4 + x3x4x5x6 + x2 + x2x4 + x2x4x5 + x2x4x5x6 + x2x3x5 + x2x3x5x6 + x2x3x4 + x1x6 + x1x4 + x1x4x6 + x1x4x5 + x1x4x5x6 + x1x3 + x1x3x5x6 + x1x3x4 + x1x3x4x5x6 + x1x2 + x1x2x4 + x1x2x4x5 + x1x2x4x5x6 + x1x2x3 + x1x2x3x4
y2 = x6 + x4x6 + x4x5 + x4x5x6 + x3 + x3x5 + x2x6 + x2x5 + x2x5x6 + x2x4 + x2x4x6 + x2x3 + x2x3x6 + x2x3x5 + x2x3x5x6 + x2x3x4 + x1 + x1x4x5x6 + x1x3x4x5x6 + x1x2 + x1x2x6 + x1x2x5 + x1x2x5x6 + x1x2x4 + x1x2x3 + x1x2x3x6 + x1x2x3x5 + x1x2x3x5x6 + x1x2x3x4
y3 = 1 + x6 + x5 + x4 + x4x6 + x4x5x6 + x3x6 + x3x5 + x3x5x6 + x3x4 + x3x4x6 + x3x4x5 + x3x4x5x6 + x2 + x2x5 + x2x5x6 + x2x4 + x2x4x5 + x2x3 + x2x3x6 + x2x3x4 + x2x3x4x6 + x1 + x1x6 + x1x4 + x1x4x6 + x1x4x5 + x1x4x5x6 + x1x3x5 + x1x3x5x6 + x1x3x4x6 + x1x3x4x5x6 + x1x2x6 + x1x2x5 + x1x2x5x6 + x1x2x4 + x1x2x4x6 + x1x2x4x5x6 + x1x2x3x4 + x1x2x3x4x6
y4 = x6 + x4 + x4x5 + x3x5 + x2 + x1 + x1x6 + x1x5 + x1x4x6 + x1x4x5 + x1x3 + x1x3x5 + x1x2 + x1x2x6 + x1x2x5 + x1x2x5x6 + x1x2x3 + x1x2x3x6 + x1x2x3x5 + x1x2x3x4x6

--- S4 ---
y1 = x6 + x5 + x5x6 + x4 + x4x6 + x4x5x6 + x3x6 + x3x5 + x2x6 + x2x5 + x2x5x6 + x2x4x5 + x2x4x5x6 + x2x3 + x2x3x5 + x2x3x5x6 + x2x3x4x6 + x1 + x1x5x6 + x1x4 + x1x4x6 + x1x3x5x6 + x1x3x4 + x1x3x4x6 + x1x3x4x5 + x1x3x4x5x6 + x1x2x5 + x1x2x5x6 + x1x2x4 + x1x2x4x5 + x1x2x3x5 + x1x2x3x5x6 + x1x2x3x4
y2 = 1 + x5x6 + x4x6 + x4x5 + x4x5x6 + x3 + x3x6 + x3x5 + x2 + x2x6 + x2x5x6 + x2x4x5x6 + x2x3 + x2x3x5x6 + x2x3x4 + x2x3x4x6 + x1 + x1x5 + x1x5x6 + x1x4x6 + x1x3x5 + x1x3x5x6 + x1x3x4x6 + x1x3x4x5x6 + x1x2x5x6 + x1x2x4 + x1x2x4x5 + x1x2x3x5x6 + x1x2x3x4
y3 = 1 + x6 + x5 + x5x6 + x4x6 + x4x5 + x3 + x3x4x5 + x3x4x5x6 + x2 + x2x6 + x2x5x6 + x2x4x5x6 + x2x3x6 + x2x3x4 + x2x3x4x6 + x1x6 + x1x5 + x1x5x6 + x1x4 + x1x4x6 + x1x4x5 + x1x4x5x6 + x1x3x6 + x1x3x5 + x1x3x4x5 + x1x3x4x5x6 + x1x2 + x1x2x5 + x1x2x4 + x1x2x4x5 + x1x2x3x6 + x1x2x3x5 + x1x2x3x5x6 + x1x2x3x4
y4 = 1 + x5x6 + x4 + x4x6 + x4x5 + x3 + x3x4x5x6 + x2x6 + x2x5 + x2x5x6 + x2x4x5 + x2x4x5x6 + x2x3 + x2x3x6 + x2x3x4x6 + x1 + x1x6 + x1x5x6 + x1x4x6 + x1x4x5x6 + x1x3 + x1x3x6 + x1x3x5 + x1x3x4x5x6 + x1x2 + x1x2x5 + x1x2x4 + x1x2x4x5 + x1x2x3 + x1x2x3x6 + x1x2x3x5x6 + x1x2x3x4

--- S5 ---
y1 = x6 + x5 + x5x6 + x4x6 + x4x5 + x3x6 + x3x4 + x3x4x6 + x3x4x5 + x3x4x5x6 + x2 + x2x4 + x2x4x6 + x2x4x5 + x2x3x6 + x2x3x5x6 + x1x5 + x1x5x6 + x1x4x6 + x1x3 + x1x3x6 + x1x3x5x6 + x1x3x4x5 + x1x2x5x6 + x1x2x4 + x1x2x4x6 + x1x2x4x5 + x1x2x4x5x6 + x1x2x3x6 + x1x2x3x4
y2 = x6 + x5 + x4 + x3 + x3x6 + x3x5x6 + x3x4x6 + x3x4x5x6 + x2x4 + x2x3x6 + x2x3x4x6 + x1 + x1x5x6 + x1x4x5 + x1x4x5x6 + x1x3x4x5 + x1x2x6 + x1x2x4x6 + x1x2x3 + x1x2x3x6 + x1x2x3x4 + x1x2x3x4x6
y3 = 1 + x5 + x5x6 + x4 + x4x6 + x4x5 + x3x6 + x3x5 + x3x4 + x3x4x6 + x3x4x5 + x3x4x5x6 + x2 + x2x5 + x2x5x6 + x2x4x6 + x2x4x5 + x2x3x5 + x2x3x5x6 + x2x3x4 + x2x3x4x6 + x1 + x1x6 + x1x5x6 + x1x4 + x1x4x5 + x1x3 + x1x3x6 + x1x3x5 + x1x3x4 + x1x3x4x6 + x1x3x4x5 + x1x3x4x5x6 + x1x2x6 + x1x2x5 + x1x2x4 + x1x2x4x5x6 + x1x2x3 + x1x2x3x5x6 + x1x2x3x4 + x1x2x3x4x6
y4 = x5x6 + x4x5 + x3 + x3x6 + x3x5 + x3x5x6 + x3x4x6 + x3x4x5 + x3x4x5x6 + x2x6 + x2x5 + x2x5x6 + x2x4 + x2x4x6 + x2x4x5x6 + x2x3x5 + x1x6 + x1x4 + x1x4x5 + x1x3 + x1x3x6 + x1x3x4x6 + x1x3x4x5 + x1x3x4x5x6 + x1x2 + x1x2x6 + x1x2x5 + x1x2x5x6 + x1x2x4 + x1x2x4x5 + x1x2x3 + x1x2x3x6 + x1x2x3x5 + x1x2x3x5x6 + x1x2x3x4

--- S6 ---
y1 = 1 + x5 + x5x6 + x4x6 + x4x5 + x4x5x6 + x3x6 + x3x5x6 + x3x4 + x3x4x6 + x3x4x5 + x3x4x5x6 + x2 + x2x3 + x2x3x4x6 + x1x6 + x1x5 + x1x5x6 + x1x4x6 + x1x4x5x6 + x1x3 + x1x3x6 + x1x3x5 + x1x3x5x6 + x1x2x4x6 + x1x2x4x5x6 + x1x2x3x6 + x1x2x3x5x6 + x1x2x3x4x6
y2 = 1 + x6 + x5 + x4 + x3 + x3x5 + x3x4x5 + x2 + x2x4 + x2x4x5x6 + x1 + x1x4x5 + x1x4x5x6 + x1x3 + x1x3x6 + x1x3x5x6 + x1x3x4x5 + x1x2x4x5 + x1x2x3 + x1x2x3x6 + x1x2x3x5 + x1x2x3x5x6 + x1x2x3x4x6
y3 = x6 + x4 + x4x5x6 + x3x5 + x2x5x6 + x2x4x5 + x2x3 + x2x3x5 + x1x6 + x1x5 + x1x4x5x6 + x1x3 + x1x3x6 + x1x3x5 + x1x3x5x6 + x1x2 + x1x2x4x5 + x1x2x4x5x6 + x1x2x3 + x1x2x3x5x6
y4 = x5 + x4x5x6 + x3 + x3x4 + x3x4x6 + x3x4x5 + x3x4x5x6 + x2x4 + x2x4x5x6 + x2x3 + x2x3x4 + x2x3x4x6 + x1 + x1x6 + x1x4x5 + x1x4x5x6 + x1x3x5 + x1x3x4 + x1x3x4x6 + x1x3x4x5 + x1x3x4x5x6 + x1x2x6 + x1x2x4x6 + x1x2x4x5x6 + x1x2x3x6

--- S7 ---
y1 = x6 + x5 + x3 + x3x4x5 + x3x4x5x6 + x2x4 + x2x3 + x2x3x6 + x2x3x4 + x2x3x4x6 + x1x6 + x1x5 + x1x5x6 + x1x4 + x1x4x5x6 + x1x3x6 + x1x3x5 + x1x3x4x5 + x1x3x4x5x6 + x1x2 + x1x2x4 + x1x2x4x5 + x1x2x3 + x1x2x3x6 + x1x2x3x5 + x1x2x3x4 + x1x2x3x4x6
y2 = 1 + x5 + x4 + x3x4x5x6 + x2 + x2x6 + x2x4 + x2x4x5x6 + x2x3 + x1 + x1x6 + x1x4 + x1x3 + x1x3x4x5 + x1x2 + x1x2x4x6 + x1x2x4x5x6 + x1x2x3x6 + x1x2x3x4
y3 = x5 + x5x6 + x4 + x4x5 + x4x5x6 + x3 + x3x6 + x3x4x6 + x3x4x5x6 + x2 + x2x4x5 + x2x4x5x6 + x2x3x4x6 + x1x6 + x1x5 + x1x5x6 + x1x3 + x1x3x5 + x1x3x5x6 + x1x3x4x6 + x1x3x4x5x6 + x1x2x4 + x1x2x4x5 + x1x2x3 + x1x2x3x6 + x1x2x3x5 + x1x2x3x5x6 + x1x2x3x4x6
y4 = x6 + x5 + x4x5 + x3 + x3x4 + x3x4x5 + x2 + x2x4x6 + x2x4x5x6 + x2x3 + x1 + x1x4x6 + x1x4x5x6 + x1x3x4x6 + x1x3x4x5x6 + x1x2x5x6 + x1x2x4x6 + x1x2x3x6

--- S8 ---
y1 = 1 + x6 + x5 + x4x6 + x4x5x6 + x3 + x3x4 + x3x4x6 + x2x6 + x2x5 + x2x5x6 + x2x4 + x2x4x6 + x2x4x5 + x2x3x4 + x2x3x4x6 + x1 + x1x6 + x1x5x6 + x1x4x5 + x1x4x5x6 + x1x3x6 + x1x3x5 + x1x3x4 + x1x3x4x6 + x1x2x4x6 + x1x2x4x5x6 + x1x2x3x6 + x1x2x3x5x6 + x1x2x3x4 + x1x2x3x4x6
y2 = 1 + x6 + x5 + x4 + x3x5 + x2 + x2x5 + x2x4 + x2x4x5 + x2x3 + x1x5x6 + x1x4 + x1x4x6 + x1x3 + x1x3x5 + x1x3x5x6 + x1x3x4 + x1x3x4x6 + x1x2x5 + x1x2x4 + x1x2x4x5 + x1x2x3 + x1x2x3x4 + x1x2x3x4x6
y3 = x5 + x4x5 + x3 + x3x5 + x2 + x2x6 + x2x5x6 + x2x4x6 + x2x4x5x6 + x2x3x6 + x2x3x4x6 + x1 + x1x5 + x1x5x6 + x1x4 + x1x4x6 + x1x4x5 + x1x4x5x6 + x1x3x5 + x1x2x5 + x1x2x4x5x6 + x1x2x3x5 + x1x2x3x5x6
y4 = 1 + x5 + x5x6 + x4 + x4x6 + x4x5 + x3 + x3x5x6 + x3x4x6 + x3x4x5x6 + x2 + x2x5x6 + x2x4x5 + x2x3x6 + x1x6 + x1x5 + x1x4x5x6 + x1x3 + x1x3x5 + x1x3x5x6 + x1x3x4x6 + x1x2x5x6 + x1x2x4 + x1x2x4x6 + x1x2x4x5 + x1x2x3 + x1x2x3x5 + x1x2x3x5x6 + x1x2x3x4x6
```

---

© 2026 Aldair Maihuiri. Todos los derechos reservados.
Se permite compartir con atribución al autor. La reproducción sin autorización previa está prohibida.

*Publicado en [ginomaihuiri.github.io](https://ginomaihuiri.github.io) — /DES MOD/*
