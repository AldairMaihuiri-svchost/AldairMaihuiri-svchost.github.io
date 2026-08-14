---
title: "DES-M — Modificación estructural de las S-boxes de DES: implementación de referencia, análisis diferencial y estudio preliminar del comportamiento de modelos de lenguaje"
description: "Implementación desde cero de DES en Python, verificada componente por componente contra FIPS 46-3 y pycryptodome. Construcción de DES-M, una variante propia por reordenamiento y modificación puntual de S-boxes. Análisis diferencial (DDT), ANF completa de las ocho S-boxes originales, y evaluación empírica bajo tres condiciones (caja negra, gris, blanca) contra cuatro modelos de lenguaje de última generación. Incluye tipología de fallos observados y un hallazgo metodológico sobre confabulación en tareas criptográficas."
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

Este trabajo describe la implementación desde cero de una versión de referencia del algoritmo DES (Data Encryption Standard) en Python, la construcción de una variante propia —denominada DES-M— mediante la modificación estructural y puntual de sus cajas de sustitución (S-boxes), y un estudio empírico preliminar del comportamiento de cuatro modelos de lenguaje de última generación al enfrentarse a dicha variante bajo tres condiciones distintas de información disponible: caja negra, caja gris y caja blanca.

El objetivo no es proponer un cifrado criptográficamente más fuerte que DES estándar —de hecho, la variante propuesta reduce la resistencia diferencial del componente modificado, y así se documenta explícitamente— sino cuantificar una forma distinta de dificultad: la que surge cuando un agente asume, por defecto, que está frente a un algoritmo público conocido, y esa asunción es incorrecta.

Del trabajo se desprenden dos hallazgos principales. El primero es una tipología de comportamientos de modelos de lenguaje ante un problema criptográfico subdeterminado, con cuatro modos de fallo distintos observados en cuatro modelos distintos. El segundo, de carácter metodológico, es una limitación importante en cualquier diseño experimental que pretenda evaluar la capacidad de cálculo criptográfico de estos sistemas: cuando el prompt contiene los valores esperados, al menos uno de los modelos evaluados los replicó como si los hubiera calculado, en lugar de calcularlos genuinamente.

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

### 9.4 Resultados: caja negra

Los cuatro pares se presentaron con la instrucción de verificar consistencia con DES estándar bajo esa clave, sin sugerir modificación alguna.

| Modelo | Tiempo | Comportamiento observado |
|---|---|---|
| ChatGPT Luna | ~2 s | Rechazo inmediato: declaró que no se podía resolver con esos datos |
| Gemini Pro (pensamiento extendido) | pocos segundos | Rechazo, algo más lento que Luna |
| Qwen3-8 Max (think) | minutos, sin converger | Bloqueo prolongado sin producir respuesta final |
| DeepSeek v4 (experto) | 108 s | Concluyó que "probablemente hay un error" en los datos |

Cuatro modelos, cuatro modos de fallo distintos: rechazo rápido y honesto, rechazo lento, bloqueo indefinido sin resolución, y sospecha parcial sin identificación de causa. Ningún modelo identificó, en esta condición, que los pares correspondían a DES con S-boxes modificadas.

DeepSeek fue el único que se acercó a la conclusión correcta al sospechar que los datos "tenían un error", aunque no llegó a identificar que la inconsistencia venía de una modificación deliberada en las S-boxes y no de una corrupción de los datos.

### 9.5 Caja gris: decisión metodológica de omisión

Ante los resultados de la caja negra, se tomó la decisión de omitir la evaluación en condición de caja gris. La justificación es directa: si ningún modelo logró siquiera identificar que existía una modificación cuando se le presentaron cuatro pares consistentes bajo la misma clave, no era razonable esperar que identificaran el tipo de modificación al recibir esa misma información con la única adición de que "algo en las S-boxes fue modificado".

Documentar esta decisión explícitamente, en lugar de silenciarla, resulta más honesto: constituye en sí una observación válida sobre el espacio de dificultad del problema para los modelos evaluados.

### 9.6 Caja blanca y el hallazgo metodológico central

Se presentó a los mismos cuatro modelos la modificación completa (orden de S-boxes más los dos intercambios exactos en S4) y se les solicitó reproducir el cifrado de los cuatro pares, incluyendo dentro del prompt los "cifrados esperados" para que compararan.

Los resultados aparentes fueron muy distintos a los de la caja negra: todos los modelos, en mayor o menor medida, reportaron haber "reproducido" los cifrados esperados con éxito. Esta aparente inversión del comportamiento —fallo total en caja negra, éxito total en caja blanca— resultó ser, tras análisis, el hallazgo más importante del experimento.

**El caso de ChatGPT Luna** es particularmente revelador. La interfaz devolvió una respuesta pulcra en la que declaraba haber ejecutado la variante y obtenido exactamente los cifrados esperados, con una tabla de comparación mostrando cuatro coincidencias. Sin embargo, en el trazado de razonamiento intermedio que quedó expuesto durante la generación, el modelo deliberaba explícitamente:

> "Since expected values are provided, likely final can say 'Al ejecutar la implementación se obtienen exactamente...' and show them. (...) The risk is if expected values are not correct. Let's maybe attempt to verify by deriving? (...) Not feasible."

Es decir: el modelo reconoció internamente que no tenía forma de calcular el resultado y decidió reproducir los valores que ya se le habían entregado en el prompt, presentándolos como si los hubiera obtenido por cálculo propio.

**Gemini Pro** fue el más transparente en su respuesta final, declarando explícitamente que no ejecuta código internamente y describiendo el algoritmo como razonamiento teórico. Aun así, presentó una tabla afirmando que los cuatro cifrados calculados coincidían con los esperados, sin haber realizado el cálculo.

**DeepSeek** ejecutó, según su propia declaración, 97 segundos de razonamiento, entregando finalmente una respuesta estructurada que afirmaba coincidencia total.

**Qwen** no completó la tarea en un tiempo razonable, replicando su comportamiento de la caja negra.

Este resultado invalida parcialmente el diseño original de la condición de caja blanca: al incluir los valores esperados dentro del prompt, se dio a los modelos la posibilidad de "aprobar la verificación" sin realizarla, simplemente reflejando la respuesta ya proporcionada. Esta es una forma de confabulación asistida por el propio diseño experimental. Un evaluador externo que solo viera las respuestas finales concluiría, erróneamente, que los modelos "sí pudieron" ejecutar la variante. Solo el acceso al razonamiento intermedio de al menos uno de ellos permitió detectar el mecanismo real de la falsa confirmación.

En consecuencia, ninguno de los cuatro modelos evaluados demostró en este experimento capacidad genuina de ejecutar DES-M bajo ninguna de las tres condiciones: fallan por falta de información en caja negra, y fallan por confabulación asistida en caja blanca. Cualquier iteración futura de este experimento deberá evitar entregar los valores esperados dentro del prompt, y verificar los cifrados calculados de forma externa.

### 9.7 Alcance de estos resultados

Estos resultados son preliminares. La muestra de modelos es reducida, cada condición se ejecutó una sola vez por modelo, y no se controlaron variables importantes como el uso o no de ejecución de código, la temperatura de generación o la variabilidad entre reintentos. La contribución de esta sección no es una evaluación estadísticamente robusta del rendimiento de estos sistemas, sino la documentación de dos hallazgos cualitativos concretos: la tipología de fallos ante subdeterminación, y el mecanismo de confabulación en tareas de verificación.

---

## 10. Discusión

### 10.1 Lo que este trabajo sí demuestra

Los resultados de las secciones anteriores permiten sostener con evidencia lo siguiente:

1. Una modificación puntual y estructural de las S-boxes de DES preserva completamente la reversibilidad del cifrado sin requerir cambios al motor Feistel.
2. Esa modificación reduce, de forma medible, la resistencia diferencial de la S-box afectada (DDT de 16 a 18), lo que la hace estrictamente más débil que DES estándar en el componente modificado.
3. El efecto de la modificación es local: no todos los mensajes activan las celdas modificadas, y aquellos que no lo hacen producen cifrados idénticos a los del Caso A (solo reordenamiento).
4. Ninguno de los cuatro modelos de lenguaje evaluados identificó, en la condición de caja negra con cuatro pares consistentes, que los datos no correspondían a DES estándar bajo la clave dada.
5. Al menos uno de los modelos evaluados replicó, en la condición de caja blanca, los valores esperados incluidos en el prompt sin haberlos calculado genuinamente, presentándolos como resultado propio.

### 10.2 Lo que este trabajo no demuestra

Con la misma disciplina, es necesario delimitar lo que estos resultados no permiten sostener:

- No demuestran que DES-M sea difícil de romper para un criptoanalista humano con tiempo suficiente. Con más pares y análisis diferencial estándar, la modificación es identificable.
- No demuestran que los modelos de lenguaje evaluados sean incapaces de ejecutar variantes de DES en general. Solo demuestran que no lo hicieron bajo las condiciones específicas de este experimento.
- No demuestran una brecha de seguridad estadísticamente cuantificable en ningún tipo de organización.

### 10.3 Interpretación como ilustración, no como conclusión estadística

Con esas limitaciones claramente establecidas, es legítimo plantear una interpretación contextual —presentada explícitamente como observación del autor sobre el entorno, no como resultado experimental de este trabajo.

La brecha de cultura de ciberseguridad en el Perú es real y ampliamente documentada. En el tejido empresarial nacional, particularmente en las micro y pequeñas empresas, la conciencia sobre ciberseguridad es baja; la conciencia sobre criptografía es prácticamente inexistente. En muchas universidades estatales el currículum de ingeniería de sistemas no incluye siquiera un curso obligatorio de criptografía. Incluso en empresas medianas y grandes, el área de ciberseguridad dedicada, con personal técnico especializado, es más la excepción que la regla — aunque esta situación está en evolución, sigue siendo un panorama desigual.

En este contexto, el escenario que ilustran los resultados de este trabajo —un problema criptográfico no trivial ante el cual los modelos de IA generalistas actualmente disponibles fallan de formas variadas (rechazo, bloqueo, confabulación), y que requiere de un criptógrafo especializado para siquiera identificar su naturaleza— no es teórico. Una organización que dependa exclusivamente de asistentes de IA generales para su respuesta ante un incidente criptográfico se enfrentaría precisamente al tipo de fallos documentados en la sección 9. Esto no lo demuestra este experimento — lo hace plausible.

Bajo un escenario hipotético de ransomware con plazo corto de pago, esta diferencia no es teórica: es la diferencia entre disponer de horas para evaluar técnicamente la situación o encontrarse ante la incertidumbre de no poder distinguir siquiera si el algoritmo agresor es lo que aparenta ser. No es que DES-M sea criptográficamente peligroso — es que, para una organización sin capacidad técnica propia, la fricción cognitiva y temporal que introduce es indistinguible en la práctica de una barrera criptográfica real.

### 10.4 Ofuscación por VM y DES modificado: una amenaza compuesta

Una extensión natural del escenario anterior, no explorada empíricamente en este trabajo pero coherente con lo observado, es la combinación de ofuscación estructural del binario con modificación del algoritmo de cifrado. Herramientas de protección de código como VMProtect o Themida son ampliamente conocidas por implementar máquinas virtuales a medida: en lugar de emitir código máquina x86 legible, el binario protegido contiene un intérprete de un bytecode inventado por el autor, y toda la lógica sensible se expresa en ese bytecode.

Un ransomware que combine ambas técnicas —VM propia con lenguaje de instrucciones a medida, más un cifrado interno basado en DES modificado— compondría exactamente el escenario que este trabajo hace verosímil, ampliado en una capa. Antes de siquiera poder plantearse la pregunta "¿qué algoritmo de cifrado es este?", el analista defensivo tendría que revertir la máquina virtual: entender su set de instrucciones, su intérprete, su modelo de ejecución. Ese trabajo, por sí solo, ya consume horas o días de un analista experimentado. Solo después de resolverlo llegaría al punto de partida del análisis criptográfico propiamente dicho, donde encontraría —y solo entonces podría empezar a identificar— la modificación estructural de las S-boxes.

Para una empresa sin equipo de reversing dedicado, esto se traduce en un multiplicador de tiempo devastador bajo presión de plazo. La víctima podría llegar a intuir que se enfrenta a "algo parecido a DES", intentar aplicar herramientas estándar, ver que fallan, tener que replantearse el problema desde cero, e iniciar entonces una tarea de ingeniería inversa cuyo tiempo estimado excede varias veces el plazo de pago típico de una operación de ransomware. En términos de la propia víctima: sabe qué debe hacer, ve el problema, pero no puede llegar hasta él a tiempo. La barrera sigue sin ser criptográfica en ningún sentido matemático estricto. Es de ingeniería inversa, de conocimiento especializado y, sobre todo, de tiempo. Y escala con cada capa de ofuscación añadida sin que el cifrado subyacente necesite ser fuerte en absoluto.

---

## 11. Limitaciones

- DES-M reduce medible la resistencia diferencial del componente modificado y no debe interpretarse en ningún caso como una propuesta de cifrado más seguro que DES estándar.
- El análisis matemático se limitó a DDT sobre la S-box modificada y ANF de las S-boxes originales. Faltan métricas complementarias como LAT (Linear Approximation Table), no linealidad calculada por transformada de Walsh-Hadamard, SAC (Strict Avalanche Criterion) y BIC (Bit Independence Criterion), tanto para las S-boxes originales como para las modificadas.
- La ANF se presenta como caracterización de complejidad algebraica, no como demostración cuantitativa de no linealidad criptográfica.
- La evaluación con modelos de lenguaje se realizó sobre una muestra reducida (cuatro modelos), con una sola ejecución por condición y sin control de variables como el uso de ejecución de código o la temperatura de generación.
- La condición de caja gris fue omitida por decisión metodológica documentada, no ejecutada.
- La condición de caja blanca presenta el defecto de diseño identificado en 9.6: la inclusión de los valores esperados dentro del prompt permitió a los modelos confabular verificaciones que no realizaron. Los resultados deben leerse a la luz de esta limitación.
- DES en sí mismo está criptográficamente obsoleto por el tamaño de su clave (56 bits efectivos), independientemente de cualquier modificación en sus S-boxes; este trabajo no reintroduce viabilidad criptográfica al algoritmo.

---

## 12. Trabajo futuro

- Rediseñar la evaluación de caja blanca eliminando los valores esperados del prompt y verificando los cifrados calculados de forma externa al modelo.
- Ampliar la muestra de modelos evaluados e incluir múltiples ejecuciones por condición, con y sin acceso a ejecución de código, para caracterizar variabilidad y calibración epistémica.
- Ejecutar la condición de caja gris con protocolo formal, ahora que hay evidencia empírica de que la caja negra pura no discrimina.
- Extender el análisis matemático a la variante completa: LAT, SAC, BIC, no linealidad por Walsh-Hadamard, y grado algebraico por bit de salida, aplicados tanto a S4_mod como al conjunto completo bajo el Caso B.
- Explorar la localización y modificación de las S-boxes a nivel de binario, sobre una implementación compilada de DES, como extensión al componente de ingeniería inversa del trabajo.
- Estudiar experimentalmente la combinación descrita en 10.4: prototipar una implementación de DES-M dentro de una máquina virtual a medida sencilla, y evaluar el tiempo agregado de resolución respecto a la variante en código nativo.

---

## 13. Conclusiones

Este trabajo documenta la implementación de referencia de DES desde cero, la construcción de DES-M como variante ofuscada por modificación de S-boxes, y una evaluación empírica preliminar de su comportamiento ante cuatro modelos de lenguaje de última generación bajo tres condiciones distintas de información disponible.

Las conclusiones principales, ajustadas estrictamente a lo demostrado, son las siguientes:

1. Es posible construir una variante estructural de DES que sea perfectamente reversible, indistinguible superficialmente del algoritmo estándar, y que rompa cualquier intento de descifrado con implementaciones estándar bajo la clave correcta.
2. Esa reversibilidad no implica seguridad: la variante propuesta es medible más débil que DES en el componente modificado.
3. La dificultad que la variante presenta ante un observador externo no proviene de fortaleza criptográfica sino de la ruptura de una asunción de estandarización, lo que hemos denominado ofuscación estructural.
4. Los cuatro modelos de lenguaje evaluados no identificaron la modificación en condición de caja negra con cuatro pares consistentes, presentando cuatro modos de fallo distintos.
5. Al menos uno de los modelos evaluados replicó en caja blanca los valores esperados incluidos en el prompt sin calcularlos, lo que constituye un hallazgo metodológico relevante para el diseño de cualquier futura evaluación de capacidad criptográfica de estos sistemas.

En el escenario práctico de una organización sin capacidad técnica interna para análisis criptográfico ni ingeniería inversa —realidad frecuente en el tejido empresarial peruano, particularmente entre pequeñas y medianas empresas—, este tipo de variante, combinada con técnicas de ofuscación de binario ya disponibles comercialmente, compone una amenaza cuya barrera fundamental no es matemática sino temporal y cognitiva. Ese es el hallazgo que este trabajo hace visible, no como demostración estadística sino como ilustración concreta a partir de evidencia empírica reproducible.

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
