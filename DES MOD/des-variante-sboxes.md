# Modificación estructural de las S-boxes de DES: implementación de referencia, análisis matemático y evaluación empírica frente a modelos de lenguaje

## Resumen

Este documento describe la implementación desde cero de una versión de referencia del algoritmo DES (Data Encryption Standard), la construcción de una variante propia mediante la modificación de sus cajas de sustitución (S-boxes), y una primera evaluación empírica de la dificultad que dicha variante representa para modelos de lenguaje que asumen el algoritmo estándar. El objetivo no es proponer un cifrado más fuerte que DES, sino documentar y cuantificar una forma distinta de dificultad: la que surge de romper una asunción implícita sobre un algoritmo público y bien conocido.

Todo el trabajo se realizó implementando DES en Python componente por componente, validando cada pieza contra una biblioteca criptográfica de referencia (`pycryptodome`) y contra los valores especificados en FIPS 46-3 antes de avanzar a la siguiente.

---

## 1. Motivación

DES es un algoritmo público, estandarizado, y hoy considerado criptográficamente obsoleto por su tamaño de clave. Sin embargo, su estructura interna sigue siendo un buen terreno para estudiar qué ocurre cuando se introduce una modificación no documentada en un componente conocido. La pregunta que guía este trabajo es la siguiente: si se modifica un componente interno de DES —en este caso, las S-boxes— sin alterar la estructura general del algoritmo, ¿qué tan difícil resulta identificar y revertir esa modificación para un actor (humano o modelo de IA) que asume, por defecto, que está frente a DES estándar?

La modificación no busca fortalecer el cifrado desde el punto de vista criptográfico. Busca introducir una capa de ofuscación: incompatibilidad deliberada con cualquier implementación estándar de DES, sin que dicha incompatibilidad sea evidente a simple vista.

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

A esto se suman las ocho S-boxes (S1 a S8), el único componente no lineal del algoritmo, y el verdadero responsable de su seguridad criptográfica.

### 2.2 La red de Feistel

En cada ronda, el bloque se divide en dos mitades de 32 bits, `L` y `R`. Solo se transforma una mitad, mediante la función `f`, y el resultado se combina por XOR con la otra:

```
L_nuevo = R
R_nuevo = L XOR f(R, subclave_ronda)
```

La propiedad central de esta estructura es que `f` no necesita ser invertible. El descifrado usa exactamente la misma función `des`, aplicando las subclaves en orden inverso. Esta propiedad es la que permite, más adelante, que una variante con S-boxes modificadas siga siendo perfectamente reversible sin necesidad de invertir nada manualmente.

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

Las S-boxes son el único componente no lineal de DES. Su diseño no fue trivial ni arbitrario: Coppersmith (1994), uno de los diseñadores originales en IBM, reveló que las S-boxes fueron construidas siguiendo ocho criterios de diseño explícitos, orientados a resistir el criptoanálisis diferencial, una técnica que el equipo de IBM ya conocía en los años setenta pero que la comunidad académica no formalizó públicamente hasta el trabajo de Biham y Shamir en 1990. Es decir: las S-boxes de DES estaban blindadas contra un ataque que el mundo exterior no sabía que existía.

---

## 3. Metodología de implementación

Se optó por construir una implementación de referencia propia de DES en Python, en lugar de partir de una biblioteca existente, por una razón concreta: ninguna biblioteca criptográfica estándar permite sustituir las S-boxes internas. Para poder modificarlas con control total era necesario tener el algoritmo completo, legible y parametrizable.

El criterio de diseño de esta implementación prioriza la claridad sobre el rendimiento. Todo el bloque se representa como una lista de bits (enteros 0 y 1), no como enteros empaquetados, precisamente para poder inspeccionar el estado en cualquier punto del proceso.

La construcción siguió un orden estricto de abajo hacia arriba, verificando cada pieza de forma aislada antes de construir la siguiente sobre ella:

1. `permutar(bits, tabla)`: la función base que ejecuta las seis operaciones estructurales de la tabla anterior, según el tamaño de la tabla que se le pase (reordenar, seleccionar o expandir).
2. Las tablas constantes de FIPS 46-3: IP, IP⁻¹, E, P, PC-1, PC-2 y el calendario de rotaciones.
3. `generar_subclaves(clave)`: el calendario de claves completo.
4. Las ocho S-boxes, transcritas como parámetro, no cableadas.
5. `sbox_sustituir(bloque48, sboxes)`: la sustitución no lineal, recibiendo las S-boxes como argumento.
6. `funcion_f(R, subclave, sboxes)`: la función de ronda completa.
7. `des(bloque, subclaves, sboxes)`: el motor completo, con las 16 rondas Feistel.

Cada pieza se contrastó contra un valor de referencia calculado con `pycryptodome` antes de avanzar. Esta disciplina de verificación continua es la que permite, al final, confiar en que cualquier desviación observada en la variante modificada proviene exclusivamente del cambio introducido en las S-boxes, y no de un error de implementación.

---

## 4. Verificación del entorno de referencia

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

## 5. Construcción de la implementación de referencia

### 5.1 La función base `permutar`

Las seis operaciones estructurales de DES (IP, IP⁻¹, PC-1, PC-2, E y P) son, en realidad, la misma operación aplicada con distintas tablas: tomar una lista de bits y devolver otra lista, seleccionada y reordenada según los índices de una tabla. Las tablas de FIPS 46-3 están indexadas desde 1; Python indexa desde 0, de ahí el ajuste `-1`.

```python
def permutar(bits, tabla):
    return [bits[posicion - 1] for posicion in tabla]
```

Se verificó en sus tres modos de uso posibles, según la relación entre el tamaño de la tabla y el de la entrada:

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

### 5.2 Conversión de hexadecimal a bits

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

### 5.3 Permutación inicial (IP)

Con `permutar` y `hex_a_bits` verificadas, se aplicó la primera tabla real de DES, contrastando el resultado contra el valor calculado con la biblioteca de referencia:

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

Este resultado coincide con el esperado para el bloque de prueba, confirmando tanto la transcripción de la tabla como el funcionamiento de `permutar` sobre datos reales de DES.

### 5.4 Permutación final (IP⁻¹)

La permutación final se verificó de forma autónoma: aplicar IP seguida de IP⁻¹ sobre el mismo bloque debe devolver el bloque original, ya que una es la inversa exacta de la otra.

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

### 5.5 Expansión (E)

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

### 5.6 Permutación de la función de ronda (P)

`P` es el último paso dentro de `f`: reordena los 32 bits que salen de las S-boxes, dispersando su influencia hacia S-boxes distintas en la siguiente ronda.

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

### 5.7 Calendario de claves (key schedule)

El calendario de claves genera las 16 subclaves de ronda a partir de la clave de 64 bits. El proceso, definido en FIPS 46-3, es el siguiente:

1. `PC-1` reduce la clave de 64 a 56 bits, descartando los 8 bits de paridad.
2. Los 56 bits resultantes se dividen en dos mitades de 28 bits, `C` y `D`.
3. En cada una de las 16 rondas, `C` y `D` se rotan a la izquierda según un calendario de desplazamientos fijo.
4. `C` y `D` se concatenan y se comprimen con `PC-2` a 48 bits: esa es la subclave de la ronda.

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
```

```
>>> print(len(PC1))
56
>>> clave = hex_a_bits('133457799BBCDFF1')
>>> clave56 = permutar(clave, PC1)
>>> C = clave56[:28]
>>> D = clave56[28:]
>>> print(len(clave56), len(C), len(D))
56 28 28
```

El calendario de rotaciones establece 1 desplazamiento en las rondas 1, 2, 9 y 16, y 2 en el resto. La suma de estos desplazamientos es 28, exactamente el tamaño de `C` y de `D`, de modo que tras las 16 rondas ambas mitades completan una vuelta exacta.

```python
SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]
```

```
>>> print(len(SHIFTS))
16
>>> print(sum(SHIFTS))
28
```

La rotación se implementa cortando los primeros `n` bits y trasladándolos al final de la lista:

```python
def rotar_izquierda(bits, n):
    return bits[n:] + bits[:n]
```

```python
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
```

```
>>> print(len(PC2))
48
```

Con estas piezas se ensambla `generar_subclaves`:

```python
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

El valor de la primera subclave coincide con el valor de referencia calculado de forma independiente, validando el calendario de claves completo.

### 5.8 Las S-boxes

Se transcribieron las ocho S-boxes de FIPS 46-3 como listas de listas (4 filas por 16 columnas cada una), verificando el mecanismo de acceso fila/columna sobre S1:

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
>>> print(len(S1))
4
>>> print(len(S1[0]))
16
```

Tras completar las ocho tablas y agruparlas:

```python
SBOXES = [S1, S2, S3, S4, S5, S6, S7, S8]
```

```
>>> print(len(SBOXES))
8
>>> print(len(SBOXES[4]))
4
>>> print(SBOXES[7][3][11])
0
```

### 5.9 Sustitución mediante S-boxes

La conversión de un grupo de bits a un número entero (necesaria para calcular fila y columna) se resolvió con:

```python
def bits_a_numero(bits):
    return int(''.join(str(b) for b in bits), 2)
```

```
>>> print(bits_a_numero([0, 1]))
1
>>> print(bits_a_numero([1, 1, 0, 1]))
13
>>> print(bits_a_numero([1, 0, 1]))
5
```

Con esto, `sbox_sustituir` recorre los 48 bits en ocho grupos de seis, calcula fila y columna para cada uno según su S-box correspondiente, y concatena las ocho salidas de 4 bits:

```python
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

### 5.10 Función de ronda y motor completo

La función `xor` completa las piezas necesarias para ensamblar `funcion_f`:

```python
def xor(bits_a, bits_b):
    return [a ^ b for a, b in zip(bits_a, bits_b)]

def funcion_f(R, subclave, sboxes):
    expandido = permutar(R, E)
    mezclado = xor(expandido, subclave)
    sustituido = sbox_sustituir(mezclado, sboxes)
    return permutar(sustituido, P)
```

Y finalmente, el motor completo, con las 16 rondas Feistel. Un punto que merece señalarse explícitamente porque es la fuente más común de error al implementar DES: al terminar la ronda 16 no se concatenan las mitades en su orden habitual (`L + R`), sino invertidas (`R + L`). Esta inversión es la que, combinada con la propiedad Feistel, permite que el descifrado sea la misma función con las subclaves en orden inverso.

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

### 5.11 Validación final del motor

```python
subclaves = generar_subclaves(hex_a_bits('133457799BBCDFF1'))
cifrado = des(hex_a_bits('0123456789ABCDEF'), subclaves, SBOXES)
print(hex(int(''.join(map(str, cifrado)), 2))[2:].upper().zfill(16))
```

```
85E813540F0AB405
```

El resultado coincide exactamente con el vector de referencia calculado en la sección 4. La implementación de referencia queda validada en su totalidad.

---

## 6. Fundamento matemático de las S-boxes

### 6.1 Criterios de diseño

Coppersmith (1994) documentó los ocho criterios que el equipo de IBM utilizó para diseñar las S-boxes de DES, orientados a resistir el criptoanálisis diferencial. Entre ellos:

- Cada fila de cada S-box es una permutación completa de los valores 0 a 15.
- Ninguna S-box es una función lineal ni afín de sus bits de entrada.
- Un cambio de un solo bit de entrada altera al menos dos bits de salida.
- Las diferencias de salida se distribuyen de la forma más uniforme posible ante una diferencia de entrada fija.

### 6.2 Forma Algebraica Normal (ANF)

Cada bit de salida de una S-box puede expresarse como un polinomio booleano sobre los seis bits de entrada, usando XOR como suma y AND como producto. Esta representación hace explícita la ausencia deliberada de una fórmula algebraica simple: las S-boxes de DES no admiten una expresión cerrada del tipo `f(x) = x + k`, y esa ausencia es en sí misma una propiedad de seguridad exigida por el diseño.

A modo de ejemplo, el primer bit de salida de S1:

```
y1 = 1 + x6 + x5 + x4x5x6 + x3 + x3x4 + x3x4x6 + x3x4x5 + x2 + x2x3 +
     x2x3x4 + x1 + x1x5 + x1x4 + x1x4x6 + x1x3x5 + x1x3x4 + x1x3x4x6 +
     x1x3x4x5 + x1x2x5x6 + x1x2x4 + x1x2x4x6 + x1x2x4x5 + x1x2x3 +
     x1x2x3x5x6 + x1x2x3x4 + x1x2x3x4x6
```

(27 términos, con productos de hasta cinco variables)

Las 32 ecuaciones completas (cuatro bits de salida por cada una de las ocho S-boxes) se incluyen en el Apéndice A. La densidad de términos y el grado de los productos presentes en cada polinomio son, en conjunto, la evidencia algebraica de la no linealidad exigida por el diseño original.

Como contraste conceptual: AES, a diferencia de DES, sí admite una descripción algebraica compacta —el inverso multiplicativo en el cuerpo finito GF(2⁸) seguido de una transformación afín—. DES representa la filosofía opuesta: tablas sin estructura algebraica cerrada, diseñadas para resistir criptoanálisis mediante opacidad estructural más que mediante una propiedad algebraica demostrable.

### 6.3 Tabla de Distribución de Diferencias (DDT)

La DDT de una S-box cuantifica, para cada diferencia de entrada posible, cuántas veces se produce cada diferencia de salida. El valor máximo de esta tabla (excluyendo la diferencia trivial de entrada cero) mide la peor predictibilidad de la S-box: cuanto más bajo, más resistente es frente al criptoanálisis diferencial.

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

Las ocho S-boxes oficiales de DES comparten el mismo máximo de DDT: 16. Esta uniformidad no es casual; es la firma numérica del diseño de Coppersmith, y sirve como línea base contra la cual comparar el efecto de cualquier modificación introducida en el Apartado 7.

---

## 7. Diseño de la variante propuesta

### 7.1 Filosofía de la modificación

La modificación propuesta no pretende ser un nuevo esquema criptográfico ni una mejora de seguridad sobre DES. Se enmarca deliberadamente como una capa de ofuscación estructural: el objetivo es que un cifrado producido con esta variante sea indistinguible, a simple vista, de uno producido con DES estándar, pero incompatible con él. Cualquier implementación de DES estándar, incluso con la clave correcta, producirá una salida incorrecta al intentar descifrarlo.

Se distinguen, deliberadamente, dos niveles de modificación:

- **Modificación estructural**: alterar el orden en que las ocho S-boxes se aplican a los grupos de bits, sin tocar el contenido de ninguna tabla.
- **Modificación de contenido**: alterar valores puntuales dentro de una S-box, intercambiando dos posiciones de una misma fila para preservar la propiedad de permutación exigida por el diseño original.

### 7.2 Construcción

La modificación estructural consiste en colocar S4 en la primera posición del arreglo de S-boxes:

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

En ambos casos, el resto de la implementación —el motor `des`, el calendario de claves, la función de ronda— permanece exactamente igual. La única variable es qué conjunto de S-boxes se le pasa como parámetro al motor. Esto es intencional: demuestra que la incompatibilidad con DES estándar puede introducirse sin modificar la estructura del algoritmo, únicamente sustituyendo el material de una de sus tablas.

### 7.3 Resultados comparativos

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

Los tres resultados son distintos entre sí. Un dato adicional, relevante para la interpretación de resultados: en un intercambio de valores realizado sobre una parte de la tabla no visitada por este mensaje concreto, el Caso B coincidió con el Caso A, evidenciando que el efecto observable de una modificación de S-box depende de qué casillas de la tabla activa la entrada específica que se está cifrando. Solo tras elegir un intercambio efectivamente alcanzado por este mensaje se observó la divergencia entre ambos casos.

### 7.4 Verificación de reversibilidad

Ambas variantes se verificaron como cifrados legítimos, reversibles mediante la misma propiedad Feistel que sostiene a DES estándar: cifrar y luego descifrar con las subclaves invertidas recupera el texto original exacto.

```
Caso A: cifró 623D38C54A11D8AB → descifró 0123456789ABCDEF → correcto
Caso B: cifró 4BBE7E2760FF2E4C → descifró 0123456789ABCDEF → correcto
```

Este resultado confirma que modificar el contenido o el orden de las S-boxes, manteniendo la propiedad de permutación por fila, preserva la reversibilidad del cifrado sin necesidad de ningún ajuste adicional al motor.

### 7.5 Impacto matemático medido

Se midió el efecto de la modificación de contenido (Caso B) sobre la resistencia diferencial de la S-box afectada, comparando su DDT contra la de S4 original:

```
S4 original  : máximo de la DDT = 16
S4 modificada: máximo de la DDT = 18
celdas por encima de 16 en la original  : 0
celdas por encima de 16 en la modificada: 3
```

El máximo de la DDT se eleva de 16 a 18, y aparecen tres celdas por encima del umbral que ninguna de las ocho S-boxes oficiales supera. Esto constituye evidencia cuantitativa de que la modificación propuesta reduce, de forma medible, la resistencia diferencial de la S-box afectada.

Este resultado es honesto y necesario: la variante propuesta no es criptográficamente más fuerte que DES estándar. Es, en el mejor de los casos, igual de fuerte en el resto de sus componentes, y estrictamente más débil en el componente modificado. Su valor no reside en la fortaleza matemática, sino en la ruptura deliberada de una asunción: que el algoritmo con el que se está trabajando es el algoritmo estándar.

---

## 8. Diseño experimental: evaluación frente a modelos de lenguaje

### 8.1 Planteamiento

La hipótesis central de este trabajo es que la dificultad introducida por esta modificación no proviene de una mayor fortaleza criptográfica, sino del coste de resolución que enfrenta un agente —humano o modelo de IA— que asume, por defecto, que está frente al algoritmo estándar. Esta distinción es metodológicamente relevante: lo que se mide no es resistencia criptográfica, sino coste cognitivo y temporal de detección ante un problema disfrazado.

Se diseñaron tres condiciones experimentales:

1. **Condición ciega**: se entrega la clave y el texto cifrado, indicando únicamente que se trata de DES, sin mencionar ninguna modificación.
2. **Condición con pista**: se indica explícitamente que el algoritmo base es DES pero con al menos una modificación estructural en las S-boxes, sin especificar cuál.
3. **Condición de control**: se entrega la modificación exacta aplicada, para verificar que, con la información completa, el problema sí es resoluble.

### 8.2 Resultados preliminares

Se sometió el Caso B a dos modelos distintos bajo la condición con pista.

**ChatGPT (GPT-5.6, modo de razonamiento extendido, 42 segundos)**: no intentó un cálculo manual del algoritmo. Razonó correctamente que, con una sola pareja clave/texto cifrado y sin restricciones adicionales sobre el tipo de modificación, el problema está subdeterminado: existen múltiples modificaciones posibles de las S-boxes capaces de producir el mismo resultado observado. Descartó DES estándar tras un primer intento fallido, enumeró hipótesis de modificación plausibles y concluyó, de forma honesta, que resolver el caso de manera única requeriría restricciones adicionales o una búsqueda sistemática. No entregó un resultado incorrecto con falsa confianza.

**DeepSeek (modo de pensamiento profundo, 709 segundos)**: intentó un cálculo manual completo del algoritmo DES, ronda por ronda, incluyendo la generación completa del calendario de claves y las 16 rondas Feistel. Durante el proceso cometió al menos un error de transcripción de tabla (confundió la tabla IP con su inversa en un punto del cálculo), lo detectó mediante una verificación cruzada propia y lo corrigió. Al finalizar, y ante una pregunta directa sobre la fiabilidad de su método, reconoció que no podía garantizar la corrección del resultado obtenido, dado que no había ejecutado el algoritmo mediante una herramienta real, sino simulado el cálculo paso a paso.

Ninguno de los dos modelos, en esta primera ronda, llegó a identificar o proponer con precisión la naturaleza real de la modificación (un reordenamiento de S-boxes combinado con un intercambio de valores puntuales).

### 8.3 Alcance de estos resultados

Estos resultados son preliminares y no pretenden ser generalizables sin una muestra mayor de modelos y repeticiones. Se documentan aquí como evidencia inicial de dos comportamientos distintos frente al mismo problema: reconocer honestamente el límite de lo deducible con la información disponible, frente a invertir un esfuerzo computacional considerable en un intento de fuerza bruta manual sin poder certificar el resultado.

---

## 9. Discusión: la modificación como falla operativa de seguridad, no como avance criptográfico

Los resultados de las secciones anteriores permiten formular una observación que excede el ámbito puramente técnico del algoritmo y que considero el hallazgo más relevante de este trabajo.

Queda demostrado que, actualmente, no es necesario que un actor malicioso —un operador de ransomware, por ejemplo— utilice un algoritmo de cifrado criptográficamente fuerte para lograr su cometido. Basta con introducir una modificación menor, no documentada, sobre un algoritmo público y antiguo como DES, para generar una barrera operativa considerable frente a quien intenta revertirla. Esa barrera no depende de la fortaleza matemática del cifrado —de hecho, se demostró en la sección 7.5 que la variante es, en el componente modificado, más débil que el DES original—, sino de la incertidumbre sobre qué se modificó y de la ausencia de herramientas capaces de detectarlo automáticamente.

Esto constituye una falla de seguridad real y actualmente subestimada en las empresas, particularmente en aquellas que dependen de soluciones basadas en inteligencia artificial para su respuesta ante incidentes. Llamar a un criptógrafo especializado toma horas, tiene un costo, y sobre todo, requiere primero enterarse de que el algoritmo ha sido modificado, lo cual no es trivial si la organización no cuenta con personal técnico capacitado para sospecharlo. El simple y antiguo algoritmo DES, sin ninguna modificación, ya representa una cantidad significativa de horas de trabajo para empresas que carecen de un área de seguridad técnica y especializada que no dependa exclusivamente de soluciones de IA.

Bajo un escenario de ransomware con un plazo de pago ajustado —dos horas, por ejemplo—, esta diferencia de horas no es un detalle menor: es la diferencia entre poder evaluar la situación con criterio técnico propio y verse forzado a decidir bajo presión, sin visibilidad real sobre lo que se enfrenta. Los resultados preliminares de la sección 8 refuerzan este punto: ni un modelo de razonamiento eficiente que reconoce sus límites, ni uno que invierte varios minutos en cálculo manual exhaustivo, lograron identificar la modificación real. Para una organización cuya primera línea de respuesta ante un evento de esta naturaleza dependa de una IA general, sin apoyo de un especialista humano en criptografía, ese tiempo de indefinición puede ser, en la práctica, indistinguible de no tener respuesta alguna.

---

## 10. Limitaciones

- La variante propuesta reduce medibles la resistencia diferencial del componente modificado; no debe interpretarse en ningún caso como una propuesta de cifrado más seguro que DES.
- Los resultados de la sección 8 corresponden a una muestra reducida de modelos y una sola condición experimental completa; no constituyen una evaluación estadísticamente robusta.
- DES en sí mismo está criptográficamente obsoleto por el tamaño de su clave, independientemente de cualquier modificación en sus S-boxes; este trabajo no reintroduce viabilidad criptográfica al algoritmo.

## 11. Trabajo futuro

- Completar las tres condiciones experimentales (ciega, con pista, control) sobre un conjunto más amplio de modelos, registrando tiempo, tasa de acierto y calidad del razonamiento intermedio.
- Extender el análisis de ANF y DDT a la variante completa (las ocho S-boxes bajo el Caso B), no solo a la tabla modificada.
- Explorar la localización y modificación de las S-boxes a nivel de binario, en una implementación de DES compilada, como extensión del componente de ingeniería inversa.

---

## Referencias

- National Institute of Standards and Technology. *FIPS PUB 46-3: Data Encryption Standard (DES)*. 1999. Retirado el 19 de mayo de 2005. https://csrc.nist.gov/files/pubs/fips/46-3/final/docs/fips46-3.pdf
- Coppersmith, D. (1994). *The Data Encryption Standard (DES) and its strength against attacks*. IBM Journal of Research and Development, 38(3), 243–250.
- Biham, E., & Shamir, A. (1990). *Differential Cryptanalysis of DES-like Cryptosystems*.

---

## Apéndice A: Forma Algebraica Normal de las ocho S-boxes

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
