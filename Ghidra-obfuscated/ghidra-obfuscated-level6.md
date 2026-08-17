---
title: "Ghidra contra binarios ofuscados — Nivel 6: máquina de estados y entrega de payload binario"
description: "Sexto nivel de la serie de entrenamiento en Ghidra sobre binarios ofuscados. Un crackme PE32+ que valida la contraseña mediante una máquina de estados con rotaciones de bits y constantes tipo hash, alimentada por un desbordamiento de buffer en la pila que reparte los diez bytes de la entrada entre variables locales separadas. Romper el algoritmo con Z3 fue solo la mitad del problema: la clave solución contiene bytes no imprimibles que ni el teclado ni una tubería de Wine pueden transmitir sin corromperse."
author: Aldair Maihuiri
---

# Ghidra contra binarios ofuscados — Nivel 6: máquina de estados y entrega de payload binario

**Gino Aldair Maihuiri Romero**

([English version](ghidra-obfuscated-level6-en)) · ([Nivel 1](ghidra-obfuscated-level1)) · ([Nivel 2](ghidra-obfuscated-level2)) · ([Nivel 3](ghidra-obfuscated-level3)) · ([Nivel 4](ghidra-obfuscated-level4)) · ([Nivel 5](ghidra-obfuscated-level5))

Este nivel requiere un tipo de comprensión distinta a los cinco anteriores, y quiero ser preciso sobre en qué sentido lo es. No es el binario más difícil de leer de la serie —la función de validación cabe en una sola pantalla y no hay vtables, ni tablas de fábricas, ni C++ de por medio—, pero es el primero donde encontrar el algoritmo correcto y resolverlo matemáticamente no es suficiente para terminar el trabajo. La clave que exige el binario resultó ser una secuencia de diez bytes crudos, varios de ellos fuera del rango de caracteres imprimibles, y hacer que esos bytes exactos lleguen intactos a la entrada estándar de un ejecutable de Windows corriendo bajo Wine terminó siendo un problema tan real como el propio criptoanálisis. Ese tramo final —el de ingeniería de la entrega, no del algoritmo— es la parte que más vale la pena documentar bien aquí, porque es donde más tropecé.

Mismo entorno de siempre: Linux, PE32+ de Windows, análisis estático en Ghidra primero, verificación con Wine al final.

---

## Reconocimiento y hallazgo directo

Esta vez fui directo a `Defined Strings` desde el principio, sin pasar por `strncmp` ni por ningún desvío de C++. Encontré `"Password: "` en `140004050`, con una única referencia a `FUN_140001580`. Esa función es toda la lógica del crackme:

```c
undefined8
FUN_140001580(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4)
{
  uint uVar1;
  char cVar2;
  FILE *pFVar3;
  char *pcVar4;
  size_t sVar5;
  uint local_4c;
  byte local_48 [4];
  byte local_44;
  undefined1 local_43;
  undefined1 local_42;
  byte local_41;
  byte local_40;
  byte local_3f;

  FUN_140001820();
  FUN_140002a40("Password: ",param_2,param_3,param_4);
  pFVar3 = (FILE *)__acrt_iob_func(1);
  fflush(pFVar3);
  pFVar3 = (FILE *)__acrt_iob_func(0);
  pcVar4 = fgets((char *)local_48,0x40,pFVar3);
  if (pcVar4 != (char *)0x0) {
    sVar5 = strcspn((char *)local_48,"\n");
    local_48[sVar5] = 0;
    sVar5 = strlen((char *)local_48);
    local_4c = 0;
    cVar2 = '\0';
    do {
      switch(cVar2) {
      case '\0':
        if ((int)sVar5 == 10) {
          local_4c = 0x1234abcd;
          cVar2 = '\x01';
        }
        else {
          cVar2 = '\x06';
        }
        break;
      case '\x01':
        local_4c = local_4c ^ ((uint)local_48[0] << 0x18 | (uint)local_48[1] << 0x10);
        local_4c = local_4c << 7 | local_4c >> 0x19;
        cVar2 = '\x02';
        break;
      case '\x02':
        uVar1 = local_4c + (uint)local_48[2] * 0x1337 + (uint)local_48[3] * 0xbeef ^ (uint)local_44;
        local_4c = uVar1 >> 3 | uVar1 << 0x1d;
        cVar2 = '\x03';
        break;
      case '\x03':
        local_4c = (local_4c ^ CONCAT11(local_43,local_42)) * 0x1000193 ^ (uint)local_41;
        cVar2 = '\x04';
        break;
      case '\x04':
        local_4c = local_4c + (uint)local_40 * 7 + (uint)local_3f * 0xd;
        local_4c = local_4c ^ local_4c >> 0x10;
        cVar2 = (local_4c != 0xeb42f0aa) + '\x05';
        break;
      case '\x05':
        puts("[+] Correcto!");
        return 0;
      default:
        puts("[-] Incorrecto.");
        return 1;
      }
    } while( true );
  }
  return 1;
}
```

Un solo salto desde el string me dejó frente a toda la validación. La complejidad de este nivel no está en llegar hasta aquí, está en lo que hay dentro.

## El buffer que Ghidra ve mal a propósito

Lo primero que llama la atención es la firma de las variables locales:

```c
uint local_4c;
byte local_48 [4];
byte local_44;
undefined1 local_43;
undefined1 local_42;
byte local_41;
byte local_40;
byte local_3f;
```

`local_48` está declarado como un arreglo de solo 4 bytes, pero la lectura es `fgets((char *)local_48,0x40,pFVar3)` — hasta 64 bytes. Y la condición de entrada exige `sVar5 == 10`, es decir, exactamente diez caracteres. Eso es más de lo que cabe en los 4 bytes que Ghidra le asignó a `local_48`.

La explicación está en cómo se ordenan las variables locales en la pila: `local_48`, `local_44`, `local_43`, `local_42`, `local_41`, `local_40` y `local_3f` son direcciones contiguas y consecutivas en memoria —los nombres en hexadecimal casi lo delatan: 0x48, 0x44, 0x43, 0x42, 0x41, 0x40, 0x3f, cada uno un byte más cerca del tope de la pila que el anterior—. Cuando `fgets` escribe diez bytes empezando en `local_48`, los primeros cuatro caen dentro del arreglo declarado, y los seis restantes se derraman sobre las variables vecinas, una por una:

```
local_48[0..3]  → bytes 0-3 de la entrada
local_44        → byte 4
local_43        → byte 5
local_42        → byte 6
local_41        → byte 7
local_40        → byte 8
local_3f        → byte 9
```

Ghidra no está equivocado al declarar `local_48` de 4 bytes —esa es la única cantidad de memoria que el compilador reservó bajo ese nombre—; lo que pasa es que el resto del buffer de diez bytes vive repartido en variables que Ghidra nombró por separado porque nunca vio una declaración de arreglo de diez bytes en el código fuente original. El programa entero, sin embargo, sí trata esos siete nombres como un único buffer contiguo, y hay que hacer lo mismo para entender la validación: hay que leer `local_48[0]`, `local_48[1]`, `local_48[2]`, `local_48[3]`, `local_44`, `local_43`, `local_42`, `local_41`, `local_40`, `local_3f` como los diez bytes 0 a 9 de la entrada del usuario, en ese orden.

## La máquina de estados

El `switch` dentro del `do { } while(true)` implementa una máquina de estados de seis pasos, controlada por `cVar2`. Cada estado consume un par de bytes de la entrada y transforma un acumulador de 32 bits, `local_4c`, que arranca en `0x1234abcd`:

- **Estado 0** — valida que la longitud sea exactamente 10; si no, salta directo al estado por defecto (falla).
- **Estado 1** — combina los bytes 0 y 1 con un XOR posicional (`byte0 << 24 | byte1 << 16`) contra el acumulador, y rota el resultado 7 bits a la izquierda.
- **Estado 2** — multiplica el byte 2 por `0x1337` y el byte 3 por `0xbeef`, suma ambos productos al acumulador, aplica XOR con el byte 4, y rota el resultado 3 bits a la derecha.
- **Estado 3** — concatena los bytes 5 y 6 en un valor de 16 bits (`CONCAT11` en la notación de Ghidra: el primer argumento como byte alto, el segundo como byte bajo), hace XOR con el acumulador, multiplica todo por `0x1000193` —el primo estándar de FNV-1a, aunque aquí la estructura completa ya no es un FNV-1a genérico, es una mezcla propia— y aplica XOR con el byte 7.
- **Estado 4** — multiplica el byte 8 por 7 y el byte 9 por `0xd`, suma ambos al acumulador, hace XOR del resultado consigo mismo desplazado 16 bits a la derecha, y compara el valor final contra la constante `0xeb42f0aa`.
- **Estado 5 / por defecto** — imprime el mensaje de éxito o de error según el resultado de esa comparación.

No es un algoritmo de hash publicado y reconocible como el FNV-1a del nivel 4 —usa una de sus constantes, pero la mezcla de rotaciones, multiplicaciones por constantes arbitrarias (`0x1337`, `0xbeef`, `7`, `0xd`) y XORs posicionales es una construcción propia del autor del crackme. Eso no cambia la estrategia de resolución: sigue siendo una cadena de operaciones reversibles en cada paso individual, pero encadenadas de una forma que no vale la pena despejar a mano término por término.

## Resolviendo con Z3

Con seis pasos de mezcla de bits, rotaciones y productos por constantes, plantear la ecuación inversa a mano es exactamente el tipo de trabajo que un solver SMT hace mejor que una persona. Modelé los diez bytes de la contraseña como variables simbólicas de 8 bits, reproduje cada estado de la máquina como una operación sobre esas variables, y le pedí a Z3 que encontrara una asignación que hiciera que el acumulador final fuera igual a `0xeb42f0aa`.

El primer intento no encontró solución, y la razón fue un detalle de precisión que es fácil pasar por alto al traducir C a Z3: en el código original, `local_4c` es `uint` — sin signo —, así que sus desplazamientos a la derecha (`>>`) son lógicos, rellenan con ceros. El operador `>>` de Z3 sobre un `BitVec`, en cambio, es aritmético por defecto: preserva el bit más significativo como si fuera de signo. Para las rotaciones y el desplazamiento final del estado 4, eso produce un resultado distinto al del binario real en cuanto el bit alto queda en 1. La corrección es usar `LShR` (*logical shift right*) en vez de `>>` en cada lugar donde el código C opera sobre un entero sin signo.

Con esa corrección, el script sí encontró una solución — pero una inválida en la práctica: contenía un byte `0x00` en una de las posiciones intermedias. El binario lee la entrada con `fgets` y mide su longitud con `strlen`, y `strlen` se detiene en el primer byte nulo. Una contraseña con un `0x00` en el medio no mide diez bytes para `strlen`, sin importar cuántos bytes reales se hayan escrito — la validación de longitud del estado 0 fallaría antes de llegar a la máquina de estados. Añadí la restricción `p != 0` para cada byte simbólico y volví a resolver.

```python
from z3 import *

password = [BitVec(f'p_{i}', 8) for i in range(10)]

def rol(val, r):
    return (val << r) | LShR(val, (32 - r))

def ror(val, r):
    return LShR(val, r) | (val << (32 - r))

local_4c = BitVecVal(0x1234abcd, 32)

# Estado 1
part1 = ZeroExt(24, password[0]) << 24 | ZeroExt(24, password[1]) << 16
local_4c = local_4c ^ part1
local_4c = rol(local_4c, 7)

# Estado 2
p2 = ZeroExt(24, password[2]) * 0x1337
p3 = ZeroExt(24, password[3]) * 0xbeef
p4 = ZeroExt(24, password[4])
uVar1 = local_4c + p2 + p3 ^ p4
local_4c = ror(uVar1, 3)

# Estado 3
concat_5_6 = ZeroExt(24, password[5]) << 8 | ZeroExt(24, password[6])
p7 = ZeroExt(24, password[7])
local_4c = (local_4c ^ concat_5_6) * 0x1000193 ^ p7

# Estado 4
p8 = ZeroExt(24, password[8])
p9 = ZeroExt(24, password[9])
local_4c = local_4c + p8 * 7 + p9 * 0xd
local_4c = local_4c ^ LShR(local_4c, 16)

s = Solver()
s.add(local_4c == 0xeb42f0aa)

# Sin bytes nulos: strlen() cortaría la cadena antes de tiempo
for p in password:
    s.add(p != 0)

if s.check() == sat:
    m = s.model()
    raw_bytes = bytes([m[p].as_long() for p in password])
    print(f"[+] Clave en hexadecimal: {raw_bytes.hex()}")
else:
    print("[-] No hay solución.")
```

Esta vez sí devolvió un resultado consistente:

```
[+] Clave en hexadecimal: c941426d6aae414da5e1
```

Antes de dar el resultado por bueno, reescribí la máquina de estados completa en Python plano —sin Z3, con los diez bytes concretos ya en mano— para confirmar que efectivamente produce `0xeb42f0aa`. La cuenta cuadra: `c9 41 42 6d 6a ae 41 4d a5 e1` pasa por los cuatro estados y llega exactamente al valor esperado.

## El verdadero obstáculo: hacer llegar bytes crudos a un binario de Windows

Con la clave matemáticamente confirmada, el problema debería haber terminado ahí. No fue así. `c941426d6aae414da5e1` es hexadecimal — la representación legible de diez bytes, varios de los cuales no corresponden a ningún carácter que se pueda escribir desde un teclado (`0xc9`, `0xae`, `0xa5`, `0xe1` no son ASCII imprimible). Intentar escribir o pegar esa cadena de texto directamente en el prompt de `wine crackme.exe` no envía los bytes `0xc9 0x41 0x42...` — envía los caracteres de texto literales `c`, `9`, `4`, `1`, `4`, `2`..., que es una entrada completamente distinta, de más de diez bytes, y que además no es la secuencia binaria que la máquina de estados espera.

El primer intento de solucionarlo fue generar los bytes crudos desde Python y canalizarlos por una tubería estándar de Linux: `python get_key.py | wine crackme.exe`. Falló con un error de Wine ajeno por completo a la lógica del crackme: `Application could not be started, or no application associated with the specified file` / `ShellExecuteEx failed: File not found`. Wine no estaba interpretando la tubería como una entrada estándar hacia el proceso de Windows de la forma esperada.

El segundo intento fue automatizar todo desde Python con `subprocess`, lanzando `wine crackme.exe` como proceso hijo y pasándole los bytes por su `stdin` directamente vía `communicate(input=raw_bytes)`. Esto sí evitó el problema de la tubería de shell, pero seguía fallando — y la causa, en ese momento, fue más mundana: el script no estaba corriendo en el mismo directorio donde vivía `crackme.exe`, así que Wine simplemente no encontraba el ejecutable. Copiar el binario al directorio de trabajo del script resolvió ese error puntual, pero para entonces ya había decidido que automatizar la ejecución completa no era lo que quería — solo necesitaba la clave en un formato que pudiera introducir yo mismo, a mano, de forma controlada.

La solución que terminó funcionando fue más simple que cualquiera de los intentos anteriores: generar los bytes crudos con una línea de Python y canalizarlos directamente a Wine, sin scripts intermedios ni automatización de más:

```bash
python -c "import sys; sys.stdout.buffer.write(bytes.fromhex('c941426d6aae414da5e1'))" | wine crackme.exe
```

```
Password: [+] Correcto!
```

Diez bytes exactos, escritos en binario puro a la salida estándar de Python, canalizados como entrada estándar de Wine — sin pasar por la interpretación de texto de una terminal en ningún punto del camino.

## Resumen del análisis

Este nivel separa con claridad dos habilidades que en los niveles anteriores solían resolverse con la misma herramienta:

- **Un buffer disperso entre variables con nombres separados.** `local_48` de 4 bytes, seguido de seis variables de 1 byte cada una, contiguas en la pila, forman en conjunto el verdadero buffer de diez bytes que la máquina de estados consume. Reconocer que Ghidra nombra por separado lo que el programa trata como un solo arreglo es la primera pieza del rompecabezas.
- **Una máquina de estados con mezcla de bits propia, no un hash reconocible.** Rotaciones, multiplicaciones por constantes arbitrarias y XORs posicionales encadenados en cuatro pasos — resoluble con Z3 igual que el hash FNV-1a del nivel 4, pero sin la ventaja de reconocer constantes estándar de un algoritmo publicado.
- **El detalle de `LShR` frente a `>>` en Z3.** Un desplazamiento aritmético en vez de lógico sobre una variable que en C es `unsigned` produce una ecuación distinta a la real, y el solver simplemente no encuentra solución — no porque el modelo esté mal planteado en su estructura, sino porque una operación puntual no refleja la semántica exacta del tipo de dato original.
- **Restringir el espacio de búsqueda con el contexto del programa, no solo con el algoritmo.** La restricción `p != 0` no sale de la máquina de estados en sí, sale de saber que el binario usa `fgets` seguido de `strlen` — un dato que solo aparece unas líneas antes en la misma función, y que cualquier solución matemáticamente válida pero con un byte nulo habría violado en la práctica.
- **Encontrar la clave matemáticamente correcta no es lo mismo que poder introducirla.** Cuando la solución es una secuencia de bytes no imprimibles, el problema deja de ser criptoanálisis y pasa a ser ingeniería de entrada: cómo lograr que esos bytes exactos, sin alteración de codificación de texto ni de interpretación de shell, lleguen intactos al proceso objetivo.

La lección de este nivel no está en ningún paso individual, está en la naturaleza de sus dos mitades: la primera es un problema de matemáticas que un solver resuelve en segundos; la segunda es un problema de sistemas —cómo se mueve un byte crudo desde un script de Python hasta el `stdin` de un binario de Windows corriendo sobre una capa de compatibilidad— que no tiene atajo automático y que hay que resolver a mano, un error a la vez.

---

© 2026 Gino Aldair Maihuiri Romero
