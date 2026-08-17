---
title: "Ghidra contra binarios ofuscados — Nivel 4: tablas virtuales y validación por hash"
description: "Cuarto nivel de la serie de entrenamiento en Ghidra sobre binarios ofuscados. Un crackme PE32+ compilado en C++ que despacha la validación a través de una tabla de fábricas, construye objetos con vtable propia en tiempo de ejecución, y valida la contraseña comparando su hash FNV-1a de 32 bits contra una constante — con un segundo objeto, alcanzable por la misma tabla, cuyo único método siempre devuelve falso."
author: Aldair Maihuiri
---

# Ghidra contra binarios ofuscados — Nivel 4: tablas virtuales y validación por hash

**Gino Aldair Maihuiri Romero**

([English version](ghidra-obfuscated-level4-en)) · ([Nivel 1](ghidra-obfuscated-level1)) · ([Nivel 2](ghidra-obfuscated-level2)) · ([Nivel 3](ghidra-obfuscated-level3))

Este nivel fue el más largo de resolver de toda la serie hasta ahora, y lo digo sin rodeos: aunque ya había trabajado con vtables antes, esta vez me costó ubicarme durante buen tramo del análisis, y en algún punto dejé de documentar el proceso paso a paso porque estaba concentrado en entender qué estaba pasando. Lo que sigue es la reconstrucción completa de ese análisis — el camino que sí documenté en su momento, más el resto reconstruido a partir de las capturas del decompilador y del razonamiento que fui aplicando, ya ordenado para que se lea de corrido.

El binario está compilado en C++ y usa polimorfismo real: una tabla de funciones "fábrica" que construye uno de dos objetos posibles según una variable de índice, cada objeto con su propia tabla virtual (vtable), y el método de validación real invocado a través de esa vtable en vez de aparecer como una llamada directa. A diferencia de los niveles anteriores, aquí no hay un solo camino desde `strncmp` o desde las strings hasta la lógica — hay que atravesar varias capas de indirección orientada a objetos, y una de las dos rutas posibles ni siquiera lleva a ningún lado.

Mismo entorno de siempre: Linux, PE32+ de Windows, análisis estático en Ghidra primero, verificación con Wine al final.

---

## Reconocimiento inicial

```
$ file crackme.exe
crackme.exe: PE32+ executable for MS Windows 5.02 (console), x86-64 (stripped to external PDB), 10 sections
```

Mismo perfil que los tres niveles anteriores.

## Un punto de partida distinto — y dos callejones sin salida más largos

Con malware suelo ir directo a la sección `.text` a buscar la lógica, así que probé ese mismo enfoque aquí. No encontré nada evidente de inmediato, pero sí una función vacía:

```c
void FUN_140001000(void)
{
  return;
}
```

Seguí sus referencias hasta `FUN_140001020`, una función larga que en un primer vistazo parecía prometedora — hasta que la leí completa y reconocí el patrón: es la rutina de arranque del CRT de Microsoft Visual C++ para un ejecutable de 64 bits (el equivalente a `mainCRTStartup`). Ahí están el candado de sincronización para inicialización segura entre hilos (`DAT_1400280b0` con `LOCK`/`Sleep`), el registro de un manejador de excepciones no controladas con `SetUnhandledExceptionFilter`, la llamada a `_set_invalid_parameter_handler(FUN_140001000)` — que es exactamente la función vacía que me trajo hasta aquí, un handler que no hace nada — y el procesamiento final de los argumentos de línea de comandos con `malloc` y `memcpy`. Nada de esto es la lógica del crackme; es código que genera el compilador para cualquier ejecutable de C/C++, y a estas alturas de la serie ya reconozco la forma general de un arranque de CRT en cuanto la veo, aunque nunca la hubiera leído completa antes.

Seguí con `strncmp`. Esta vez la entrada en el listado se veía distinta a los niveles anteriores:

```
140015300
strncmp
JMP qword ptr [->API-MS-WIN-CRT-STRING-L1-1-0.DLL::strncmp]
INDIRECTION
```

Etiquetada como `INDIRECTION` en vez de `THUNK`/`COMPUTED_JUMP` como en los niveles 2 y 3 — una diferencia de cómo Ghidra clasifica el salto, no algo que cambiara mi forma de seguirlo. La referencia me llevó a `FUN_14000c740`, una función bastante más larga que cualquier cosa que hubiera visto en los niveles anteriores. Al leerla hasta el final, tampoco era la validación: es una rutina que detecta y procesa nombres decorados de C++ (name mangling) — comprueba si una cadena empieza con el prefijo `_Z` del ABI de Itanium, o con `_GLOBAL_` seguido de los sufijos que usan los constructores y destructores globales (`_GLOBAL__I_`, `_GLOBAL__D_`), y a partir de ahí desglosa la estructura del nombre. Es código de soporte del runtime de C++ — probablemente relacionado con RTTI o con el manejo de excepciones — y aparece aquí, en un crackme que antes no tenía este tipo de código, precisamente porque este binario sí usa clases y polimorfismo real. Es el primer indicio, antes incluso de llegar a la validación, de que el nivel iba a girar en torno a C++ orientado a objetos.

Dos callejones sin salida más largos que los de los niveles anteriores, pero con la misma lección de siempre: si la función no toca la entrada del usuario ni el mensaje de resultado, no es la validación, por larga o interesante que parezca.

## Pivotando por las strings

Fui a `Defined Strings` a buscar `"Password: "`, y sus referencias me llevaron directo a la función de entrada real:

```c
undefined8 FUN_14001ced0(undefined8 param_1,ulonglong param_2,undefined8 param_3,undefined8 param_4)
{
  char cVar1;
  FILE *pFVar2;
  char *pcVar3;
  size_t sVar4;
  longlong *plVar5;
  undefined8 uVar6;
  char local_58 [72];

  FUN_14000da10();
  FUN_14000f6c0((byte *)"Password: ",param_2,param_3,param_4);
  pFVar2 = (FILE *)__acrt_iob_func(1);
  fflush(pFVar2);
  pFVar2 = (FILE *)__acrt_iob_func(0);
  pcVar3 = fgets(local_58,0x40,pFVar2);
  if (pcVar3 == (char *)0x0) {
    uVar6 = 1;
  }
  else {
    sVar4 = strcspn(local_58,"\n");
    local_58[sVar4] = '\0';
    plVar5 = (longlong *)(*(code *)(&PTR_FUN_14001f080)[DAT_14001e010])();
    cVar1 = (**(code **)*plVar5)(plVar5,local_58);
    (**(code **)(*plVar5 + 0x10))(plVar5);
    pcVar3 = "[-] Incorrecto.";
    if (cVar1 != '\0') {
      pcVar3 = "[+] Correcto!";
    }
    puts(pcVar3);
    uVar6 = 0;
  }
  return uVar6;
}
```

El prompt, el `fgets` y el recorte del salto de línea son idénticos a los niveles anteriores. Lo que cambia por completo es la parte de la validación — no hay ningún `strcmp` ni comparación directa aquí, solo tres líneas de C++ compilado que había que desglosar con calma:

```c
plVar5 = (longlong *)(*(code *)(&PTR_FUN_14001f080)[DAT_14001e010])();
cVar1 = (**(code **)*plVar5)(plVar5,local_58);
(**(code **)(*plVar5 + 0x10))(plVar5);
```

**La primera línea** llama a una función seleccionada dentro de una tabla — `PTR_FUN_14001f080` es la dirección base de un arreglo de punteros a función, y `DAT_14001e010` es el índice que decide cuál de esas funciones se ejecuta. Esa función seleccionada actúa como una fábrica: construye un objeto en memoria y devuelve un puntero a él (`plVar5`).

**La segunda línea** es la llamada polimórfica en sí. `*plVar5` lee el primer campo del objeto, que en C++ es la dirección de su vtable; `*(code **)*plVar5` toma el primer puntero de esa vtable; y la llamada final ejecuta ese método pasándole el propio objeto (`plVar5`, el `this` implícito) y la contraseña ingresada (`local_58`). El resultado booleano queda en `cVar1`.

**La tercera línea** llama al método en el desplazamiento `+0x10` de la vtable — casi con certeza el destructor del objeto, liberando la memoria reservada por la fábrica.

Con esto entendido, quedaba claro que el camino no terminaba aquí: tenía que ir a ver qué había dentro de `PTR_FUN_14001f080`, porque ahí es donde se decide qué objeto se construye y, por lo tanto, qué lógica de validación se ejecuta.

## La tabla de fábricas

```
                             PTR_FUN_14001f080                               XREF[1]:     FUN_14001ced0:14001cf35(*)
       14001f080 b0 15 00        addr       FUN_1400015b0
                 40 01 00
                 00 00
                             PTR_FUN_14001f088                               XREF[1]:     FUN_14001ced0:14001cf3c(R)
       14001f088 80 15 00        addr       FUN_140001580
                 40 01 00
                 00 00
```

Dos entradas: índice 0 apunta a `FUN_1400015b0`, índice 1 apunta a `FUN_140001580`. No llegué a comprobar en memoria qué valor tiene `DAT_140028010` en tiempo de ejecución, así que no puedo afirmar de entrada cuál de las dos rutas toma el programa por defecto — lo que hice fue revisar ambas fábricas para entender qué construye cada una, y dejar que el resultado final (la contraseña verificada contra el binario real) confirmara cuál importaba.

## Índice 0 — un objeto que nunca puede tener éxito

```c
void FUN_1400015b0(void)
{
  undefined8 *puVar1;

  puVar1 = (undefined8 *)FUN_14001ca10(8);
  *puVar1 = &PTR_FUN_140021af0;
  return;
}
```

Esta fábrica reserva 8 bytes — el tamaño justo de un puntero — y los llena con la dirección de una vtable, `PTR_FUN_140021af0`. Es el objeto más simple posible en C++: no tiene ningún dato propio, solo su puntero a vtable. Fui a ver esa tabla:

```
                             PTR_FUN_140021af0                               XREF[2]:     FUN_1400015b0:1400015be(*),
                                                                                          FUN_1400015b0:1400015c5(*)
       140021af0 c0 c1 01        addr       FUN_14001c1c0
                 40 01 00
                 00 00
```

(Dos referencias cruzadas, ambas dentro de la misma `FUN_1400015b0` — no llegué a determinar a qué corresponde exactamente la segunda sin desensamblar instrucción por instrucción; lo documento igual que hice con una discrepancia parecida en el nivel 2, sin forzarla a cuadrar.)

Una sola entrada, apuntando a `FUN_14001c1c0`. Y ahí, tanto en el listado como en el decompilador, encontré la función más corta de toda la serie:

```c
undefined8 FUN_14001c1c0(void)
{
  return 0;
}
```

Un `XOR EAX,EAX` en el ensamblador, que en C equivale a `return 0`. Si el programa toma la ruta del índice 0, el objeto que construye tiene un único método, y ese método ignora por completo el parámetro con la contraseña y siempre devuelve falso. No es una rama muerta como las del nivel 2 — es perfectamente alcanzable si `DAT_14001e010` vale 0 — pero funcionalmente cumple el mismo papel: es una validación que jamás puede tener éxito, sin importar qué se escriba. Un objeto señuelo, expresado con el vocabulario de C++ en vez de con ramas de control de flujo.

## Índice 1 — el objeto real

```c
void FUN_140001580(void)
{
  undefined8 *puVar1;

  puVar1 = (undefined8 *)FUN_14001ca10(0x18);
  *puVar1 = &PTR_FUN_140021ac0;
  *(undefined4 *)(puVar1 + 1) = 0x19884f5c;
  puVar1[2] = 8;
  return;
}
```

Esta fábrica sí reserva espacio de sobra — 0x18 (24) bytes en vez de 8 — porque el objeto que construye tiene estado propio además del puntero a vtable: un valor de 4 bytes, `0x19884f5c`, guardado justo después del puntero a vtable, y un segundo valor, `8`, guardado a continuación. Sin haber visto todavía el método de validación, ya podía anticipar qué eran esos dos campos: una especie de firma o valor objetivo, y una longitud esperada de contraseña.

La vtable de este objeto:

```
                             PTR_FUN_140021ac0                               XREF[2]:     FUN_140001580:14000158e(*),
                                                                                          FUN_140001580:140001595(*)
       140021ac0 40 c1 01        addr       FUN_14001c140
                 40 01 00
                 00 00
```

(Misma situación con las dos referencias cruzadas dentro de la propia función constructora — la documento sin forzarla a explicar del todo, igual que la anterior.)

Una entrada, apuntando a `FUN_14001c140`. Esta sí es la validación real.

## El algoritmo de validación: FNV-1a de 32 bits

```c
bool FUN_14001c140(longlong param_1,byte *param_2)
{
  byte bVar1;
  size_t sVar2;
  uint uVar3;
  bool bVar4;

  sVar2 = strlen((char *)param_2);
  bVar4 = false;
  if (sVar2 == *(size_t *)(param_1 + 0x10)) {
    uVar3 = 0x811c9dc5;
    bVar1 = *param_2;
    while (bVar1 != 0) {
      param_2 = param_2 + 1;
      uVar3 = (uVar3 ^ bVar1) * 0x1000193;
      bVar1 = *param_2;
    }
    bVar4 = *(uint *)(param_1 + 8) == uVar3;
  }
  return bVar4;
}
```

`param_1` es el objeto (`this`), `param_2` es la contraseña ingresada. Primero compara la longitud de la entrada contra `*(param_1 + 0x10)` — el campo que la fábrica había inicializado en `8`. Si la longitud no coincide, devuelve falso de inmediato sin tocar el resto del algoritmo.

Si la longitud es correcta, entra al bucle: arranca con `uVar3 = 0x811c9dc5` y, por cada byte de la entrada, hace `uVar3 = (uVar3 XOR byte) * 0x1000193`. Reconocí esta estructura de inmediato — el valor inicial `0x811c9dc5` y el multiplicador `0x1000193` son las constantes estándar del algoritmo **FNV-1a de 32 bits** (Fowler–Noll–Vo, variante *a*, donde el XOR ocurre antes de la multiplicación en cada iteración). Al terminar el bucle, compara el resultado contra `*(param_1 + 8)` — el campo que la fábrica había inicializado en `0x19884f5c`.

La regla completa del nivel: la contraseña debe tener exactamente 8 caracteres, y el hash FNV-1a de 32 bits de esos 8 caracteres tiene que ser exactamente `0x19884f5c`.

## Por qué esto no se resuelve por deducción directa

A diferencia de la suma ponderada del nivel 2, un hash como FNV-1a no se puede invertir con álgebra simple. Cada byte de la entrada modifica el estado interno del hash de una forma que depende de todo lo que vino antes — no hay una ecuación lineal que aislar. Las dos formas prácticas de resolver esto son fuerza bruta pura (inviable para 8 caracteres imprimibles: el espacio de búsqueda es demasiado grande para probar uno por uno en un tiempo razonable) o plantear el problema como restricciones lógicas y dejar que un solver las resuelva. Elegí la segunda opción, con Z3, la librería de resolución SMT (*Satisfiability Modulo Theories*) de Microsoft.

La idea es modelar cada uno de los 8 caracteres de la contraseña como una variable simbólica de 8 bits, restringir esas variables a un rango de caracteres imprimibles razonable, reproducir exactamente el mismo bucle FNV-1a que hay en el binario pero con esas variables simbólicas en vez de valores concretos, y pedirle a Z3 que encuentre una asignación de las 8 variables que haga que el hash resultante sea igual a `0x19884f5c`.

```python
from z3 import *

def solve_fnv_hash():
    # Crear el solver SMT
    s = Solver()

    # Definir 8 variables de 8 bits (representan cada carácter de la contraseña)
    password_chars = [BitVec(f'c_{i}', 8) for i in range(8)]

    # Restringir los caracteres a un conjunto imprimible común (letras y números: a-z, A-Z, 0-9)
    for c in password_chars:
        s.add(Or(
            And(c >= ord('a'), c <= ord('z')),
            And(c >= ord('A'), c <= ord('Z')),
            And(c >= ord('0'), c <= ord('9'))
        ))

    # Constantes oficiales del algoritmo FNV-1a de 32 bits
    h = BitVecVal(0x811c9dc5, 32)
    prime = BitVecVal(0x1000193, 32)

    # Replicar exactamente el bucle FNV-1a que encontramos en el binario
    for c in password_chars:
        c_32 = ZeroExt(24, c)  # Expandir el byte a 32 bits
        h = (h ^ c_32) * prime

    # El hash objetivo extraído del crackme (0x19884f5c)
    target_hash = 0x19884f5c
    s.add(h == target_hash)

    # Resolver el sistema de ecuaciones
    if s.check() == sat:
        model = s.model()
        password = "".join([chr(model[c].as_long()) for c in password_chars])
        print(f"\n[+] ¡Contraseña encontrada con éxito!: {password}")
    else:
        print("\n[-] No se encontró solución con el conjunto de caracteres actual.")

if __name__ == "__main__":
    print("[*] Buscando la contraseña para el hash FNV-1a...")
    solve_fnv_hash()
```

En Arch Linux instalar `z3-solver` con `pip` requiere un entorno virtual por la política de entornos gestionados externamente (PEP 668), así que lo instalé dentro de un `venv` en vez de intentar instalarlo a nivel de sistema.

## Verificación

```
[house@archlinux nivel4_vtable]$ wine crackme.exe
Password: KiutOCpz
[+] Correcto!
[house@archlinux nivel4_vtable]$
```

Antes de dar esto por cerrado, calculé el hash FNV-1a de `KiutOCpz` por mi cuenta para confirmar que coincide con el valor extraído del binario, y no solo con lo que devolvió el solver:

```
h = 0x811c9dc5
para cada byte de "KiutOCpz": h = (h XOR byte) * 0x1000193  (mod 2^32)
resultado final: 0x19884f5c
```

Coincide exactamente con la constante de `FUN_140001580`. La cuenta cuadra.

## Resumen del análisis

Este nivel introduce el tipo de ofuscación más distinto de toda la serie hasta ahora, apoyado en el propio lenguaje en vez de en trucos a nivel de ensamblador:

- **Despacho a través de una tabla de fábricas.** En vez de una llamada directa a la función de validación, el programa selecciona entre dos rutinas constructoras usando un índice en tiempo de ejecución, y cada una construye un objeto distinto.
- **Polimorfismo real (vtables).** El método de validación no aparece como una llamada nombrada en el decompilador — se invoca a través del primer puntero de la vtable del objeto, lo que obliga a rastrear manualmente el objeto, su vtable, y el método concreto antes de ver una sola línea del algoritmo real.
- **Un objeto señuelo con el mismo espíritu que una rama muerta.** El objeto del índice 0 es funcionalmente equivalente a las ramas muertas del nivel 2 — una validación que nunca puede tener éxito — pero expresado como un método que ignora su entrada, no como una condición inalcanzable.
- **Validación por hash no invertible.** A diferencia de la suma ponderada del nivel 2, un hash FNV-1a no se resuelve con álgebra directa. Hubo que reconocer las constantes del algoritmo, modelar el problema como restricciones simbólicas, y usar un solver SMT para encontrar una entrada válida en vez de deducirla a mano.
- **Más código de soporte de C++ que filtrar.** Los dos callejones sin salida de este nivel — el arranque del CRT y la rutina de detección de nombres decorados — son más largos que los de niveles anteriores porque un binario que usa clases y vtables arrastra más infraestructura del runtime de C++ antes de llegar al código propio del autor.

La lección de fondo, más allá de la técnica puntual: cuando la ofuscación se apoya en el paradigma del lenguaje en vez de en trucos de bajo nivel, hay que reconstruir la semántica de más alto nivel —qué objeto es cuál, qué vtable le corresponde, qué método se está invocando en realidad— antes de que el algoritmo concreto tenga algún sentido. Perderse un poco en el camino, como me pasó aquí, es parte normal de ese proceso.

---

© 2026 Gino Aldair Maihuiri Romero
