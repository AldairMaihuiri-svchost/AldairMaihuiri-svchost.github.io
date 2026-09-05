---
title: "Ghidra contra binarios ofuscados — Nivel 1: cifrado de strings"
description: "Primer nivel de una serie de entrenamiento en ingeniería inversa con Ghidra sobre binarios ofuscados. Análisis estático puro de un crackme PE32+ que oculta su contraseña y sus mensajes mediante construcción de strings en memoria y cifrado XOR de un solo byte, resuelto sin ejecutar el binario."
author: Aldair Maihuiri
---

# Ghidra contra binarios ofuscados — Nivel 1: cifrado de strings

**Gino Aldair Maihuiri Romero**

([English version](ghidra-obfuscated-level1-en))

Esta es la primera entrega de una serie de entrenamiento distinta a mis crackmes anteriores. Ahí trabajaba con binarios ELF propios, sin ofuscación, pensados para practicar primitivas concretas de reversing: comparación de cadenas, parcheo con ptrace, canarios de pila. Aquí el objetivo cambia: son binarios PE32+ de Windows, ya ofuscados, y la pregunta ya no es "cómo funciona esta primitiva" sino "cómo se ve una técnica de ofuscación real cuando la abro en Ghidra, y cómo la desmonto usando solo el decompilador y el listado de memoria, sin depender de ejecutar el binario ni una sola vez".

Esa restricción no es arbitraria: yo trabajo en Linux, y estos crackmes son binarios nativos de Windows. Podría ejecutarlos bajo Wine, pero para este entrenamiento decidí no hacerlo durante el análisis. El objetivo es que la resolución salga enteramente del análisis estático en Ghidra. Solo después, en un entorno Windows aparte, verifico que la contraseña encontrada sea correcta. Si estás leyendo este documento es porque esa verificación ya se hizo.

---

## Reconocimiento inicial

Lo primero, como es costumbre antes de abrir cualquier binario en Ghidra, es mirar qué tengo enfrente con `file`:

```
$ file crackme.exe
crackme.exe: PE32+ executable for MS Windows 5.02 (console), x86-64 (stripped to external PDB), 10 sections
```

Un ejecutable PE32+ de consola, x86-64, con los símbolos de depuración retirados hacia un PDB externo que no tengo. Diez secciones. Nada fuera de lo común todavía — es la forma estándar en que se distribuye un binario de release en Windows.

Con el binario cargado en Ghidra, mi siguiente parada habitual es la ventana de **Defined Strings**, porque en un crackme sin ofuscar suele bastar con leer ahí el mensaje de éxito, el de error, o incluso la contraseña en texto plano. Aquí no encontré ninguno de esos tres. Lo que sí encontré fue `strcmp`, y eso ya es una señal útil por sí sola: si el binario compara algo con `strcmp`, hay una rama de validación en algún punto del código, y esa rama es mi objetivo.

## De la string a la función

Con `strcmp` como punto de entrada, fui al **Symbol Tree** a buscar de dónde viene esa referencia. La encontré importada desde `API-MS-WIN-CRT-STRING-L1-1-0.DLL`, que es una de las DLLs de reenvío del CRT universal de Windows — el binario no trae su propio `strcmp`, lo importa del sistema. Ver las referencias a esa entrada me dio esto:

```
140008480    strcmp    JMP qword ptr [->API-MS-WIN-CRT-STRING-L1-1-0.DLL::strcmp]    COMPUTED_JUMP
140008480    strcmp    JMP qword ptr [->API-MS-WIN-CRT-STRING-L1-1-0.DLL::strcmp]    THUNK
14000f528    PTR_strcmp_14000f528    float * API-MS-WIN-CRT-STRING-L1-1-0.DLL::strcmp    DATA
```

`140008480` es el thunk: el salto que redirige cualquier llamada a `strcmp` hacia la DLL real. Lo que necesito no es el thunk en sí, sino quién lo llama. Revisando las referencias a esa dirección encontré exactamente una:

```
140008761        CALL API-MS-WIN-CRT-STRING-L1-1-0.DLL::strcmp    UNCONDITIONAL_CALL
```

Esa dirección, `140008761`, cae dentro de una función. Fui ahí en el decompilador y encontré toda la lógica de validación del crackme en un solo lugar.

## La función de validación

```c
undefined8
FUN_140008680(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4)
{
  int iVar1;
  undefined8 *_Memory;
  FILE *pFVar2;
  char *pcVar3;
  undefined8 uVar4;
  size_t sVar5;
  ulonglong *_Str;
  char local_68 [16];
  char local_58 [72];

  FUN_1400016d0();
  _Memory = malloc(0xb);
  *(undefined2 *)(_Memory + 1) = 0x203a;
  *_Memory = 0x64726f7773736150;
  *(undefined1 *)((longlong)_Memory + 10) = 0;
  FUN_1400028a0(&DAT_14000a050,(ulonglong)_Memory,param_3,param_4);
  pFVar2 = (FILE *)__acrt_iob_func(1);
  fflush(pFVar2);
  free(_Memory);
  pFVar2 = (FILE *)__acrt_iob_func(0);
  pcVar3 = fgets(local_58,0x40,pFVar2);
  uVar4 = 1;
  if (pcVar3 != (char *)0x0) {
    sVar5 = strcspn(local_58,"\n");
    local_58[sVar5] = '\0';
    pcVar3 = malloc(10);
    builtin_strncpy(pcVar3,"0bfu5c4t3",10);
    strncpy(local_68,pcVar3,0xf);
    free(pcVar3);
    iVar1 = strcmp(local_58,local_68);
    if (iVar1 == 0) {
      _Str = FUN_140001580((ulonglong *)&DAT_14000a068,0xd);
    }
    else {
      _Str = FUN_140001580((ulonglong *)&DAT_14000a058,0xf);
    }
    puts((char *)_Str);
    free(_Str);
    uVar4 = 0;
  }
  return uVar4;
}
```

Vale la pena leer esto con calma, porque las dos primeras técnicas de ofuscación de esta serie ya están aquí, y ninguna de las dos toca la contraseña en sí — tocan cómo se construyen las strings alrededor de ella.

**La primera técnica** es la construcción del prompt `"Password: "` sin que exista como literal en ningún lado. En vez de una referencia directa a una cadena, el código reserva 11 bytes con `malloc`, y arma el texto escribiendo directamente los bytes en memoria: `0x64726f7773736150` es la cadena `"Passwor"` seguida de una `d` codificada como little-endian en ese entero de 64 bits, y `0x203a` son los dos bytes finales `": "`. Es la razón por la que `Defined Strings` no mostró nada útil: el string no existe como tal en el binario, se ensambla en tiempo de ejecución byte a byte dentro de un entero.

**La segunda** es cómo se construye el string contra el que se compara la entrada del usuario. El código no compara directamente contra un literal — reserva memoria con `malloc(10)`, copia ahí `"0bfu5c4t3"` con `builtin_strncpy`, copia ese buffer a una variable local con `strncpy`, y libera el buffer original. El resultado neto es exactamente `strcmp(entrada_usuario, "0bfu5c4t3")`, pero llegar hasta ahí exige seguir tres funciones de copia en vez de leer un literal. Es una ofuscación débil en comparación con lo que viene después: la contraseña sigue apareciendo en texto plano en el decompilador, solo que no en la vista de strings. Para este nivel de entrenamiento eso ya es suficiente lección — no toda ofuscación necesita ser fuerte para cumplir su función de complicar un escaneo automático o una lectura superficial.

Con esto ya tengo la contraseña: **`0bfu5c4t3`**.

## El mensaje de éxito, cifrado con XOR

Lo interesante viene después de la comparación. Cuando `strcmp` devuelve 0, el código no llama a `puts` con un literal — llama a una función, `FUN_140001580`, pasándole un puntero a `DAT_14000a068` y una longitud de `0xd` (13 bytes). Fui a ver esa función:

```c
ulonglong * FUN_140001580(ulonglong *param_1,ulonglong param_2)
{
  ulonglong *puVar1;
  ulonglong uVar2;

  puVar1 = malloc(param_2 + 1);
  *puVar1 = *param_1 ^ 0x5a5a5a5a5a5a5a5a;
  uVar2 = 8;
  do {
    *(byte *)((longlong)puVar1 + uVar2) = *(byte *)((longlong)param_1 + uVar2) ^ 0x5a;
    uVar2 = uVar2 + 1;
  } while (uVar2 < param_2);
  *(undefined1 *)((longlong)puVar1 + param_2) = 0;
  return puVar1;
}
```

Esto es un descifrador XOR de un solo byte, con una particularidad de compilador: los primeros 8 bytes se descifran de un tirón como un entero de 64 bits contra la máscara `0x5a5a5a5a5a5a5a5a` (que no es más que la clave `0x5a` repetida ocho veces), y el resto del buffer se procesa byte a byte en un bucle. Es la misma operación en ambos casos — un XOR contra `0x5a` — solo que el compilador optimizó el primer bloque agrupando ocho XOR de un byte en uno solo de ocho.

Con eso claro, lo único que me falta es el contenido cifrado. Fui a `DAT_14000a068` en la vista de memoria de Ghidra:

```
                             DAT_14000a068                                   XREF[1]:     FUN_140008680:14000879c(*)
       14000a068 01              ??         01h
       14000a069 71              ??         71h    q
       14000a06a 07              ??         07h
       14000a06b 7a              ??         7Ah    z
       14000a06c 19              ??         19h
       14000a06d 35              ??         35h    5
       14000a06e 28              ??         28h    (
       14000a06f 28              ??         28h    (
       14000a070 3f              ??         3Fh    ?
       14000a071 39              ??         39h    9
       14000a072 2e              ??         2Eh    .
       14000a073 35              ??         35h    5
       14000a074 7b              ??         7Bh    {
       14000a075 00              ??         00h
       14000a076 00              ??         00h
       14000a077 00              ??         00h
```

Trece bytes útiles antes del padding de ceros, exactamente la longitud `0xd` que se le pasó a la función. Los llevo a Python para aplicar el mismo XOR que hace el binario:

```
>>> # Bytes cifrados obtenidos de Ghidra (DAT_14000a068, longitud 0xd / 13 bytes)
... bytes_cifrados = [0x01, 0x71, 0x07, 0x7a, 0x19, 0x35, 0x28, 0x28, 0x3f, 0x39, 0x2e, 0x35, 0x7b]
...
... # Aplicamos XOR con 0x5a a cada byte y lo convertimos a caracteres
... texto_descifrado = "".join([chr(b ^ 0x5a) for b in bytes_cifrados])
...
... print(f"Mensaje descifrado: {texto_descifrado}")
...
Mensaje descifrado: [+] Correcto!
```

El mensaje de éxito es `[+] Correcto!`.

## El mensaje de error, mismo mecanismo

Cuando `strcmp` no devuelve 0, el código llama a la misma función `FUN_140001580`, esta vez con `&DAT_14000a058` y longitud `0xf` (15 bytes). Es el mismo descifrador que ya analicé arriba — vale la pena notarlo porque es una elección de diseño razonable del autor del crackme: reutilizar una única rutina de descifrado para ambos mensajes en vez de duplicar la lógica.

En mi opinión, si el objetivo era ofuscar de verdad, hubiera tenido más sentido cifrar la contraseña misma en vez de (o además de) los mensajes de salida — un atacante que solo necesita la contraseña puede ignorar por completo esta capa. Pero como ejercicio de entrenamiento en Ghidra cumple bien su función: obliga a trabajar con datos que no aparecen como texto legible en ninguna vista automática de strings, que es exactamente la habilidad que quiero practicar en este nivel.

El contenido cifrado en `DAT_14000a058`:

```
                             DAT_14000a058                                   XREF[1]:     FUN_140008680:14000876f(*)
       14000a058 01              ??         01h
       14000a059 77              ??         77h    w
       14000a05a 07              ??         07h
       14000a05b 7a              ??         7Ah    z
       14000a05c 13              ??         13h
       14000a05d 34              ??         34h    4
       14000a05e 39              ??         39h    9
       14000a05f 35              ??         35h    5
       14000a060 28              ??         28h    (
       14000a061 28              ??         28h    (
       14000a062 3f              ??         3Fh    ?
       14000a063 39              ??         39h    9
       14000a064 2e              ??         2Eh    .
       14000a065 35              ??         35h    5
       14000a066 74              ??         74h    t
       14000a067 00              ??         00h
```

Mismo script, mismos datos distintos:

```
>>> bytes_error = [0x01, 0x77, 0x07, 0x7a, 0x13, 0x34, 0x39, 0x35, 0x28, 0x28, 0x3f, 0x39, 0x2e, 0x35, 0x74]
... mensaje_error = "".join([chr(b ^ 0x5a) for b in bytes_error])
... print(mensaje_error)
...
[-] Incorrecto.
```

## Resumen del análisis

Todo el crackme queda resuelto sin ejecutar el binario ni una sola vez, apoyándose únicamente en tres herramientas de Ghidra: el listado de referencias cruzadas para llegar de un import conocido (`strcmp`) a la función que lo usa, el decompilador para leer la lógica de validación, y la vista de memoria en bruto para extraer los bytes cifrados que el decompilador no traduce automáticamente a texto.

- **Contraseña**: `0bfu5c4t3` — visible en texto plano en el decompilador, oculta solo de una lectura superficial de `Defined Strings` por estar ensamblada mediante copias en memoria en vez de una referencia directa.
- **Técnica de ofuscación identificada**: construcción de strings en tiempo de ejecución (el prompt) y cifrado XOR de un solo byte con clave `0x5a` (los dos mensajes de resultado).
- **Mecanismo de descifrado**: una única función reutilizada para ambos mensajes, con la particularidad de que el compilador agrupa el XOR de los primeros 8 bytes en una sola operación de 64 bits.

La lección central de este primer nivel no es la fortaleza de la ofuscación —un XOR de un byte se rompe con una línea de Python en cuanto se tiene la clave y el buffer— sino el hábito de trabajo: cuando `Defined Strings` no da nada, el siguiente paso no es rendirse ni ejecutar el binario a ciegas, es seguir las referencias cruzadas desde una API conocida hasta la lógica que la usa, y de ahí a los datos en bruto que el decompilador no interpreta por sí solo.

---

© 2026 Gino Aldair Maihuiri Romero
