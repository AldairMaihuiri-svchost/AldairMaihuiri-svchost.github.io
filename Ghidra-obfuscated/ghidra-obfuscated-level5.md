---
title: "Ghidra contra binarios ofuscados — Nivel 5: el nivel final"
description: "Quinto y último nivel de la serie de entrenamiento en Ghidra sobre binarios ofuscados. Un crackme PE32+ que combina técnicas de los cuatro niveles anteriores —construcción dinámica de la contraseña, un predicado opaco, despacho por vtable, comparación manual sin strcmp— con dos elementos nuevos: relocación de código a memoria ejecutable en tiempo de ejecución y una detección de depurador que sí bloquea el análisis."
author: Aldair Maihuiri
---

# Ghidra contra binarios ofuscados — Nivel 5: el nivel final

**Gino Aldair Maihuiri Romero**

([English version](ghidra-obfuscated-level5-en)) · ([Nivel 1](ghidra-obfuscated-level1)) · ([Nivel 2](ghidra-obfuscated-level2)) · ([Nivel 3](ghidra-obfuscated-level3)) · ([Nivel 4](ghidra-obfuscated-level4))

El nombre de la carpeta de este binario es `nivel5_boss`, y en cuanto empecé a desenredarlo quedó claro por qué: no trae una técnica nueva y ya está, reúne piezas de los cuatro niveles anteriores en una sola función y les suma dos elementos que no había visto en la serie hasta ahora. Fue el más largo de entender de los cinco, y hubo tramos donde me costó ubicar qué pieza correspondía a qué técnica ya conocida — pero justamente por eso avancé más rápido que si hubiera sido la primera vez que veía cada una: reconocer un patrón que ya había resuelto antes ahorra tiempo, aunque el conjunto completo sea nuevo.

Mismo entorno de siempre: Linux, PE32+ de Windows, análisis estático en Ghidra primero, verificación con Wine al final.

---

## Reconocimiento inicial

```
$ file crackme.exe
crackme.exe: PE32+ executable for MS Windows 5.02 (console), x86-64 (stripped to external PDB), 10 sections
```

Mismo perfil que los cuatro niveles anteriores.

## Un desvío que esta vez reconocí de inmediato

Fui a las referencias de `strncmp` y llegué a esto:

```
140015300
strncmp
JMP qword ptr [->API-MS-WIN-CRT-STRING-L1-1-0.DLL::strncmp]
COMPUTED_JUMP
140015300
strncmp
JMP qword ptr [->API-MS-WIN-CRT-STRING-L1-1-0.DLL::strncmp]
THUNK
1400298d0
PTR_strncmp_1400298d0
addr API-MS-WIN-CRT-STRING-L1-1-0.DLL::strncmp
DATA
```

Y la función que lo llama fue, byte por byte, la misma que ya había analizado en el nivel 4: `FUN_14000c740`, la rutina de detección y análisis de nombres decorados de C++ (comprobación de los prefijos `_Z` y `_GLOBAL_` del ABI de Itanium). Esta vez no necesité releerla entera — la reconocí en cuanto vi el `if ((*param_1 == '_') && (param_1[1] == 'Z'))` del principio. De ahí colgaba otra función, `FUN_140001600`, que actúa como constructor de nodos para el árbol de parsing que arma el demangler: valida cada token contra máscaras de bits, comprueba que no se exceda la capacidad de un buffer interno, y va guardando cada carácter procesado en una estructura de 32 bytes. Es la maquinaria interna del parser de símbolos, no la validación — la misma conclusión a la que había llegado con el resto de este código en el nivel 4, aplicada aquí más rápido.

En vez de seguir cavando por ese camino como hice la primera vez que me encontré con este demangler, esta vez fui directo a `Defined Strings` a buscar el prompt de contraseña. Fue la decisión correcta: llegué a la función real en un solo salto.

## La función principal

```c
undefined8 FUN_14001ce70(undefined8 param_1,ulonglong param_2,undefined8 param_3,undefined8 param_4)
{
  undefined8 uVar1;
  undefined8 uVar2;
  undefined8 uVar3;
  undefined8 uVar4;
  undefined8 uVar5;
  undefined8 uVar6;
  undefined8 uVar7;
  int iVar8;
  int iVar9;
  BOOL BVar10;
  FILE *pFVar11;
  char *pcVar12;
  size_t sVar13;
  undefined8 *_Memory;
  code *lpBaseAddress;
  HANDLE hProcess;
  longlong *plVar14;
  code *pcVar15;
  uint uVar16;
  ulonglong uVar17;
  char local_58 [64];

  FUN_14000da10();
  FUN_14000f6c0((byte *)"Password: ",param_2,param_3,param_4);
  pFVar11 = (FILE *)__acrt_iob_func(1);
  fflush(pFVar11);
  pFVar11 = (FILE *)__acrt_iob_func(0);
  pcVar12 = fgets(local_58,0x40,pFVar11);
  if (pcVar12 == (char *)0x0) {
    return 1;
  }
  sVar13 = strcspn(local_58,"\n");
  local_58[sVar13] = '\0';
  _Memory = malloc(0xb);
  *_Memory = 0x3062347264316867;
  *(undefined2 *)(_Memory + 1) = 0x7373;
  *(undefined1 *)((longlong)_Memory + 10) = 0;
  lpBaseAddress = VirtualAlloc((LPVOID)0x0,0x100,0x3000,0x40);
  pcVar15 = FUN_140001580;
  if (lpBaseAddress != (code *)0x0) {
    *(undefined8 *)(lpBaseAddress + 0xc0) = 0x20400000000;
    *(undefined8 *)(lpBaseAddress + 200) = 0xc9854d7374c88548;
    *(undefined8 *)(lpBaseAddress + 0xd0) = 0x3b41284a8b413e74;
    *(undefined8 *)(lpBaseAddress + 0xd8) = 0x83c16348347d2c4a;
    *(undefined8 *)(lpBaseAddress + 0xe0) = 0x34905e0c14801c1;
    *(undefined8 *)(lpBaseAddress + 0xe8) = 0x440c7482042;
    *(undefined8 *)(lpBaseAddress + 0xf0) = 0x1089284a89410000;
    *(undefined8 *)(lpBaseAddress + 0xf8) = 0x1848894c1040894c;
    uVar17 = 0;
    do {
      uVar16 = (int)uVar17 + 0x40;
      uVar1 = *(undefined8 *)(uVar17 + 0x140001588);
      uVar2 = *(undefined8 *)(&DAT_140001590 + uVar17);
      uVar3 = *(undefined8 *)(&UNK_140001598 + uVar17);
      uVar4 = *(undefined8 *)(uVar17 + 0x1400015a0);
      uVar5 = *(undefined8 *)(uVar17 + 0x1400015a8);
      uVar6 = *(undefined8 *)(uVar17 + 0x1400015b0);
      uVar7 = *(undefined8 *)(&UNK_1400015b8 + uVar17);
      *(undefined8 *)(lpBaseAddress + uVar17) = *(undefined8 *)(FUN_140001580 + uVar17);
      *(undefined8 *)(lpBaseAddress + uVar17 + 8) = uVar1;
      *(undefined8 *)(lpBaseAddress + uVar17 + 0x10) = uVar2;
      *(undefined8 *)(lpBaseAddress + uVar17 + 0x10 + 8) = uVar3;
      *(undefined8 *)(lpBaseAddress + uVar17 + 0x20) = uVar4;
      *(undefined8 *)(lpBaseAddress + uVar17 + 0x20 + 8) = uVar5;
      *(undefined8 *)(lpBaseAddress + uVar17 + 0x30) = uVar6;
      *(undefined8 *)(lpBaseAddress + uVar17 + 0x30 + 8) = uVar7;
      uVar17 = (ulonglong)uVar16;
    } while (uVar16 < 0xc0);
    hProcess = GetCurrentProcess();
    FlushInstructionCache(hProcess,lpBaseAddress,0x100);
    pcVar15 = lpBaseAddress;
  }
  plVar14 = (longlong *)FUN_14001c9b0(0x10);
  *plVar14 = (longlong)&PTR_FUN_140021aa0;
  iVar8 = DAT_14001e020;
  iVar9 = DAT_14001e01c;
  plVar14[1] = (longlong)pcVar15;
  if (iVar8 * iVar8 + iVar9 * DAT_14001e01c == DAT_14001e018 * DAT_14001e018) {
    BVar10 = IsDebuggerPresent();
    if (BVar10 != 0) {
      (*(code *)((undefined8 *)*plVar14)[2])(plVar14);
      free(_Memory);
      pcVar12 = "[-] Incorrecto.";
      goto LAB_14001d05b;
    }
    uVar16 = (**(code **)*plVar14)(plVar14,local_58,_Memory,10);
  }
  else {
    iVar9 = FUN_14001c160((longlong)plVar14,local_58,_Memory,10);
    uVar16 = (uint)(iVar9 == 0);
  }
  (**(code **)(*plVar14 + 0x10))(plVar14);
  free(_Memory);
  pcVar12 = "[+] Correcto!";
  if (uVar16 == 0) {
    pcVar12 = "[-] Incorrecto.";
  }
LAB_14001d05b:
  puts(pcVar12);
  return 0;
}
```

Es la función más larga de la serie, y reconocer qué parte corresponde a qué técnica ya vista fue lo que me permitió avanzar. La desglosé pieza por pieza.

## Construyendo la contraseña en memoria — otra vez

```c
_Memory = malloc(0xb);
*_Memory = 0x3062347264316867;
*(undefined2 *)(_Memory + 1) = 0x7373;
*(undefined1 *)((longlong)_Memory + 10) = 0;
```

La misma técnica del nivel 3: la contraseña de referencia no está en el binario como string, se ensambla byte a byte en un buffer reservado con `malloc`. Reconstruí los bytes en little-endian:

- `0x3062347264316867` (8 bytes): `67 68 31 64 72 34 62 30` → `g h 1 d r 4 b 0` → `"gh1dr4b0"`.
- `0x7373` (2 bytes, a partir del offset 8): `73 73` → `s s` → `"ss"`.
- Terminador nulo en el offset 10.

Uniendo todo: **`gh1dr4b0ss`**, diez caracteres. Y si se lee en leetspeak (1→i, 4→a, 0→o): **"ghidraboss"**. El nombre de la carpeta del binario, otra vez, resultó ser literalmente la contraseña — la misma broma que ya me había encontrado con "indirect" en el nivel 3.

## Código que se copia a sí mismo a memoria ejecutable

```c
lpBaseAddress = VirtualAlloc((LPVOID)0x0,0x100,0x3000,0x40);
pcVar15 = FUN_140001580;
if (lpBaseAddress != (code *)0x0) {
  ...
  uVar17 = 0;
  do {
    ...
    *(undefined8 *)(lpBaseAddress + uVar17) = *(undefined8 *)(FUN_140001580 + uVar17);
    ...
  } while (uVar16 < 0xc0);
  hProcess = GetCurrentProcess();
  FlushInstructionCache(hProcess,lpBaseAddress,0x100);
  pcVar15 = lpBaseAddress;
}
```

Esto es nuevo en la serie: el programa reserva una página de memoria con `VirtualAlloc` usando los flags `0x3000` (`MEM_COMMIT | MEM_RESERVE`) y `0x40` (`PAGE_EXECUTE_READWRITE`), copia 0xC0 (192) bytes desde la dirección de `FUN_140001580` hacia esa memoria recién reservada en bloques de 8 bytes, y llama a `FlushInstructionCache` para asegurarse de que el procesador vea el código recién escrito. Al final, `pcVar15` queda apuntando a esa copia en memoria ejecutable en vez de a la función original — pero solo si `VirtualAlloc` tuvo éxito; si falla, `pcVar15` se queda apuntando a la `FUN_140001580` estática de siempre.

Revisando el bucle de copia con calma, no encontré ninguna transformación de los bytes — ni XOR, ni suma, nada. Es una copia directa, byte por byte, del cuerpo de `FUN_140001580` a la nueva región de memoria. Y eso importa para el análisis: como Ghidra ya puede descompilar `FUN_140001580` en su ubicación estática original —cosa que hice más abajo—, esta relocación en tiempo de ejecución no esconde absolutamente nada del análisis estático. Sea que el programa termine ejecutando la copia en memoria o el original, el código es idéntico bit a bit. Es una técnica que en otros contextos serviría contra herramientas de parcheo o de hooking que apuntan a una dirección fija, pero que no aporta nada contra un análisis puramente estático como el que vengo haciendo en toda la serie.

## El predicado opaco, de vuelta

```c
iVar8 = DAT_14001e020;
iVar9 = DAT_14001e01c;
plVar14[1] = (longlong)pcVar15;
if (iVar8 * iVar8 + iVar9 * DAT_14001e01c == DAT_14001e018 * DAT_14001e018) {
```

La misma forma algebraica pitagórica del nivel 2 — suma de dos cuadrados igual a un tercero, con tres constantes globales. A diferencia de aquel nivel, aquí no llegué a dumpear los valores reales de `DAT_14001e020`, `DAT_14001e01c` y `DAT_14001e018` en memoria, así que no puedo confirmar con certeza que esta condición sea siempre verdadera ni descartar del todo la rama del `else`. Lo dejo documentado como una incógnita abierta en vez de asumir que se comporta igual que en el nivel 2 sin haberlo comprobado.

## Un objeto con vtable — y una comprobación de depurador que sí importa

Si la condición se cumple, el código arma un objeto con vtable (misma técnica que el nivel 4: `FUN_14001c9b0(0x10)` reserva el objeto, `&PTR_FUN_140021aa0` es su vtable, `plVar14[1]` guarda un puntero a la función de validación —la original o la copiada, según haya funcionado `VirtualAlloc`—) y, antes de invocar nada, llama a `IsDebuggerPresent()`:

```c
BVar10 = IsDebuggerPresent();
if (BVar10 != 0) {
  (*(code *)((undefined8 *)*plVar14)[2])(plVar14);
  free(_Memory);
  pcVar12 = "[-] Incorrecto.";
  goto LAB_14001d05b;
}
uVar16 = (**(code **)*plVar14)(plVar14,local_58,_Memory,10);
```

Esto sí es una medida defensiva real, no un adorno. Si el programa detecta que se está ejecutando bajo un depurador, salta directo a limpiar el objeto e imprimir "Incorrecto" sin siquiera llamar al método de comparación — la contraseña que se haya escrito no importa, el resultado ya está decidido. En retrospectiva, seguir la sugerencia de poner un breakpoint dentro de esta función para ver la contraseña en tiempo real —que es justo lo que se me había planteado como camino alternativo al analizar el demangler— no habría funcionado sin antes neutralizar esta comprobación. Terminé resolviendo el nivel completo sin abrir un depurador ni una sola vez, así que esta trampa nunca llegó a activarse contra mí, pero vale la pena dejar constancia de que está ahí.

Si no hay depurador, se invoca el primer método de la vtable —la función de comparación real— pasándole el objeto, la entrada del usuario, la contraseña de referencia y la longitud `10`.

Hay una rama alternativa que no exploré del todo: si el predicado pitagórico fuera falso, el código llama en cambio a `FUN_14001c160` directamente, sin pasar por la vtable ni por la comprobación de depurador. No tengo el código de esa función ni confirmación de si esa rama es alcanzable en la práctica, así que la dejo señalada como un hilo suelto en vez de inventar qué hace.

## La comparación real, sin `strcmp`

```c
bool FUN_140001580(longlong param_1,longlong param_2,longlong param_3)
{
  longlong lVar1;

  if (param_3 != 0) {
    lVar1 = 0;
    do {
      if (*(char *)(param_1 + lVar1) != *(char *)(param_2 + lVar1)) {
        return false;
      }
      lVar1 = lVar1 + 1;
    } while (param_3 != lVar1);
  }
  if (*(char *)(param_1 + param_3) != '\0') {
    return false;
  }
  return *(char *)(param_2 + param_3) == '\0';
}
```

Otra vez la idea del nivel 3: evitar un `strcmp`/`strncmp` nombrado que apareciera fácil en las referencias cruzadas, y en su lugar escribir la comparación a mano. Recorre carácter por carácter las dos cadenas hasta la longitud dada (`10`), y si en algún punto no coinciden, corta y devuelve falso. Al final del bucle, además, comprueba explícitamente que ambas cadenas terminen exactamente en la posición 10 con un byte nulo — así se asegura de que la entrada tenga exactamente esa longitud, no solo que los primeros diez caracteres coincidan.

## Verificación

```
[house@archlinux nivel5_boss]$ file crackme.exe
crackme.exe: PE32+ executable for MS Windows 5.02 (console), x86-64 (stripped to external PDB), 10 sections
[house@archlinux nivel5_boss]$ wine crackme.exe
Password: gh1dr4b0ss
[+] Correcto!
[house@archlinux nivel5_boss]$
```

Confirmado.

## Resumen del análisis

Este nivel no introduce una técnica dominante propia — funciona como una síntesis de la serie completa, con dos añadidos genuinamente nuevos:

- **Técnicas reconocidas de niveles anteriores.** Construcción de la contraseña en memoria (nivel 3), un predicado opaco de forma pitagórica (nivel 2), despacho por vtable (nivel 4), y una comparación manual sin `strcmp`/`strncmp` nombrado (nivel 3). Reconocer cada una de inmediato, en vez de volver a analizarlas desde cero, fue lo que hizo manejable un nivel que de otro modo habría sido abrumador.
- **Relocación de código a memoria ejecutable — sin efecto real contra el análisis estático.** El programa copia su propia función de validación a una región de memoria reservada con `VirtualAlloc`, pero al ser una copia byte a byte sin ninguna transformación, no oculta nada que Ghidra no pudiera ya mostrar en la ubicación estática original.
- **Una detección de depurador que sí funciona.** A diferencia de las ramas muertas del nivel 2, este `IsDebuggerPresent()` bloquea de verdad el camino de éxito si el binario corre bajo un depurador — la primera medida defensiva de la serie que habría interferido con un enfoque dinámico.
- **Un hilo sin resolver, documentado como tal.** No confirmé los valores reales del predicado pitagórico de este nivel ni analicé la rama alternativa (`FUN_14001c160`) que se toma si esa condición fuera falsa. Queda anotado como una pregunta abierta en vez de una afirmación sin respaldo.

La lección de cierre de la serie: a partir de cierto punto, resolver un binario ofuscado deja de ser reconocer una técnica aislada y pasa a ser reconocer varias a la vez, superpuestas, y saber en qué orden desenredarlas. Ese reconocimiento de patrones —construido nivel a nivel a lo largo de esta serie— es lo que convirtió el nivel más largo en algo resoluble en vez de abrumador.

---

© 2026 Gino Aldair Maihuiri Romero
