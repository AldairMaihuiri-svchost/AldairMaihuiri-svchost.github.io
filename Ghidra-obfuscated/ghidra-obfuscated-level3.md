---
title: "Ghidra contra binarios ofuscados — Nivel 3: indirección"
description: "Tercer nivel de la serie de entrenamiento en Ghidra sobre binarios ofuscados. Un crackme PE32+ que separa la validación de la contraseña en dos funciones auxiliares encadenadas por un AND — comparación de longitud y comparación de contenido por separado — y construye la contraseña de referencia byte a byte en memoria en vez de almacenarla como literal."
author: Aldair Maihuiri
---

# Ghidra contra binarios ofuscados — Nivel 3: indirección

**Gino Aldair Maihuiri Romero**

([English version](ghidra-obfuscated-level3-en)) · ([Nivel 1](ghidra-obfuscated-level1)) · ([Nivel 2](ghidra-obfuscated-level2))

Los dos niveles anteriores ocultaban la contraseña de dos formas distintas: cifrándola (nivel 1) o enterrando la lógica de validación bajo ramas muertas y un predicado opaco reutilizado (nivel 2). Este tercero usa una técnica distinta a ambas: la comparación en sí no está cifrada ni envuelta en ramas falsas — está **fragmentada en dos funciones separadas**, encadenadas por una condición lógica, y la propia contraseña de referencia no existe como string en ningún lugar del binario, se ensambla byte a byte en memoria justo antes de compararla. El nombre de la carpeta, `nivel3_indirect`, describe exactamente el mecanismo: en vez de un `strcmp` directo contra un literal, hay una cadena de indirecciones que hay que seguir hasta el final para entender qué se está comparando y contra qué.

Mismo entorno que los niveles anteriores: Linux, binario PE32+ de Windows, análisis estático en Ghidra primero y verificación con Wine al final.

---

## Reconocimiento inicial

```
$ file crackme.exe
crackme.exe: PE32+ executable for MS Windows 5.02 (console), x86-64 (stripped to external PDB), 10 sections
```

Mismo perfil que los dos anteriores.

## Un desvío que ya empieza a resultar familiar

Fui directo a `API-MS-WIN-CRT-STRING-L1-1-0.DLL` a buscar `strncmp`, y sus referencias:

```
140008498    strncmp    JMP qword ptr [->API-MS-WIN-CRT-STRING-L1-1-0.DLL::strncmp]    COMPUTED_JUMP
140008498    strncmp    JMP qword ptr [->API-MS-WIN-CRT-STRING-L1-1-0.DLL::strncmp]    THUNK
14000f538    PTR_strncmp_14000f538    addr API-MS-WIN-CRT-STRING-L1-1-0.DLL::strncmp    DATA
```

Buscando la referencia a `8498` llegué a:

```
14000258c    CALL API-MS-WIN-CRT-STRING-L1-1-0.DLL::strncmp    UNCONDITIONAL_CALL
```

Y, como en el nivel anterior, esto no fue la lógica del crackme:

```c
/* WARNING: Enum "SectionFlags": Some values do not have unique names */
IMAGE_SECTION_HEADER * FUN_140002510(char *param_1)
{
  int iVar1;
  size_t sVar2;
  IMAGE_SECTION_HEADER *_Str1;
  uint uVar3;

  sVar2 = strlen(param_1);
  if (sVar2 < 9) {
    uVar3 = 0;
    _Str1 = &IMAGE_SECTION_HEADER_140000188;
    do {
      iVar1 = strncmp(_Str1->Name,param_1,8);
      if (iVar1 == 0) {
        return _Str1;
      }
      uVar3 = uVar3 + 1;
      _Str1 = _Str1 + 1;
    } while (uVar3 < 10);
  }
  return (IMAGE_SECTION_HEADER *)0x0;
}
```

Es la misma función de búsqueda de cabeceras de sección del PE que ya apareció en el nivel 2 — con la dirección desplazada porque el binario es distinto, pero la lógica es idéntica. A estas alturas de la serie ya reconozco el patrón de memoria: cuando sigo `strncmp` y aparece este bloque, sé que estoy en código de arranque interno, no en la validación, y toca buscar por otro camino. Vale la pena documentarlo de nuevo aquí porque es útil verlo repetirse — la primera vez fue un hallazgo, la segunda ya es una firma reconocible del binario base sobre el que están construidos estos crackmes.

## Pivotando por las strings — con una diferencia notable

Fui a `Defined Strings` a buscar el mensaje de éxito, igual que en los niveles anteriores. Encontré `[+] Correcto!` en `14000a050`:

```
                             s_[+]_Correcto!_14000a050                       XREF[2]:     FUN_140008680:1400086fe(*),
                                                                                          FUN_140008680:140008721(*)
       14000a050 5b 2b 5d        ds         "[+] Correcto!"
                 20 43 6f
                 72 72 65
```

Solo dos referencias cruzadas, no cinco como en el nivel 2. Ya con eso puedo anticipar que este nivel no reutiliza el mismo predicado como guardia de ramas muertas — la ofuscación aquí va a venir de otro lado. Con `FUN_140008680` identificada como la función objetivo, fui directo al decompilador.

## La función de validación

```c
undefined8 FUN_140008680(undefined8 param_1,ulonglong param_2,undefined8 param_3,undefined8 param_4)
{
  bool bVar1;
  FILE *pFVar2;
  char *pcVar3;
  size_t sVar4;
  undefined7 extraout_var;
  undefined7 extraout_var_00;
  undefined8 uVar5;
  char *pcVar6;
  char *_Str;
  char local_48 [64];

  FUN_1400016e0();
  FUN_1400028c0((byte *)"Password: ",param_2,param_3,param_4);
  pFVar2 = (FILE *)__acrt_iob_func(1);
  fflush(pFVar2);
  pFVar2 = (FILE *)__acrt_iob_func(0);
  pcVar3 = fgets(local_48,0x40,pFVar2);
  if (pcVar3 == (char *)0x0) {
    uVar5 = 1;
  }
  else {
    sVar4 = strcspn(local_48,"\n");
    pcVar6 = &DAT_14000e0a0;
    pcVar3 = local_48;
    local_48[sVar4] = '\0';
    _Str = "[-] Incorrecto.";
    FUN_1400015d0();
    bVar1 = FUN_1400015a0(pcVar3,pcVar6);
    if (((int)CONCAT71(extraout_var,bVar1) != 0) &&
       (bVar1 = FUN_140001580(local_48,&DAT_14000e0a0), (int)CONCAT71(extraout_var_00,bVar1) != 0))
    {
      _Str = "[+] Correcto!";
    }
    puts(_Str);
    uVar5 = 0;
  }
  return uVar5;
}
```

A diferencia de los dos niveles anteriores, aquí no hay un `strcmp` a la vista dentro de esta función. La validación se reparte entre dos llamadas encadenadas con un AND: `FUN_1400015a0(pcVar3, pcVar6)` primero, y solo si esa devuelve verdadero, `FUN_140001580(local_48, &DAT_14000e0a0)` después. Las dos tienen que devolver verdadero para que `_Str` cambie a `"[+] Correcto!"`. Antes de sacar conclusiones, entré a cada una.

## Desmontando las dos funciones de validación

**La primera — comprobación de longitud, no de contenido:**

```c
bool FUN_1400015a0(char *param_1,char *param_2)
{
  size_t sVar1;
  size_t sVar2;

  sVar1 = strlen(param_1);
  sVar2 = strlen(param_2);
  return sVar1 == sVar2;
}
```

Esta función no compara el contenido de las dos cadenas — solo sus longitudes. `param_1` es la entrada del usuario, `param_2` es un puntero a `DAT_14000e0a0`, que a esta altura no sabía todavía qué contenía. Esta es la primera capa de indirección del nivel: la condición que hay que cumplir primero no es "la contraseña es correcta", es "la contraseña tiene el largo correcto" — un chequeo separado que, leído aislado en el decompilador sin ver la función que lo llama, no deja claro qué es lo que en realidad se está verificando.

**Yendo a ver qué hay en `DAT_14000e0a0`:**

```
                             DAT_14000e0a0                                   XREF[3]:     FUN_1400015d0:1400015d6(W),
                                                                                          FUN_140008680:1400086d8(*),
                                                                                          FUN_140008680:14000870e(*)
       14000e0a0                 ??         ??
```

Sin valor visible directamente — pero la primera referencia cruzada, marcada con `(W)`, me llamó la atención de inmediato. Una `W` en Ghidra suele indicar una escritura (*write*) sobre esa dirección, lo que significa que algo, en algún punto del programa, escribe en `DAT_14000e0a0` en tiempo de ejecución en vez de que el valor ya esté ahí desde que se compiló el binario. Fui a `FUN_1400015d0` a confirmarlo.

**La función que construye la contraseña de referencia, byte a byte:**

```c
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */
void FUN_1400015d0(void)
{
  _DAT_14000e0a0 = 0x31646e31;
  uRam000000014000e0a4 = 0x3372;
  DAT_14000e0a6 = 99;
  uRam000000014000e0a7 = 0x74;
  DAT_14000e0a8 = 0;
  return;
}
```

No era lo que esperaba encontrar, pero apenas la leí quedó claro: esta función construye la contraseña real dentro de la memoria, en el momento en que se llama, en vez de que exista como un string ya listo en la sección de datos del binario. Es la misma idea que ya había visto con el prompt `"Password: "` del nivel 1 —ensamblar bytes directamente en vez de referenciar un literal— pero aplicada esta vez a la contraseña misma, no solo a un texto decorativo.

Fui reconstruyendo la cadena byte a byte, teniendo en cuenta que x86-64 almacena los enteros en memoria en orden little-endian:

- `_DAT_14000e0a0 = 0x31646e31` — cuatro bytes. En memoria, del menos significativo al más significativo: `31 6e 64 31`. En ASCII: `1`, `n`, `d`, `1` → `"1nd1"`.
- `uRam000000014000e0a4 = 0x3372` — dos bytes: `72 33` → `r`, `3` → `"r3"`.
- `DAT_14000e0a6 = 99` — un byte, `0x63` → `c`.
- `uRam000000014000e0a7 = 0x74` — un byte → `t`.
- `DAT_14000e0a8 = 0` — terminador nulo.

Uniendo todo en orden de dirección de memoria: `1nd1` + `r3` + `c` + `t` = **`1nd1r3ct`** — que, leído en leetspeak, dice "indirect". El nombre de la carpeta del binario no era casualidad: la propia contraseña es el nombre del nivel.

Antes de tener la reconstrucción completa, probé pegando solo el primer fragmento a mano en la terminal:

```
[house@archlinux nivel3_indirect]$ wine crackme.exe
Password: 1ed1
[-] Incorrecto.
```

(Ese primer intento tiene una pequeña variación de tipeo frente al valor exacto reconstruido, `1nd1` — pero el resultado no cambia: de todas formas era solo un fragmento de ocho caracteres, incompleto, así que el rechazo era el esperado en cualquier caso.) Con la cadena completa:

```
Password: 1nd1r3ct
[+] Correcto!
[house@archlinux nivel3_indirect]$
```

## Volviendo a la segunda función, para cerrar el análisis

Con la contraseña ya confirmada, volví a `FUN_140001580` para entender qué hace exactamente la segunda mitad del AND — la parte que de verdad decide si el contenido coincide:

```c
bool FUN_140001580(char *param_1,char *param_2)
{
  int iVar1;

  iVar1 = strcmp(param_1,param_2);
  return iVar1 == 0;
}
```

Aquí está, finalmente, la comparación real: un `strcmp` de toda la vida, envuelto en una función que solo devuelve verdadero o falso en vez de exponer directamente el resultado entero de `strcmp`. Es la segunda capa de indirección del nivel: no alcanza con saber que en algún lugar hay un `strcmp` — hay que saber que ese `strcmp` solo se ejecuta si la comprobación de longitud anterior ya pasó, y que su resultado booleano es el segundo operando de un AND cuyo primer operando está en una función completamente distinta.

## Resumen del análisis

Este nivel no repite ni el cifrado del nivel 1 ni las ramas muertas del nivel 2 — introduce una técnica propia:

- **Validación fragmentada en dos funciones encadenadas por AND.** En vez de un único `strcmp` visible en la función principal, la comparación se reparte entre una función que solo verifica longitud y otra que solo verifica contenido, y ambas tienen que devolver verdadero. Leer cualquiera de las dos por separado, sin ver quién las llama y en qué orden, no revela la lógica completa.
- **Contraseña construida en memoria, no almacenada como literal.** `DAT_14000e0a0` no existe como string en el binario compilado — se ensambla byte a byte, incluyendo un entero de 32 bits interpretado en little-endian, justo antes de la comparación. Encontrar la XREF marcada con `(W)` fue la pista que llevó directo a la función constructora.
- **Un desvío ya reconocible.** La función de búsqueda de secciones del PE que apareció como callejón sin salida en el nivel 2 volvió a aparecer aquí, en la misma posición del flujo de análisis. Vale la pena aprender a reconocerla rápido en vez de volver a investigarla desde cero cada vez.

La lección central de este nivel es que seguir una sola función hasta el final no basta cuando la lógica está repartida entre varias. Hay que reconstruir la cadena completa de llamadas —quién llama a quién, con qué argumentos, y bajo qué condición— antes de poder afirmar que se entendió la validación completa.

---

© 2026 Gino Aldair Maihuiri Romero
