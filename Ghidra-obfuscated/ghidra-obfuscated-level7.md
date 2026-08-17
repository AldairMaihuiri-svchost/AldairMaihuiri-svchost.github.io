---
title: "Ghidra contra binarios ofuscados — Nivel 7: aritmética booleana mixta y shellcode dinámico"
description: "Séptimo nivel de la serie de entrenamiento en Ghidra sobre binarios ofuscados. Un crackme PE32+ que oculta un hash FNV-1a estándar detrás de identidades de aritmética booleana mixta (OR/AND en vez de XOR, XOR más acarreo en vez de suma), y esconde el valor objetivo de la comparación dentro de un fragmento de shellcode que el propio binario ensambla y descifra en memoria ejecutable antes de invocarlo."
author: Aldair Maihuiri
---

# Ghidra contra binarios ofuscados — Nivel 7: aritmética booleana mixta y shellcode dinámico

**Gino Aldair Maihuiri Romero**

([English version](ghidra-obfuscated-level7-en)) · ([Nivel 1](ghidra-obfuscated-level1)) · ([Nivel 2](ghidra-obfuscated-level2)) · ([Nivel 3](ghidra-obfuscated-level3)) · ([Nivel 4](ghidra-obfuscated-level4)) · ([Nivel 5](ghidra-obfuscated-level5)) · ([Nivel 6](ghidra-obfuscated-level6))

El nombre de la carpeta de este binario es `nivel7_mba`, y las siglas ya anticipan de qué se trata: aritmética booleana mixta (*Mixed Boolean-Arithmetic*), una técnica de ofuscación que no cifra ni esconde datos, sino que reescribe operaciones simples —un XOR, una suma— como combinaciones de otras operaciones matemáticamente equivalentes pero visualmente irreconocibles. Este nivel apila esa técnica sobre otra que ya había visto en el nivel 6: la validación real no vive en la función principal, sino en un fragmento de shellcode que el propio binario ensambla y descifra en memoria ejecutable antes de invocarlo. Entre las dos capas, terminé cometiendo y corrigiendo dos errores propios durante el análisis, y ambos quedan documentados aquí tal como ocurrieron, porque enseñan tanto como el resultado final.

Mismo entorno de siempre: Linux, PE32+ de Windows, análisis estático en Ghidra primero, verificación con Wine al final.

---

## Reconocimiento y hallazgo directo

```
$ file crackme.exe
crackme.exe: PE32+ executable for MS Windows 5.02 (console), x86-64 (stripped to external PDB), 10 sections
```

Fui directo a `Defined Strings`, sin pasar por `strncmp` ni por ningún desvío de C++, tal como en el nivel 6. Encontré `"Password: "` en `14000406e`, con una única referencia a `FUN_140002c20`. Esa función contiene toda la lógica de orquestación del crackme.

## La función principal: shellcode ensamblado en memoria

```c
undefined8
FUN_140002c20(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4)
{
  uint uVar1;
  int iVar2;
  FILE *pFVar3;
  char *pcVar4;
  size_t sVar5;
  code *lpBaseAddress;
  longlong lVar6;
  HANDLE hProcess;
  DWORD flProtect;
  byte local_58 [72];

  FUN_1400016e0();
  FUN_140002900("Password: ",param_2,param_3,param_4);
  pFVar3 = (FILE *)__acrt_iob_func(1);
  fflush(pFVar3);
  pFVar3 = (FILE *)__acrt_iob_func(0);
  pcVar4 = fgets((char *)local_58,0x40,pFVar3);
  if (pcVar4 != (char *)0x0) {
    sVar5 = strcspn((char *)local_58,"\n");
    flProtect = 0x40;
    local_58[sVar5] = 0;
    uVar1 = FUN_140001580(local_58);
    lpBaseAddress = VirtualAlloc((LPVOID)0x0,0xe,0x3000,flProtect);
    if (lpBaseAddress != (code *)0x0) {
      *(undefined8 *)lpBaseAddress = 0xfc839cdb73089b8;
      lVar6 = 8;
      do {
        lpBaseAddress[lVar6] = (code)((&DAT_140004090)[lVar6] ^ 0x5a);
        lVar6 = lVar6 + 1;
      } while (lVar6 != 0xe);
      hProcess = GetCurrentProcess();
      FlushInstructionCache(hProcess,lpBaseAddress,0xe);
      iVar2 = (*lpBaseAddress)(uVar1);
      pcVar4 = "[-] Incorrecto.";
      if (iVar2 != 0) {
        pcVar4 = "[+] Correcto!";
      }
      puts(pcVar4);
      return 0;
    }
    puts("[-] Error interno.");
  }
  return 1;
}
```

El prompt, la lectura y el recorte del salto de línea son los de siempre. Lo que sigue es la parte interesante: la entrada del usuario no se compara directamente contra nada aquí. En cambio, se pasa por `FUN_140001580` para obtener un valor numérico (`uVar1`), se reserva una página de memoria ejecutable con `VirtualAlloc` (14 bytes, flags `0x3000` y `0x40` = `PAGE_EXECUTE_READWRITE`, el mismo patrón que ya había visto en el nivel 5), se ensamblan 14 bytes de código máquina en esa página —8 bytes escritos directamente como constante, 6 más descifrados con XOR contra `0x5a` desde `DAT_140004090`—, se sincroniza la caché de instrucciones, y recién entonces se invoca ese bloque de memoria como si fuera una función, pasándole `uVar1` como único argumento. El resultado de esa llamada decide el mensaje final.

Dos preguntas separadas, entonces: qué hace `FUN_140001580` con la contraseña, y qué compara exactamente el shellcode una vez ensamblado.

## Desenredando la aritmética booleana mixta

```c
uint FUN_140001580(byte *param_1)
{
  byte bVar1;
  int iVar2;
  uint uVar3;
  uint uVar4;
  uint local_20;

  bVar1 = *param_1;
  local_20 = 0x811c9dc5;
  while (bVar1 != 0) {
    param_1 = param_1 + 1;
    iVar2 = (local_20 | bVar1) - (local_20 & bVar1);
    uVar3 = iVar2 * 0x1000000;
    uVar4 = iVar2 * 0x193;
    local_20 = (uVar3 ^ uVar4) + (uVar3 & uVar4) * 2;
    bVar1 = *param_1;
  }
  return local_20;
}
```

A primera vista esto no se parece a nada reconocible, pero cada línea es una identidad matemática disfrazada. Las desenredé una por una.

**La primera línea**, `iVar2 = (local_20 | bVar1) - (local_20 & bVar1)`, es un XOR escrito como OR menos AND. Se puede verificar bit a bit: en cualquier posición donde ambos bits coinciden (00 o 11), el OR y el AND dan el mismo valor y la resta da 0 — que es también lo que da el XOR en esa posición. En cualquier posición donde los bits difieren (01 o 10), el OR da 1 y el AND da 0, así que la resta da 1 — otra vez, lo mismo que el XOR. No hay acarreos que se propaguen entre posiciones porque el OR nunca es menor que el AND en ningún bit individual. La identidad es exacta: `(A | B) - (A & B) = A ^ B`.

**La última línea**, `local_20 = (uVar3 ^ uVar4) + (uVar3 & uVar4) * 2`, es la identidad inversa: una suma disfrazada de XOR más acarreo. El XOR de dos números da la suma ignorando los acarreos entre posiciones, y el AND multiplicado por 2 reintroduce exactamente esos acarreos desplazados una posición a la izquierda, donde corresponden. La identidad `A + B = (A ^ B) + 2·(A & B)` también es exacta, sin necesidad de iterarla.

Con las dos disfraces retirados, lo que queda es:

```
iVar2 = local_20 ^ byte_actual
local_20 = (iVar2 * 0x1000000) + (iVar2 * 0x193)
         = iVar2 * (0x1000000 + 0x193)
```

Aquí me detuve a sumar la constante con cuidado, porque es exactamente el tipo de paso donde es fácil deslizar un dígito de más sin darse cuenta al pasar de cabeza dos números hexadecimales de longitud distinta. `0x1000000` son siete dígitos hexadecimales; `0x193` son tres. Alineados por el dígito menos significativo:

```
  1000000
+     193
---------
  1000193
```

`0x1000000 + 0x193 = 0x1000193` — siete dígitos, no ocho. Y ese valor, `0x1000193`, es exactamente la constante prima estándar del algoritmo **FNV-1a de 32 bits** (`0x01000193`, con el cero inicial que no cambia el valor). El valor inicial de `local_20`, `0x811c9dc5`, es también el *offset basis* estándar de FNV-1a, escrito ahí sin ningún disfraz. Con eso confirmado, `FUN_140001580` no es más que un FNV-1a de libro, con el paso de XOR y el paso de suma reescritos mediante identidades booleanas para que no se reconozcan a simple vista en el descompilador.

## Por qué no basta con reconocer el algoritmo

FNV-1a es una función de hash de una sola vía — no hay forma de despejar algebraicamente qué cadena produjo un valor final dado, solo se puede buscar una cadena que lo reproduzca. Y para buscarla hace falta el valor objetivo, que no aparece en ningún lado de `FUN_140002c20` ni de `FUN_140001580`: el resultado de `uVar1` simplemente se pasa como argumento al shellcode, y es el shellcode —ensamblado en tiempo de ejecución, no antes— el que sabe contra qué compararlo.

Por eso el paso siguiente no es matemático todavía. Es reconstruir el shellcode a mano, sin ejecutar nada, y desensamblarlo.

## Reconstruyendo el shellcode, y el primer error

El código escribe directamente los primeros 8 bytes del shellcode como una constante de 64 bits:

```c
*(undefined8 *)lpBaseAddress = 0xfc839cdb73089b8;
```

Para saber qué bytes quedan en memoria hay que recordar que x86-64 almacena los enteros en little-endian: el byte menos significativo del valor va en la dirección más baja. `0xfc839cdb73089b8` tiene 15 dígitos hexadecimales, así que hay que completarlo a 16 con un cero inicial: `0x0fc839cdb73089b8`. Agrupando de a dos dígitos desde el más significativo: `0f c8 39 cd b7 30 89 b8`. Invirtiendo ese orden para obtener la secuencia en memoria (de la dirección más baja a la más alta): `b8 89 30 b7 cd 39 c8 0f`.

Los seis bytes restantes vienen de un bucle:

```c
lVar6 = 8;
do {
  lpBaseAddress[lVar6] = (code)((&DAT_140004090)[lVar6] ^ 0x5a);
  lVar6 = lVar6 + 1;
} while (lVar6 != 0xe);
```

El índice `lVar6` arranca en 8, así que el primer byte que se lee es `(&DAT_140004090)[8]` — es decir, la dirección `DAT_140004090 + 8 = 140004098`, no `DAT_140004090` misma. Fui a esa dirección en el listado de memoria de Ghidra:

```
                             DAT_140004098                                   XREF[1]:     FUN_140002c20:140002ce0(R)
       140004098 ce              undefined1 CEh
                             DAT_140004099                                   XREF[1]:     FUN_140002c20:140002ce0(R)
       140004099 9a              undefined1 9Ah
       14000409a 55              ??         55h    U
       14000409b ec              ??         ECh
       14000409c 9a              ??         9Ah
       14000409d 99              ??         99h
```

Seis bytes: `ce 9a 55 ec 9a 99`. Aplicando XOR con `0x5a` a cada uno: `94 c0 0f b6 c0 c3`.

La primera vez que armé el bloque completo de 14 bytes, cometí un error de transcripción: en vez de usar los primeros 8 bytes que acababa de calcular correctamente (`b8 89 30 b7 cd 39 c8 0f`), terminé escribiendo una secuencia distinta que no correspondía a nada real. El desensamblado de esa secuencia incorrecta lo delató de inmediato: después de una primera instrucción que parecía razonable, el resto se desintegraba en instrucciones sin sentido en este contexto —una manipulación de banderas, una comparación contra el puntero de pila— que no encajaban con un simple bloque de comparación de 14 bytes. Un shellcode de 14 bytes bien reconstruido tiene que desensamblarse limpio, instrucción tras instrucción, sin que sobre ni falte un solo byte al final. Cuando no ocurre así, la reconstrucción está mal, no el desensamblador.

Volví a armar el bloque con los bytes correctos:

```
b8 89 30 b7 cd 39 c8 0f 94 c0 0f b6 c0 c3
```

Y esta vez el desensamblado fue limpio, completo, sin sobrar un byte:

```
mov eax, 0xcdb73089
cmp eax, ecx
sete al
movzx eax, al
ret
```

Cinco instrucciones, `5 + 2 + 3 + 3 + 1 = 14` bytes exactos. `ECX` es el registro donde la convención de llamada de Windows x64 coloca el primer argumento entero — en este caso, `uVar1`, el hash calculado por `FUN_140001580`. El shellcode entero se reduce a: cargar la constante `0xcdb73089`, compararla contra el hash de la entrada, y devolver 1 si coinciden.

## Resolviendo el hash — y el segundo error

Con el algoritmo identificado como FNV-1a estándar y el objetivo confirmado en `0xcdb73089`, quedaba encontrar una cadena que produjera ese hash exacto. En vez de recurrir a un solver SMT como en los niveles 4 y 6, esta vez planteé el problema con una técnica distinta: **meet-in-the-middle**. FNV-1a tiene una propiedad que la hace especialmente apta para esto — cada paso es `estado = (estado XOR byte) × primo`, y como el primo es impar, la multiplicación es invertible módulo 2³². Eso significa que, dado un estado final y una secuencia de bytes, se puede recuperar el estado anterior a esos bytes sin necesidad de adivinarlos: basta multiplicar por el inverso modular del primo y aplicar XOR con el byte conocido, en reversa.

La estrategia: dividir la contraseña candidata en una mitad delantera y una mitad trasera. Para la mitad delantera, calcular hacia adelante el estado que resulta de cada combinación posible de caracteres, empezando desde el *offset basis* estándar. Para la mitad trasera, calcular hacia atrás —invirtiendo cada paso— qué estado intermedio *tendría que existir* para que, continuando hacia adelante con esa combinación de caracteres, se llegue exactamente al hash objetivo. Si alguna combinación delantera y alguna combinación trasera producen el mismo estado intermedio, esas dos mitades juntas forman una contraseña válida. En vez de explorar las decenas de miles de millones de combinaciones completas, solo hace falta generar las combinaciones de cada mitad por separado —muchísimo menos— y buscar la coincidencia.

El primer intento con esta técnica devolvió una contraseña. La probé contra el binario real y falló. Volví a revisar la ecuación completa, paso por paso, y encontré el problema: había usado `0x10000193` como multiplicador en el script de búsqueda —el mismo error de un dígito de más en la suma hexadecimal que había estado a punto de cometer al simplificar `FUN_140001580` a mano, y que esta vez sí se me escapó al escribir la constante en el código. El solver encontró una cadena matemáticamente consistente con esa ecuación equivocada, pero una ecuación equivocada no tiene nada que ver con el binario real, por más que el solver "funcione" y devuelva un resultado. Corregí la constante a `0x1000193` y volví a ejecutar la búsqueda.

Antes de dar el resultado por bueno esta vez, lo verifiqué de dos formas independientes: con la fórmula simplificada de FNV-1a, y con la fórmula de aritmética booleana mixta tal como aparece literalmente en el binario, sin ninguna simplificación, byte por byte. Las dos coincidieron entre sí y con el objetivo `0xcdb73089`.

## Verificación

```
[house@archlinux nivel7_mba]$ wine crackme.exe
Password: hVZd8L
[+] Correcto!
[house@archlinux nivel7_mba]$
```

Confirmado — después de dos vueltas fallidas, cada una por una razón distinta y cada una detectada antes de darla por buena sin comprobar.

## Resumen del análisis

Este nivel combina dos capas de ofuscación genuinamente distintas, y el proceso de resolverlo enseñó tanto de mis propios errores como del binario:

- **Aritmética booleana mixta ocultando un algoritmo estándar.** `FUN_140001580` no inventa ninguna operación nueva — reescribe XOR como OR-menos-AND y suma como XOR-más-el-doble-del-AND, dos identidades bit a bit exactas que, una vez reconocidas, revelan que todo el asunto es FNV-1a de libro. La ofuscación está en el disfraz, no en la sustancia.
- **Un shellcode ensamblado en memoria ejecutable que sí hay que reconstruir, no solo desencriptar.** A diferencia del descifrado XOR simple del nivel 1, aquí hay que combinar correctamente dos fuentes distintas de bytes —una constante de 64 bits interpretada en little-endian, y un bucle de descifrado que empieza en un desplazamiento no evidente a primera vista— antes de tener algo que desensamblar.
- **Un desensamblado limpio es su propia validación.** Cuando la reconstrucción de bytes está mal, el desensamblador no falla silenciosamente — produce instrucciones que no encajan, o deja bytes sueltos al final. Esa señal es tan útil como cualquier otra pista del binario.
- **Un solver que devuelve un resultado no confirma que el planteamiento esté bien.** La primera contraseña encontrada era matemáticamente correcta para la ecuación que le di al buscador — solo que esa ecuación tenía una constante mal calculada. Verificar el resultado contra el binario real, y no solo contra la propia ecuación, fue lo que expuso el error.
- **Los mismos errores de aritmética hexadecimal amenazan en dos lugares distintos.** El deslice de sumar un dígito de más a `0x1000000 + 0x193` pudo haber ocurrido al simplificar la función a mano o al transcribir la constante al script de búsqueda — y de hecho estuvo a punto de ocurrir en el primer caso y ocurrió de verdad en el segundo. Vale la pena revisar la aritmética dos veces en cualquiera de los dos puntos.

La lección de este nivel, más allá de la técnica puntual, es que ni reconocer el algoritmo correcto ni tener una herramienta de búsqueda funcionando garantiza un resultado correcto — cada constante que se traduce a mano, del binario al papel o del papel al código, es un punto donde se puede introducir un error silencioso, y la única defensa real es verificar el resultado final contra el sistema real, no solo contra la propia lógica interna del análisis.

---

© 2026 Gino Aldair Maihuiri Romero
