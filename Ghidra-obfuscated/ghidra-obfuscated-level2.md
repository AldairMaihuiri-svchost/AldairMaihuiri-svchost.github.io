---
title: "Ghidra contra binarios ofuscados — Nivel 2: ofuscación de flujo de control"
description: "Segundo nivel de la serie de entrenamiento en Ghidra sobre binarios ofuscados. Un crackme PE32+ que reutiliza un mismo predicado opaco como guardia de varias ramas muertas con lógica invertida, y valida la contraseña mediante una suma ponderada módulo 256 sin solución única."
author: Aldair Maihuiri
---

# Ghidra contra binarios ofuscados — Nivel 2: ofuscación de flujo de control

**Gino Aldair Maihuiri Romero**

([English version](ghidra-obfuscated-level2-en)) · ([Nivel 1](ghidra-obfuscated-level1))

Este es el segundo nivel de la serie. En el primero la ofuscación estaba en cómo se construían las strings — el reto era encontrar dónde vivía la contraseña una vez que `Defined Strings` no ayudaba. Aquí el reto cambia de naturaleza: la contraseña en sí no está cifrada, está protegida por una validación matemática sin solución única, y el código que la rodea está deliberadamente duplicado para incluir ramas que parecen válidas pero nunca se ejecutan. El nombre de la carpeta del binario, `nivel2_ctrlflow`, ya avisa por dónde va la cosa, y una vez dentro del decompilador la razón queda clara.

Como en el nivel anterior, trabajo en Linux y el binario es un PE32+ de Windows, así que el análisis es enteramente estático en Ghidra. La diferencia con el nivel 1 es que aquí sí tuve que instalar Wine al final, por una razón que explico más adelante y que es, en sí misma, parte de la lección de este nivel.

---

## Reconocimiento inicial

Lo de siempre primero:

```
$ file crackme.exe
crackme.exe: PE32+ executable for MS Windows 5.02 (console), x86-64 (stripped to external PDB), 10 sections
```

Mismo perfil que el nivel 1: PE32+ de consola, x86-64, símbolos retirados a un PDB externo, diez secciones. Nada distinto todavía a nivel de formato.

## De la string a la función — y un primer callejón sin salida

Fui directo a los imports. En `API-MS-WIN-CRT-STRING-L1-1-0.DLL` esta vez encontré `strncmp` en vez de `strcmp` — la variante con límite de longitud. Revisando sus referencias:

```
140008410    strncmp    JMP qword ptr [->API-MS-WIN-CRT-STRING-L1-1-0.DLL::strncmp]    COMPUTED_JUMP
140008410    strncmp    JMP qword ptr [->API-MS-WIN-CRT-STRING-L1-1-0.DLL::strncmp]    THUNK
14000f528    PTR_strncmp_14000f528    addr API-MS-WIN-CRT-STRING-L1-1-0.DLL::strncmp    DATA
```

El thunk en el decompilador:

```c
int __cdecl strncmp(char *_Str1,char *_Str2,size_t _MaxCount)

{
  int iVar1;

                    /* WARNING: Could not recover jumptable at 0x000140008410. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  iVar1 = strncmp(_Str1,_Str2,_MaxCount);
  return iVar1;
}
```

Hasta aquí, casi calcado del nivel 1: una comparación entre dos strings. Fui a buscar quién llama a ese thunk y encontré una única referencia:

```
1400024ec        CALL API-MS-WIN-CRT-STRING-L1-1-0.DLL::strncmp    UNCONDITIONAL_CALL
```

Pero la función a la que me llevó esa dirección no fue lo que esperaba:

```c
IMAGE_SECTION_HEADER * FUN_140002470(char *param_1)

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

Esto no es la lógica del crackme. Es una función que recorre las diez cabeceras de sección del propio PE (`IMAGE_SECTION_HEADER`) buscando una por nombre — típico de código de arranque o de utilidades internas del binario, no de la validación de contraseña. Vale la pena dejarlo documentado como lo que es: un callejón sin salida, y una lección concreta para este nivel. En el nivel 1 solo había una llamada a `strcmp` en todo el binario, así que seguir la referencia era directo. Aquí `strncmp` tiene varios llamadores posibles y no todos van a donde uno espera. La API correcta no garantiza el sitio correcto — hay que leer qué hace la función antes de asumir que es la que buscas.

## Pivotando por las strings de resultado

Con el camino de `strncmp` agotado como pista directa, cambié de estrategia y fui a `Defined Strings` a buscar los mensajes de resultado, igual que en el nivel 1. Encontré `[+] Correcto!` en `14000a050`. Fui a esa dirección a ver sus referencias, y aquí apareció el primer indicio real de que el nombre `ctrlflow` no es casualidad:

```
                             s_[+]_Correcto!_14000a050                       XREF[5]:     FUN_140008600:14000870e(*),
                                                                                          FUN_140008600:140008757(*),
                                                                                          FUN_140008600:14000876b(*),
                                                                                          FUN_140008600:14000878f(*),
                                                                                          FUN_140008600:140008796(*)
       14000a050 5b 2b 5d        ds         "[+] Correcto!"
                 20 43 6f
                 72 72 65
```

Cinco referencias cruzadas a la misma cadena de éxito, todas dentro de una sola función, `FUN_140008600`. En un binario sin ofuscar, un mensaje de éxito se imprime desde un único punto del código. Verlo referenciado cinco veces dentro de la misma función es la primera huella de que el flujo de control ahí dentro no es lineal — más adelante, al leer la función completa, se ve exactamente por qué.

Para confirmar que estaba en la función correcta, busqué también el string `"Password: "`:

```
                             s_Password:_14000a06e                           XREF[1]:     FUN_140008600:14000860a(*)
       14000a06e 50 61 73        ds         "Password: "
                 73 77 6f
                 72 64 3a
```

Una sola referencia, también dentro de `FUN_140008600`. Con el prompt y el mensaje de éxito apuntando a la misma función, ya no hay duda: ahí está la lógica de validación completa. El problema es que, a diferencia del nivel 1, esa función no se lee de corrido.

## La función de validación completa

```c
undefined8 FUN_140008600(undefined8 param_1,ulonglong param_2,undefined8 param_3,undefined8 param_4)
{
  byte bVar1;
  FILE *pFVar2;
  char *pcVar3;
  undefined8 uVar4;
  size_t sVar5;
  byte *pbVar6;
  int iVar7;
  int iVar8;
  byte local_48 [64];

  FUN_140001650();
  FUN_140002820((byte *)"Password: ",param_2,param_3,param_4);
  pFVar2 = (FILE *)__acrt_iob_func(1);
  fflush(pFVar2);
  pFVar2 = (FILE *)__acrt_iob_func(0);
  pcVar3 = fgets((char *)local_48,0x40,pFVar2);
  uVar4 = 1;
  if (pcVar3 != (char *)0x0) {
    sVar5 = strcspn((char *)local_48,"\n");
    local_48[sVar5] = 0;
    if (DAT_140009018 * DAT_140009018 + DAT_140009014 * DAT_140009014 ==
        DAT_140009010 * DAT_140009010) {
      sVar5 = strlen((char *)local_48);
      if (sVar5 == 8) {
        pbVar6 = local_48;
        iVar8 = 0;
        iVar7 = 0;
        do {
          bVar1 = *pbVar6;
          iVar7 = iVar7 + 1;
          pbVar6 = pbVar6 + 1;
          iVar8 = iVar8 + (uint)bVar1 * iVar7;
        } while (iVar7 != 8);
        if (DAT_140009018 * DAT_140009018 + DAT_140009014 * DAT_140009014 ==
            DAT_140009010 * DAT_140009010) {
          pcVar3 = "[+] Correcto!";
          if ((char)iVar8 != '*') {
            pcVar3 = "[-] Incorrecto.";
          }
        }
        else {
          pcVar3 = "[-] Incorrecto.";
          if ((char)iVar8 != '*') {
            pcVar3 = "[+] Correcto!";
          }
        }
      }
      else if (DAT_140009014 * DAT_140009014 + DAT_140009018 * DAT_140009018 ==
               DAT_140009010 * DAT_140009010) {
        pcVar3 = "[-] Incorrecto.";
      }
      else {
        pcVar3 = "[+] Correcto!";
      }
      puts(pcVar3);
      uVar4 = 0;
    }
    else {
      puts("[+] Correcto!");
      uVar4 = 0;
    }
  }
  return uVar4;
}
```

La primera vez que leí esto no me cuadraba: había demasiadas ramas para una lógica que, según había deducido, era solo "suma ponderada módulo 256 igual a 42". La razón es que el autor no escribió una sola vez esa lógica — la escribió una vez de forma correcta y, alrededor de ella, sembró copias con la lógica invertida, todas guardadas por la misma condición.

## Descomponiendo la validación

**Entrada.** Nada inusual: se imprime `"Password: "`, se lee con `fgets` en un buffer de 64 bytes, y se recorta el salto de línea con `strcspn`.

**El predicado que decide todo.** La primera condición real del código es:

```c
DAT_140009018 * DAT_140009018 + DAT_140009014 * DAT_140009014 == DAT_140009010 * DAT_140009010
```

Tres variables globales, sin ninguna dependencia de la entrada del usuario. La forma algebraica es la del teorema de Pitágoras — la suma de dos cuadrados igual a un tercero. No extraje los bytes de memoria de esas tres direcciones como sí hice con los buffers cifrados del nivel 1, así que no puedo afirmar con certeza que los valores sean 3, 4 y 5; lo que sí puedo afirmar, porque se deduce de la propia estructura del código y se confirma con el comportamiento real del binario, es que esta condición se cumple siempre. Son constantes globales que ninguna parte de la función modifica, así que el resultado de la comparación es fijo desde que el programa arranca. Esto es un predicado opaco en el sentido estricto: una condición que, en teoría, un analista tendría que evaluar en tiempo de ejecución, pero que en la práctica es una constante que el compilador (o el ofuscador) se niega a resolver por adelantado.

**La trampa del `else` exterior.** Justo debajo de ese predicado hay un `else` que dice, literalmente:

```c
else {
  puts("[+] Correcto!");
  uVar4 = 0;
}
```

Leído aislado, esto parece decir "si el predicado es falso, el programa imprime éxito sin comprobar nada más" — lo cual, si fuera alcanzable, sería una forma trivial de saltarse toda la validación. Pero no es alcanzable: como el predicado es siempre verdadero, este `else` es código muerto. Es la primera de varias ramas de este tipo en la función, y su función no es ejecutarse — es aparecer como una posibilidad tentadora para quien lee rápido o para una herramienta de análisis que no logre demostrar que el predicado es constante.

**Longitud fija.** Dentro de la rama verdadera (la única alcanzable), se exige que la entrada tenga exactamente 8 caracteres:

```c
sVar5 = strlen((char *)local_48);
if (sVar5 == 8) { ... }
```

**La suma ponderada.** El núcleo real del crackme. Se recorre cada uno de los 8 bytes de la entrada, se multiplica por su posición (empezando en 1) y se acumula:

```c
pbVar6 = local_48;
iVar8 = 0;
iVar7 = 0;
do {
  bVar1 = *pbVar6;
  iVar7 = iVar7 + 1;
  pbVar6 = pbVar6 + 1;
  iVar8 = iVar8 + (uint)bVar1 * iVar7;
} while (iVar7 != 8);
```

En notación matemática:

```
iVar8 = (c0×1) + (c1×2) + (c2×3) + (c3×4) + (c4×5) + (c5×6) + (c6×7) + (c7×8)
```

donde cada `c_i` es el valor ASCII del carácter en esa posición.

**El mismo predicado, otra vez, con la lógica invertida al lado.** Justo después del bucle, el código vuelve a evaluar exactamente la misma condición pitagórica:

```c
if (DAT_140009018 * DAT_140009018 + DAT_140009014 * DAT_140009014 ==
    DAT_140009010 * DAT_140009010) {
  pcVar3 = "[+] Correcto!";
  if ((char)iVar8 != '*') {
    pcVar3 = "[-] Incorrecto.";
  }
}
else {
  pcVar3 = "[-] Incorrecto.";
  if ((char)iVar8 != '*') {
    pcVar3 = "[+] Correcto!";
  }
}
```

La rama verdadera (siempre alcanzada) es la lógica real: por defecto asume éxito, y lo revierte a fallo si `(char)iVar8` no coincide con `'*'` — el casteo a `char` se queda con el byte menos significativo de la suma, es decir, el resultado módulo 256. La condición de victoria completa es: la suma ponderada, reducida a un solo byte, tiene que ser exactamente 42 (el valor ASCII de `'*'`).

La rama `else` es la parte más interesante de este nivel: no es solo código muerto, es una **copia invertida** de la lógica real. Por defecto asume fallo, y lo revierte a éxito si `(char)iVar8` no coincide con `'*'` — exactamente lo contrario de la rama viva. No es un descuido del autor: es una réplica deliberada de la lógica de validación con el resultado invertido, colocada detrás de una condición que nunca se cumple. Si alguien intentara parchear el binario invirtiendo a mano el salto de esta condición sin entender que el predicado es constante, terminaría activando una validación que acepta exactamente las contraseñas que deberían fallar y rechaza las que deberían pasar.

**El mismo patrón, una tercera vez, para la longitud incorrecta.** Si la entrada no tiene 8 caracteres, el código no se limita a imprimir "Incorrecto" directamente — vuelve a evaluar el predicado pitagórico (con los operandos de la suma en otro orden, algebraicamente idéntico) antes de decidir el mensaje:

```c
else if (DAT_140009014 * DAT_140009014 + DAT_140009018 * DAT_140009018 ==
         DAT_140009010 * DAT_140009010) {
  pcVar3 = "[-] Incorrecto.";
}
else {
  pcVar3 = "[+] Correcto!";
}
```

La rama alcanzable imprime correctamente "Incorrecto" cuando la longitud no es 8. La rama `else` final —también muerta— es otra trampa: imprimiría "[+] Correcto!" para una contraseña de longitud equivocada, algo que nunca ocurre porque el predicado que la guarda jamás es falso.

**Sobre las cinco referencias al string de éxito.** Contando el código fuente reconstruido, `"[+] Correcto!"` aparece cuatro veces como literal: en el `else` exterior muerto, en la rama viva de la comprobación final, en la rama muerta invertida de esa misma comprobación, y en la rama muerta del caso de longitud incorrecta. Ghidra reportó cinco referencias cruzadas. No tengo forma de confirmar con certeza a qué corresponde la quinta sin desensamblar instrucción por instrucción, pero es consistente con que el compilador —o el paso de ofuscación— haya generado una carga duplicada de la dirección del string en alguno de esos saltos, algo habitual cuando el flujo de control de una función se reestructura o se duplica artificialmente. Documento la discrepancia en vez de forzarla a cuadrar: cuatro apariciones confirmadas en el código fuente, cinco referencias cruzadas observadas en Ghidra.

## Por qué esto no tiene una única solución

Independientemente de las ramas muertas, la lógica que realmente se ejecuta es clara: la suma de cada carácter de la contraseña multiplicado por su posición (1 a 8), reducida a un solo byte, tiene que dar exactamente 42. Esto es distinto del nivel anterior. En el nivel 1 la contraseña era una cadena fija embebida en el binario — solo había que encontrarla. Aquí no hay ninguna cadena de referencia: la validación es una ecuación modular, y una ecuación módulo 256 con ocho variables libres tiene, casi con toda seguridad, muchísimas soluciones. No estoy extrayendo una contraseña del binario; estoy generando una que satisfaga la ecuación.

Para comprobarlo en papel antes de automatizarlo: si eligiera arbitrariamente los primeros siete caracteres como `AAAAAAA` (siete `A`, cada una con valor ASCII 65), la suma parcial de las posiciones 1 a 7 sería:

```
65×1 = 65
65×2 = 130
65×3 = 195
65×4 = 260
65×5 = 325
65×6 = 390
65×7 = 455
suma parcial = 1820
```

Y bastaría con elegir el octavo carácter de forma que `1820 + (c7 × 8)` diera 42 módulo 256 — hay más de un valor de `c7` en el rango ASCII imprimible que puede cumplir eso, dependiendo de cómo se acomoden los módulos.

## Generando una contraseña válida

En vez de resolver la ecuación a mano para un caso específico, escribí un script que prueba combinaciones aleatorias de siete caracteres y busca, para cada una, qué octavo carácter completa la ecuación:

```python
import random


def encontrar_contrasena():
  print("[*] Buscando una contraseña válida de 8 caracteres...")

  while True:
    # 1. Elegimos 7 caracteres aleatorios (letras mayúsculas de la A a la Z)
    chars = [chr(random.randint(65, 90)) for _ in range(7)]

    # 2. Calculamos la suma ponderada de los primeros 7 (letra * posición del 1 al 7)
    suma_parcial = sum(ord(c) * (i + 1) for i, c in enumerate(chars))

    # 3. Probamos qué carácter (del espacio 32 al 126 ASCII) completa la ecuación
    for ascii_val in range(32, 127):
      # Multiplicamos el 8º carácter por su posición (8)
      total = suma_parcial + (ascii_val * 8)

      # Verificamos si cumple la condición del módulo 256 == 42
      if total % 256 == 42:
        password = "".join(chars) + chr(ascii_val)
        print(f"\n[+] ¡Contraseña válida encontrada: {password}!")
        print(f"    - Suma ponderada total: {total}")
        print(f"    - Residuo (total % 256): {total % 256}")
        return password


# Ejecutar la función
encontrar_contrasena()
```

```
[*] Buscando una contraseña válida de 8 caracteres...

[+] ¡Contraseña válida encontrada: JSSSZGO,!
    - Suma ponderada total: 2602
    - Residuo (total % 256): 42
'JSSSZGO,'
>>>
```

Vale la pena verificar el resultado a mano, porque es una buena forma de confirmar que entendí bien la lógica del binario y no solo confié en la salida del script. Con `J=74, S=83, S=83, S=83, Z=90, G=71, O=79, ,=44`:

```
74×1 + 83×2 + 83×3 + 83×4 + 90×5 + 71×6 + 79×7 + 44×8
= 74 + 166 + 249 + 332 + 450 + 426 + 553 + 352
= 2602
```

`2602 mod 256 = 42`, que es exactamente `'*'`. La cuenta cuadra.

## Verificación

Como esta contraseña no viene de un string cifrado dentro del binario sino de resolver una ecuación, la única forma de confirmar que el razonamiento sobre la lógica de validación era correcto es probarla contra el binario real. Por eso instalé Wine en esta ocasión — quería confirmar en un entorno donde el PE se ejecuta de verdad, no solo en el papel:

```
[house@archlinux nivel2_ctrlflow]$ wine crackme.exe
Password: JSSSZGO,
[+] Correcto!
```

Confirmado.

## Resumen del análisis

Este nivel introduce ideas que no aparecían en el nivel 1:

- **Predicado opaco reutilizado como guardia, no como adorno.** La misma condición pitagórica —constante, siempre verdadera, sin dependencia de la entrada— aparece evaluada tres veces en la función, y cada vez que aparece protege un par de ramas: una viva con la lógica correcta, y una muerta con la lógica invertida. No es una condición decorativa aislada; es el mecanismo estructural que sostiene toda la ofuscación de la función.
- **Ramas muertas con lógica invertida, no solo código basura.** Las tres ramas inalcanzables de esta función no son ruido aleatorio — reproducen la lógica real con el resultado exactamente al revés. Eso las convierte en trampas activas para cualquiera que intente parchear el binario o razonar sobre el control de flujo sin antes demostrar que el predicado es constante.
- **Discrepancia entre el conteo de referencias y el código fuente reconstruido.** Cuatro apariciones del string de éxito en el pseudocódigo, cinco referencias cruzadas en Ghidra. Documentar esa diferencia sin forzarla a cuadrar es parte honesta del análisis — es evidencia adicional de que el flujo de control fue manipulado, aunque no reconstruí el ensamblador para explicar la referencia exacta que falta.
- **Validación sin solución única.** A diferencia de una comparación contra una contraseña fija, la condición de éxito es una ecuación modular con múltiples soluciones válidas. Resolver el crackme no es extraer un string — es entender la ecuación, generar cualquier entrada que la satisfaga, y verificarla ejecutando el binario real, porque no hay una única respuesta "correcta" que uno pueda simplemente leer del binario.

Y una lección que ya había asomado en el nivel 1 y aquí se confirma con más fuerza: seguir una API conocida (`strncmp`) hasta su primer llamador no garantiza llegar a la lógica del crackme. Hay que leer lo que hace esa función antes de darla por buena, y si no encaja, seguir buscando por otra vía — en este caso, por las strings de resultado.

---

© 2026 Gino Aldair Maihuiri Romero
