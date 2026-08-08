---
title: "Crackme 04 — Stack Strings Puras: Diez instrucciones movb que strings no puede ver"
description: "Resolución de cm4_stackstring: fallo total del análisis estático con strings, resolución con GDB, secuencia completa de movb en el desensamblado, recuperación estática de bytes, y el comportamiento del compilador que hace funcionar esta técnica — el mismo primitivo que usa LockBit."
author: Aldair Maihuiri
date: 2026-08-07
---

🇬🇧 [Read in English](https://ginomaihuiri.github.io/crackmes/cm4-stackstring)

# Crackme 04 — Stack Strings Puras: Diez instrucciones movb que strings no puede ver

**Autor:** Aldair Maihuiri
**Fecha:** 7 de agosto de 2026
**Binario:** cm4_stackstring (ELF 64-bit, PIE, sin strippear)
**Herramientas:** GDB, objdump, strings
**Tags:** `crackme` `reverse-engineering` `gdb` `x86_64` `stack-strings` `ofuscacion`

---

© 2026 Aldair Maihuiri. Todos los derechos reservados.
Puedes compartir este writeup con atribución. Prohibida la reproducción sin permiso.

---

## Reconocimiento inicial

```
$ chmod +x ./crackme
$ file ./crackme

./crackme: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV),
dynamically linked,
interpreter /lib64/ld-linux-x86-64.so.2,
BuildID[sha1]=6b8b7a7d8e684085ef2e94674ed5aef131a39d46,
for GNU/Linux 4.4.0, with debug_info, not stripped
```

ELF 64-bit, PIE, sin strippear. El crackme anuncia su técnica de inmediato:

```
╔══════════════════════════════════════════════
║ Nivel 1 · CM04  [*       ]
║ Stack string
╠══════════════════════════════════════════════
║ La clave se construye caracter a caracter en la pila.
╚══════════════════════════════════════════════

Contrasena : hackme
[-] Nope.
```

"La clave se construye carácter a carácter en la pila." El nombre y el enunciado juntos
describen exactamente lo que veremos en el desensamblado.

---

## Análisis estático: donde strings falla completamente

```
$ strings ./crackme | head -50
```

Salida relevante:

```
strcmp
fgets
strlen
getenv
NO_COLOR
La clave se construye caracter a caracter en la pila.
Stack string
Contrasena :
Excelente! Flag encontrado.
```

La contraseña está completamente ausente de la salida de `strings`. No parcialmente
visible como el `cd}v` del cm3 — invisible por completo.

En el cm3, los bytes cifrados XOR se almacenaban como un inmediato de 32 bits en una
sola instrucción `movl`, lo que hacía que cuatro bytes imprimibles consecutivos
aparecieran en el binario. Aquí, cada carácter se almacena mediante una instrucción
`movb` separada. Entre cada `movb` y el siguiente hay bytes de codificación de
instrucción — opcode, ModR/M, desplazamiento — que rompen cualquier secuencia
imprimible contigua. `strings` no tiene nada que encontrar.

Esta es la **construcción pura de stack strings**: la contraseña se ensambla en el
frame del stack un byte a la vez, sin representación contigua en ninguna parte del
binario.

---

## Identificación de funciones importadas

```
$ objdump -T ./crackme | grep -i "strcmp\|atoi\|strtol\|scanf\|strtoul\|memcmp"

0000000000000000  DF *UND*  0000000000000000 (GLIBC_2.2.5) strcmp
```

`strcmp` confirmado. Misma estrategia de resolución que el cm1 y el cm3: la contraseña
está completamente ensamblada en el stack antes de llamar a `strcmp`. Cuando llegamos
a la comparación, todos los caracteres ya están en su lugar.

---

## GDB — resolución rápida

```
$ gdb ./crackme

(gdb) break strcmp
Breakpoint 1 at 0x1090

(gdb) run
```

```
╔══════════════════════════════════════════════
║ Nivel 1 · CM04  [*       ]
║ Stack string
╠══════════════════════════════════════════════
║ La clave se construye caracter a caracter en la pila.
╚══════════════════════════════════════════════

Contrasena : hackme

Breakpoint 1, 0x00007ffff7d73210 in ?? () from /usr/lib/libc.so.6
```

Los diez caracteres ya están ensamblados en el stack:

```
(gdb) x/s $rdi
0x7fffffffe4b0: "hackme"

(gdb) x/s $rsi
0x7fffffffe4a6: "flag_2024"
```

`$rdi` contiene el input del usuario. `$rsi` contiene la contraseña ensamblada: **`flag_2024`**.

### Verificación

```
(gdb) run
Contrasena: flag_2024

Breakpoint 1, 0x00007ffff7d73210 in ?? () from /usr/lib/libc.so.6

(gdb) continue

  [+] Excelente! Flag encontrado.
```

---

## Análisis profundo — la secuencia de movb

La resolución rápida encontró la contraseña. La pregunta más profunda es: ¿cómo la
construye exactamente el binario? `disassemble main` revela la secuencia completa.

```
(gdb) break main
(gdb) run
(gdb) disassemble main
```

Después de `read_input`, la construcción de la contraseña comienza inmediatamente:

```asm
main+86:  call  read_input

; --- Construcción del stack string: un movb por carácter ---
main+91:  movb  $0x66, -0x11a(%rbp)   ; pw[0] = 0x66
main+98:  movb  $0x6c, -0x119(%rbp)   ; pw[1] = 0x6c
main+105: movb  $0x61, -0x118(%rbp)   ; pw[2] = 0x61
main+112: movb  $0x67, -0x117(%rbp)   ; pw[3] = 0x67
main+119: movb  $0x5f, -0x116(%rbp)   ; pw[4] = 0x5f
main+126: movb  $0x32, -0x115(%rbp)   ; pw[5] = 0x32
main+133: movb  $0x30, -0x114(%rbp)   ; pw[6] = 0x30
main+140: movb  $0x32, -0x113(%rbp)   ; pw[7] = 0x32
main+147: movb  $0x34, -0x112(%rbp)   ; pw[8] = 0x34
main+154: movb  $0x00, -0x111(%rbp)   ; pw[9] = terminador nulo

; --- Carga de punteros y llamada a strcmp ---
main+161: lea   -0x11a(%rbp), %rdx    ; rdx → pw (contraseña ensamblada)
main+168: lea   -0x110(%rbp), %rax    ; rax → input (input del usuario)
main+175: mov   %rdx, %rsi            ; 2do argumento: pw
main+178: mov   %rax, %rdi            ; 1er argumento: input
main+181: call  strcmp@plt

; --- Decisión ---
main+186: test  %eax, %eax
main+188: jne   main+212              ; si no son iguales → print_err
main+190: lea   ...                   ; → print_ok
```

### Por qué no hay loop

Compara con el cm3: allí el descifrado XOR requería iterar sobre los bytes cifrados —
de ahí el loop `do/while` con un contador en `-0x120(%rbp)`. Aquí no hay cifrado ni
descifrado. Cada carácter se escribe directamente en su posición final. No se necesita
iteración — el compilador genera una instrucción por carácter.

Esta es la distinción estructural entre las dos técnicas:

| | cm3_xor | cm4_stackstring |
|---|---|---|
| Almacenamiento en binario | Inmediatos cifrados | Inmediatos en texto plano |
| ¿Loop? | Sí — loop de descifrado XOR | No — escrituras directas |
| Instrucciones por carácter | 1 iteración XOR | 1 `movb` |
| Clave | `0x13` | Ninguna |

### Disposición en el stack tras la construcción

Los nueve caracteres más el terminador nulo ocupan diez bytes consecutivos:

```
Dirección          Byte   ASCII
-0x11a(%rbp)   0x66   'f'   ← pw[0]  inicio de la contraseña
-0x119(%rbp)   0x6c   'l'   ← pw[1]
-0x118(%rbp)   0x61   'a'   ← pw[2]
-0x117(%rbp)   0x67   'g'   ← pw[3]
-0x116(%rbp)   0x5f   '_'   ← pw[4]
-0x115(%rbp)   0x32   '2'   ← pw[5]
-0x114(%rbp)   0x30   '0'   ← pw[6]
-0x113(%rbp)   0x32   '2'   ← pw[7]
-0x112(%rbp)   0x34   '4'   ← pw[8]
-0x111(%rbp)   0x00   '\0'  ← pw[9]  terminador nulo explícito
```

El terminador en `main+154` se escribe explícitamente con su propio `movb` — no hay
ninguna condición de loop que lo coloque automáticamente.

---

## Recuperación estática — sin ejecutar el binario

Con los bytes extraídos directamente del desensamblado:

| Offset | Dirección | Byte | ASCII |
|---|---|---|---|
| `main+91` | `-0x11a` | `0x66` | `f` |
| `main+98` | `-0x119` | `0x6c` | `l` |
| `main+105` | `-0x118` | `0x61` | `a` |
| `main+112` | `-0x117` | `0x67` | `g` |
| `main+119` | `-0x116` | `0x5f` | `_` |
| `main+126` | `-0x115` | `0x32` | `2` |
| `main+133` | `-0x114` | `0x30` | `0` |
| `main+140` | `-0x113` | `0x32` | `2` |
| `main+147` | `-0x112` | `0x34` | `4` |
| `main+154` | `-0x111` | `0x00` | `\0` |

Contraseña recuperada estáticamente: **`flag_2024`**.

---

## Por qué el compilador genera instrucciones movb individuales

Para entender esto hay que saber cómo los compiladores de C manejan los arrays locales.

Cuando un string se define como **literal de cadena** en C — `"flag_2024"` — el
compilador lo ubica en la sección `.rodata` como una secuencia contigua de bytes.
`strings` lo encuentra de inmediato.

Cuando los mismos caracteres se asignan **individualmente a un array local**, el
compilador traduce cada asignación a una escritura separada en el stack. No hay
ningún literal de cadena en ninguna parte — solo valores inmediatos de un byte
incrustados dentro de instrucciones de máquina separadas. Entre cada
`movb $0x66, dirección` y el siguiente hay bytes de codificación que rompen cualquier
secuencia imprimible contigua.

La CPU ensambla el string completo en memoria en tiempo de ejecución, un byte a la vez.
`strings` nunca lo ve porque solo lee el contenido estático del archivo — no lo que
se construye en memoria durante la ejecución.

Esta es una decisión a nivel de código fuente que tiene un efecto directo y profundo
sobre el análisis estático. El comportamiento en runtime es idéntico. La visibilidad
estática es completamente diferente.

---

## Conexión con malware real

Esta técnica no es teórica. Durante mi análisis de una muestra de LockBit, documenté
exactamente el mismo patrón: nombres de DLLs construidos byte a byte en el stack
mediante instrucciones `MOV BYTE PTR` individuales, sin existir nunca como strings
contiguos en el binario.

La comparación entre este crackme y LockBit:

| | cm4_stackstring | LockBit |
|---|---|---|
| Instrucciones | `movb` por carácter | `mov byte ptr` por carácter |
| ¿Caracteres en texto plano? | Sí | No — cifrados antes de almacenar |
| ¿Loop? | No | No |
| Terminador nulo | `movb $0x0` explícito | Producido por el diseño del cifrado |
| ¿Visible con `strings`? | No | No |
| IAT | `strcmp` visible | Sin imports visibles |

El cm4 es el **patrón base** — bytes en claro, sin cifrado. LockBit toma el mismo
enfoque estructural pero agrega un cifrado afín por string encima: los bytes que
almacenan las instrucciones `mov byte ptr` son texto cifrado, no texto plano. El loop
de descifrado corre inmediatamente después de la construcción, antes de usar el string.

Entender el cm4 hace más fácil razonar el análisis de LockBit: separa el patrón de
construcción en el stack de la capa de cifrado, mostrando que son dos técnicas
independientes que se combinan.

---

## Progresión cm1 / cm2 / cm3 / cm4

| Aspecto | CM1 | CM2 | CM3 | CM4 |
|---|---|---|---|---|
| Función clave | `strcmp` | `atoi` | `strcmp` | `strcmp` |
| Ubicación del secreto | `.rodata` | Opcode de `cmpl` | `movl`/`movb` (cifrado) | `movb` (texto plano) |
| ¿Visible con `strings`? | Sí | No | Parcialmente | No |
| ¿Loop? | — | — | Sí (XOR) | No |
| Recuperación estática | Trivial | Leer inmediato | Extraer + XOR | Leer valores `movb` |
| Concepto nuevo | Convención de llamadas | Comparación de enteros | Ofuscación XOR | Construcción de stack strings |

---

*Parte de una serie de writeups de crackmes cubriendo binarios progresivamente más difíciles — desde comparaciones hardcodeadas hasta chequeos ofuscados, funciones hash propias y técnicas anti-debug.*

*Los binarios están disponibles en [github.com/GinoMaihuiri/Crackmes](https://github.com/GinoMaihuiri/Crackmes)*

*Todos los writeups: [ginomaihuiri.github.io](https://ginomaihuiri.github.io)*

---

© 2026 Aldair Maihuiri. Todos los derechos reservados.
Compartir con atribución es bienvenido. Prohibida la reproducción no autorizada.
