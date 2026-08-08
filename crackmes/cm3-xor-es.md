---
title: "Crackme 03 — XOR Stack Strings: Texto cifrado embebido en el flujo de instrucciones"
description: "Resolución de cm3_xor: análisis estático con strings, resolución con breakpoint en strcmp, desensamblado completo del loop XOR, descifrado manual sin ejecutar y conexión con ofuscación en malware real."
author: Aldair Maihuiri
date: 2026-08-07
---

🇬🇧 [Read in English](https://ginomaihuiri.github.io/crackmes/cm3-xor)

# Crackme 03 — XOR Stack Strings: Texto cifrado embebido en el flujo de instrucciones

**Autor:** Aldair Maihuiri
**Fecha:** 7 de agosto de 2026
**Binario:** cm3_xor (ELF 64-bit, PIE, sin strippear)
**Herramientas:** GDB, objdump, strings, Python 3
**Tags:** `crackme` `reverse-engineering` `gdb` `x86_64` `xor` `ofuscacion` `stack-strings`

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
BuildID[sha1]=4f6bf934d0834c622552d31faa6a140065a6dabc,
for GNU/Linux 4.4.0, with debug_info, not stripped
```

ELF 64-bit, PIE, sin strippear. El propio crackme anuncia el desafío:

```
╔══════════════════════════════════════════════
║ Nivel 1 · CM03  [*       ]
║ XOR decode
╠══════════════════════════════════════════════
║ La clave esta cifrada. Aplica XOR para revelarla.
╚══════════════════════════════════════════════

Contrasena : AAAABBBCCCDDD
[-] Password incorrecto.
```

"La clave está cifrada. Aplica XOR para revelarla." El crackme nos dice exactamente
qué buscar — una rutina de descifrado XOR en algún punto antes de la comparación.

---

## Análisis estático: qué revela strings y qué oculta

```
$ strings ./crackme
```

Salida relevante seleccionada:

```
strcmp
fgets
strlen
getenv
decoded
cd}v
La clave esta cifrada. Aplica XOR para revelarla.
XOR decode
Contrasena :
Password correcto!
Password incorrecto.
```

Tres observaciones que definen la estrategia de análisis antes de abrir GDB:

**`strcmp` está presente** — el binario compara cadenas. Misma familia que el cm1. El enfoque `break strcmp` funcionará.

**`decoded` aparece como símbolo** — es el nombre de una variable o buffer en el código fuente. Al no estar strippado, los símbolos de depuración confirman que existe un paso de decodificación: la contraseña está almacenada cifrada y se descifra en runtime antes de la comparación. `strings` no puede mostrarnos la contraseña real — estará en el stack, construida en tiempo de ejecución.

**`cd}v` aparece** — parece basura aleatoria, pero no lo es. En ASCII: `'c'=0x63`, `'d'=0x64`, `'}'=0x7d`, `'v'=0x76`. Son los primeros cuatro bytes cifrados de la contraseña, visibles porque resultan ser caracteres ASCII imprimibles embebidos dentro de una instrucción `movl` en la sección `.text`. El quinto byte (`0x77`) vive en una instrucción `movb` separada, así que `strings` no los ve como secuencia contigua.

La contraseña no está en `.rodata` — está hardcodeada como valores inmediatos en el flujo de instrucciones y se descifra al stack en runtime. `strings` casi la revela, pero no del todo.

---

## Identificación de funciones importadas

```
$ objdump -T ./crackme | grep -i "strcmp\|atoi\|strtol\|scanf\|strtoul"

0000000000000000  DF *UND*  0000000000000000 (GLIBC_2.2.5) strcmp
```

`strcmp` confirmado. Mismo enfoque que el cm1: el descifrado ocurre antes de llamar a `strcmp`. Cuando los strings llegan a la comparación, el XOR ya corrió y el texto plano está en el stack.

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
║ Nivel 1 · CM03  [*       ]
║ XOR decode
╠══════════════════════════════════════════════
║ La clave esta cifrada. Aplica XOR para revelarla.
╚══════════════════════════════════════════════

Contrasena : crackme3

Breakpoint 1, 0x00007ffff7d73210 in ?? () from /usr/lib/libc.so.6
```

El descifrado XOR ya se ejecutó. Ambos strings están en memoria, en texto plano:

```
(gdb) x/s $rdi
0x7fffffffe4c0: "crackme3"

(gdb) x/s $rsi
0x7fffffffe4ba: "pwned"
```

`$rdi` contiene el input del usuario. `$rsi` contiene la contraseña descifrada: **`pwned`**.

### Verificación

```
(gdb) run
Contrasena: pwned

Breakpoint 1, 0x00007ffff7d73210 in ?? () from /usr/lib/libc.so.6

(gdb) continue

  [+] Password correcto!
```

---

## Análisis profundo — el loop XOR en ensamblador

La resolución rápida encontró la contraseña. La pregunta más profunda es: ¿cómo la descifra el binario? El desensamblado de `main` revela el mecanismo completo.

```
$ gdb ./crackme

(gdb) break main
(gdb) run
(gdb) disassemble main
```

La sección relevante:

```asm
; --- Bytes cifrados cargados como valores inmediatos al stack ---
main+91:  movl  $0x767d6463, -0x11b(%rbp)   ; 4 bytes: 63 64 7d 76 (little-endian)
main+101: movb  $0x77, -0x117(%rbp)          ; 1 byte:  77

; --- Inicialización del contador ---
main+108: movl  $0x0, -0x120(%rbp)           ; i = 0
main+118: jmp   main+163                     ; salta al final (condición al final)

; --- Cuerpo del loop ---
main+120: mov   -0x120(%rbp), %eax           ; eax = i
main+126: cltq                               ; extiende eax a rax (para indexar memoria)
main+128: movzbl -0x11b(%rbp,%rax,1), %eax  ; eax = cifrado[i] (byte extendido con ceros)
main+136: xor   $0x13, %eax                 ; eax = cifrado[i] XOR 0x13
main+139: mov   %eax, %edx                  ; edx = byte descifrado
main+141: mov   -0x120(%rbp), %eax           ; eax = i
main+147: cltq                               ; extiende a rax
main+149: mov   %dl, -0x116(%rbp,%rax,1)    ; descifrado[i] = byte descifrado

main+156: addl  $0x1, -0x120(%rbp)          ; i++

; --- Condición del loop ---
main+163: cmpl  $0x4, -0x120(%rbp)          ; i <= 4 ?
main+170: jle   main+120                    ; si sí, repite
```

### Desglose instrucción por instrucción

**`main+91 — movl $0x767d6463, -0x11b(%rbp)`**

Almacena 4 bytes como un inmediato de 32 bits en el stack. Little-endian significa que el byte menos significativo se guarda en la dirección más baja:

```
Dirección   Valor
-0x11b      0x63    ← byte menos significativo
-0x11a      0x64
-0x119      0x7d
-0x118      0x76    ← byte más significativo
```

**`main+101 — movb $0x77, -0x117(%rbp)`**

Almacena el quinto byte justo a continuación. El buffer cifrado completo queda en el stack:

```
-0x11b: 0x63
-0x11a: 0x64
-0x119: 0x7d
-0x118: 0x76
-0x117: 0x77
```

Estos son exactamente los bytes que `strings` detectó parcialmente como `cd}v`. El quinto (`0x77='w'`) estaba en una instrucción separada, rompiendo la secuencia imprimible.

**`main+108 — movl $0x0, -0x120(%rbp)`**

Inicializa el contador `i` a 0. El contador vive en una posición separada del stack, 8 bytes por debajo del buffer cifrado.

**`main+118 — jmp main+163`**

Salta directamente a la condición del loop. Este es un **loop con condición al final** — equivalente en C a `for (i=0; i<=4; i++)` donde la condición se evalúa al terminar cada iteración, no al inicio.

**`main+126 — cltq`**

Convierte `%eax` (32 bits) a `%rax` (64 bits) mediante extensión de signo. El direccionamiento de memoria en x86-64 requiere registros de 64 bits para el índice. Sin esto, los 32 bits superiores de `%rax` podrían contener basura de una operación anterior, causando que el índice apunte a la dirección incorrecta.

**`main+128 — movzbl -0x11b(%rbp,%rax,1), %eax`**

Carga un byte de `cifrado[i]` y lo extiende con ceros a 32 bits.

El cálculo de la dirección: `-0x11b + %rbp + %rax * 1`. Cuando `i=0`, apunta exactamente a `-0x11b(%rbp)` — el inicio del buffer cifrado. Conforme `i` crece, recorre cada byte.

`movzbl` (move zero-byte-long) es importante: carga un solo byte y rellena los bits superiores de `%eax` con ceros. Esto garantiza que el XOR opere solo sobre el byte cargado, sin interferencia de bits residuales.

**`main+136 — xor $0x13, %eax`**

La instrucción XOR. `0x13` es la clave — un solo byte aplicado a todos los caracteres. XOR tiene una propiedad fundamental que lo hace útil para ofuscación simple:

```
cifrar:    texto_plano XOR clave = texto_cifrado
descifrar: texto_cifrado XOR clave = texto_plano
```

La misma operación cifra y descifra. Aplicar XOR dos veces con la misma clave devuelve el valor original. No se necesitan funciones separadas de cifrado y descifrado.

**`main+149 — mov %dl, -0x116(%rbp,%rax,1)`**

Almacena el byte descifrado en un buffer separado (`decoded`), 5 bytes por encima del cifrado en el frame del stack. `%dl` es el byte bajo de `%edx`, que contiene el valor descifrado.

**`main+163 — cmpl $0x4, -0x120(%rbp)` / `main+170 — jle main+120`**

Condición del loop: continúa mientras `i <= 4`. Cinco iteraciones en total (0, 1, 2, 3, 4) — exactamente la longitud de `pwned`.

Al terminar el loop, `main+172` escribe el terminador nulo, completando el string descifrado. Luego el puntero al buffer descifrado va a `%rsi`, el input del usuario a `%rdi`, y se llama a `strcmp`.

---

## Descifrado manual — sin ejecutar el binario

Con la clave (`0x13`) y los bytes cifrados extraídos estáticamente del desensamblado, se puede recuperar la contraseña sin correr el binario.

**Bytes cifrados en orden de memoria:**

| Índice | Dirección | Byte cifrado | Clave XOR | Resultado (dec) | Resultado (ASCII) |
|---|---|---|---|---|---|
| 0 | `-0x11b` | `0x63` | `0x13` | 112 | `p` |
| 1 | `-0x11a` | `0x64` | `0x13` | 119 | `w` |
| 2 | `-0x119` | `0x7d` | `0x13` | 110 | `n` |
| 3 | `-0x118` | `0x76` | `0x13` | 101 | `e` |
| 4 | `-0x117` | `0x77` | `0x13` | 100 | `d` |

**Verificación en Python:**

```python
cifrado = [0x63, 0x64, 0x7d, 0x76, 0x77]
clave = 0x13

descifrado = [chr(b ^ clave) for b in cifrado]
print(''.join(descifrado))
# Salida: pwned
```

La contraseña recuperada puramente por análisis estático, sin ejecutar el binario.

---

## Conexión con malware real

Esta técnica no es académica. Durante mi análisis de una muestra de LockBit, encontré
exactamente el mismo primitivo: nombres de DLLs cifrados con un cifrado afín por string,
almacenados como valores inmediatos en instrucciones `MOV BYTE PTR` sobre el stack,
descifrados en runtime antes de pasárselos al resolutor dinámico de APIs.

El patrón estructural es idéntico a lo que demuestra este crackme:

| Paso | cm3_xor | LockBit |
|---|---|---|
| Almacenamiento | Valores inmediatos en `movl`/`movb` | Valores inmediatos en `mov byte ptr` |
| Ubicación | Stack (variable local) | Stack (variable local) |
| Clave | Un solo byte `0x13` | Cifrado afín por string (clave + multiplicador) |
| Descifrado | Runtime, antes de `strcmp` | Runtime, antes de resolución de API |
| ¿Visible con `strings`? | Parcialmente (como basura) | No |
| IAT / imports | `strcmp` visible | No hay imports visibles |

LockBit va más lejos — cada string usa su propia clave y multiplicador, y la API se
resuelve dinámicamente para mantenerla fuera de la IAT por completo. Pero la idea
fundamental es la misma: **inmediatos cifrados en el stack, descifrados justo antes de usarlos**.

Entender este patrón en un entorno controlado como este crackme construye la intuición
necesaria para reconocerlo y revertirlo cuando aparece en malware real.

---

## Progresión cm1 / cm2 / cm3

| Aspecto | CM1 (strcmp) | CM2 (numeric) | CM3 (xor) |
|---|---|---|---|
| Función clave | `strcmp` | `atoi` | `strcmp` |
| Tipo de secreto | Texto plano en `.rodata` | Inmediato en opcode de `cmpl` | Inmediatos cifrados en `movl`/`movb` |
| ¿Visible con `strings`? | Sí — completo | No | Parcialmente — como texto cifrado |
| Estrategia de breakpoint | `break strcmp` → `x/s $rsi` | `break atoi` → `x/10i $rip` | `break strcmp` → `x/s $rsi` |
| Recuperación estática | Trivial | Leer el inmediato del `cmpl` | Extraer bytes + clave → XOR |
| Concepto nuevo | Convención de llamadas | Comparación de enteros, atoi | Ofuscación XOR, inmediatos en el flujo de código |

---

*Parte de una serie de writeups de crackmes cubriendo binarios progresivamente más difíciles — desde comparaciones hardcodeadas hasta chequeos ofuscados, funciones hash propias y técnicas anti-debug.*

*Los binarios están disponibles en [github.com/GinoMaihuiri/Crackmes](https://github.com/GinoMaihuiri/Crackmes)*

*Todos los writeups: [ginomaihuiri.github.io](https://ginomaihuiri.github.io)*

---

© 2026 Aldair Maihuiri. Todos los derechos reservados.
Compartir con atribución es bienvenido. Prohibida la reproducción no autorizada.
