---
title: "Crackme 01 — strcmp hardcodeado: encontrando la contraseña con GDB"
description: "Writeup paso a paso de cm1_strcmp: reconocimiento inicial, breakpoints en GDB, convención de llamadas x86_64, internals de strcmp con AVX2 y análisis completo del flujo en ensamblador."
author: Aldair Maihuiri
date: 2026-08-02
---

[Read in English](https://ginomaihuiri.github.io/crackmes/cm1-strcmp)

# Crackme 01 — strcmp hardcodeado: encontrando la contraseña con GDB

**Autor:** Aldair Maihuiri
**Fecha:** 2 de agosto de 2026
**Binario:** cm1_strcmp (ELF 64-bit, sin strippear)
**Herramientas:** GDB, file, chmod
**Tags:** `crackme` `reverse-engineering` `gdb` `x86_64` `strcmp` `elf`

---

© 2026 Aldair Maihuiri. Todos los derechos reservados.
Puedes compartir este writeup con atribución. Prohibida la reproducción sin permiso.

---

## Reconocimiento inicial

Lo primero que hago antes de abrir un binario en el debugger es correr `file` sobre él.
Sirve para saber con qué tipo de ejecutable estoy tratando: arquitectura, si está
strippado o no, si es dinámico o estático.

```
$ file ./crackme

./crackme: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV),
dynamically linked,
interpreter /lib64/ld-linux-x86-64.so.2,
BuildID[sha1]=b4784a7ce15cbbec0e4411e0179fb8eb4959548c,
for GNU/Linux 4.4.0, with debug_info, not stripped
```

ELF 64-bit, enlazado dinámicamente y **sin strippear**. Que no esté strippado es
conveniente porque significa que los símbolos de depuración están presentes, así que
los nombres de funciones como `main` o `strcmp` van a aparecer en el debugger
directamente.

En los siguientes crackmes quizá sea necesario verificar si están strippados o no,
pero en este primer ejercicio no hace falta. De todas formas queda en el lector ir
investigando ese tema para que cuando llegue el momento no le tome por sorpresa.

---

## Abriendo en GDB — error de permisos

```
$ gdb ./crackme
(gdb) break main
Breakpoint 1 at 0x1721: file crackme.c, line 5.
(gdb) run
```

Y me dio un error bastante común cuando se trabaja con binarios descargados o clonados:

```
/bin/bash: line 1:
/home/house/Cracmes-main/nivel1/cm1_strcmp/crackme: Permission denied
❌ During startup program exited with code 126.
```

El archivo no tenía permisos de ejecución. La solución:

```
$ chmod +x ./crackme
```

Algo que hay que tener en mente cada vez que se clona un repositorio con binarios.

---

## Primera ejecución

Con los permisos corregidos:

```
$ gdb ./crackme
(gdb) run
```

```
╔══════════════════════════════════════════════
║ Nivel 1 · CM01 [* ]
║ strcmp hardcodeado
╠══════════════════════════════════════════════
║ Un guardian compara tu clave directamente con strcmp.
╚══════════════════════════════════════════════

Contrasena : asdasd
```

El propio enunciado del crackme nos da la pista: **strcmp hardcodeado**. Eso ya nos
dice exactamente por dónde hay que ir.

---

## ¿Qué es strcmp?

`strcmp` significa **STRing CoMPare**, o sea, comparar cadenas de texto. Es una
función estándar de C que compara dos cadenas y devuelve un entero que indica la
diferencia:

```c
int strcmp(const char *cadena1, const char *cadena2);
```

| Valor devuelto | Significado | En assembly (condicional) |
|---|---|---|
| 0 | ¡Son **IGUALES**! ✅ | `test eax, eax` → `je` (salta si cero) |
| < 0 (negativo) | cadena1 < cadena2 | `js`/`jl` — raro verlo en la práctica |
| > 0 (positivo) | cadena1 > cadena2 | `jg` — raro; los compiladores usan `je`/`jne` |

**Regla de oro: si strcmp devuelve 0, las cadenas son IDÉNTICAS.** Todo lo que
hagamos a continuación gira alrededor de ese cero.

### Implementación interna simplificada

```c
int strcmp(const char *s1, const char *s2) {
    while (*s1 && (*s1 == *s2)) {
        s1++;
        s2++;
    }
    return *(unsigned char *)s1 - *(unsigned char *)s2;
}
```

Esta es la lógica base. La implementación real de glibc está fuertemente optimizada —
la veremos en ensamblador más adelante.

---

## Poniendo el breakpoint en strcmp

Esta vez el breakpoint va directamente en `strcmp`, no en `main`. El crackme ya nos
dijo que usa strcmp, así que saltamos directo a la comparación en lugar de caminar
todo el programa desde el inicio:

| Breakpoint | Cuándo se dispara | Qué ves |
|---|---|---|
| `break main` | Al inicio del programa, antes de pedir la contraseña | El programa recién arranca |
| `break strcmp` | En el momento exacto de la comparación | Ambas cadenas (tu input y la correcta) |

¿Por qué no usar siempre `break strcmp` en todos los crackmes? Porque en los más
avanzados strcmp está ofuscado, se llama indirectamente, o simplemente no se usa. Ese
es el caso normal — exponer una comparación sensible a través de una llamada de
librería con nombre visible es un punto débil obvio.

```
(gdb) break strcmp
(gdb) run
```

Metemos `Hola` como contraseña para avanzar la ejecución hasta el punto de comparación:

```
╔══════════════════════════════════════════════
║ Nivel 1 · CM01 [* ]
║ strcmp hardcodeado
╠══════════════════════════════════════════════
║ Un guardian compara tu clave directamente con strcmp.
╚══════════════════════════════════════════════

Contrasena : Hola

Breakpoint 1, 0x00007ffff7d73210 in ?? () from /usr/lib/libc.so.6
```

El debugger se detuvo justo cuando strcmp estaba a punto de ejecutarse.

---

## Los argumentos en x86_64

En arquitectura de 64 bits, los argumentos de una función se pasan en registros en
lugar de en la pila. Esta es una decisión de rendimiento tomada cuando los
procesadores pasaron de 32 a 64 bits:

| Sistema | 1er argumento | 2do argumento | Comando en GDB |
|---|---|---|---|
| 32 bits (x86) | `$esp+4` | `$esp+8` | `x/s $esp+4` |
| 64 bits (x86_64) | `rdi` | `rsi` | `x/s $rsi` |

### ¿Por qué RDI y RSI?

`RDI` (Destination Index) y `RSI` (Source Index) fueron diseñados originalmente para
las instrucciones de manipulación de cadenas del 8086 (1978): `movsb`, `stosb`,
`lodsb`, `rep movs`, `scasb`. En esas instrucciones RSI apunta al origen y RDI al
destino.

Su uso para pasar los dos primeros argumentos de función es una convención moderna
del **System V AMD64 ABI**, decidida cuando se diseñó el ISA de 64 bits (~2003). No
es universal: en Windows x64 la convención es distinta — se usan `RCX`/`RDX` para los
dos primeros argumentos. Linux eligió `RDI`/`RSI` precisamente porque las
instrucciones de cadena habían caído en desuso, dejando esos registros efectivamente
libres.

Para `strcmp`: **RDI contiene tu input, RSI contiene la contraseña correcta.**

Tabla completa de registros de argumentos en x86_64:

| Argumento | Registro | Uso típico |
|---|---|---|
| 1ro | rdi | Primer parámetro |
| 2do | rsi | Segundo parámetro |
| 3ro | rdx | Tercer parámetro |
| 4to | rcx | Cuarto parámetro |
| 5to | r8 | Quinto parámetro |
| 6to | r9 | Sexto parámetro |
| 7mo+ | Pila (`$rsp`) | Cuando hay más de 6 argumentos |

---

## Encontrando la contraseña

```
(gdb) x/s $rdi
0x7fffffffe490: "Hola"

(gdb) x/s $rsi
0x5555555562cf: "s3cr3t0"
```

**La contraseña es `s3cr3t0`.** La encontramos sin leer una sola línea de
ensamblador — deteniendo la ejecución en el momento exacto de la comparación y
leyendo los registros directamente.

---

## ¿Por qué la dirección no cambia entre ejecuciones?

Uno esperaría que ASLR aleatorice la dirección de strcmp en cada ejecución, y sin
embargo `0x7ffff7d73210` aparece idéntica entre corridas. La razón no es que ASLR
esté desactivado en el sistema — **GDB desactiva ASLR por defecto para el proceso que
está depurando.** Es una comodidad del debugger, no una propiedad del sistema
operativo.

La dirección `0x7ffff7...` es la firma clásica de libc cargada con ASLR desactivado
bajo GDB. Con ASLR activo verías una base completamente distinta en cada ejecución.

Dentro de una misma ejecución, todas las funciones de libc tienen offsets relativos
fijos respecto a esa base. Esta es la primitiva que hace posibles los **ataques
ret2libc**: si logras filtrar un solo puntero de libc, puedes calcular la dirección
de cualquier otra función restando su offset conocido.

---

## La implementación AVX2 de strcmp

```
(gdb) x/20i $rip

=> 0x7ffff7d73210:  endbr64
   0x7ffff7d73214:  vpxor   %xmm15,%xmm15,%xmm15
   0x7ffff7d73219:  mov     %edi,%eax
   0x7ffff7d7321b:  or      %esi,%eax
   0x7ffff7d7321d:  shl     $0x14,%eax
   0x7ffff7d73220:  cmp     $0xf8000000,%eax
   0x7ffff7d73225:  ja      0x7ffff7d73550
   0x7ffff7d7322b:  vmovdqu (%rdi),%ymm0
   0x7ffff7d7322f:  vpcmpeqb (%rsi),%ymm0,%ymm1
   0x7ffff7d73233:  vpcmpeqb %ymm0,%ymm15,%ymm2
   0x7ffff7d73237:  vpandn  %ymm1,%ymm2,%ymm1
   0x7ffff7d7323b:  vpmovmskb %ymm1,%ecx
   0x7ffff7d7323f:  inc     %ecx
   0x7ffff7d73241:  je      0x7ffff7d732a0
   0x7ffff7d73243:  tzcnt   %ecx,%ecx
   0x7ffff7d73247:  movzbl  (%rdi,%rcx,1),%eax
   0x7ffff7d7324b:  movzbl  (%rsi,%rcx,1),%ecx
   0x7ffff7d7324f:  sub     %ecx,%eax
   0x7ffff7d73251:  vzeroupper
   0x7ffff7d73254:  ret
```

Esto no es el loop byte a byte de la implementación simplificada. Esta es la
**implementación AVX2 de strcmp en glibc**, que compara 32 bytes a la vez usando
instrucciones SIMD:

| Dirección | Instrucción | Significado |
|---|---|---|
| `0x...3210` | `endbr64` | Seguridad CET — marca destino de salto válido |
| `0x...3214` | `vpxor %xmm15,%xmm15,%xmm15` | Pone ymm15 a cero (todos los bytes = 0) |
| `0x...3219` | `mov %edi,%eax` | Copia dirección de s1 a eax para chequeo de límite de página |
| `0x...321b` | `or %esi,%eax` | OR con dirección de s2 (combina bits altos de ambos punteros) |
| `0x...321d` | `shl $0x14,%eax` | Desplaza para aislar bits que indican cercanía al límite de página |
| `0x...3220` | `cmp $0xf8000000,%eax` | Comprueba si algún puntero está a menos de 32 bytes de un límite de página de 4KB |
| `0x...3225` | `ja 0x...3550` | Si hay riesgo de cruzar página, salta a la ruta segura |
| `0x...322b` | `vmovdqu (%rdi),%ymm0` | Carga 32 bytes de s1 en ymm0 |
| `0x...322f` | `vpcmpeqb (%rsi),%ymm0,%ymm1` | Compara 32 bytes de s2 contra s1, byte por byte |
| `0x...3233` | `vpcmpeqb %ymm0,%ymm15,%ymm2` | Busca bytes nulos en s1 |
| `0x...3237` | `vpandn %ymm1,%ymm2,%ymm1` | ymm1 = (NOT ymm2) AND ymm1 → marca bytes iguales no nulos |
| `0x...323b` | `vpmovmskb %ymm1,%ecx` | Extrae un bit por byte → máscara de 32 bits en ecx |
| `0x...323f` | `inc %ecx` | Si los 32 bytes coincidieron y no hay nulo, ecx era 0xFFFFFFFF → inc lo hace 0 |
| `0x...3241` | `je 0x...32a0` | ZF=1 → los 32 bytes iguales y sin nulo: salta a procesar el siguiente bloque |
| `0x...3243` | `tzcnt %ecx,%ecx` | Cuenta ceros al final → posición del primer byte que difiere |
| `0x...3247` | `movzbl (%rdi,%rcx,1),%eax` | Carga byte de s1 en la posición de divergencia |
| `0x...324b` | `movzbl (%rsi,%rcx,1),%ecx` | Carga byte de s2 en la posición de divergencia |
| `0x...324f` | `sub %ecx,%eax` | Resta → valor de retorno de strcmp |
| `0x...3251` | `vzeroupper` | Limpia registros YMM (evita penalización de transición) |
| `0x...3254` | `ret` | Retorna |

---

## Volviendo a main con `finish`

```
(gdb) finish

Run till exit from #0 0x00007ffff7d73210 in ?? () from /usr/lib/libc.so.6
0x000055555555578a in main () at crackme.c:12
12          if (strcmp(input, "s3cr3t0") == 0) {
```

Ya estamos en el punto exacto de la comparación en `main`. Diez instrucciones lo
deciden todo:

```
=> 0x55555555578a <main+116>: test   %eax,%eax
   0x55555555578c <main+118>: jne    0x5555555557a4 <main+142>
   0x55555555578e <main+120>: lea    0xb42(%rip),%rax    # "Acceso concedido"
   0x555555555795 <main+127>: mov    %rax,%rdi
   0x555555555798 <main+130>: call   0x55555555560c <print_ok>
   0x55555555579d <main+135>: mov    $0x0,%eax
   0x5555555557a2 <main+140>: jmp    0x5555555557b8 <main+162>
   0x5555555557a4 <main+142>: lea    0xb42(%rip),%rax    # "Acceso denegado"
   0x5555555557ab <main+149>: mov    %rax,%rdi
   0x5555555557ae <main+152>: call   0x555555555691 <print_err>
```

### Flujo de ejecución

```
1. test %eax, %eax  →  ¿eax == 0?
│
├── SÍ (eax == 0, las cadenas coinciden)
│   2. jne NO salta
│   3. lea "Acceso concedido" → rax
│   4. mov rax → rdi
│   5. call print_ok
│   6. mov $0x0, %eax      (return 0)
│   7. jmp al final
│
└── NO (eax != 0, las cadenas difieren)
    2. jne SALTA a 0x...57a4
    8. lea "Acceso denegado" → rax
    9. mov rax → rdi
   10. call print_err
```

### Desglose instrucción por instrucción

**1 — `test %eax, %eax`** (2 bytes: `85 c0`)
AND lógico de eax consigo mismo. El resultado se descarta, pero las flags se
actualizan. Si eax == 0 → ZF = 1. Equivale a `if (strcmp(...) == 0)` en C.

**2 — `jne 0x...57a4`** (2 bytes: `75 16`)
Jump if Not Equal — se dispara cuando ZF = 0 (las cadenas difieren). Cálculo del
salto: `0x...578c + 2 + 0x16 = 0x...57a4`. Confirmado.

**3 — `lea 0xb42(%rip), %rax`** (7 bytes: `48 8d 05 42 0b 00 00`)
Carga la dirección de la cadena "Acceso concedido". Direccionamiento relativo a RIP:
RIP apunta a la **siguiente** instrucción al momento del cálculo.
`0x...578e + 7 = 0x...5795`, luego `0x...5795 + 0xb42 = 0x...62d7`.

Verificación:
```
(gdb) x/s 0x5555555562d7
0x5555555562d7: "Acceso concedido"
```

**4 — `mov %rax, %rdi`** (3 bytes: `48 89 c7`)
Mueve la dirección del mensaje a rdi — registro del primer argumento para la llamada
que viene.

**5 — `call 0x...560c <print_ok>`** (5 bytes: `e8 6f fe ff ff`)
Llama a `print_ok`. Empuja la dirección de retorno (`0x...579d`) a la pila y salta.
Offset relativo: `0x...5798 + 5 + 0xfffffe6f = 0x...560c`. Confirmado.

**6 — `mov $0x0, %eax`** (5 bytes: `b8 00 00 00 00`)
Establece el valor de retorno de `main` en 0 (éxito).

**7 — `jmp 0x...57b8`** (5 bytes: `e9 11 00 00 00`)
Salto incondicional al final de `main`, saltándose la rama de error.
`0x...57a2 + 5 + 0x11 = 0x...57b8`. Confirmado.

**8 — `lea 0xb42(%rip), %rax`** (7 bytes: `48 8d 05 42 0b 00 00`) — rama de error
Mismo principio, destino distinto. `0x...57a4 + 7 = 0x...57ab`,
luego `0x...57ab + 0xb42 = 0x...62ed`.

Verificación:
```
(gdb) x/s 0x5555555562ed
0x5555555562ed: "Acceso denegado"
```

**9 — `mov %rax, %rdi`** (3 bytes: `48 89 c7`)
Mueve la dirección del mensaje de error a rdi para la llamada a `print_err`.

**10 — `call 0x...5691 <print_err>`** (5 bytes: `e8 de fe ff ff`)
Llama a `print_err`. `0x...57ae + 5 + 0xfffffede = 0x...5691`. Confirmado.

### Tabla resumen completa

| Dirección | Bytes (hex) | Instrucción | Registros | Tamaño | Qué hace |
|---|---|---|---|---|---|
| `0x...578a` | `85 c0` | `test %eax,%eax` | eax, flags | 2 | Comprueba eax == 0 |
| `0x...578c` | `75 16` | `jne 0x...57a4` | flags | 2 | Salta si eax != 0 |
| `0x...578e` | `48 8d 05 42 0b 00 00` | `lea 0xb42(%rip),%rax` | rip, rax | 7 | Dirección de "Acceso concedido" |
| `0x...5795` | `48 89 c7` | `mov %rax,%rdi` | rax, rdi | 3 | Prepara mensaje de éxito |
| `0x...5798` | `e8 6f fe ff ff` | `call print_ok` | rip, rsp | 5 | Llama función de éxito |
| `0x...579d` | `b8 00 00 00 00` | `mov $0x0,%eax` | rax | 5 | return 0 |
| `0x...57a2` | `e9 11 00 00 00` | `jmp 0x...57b8` | rip | 5 | Salta al final |
| `0x...57a4` | `48 8d 05 42 0b 00 00` | `lea 0xb42(%rip),%rax` | rip, rax | 7 | Dirección de "Acceso denegado" |
| `0x...57ab` | `48 89 c7` | `mov %rax,%rdi` | rax, rdi | 3 | Prepara mensaje de error |
| `0x...57ae` | `e8 de fe ff ff` | `call print_err` | rip, rsp | 5 | Llama función de error |

---

## Notas

**`test` vs `cmp`**
`test %eax, %eax` y `cmp $0, %eax` producen las mismas flags, pero:
`test` es un AND lógico — `cmp` es una resta. `test` es marginalmente más rápido y es
el idiom estándar para comprobar si un valor es cero.

**`lea` vs `mov`**
`lea` calcula una dirección y la guarda sin acceder a memoria — sin riesgo de page
fault. `mov` lee de o escribe en memoria. `lea` se usa frecuentemente para aritmética
de punteros que no requiere desreferenciar.

**`call` y la pila**
`call` empuja la dirección de retorno a la pila antes de saltar. El `ret`
correspondiente la saca y salta de vuelta.

---

## Verificación final

Matamos el proceso actual, ejecutamos de nuevo con la contraseña correcta, y
confirmamos que el `jne` no se dispara:

```
(gdb) kill
(gdb) run

Contrasena : s3cr3t0

Breakpoint 1, 0x00007ffff7d73210 in ?? () from /usr/lib/libc.so.6

(gdb) finish
0x000055555555578a in main () at crackme.c:12
12          if (strcmp(input, "s3cr3t0") == 0) {

(gdb) stepi
0x000055555555578c   12    if (strcmp(input, "s3cr3t0") == 0) {

(gdb) stepi
13      print_ok("Correcto! Bien hecho.");
```

`jne` no saltó. La ejecución fue directo a la línea 13 — `print_ok`.

**Crackme 1 resuelto.** La contraseña estaba hardcodeada en el binario, se pasaba
directamente como segundo argumento a `strcmp`, y era visible inspeccionando `$rsi`
en el momento exacto de la comparación.

---

*Nota sobre verificación: los bytes de las instrucciones `lea` de este writeup fueron
verificados directamente en GDB con `x/7xb`. La aritmética de todos los saltos y
llamadas fue confirmada de forma independiente.*

---

*Parte de una serie de writeups de crackmes cubriendo binarios progresivamente más
difíciles — desde comparaciones hardcodeadas hasta chequeos ofuscados, funciones hash
propias y técnicas anti-debug.*

*Los binarios de los crackmes están disponibles en
[github.com/GinoMaihuiri/Crackmes](https://github.com/GinoMaihuiri/Crackmes)*

*Todos los writeups: [ginomaihuiri.github.io](https://ginomaihuiri.github.io)*

---

© 2026 Aldair Maihuiri. Todos los derechos reservados.
Compartir con atribución es bienvenido. Prohibida la reproducción no autorizada.
