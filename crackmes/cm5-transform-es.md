---
title: "Crackme 05 — Transformar antes de comparar: El primer crackme sin strcmp"
description: "Resolución de cm5_transform: sin función de comparación en la IAT, filtro de longitud con strlen, loop de transformación con lea, análisis del overflow con unsigned char, verificación en GDB, corrupción del stack canary y bypass del SSP con Rust y ptrace."
author: Aldair Maihuiri
date: 2026-08-07
---

🇬🇧 [Read in English](https://ginomaihuiri.github.io/crackmes/cm5-transform)

# Crackme 05 — Transformar antes de comparar: El primer crackme sin strcmp

**Autor:** Aldair Maihuiri
**Fecha:** 7 de agosto de 2026
**Binario:** cm5_transform (ELF 64-bit, PIE, sin strippear)
**Herramientas:** GDB, objdump, strings, Rust (crate nix)
**Tags:** `crackme` `reverse-engineering` `gdb` `x86_64` `transformacion` `comparacion-manual` `stack-canary` `ptrace`

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
BuildID[sha1]=7ed4c1480c09bad96fd6e42d38a45689f95b6aca,
for GNU/Linux 4.4.0, with debug_info, not stripped
```

ELF 64-bit, PIE, sin strippear. El crackme anuncia su mecanismo:

```
╔══════════════════════════════════════════════
║ Nivel 1 · CM05  [*       ]
║ Transform
╠══════════════════════════════════════════════
║ Cada caracter es transformado antes de comparar.
╚══════════════════════════════════════════════
```

"Cada carácter es transformado antes de comparar." El programa no compara el input
directamente — primero aplica una transformación a cada carácter y luego compara el
resultado. Esto cambia completamente la estrategia de análisis.

---

## Análisis estático — strings revela parcialmente los valores transformados

```
$ strings ./crackme | head -50
```

Salida relevante:

```
hwfh
hprj
Cada caracter es transformado antes de comparar.
Transform
Contrasena :
```

Dos strings destacan: `hwfh` y `hprj`. No son la contraseña — son los **valores
esperados ya transformados**. Reconocer esta distinción desde el principio es lo que
separa una lectura superficial de un análisis productivo.

Juntos forman una secuencia de 8 bytes: `68 77 66 68 68 70 72 6a`. La contraseña
tiene 7 caracteres. El solapamiento viene de cómo dos instrucciones `movl` de 32 bits
almacenan valores en el stack — esto quedará claro en el desensamblado.

---

## Identificación de funciones importadas — la ausencia crítica

```
$ objdump -T ./crackme | grep -i "strcmp\|atoi\|strtol\|scanf\|strtoul\|memcmp\|strncmp"
```

Sin salida.

**No hay ninguna función de comparación de strings en la tabla de imports.** `strcmp`,
`memcmp`, `strncmp` — ninguna. El enfoque `break strcmp` que funcionó en los crackmes
anteriores ya no existe. El binario realiza su comparación manualmente dentro de `main`
usando un loop propio. El desensamblado es el único camino.

---

## GDB — desensamblado de main

```
$ gdb ./crackme

(gdb) break main
Breakpoint 1 at 0x1711: file crackme.c, line 5.

(gdb) run
Breakpoint 1, main () at crackme.c:5

(gdb) disassemble main
```

El desensamblado completo se divide en cinco secciones.

### Sección 1 — Stack canary (main+11 a main+24)

```asm
main+11:  mov  %fs:0x28, %rax       ; carga el canary desde el almacenamiento local del hilo
main+20:  mov  %rax, -0x8(%rbp)     ; almacena el canary en el stack
main+24:  xor  %eax, %eax
```

Este es el primer crackme de la serie donde la **protección de stack** de GCC (SSP)
está activa. GCC (GNU Compiler Collection) es el compilador que traduce el código C
al binario ejecutable — inserta el mecanismo del canary automáticamente al compilar
con `-fstack-protector`, que las distribuciones Linux modernas activan por defecto.

Al inicio de la función, se carga un valor aleatorio llamado **canary** desde el
almacenamiento local del hilo (`%fs:0x28`) y se guarda justo debajo del frame pointer
guardado. Al final de la función, ese valor se compara con el original. Si algo lo
modificó, se llama a `__stack_chk_fail` y el programa aborta antes de retornar.

Dos detalles de diseño importantes. Primero, el canary es **aleatorio en cada
ejecución** — un atacante no puede hardcodearlo. Segundo, su **byte menos
significativo es siempre `0x00`**: GCC lo fuerza para que los desbordamientos basados
en strings (que terminan en bytes nulos) no puedan sobrescribir silenciosamente el
canary. Ambas propiedades las veremos confirmadas cuando probemos este mecanismo.

### Sección 2 — Valores esperados cargados en el stack (main+91 a main+111)

```asm
main+91:  movl  $0x68667768, -0x117(%rbp)
main+101: movl  $0x6a727068, -0x114(%rbp)
main+111: movl  $0x7, -0x11c(%rbp)
```

Dos `movl` almacenan los valores esperados (ya transformados) como inmediatos de 32
bits en little-endian. En memoria:

```
Primer movl  ($0x68667768) → 68 77 66 68
Segundo movl ($0x6a727068) → 68 70 72 6a
```

Con un solapamiento de un byte en `-0x114`. El buffer resultante en orden de memoria:

```
Dirección   Byte
-0x117      0x68    ← expected[0]
-0x116      0x77    ← expected[1]
-0x115      0x66    ← expected[2]
-0x114      0x68    ← expected[3]
-0x113      0x70    ← expected[4]
-0x112      0x72    ← expected[5]
-0x111      0x6a    ← expected[6]
```

Siete bytes. La tercera instrucción — `movl $0x7` — confirma que el programa espera
exactamente **7 caracteres**. Por eso `strings` mostró `hwfh` y `hprj`: las
representaciones ASCII de los chunks de 4 bytes de cada `movl`.

### Sección 3 — Filtro de longitud (main+121 a main+164)

```asm
main+121: lea   -0x110(%rbp), %rax
main+131: call  strlen@plt             ; eax = strlen(input)
main+136: cmp   %eax, -0x11c(%rbp)    ; compara strlen(input) con 7
main+142: je    main+166               ; si son iguales, continúa
main+154: call  print_err              ; "Longitud incorrecta."
main+164: jmp   main+280
```

El programa valida la longitud del input **antes** de entrar al loop. Si
`strlen(input) != 7`, sale con error inmediatamente. También revela la longitud de
la contraseña para el análisis estático: **7 caracteres**.

### Sección 4 — Loop de transformación y comparación (main+166 a main+258)

```asm
; Inicialización del contador
main+166: movl  $0x0, -0x120(%rbp)     ; i = 0
main+176: jmp   main+246               ; salta a la condición (loop con condición al final)

; Cuerpo del loop
main+178: mov   -0x120(%rbp), %eax     ; eax = i
main+184: cltq                         ; extiende eax a rax
main+186: movzbl -0x110(%rbp,%rax,1), %eax  ; eax = input[i]
main+194: lea   0x5(%rax), %edx        ; edx = input[i] + 5  ← la transformación
main+197: mov   -0x120(%rbp), %eax     ; eax = i (recarga)
main+203: cltq
main+205: movzbl -0x117(%rbp,%rax,1), %eax  ; eax = expected[i]
main+213: cmp   %al, %dl              ; compara expected[i] con (input[i] + 5)
main+215: je    main+239              ; si son iguales, continúa
main+227: call  print_err
main+237: jmp   main+280

; Incremento y condición
main+239: addl  $0x1, -0x120(%rbp)    ; i++
main+246: mov   -0x120(%rbp), %eax
main+252: cmp   -0x11c(%rbp), %eax    ; compara i con 7
main+258: jl    main+178              ; si i < 7, repite
```

**La transformación** en `main+194`: `lea 0x5(%rax), %edx`.

`lea` (Load Effective Address) se usa aquí como aritmética pura — calcula
`fuente + 5` y guarda el resultado en el destino sin acceder a memoria y sin
modificar el registro fuente. El compilador elige `lea` sobre `add` porque permite
`destino = fuente + inmediato` en una sola instrucción sin efectos secundarios.

**La comparación** en `main+213` compara `%al` (expected[i]) con `%dl`
(input[i] + 5). Si difieren, el programa sale.

**La condición del loop** en `main+258` usa `jl` (signed less than) — corre mientras
`i < 7`, cubriendo índices 0 a 6: siete comparaciones para siete caracteres.

### Sección 5 — Comprobación del stack canary (main+280 a main+301)

```asm
main+280: mov  -0x8(%rbp), %rdx       ; carga el canary almacenado en %rdx
main+284: sub  %fs:0x28, %rdx        ; resta el canary original del TLS
main+293: je   main+300              ; si cero, retorna normalmente
main+295: call __stack_chk_fail      ; si no cero, aborta
main+300: leave
main+301: ret
```

El canary escrito al inicio se verifica aquí. Si la resta produce cero, los valores
coinciden y la función retorna. Cualquier discrepancia llama a `__stack_chk_fail`.

---

## El cast `(unsigned char)` — tipos aritméticos y overflow

Los símbolos de depuración de GDB revelan la expresión exacta:

```
Breakpoint 1, main () at crackme.c:20
20      if ((unsigned char)(input[i] + 5) != expected[i]) {
```

El cast `(unsigned char)` es una decisión de diseño deliberada.

Cuando C evalúa `input[i] + 5`, el compilador **promueve** el `char` a `int` antes
de la suma. El resultado es un entero de 32 bits. Para caracteres ASCII normales esto
no es problema. Pero considera un carácter con valor 252:

```
252 + 5 = 257
```

En binario, 257 necesita 9 bits: `1 0000 0001`. Un byte solo tiene 8. El bit sobrante
se descarta y el resultado se convierte en `0000 0001 = 1`.

Esto es **desbordamiento entero**: el valor da la vuelta al principio del rango.
Piensa en un cuentakilómetros con solo 3 dígitos — después de 999 viene 000, no 1000.
Un byte funciona igual, con límite en 255.

**La diferencia entre `signed char` y `unsigned char`:**

Un `signed char` reserva su bit más alto (bit 7) como bit de signo — rango de -128 a
127. Un `unsigned char` usa todos los 8 bits para magnitud — rango de 0 a 255. Al
eliminar el rol especial del bit de signo, el overflow se convierte en un truncamiento
limpio y predecible: los bits sobrantes simplemente se descartan, dando el resultado
módulo 256.

El cast `(unsigned char)` hace esto explícito:

```c
(unsigned char)(input[i] + 5)
```

Le indica al compilador: "toma solo los 8 bits bajos de este resultado." La operación
equivale a `(input[i] + 5) % 256`. La comparación siempre está bien definida,
independientemente del valor del input.

En este crackme, la contraseña consiste en ASCII minúsculo (rango 97–122). Sumar 5
produce valores entre 102 y 127 — no hay overflow posible en la práctica. El cast es
defensivo: hace explícita la intención sin depender de conversiones implícitas.

---

## Verificación en vivo con GDB

```
(gdb) break *main+194
Breakpoint 1 at 0x17c8: file crackme.c, line 20.

(gdb) run
Contrasena : crackme

Breakpoint 1, main () at crackme.c:20
20      if ((unsigned char)(input[i] + 5) != expected[i]) {

(gdb) print $rax
$1 = 99
```

`%rax` = 99 = `'c'` (ASCII 0x63).

```
(gdb) stepi

(gdb) print $edx
$2 = 104
```

`%edx` = 104 = `'h'` (ASCII 0x68). `'c' (99) + 5 = 104 = 'h'` = `expected[0]`.
Transformación confirmada en vivo.

---

## Recuperación estática — sin ejecutar el binario

`contraseña[i] = expected[i] - 5`:

| Índice | Dirección | Byte esperado | − 5 | Decimal | ASCII |
|---|---|---|---|---|---|
| 0 | `-0x117` | `0x68` | `0x63` | 99 | `c` |
| 1 | `-0x116` | `0x77` | `0x72` | 114 | `r` |
| 2 | `-0x115` | `0x66` | `0x61` | 97 | `a` |
| 3 | `-0x114` | `0x68` | `0x63` | 99 | `c` |
| 4 | `-0x113` | `0x70` | `0x6b` | 107 | `k` |
| 5 | `-0x112` | `0x72` | `0x6d` | 109 | `m` |
| 6 | `-0x111` | `0x6a` | `0x65` | 101 | `e` |

**Contraseña: `crackme`** — recuperada puramente por análisis estático.

```python
expected = [0x68, 0x77, 0x66, 0x68, 0x70, 0x72, 0x6a]
print(''.join(chr(b - 5) for b in expected))
# Salida: crackme
```

```
$ ./crackme
Contrasena : crackme
[+] Password valido!
```

---

## Post-resolución: Stack Canary — Corrupción y bypass con ptrace

Una vez resuelto el crackme, el stack canary es el tema natural siguiente. El mismo
primitivo ptrace del cm2 puede probar su comportamiento directamente desde fuera del
proceso. Dos escenarios, dos programas en Rust.

Primero, los offsets necesarios para los scripts:

```
$ objdump -d ./crackme | grep -A5 "fs:0x28"

    1711:  64 48 8b 04 25 28 00    mov    %fs:0x28,%rax
    171a:  48 89 45 f8             mov    %rax,-0x8(%rbp)     ← offset del store

$ objdump -d ./crackme | grep -A2 "stack_chk_fail"

    181e:  48 8b 55 f8             mov    -0x8(%rbp),%rdx     ← carga canary en rdx
    1822:  64 48 2b 14 25 28 00    sub    %fs:0x28,%rdx        ← offset del check
    182b:  74 05                   je     1832
    182d:  e8 2e f8 ff ff          call   1060 <__stack_chk_fail@plt>
```

Offset del store: `0x171a`. Offset del check: `0x1822`.

### Escenario 1 — Corrompiendo el canary

El script pone un breakpoint en offset `0x171a`, deja ejecutar el store con
`singlestep`, lee el canary desde `rbp - 8`, lo sobreescribe con
`0xDEADBEEFCAFEBABE`, y reanuda. Cuando la ejecución llega al check, la comparación
falla y se llama a `__stack_chk_fail`.

```
[*] load base         : 0x55e0a7a0b000
[*] canary store at   : 0x55e0a7a0c71a
[*] rbp               : 0x7fffb1681c10
[*] canary on stack at: 0x7fffb1681c08
[*] canary value      : 0x8964659be4698200
[*] canary corrupted with 0xDEADBEEFCAFEBABE
[*] resuming — expect stack smashing detected...

  Contrasena : crackme
  [+] Password valido!
*** stack smashing detected ***: terminated
```

Tres observaciones:

**El canary es aleatorio.** Volver a ejecutar produce un valor completamente distinto
— un atacante no puede hardcodearlo.

**El byte bajo es siempre `0x00`.** Tanto `0x...698200` como `0x...b68f00` terminan
en `00`. GCC lo fuerza para que los desbordamientos basados en strings (que terminan
en bytes nulos) no puedan sobrescribir silenciosamente el canary.

**El programa imprimió "Password valido!" antes de crashear.** El check del canary
dispara al salir de la función, no durante la ejecución. La validación de la
contraseña fue exitosa — el crash es exclusivamente sobre la integridad del stack.

**Script — Escenario 1:**

`Cargo.toml` (el mismo para ambos escenarios):

```toml
[package]
name = "cm5_canary"
version = "0.1.0"
edition = "2021"

[dependencies]
nix = { version = "0.29", features = ["ptrace", "process", "signal"] }
```

`src/main.rs`:

```rust
use nix::sys::ptrace;
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{fork, ForkResult, execv, Pid};
use std::ffi::CString;
use std::fs;

// Offset del store del canary: main+20 — mov %rax, -0x8(%rbp)
const CANARY_STORE_OFFSET: u64 = 0x171a;

fn get_load_base(pid: i32) -> u64 {
    let maps = fs::read_to_string(format!("/proc/{}/maps", pid)).unwrap();
    for line in maps.lines() {
        if line.contains("crackme") {
            let base = line.split('-').next().unwrap();
            return u64::from_str_radix(base, 16).unwrap();
        }
    }
    panic!("base de carga no encontrada");
}

fn run_tracer(child: Pid) {
    waitpid(child, None).expect("waitpid inicial falló");

    let base = get_load_base(child.as_raw());
    let store_addr = base + CANARY_STORE_OFFSET;
    println!("[*] base de carga     : {:#x}", base);
    println!("[*] canary store en   : {:#x}", store_addr);

    // Breakpoint en el store del canary
    let orig_store = ptrace::read(child, store_addr as *mut _).expect("peek falló");
    ptrace::write(child, store_addr as *mut _, (orig_store & !0xff) | 0xCC)
        .expect("poke falló");

    ptrace::cont(child, None).expect("cont falló");

    match waitpid(child, None).expect("waitpid falló") {
        WaitStatus::Stopped(_, _) => {
            let mut regs = ptrace::getregs(child).expect("getregs falló");
            regs.rip -= 1;
            ptrace::write(child, store_addr as *mut _, orig_store as i64)
                .expect("restaurar falló");
            ptrace::setregs(child, regs).expect("setregs falló");

            // Single-step para ejecutar el store
            ptrace::step(child, None).expect("step falló");
            waitpid(child, None).ok();

            // Leer rbp para calcular la dirección del canary
            let regs = ptrace::getregs(child).expect("getregs falló");
            let canary_addr = regs.rbp - 8;
            let canary_value = ptrace::read(child, canary_addr as *mut _)
                .expect("leer canary falló");

            println!("[*] rbp               : {:#x}", regs.rbp);
            println!("[*] canary en stack   : {:#x}", canary_addr);
            println!("[*] valor del canary  : {:#x}", canary_value as u64);

            // Corrompemos el canary
            ptrace::write(child, canary_addr as *mut _, 0xDEADBEEFCAFEBABEu64 as i64)
                .expect("corromper falló");
            println!("[*] canary corrompido con 0xDEADBEEFCAFEBABE");
            println!("[*] reanudando — espera stack smashing detected...");

            ptrace::cont(child, None).expect("cont final falló");
            waitpid(child, None).ok();
        }
        other => println!("estado inesperado: {:?}", other),
    }
}

fn main() {
    match unsafe { fork() }.expect("fork falló") {
        ForkResult::Child => {
            ptrace::traceme().expect("traceme falló");
            let path = CString::new("./crackme").unwrap();
            execv(&path, &[] as &[CString]).expect("execv falló");
        }
        ForkResult::Parent { child } => {
            run_tracer(child);
        }
    }
}
```

### Escenario 2 — Bypasseando el SSP

Restaurar solo el stack no es suficiente. La secuencia del check:

```asm
main+280: mov  -0x8(%rbp), %rdx    ← carga el canary (corrompido) en %rdx
main+284: sub  %fs:0x28, %rdx      ← nuestro breakpoint dispara AQUÍ
main+293: je   main+300
main+295: call __stack_chk_fail
```

Cuando nuestro breakpoint en `0x1822` dispara, `main+280` ya ejecutó — `%rdx` ya
contiene el valor corrompido `0xDEADBEEFCAFEBABE`. Hay que restaurar tanto la
posición en el stack como `%rdx`, o la resta no producirá cero.

El bypass: dos breakpoints (store y check), leer el canary original, corromperse, y
en el check restaurar tanto el stack como `%rdx`.

```
[*] load base         : 0x5569c68b8000
[*] canary store at   : 0x5569c68b971a
[*] canary check at   : 0x5569c68b9822
[*] rbp               : 0x7ffe26143400
[*] canary on stack at: 0x7ffe261433f8
[*] canary value      : 0x6d89dc5a86b68f00
[*] canary corrupted with 0xDEADBEEFCAFEBABE
  [+] Password valido!
[*] canary restored on stack and in %rdx
[*] done — process exited cleanly, no crash
```

Sin crash. El check del SSP pasó.

**Script — Escenario 2:**

```rust
use nix::sys::ptrace;
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{fork, ForkResult, execv, Pid};
use std::ffi::CString;
use std::fs;

const CANARY_STORE_OFFSET: u64 = 0x171a;
const CANARY_CHECK_OFFSET: u64 = 0x1822;

fn get_load_base(pid: i32) -> u64 {
    let maps = fs::read_to_string(format!("/proc/{}/maps", pid)).unwrap();
    for line in maps.lines() {
        if line.contains("crackme") {
            let base = line.split('-').next().unwrap();
            return u64::from_str_radix(base, 16).unwrap();
        }
    }
    panic!("base de carga no encontrada");
}

fn run_tracer(child: Pid) {
    waitpid(child, None).expect("waitpid inicial falló");

    let base = get_load_base(child.as_raw());
    let store_addr = base + CANARY_STORE_OFFSET;
    let check_addr = base + CANARY_CHECK_OFFSET;
    println!("[*] base de carga     : {:#x}", base);
    println!("[*] canary store en   : {:#x}", store_addr);
    println!("[*] canary check en   : {:#x}", check_addr);

    // Breakpoint 1 — store del canary
    let orig_store = ptrace::read(child, store_addr as *mut _).expect("peek store falló");
    ptrace::write(child, store_addr as *mut _, (orig_store & !0xff) | 0xCC)
        .expect("poke store falló");

    // Breakpoint 2 — check del canary
    let orig_check = ptrace::read(child, check_addr as *mut _).expect("peek check falló");
    ptrace::write(child, check_addr as *mut _, (orig_check & !0xff) | 0xCC)
        .expect("poke check falló");

    ptrace::cont(child, None).expect("cont falló");

    // Breakpoint 1 dispara: store del canary
    match waitpid(child, None).expect("waitpid bp1 falló") {
        WaitStatus::Stopped(_, _) => {
            let mut regs = ptrace::getregs(child).expect("getregs bp1 falló");
            regs.rip -= 1;
            ptrace::write(child, store_addr as *mut _, orig_store as i64)
                .expect("restaurar store falló");
            ptrace::setregs(child, regs).expect("setregs bp1 falló");
            ptrace::step(child, None).expect("step falló");
            waitpid(child, None).ok();

            let regs = ptrace::getregs(child).expect("getregs post-step falló");
            let canary_addr = regs.rbp - 8;
            let canary_original = ptrace::read(child, canary_addr as *mut _)
                .expect("leer canary falló");

            println!("[*] rbp               : {:#x}", regs.rbp);
            println!("[*] canary en stack   : {:#x}", canary_addr);
            println!("[*] valor del canary  : {:#x}", canary_original as u64);

            ptrace::write(child, canary_addr as *mut _, 0xDEADBEEFCAFEBABEu64 as i64)
                .expect("corromper canary falló");
            println!("[*] canary corrompido con 0xDEADBEEFCAFEBABE");

            ptrace::cont(child, None).expect("cont al check falló");

            // Breakpoint 2 dispara: check del canary
            match waitpid(child, None).expect("waitpid bp2 falló") {
                WaitStatus::Stopped(_, _) => {
                    let mut regs = ptrace::getregs(child).expect("getregs bp2 falló");
                    regs.rip -= 1;
                    ptrace::write(child, check_addr as *mut _, orig_check as i64)
                        .expect("restaurar check falló");

                    // Restauramos el canary en el stack
                    ptrace::write(child, canary_addr as *mut _, canary_original)
                        .expect("restaurar canary en stack falló");

                    // Restauramos %rdx — main+280 ya cargó el valor corrompido
                    // antes de que nuestro breakpoint disparara en main+284.
                    regs.rdx = canary_original as u64;

                    println!("[*] canary restaurado en stack y en %rdx");
                    ptrace::setregs(child, regs).expect("setregs bp2 falló");
                    ptrace::cont(child, None).expect("cont final falló");
                    waitpid(child, None).ok();
                    println!("[*] hecho — proceso terminó limpiamente, sin crash");
                }
                other => println!("estado inesperado en check: {:?}", other),
            }
        }
        other => println!("estado inesperado en store: {:?}", other),
    }
}

fn main() {
    match unsafe { fork() }.expect("fork falló") {
        ForkResult::Child => {
            ptrace::traceme().expect("traceme falló");
            let path = CString::new("./crackme").unwrap();
            execv(&path, &[] as &[CString]).expect("execv falló");
        }
        ForkResult::Parent { child } => {
            run_tracer(child);
        }
    }
}
```

**Lo que esto demuestra sobre el modelo de seguridad del SSP:**

El stack canary no es una garantía contra todos los ataques — es una garantía contra
los no informados. Su modelo de amenaza asume que el atacante no conoce el valor del
canary. Si el atacante tiene acceso a la memoria del proceso (una vulnerabilidad de
filtrado de información, o acceso a nivel de proceso como demuestra ptrace aquí), el
canary puede leerse, el overflow puede ocurrir, y el canary puede restaurarse antes
del check.

Las técnicas reales de bypass en exploits siguen el mismo patrón: primero filtrar el
canary, luego corromper el stack, luego sobreescribir la posición del canary con el
valor filtrado antes de que la función retorne. La defensa del byte nulo mitiga el
filtrado mediante strings de formato `printf` o funciones de string, pero no mediante
primitivas de lectura arbitraria.

Entender el mecanismo a nivel de instrucción — no solo que existe, sino cómo funciona
internamente — es lo que permite razonar sobre cuándo protege y cuándo no.

---

## Conexión con malware real y la progresión cm4/cm5

En el contexto de esta serie de crackmes, el cm4 y el cm5 juntos representan las dos
capas que LockBit combina en su ofuscación:

**cm4** demuestra el **patrón estructural**: construir strings byte a byte con
instrucciones `movb` individuales, para que el dato nunca exista como secuencia
contigua en el binario. LockBit hace exactamente esto con los nombres de sus DLLs.

**cm5** demuestra la **capa de ofuscación**: aplicar una transformación al dato antes
de almacenarlo, para que el valor almacenado no sea el texto plano. En el cm5 la
transformación es una suma simple (`+5`). LockBit usa un cifrado afín por string —
significativamente más difícil de invertir sin los parámetros, pero estructuralmente
idéntico: el binario almacena el valor transformado, no el original.

LockBit aplica ambas simultáneamente: los bytes escritos por las instrucciones
`MOV BYTE PTR` son texto cifrado, y un loop de descifrado corre inmediatamente
después de la construcción. Entender el cm4 y el cm5 como conceptos separados hace
que el mecanismo combinado en malware real sea más fácil de descomponer durante el
análisis.

---

## Progresión cm1 / cm2 / cm3 / cm4 / cm5

| Aspecto | CM1 | CM2 | CM3 | CM4 | CM5 |
|---|---|---|---|---|---|
| Función clave | `strcmp` | `atoi` | `strcmp` | `strcmp` | **ninguna** |
| Comparación | Librería | Librería | Librería | Librería | **loop manual** |
| Ubicación del secreto | `.rodata` | Opcode `cmpl` | `movl` cifrado | `movb` plano | `movl` transformado |
| Filtro de longitud | No | No | No | No | **Sí — strlen** |
| Transformación | Ninguna | Ninguna | XOR 0x13 | Ninguna | **+5 por carácter** |
| ¿Visible con `strings`? | Sí | No | Parcialmente | No | Parcialmente |
| Stack canary | No | No | No | No | **Sí** |
| Concepto nuevo | Conv. de llamadas | Comp. de enteros | XOR | Stack strings | Loop custom, transformación, canary, bypass SSP |

---

*Parte de una serie de writeups de crackmes cubriendo binarios progresivamente más difíciles.*

*Los binarios están disponibles en [github.com/GinoMaihuiri/Crackmes](https://github.com/GinoMaihuiri/Crackmes)*
*Tooling: [github.com/GinoMaihuiri/Crackmes/tree/main/tooling](https://github.com/GinoMaihuiri/Crackmes/tree/main/tooling)*
*Todos los writeups: [ginomaihuiri.github.io](https://ginomaihuiri.github.io)*

---

© 2026 Aldair Maihuiri. Todos los derechos reservados.
Compartir con atribución es bienvenido. Prohibida la reproducción no autorizada.
