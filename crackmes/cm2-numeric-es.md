---
title: "Crackme 02 — Serial numérico: deducción por desensamblado y live patching con Rust"
description: "Resolución de cm2_numeric: uso de atoi, lectura del cmpl con GDB, deducción del serial por instrucción, e implementación de live patching via ptrace en Rust."
author: Aldair Maihuiri
date: 2026-08-07
---

🇬🇧 [Read in English](https://ginomaihuiri.github.io/crackmes/cm2-numeric)

# Crackme 02 — Serial numérico: deducción por desensamblado y live patching con Rust

**Autor:** Aldair Maihuiri
**Fecha:** 7 de agosto de 2026
**Binario:** cm2_numeric (ELF 64-bit, PIE, sin strippear)
**Herramientas:** GDB, objdump, Rust (crate nix)
**Tags:** `crackme` `reverse-engineering` `gdb` `x86_64` `atoi` `ptrace` `rust` `live-patching`

---

© 2026 Aldair Maihuiri. Todos los derechos reservados.
Puedes compartir este writeup con atribución. Prohibida la reproducción sin permiso.

---

## Reconocimiento inicial

```
$ file ./crackme

./crackme: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV),
dynamically linked,
interpreter /lib64/ld-linux-x86-64.so.2,
BuildID[sha1]=78322b7005129073b4dd2da6e3b1fea092930383,
for GNU/Linux 4.4.0, with debug_info, not stripped
```

ELF 64-bit, enlazado dinámicamente y sin strippear. El flag **PIE** (Position Independent Executable) es el dato que más importa en este crackme: significa que el sistema asigna una dirección base aleatoria en cada ejecución. Ninguna dirección vista en GDB o en el desensamblado será fija en disco — siempre será `base_de_carga + offset`. Esto será determinante cuando implementemos el live patching.

---

## Identificación de funciones importadas

Antes de abrir el debugger, examinamos qué funciones externas usa el binario:

```
$ objdump -T ./crackme | grep -i "strcmp\|atoi\|strtol\|sscanf\|scanf"

0000000000000000  DF *UND*  0000000000000000 (GLIBC_2.2.5) atoi
```

Un solo resultado: `atoi`. Esta función convierte una cadena de texto a un entero:

```c
int atoi(const char *str);
```

Su comportamiento define toda la lógica del crackme:

- Lee caracteres desde el inicio mientras sean dígitos.
- Al encontrar el primer carácter no-dígito, para y devuelve lo acumulado.
- Si el primer carácter ya no es dígito, devuelve directamente 0.

Esto significa que el programa **no compara cadenas** — compara enteros. La diferencia respecto al cm1 (que usaba `strcmp`) es fundamental:

| | CM1 (strcmp) | CM2 (atoi) |
|---|---|---|
| Función clave | `strcmp` | `atoi` |
| Tipo de secreto | String en `.rodata` | Número inmediato en opcode |
| ¿Visible con `strings`? | Sí | No |
| Breakpoint útil | `break strcmp` | `break atoi` |

El secreto del cm1 era una cadena en el segmento de datos — visible para cualquier herramienta de extracción de strings. El secreto del cm2 está incrustado dentro de la instrucción `cmp`, como operando inmediato. No existe como dato separado en el binario: es parte del código.

---

## Análisis con GDB

### Estrategia

La misma lógica que el cm1: ponemos el breakpoint en la función que procesa el input (`atoi`), la dejamos ejecutar con `finish`, y al regresar a `main` inspeccionamos las instrucciones que siguen. Ahí está el secreto.

```
$ gdb ./crackme

(gdb) break atoi
Breakpoint 1 at 0x10a0

(gdb) run
```

```
╔══════════════════════════════════════════════
║ Nivel 1 · CM02  [*       ]
║ Serial numerico
╠══════════════════════════════════════════════
║ Solo un numero desbloquea el sistema.
╚══════════════════════════════════════════════

Serial: 99999

Breakpoint 1, 0x00007ffff7c3f780 in atoi () from /usr/lib/libc.so.6
```

El debugger paró dentro de `atoi`, antes de que la función haga su trabajo. Con `finish` la ejecutamos completa y regresamos a `main`:

```
(gdb) finish

Run till exit from #0  0x00007ffff7c3f780 in atoi ()
   from /usr/lib/libc.so.6
0x0000555555555780 in main () at crackme.c:12
12      int val = atoi(input);
```

Estamos parados en `main+106`. Con `x/10i $rip` vemos las instrucciones que vienen:

```
(gdb) x/10i $rip

=> 0x555555555780 <main+106>: mov    %eax,-0x114(%rbp)
   0x555555555786 <main+112>: cmpl   $0x539,-0x114(%rbp)
   0x555555555790 <main+122>: jne    0x5555555557a8 <main+146>
   0x555555555792 <main+124>: lea    0xb23(%rip),%rax        # 0x5555555562bc
   0x555555555799 <main+131>: mov    %rax,%rdi
   0x55555555579c <main+134>: call   0x55555555560c <print_ok>
   0x5555555557a1 <main+139>: mov    $0x0,%eax
   0x5555555557a6 <main+144>: jmp    0x5555555557bc <main+166>
   0x5555555557a8 <main+146>: lea    0xb1c(%rip),%rax        # 0x5555555562cb
   0x5555555557af <main+153>: mov    %rax,%rdi
```

### Lectura instrucción por instrucción

**`main+106 — mov %eax, -0x114(%rbp)`**

En sintaxis AT&T, el origen va primero y el destino después. Esta instrucción **mueve** el contenido de `%eax` **hacia** la posición de memoria `-0x114(%rbp)`.

`%eax` contiene el valor de retorno de `atoi` — el número recién convertido. `-0x114(%rbp)` es la dirección en el stack donde el compilador ubicó la variable local `val`. El cálculo: `rbp` es la base del frame actual, y restamos `0x114` (276 en decimal) porque el stack crece hacia abajo — las variables locales viven en offsets negativos:

```
[%rbp]              ← base del frame de main
...
[%rbp - 0x114]      ← variable "val" ← aquí se guarda el retorno de atoi
```

Esta instrucción es la traducción de `val = atoi(input)`.

**`main+112 — cmpl $0x539, -0x114(%rbp)`**

Aquí está el serial.

El sufijo `l` indica operandos de 32 bits (el tamaño de un `int`). La instrucción calcula internamente `val - 0x539` y actualiza las flags del procesador sin modificar ningún operando. Si el resultado es cero, el Zero Flag (ZF) se pone en 1.

`$0x539` es el operando inmediato — el valor correcto, incrustado directamente en los bytes del opcode. No existe en ninguna otra parte del binario como dato. No aparece con `strings`.

```
(gdb) print 0x539
$1 = 1337
```

**El serial es 1337.** Es el número que eligió quien programó el crackme — "leet", de la jerga hacker. No es accidental.

**`main+122 — jne 0x5555555557a8`**

Jump if Not Equal: salta si ZF=0, es decir, si los valores difirieron. El destino del salto (`main+146`) es la rama de error. Si no salta (val == 1337), la ejecución avanza a `main+124` y llega a `print_ok`.

### Flujo completo de la decisión

```
atoi(input) → val

cmpl $1337, val → ZF = (val == 1337) ? 1 : 0

│
├── ZF = 1  → jne NO salta → print_ok → "Serial válido"
│
└── ZF = 0  → jne SALTA   → print_err → "Serial inválido"
```

Esta estructura es idéntica a la del cm1 (`test eax, eax → jne`). Cambia la función que produce el valor, no la mecánica de la decisión.

### Verificación

```
(gdb) run

Serial: 1337

Breakpoint 1, 0x00007ffff7c3f780 in atoi () from /usr/lib/libc.so.6

(gdb) continue

  [+] Serial valido!
```

---

## Investigación post-resolución: comportamiento de atoi con input no numérico

Resuelto el crackme, investigamos cómo responde a inputs que no son números puros.
La pregunta de fondo: si `atoi` devuelve 0 ante cualquier input que empiece con letra,
y el serial correcto fuera 0, **cualquier basura no numérica pasaría la validación**.
Ese sería un bug de diseño real — y es exactamente el tipo de razonamiento que lleva de resolver crackmes a encontrar vulnerabilidades.

Para leer el retorno de `atoi` en el instante exacto en que está disponible, aprovechamos el punto donde quedamos tras el `finish`: en `main+106`, antes de que el `mov` ejecute. En ese instante, el resultado de `atoi` vive solo en `%eax` — el registro de retorno.

```
(gdb) run
Serial: HolaMaihuiri

Breakpoint 1, 0x00007ffff7c3f780 in atoi () from /usr/lib/libc.so.6

(gdb) finish
0x0000555555555780 in main () at crackme.c:12
12      int val = atoi(input);

(gdb) print $eax
$2 = 0
```

`atoi("HolaMaihuiri")` devuelve 0. El primer carácter es una letra, no se acumula ningún dígito.

Con `stepi` ejecutamos el `mov` para que el valor se guarde en memoria y podemos verificar que la escritura fue correcta:

```
(gdb) stepi
13      if (val == 0x539) {

(gdb) x/d $rbp - 0x114
0x7fffffffe4ac: 0
```

`x/d` examina la dirección `rbp - 0x114` e interpreta el contenido como entero decimal. Coincide con `%eax`. La tabla completa de comportamiento:

| Input | Retorno de atoi | ¿Pasa? | Por qué |
|---|---|---|---|
| `1337` | 1337 | ✅ | Número exacto |
| `HolaMaihuiri` | 0 | ❌ | Primer carácter no es dígito |
| `123HolaMaihuiri` | 123 | ❌ | Para en la 'H', devuelve lo acumulado |
| `1337abc` | 1337 | ✅ | Para en la 'a', ya acumuló 1337 |

El último caso es el más interesante: `1337abc`, `1337!!!`, `1337 cualquiercosa` pasan la validación. `atoi` para en el primer carácter no-dígito y devuelve lo acumulado hasta ese punto. No lanza un error, no devuelve -1, simplemente ignora el resto. En un contexto real, ese parsing laxo puede ser un vector de manipulación de input.

---

## Extracción del offset del jne

Para el live patching necesitamos el **offset del `jne` dentro del archivo**, no la dirección de carga — que por el PIE cambia en cada ejecución. `objdump` trabaja sobre el archivo en disco y nos da exactamente eso:

```
$ objdump -d ./crackme | grep -A2 "cmpl.*0x539"

    1786:   81 bd ec fe ff ff 39    cmpl   $0x539,-0x114(%rbp)
    178d:   05 00 00
    1790:   75 16                   jne    17a8 <main+0x92>
```

| Offset en archivo | Bytes | Instrucción |
|---|---|---|
| `0x1786` | `81 bd ec fe ff ff 39 05 00 00` | `cmpl $0x539, -0x114(%rbp)` |
| `0x1790` | `75 16` | `jne 17a8` |

El `jne` vive en el offset `0x1790`. Su dirección real en tiempo de ejecución es `base_de_carga + 0x1790`. El proceso tracer tiene que calcular esa base antes de poder intervenir.

---

## Live patching con Rust y ptrace

### Concepto

La resolución anterior encontró el serial leyendo las instrucciones. Esta fase no busca el serial — lo evita completamente.

La técnica es **CPU state manipulation via ptrace**: intervenimos el estado interno del procesador en el instante exacto de la decisión, sin tocar el binario en disco.

El plan:

1. Un proceso en Rust se adjunta al crackme como tracer vía `ptrace`.
2. Escribe `0xCC` (`int3`) en la dirección del `jne` — así funciona un breakpoint a nivel de CPU.
3. Cuando el proceso para en ese breakpoint, modifica un bit en `EFLAGS`: el Zero Flag (ZF), bit 6.
4. Restaura el byte original del `jne` y corrige `RIP`.
5. Al reanudar, el `jne` lee ZF=1, interpreta que la comparación fue exitosa, y no salta.
6. "Serial válido" con cualquier input.

### Por qué ptrace

`ptrace` es la syscall del kernel sobre la que está construido GDB. Cada breakpoint, cada `stepi`, cada lectura de registro de este writeup pasó por `ptrace`. Aquí la usamos directamente, sin intermediarios.

`ptrace` no tiene un request "poner breakpoint". Un breakpoint se construye: se escribe `0xCC` en la dirección objetivo con `POKEDATA`, la CPU genera una interrupción al ejecutarlo, el kernel notifica al tracer. GDB hace exactamente esto cada vez que escribes `break`. Aquí lo hacemos manualmente.

### Estructura del proyecto

```
$ cargo new cm2_patcher
$ cd cm2_patcher
```

`Cargo.toml`:

```toml
[package]
name = "cm2_patcher"
version = "0.1.0"
edition = "2021"

[dependencies]
nix = { version = "0.29", features = ["ptrace", "process", "signal"] }
```

### Código fuente

`src/main.rs`:

```rust
use nix::sys::ptrace;
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{fork, ForkResult, execv, Pid};
use std::ffi::CString;
use std::fs;

// Offset del jne en el archivo, extraído con objdump
const JNE_OFFSET: u64 = 0x1790;

/// Lee /proc/<pid>/maps para resolver la base de carga del binario.
/// Necesario porque el binario es PIE: la base es aleatoria en cada ejecución.
fn get_load_base(pid: i32) -> u64 {
    let maps = fs::read_to_string(format!("/proc/{}/maps", pid)).unwrap();
    for line in maps.lines() {
        if line.contains("crackme") {
            let base = line.split('-').next().unwrap();
            return u64::from_str_radix(base, 16).unwrap();
        }
    }
    panic!("no se encontró la base de carga en /proc/{}/maps", pid);
}

fn run_tracer(child: Pid) {
    // Esperamos a que el hijo se detenga tras el exec
    // El kernel detiene automáticamente al tracee al ejecutar execv
    waitpid(child, None).expect("waitpid inicial falló");

    // Calculamos la dirección real del jne en tiempo de ejecución
    let base = get_load_base(child.as_raw());
    let jne_addr = base + JNE_OFFSET;
    println!("[*] base de carga : {:#x}", base);
    println!("[*] jne en        : {:#x}", jne_addr);

    // PEEKDATA: leemos la palabra de 8 bytes donde está el jne
    // Guardamos el valor original para restaurarlo después
    let original = ptrace::read(child, jne_addr as *mut _)
        .expect("PEEKDATA falló");

    // Reemplazamos el byte más bajo por 0xCC (int3)
    // Los otros 7 bytes quedan intactos con la máscara & !0xff
    let with_bp = (original & !0xff) | 0xCC;
    ptrace::write(child, jne_addr as *mut _, with_bp as i64)
        .expect("POKEDATA (breakpoint) falló");
    println!("[*] breakpoint colocado en el jne (0xCC)");

    // CONT: reanudamos — el crackme pedirá el serial, el usuario teclea algo
    ptrace::cont(child, None).expect("cont falló");

    // Esperamos a que el proceso pare al ejecutar el 0xCC
    match waitpid(child, None).expect("waitpid falló") {
        WaitStatus::Stopped(_, _) => {
            println!("[*] breakpoint alcanzado — forzando ZF=1");

            // GETREGS: leemos todos los registros del proceso detenido
            let mut regs = ptrace::getregs(child).expect("GETREGS falló");

            // Forzamos ZF = 1 en EFLAGS (bit 6, máscara 0x40)
            // El jne leerá ZF=1 e interpretará que la comparación fue "igual"
            regs.eflags |= 0x40;

            // Ajuste de RIP:
            // Al ejecutar 0xCC, la CPU avanza RIP un byte más allá del breakpoint.
            // Lo retrocedemos para que al reanudar se ejecute el jne original.
            regs.rip -= 1;

            // Restauramos el byte original del jne (eliminamos el 0xCC)
            ptrace::write(child, jne_addr as *mut _, original as i64)
                .expect("POKEDATA (restauración) falló");

            // SETREGS: escribimos los registros modificados de vuelta al proceso
            ptrace::setregs(child, regs).expect("SETREGS falló");

            // CONT: reanudamos — el jne ve ZF=1 y no salta
            ptrace::cont(child, None).expect("cont final falló");
            waitpid(child, None).ok();
            println!("[*] hecho");
        }
        other => println!("estado inesperado: {:?}", other),
    }
}

fn main() {
    match unsafe { fork() }.expect("fork falló") {
        ForkResult::Child => {
            // El hijo se ofrece a ser trazado por su padre
            ptrace::traceme().expect("TRACEME falló");
            // Reemplaza la imagen del proceso con el crackme
            let path = CString::new("./crackme").unwrap();
            execv(&path, &[] as &[CString]).expect("execv falló");
        }
        ForkResult::Parent { child } => {
            run_tracer(child);
        }
    }
}
```

### Tabla de llamadas a ptrace

| Llamada | Request interno | Qué hace |
|---|---|---|
| `ptrace::traceme()` | `PTRACE_TRACEME` | El hijo le indica al kernel que acepte ser trazado por su padre |
| `waitpid` | — | El padre espera a que el tracee se detenga |
| `ptrace::read` | `PTRACE_PEEKDATA` | Lee una palabra de 8 bytes de la memoria del tracee |
| `ptrace::write` | `PTRACE_POKEDATA` | Escribe una palabra de 8 bytes en la memoria del tracee |
| `ptrace::cont` | `PTRACE_CONT` | Reanuda la ejecución del tracee |
| `ptrace::getregs` | `PTRACE_GETREGS` | Lee todos los registros del tracee (rax, rbp, rip, eflags, ...) |
| `ptrace::setregs` | `PTRACE_SETREGS` | Escribe todos los registros del tracee |

### Por qué RIP -= 1

Cuando la CPU ejecuta `0xCC` en la dirección `jne_addr`, RIP queda apuntando al byte inmediatamente siguiente — `jne_addr + 1`. Si reanudamos sin corregir, la CPU ejecutaría lo que haya en esa posición, saltándose el `jne`.

El ajuste `rip -= 1` lo devuelve a `jne_addr`. Como antes de reanudar restauramos el byte original (`75 16`, el `jne` real), la CPU ejecutará el `jne` con ZF=1 ya forzado en `eflags`, y no saltará.

### Compilación y prueba

```
$ cargo build

   Compiling cm2_patcher v0.1.0
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 4.24s
```

El crackme debe estar en el mismo directorio que el patcher:

```
$ cp ../crackme .
$ ./target/debug/cm2_patcher
```

```
╔══════════════════════════════════════════════
║ Nivel 1 · CM02  [*       ]
║ Serial numerico
╠══════════════════════════════════════════════
║ Solo un numero desbloquea el sistema.
╚══════════════════════════════════════════════

  Serial     : HolaMaihuiri

[*] base de carga : 0x555555554000
[*] jne en        : 0x555555555790
[*] breakpoint colocado en el jne (0xCC)
[*] breakpoint alcanzado — forzando ZF=1
  [+] Serial valido!
[*] hecho
```

Cualquier input — letras, números arbitrarios, símbolos — produce "Serial válido".

El binario en disco no fue modificado.  
El serial no fue consultado.  
El estado interno del procesador fue intervenido en el instante exacto de la decisión.

---

## Resumen comparativo cm1 vs cm2

| Aspecto | CM1 (strcmp) | CM2 (numeric) |
|---|---|---|
| Función clave | `strcmp` | `atoi` |
| Tipo de secreto | String en `.rodata` | Inmediato en opcode de `cmpl` |
| ¿Visible con `strings`? | Sí | No |
| Cómo detectarlo | `break strcmp` → `x/s $rsi` | `break atoi` → `finish` → `x/10i $rip` |
| Valor de retorno relevante | Puntero al string | Entero en `%eax` |
| Técnica adicional | — | Live patching via ptrace en Rust |
| Estado intervenido | — | EFLAGS — Zero Flag (ZF) |

---

*Parte de una serie de writeups de crackmes cubriendo binarios progresivamente más difíciles — desde comparaciones hardcodeadas hasta chequeos ofuscados, funciones hash propias y técnicas anti-debug.*

*Los binarios están disponibles en [github.com/GinoMaihuiri/Crackmes](https://github.com/GinoMaihuiri/Crackmes)*

*Todos los writeups: [ginomaihuiri.github.io](https://ginomaihuiri.github.io)*

---

© 2026 Aldair Maihuiri. Todos los derechos reservados.
Compartir con atribución es bienvenido. Prohibida la reproducción no autorizada.
