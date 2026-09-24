---
title: "Ransomware Red Teaming — Module 1: Introduction"
description: "How is ransomware built?"
author: Aldair Maihuiri
---
# Módulo 01 — Introducción al Curso de Ransomware (Red team)


## 1.1 ¿Qué es el Ransomware?

Ransomware = malware que:

1. **Enumera** archivos del sistema/red

2. **Cifra** los archivos con criptografía asimétrica+simétrica

3. **Elimina** las copias de seguridad del SO

4. **Muestra** una nota de rescate con instrucciones de pago

### Familias reales de referencia (para análisis)

| Familia | Año | Algoritmo | Particularidad |
| - | - | - | - |
| WannaCry | 2017 | RSA-2048 + AES-128 | NSA EternalBlue exploit |
| REvil/Sodinokibi | 2019-2021 | Curve25519 + Salsa20 | RaaS, MMP (Multi-Master Pattern) |
| Conti | 2020-2022 | RSA + ChaCha20 | Múltiples threads, muy rápido |
| LockBit 3.0 | 2022-2024 | ECDH + AES-CTR | Más rápido del mercado, 3000 archivos/min |
| BlackCat/ALPHV | 2021-2024 | ECDH + ChaCha20 | Escrito en Rust |
| Akira | 2023-2026 | ECDH + ChaCha20-Poly1305 | Go/C++, Linux+Windows |


### Evolución 2020-2026

```
2020: Encrypt-and-exfiltrate → "double extortion"  
2021: Triple extortion (DDoS + encrypt + leak)  
2022: RaaS (Ransomware-as-a-Service) dominante  
2023: Intermittent encryption (solo parcial → más rápido)  
2024: Linux/ESXi targets (VMware VMDK)  
2025: BYOD/cloud-aware (OneDrive sync encryption)  
2026: AI-assisted target selection, supply chain ransomware
```

> **¿Por qué el ransomware evolucionó de cifrado simple a triple extorsión?** El modelo original de "solo cifrar" fracasó contra empresas con backups funcionales: si IT tiene copia limpia, no paga. Maze (noviembre 2019) descubrió que el daño reputacional y regulatorio de una filtración de datos es independiente de si hay backup — el GDPR impone multas de hasta el 4% del revenue global por exposición de PII, paguen o no. La doble extorsión convierte el cifrado en amenaza secundaria: la exfiltración es la palanca real. La triple extorsión añade presión directa sobre clientes, reguladores y empleados porque la víctima no puede hacer que la filtración "desaparezca" aunque restaure desde backup. El caso extremo: Cl0p/MOVEit (2023) no desplegó un solo locker — solo exfiltró 2.000+ organizaciones y ganó ~$100M sin escribir una sola clave de cifrado.

## 1.2 Consideraciones Legales y Éticas

### Marco legal

**IMPORTANTE**: Desarrollar, poseer o usar ransomware contra sistemas sin autorización es:

- **España**: Art. 264 bis CP — sabotaje informático → hasta 10 años

- **México**: Art. 211 bis CP → acceso ilícito a sistemas

- **USA**: CFAA (Computer Fraud and Abuse Act) → hasta 10 años/cargo

- **UK**: Computer Misuse Act 1990 → hasta 10 años

### Uso legítimo de este conocimiento

Este curso es para:

- **Red teamers** 

- **Analistas de malware** para análisis forense y detección

- **Defensores** para entender cómo funcionan los ataques y construir mejores defensas

- **CTF/lab environments** — máquinas virtuales aisladas

### Reglas del laboratorio

```
SIEMPRE:  
✓ Usar VM aislada de red (sin acceso a red real)  
✓ Snapshots antes de ejecutar el ransomware  
✓ Solo archivos de prueba generados por ti mismo  
✓ Documentar todo para informe de red team  
  
NUNCA:  
✗ Ejecutar en sistema real / producción  
✗ Usar contra terceros sin autorización firmada  
✗ Exfiltrar datos reales  
✗ Conectar C2 a infraestructura real sin autorización
```

### Entorno de laboratorio recomendado

```
Host: Tu So  
VM 1: Windows 10/11 AISLADA  
  - Sin adaptador de red (host-only o desconectado)  
  - Snapshots cada módulo  
  - Directorio de prueba: C:\\TestFiles\\ con archivos dummy  
VM 2: Windows Server (para probar funciones de dominio)  
  
Software:  
- VMware Workstation / VirtualBox  
- Ghidra (para análisis inverso de los binarios que produces)  
- x64dbg (debugging)  
- Process Monitor (ver operaciones de archivos)  
- Wireshark (verificar que no hay tráfico saliente)
```


## 1.3 Arquitectura General de un Ransomware Moderno

```
┌─────────────────────────────────────────────────────┐  
│                    RANSOMWARE                       │  
├──────────────┬──────────────┬───────────────────────┤  
│   BUILDER    │    LOCKER    │      DECRYPTOR        │  
│              │              │                       │  
│ Configura:   │ - Enumerar   │ - Recibe clave        │  
│ - Clave RSA  │   archivos   │   del atacante        │  
│ - Extensión  │ - Cifrar     │ - Descifra archivos   │  
│ - Nota       │ - Borrar VSS │ - Verifica hash       │  
│ - Exclusiones│ - Nota ransom│                       │  
└──────────────┴──────────────┴───────────────────────┘
```

### Flujo de operación del locker

```
1. Inicialización  
   ├── Verificar si ya hay instancia corriendo (mutex)  
   ├── Cargar configuración (embebida en el binario)  
   └── Generar par de claves efímeras (ECDH)  
  
2. Preparación  
   ├── Escalar privilegios (si es posible)  
   ├── Deshabilitar recuperación (VSS, System Restore)  
   └── Terminar procesos que bloquean archivos (SQL, Office)  
  
3. Enumeración  
   ├── Listar unidades (locales + red)  
   ├── Recorrer directorios recursivamente  
   └── Filtrar por extensión / exclusiones  
  
4. Cifrado (en paralelo con thread pool)  
   ├── Para cada archivo:  
   │   ├── Generar AES key/IV únicos  
   │   ├── Cifrar el archivo  
   │   ├── Cifrar el AES key con RSA/ECDH público del atacante  
   │   └── Escribir footer con AES key cifrado  
   └── Renombrar/cambiar extensión  
  
5. Cleanup  
   ├── Soltar nota de rescate en cada directorio  
   ├── Cambiar wallpaper  
   └── Eliminar rastros (logs, copias)
```

> **¿Por qué separar en tres componentes (builder/locker/decryptor) en lugar de un binario monolítico?** El diseño modular protege al atacante en capas. Si el locker es capturado por un investigador, no contiene la clave privada — solo la pública embebida. Si el builder es incautado, permite analizar muestras previas pero no da acceso a la infraestructura activa. El decryptor solo se entrega tras el pago, funcionando como mecanismo de custodia: la víctima no puede descifrar sin él, y el atacante puede generarlo a demanda para cualquier víctima sin exponer claves globales. Esta separación habilitó el modelo RaaS: el core team distribuye el builder a affiliates sin darles acceso a las claves maestras del C2. El riesgo de la arquitectura modular se materializó en septiembre 2022 cuando el builder de LockBit 3.0 fue leakeado por un affiliate disconforme — aparecieron docenas de "LockBit 3.0" copycats, pero sin las private keys del C2 los archivos que cifraban eran irrecuperables para todos, incluyendo el copycat.


## 1.4 El Esquema Criptográfico — Vista General

```
GENERACIÓN DE CLAVES (en builder):  
  Atacante genera par RSA/ECDH:  
    master\_privkey (atacante guarda en servidor C2)  
    master\_pubkey  (embebido en el binario del ransomware)  
  
CIFRADO (en locker, para cada archivo):  
  1. Generar AES-256 key aleatorio (file\_key)  
  2. Generar AES-256 IV aleatorio (file\_iv)  
  3. Cifrar contenido del archivo con AES-256-CBC/CTR usando file\_key+file\_iv  
  4. Cifrar file\_key con master\_pubkey (RSA-OAEP o ECDH)  
  5. Escribir al final del archivo cifrado:  
     \[encrypted\_content\]\[encrypted\_file\_key\]\[iv\]\[footer\_magic\]  
  
DESCIFRADO (el atacante puede descifrar):  
  1. Leer encrypted\_file\_key del footer  
  2. Descifrar con master\_privkey → file\_key  
  3. Descifrar contenido con file\_key+iv → original
```

### Por qué este esquema (y no solo RSA)

- RSA directo en archivo grande = lento (RSA solo cifra hasta ~245 bytes con RSA-2048)

- AES en archivo grande = rápido

- Solución híbrida: AES para datos (rápido), RSA para proteger la clave AES

> **¿Por qué cifrado híbrido y no solo RSA o solo AES?** RSA-2048 tiene un límite físico: con padding OAEP-SHA1 puede cifrar máximo ~214 bytes de datos en una operación. Un archivo de 1 GB requeriría millones de operaciones RSA secuenciales, tardando horas. AES por sí solo sería instantáneo pero crea un problema irresolvable de gestión de claves: si guardas la clave AES en el archivo, el investigador forense puede extraerla; si la mandas al C2 durante el cifrado, necesitas conectividad y dejas artefactos de red detectables. La solución híbrida elimina ambos problemas: AES cifra datos a velocidad de hardware (2-3 GB/s con AES-NI), y RSA/ECDH protege esa clave AES de 32 bytes en microsegundos por archivo. La clave protegida en el footer es criptográficamente inútil sin la private key del atacante, que nunca abandona el C2. Por eso el análisis forense post-incidente no puede descifrar archivos aunque tenga el binario completo del locker.

## 1.5 El Código Fuente: C vs Rust

El curso ofrece ambos. Comparación relevante para ti:

| Aspecto | C | Rust |
| - | - | - |
| Control bajo nivel | Total | Total (unsafe) |
| Seguridad de memoria | Manual (tu responsabilidad) | Garantizada por compilador |
| Interop con WinAPI | Directo (windows.h) | Via `windows` crate o bindgen |
| Rendimiento | Máximo | Comparable |
| Tamaño de binario | Pequeño | Mayor (stdlib estática) |
| Análisis en Ghidra | Familiar para ti | Más complejo (demangling) |
| RaaS reales | WannaCry, REvil | BlackCat/ALPHV |


### Setup C (MinGW en Linux para cross-compile Windows)

```
  
x86\_64-w64-mingw32-gcc -o ransomware.exe main.c -lws2\_32 -ladvapi32 -lcrypt32  
  
\# Con optimizaciones  
x86\_64-w64-mingw32-gcc -O2 -s -o ransomware.exe main.c \\  
  -lws2\_32 -ladvapi32 -lcrypt32 -lbcrypt
```

### Setup Rust para Windows targets

```
\# Instalar rustup  
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh  
  
\# Añadir target Windows  
rustup target add x86\_64-pc-windows-gnu  
  
\# Compilar  
cargo build --target x86\_64-pc-windows-gnu --release  
  
\# Cargo.toml básico para ransomware  
\[package\]  
name = "locker"  
version = "0.1.0"  
edition = "2021"  
  
\[dependencies\]  
windows = \{ version = "0.52", features = \[  
    "Win32\_Foundation",  
    "Win32\_System\_IO",  
    "Win32\_Storage\_FileSystem",  
    "Win32\_System\_Threading",  
    "Win32\_Security\_Cryptography",  
    "Win32\_System\_SystemServices",  
\] \}  
  
\[profile.release\]  
opt-level = 3  
strip = true  
lto = true  
codegen-units = 1  
panic = "abort"
```


## 1.6 Herramientas del Entorno de Análisis

### Para el desarrollo (tu máquina)

```
\# Compilador C (MinGW)  
x86\_64-w64-mingw32-gcc --version  
  
\# Rust  
rustup show  
cargo --version  
  
\# Dependencias de criptografía (C)  
\# Usaremos Windows CNG (Cryptography Next Generation) - ya viene con Windows  
\# Para cross-compile, también OpenSSL:  
sudo pacman -S mingw-w64-openssl  
  
\# Dependencias de criptografía (Rust)  
\# En Cargo.toml:  
\# aes = "0.8"  
\# chacha20poly1305 = "0.10"  
\# p256 = "0.13"  (ECDH)
```

### En la VM de Windows (para testing)

```
Process Monitor (ProcMon) - Sysinternals  
  → Ver exactamente qué archivos abre/modifica el ransomware  
  
Process Hacker / Task Manager  
  → Ver threads, handles, memoria  
  
x64dbg  
  → Debugging si algo falla  
  
Autoruns  
  → Ver si el ransomware añadió persistencia  
  
WinDirStat  
  → Ver archivos cifrados vs originales
```


## Resumen Módulo 01

Entendiste:

- Arquitectura completa de ransomware moderno

- Esquema criptográfico híbrido (RSA+AES o ECDH+ChaCha20)

- El flujo: builder → locker → decryptor

- Entorno de lab seguro

- C vs Rust para implementación

**Siguiente**: Módulo 02 — Algoritmos criptográficos (AES, ChaCha20, RSA, ECDH)

