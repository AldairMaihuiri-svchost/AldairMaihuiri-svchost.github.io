---
title: "Ransomware Red Teaming — Module 1: Introduction"
description: "How is ransomware built?"
author: Aldair Maihuiri
---
---

© 2026 Aldair Maihuiri. All rights reserved.
This document may be shared with attribution to the author. Full or partial reproduction without prior authorization is prohibited.

---
# Module 01 — Introduction to the Ransomware Course (Red Team)


## 1.1 What is Ransomware?

Ransomware = malware that:

1. **Enumerates** system/network files

2. **Encrypts** files with asymmetric+symmetric cryptography

3. **Deletes** OS backup copies

4. **Displays** a ransom note with payment instructions

### Real reference families (for analysis)

| Family | Year | Algorithm | Key Feature |
| - | - | - | - |
| WannaCry | 2017 | RSA-2048 + AES-128 | NSA EternalBlue exploit |
| REvil/Sodinokibi | 2019-2021 | Curve25519 + Salsa20 | RaaS, MMP (Multi-Master Pattern) |
| Conti | 2020-2022 | RSA + ChaCha20 | Multiple threads, very fast |
| LockBit 3.0 | 2022-2024 | ECDH + AES-CTR | Fastest on the market, 3,000 files/min |
| BlackCat/ALPHV | 2021-2024 | ECDH + ChaCha20 | Written in Rust |
| Akira | 2023-2026 | ECDH + ChaCha20-Poly1305 | Go/C++, Linux+Windows |


### Evolution 2020-2026

```
2020: Encrypt-and-exfiltrate → "double extortion"
2021: Triple extortion (DDoS + encrypt + leak)
2022: RaaS (Ransomware-as-a-Service) dominant
2023: Intermittent encryption (partial only → faster)
2024: Linux/ESXi targets (VMware VMDK)
2025: BYOD/cloud-aware (OneDrive sync encryption)
2026: AI-assisted target selection, supply chain ransomware
```

> **Why did ransomware evolve from simple encryption to triple extortion?** The original "encrypt-only" model failed against organizations with functional backups: if IT has a clean copy, they don't pay. Maze (November 2019) discovered that the reputational and regulatory damage of a data breach is independent of whether a backup exists — GDPR imposes fines of up to 4% of global revenue for PII exposure, whether the victim pays or not. Double extortion turns encryption into a secondary threat: exfiltration is the real leverage. Triple extortion adds direct pressure on customers, regulators, and employees because the victim cannot make the leak "disappear" even by restoring from backup. The extreme case: Cl0p/MOVEit (2023) deployed not a single locker — it only exfiltrated 2,000+ organizations and made ~$100M without writing a single encryption key.

## 1.2 Legal and Ethical Considerations

### Legal Framework

**IMPORTANT**: Developing, possessing, or using ransomware against systems without authorization is:

- **Spain**: Art. 264 bis CP — computer sabotage → up to 10 years

- **Mexico**: Art. 211 bis CP → unauthorized system access

- **USA**: CFAA (Computer Fraud and Abuse Act) → up to 10 years/charge

- **UK**: Computer Misuse Act 1990 → up to 10 years

### Legitimate Use of This Knowledge

This course is for:

- **Red teamers**

- **Malware analysts** for forensic analysis and detection

- **Defenders** to understand how attacks work and build better defenses

- **CTF/lab environments** — isolated virtual machines

### Lab Rules

```
ALWAYS:
✓ Use a network-isolated VM (no real network access)
✓ Snapshots before executing the ransomware
✓ Only test files you generated yourself
✓ Document everything for the red team report

NEVER:
✗ Execute on a real/production system
✗ Use against third parties without signed authorization
✗ Exfiltrate real data
✗ Connect C2 to real infrastructure without authorization
```

### Recommended Lab Environment

```
Host: Your OS
VM 1: Windows 10/11 ISOLATED
  - No network adapter (host-only or disconnected)
  - Snapshots per module
  - Test directory: C:\TestFiles\ with dummy files
VM 2: Windows Server (to test domain functions)

Software:
- VMware Workstation / VirtualBox
- Ghidra (for reverse analysis of the binaries you produce)
- x64dbg (debugging)
- Process Monitor (view file operations)
- Wireshark (verify no outbound traffic)
```


## 1.3 General Architecture of a Modern Ransomware

```
┌─────────────────────────────────────────────────────┐
│                    RANSOMWARE                       │
├──────────────┬──────────────┬───────────────────────┤
│   BUILDER    │    LOCKER    │      DECRYPTOR        │
│              │              │                       │
│ Configures:  │ - Enumerate  │ - Receives key        │
│ - RSA key    │   files      │   from attacker       │
│ - Extension  │ - Encrypt    │ - Decrypts files      │
│ - Note       │ - Delete VSS │ - Verifies hash       │
│ - Exclusions │ - Ransom note│                       │
└──────────────┴──────────────┴───────────────────────┘
```

### Locker Operation Flow

```
1. Initialization
   ├── Check if an instance is already running (mutex)
   ├── Load configuration (embedded in the binary)
   └── Generate ephemeral key pair (ECDH)

2. Preparation
   ├── Escalate privileges (if possible)
   ├── Disable recovery (VSS, System Restore)
   └── Terminate processes locking files (SQL, Office)

3. Enumeration
   ├── List drives (local + network)
   ├── Traverse directories recursively
   └── Filter by extension / exclusions

4. Encryption (parallel thread pool)
   ├── For each file:
   │   ├── Generate unique AES key/IV
   │   ├── Encrypt the file
   │   ├── Encrypt AES key with attacker's RSA/ECDH public key
   │   └── Write footer with encrypted AES key
   └── Rename/change extension

5. Cleanup
   ├── Drop ransom note in each directory
   ├── Change wallpaper
   └── Remove traces (logs, copies)
```

> **Why split into three components (builder/locker/decryptor) instead of a monolithic binary?** The modular design protects the attacker in layers. If the locker is captured by a researcher, it does not contain the private key — only the embedded public one. If the builder is seized, it allows analysis of previous samples but gives no access to the active infrastructure. The decryptor is only delivered after payment, functioning as an escrow mechanism: the victim cannot decrypt without it, and the attacker can generate it on demand for any victim without exposing global keys. This separation enabled the RaaS model: the core team distributes the builder to affiliates without giving them access to the C2 master keys. The risk of modular architecture materialized in September 2022 when the LockBit 3.0 builder was leaked by a disgruntled affiliate — dozens of "LockBit 3.0" copycats appeared, but without the C2 private keys the files they encrypted were unrecoverable for everyone, including the copycat.


## 1.4 The Cryptographic Scheme — Overview

```
KEY GENERATION (in builder):
  Attacker generates RSA/ECDH pair:
    master_privkey (attacker stores on C2 server)
    master_pubkey  (embedded in the ransomware binary)

ENCRYPTION (in locker, for each file):
  1. Generate random AES-256 key (file_key)
  2. Generate random AES-256 IV (file_iv)
  3. Encrypt file content with AES-256-CBC/CTR using file_key+file_iv
  4. Encrypt file_key with master_pubkey (RSA-OAEP or ECDH)
  5. Write at the end of the encrypted file:
     [encrypted_content][encrypted_file_key][iv][footer_magic]

DECRYPTION (the attacker can decrypt):
  1. Read encrypted_file_key from footer
  2. Decrypt with master_privkey → file_key
  3. Decrypt content with file_key+iv → original
```

### Why this scheme (and not just RSA)

- Direct RSA on large file = slow (RSA only encrypts up to ~245 bytes with RSA-2048)

- AES on large file = fast

- Hybrid solution: AES for data (fast), RSA to protect the AES key

> **Why hybrid encryption and not just RSA or just AES?** RSA-2048 has a physical limit: with OAEP-SHA1 padding it can encrypt at most ~214 bytes of data per operation. A 1 GB file would require millions of sequential RSA operations, taking hours. AES alone would be instantaneous but creates an irresolvable key management problem: if you store the AES key in the file, the forensic investigator can extract it; if you send it to the C2 during encryption, you need connectivity and leave detectable network artifacts. The hybrid solution eliminates both problems: AES encrypts data at hardware speed (2–3 GB/s with AES-NI), and RSA/ECDH protects that 32-byte AES key in microseconds per file. The key stored in the footer is cryptographically useless without the attacker's private key, which never leaves the C2. This is why post-incident forensic analysis cannot decrypt files even with the complete locker binary.

## 1.5 The Source Code: C vs Rust

The course covers both. Relevant comparison:

| Aspect | C | Rust |
| - | - | - |
| Low-level control | Total | Total (unsafe) |
| Memory safety | Manual (your responsibility) | Guaranteed by compiler |
| WinAPI interop | Direct (windows.h) | Via `windows` crate or bindgen |
| Performance | Maximum | Comparable |
| Binary size | Small | Larger (static stdlib) |
| Ghidra analysis | Familiar to you | More complex (demangling) |
| Real RaaS | WannaCry, REvil | BlackCat/ALPHV |


### C Setup (MinGW on Linux for Windows cross-compilation)

```bash
x86_64-w64-mingw32-gcc -o ransomware.exe main.c -lws2_32 -ladvapi32 -lcrypt32

# With optimizations
x86_64-w64-mingw32-gcc -O2 -s -o ransomware.exe main.c \
  -lws2_32 -ladvapi32 -lcrypt32 -lbcrypt
```

### Rust Setup for Windows Targets

```bash
# Install rustup
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Add Windows target
rustup target add x86_64-pc-windows-gnu

# Compile
cargo build --target x86_64-pc-windows-gnu --release

# Basic Cargo.toml for ransomware
[package]
name = "locker"
version = "0.1.0"
edition = "2021"

[dependencies]
windows = { version = "0.52", features = [
    "Win32_Foundation",
    "Win32_System_IO",
    "Win32_Storage_FileSystem",
    "Win32_System_Threading",
    "Win32_Security_Cryptography",
    "Win32_System_SystemServices",
] }

[profile.release]
opt-level = 3
strip = true
lto = true
codegen-units = 1
panic = "abort"
```


## 1.6 Analysis Environment Tools

### For development (your machine)

```bash
# C compiler (MinGW)
x86_64-w64-mingw32-gcc --version

# Rust
rustup show
cargo --version

# Cryptography dependencies (C)
# We'll use Windows CNG (Cryptography Next Generation) - ships with Windows
# For cross-compilation, also OpenSSL:
sudo pacman -S mingw-w64-openssl

# Cryptography dependencies (Rust)
# In Cargo.toml:
# aes = "0.8"
# chacha20poly1305 = "0.10"
# p256 = "0.13"  (ECDH)
```

### In the Windows VM (for testing)

```
Process Monitor (ProcMon) - Sysinternals
  → See exactly which files the ransomware opens/modifies

Process Hacker / Task Manager
  → View threads, handles, memory

x64dbg
  → Debugging if something fails

Autoruns
  → See if the ransomware added persistence

WinDirStat
  → View encrypted vs original files
```


## Module 01 Summary

You now understand:

- Complete architecture of modern ransomware

- Hybrid cryptographic scheme (RSA+AES or ECDH+ChaCha20)

- The flow: builder → locker → decryptor

- Secure lab environment

- C vs Rust for implementation

Xtra:
- Why is hybrid encryption (AES + RSA/ECDH) superior to using solely RSA or solely AES in ransomware? What specific problem does each algorithm solve, and what would happen if you were to remove one of them?

- In the locker flow, why is the file_key encrypted with the master_pubkey first and not the other way around? What security implications would reversing this order have?

- Identify differences between WannaCry (2017), LockBit 3.0 (2022), and Jigsaw (2016) in terms of:

Propagation vector
Cryptographic algorithms used
Business model (RaaS vs. non-RaaS)
Encryption speed

**Next**: Module 02 — Cryptographic algorithms (AES, ChaCha20, RSA, ECDH)

---

© 2026 Aldair Maihuiri. All rights reserved.
Sharing with attribution is welcome. Unauthorized reproduction is prohibited.
