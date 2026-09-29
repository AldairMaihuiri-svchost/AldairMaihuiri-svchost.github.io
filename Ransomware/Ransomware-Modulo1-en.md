---
title: "Ransomware Red Teaming — Module 1: Introduction"
description: "Core concepts, documented cases, general architecture, and the course analysis environment."
author: Aldair Maihuiri
---

# Module 01 — Introduction to the ransomware course (Red Team)

This course examines the architecture of real ransomware families, the controlled reproduction of selected behaviors using test data, and their analysis for detection and mitigation. The component names in this chapter describe observable functions; ransomware families do not all use the same architecture or cryptographic scheme.

## 1.1 What is ransomware?

Ransomware is malicious software used to demand payment by disrupting access to data or systems. File encryption is a common way to produce this effect. Related extortion campaigns may also threaten to publish stolen data, whether or not encryption took place in the incident under study. It is useful to distinguish the **program** that blocks access to data, the **operation** that compromises an organization, and the **extortion** that exploits the access gained. [CISA: Ransomware Guide](https://www.cisa.gov/stopransomware/ransomware-guide).

File enumeration, information theft, interference with recovery, and ransom notes are all possible behaviors. None of them, on its own, describes every sample. There is no single encryption algorithm used by all ransomware, either.

### Documented ransomware families

| Family or variant | Time reference | Documented characteristic | Source |
| --- | --- | --- | --- |
| WannaCry / WannaCrypt | 2017 outbreak | Spread through a previously patched SMB vulnerability | [Microsoft Security](https://www.microsoft.com/en-us/security/blog/2017/05/12/wannacrypt-ransomware-worm-targets-out-of-date-systems/) |
| REvil / Sodinokibi | 2020 analysis | RaaS operation; the samples examined used Curve25519, Salsa20, and other components | [Intel 471](https://www.intel471.com/blog/revil-ransomware-as-a-service-an-analysis-of-a-ransomware-affiliate-operation) |
| Conti | Variants analyzed from 2020 onward | Changes in the encryption mechanism across samples and use of RSA to protect key material | [SentinelLabs](https://www.sentinelone.com/labs/conti-unpacked-understanding-ransomware-development-as-a-response-to-detection/) |
| LockBit 3.0 | Emerged in 2022 | Variant associated with a RaaS operation and its affiliates | [CISA and partners](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-165a) |
| BlackCat / ALPHV | Identified from 2021 onward | Rust based family offered through RaaS | [MITRE ATT&CK](https://attack.mitre.org/software/S1068/) |
| Akira | Advisory updated in 2025 | The samples described use a hybrid scheme combining ChaCha20 and RSA; variants may differ | [FBI and partners, joint advisory](https://www.fbi.gov/file-repository/cyber-alerts/stopransomware-akira-ransomware.pdf) |
| Jigsaw | Documented in 2016 | Countdown, periodic deletion of encrypted files, and a restart related threat in the variants studied | [ESET, 2016 analysis](https://www.welivesecurity.com/la-es/2016/04/15/jigsaw-ransomware-mas-agresivo-nuevas-capacidades/) |
| AvosLocker | Identified in 2021; advisory updated in 2023 | RaaS operation with incidents affecting Windows, Linux, and VMware ESXi environments | [FBI and CISA, AA23-284A](https://www.cisa.gov/sites/default/files/2023-10/aa23-284a-joint-csa-stopransomware-avoslocker-ransomware-update.pdf) |
| EvilQuest / ThiefQuest | Analyzed from 2020 onward | macOS malware combining encryption, data exfiltration, and spyware capabilities | [SentinelLabs research](https://www.sentinelone.com/blog/evilquest-a-new-macos-malware-rolls-ransomware-spyware-and-data-theft-into-one/) |

Depending on the row, the time reference marks an outbreak, an emergence, or an analysis date; it **does not** establish the family's entire period of activity. Likewise, a description of one sample should not automatically be applied to every variant in that family.

### Three cases for studying impact and response

#### Jigsaw: a countdown designed to control the decision

Jigsaw deserves attention for more than its encryption. Analyses published in 2016 describe a window featuring imagery from *Saw*, a visible timer, and the deletion of encrypted files at intervals if payment is not made. ESET also observed a threat associated with stopping the process or restarting the computer. Together, these features make every minute seem costly and frame ordinary containment actions as dangerous. These behaviors were documented in the variants examined; they are not universal rules for everything called Jigsaw. [ESET](https://www.welivesecurity.com/la-es/2016/04/15/jigsaw-ransomware-mas-agresivo-nuevas-capacidades/) · [Check Point Research](https://blog.checkpoint.com/research/jigsaw-ransomware-decryption/).

The coercion works on three levels. **Urgency:** the timer narrows the time a person believes they have to verify what happened. **Progressive loss:** the prospect of files disappearing before the assessment is complete turns waiting into a source of distress. **Fear of intervening:** the warning about restarting seeks to discourage the victim from asking for help or taking containment measures. The horror imagery reinforces the threat, but the heart of the case is the relationship among time, loss, and decisions made under pressure. This interpretation describes the message's apparent intent; it does not, by itself, measure how each victim felt.

For an individual, the threatened files may include photographs, work, or documents whose value cannot be expressed in money. In a company, the same pressure can prompt decisions before backups, the incident's scope, and service continuity have been checked. The response team must work while business leaders and affected people seek answers that are not yet available. Assessing the actual damage in a particular case requires evidence; the purpose here is to explain **why** the interface and its threats seek to influence human behavior. A countdown on a screen does not prove that an attacker can carry out every claim.

Technology changes: a later incident may apply pressure through threatened data publication, service disruption, or contact with third parties instead of deleting files every hour. What persists is the attempt to shift control of the decision to the attacker through urgency, uncertainty, and fear of greater loss. These forms of pressure can accumulate. Defensive analysis must therefore separate the verifiable technical state from claims in the ransom note, preserve evidence, and coordinate the response before treating a threat as an established fact. Recovery tools for **some** Jigsaw variants also illustrate why the specific sample should be checked. [Check Point Research](https://blog.checkpoint.com/research/jigsaw-ransomware-decryption/) · [CISA, response guide](https://www.cisa.gov/stopransomware/ransomware-guide).

#### AvosLocker: an operation larger than the executable

AvosLocker illustrates the difference between a **malware family** and an **affiliate based operation**. The joint FBI and CISA advisory, updated on October 11, 2023 with findings from investigations conducted as recently as May of that year, provides indicators, tactics, techniques, and detection methods. It describes compromises in critical infrastructure sectors and in Windows, Linux, and VMware ESXi environments. This scope matters because an incident can affect both endpoints and the infrastructure supporting many virtual machines. [FBI and CISA, AA23-284A](https://www.cisa.gov/sites/default/files/2023-10/aa23-284a-joint-csa-stopransomware-avoslocker-ransomware-update.pdf).

In a Linux sample studied by VMware, the component targeting ESXi shut down virtual machines before encryption and used Salsa20 and RSA. These are details of **that variant**, not a universal AvosLocker blueprint. The case teaches us to correlate signs of access, tool use, hypervisor impact, and extortion instead of reducing the entire investigation to identifying an encryptor. For defenders, the updated advisory is a dated starting point: its specific indicators should be compared against evidence from the environment, not assumed to apply to every future incident. [VMware Threat Research](https://blogs.vmware.com/security/2022/09/esxi-targeting-ransomware-the-threats-that-are-after-your-virtual-machines-part-1.html).

#### EvilQuest: when the ransom demand does not explain all the harm

EvilQuest, also called ThiefQuest, shows why a family name does not capture all of its capabilities. Researchers observed file encryption, searches for and exfiltration of data, and keylogging capabilities on macOS. The alert window could be dismissed while the computer remained in use: regaining access to a file would not rule out exposure of data or credentials. [SentinelOne, capability analysis](https://www.sentinelone.com/blog/evilquest-a-new-macos-malware-rolls-ransomware-spyware-and-data-theft-into-one/).

Its encryption routine is also useful for examining the limits of an implementation. SentinelLabs found a custom construction, partly associated with RC2 and lacking the public key scheme one might expect in many ransomware families; it released a decryptor for the samples investigated. That route to recovery does not remove the need to investigate spying and possible data extraction. The case makes two points: **encryptors do not all share one architecture, and reversing encryption does not automatically resolve the incident**. [SentinelLabs, encryption routine analysis](https://www.sentinelone.com/labs/breaking-evilquest-reversing-a-custom-macos-ransomware-file-encryption-routine/).

### How extortion evolved

A useful timeline distinguishes **dated observations** from **dates of invention**. The expansion of RaaS, data theft, partial encryption, and attacks on virtualization environments overlapped; they did not all begin in consecutive years. For concrete references, CISA documented BlackMatter's impact on ESXi machines in 2021, while its 2023 Cl0p/MOVEit advisory describes the exploitation of a vulnerability to steal data from MOVEit Transfer. [CISA: BlackMatter](https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-291a) · [CISA: Cl0p/MOVEit](https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-158a).

**Why the distinction between encryption and data exposure matters:** a backup may allow data to be restored, but it cannot undo the exposure of information already taken. Nor does every data leak automatically result in a fine. In the European Union, Article 83 of the GDPR sets maximum amounts and criteria for certain infringements; the competent authority assesses each case. [GDPR, Article 83](https://eur-lex.europa.eu/eli/reg/2016/679/oj/eng).

## 1.2 Legal and ethical considerations

### Legal framework and authorization

The legal classification of an act depends on the facts, the jurisdiction, its purpose, and whether it was authorized. There is no single penalty that applies to every case of “developing, possessing, or using” a tool. In Peru, [Law No. 30096 and its amendments](https://www.gob.pe/institucion/congreso-de-la-republica/normas-legales/239569-30096) address offenses affecting computer data and systems. For a professional exercise, the authorized scope, machines, data, duration, and conditions for ending the work should be set out in writing.

For international comparison, [Articles 264 and following of the Spanish Criminal Code](https://www.boe.es/buscar/act.php?id=BOE-A-1995-25444) distinguish damage to data, obstruction of systems, and related conduct; the UK's [Computer Misuse Act](https://www.legislation.gov.uk/ukpga/1990/18/contents) contains different offenses. Penalties depend on the applicable provision and facts. These texts provide a starting point for reading the legal framework, not a substitute for assessing an individual case.

### How the course uses this knowledge

- **Red Team:** understand components and document authorized tests.
- **Malware analysis:** observe samples, extract indicators, and explain behavior.
- **Defense:** compare observed signals with detection and recovery controls.
- **Academic laboratory:** use machines and data prepared for the exercise.

### Laboratory rules

| Aspect | Working condition |
| --- | --- |
| Data | Use only test files created for the course and keep verifiable originals |
| Scope | Identify the VMs and folders included in the exercise in writing before running it |
| Network | State whether a VM is disconnected or connected to a virtual network; verify actual connectivity |
| Recovery | Have a snapshot and independent copies of the test data |
| Evidence | Record the sample, version, time, results, and limits of the observation |

**A `host-only` network is not the same as disconnecting the adapter.** It may allow communication with the host and with other VMs on that network. When an exercise requires two VMs to communicate, document that topology and check which systems can reach one another. A snapshot helps restore a VM, but does not replace a copy of the original files.

### Analysis environment

```text
Host computer: work system and copies of the test data
Primary VM: a currently supported Windows version for present-day exercises
Additional VM: only when the exercise requires observing another system
Lab folder: data created specifically for each exercise
Tools: process monitor, debugger, and captures as required by the objective
```

Windows 10 reached the end of general support on October 14, 2025. It may still serve as a legacy analysis target when an exercise calls for it, subject to appropriate isolation. [Microsoft: Windows 10 release information](https://learn.microsoft.com/en-us/windows/release-health/release-information).

## 1.3 General architecture

Three functions can be distinguished in some families. They may be implemented as separate programs or arranged differently; the following model helps identify responsibilities when analyzing a sample.

| Function | Question for the analyst |
| --- | --- |
| **Builder** or configuration | Which parameters were incorporated into the sample under examination? |
| **Impact component** or *locker* | Which resources does it observe or modify during execution? |
| **Recovery tool** or *decryptor* | Which key material and metadata does it need to reverse the effect? |

The full operation may include initial access, execution, data selection, impact, and extortion; these activities need not be contained in one binary. Nor can the relationship among a group, a developer, and an affiliate be inferred from three component names. An investigation must separate what **the sample did** from what **is attributed to a campaign**.

The course documentation follows this division: Module 2 covers algorithms; Module 3 examines key generation and lifecycle; and Module 4 addresses input enumeration. Later modules consider metadata formats, reconstruction, and detection signals. This introduction therefore does not assume that every family generates an ephemeral key pair at startup or stores the same information in every file.

> **What can be inferred from a captured binary:** the presence of a public key does not mean its corresponding private key is available in the binary. Nor does it prove, on its own, that recovery is impossible: the result depends on the implementation, material exposed during execution, and other recovery sources. In 2024, authorities obtained keys from seized LockBit infrastructure to assist victims. [U.S. Department of Justice](https://www.justice.gov/archives/opa/pr/us-and-uk-disrupt-lockbit-ransomware-variant).

## 1.4 Cryptographic schemes: an overview

A hybrid scheme combines a mechanism suited to processing data with another used to establish or protect key material. This course introduces **two conceptual approaches**:

| Approach | Role of the asymmetric mechanism | Relationship to the working key |
| --- | --- | --- |
| RSA-OAEP | Encrypt a short value using a public key | The holder of the corresponding private key can recover it, according to the defined protocol |
| ECDH + KDF | Establish a shared secret between two key pairs | A KDF derives working key material from that agreement and its parameters |

ECDH does **not directly encrypt** a file key. Module 3 examines ephemeral ECDH per file and ECDH per session with per-file derivation separately. In either case, the analysis must identify which values are secret, which are public, and which parameters are needed to reproduce the derivation. The final format of this metadata belongs in the module on file footers.

RSA is not, on its own, an appropriate mode for processing a large file, either. RFC 8017 sets the RSAES-OAEP limit at `mLen ≤ k − 2hLen − 2`; with RSA-2048 (`k = 256` bytes) and SHA-256 (`hLen = 32` bytes), the maximum is **190 bytes per operation**. This figure depends on the scheme and hash and should not be confused with limits for other padding methods. [RFC 8017, Section 7.1.1](https://www.rfc-editor.org/rfc/rfc8017.html#section-7.1.1).

Data processing performance depends on the hardware, file size, mode, and library; a GB/s figure means little without its measurement method. AES-CBC, AES-CTR, and ChaCha20-Poly1305 also have different rules for IVs, nonces, integrity, and authentication. Module 2 covers those algorithms; Module 3 separates keys, agreements, and derivation parameters.

## 1.5 C and Rust in this course

Both languages can be used to study system interfaces and cryptographic libraries. The choice affects memory management, dependencies, and calls into external code, but it **does not change the mathematical properties** of RSA, ECDH, or HKDF.

| Aspect | C | Rust |
| --- | --- | --- |
| Memory management | Requires explicit discipline from the programmer | Safe code provides guarantees; `unsafe` and FFI still require review |
| Windows interoperability | Uses platform headers and libraries | Uses bindings or libraries exposing Windows APIs |
| Dependencies | Chosen compiler, headers, and libraries | Project toolchain and declared dependencies |
| Performance and size | Depend on implementation and compiler settings | Also depend on implementation and compiler settings |
| Binary analysis | Affected by compiler and optimizations | Also affected by compiler and optimizations |

For this introductory module, checking which tools are installed is enough. Build commands, dependency versions, and complete examples will accompany the exercises that use them, with an operating system and test project specified.

```sh
rustc --version
cargo --version
x86_64-w64-mingw32-gcc --version
```

The last command applies only if that cross compilation toolchain was selected. It is not required on every computer and does not install dependencies.

## 1.6 Tools for the analysis environment

| Tool | Use in a documented exercise |
| --- | --- |
| Process Monitor (ProcMon) | Observe process, file, and registry operations |
| Task Manager or another process tool | Inspect visible processes, threads, and resource use |
| x64dbg and Ghidra | Analyze a lab binary dynamically and statically |
| Wireshark | Observe virtual network traffic when the exercise calls for it |
| Autoruns | Examine automatic start points when present in the case |

A tool reports what it **observed under a particular configuration**. No traffic in one capture does not prove that a family never uses the network; the absence of a persistence artifact does not establish that all its variants lack persistence. The sample, environment, and observation window are part of the result.

## Module 01 summary

- Ransomware, the intrusion operation, and the related extortion are connected but distinct concepts.
- Families change across variants; a technical comparison should identify its source and scope.
- Jigsaw shows how threatened, escalating loss and a countdown can pressure a victim; the human pattern recurs in other forms of extortion.
- AvosLocker illustrates the reach of an affiliate operation and its impact on virtualized environments; EvilQuest requires investigation of data theft and spying even when encrypted files can be recovered.
- Symmetric encryption processes data; RSA-OAEP and ECDH + KDF play different roles with respect to key material.
- Configuration, impact, and recovery functions help organize analysis without imposing a universal architecture.
- An exercise needs known inputs, authorized scope, an explicit network topology, and reproducible evidence.

Xtra:

- Why is hybrid encryption (AES + RSA/ECDH) preferable to using RSA alone or AES alone in ransomware? What specific problem does each algorithm solve, and what would happen if either one were removed?
- In the locker's workflow, why is `file_key` encrypted with `master_pubkey` first rather than the other way around? What security implications would reversing their roles have?
- Identify differences among WannaCry (2017), LockBit 3.0 (2022), and Jigsaw (2016) in terms of:
  - Propagation vector
  - Cryptographic algorithms used
  - Business model (RaaS or not?)
  - Encryption speed

**Next**: Module 02 — Cryptographic Algorithms (AES, ChaCha20, RSA, ECDH)

---

© 2026 Aldair Maihuiri. All rights reserved. Sharing with attribution to the author is permitted. Reproduction without prior authorization is prohibited.
