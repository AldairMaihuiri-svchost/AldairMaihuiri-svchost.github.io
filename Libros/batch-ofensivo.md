---
title: "Batch Ofensivo — Aldair Maihuiri"
description: "Free book on offensive Batch scripting 
for Windows red team. File system, reconnaissance, 
and persistence from scratch."
author: Aldair Maihuiri
---

# Batch Ofensivo
## Scripts de Windows para Red Team desde Cero

**Aldair Maihuiri (Sv-chost)** · Free · 2025

A practical introduction to offensive Batch scripting 
on Windows. No prior scripting experience required. 
By the end, you will have built three working tools: 
an automated recon script, a minimal dropper with 
persistence, and a file watcher.

Written in Spanish. Intended for beginners entering 
red team development.

[**Download PDF**](Batch_Ofensivo.pdf)

---

## Contents

**Part I — The Environment**
- Chapter 1: Why Batch matters in red team — 
  Living off the Land, cmd.exe, first script
- Chapter 2: Batch grammar — variables, 
  environment vars, conditionals, loops, 
  flow control, silencing output

**Part II — File System**
- Chapter 3: Creating and writing files — 
  redirection operators, overwrite without prompt
- Chapter 4: Reading and searching — 
  TYPE, FINDSTR, FOR /F
- Chapter 5: Moving, copying, renaming, 
  deleting — COPY /Y, MOVE, REN, DEL, ROBOCOPY
- Chapter 6: Navigation and directories — 
  CD, MD, RD, DIR with flags, recursive search

**Part III — Reconnaissance**
- Chapter 7: Recon with Batch — WHOAMI, 
  SYSTEMINFO, NET USER, IPCONFIG, NETSTAT, 
  TASKLIST, REG QUERY

**Part IV — Persistence**
- Chapter 8: Surviving reboot — Startup folder, 
  Run Keys via REG ADD (HKCU vs HKLM), 
  SCHTASKS (ONSTART, ONLOGON, interval)

**Part V — Projects**
- Chapter 9: Three complete tools —
  automated recon output, minimal dropper 
  with persistence, file watcher loop

---

## Who this is for

Someone who knows Windows at user level and has 
never written a script. Not for people who already 
know PowerShell or Python.

The book does not use generic filenames or 
business-context examples. All paths, variables, 
and file names reflect a real malware analysis 
and red team environment:
`samples\`, `payloads\`, `dropper.bat`, 
`recon_2025-01-14.txt`, `%APPDATA%\svchost\`.

---

## Series

This is the first book in a planned series on 
offensive Windows development.

| # | Title | Status |
|---|---|---|
| 1 | Batch Ofensivo | Free — available now |
| 2 | PowerShell Ofensivo | In progress |
| 3 | El Arte de la Ofuscación | In progress |
| 4 | Desarrollo Ofensivo en C | Planned |

---

## License

Free to download and share without modification 
and for non-commercial use.

© 2025 Gino Aldair Maihuiri Romero

---

[← Back to index](../)
