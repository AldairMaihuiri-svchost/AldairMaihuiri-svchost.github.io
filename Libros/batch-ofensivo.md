---
title: "Batch Ofensivo — Aldair Maihuiri"
description: "Libro gratuito de scripting Batch 
ofensivo para Windows. Sistema de archivos, 
reconocimiento y persistencia desde cero."
author: Aldair Maihuiri
---

# Batch Ofensivo
## Scripts de Windows para Red Team desde Cero

**Aldair Maihuiri (Sv-chost)** · Gratuito · 2025

Introducción práctica al scripting Batch ofensivo 
en Windows. No se requiere experiencia previa 
en scripting. Al terminar habrás construido tres 
herramientas funcionales: un script de reconocimiento 
automático, un dropper mínimo con persistencia, 
y un file watcher.

[**Descargar PDF**](Batch_Ofensivo.pdf)

---

## Contenido

**Parte I — El Terreno**
- Capítulo 1: Por qué Batch importa en red team —
  Living off the Land, cmd.exe, primer script,
  ocultar ventana de consola
- Capítulo 2: La gramática del Batch — variables,
  variables de entorno, argumentos posicionales,
  condicionales, bucles, saltos, silenciar salida

**Parte II — Sistema de Archivos**
- Capítulo 3: Crear y escribir archivos —
  operadores de redirección, sobreescribir
  sin confirmación, archivos de log con timestamp
- Capítulo 4: Leer y buscar — TYPE, FINDSTR,
  FOR /F, parseo línea a línea
- Capítulo 5: Mover, copiar, renombrar y borrar —
  COPY /Y, MOVE, REN, DEL con flags,
  XCOPY, ROBOCOPY
- Capítulo 6: Navegación y directorios —
  CD, MD, RD, DIR con flags, búsqueda recursiva

**Parte III — Reconocimiento**
- Capítulo 7: Reconocimiento con Batch —
  WHOAMI /ALL, SYSTEMINFO, NET USER,
  NET LOCALGROUP, IPCONFIG, ARP, NETSTAT,
  TASKLIST, SC QUERY, REG QUERY

**Parte IV — Persistencia**
- Capítulo 8: Sobrevivir al reinicio —
  carpeta Startup, Run Keys con REG ADD
  (HKCU vs HKLM), SCHTASKS con triggers
  ONSTART, ONLOGON e intervalo

**Parte V — Proyectos**
- Capítulo 9: Tres herramientas completas —
  recon automático con salida en archivo,
  dropper mínimo con persistencia vía Run Key,
  file watcher en bucle

---

## Para quién es

Alguien que conoce Windows a nivel usuario y nunca 
ha escrito un script. No está dirigido a personas 
que ya conocen PowerShell o Python.

El libro no usa nombres de archivo genéricos ni 
ejemplos de contexto empresarial. Todas las rutas, 
variables y nombres de archivo reflejan un entorno 
real de análisis de malware y red team:
`samples\`, `payloads\`, `dropper.bat`,
`recon_2025-01-14.txt`, `%APPDATA%\svchost\`.

---

## Licencia

Libre para descargar y compartir sin modificación 
y sin fines comerciales.

© 2025 Gino Aldair Maihuiri Romero

---

[← Volver al índice](../)
