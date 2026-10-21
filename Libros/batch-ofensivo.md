---
title: "Batch Ofensivo — Aldair Maihuiri"
description: "Libro gratuito de scripting Batch para Windows en un entorno de análisis de malware y Red Team. Bucles, sistema de archivos, escritura binaria, reconocimiento y persistencia desde cero."
author: "Aldair Maihuiri"
---

# Batch Ofensivo

## Scripts de Windows para Red Team desde Cero

**Aldair Maihuiri (Sv-chost)** · Gratuito · 2026  
**Edición ampliada · 116 páginas**

Introducción práctica al scripting Batch en Windows, con ejemplos situados en un entorno de análisis de malware y Red Team. No se requiere experiencia previa en scripting.

El libro avanza desde los primeros comandos hasta tres proyectos de laboratorio: un recolector de reconocimiento local, un dropper mínimo con persistencia mediante una Run Key y un file watcher por sondeo.

Esta edición incorpora bucles por cantidad, por condición y de duración abierta, además de un laboratorio de escritura binaria con sobrescritura parcial y total de archivos sintéticos.

[**Descargar el libro en PDF**](Batch_Ofensivo.pdf)

---

## Contenido

### Prefacio

Cómo trabajar con los ejemplos, preparar el laboratorio mínimo y comprobar los resultados de cada práctica.

### Parte I — Entender el Terreno

- **Capítulo 1: Por qué Batch importa en Red Team**  
  Herramientas presentes en Windows, funcionamiento de cmd.exe, diferencias entre .bat y .cmd, primer script, ejecución, códigos de salida y comportamiento de la ventana de consola.

- **Capítulo 2: La gramática del Batch**  
  SET, variables de entorno, argumentos, ubicación del script, IF, comprobación de archivos y directorios, FOR, expansión de variables, etiquetas, subrutinas y redirección de errores. Bucles numéricos con FOR /L, creación de veinte carpetas con nombres seudoaleatorios, comprobación de colisiones, repetición por condición, bucles continuos, parada manual con Ctrl+C, señales mediante archivos, esperas con TIMEOUT, bucles anidados y control de errores.

### Parte II — Dominando el Sistema de Archivos

- **Capítulo 3: Crear y escribir archivos**  
  Redirección con > y >>, escritura de varias líneas, comprobación de errores, archivos vacíos, caracteres de control, fecha y hora, captura de resultados y registros de actividad. Introducción a bytes, hexadecimal, posiciones y truncamiento. Laboratorio con una muestra sintética de 4096 bytes: lectura de regiones, sobrescritura de los primeros 12 y últimos 16 bytes, sustitución total con ceros, patrones fijos o bytes seudoaleatorios, comparación de contenido y hashes SHA256. Diferencias entre corrupción de archivos y borrado seguro. Las prácticas binarias utilizan Windows PowerShell 5.1 y funciones de .NET, invocadas desde CMD.

- **Capítulo 4: Leer y buscar dentro de archivos**  
  TYPE, MORE, FINDSTR y FOR /F; búsqueda literal y recursiva, lectura por líneas, separación de campos y extracción de indicadores.

- **Capítulo 5: Mover, copiar, renombrar y borrar**  
  COPY, MOVE, REN, DEL, ERASE, XCOPY y ROBOCOPY; copias de trabajo, cambios de extensión, traslado de muestras y conservación de su procedencia.

- **Capítulo 6: Navegación y directorios**  
  CD, PUSHD, POPD, MD, DIR, FOR /R y RD; rutas absolutas y relativas, recorridos, inventarios y diagnósticos separados.

### Parte III — Ver el Sistema

- **Capítulo 7: Reconocimiento con Batch**  
  WHOAMI, SYSTEMINFO, NET USER, NET LOCALGROUP, IPCONFIG, ARP, NETSTAT, TASKLIST, SC QUERY y REG QUERY. Construcción de un recolector local con un informe independiente por ejecución.

### Parte IV — Persistencia

- **Capítulo 8: Sobrevivir al reinicio**  
  Carpeta Startup, Run Keys, diferencias entre HKCU y HKLM y tareas programadas con SCHTASKS. Pruebas por intervalo, inicio de sesión y arranque del sistema; comprobación y retirada de los mecanismos del laboratorio.

### Parte V — Proyectos Integradores

- **Capítulo 9: Construyendo tus primeras herramientas**  
  Tres proyectos que reúnen lo aprendido: reconocimiento automático con salida en archivos y códigos de resultado; dropper de laboratorio con una Run Key y generación de un marcador de texto; y file watcher por sondeo, con registro de nombres nuevos, señal de parada y duración limitada.

### Epílogo

**Cuándo Batch deja de ser suficiente**: límites del intérprete y siguientes pasos hacia otras herramientas.

### Apéndices

- **Apéndice A:** Referencia rápida de comandos.
- **Apéndice B:** Variables de entorno de Windows.
- **Apéndice C:** Recursos para continuar.

El aviso completo de derechos de autor y condiciones de distribución se encuentra al final del libro.

---

## Para quién es

Para quienes conocen Windows a nivel usuario y quieren aprender a escribir sus primeros scripts en un contexto de análisis de malware y Red Team.

No necesitas conocimientos previos de Batch, PowerShell o Python. El libro explica las funciones de PowerShell utilizadas en el laboratorio de escritura binaria.

Los ejemplos emplean nombres y rutas propios de un laboratorio: `samples\`, `staging\`, `reports\`, `sandbox\loop_lab\`, `sandbox\byte_lab\`, `recon_local.bat`, `dropper_lab.bat` y `file_watcher.bat`.

Las prácticas incluyen instrucciones para observar los resultados, reconocer errores y detener los bucles.

---

## Derechos de autor y distribución

© 2026 Aldair Maihuiri. Derechos reservados, salvo las autorizaciones expresadas en el libro.

Puedes descargar, leer, imprimir para uso personal y compartir gratuitamente el libro completo, siempre que conserves íntegro su contenido, mantengas el aviso de derechos y reconozcas al autor.

La venta, la explotación comercial y la distribución de traducciones o versiones modificadas requieren autorización previa y por escrito del titular, salvo las excepciones previstas en la legislación aplicable.

Los ejemplos de código pueden copiarse, ejecutarse y adaptarse para aprendizaje, docencia y experimentación en sistemas propios o expresamente autorizados.

Consulta las condiciones completas en la última página del PDF.

---

[← Volver al índice](../)
