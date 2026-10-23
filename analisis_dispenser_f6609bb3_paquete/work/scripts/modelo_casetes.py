#!/usr/bin/env python3
"""Comprobación estática con entradas sintéticas; sin DLL, archivos ni hardware.

Reproduce las decisiones de 00401acf, 00401bbf y 00401fe9 sobre
valores decimales pequeños. No reproduce el comportamiento de _atol
ante desbordamiento, ni el contrato de ninguna biblioteca externa.
"""
from dataclasses import dataclass
import re

MASK32 = (1 << 32) - 1


def parsear(texto: str) -> list[tuple[str, str] | None]:
    """Tabla de 128 posiciones: un tramo inválido también consume posición."""
    texto = texto.split("\0", 1)[0]
    tabla: list[tuple[str, str] | None] = []
    pos = 0
    while pos < len(texto) and texto[pos] != ";" and len(tabla) < 128:
        if texto[pos] in ", \t\r\n":
            pos += 1
            continue
        resto = texto[pos:]
        limites = [i for c in ",;" if (i := resto.find(c)) >= 0]
        longitud = min(limites, default=len(resto))
        if longitud < 1:
            pos += 1
            continue
        igual = resto.find("=")
        if igual < 0:
            igual = len(resto)
        largo_valor = longitud - igual - 1
        entrada = None
        if 0 < igual < longitud - 1 and igual < 32 and largo_valor < 32:
            entrada = (resto[:igual], resto[igual + 1:longitud])
        tabla.append(entrada)
        pos += longitud
    return tabla + [None] * (128 - len(tabla))


def buscar(tabla: list, nombre: str) -> str | None:
    for entrada in tabla:
        if entrada is not None and entrada[0] == nombre:
            return entrada[1]
    return None


def decimal_acotado(texto: str) -> int:
    """Subconjunto decimal definido usado por los ejemplos sintéticos."""
    match = re.match(r"^[\t\n\v\f\r ]*([+-]?\d+)", texto)
    valor = int(match.group(1)) if match else 0
    if not -(1 << 31) <= valor < (1 << 31):
        raise ValueError("El caso excede el rango de esta comprobación")
    return valor


@dataclass(frozen=True)
class Seleccion:
    casete: int
    disponibilidad: int | None
    puntuaciones: tuple[int, ...]


def seleccionar(texto: str, maximo: int) -> Seleccion:
    tabla = parsear(texto)
    puntuaciones = [0] * 9
    disponibles = [0] * 9
    for n in range(1, 10):
        if buscar(tabla, f"{n}STA") != "R":
            continue
        valor = buscar(tabla, f"{n}VAL")
        cantidad = buscar(tabla, f"{n}ACT")
        if valor is None or cantidad is None:
            continue
        val32 = decimal_acotado(valor) & MASK32
        act32 = decimal_acotado(cantidad) & MASK32
        puntuaciones[n - 1] = (min(maximo & MASK32, act32) * val32) & MASK32
        disponibles[n - 1] = act32
    mejor = -1
    puntuacion_mejor = 0
    for indice, puntuacion in enumerate(puntuaciones):
        if puntuacion > puntuacion_mejor:
            mejor = indice
            puntuacion_mejor = puntuacion
    if mejor < 0:
        return Seleccion(-1, None, tuple(puntuaciones))
    return Seleccion(mejor + 1, disponibles[mejor], tuple(puntuaciones))


def maximo_efectivo(texto: str | None) -> int:
    valor = buscar(parsear(texto), "MAX_NOTES") if texto is not None else None
    numero = decimal_acotado(valor) if valor is not None else -1
    return numero if numero > 0 else 20


def bit_exito(resultado: int) -> int:
    return 1 ^ ((resultado >> 15) & 1)


def main() -> None:
    # Entradas de ejemplo construidas para esta comprobación, no capturas reales.
    texto = (
        "1STA=R,1VAL=10,1ACT=8,"
        "2STA=R,2VAL=20,2ACT=3,"
        "3STA=R,3VAL=5,3ACT=30,"
        "4STA=R,4VAL=20,4ACT=3;"
    )
    empate = seleccionar(texto, 5)
    assert empate == Seleccion(2, 3, (50, 60, 25, 60, 0, 0, 0, 0, 0))
    limitado = seleccionar("1STA=R,1VAL=5,1ACT=30;", 5)
    assert limitado.disponibilidad == 30
    assert min(5, limitado.disponibilidad) == 5
    assert seleccionar("1STA=R ,1VAL=10,1ACT=8;", 5).casete == -1
    assert seleccionar("1STA=r,1VAL=10,1ACT=8;", 5).casete == -1
    assert seleccionar("1STA=R,1VAL=0,1ACT=8;", 5).casete == -1
    assert buscar(parsear("A=1,A=2;"), "A") == "1"
    assert buscar(parsear("A=1;B=2"), "B") is None
    assert parsear("X" * 32 + "=1,A=2;")[:2] == [None, ("A", "2")]
    assert buscar(parsear("A =10;"), "A") is None
    assert buscar(parsear(", \t\r\nA=10;"), "A") == "10"
    assert buscar(parsear(",".join(f"K{i}=1" for i in range(129)) + ";"), "K128") is None
    assert maximo_efectivo("MAX_NOTES=7;") == 7
    assert maximo_efectivo("MAX_NOTES=0;") == 20
    assert maximo_efectivo("MAX_NOTES=-1;") == 20
    assert maximo_efectivo(None) == 20
    assert bit_exito(0) == 1
    assert bit_exito(0x8000) == 0
    assert bit_exito(0x10000) == 1
    assert ((0x80000000 * 2) & MASK32) == 0
    cadena = (0x43435343).to_bytes(4, "little") + (0x474e).to_bytes(2, "little") + b"\0"
    assert cadena == b"CSCCNG\0"
    print("Empate:", empate)
    print("Disponibilidad sin limitar:", limitado.disponibilidad)
    print("Cantidad limitada en el hilo:", min(5, limitado.disponibilidad))
    print("Máximos efectivos:", [maximo_efectivo(x) for x in ("MAX_NOTES=7;", "MAX_NOTES=0;", "MAX_NOTES=-1;", None)])
    print("Éxito por bit 15:", [bit_exito(x) for x in (0, 0x8000, 0x10000)])
    print("Cadena reconstruida:", repr(cadena))
    print("Comprobaciones completadas; solo datos sintéticos en memoria.")


if __name__ == "__main__":
    main()
