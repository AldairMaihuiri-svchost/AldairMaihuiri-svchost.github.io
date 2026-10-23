#!/usr/bin/env python3
"""Modelo independiente de MD5 con mensajes públicos y sintéticos.

Usa únicamente mensajes públicos y datos sintéticos. No incorpora datos internos,
credenciales, protocolo del dispensador ni llamadas a la muestra.
"""
from __future__ import annotations

import hashlib
import json
import struct

MASK = 0xFFFFFFFF
IV = (0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476)
S = ((7, 12, 17, 22) * 4 + (5, 9, 14, 20) * 4
     + (4, 11, 16, 23) * 4 + (6, 10, 15, 21) * 4)
T = (
    0xD76AA478, 0xE8C7B756, 0x242070DB, 0xC1BDCEEE,
    0xF57C0FAF, 0x4787C62A, 0xA8304613, 0xFD469501,
    0x698098D8, 0x8B44F7AF, 0xFFFF5BB1, 0x895CD7BE,
    0x6B901122, 0xFD987193, 0xA679438E, 0x49B40821,
    0xF61E2562, 0xC040B340, 0x265E5A51, 0xE9B6C7AA,
    0xD62F105D, 0x02441453, 0xD8A1E681, 0xE7D3FBC8,
    0x21E1CDE6, 0xC33707D6, 0xF4D50D87, 0x455A14ED,
    0xA9E3E905, 0xFCEFA3F8, 0x676F02D9, 0x8D2A4C8A,
    0xFFFA3942, 0x8771F681, 0x6D9D6122, 0xFDE5380C,
    0xA4BEEA44, 0x4BDECFA9, 0xF6BB4B60, 0xBEBFBC70,
    0x289B7EC6, 0xEAA127FA, 0xD4EF3085, 0x04881D05,
    0xD9D4D039, 0xE6DB99E5, 0x1FA27CF8, 0xC4AC5665,
    0xF4292244, 0x432AFF97, 0xAB9423A7, 0xFC93A039,
    0x655B59C3, 0x8F0CCC92, 0xFFEFF47D, 0x85845DD1,
    0x6FA87E4F, 0xFE2CE6E0, 0xA3014314, 0x4E0811A1,
    0xF7537E82, 0xBD3AF235, 0x2AD7D2BB, 0xEB86D391,
)


def rol32(value: int, count: int) -> int:
    value &= MASK
    return ((value << count) | (value >> (32 - count))) & MASK


class MD5Modelo:
    def __init__(self) -> None:
        self.estado = list(IV)
        self.total_bytes = 0
        self.pendiente = bytearray()

    def _comprimir(self, bloque: bytes) -> None:
        palabras = struct.unpack('<16I', bloque)
        a, b, c, d = self.estado
        for i in range(64):
            if i < 16:
                f = (b & c) | ((~b) & d)
                g = i
            elif i < 32:
                f = (b & d) | (c & (~d))
                g = (5 * i + 1) % 16
            elif i < 48:
                f = b ^ c ^ d
                g = (3 * i + 5) % 16
            else:
                f = c ^ (b | (~d))
                g = (7 * i) % 16
            nuevo_b = (b + rol32(a + f + T[i] + palabras[g], S[i])) & MASK
            a, b, c, d = d, nuevo_b, b, c
        self.estado = [(viejo + nuevo) & MASK
                       for viejo, nuevo in zip(self.estado, (a, b, c, d))]

    def update(self, datos: bytes) -> None:
        self.total_bytes += len(datos)
        self.pendiente.extend(datos)
        while len(self.pendiente) >= 64:
            self._comprimir(bytes(self.pendiente[:64]))
            del self.pendiente[:64]

    def digest(self) -> bytes:
        # Finaliza una copia para que el objeto original conserve su estado.
        copia = MD5Modelo()
        copia.estado = self.estado.copy()
        copia.total_bytes = self.total_bytes
        copia.pendiente = self.pendiente.copy()
        bits = (copia.total_bytes * 8) & 0xFFFFFFFFFFFFFFFF
        ceros = (56 - ((copia.total_bytes + 1) % 64)) % 64
        copia.update(b'\x80' + b'\x00' * ceros + struct.pack('<Q', bits))
        assert not copia.pendiente
        return struct.pack('<4I', *copia.estado)


def main() -> None:
    vectores = (
        (b'', 'd41d8cd98f00b204e9800998ecf8427e'),
        (b'a', '0cc175b9c0f1b6a831c399e269772661'),
        (b'abc', '900150983cd24fb0d6963f7d28e17f72'),
        (b'message digest', 'f96b697d7cb7938d525a2f31aaf161d0'),
        (b'abcdefghijklmnopqrstuvwxyz', 'c3fcd3d76192e4007dfb496cca67e13b'),
        (b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789',
         'd174ab98d277d9f5a5611c2c9f419d9f'),
        (b'1234567890' * 8, '57edf4a22be3c955ac49da2e2107b67a'),
    )
    salidas = []
    for mensaje, esperado in vectores:
        modelo = MD5Modelo()
        modelo.update(mensaje)
        obtenido = modelo.digest().hex()
        assert obtenido == esperado == hashlib.md5(mensaje).hexdigest()
        salidas.append({'mensaje': mensaje.decode('ascii'), 'md5': obtenido})
    longitudes = [0, 1, 4, 16, 20, 32, 55, 56, 57, 63, 64, 65,
                  119, 120, 121, 127, 128, 129, 256, 1000]
    particiones = [1, 7, 16, 63, 64, 65, 127]
    for longitud in longitudes:
        mensaje = bytes((i * 17 + 3) % 256 for i in range(longitud))
        esperado = hashlib.md5(mensaje).digest()
        for paso in particiones:
            modelo = MD5Modelo()
            for inicio in range(0, longitud, paso):
                modelo.update(mensaje[inicio:inicio + paso])
            assert modelo.digest() == esperado
            assert modelo.digest() == esperado
    resultado = {'vectores_publicos': salidas,
                 'casos_sinteticos': len(longitudes) * len(particiones),
                 'longitudes': longitudes, 'pasos': particiones,
                 'resultado': 'Todas las comprobaciones correctas.'}
    print(json.dumps(resultado, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
