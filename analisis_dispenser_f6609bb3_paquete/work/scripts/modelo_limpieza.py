"""Modelos de análisis: sólo cadenas, enteros y buffers en memoria."""

VIDEO = (
    '.AAF', '.3GP', '.ASF', '.AVCHD', '.AVI', '.BIK', '.CAM', '.COLLAB',
    '.DSH', '.FLV', '.MPEG', '.MPG', '.MPE', '.MP2', '.MP4', '.M4V',
    '.FLA', '.MKV', '.WRAP', '.MNG', '.MOV', '.MXF', '.NSV', '.RM',
    '.SVI', '.SMI', '.SMK', '.SWF', '.WMV', '.WTV', '.YUV', '.WEBM',
)
IMAGEN = ('.JPG', '.JPEG', '.JNG', '.BMP', '.TIFF', '.JP2', '.JPS', '.GIF', '.PNG', '.TGA')
RASTROS = ('.PF', '.DB.TRX', '.DMP', '.EVT', '.EVTX')
PATRONES = VIDEO + IMAGEN + RASTROS


def mayusculas_ascii(texto):
    # Los casos de prueba son ASCII; no sustituye al manejo de locales del CRT.
    return ''.join(chr(ord(c) - 0x20) if 'a' <= c <= 'z' else c for c in texto)


def patron_observado(nombre):
    normalizado = mayusculas_ascii(nombre)
    return next((patron for patron in PATRONES if patron in normalizado), None)


def entrar_directorio(ruta, windows, modo_total=False):
    # Modelo de la búsqueda de subcadena, sin resolver rutas en el sistema.
    return modo_total or mayusculas_ascii(windows) not in mayusculas_ascii(ruta)


def restar_u64(pendiente, escritos):
    """Equivalente SUB low / SBB high bajo precondiciones de escritura válida."""
    assert 0 <= escritos <= pendiente < (1 << 63)
    low, high = pendiente & 0xffffffff, pendiente >> 32
    borrow = int(low < escritos)
    resultado_low = (low - escritos) & 0xffffffff
    resultado_high = (high - borrow) & 0xffffffff
    return (resultado_high << 32) | resultado_low, borrow


def modelo_buffer(datos, respuestas):
    """Simula respuestas WriteFile; no abre archivos ni usa APIs de Windows."""
    salida = bytearray(datos)
    pendiente, posicion = len(salida), 0
    solicitudes = []
    for ok, escritos in respuestas:
        if pendiente == 0:
            break
        pedido = min(pendiente, 0x1000)
        solicitudes.append((pedido, ok, escritos))
        if not ok or escritos == 0:
            break
        assert 0 <= escritos <= pedido
        salida[posicion:posicion + escritos] = bytes(escritos)
        posicion += escritos
        pendiente, _ = restar_u64(pendiente, escritos)
    return bytes(salida), pendiente, solicitudes


def main():
    assert (len(VIDEO), len(IMAGEN), len(RASTROS)) == (32, 10, 5)
    print('Patrones:', len(PATRONES), '(32 + 10 + 5)')
    for nombre in ('camara.mp4', 'imagen.jpg.bak', 'notas.txt', 'archivo.db.trx', 'copia.evtx.old'):
        print('Filtro:', nombre, '->', patron_observado(nombre))
    for ruta in ('C:\\Windows', 'C:\\Windows.old', 'D:\\Datos'):
        print('Entrar:', ruta, '->', entrar_directorio(ruta, 'C:\\Windows'))
    print('Modo total en Windows:', entrar_directorio('C:\\Windows', 'C:\\Windows', True))
    completo, pendiente, solicitudes = modelo_buffer(b'X' * 9000, [(True, 4096), (True, 4096), (True, 808)])
    assert completo == bytes(9000) and pendiente == 0
    print('Buffer completo: solicitudes=', solicitudes, 'pendiente=', pendiente)
    parcial, pendiente, solicitudes = modelo_buffer(b'X' * 9000, [(True, 4096), (False, 0)])
    assert parcial[:4096] == bytes(4096) and parcial[4096:] == b'X' * 4904
    print('Buffer con fallo: solicitudes=', solicitudes, 'pendiente=', pendiente)
    resto, prestamo = restar_u64(0x100000100, 0x1000)
    assert resto == 0xfffff100 and prestamo == 1
    print('Resta de 64 bits:', hex(0x100000100), '-', hex(0x1000), '=', hex(resto), 'préstamo=', prestamo)
    print('Unidades intermedias:', ', '.join(chr(c) + ':' for c in range(0x41, 0x41 + 0x1a)))
    print('Patrones finales:', ', '.join(chr(c) + ':\\*' for c in range(0x41, 0x41 + 0x1a)))
    print('Verificación: todos los casos se ejecutaron en memoria.')


if __name__ == '__main__':
    main()
