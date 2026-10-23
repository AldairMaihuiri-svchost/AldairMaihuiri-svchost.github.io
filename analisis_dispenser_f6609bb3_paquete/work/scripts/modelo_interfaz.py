#!/usr/bin/env python3
"""Modelo inerte del orden de eventos de la interfaz; no usa Win32."""
from dataclasses import dataclass, field


@dataclass
class ModeloInterfaz:
    texto: str
    controles_presentes: bool = True
    panel_estados: bool = False
    hilo_solicitado: bool = False
    eventos: list[str] = field(default_factory=list)

    def comando(self, identificador: int) -> None:
        if identificador != 0x200B:
            return
        self.eventos.append("WM_COMMAND ENTER")
        self.inicio()

    def inicio(self) -> None:
        leido = self.texto[:31]  # Representa el buffer de WM_GETTEXT.
        self.eventos.append("texto leido sin comparacion")
        del leido  # La ruta modelada no vuelve a utilizarlo.
        self.controles_presentes = False
        self.eventos.append("controles retirados")
        self.panel_estados = True
        self.eventos.append("panel de estados habilitado")
        self.hilo_solicitado = True
        self.eventos.append("solicitud de hilo con parametro nulo")

    def arranque(self) -> None:
        self.eventos.append("ventana creada y mostrada")
        self.comando(0x200B)  # Representa entrega sincronica del mismo hilo.
        self.eventos.append("entrada al bucle de mensajes")


def comprobar() -> None:
    trazas = []
    for texto in ("", "1234567890", "texto de prueba"):
        modelo = ModeloInterfaz(texto)
        modelo.arranque()
        assert modelo.hilo_solicitado
        assert modelo.panel_estados
        assert not modelo.controles_presentes
        trazas.append(modelo.eventos)
    assert trazas[0] == trazas[1] == trazas[2]
    print("Casos comprobados: 3")
    print("Trazas iguales: si")
    print("Orden modelado:")
    for numero, evento in enumerate(trazas[0], 1):
        print(f"{numero}. {evento}")


if __name__ == "__main__":
    comprobar()
