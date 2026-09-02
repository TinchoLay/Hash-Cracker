"""Reversión de contraseñas Cisco IOS "Type 7".

No es un hash criptográfico — es un cifrado XOR con una clave fija y
pública, pensado únicamente para que la contraseña no quede a la
vista en texto plano dentro de un archivo de configuración. No hay
nada que "crackear" en el sentido de probar candidatos: existe una
fórmula directa que revierte el proceso al instante.

La tabla XLAT de 53 bytes es la misma que usan hashcat (modo 7),
John the Ripper, y prácticamente cualquier herramienta de
administración de redes desde hace más de dos décadas — no es
información sensible ni secreta, está documentada públicamente.
"""

from hashcrack.reversers.base import Reverser

_XLAT: list[int] = [
    0x64, 0x73, 0x66, 0x64, 0x3B, 0x6B, 0x66, 0x6F, 0x41, 0x2C, 0x2E, 0x69, 0x79, 0x65, 0x77, 0x72,
    0x6B, 0x6C, 0x64, 0x4A, 0x4B, 0x44, 0x48, 0x53, 0x55, 0x42, 0x73, 0x67, 0x76, 0x63, 0x61, 0x36,
    0x39, 0x38, 0x33, 0x34, 0x6E, 0x63, 0x78, 0x76, 0x39, 0x38, 0x37, 0x33, 0x32, 0x35, 0x34, 0x6B,
    0x3B, 0x66, 0x67, 0x38, 0x37,
]


class CiscoType7Reverser(Reverser):
    """Revierte una contraseña Cisco Type 7 a su texto original."""

    name = "CiscoType7Reverser"

    def reverse(self, encoded_text: str) -> str:
        salt = int(encoded_text[0:2])
        hex_pairs = encoded_text[2:]

        chars = []
        key_index = salt
        for i in range(0, len(hex_pairs), 2):
            byte = int(hex_pairs[i : i + 2], 16)
            chars.append(chr(byte ^ _XLAT[key_index % len(_XLAT)]))
            key_index += 1

        return "".join(chars)