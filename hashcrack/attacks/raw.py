"""Ataques de diccionario contra hashes "crudos": los que no traen
ninguna marca de sal en el propio string. Cubre MD5, SHA-1, SHA-256 y
NTLM.

MD5Attack, SHA1Attack y SHA256Attack aceptan sal manual opcional
(salt, position), para el caso de hashes que sí estaban salados antes
de calcularse pero cuyo string final no lo dice — el usuario tiene
que saber (o sospechar) la sal de antemano y pasarla. Por defecto
salt="" y no cambia nada, así que el comportamiento de la Sesión 3
sigue intacto si no se especifica sal.

NTLM no lleva esta opción: no es un escenario real — NTLM siempre es
MD4(UTF-16LE(contraseña)), sin sal, por diseño del algoritmo.

Cada algoritmo sigue siendo su propia clase (no una genérica
parametrizada con una función guardada como atributo), para que cada
Attack se pueda serializar sin riesgo al mandarlo a los procesos de
multiprocessing.
"""

from typing import Literal

import hashlib

from Crypto.Hash import MD4

from hashcrack.attacks.base import Attack

SaltPosition = Literal["prepend", "append"]


def _apply_salt(candidate: str, salt: str, position: SaltPosition) -> str:
    if not salt:
        return candidate
    return f"{salt}{candidate}" if position == "prepend" else f"{candidate}{salt}"


class MD5Attack(Attack):
    """Ataque de diccionario contra un hash MD5 crudo, con sal manual opcional."""

    name = "MD5Attack"

    def __init__(self, salt: str = "", position: SaltPosition = "prepend"):
        self._salt = salt
        self._position = position

    def hash_candidate(self, candidate: str) -> str:
        salted = _apply_salt(candidate, self._salt, self._position)
        return hashlib.md5(salted.encode("utf-8")).hexdigest()


class SHA1Attack(Attack):
    """Ataque de diccionario contra un hash SHA-1 crudo, con sal manual opcional."""

    name = "SHA1Attack"

    def __init__(self, salt: str = "", position: SaltPosition = "prepend"):
        self._salt = salt
        self._position = position

    def hash_candidate(self, candidate: str) -> str:
        salted = _apply_salt(candidate, self._salt, self._position)
        return hashlib.sha1(salted.encode("utf-8")).hexdigest()


class SHA256Attack(Attack):
    """Ataque de diccionario contra un hash SHA-256 crudo, con sal manual opcional."""

    name = "SHA256Attack"

    def __init__(self, salt: str = "", position: SaltPosition = "prepend"):
        self._salt = salt
        self._position = position

    def hash_candidate(self, candidate: str) -> str:
        salted = _apply_salt(candidate, self._salt, self._position)
        return hashlib.sha256(salted.encode("utf-8")).hexdigest()


class NTLMAttack(Attack):
    """Ataque de diccionario contra un hash NTLM (32 hex, nunca lleva sal).

    NTLM = MD4(contraseña codificada en UTF-16LE). Se usa el MD4 de
    pycryptodome en vez de hashlib.new("md4") porque muchas
    distribuciones modernas de OpenSSL deshabilitan MD4 por defecto.
    """

    name = "NTLMAttack"

    def hash_candidate(self, candidate: str) -> str:
        return MD4.new(candidate.encode("utf-16-le")).hexdigest()