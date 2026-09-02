"""Ataques de diccionario contra formatos que llevan la sal (y a veces
el costo computacional) incluidos en el propio string del hash — no
hace falta que el usuario la indique, se extrae sola.

Cubre bcrypt, Argon2 (id/i/d) y los tres crypt de Unix (MD5, SHA-256,
SHA-512). Dos patrones de implementación distintos conviven acá:

- bcrypt expone una función que recalcula el hash completo dado el
  mismo salt — encaja directo con la interfaz Attack.hash_candidate(),
  que siempre devuelve algo comparable con == contra el hash objetivo.
- Argon2 y los crypt de Unix (vía passlib) exponen un verify(hash,
  password) -> bool en vez de una función de recálculo standalone. Se
  adapta a la interfaz existente: si verify() confirma la coincidencia,
  se devuelve el propio target_hash (así el == da True en el motor);
  si no, se devuelve un valor centinela que nunca va a coincidir con
  un hash real.

Nota: el módulo crypt de la biblioteca estándar de Python fue
eliminado en Python 3.13 (estaba deprecado desde 3.11, PEP 594). Por
eso los tres formatos crypt de Unix se implementan acá con passlib,
que reimplementa los algoritmos en Python puro, sin depender de la
función crypt() del sistema operativo.
"""

import bcrypt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHash, VerifyMismatchError
from passlib.hash import md5_crypt, sha256_crypt, sha512_crypt

from hashcrack.attacks.base import Attack

_NO_MATCH = "\x00NO-MATCH\x00"


class BcryptAttack(Attack):
    """Ataque de diccionario contra un hash bcrypt ($2a$/$2b$/$2y$)."""

    name = "BcryptAttack"

    def __init__(self, target_hash: str):
        self._salt = target_hash[:29].encode("utf-8")

    def hash_candidate(self, candidate: str) -> str:
        return bcrypt.hashpw(candidate.encode("utf-8"), self._salt).decode("utf-8")


class Argon2Attack(Attack):
    """Ataque de diccionario contra un hash Argon2 (id/i/d)."""

    name = "Argon2Attack"

    def __init__(self, target_hash: str):
        self._target_hash = target_hash
        self._hasher = PasswordHasher()

    def hash_candidate(self, candidate: str) -> str:
        try:
            self._hasher.verify(self._target_hash, candidate)
            return self._target_hash
        except (VerifyMismatchError, InvalidHash):
            return _NO_MATCH


class Md5CryptAttack(Attack):
    """Ataque de diccionario contra MD5 crypt de Unix ($1$salt$hash)."""

    name = "Md5CryptAttack"

    def __init__(self, target_hash: str):
        self._target_hash = target_hash

    def hash_candidate(self, candidate: str) -> str:
        return self._target_hash if md5_crypt.verify(candidate, self._target_hash) else _NO_MATCH


class Sha256CryptAttack(Attack):
    """Ataque de diccionario contra SHA-256 crypt de Unix ($5$salt$hash)."""

    name = "Sha256CryptAttack"

    def __init__(self, target_hash: str):
        self._target_hash = target_hash

    def hash_candidate(self, candidate: str) -> str:
        return self._target_hash if sha256_crypt.verify(candidate, self._target_hash) else _NO_MATCH


class Sha512CryptAttack(Attack):
    """Ataque de diccionario contra SHA-512 crypt de Unix ($6$salt$hash)."""

    name = "Sha512CryptAttack"

    def __init__(self, target_hash: str):
        self._target_hash = target_hash

    def hash_candidate(self, candidate: str) -> str:
        return self._target_hash if sha512_crypt.verify(candidate, self._target_hash) else _NO_MATCH