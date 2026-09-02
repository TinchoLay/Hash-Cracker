"""Ataques de diccionario contra hashes "crudos": los que no llevan
sal ni ningún costo computacional artificial — se calculan a millones
por segundo. Cubre MD5, SHA-1, SHA-256 y NTLM.

Cada algoritmo es su propia clase, en vez de una sola clase genérica
parametrizada con una función de hash guardada como atributo. Es a
propósito: multiprocessing necesita poder serializar ("picklear") cada
Attack para mandarlo a los procesos trabajadores, y una función
guardada como atributo de instancia es más frágil para eso (sobre
todo si fuera un lambda, que directamente no se puede picklear). Una
clase simple, sin atributos raros, se serializa sin problema.

Ninguno de estos cuatro maneja sal — eso se agrega en la Sesión 4,
para los formatos que sí la necesitan (crypt, bcrypt, Argon2, y
opción manual para hashes crudos salados a mano).
"""

import hashlib

from Crypto.Hash import MD4

from hashcrack.attacks.base import Attack


class MD5Attack(Attack):
    """Ataque de diccionario contra un hash MD5 crudo (32 hex, sin sal)."""

    name = "MD5Attack"

    def hash_candidate(self, candidate: str) -> str:
        return hashlib.md5(candidate.encode("utf-8")).hexdigest()


class SHA1Attack(Attack):
    """Ataque de diccionario contra un hash SHA-1 crudo (40 hex, sin sal)."""

    name = "SHA1Attack"

    def hash_candidate(self, candidate: str) -> str:
        return hashlib.sha1(candidate.encode("utf-8")).hexdigest()


class SHA256Attack(Attack):
    """Ataque de diccionario contra un hash SHA-256 crudo (64 hex, sin sal)."""

    name = "SHA256Attack"

    def hash_candidate(self, candidate: str) -> str:
        return hashlib.sha256(candidate.encode("utf-8")).hexdigest()


class NTLMAttack(Attack):
    """Ataque de diccionario contra un hash NTLM (32 hex, sin sal).

    NTLM = MD4(contraseña codificada en UTF-16LE). Se usa el MD4 de
    pycryptodome en vez de hashlib.new("md4") porque muchas
    distribuciones modernas de OpenSSL deshabilitan MD4 por defecto
    (está roto criptográficamente desde hace años, así que algunos
    sistemas lo sacan de la lista de algoritmos disponibles). Eso
    hace que hashlib.new("md4") falle según qué OpenSSL tenga
    instalado el sistema operativo. pycryptodome trae su propia
    implementación, sin depender de esa configuración externa.
    """

    name = "NTLMAttack"

    def hash_candidate(self, candidate: str) -> str:
        return MD4.new(candidate.encode("utf-16-le")).hexdigest()