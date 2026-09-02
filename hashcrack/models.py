"""Modelos de datos compartidos por todo el paquete hashcrack."""

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class CrackResult:
    """Resultado de correr un ataque o una reversión contra un hash objetivo.

    Se usa tanto para ataques de búsqueda (diccionario) como para
    reversiones directas (Cisco Type 7) — en una reversión, attempts
    siempre va a ser 1, porque no hay búsqueda, hay una fórmula que
    da la respuesta directamente.
    """

    found: bool
    plaintext: str | None
    attempts: int
    elapsed_seconds: float
    attack_name: str