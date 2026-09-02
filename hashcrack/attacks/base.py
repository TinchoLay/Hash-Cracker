"""Clase base para los ataques de "búsqueda": los que prueban muchos
candidatos contra un hash objetivo hasta encontrar una coincidencia o
agotar las opciones.

Esto cubre tanto el ataque de diccionario clásico contra un hash de
contraseña real (MD5, SHA-256, bcrypt, etc.) como, más adelante, la
búsqueda de la clave secreta de firma de un JWT — computacionalmente
son el mismo patrón (candidato → función → comparar, repetir), aunque
la función interna sea distinta en cada caso.

No cubre Cisco Type 7 ni nada que se resuelva con una fórmula directa
sin probar candidatos — eso vive en reversers/base.py, con una
interfaz distinta a propósito.
"""

from abc import ABC, abstractmethod


class Attack(ABC):
    """Interfaz que debe cumplir todo ataque de búsqueda por candidatos."""

    #: Nombre legible del ataque, usado en resultados y logs.
    name: str = "UnnamedAttack"

    @abstractmethod
    def hash_candidate(self, candidate: str) -> str:
        """Calcula el hash de un único candidato, en el mismo formato
        que el hash objetivo, para poder compararlos directamente.

        Esta es la única responsabilidad de un Attack: saber cómo
        convertir un texto candidato en algo comparable contra el
        hash objetivo. NO decide cuántos procesos usar, ni cómo
        repartir el trabajo, ni cuándo cortar la búsqueda — eso es
        responsabilidad del motor (engine.py, Sesión 2), no de esta
        clase. Cada Attack debe ser una función pura: mismo candidato
        de entrada, mismo resultado siempre.
        """
        raise NotImplementedError