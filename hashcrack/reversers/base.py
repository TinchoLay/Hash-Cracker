"""Clase base para las "reversiones": formatos donde no hace falta
probar candidatos porque existe una fórmula matemática que revierte
el proceso directamente.

El caso principal es Cisco Type 7 (cifrado XOR reversible) — dado el
texto cifrado, hay una operación fija que devuelve el texto original
al instante, sin buscar nada. Es fundamentalmente distinto a un
Attack (búsqueda por candidatos): acá no hay wordlist, no hay
multiprocessing, no hay "no se encontró" — si el formato es válido,
siempre se resuelve.
"""

from abc import ABC, abstractmethod


class Reverser(ABC):
    """Interfaz que debe cumplir todo esquema reversible sin búsqueda."""

    #: Nombre legible del reverser, usado en resultados y logs.
    name: str = "UnnamedReverser"

    @abstractmethod
    def reverse(self, encoded_text: str) -> str:
        """Revierte encoded_text a su valor original mediante una
        fórmula directa (no una búsqueda).

        A diferencia de Attack.hash_candidate(), este método SÍ
        devuelve la respuesta final directamente — no hay comparación
        posterior contra un objetivo, porque no se está buscando nada.
        """
        raise NotImplementedError