"""Tests para el motor de multiprocessing.

La clase _EchoAttack está definida a nivel de módulo (no dentro de
una función de test) a propósito: en Windows, multiprocessing usa el
método "spawn", y cada proceso hijo necesita poder IMPORTAR la clase
por su ruta completa. Una clase definida dentro de una función no
tiene una ruta de importación válida y el proceso hijo no la puede
reconstruir.
"""

from hashcrack.attacks.base import Attack
from hashcrack.engine import run_dictionary_attack


class _EchoAttack(Attack):
    """Attack de prueba: el "hash" de un candidato es el candidato
    mismo. Permite testear el motor sin depender de un algoritmo real.
    """

    name = "EchoAttack"

    def hash_candidate(self, candidate: str) -> str:
        return candidate


def test_finds_target_in_small_wordlist():
    wordlist = ["manzana", "banana", "hunter2", "naranja"]
    result = run_dictionary_attack(
        attack=_EchoAttack(), target_hash="hunter2", wordlist=wordlist, processes=2,
    )
    assert result.found is True
    assert result.plaintext == "hunter2"
    assert result.attack_name == "EchoAttack"


def test_returns_not_found_when_target_is_absent():
    wordlist = ["manzana", "banana", "naranja"]
    result = run_dictionary_attack(
        attack=_EchoAttack(), target_hash="hunter2", wordlist=wordlist, processes=2,
    )
    assert result.found is False
    assert result.plaintext is None
    assert result.attempts == 3


def test_empty_wordlist_returns_not_found_without_error():
    result = run_dictionary_attack(
        attack=_EchoAttack(), target_hash="hunter2", wordlist=[], processes=2,
    )
    assert result.found is False
    assert result.attempts == 0


def test_ignores_blank_lines_in_wordlist():
    wordlist = ["manzana", "", "  ", "hunter2"]
    result = run_dictionary_attack(
        attack=_EchoAttack(), target_hash="hunter2", wordlist=wordlist, processes=2,
    )
    assert result.found is True