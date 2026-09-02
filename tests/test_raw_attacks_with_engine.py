"""Verifica que los ataques de raw.py funcionan de punta a punta con
el motor de multiprocessing — no solo probados en aislamiento.
"""

from hashcrack.attacks.raw import MD5Attack, SHA256Attack
from hashcrack.engine import run_dictionary_attack

_MD5_HELLO = "5d41402abc4b2a76b9719d911017c592"
_SHA256_HELLO = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"


def test_engine_cracks_md5_from_wordlist():
    wordlist = ["manzana", "banana", "hello", "naranja"]
    result = run_dictionary_attack(
        attack=MD5Attack(), target_hash=_MD5_HELLO, wordlist=wordlist, processes=2,
    )
    assert result.found is True
    assert result.plaintext == "hello"
    assert result.attack_name == "MD5Attack"


def test_engine_cracks_sha256_from_wordlist():
    wordlist = ["manzana", "banana", "hello", "naranja"]
    result = run_dictionary_attack(
        attack=SHA256Attack(), target_hash=_SHA256_HELLO, wordlist=wordlist, processes=2,
    )
    assert result.found is True
    assert result.plaintext == "hello"


def test_engine_reports_not_found_when_password_not_in_wordlist():
    wordlist = ["manzana", "banana", "naranja"]
    result = run_dictionary_attack(
        attack=MD5Attack(), target_hash=_MD5_HELLO, wordlist=wordlist, processes=2,
    )
    assert result.found is False
    assert result.plaintext is None