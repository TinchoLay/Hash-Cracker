from hashcrack.attacks.salted import BcryptAttack
from hashcrack.engine import run_dictionary_attack

_BCRYPT_HELLO = "$2b$04$XRr.uHBOZgictPvLpVdLWOILmOje3Wbn3u6uE/CIYVGzO/U7SCW16"


def test_engine_cracks_bcrypt_from_wordlist():
    wordlist = ["manzana", "banana", "hello", "naranja"]
    result = run_dictionary_attack(
        attack=BcryptAttack(_BCRYPT_HELLO),
        target_hash=_BCRYPT_HELLO,
        wordlist=wordlist,
        processes=2,
    )
    assert result.found is True
    assert result.plaintext == "hello"