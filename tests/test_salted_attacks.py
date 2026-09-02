from hashcrack.attacks.salted import (
    Argon2Attack,
    BcryptAttack,
    Md5CryptAttack,
    Sha256CryptAttack,
    Sha512CryptAttack,
)

# Los cinco calculados con las librerías reales, no tipeados a mano.
# bcrypt/Argon2/crypt usan salt fijo a propósito, para que el test sea
# determinístico (normalmente el salt sale aleatorio en cada corrida).
_BCRYPT_HELLO = "$2b$04$XRr.uHBOZgictPvLpVdLWOILmOje3Wbn3u6uE/CIYVGzO/U7SCW16"
_ARGON2_HELLO = "$argon2id$v=19$m=8,t=1,p=1$OA4FczeYLXPMk7W+xQyuOw$xEv5/o5JcQEqDLKoXBgY3g"
_MD5_CRYPT_HELLO = "$1$abcdefgh$rwnEbRiN0agqVgZBovWNQ/"
_SHA256_CRYPT_HELLO = "$5$rounds=1000$abcdefgh$okyjw/83AAX.UipXCtjVrkKTDWdqFQkp6Bg/O6/KuPB"
_SHA512_CRYPT_HELLO = (
    "$6$rounds=1000$abcdefgh$lTNfvnTTeJaP4hJRc5HKoW7.C7.Aht9eJcusrUnljrNfqeofleTkSKfi5mHqqRLRA.jW3omiyGtwR/4VdOeJX0"
)


def test_bcrypt_attack_recognizes_correct_password():
    attack = BcryptAttack(_BCRYPT_HELLO)
    assert attack.hash_candidate("hello") == _BCRYPT_HELLO


def test_bcrypt_attack_rejects_wrong_password():
    attack = BcryptAttack(_BCRYPT_HELLO)
    assert attack.hash_candidate("wrong") != _BCRYPT_HELLO


def test_argon2_attack_recognizes_correct_password():
    attack = Argon2Attack(_ARGON2_HELLO)
    assert attack.hash_candidate("hello") == _ARGON2_HELLO


def test_argon2_attack_rejects_wrong_password():
    attack = Argon2Attack(_ARGON2_HELLO)
    assert attack.hash_candidate("wrong") != _ARGON2_HELLO


def test_md5_crypt_attack_recognizes_correct_password():
    attack = Md5CryptAttack(_MD5_CRYPT_HELLO)
    assert attack.hash_candidate("hello") == _MD5_CRYPT_HELLO


def test_sha256_crypt_attack_recognizes_correct_password():
    attack = Sha256CryptAttack(_SHA256_CRYPT_HELLO)
    assert attack.hash_candidate("hello") == _SHA256_CRYPT_HELLO


def test_sha512_crypt_attack_recognizes_correct_password():
    attack = Sha512CryptAttack(_SHA512_CRYPT_HELLO)
    assert attack.hash_candidate("hello") == _SHA512_CRYPT_HELLO