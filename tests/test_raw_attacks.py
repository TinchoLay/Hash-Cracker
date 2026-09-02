from hashcrack.attacks.raw import MD5Attack, NTLMAttack, SHA1Attack, SHA256Attack

# Valores calculados con Python real, no tipeados de memoria —
# evita el tipo de error de transcripción que ya nos pasó varias
# veces en el proyecto hermano (Hash-Identifier).
_MD5_HELLO = "5d41402abc4b2a76b9719d911017c592"
_SHA1_ABC = "a9993e364706816aba3e25717850c26c9cd0d89d"
_SHA256_HELLO = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
_NTLM_HELLO = "066ddfd4ef0e9cd7c256fe77191ef43c"


def test_md5_attack_computes_known_hash():
    assert MD5Attack().hash_candidate("hello") == _MD5_HELLO


def test_sha1_attack_computes_known_hash():
    assert SHA1Attack().hash_candidate("abc") == _SHA1_ABC


def test_sha256_attack_computes_known_hash():
    assert SHA256Attack().hash_candidate("hello") == _SHA256_HELLO


def test_ntlm_attack_computes_known_hash():
    assert NTLMAttack().hash_candidate("hello") == _NTLM_HELLO


def test_different_candidates_produce_different_hashes():
    attack = MD5Attack()
    assert attack.hash_candidate("hello") != attack.hash_candidate("world")