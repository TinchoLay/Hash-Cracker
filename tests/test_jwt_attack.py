from hashcrack.attacks.jwt import JWTSecretAttack, jwt_signature
from hashcrack.engine import run_dictionary_attack

# Generado con hmac/hashlib reales, clave secreta = "secret123"
_JWT = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0."
    "9oDgE4J5RJ17rnI7HDS3ExuhN-sFbVTAKCsp-evkW6A"
)


def test_correct_secret_produces_matching_signature():
    attack = JWTSecretAttack(_JWT)
    assert attack.hash_candidate("secret123") == jwt_signature(_JWT)


def test_wrong_secret_produces_different_signature():
    attack = JWTSecretAttack(_JWT)
    assert attack.hash_candidate("wrong-secret") != jwt_signature(_JWT)


def test_attack_name_includes_algorithm():
    attack = JWTSecretAttack(_JWT)
    assert attack.name == "JWTSecretAttack(HS256)"


def test_rs256_algorithm_is_rejected():
    import base64
    import json

    header = base64.urlsafe_b64encode(
        json.dumps({"alg": "RS256", "typ": "JWT"}).encode()
    ).rstrip(b"=").decode()
    fake_jwt = f"{header}.eyJmb28iOiJiYXIifQ.fakesignature"

    try:
        JWTSecretAttack(fake_jwt)
        assert False, "debería haber lanzado ValueError"
    except ValueError:
        pass


def test_engine_cracks_jwt_secret_from_wordlist():
    wordlist = ["password", "123456", "secret123", "qwerty"]
    result = run_dictionary_attack(
        attack=JWTSecretAttack(_JWT),
        target_hash=jwt_signature(_JWT),
        wordlist=wordlist,
        processes=2,
    )
    assert result.found is True
    assert result.plaintext == "secret123"