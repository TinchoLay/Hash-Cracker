"""Ataque de diccionario contra la clave secreta de firma de un JWT
firmado con HMAC (los algoritmos HS256, HS384, HS512).

A diferencia de todos los ataques anteriores, acá lo que se busca no
es la contraseña de un usuario — es la CLAVE SECRETA que el servidor
usó para firmar el token. Si esa clave es débil (una palabra de
diccionario, por ejemplo), cualquiera puede reproducir firmas válidas
y falsificar tokens.

Computacionalmente es el mismo patrón que un ataque de diccionario
común: candidato → función → comparar, repetir. Por eso encaja en la
misma interfaz Attack y puede correr sobre el mismo motor de
multiprocessing sin ningún cambio ahí — lo único que cambia es qué
significa "candidato" (una posible clave secreta, no una contraseña)
y qué se compara (la firma del JWT, no un hash de contraseña).
"""

import base64
import hashlib
import hmac
import json

from hashcrack.attacks.base import Attack

_ALGORITHMS = {
    "HS256": hashlib.sha256,
    "HS384": hashlib.sha384,
    "HS512": hashlib.sha512,
}


def _b64url_decode(segment: str) -> bytes:
    padded = segment + "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(padded)


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def jwt_signature(jwt: str) -> str:
    """Extrae solo la firma (tercer segmento) de un JWT completo —
    esto es lo que se usa como target_hash al llamar al motor.
    """
    return jwt.split(".")[2]


class JWTSecretAttack(Attack):
    """Prueba cada candidato del diccionario como posible clave
    secreta de firma de un JWT, y compara la firma resultante contra
    la firma real del token.
    """

    def __init__(self, jwt: str):
        header_b64, payload_b64, _signature_b64 = jwt.split(".")
        self._signing_input = f"{header_b64}.{payload_b64}".encode("ascii")

        header = json.loads(_b64url_decode(header_b64))
        alg = header.get("alg", "HS256")
        if alg not in _ALGORITHMS:
            raise ValueError(
                f"Algoritmo de firma '{alg}' no soportado para este ataque "
                f"(solo HS256/HS384/HS512 — algoritmos asimétricos como RS256 "
                f"no se atacan con diccionario sobre una clave simétrica)."
            )
        self._digestmod = _ALGORITHMS[alg]
        self.name = f"JWTSecretAttack({alg})"

    def hash_candidate(self, candidate: str) -> str:
        signature = hmac.new(
            candidate.encode("utf-8"), self._signing_input, self._digestmod
        ).digest()
        return _b64url_encode(signature)