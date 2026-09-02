import pytest

from hashcrack.attacks.base import Attack
from hashcrack.reversers.base import Reverser


def test_attack_cannot_be_instantiated_directly():
    with pytest.raises(TypeError):
        Attack()


def test_reverser_cannot_be_instantiated_directly():
    with pytest.raises(TypeError):
        Reverser()


def test_concrete_attack_subclass_works():
    class EchoAttack(Attack):
        name = "EchoAttack"

        def hash_candidate(self, candidate: str) -> str:
            return candidate

    attack = EchoAttack()
    assert attack.hash_candidate("abc") == "abc"
    assert attack.name == "EchoAttack"


def test_concrete_reverser_subclass_works():
    class UppercaseReverser(Reverser):
        name = "UppercaseReverser"

        def reverse(self, encoded_text: str) -> str:
            return encoded_text.upper()

    reverser = UppercaseReverser()
    assert reverser.reverse("abc") == "ABC"