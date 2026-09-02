import hashlib

from hashcrack.attacks.raw import MD5Attack

# Hash de "sal12345" (prepend) construido a mano PERO calculado con
# hashlib acá mismo, no de memoria.
_SALTED_MD5 = hashlib.md5(b"sal12345").hexdigest()


def test_manual_salt_prepend_matches_when_salt_is_correct():
    attack = MD5Attack(salt="sal", position="prepend")
    assert attack.hash_candidate("12345") == _SALTED_MD5


def test_manual_salt_prepend_does_not_match_without_salt():
    attack = MD5Attack()  # sin sal
    assert attack.hash_candidate("12345") != _SALTED_MD5


def test_manual_salt_append_uses_correct_order():
    salted_hash = hashlib.md5(b"12345sal").hexdigest()
    attack = MD5Attack(salt="sal", position="append")
    assert attack.hash_candidate("12345") == salted_hash


def test_no_salt_behaves_exactly_like_session_3():
    plain_hash = hashlib.md5(b"hello").hexdigest()
    attack = MD5Attack()
    assert attack.hash_candidate("hello") == plain_hash