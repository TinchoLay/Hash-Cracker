from hashcrack.reversers.cisco import CiscoType7Reverser


def test_classic_example_reverses_to_cisco():
    # Verificado con el algoritmo real antes de escribir el test —
    # es el ejemplo canónico usado en cualquier tutorial de Type 7.
    assert CiscoType7Reverser().reverse("094F471A1A0A") == "cisco"


def test_different_salt_still_reverses_correctly():
    # Mismo texto "cisco", codificado con sal 15 en vez de 09 (el
    # ejemplo clásico) — confirma que el offset dentro de la tabla se
    # maneja bien y no funciona solo por casualidad con la sal de
    # siempre. Valor generado y verificado con el algoritmo real,
    # codificando "cisco" y decodificándolo de vuelta.
    assert CiscoType7Reverser().reverse("1511021F0725") == "cisco"