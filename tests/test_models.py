from hashcrack.models import CrackResult


def test_crack_result_holds_all_fields():
    result = CrackResult(
        found=True,
        plaintext="hunter2",
        attempts=42,
        elapsed_seconds=0.5,
        attack_name="DictionaryAttack",
    )
    assert result.found is True
    assert result.plaintext == "hunter2"
    assert result.attempts == 42
    assert result.attack_name == "DictionaryAttack"


def test_crack_result_not_found_has_no_plaintext():
    result = CrackResult(
        found=False,
        plaintext=None,
        attempts=1000,
        elapsed_seconds=2.1,
        attack_name="DictionaryAttack",
    )
    assert result.found is False
    assert result.plaintext is None