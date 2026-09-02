import hashlib

from click.testing import CliRunner

from hashcrack.cli import main


def test_crack_finds_md5_password(tmp_path):
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("banana\nhello\nmanzana\n", encoding="utf-8")

    target = hashlib.md5(b"hello").hexdigest()

    runner = CliRunner()
    result = runner.invoke(main, ["crack", target, "--wordlist", str(wordlist)])
    assert result.exit_code == 0
    assert "hello" in result.output


def test_crack_reports_not_found_with_error_code(tmp_path):
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("banana\nmanzana\n", encoding="utf-8")

    target = hashlib.md5(b"hello").hexdigest()

    runner = CliRunner()
    result = runner.invoke(main, ["crack", target, "--wordlist", str(wordlist)])
    assert result.exit_code == 1


def test_crack_reverses_cisco_type7_without_wordlist():
    runner = CliRunner()
    result = runner.invoke(main, ["crack", "094F471A1A0A"])
    assert result.exit_code == 0
    assert "cisco" in result.output


def test_crack_forced_algorithm_skips_detection(tmp_path):
    wordlist = tmp_path / "words.txt"
    wordlist.write_text("hello\n", encoding="utf-8")

    target = hashlib.sha256(b"hello").hexdigest()

    runner = CliRunner()
    result = runner.invoke(
        main, ["crack", target, "--wordlist", str(wordlist), "--algorithm", "SHA-256"]
    )
    assert result.exit_code == 0
    assert "hello" in result.output