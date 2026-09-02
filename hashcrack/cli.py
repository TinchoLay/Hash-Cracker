"""Interfaz de línea de comandos de hashcrack.

El corazón de esta CLI es el subcomando crack: recibe un hash, le
pregunta a hashid (el proyecto hermano, instalado como dependencia de
Git) qué algoritmo es, y elige automáticamente el Attack o Reverser
correspondiente. Esta es la primera vez que la integración entre los
dos repos se pone en uso desde una interfaz real, no solo desde tests.
"""

import sys
import time

import click
from hashid.engine import identify as identify_hash
from rich.console import Console

from hashcrack.attacks.jwt import JWTSecretAttack, jwt_signature
from hashcrack.attacks.raw import MD5Attack, NTLMAttack, SHA1Attack, SHA256Attack
from hashcrack.attacks.salted import (
    Argon2Attack,
    BcryptAttack,
    Md5CryptAttack,
    Sha256CryptAttack,
    Sha512CryptAttack,
)
from hashcrack.engine import run_dictionary_attack
from hashcrack.reversers.cisco import CiscoType7Reverser

console = Console()

_DEFAULT_WORDLIST = "wordlists/sample.txt"

_RAW_ATTACK_BUILDERS = {
    "MD5": lambda salt, position: MD5Attack(salt=salt, position=position),
    "SHA-1": lambda salt, position: SHA1Attack(salt=salt, position=position),
    "SHA-256": lambda salt, position: SHA256Attack(salt=salt, position=position),
    "NTLM": lambda salt, position: NTLMAttack(),
}

_SALTED_ATTACK_CLASSES = {
    "bcrypt": BcryptAttack,
    "Argon2id": Argon2Attack,
    "Argon2i": Argon2Attack,
    "Argon2d": Argon2Attack,
    "MD5 crypt": Md5CryptAttack,
    "SHA-256 crypt": Sha256CryptAttack,
    "SHA-512 crypt": Sha512CryptAttack,
}


@click.group()
@click.version_option(package_name="hashcrack")
def main() -> None:
    """hashcrack — crackea o revierte hashes, detectando el algoritmo automáticamente."""


@main.command()
@click.argument("target_hash")
@click.option(
    "--wordlist", "wordlist_path",
    type=click.Path(exists=True, dir_okay=False),
    default=None,
    help=f"Wordlist a usar (por defecto, {_DEFAULT_WORDLIST}).",
)
@click.option("--salt", default="", help="Sal manual para hashes crudos (MD5/SHA-1/SHA-256).")
@click.option(
    "--salt-position",
    type=click.Choice(["prepend", "append"]),
    default="prepend",
    help="Dónde va la sal manual respecto al candidato.",
)
@click.option(
    "--algorithm", "forced_algorithm",
    default=None,
    help="Forzar el algoritmo en vez de autodetectar con hashid (útil si la detección es ambigua).",
)
@click.option("--processes", type=int, default=None, help="Cantidad de procesos (por defecto, todos los núcleos).")
def crack(
    target_hash: str,
    wordlist_path: str | None,
    salt: str,
    salt_position: str,
    forced_algorithm: str | None,
    processes: int | None,
) -> None:
    """Detecta el algoritmo de TARGET_HASH y lo crackea (o lo revierte, si aplica)."""

    if forced_algorithm:
        algorithm = forced_algorithm
        console.print(f"Algoritmo forzado por el usuario: [bold cyan]{algorithm}[/bold cyan]")
    else:
        candidates = identify_hash(target_hash)
        if not candidates:
            console.print(f"[red]hashid no pudo identificar el algoritmo de:[/red] {target_hash}")
            console.print("Probá con --algorithm si ya sabés qué formato es.")
            sys.exit(1)
        best = candidates[0]
        algorithm = best.algorithm
        console.print(
            f"Algoritmo detectado: [bold cyan]{algorithm}[/bold cyan] "
            f"(confianza: {best.confidence}, vía hashid)"
        )

    if algorithm.startswith("Cisco IOS Type 7"):
        plaintext = CiscoType7Reverser().reverse(target_hash)
        console.print(f"[bold green]Revertido directamente (sin búsqueda):[/bold green] {plaintext}")
        return

    effective_target = target_hash

    if algorithm in _RAW_ATTACK_BUILDERS:
        attack = _RAW_ATTACK_BUILDERS[algorithm](salt, salt_position)
    elif algorithm in _SALTED_ATTACK_CLASSES:
        attack = _SALTED_ATTACK_CLASSES[algorithm](target_hash)
    elif algorithm.startswith("JWT"):
        attack = JWTSecretAttack(target_hash)
        effective_target = jwt_signature(target_hash)
    else:
        console.print(f"[yellow]Todavía no hay un ataque implementado para:[/yellow] {algorithm}")
        sys.exit(1)

    wordlist_path = wordlist_path or _DEFAULT_WORDLIST
    try:
        with open(wordlist_path, encoding="utf-8", errors="ignore") as f:
            wordlist_lines = f.readlines()
    except FileNotFoundError:
        console.print(f"[red]No se encontró el wordlist:[/red] {wordlist_path}")
        console.print("Pasá --wordlist con una ruta válida, o corré desde la raíz del proyecto.")
        sys.exit(1)

    console.print(f"Probando contra [bold]{len(wordlist_lines)}[/bold] candidatos de {wordlist_path}...")

    def on_progress(attempts: int, elapsed: float) -> None:
        rate = attempts / elapsed if elapsed > 0 else 0
        print(f"\r  {attempts} intentos — {elapsed:.1f}s — {rate:,.0f} hashes/seg   ", end="", flush=True)

    result = run_dictionary_attack(
        attack=attack,
        target_hash=effective_target,
        wordlist=wordlist_lines,
        processes=processes,
        on_progress=on_progress,
    )
    print()

    if result.found:
        console.print(f"[bold green]¡Encontrado![/bold green] {result.plaintext}")
    else:
        console.print("[red]No se encontró en el wordlist.[/red]")

    if result.elapsed_seconds > 0:
        rate = result.attempts / result.elapsed_seconds
        console.print(f"{result.attempts} intentos en {result.elapsed_seconds:.2f}s ({rate:,.0f} hashes/seg)")

    if not result.found:
        sys.exit(1)


if __name__ == "__main__":
    main()