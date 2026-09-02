"""Motor de multiprocessing: reparte una lista de candidatos entre
varios procesos y corre un Attack contra cada uno, hasta encontrar
una coincidencia o agotar todos los candidatos.

Se usa multiprocessing (procesos reales del sistema operativo) en vez
de threading, porque calcular hashes es trabajo intensivo de CPU — el
GIL de Python impide que varios hilos ejecuten cálculo en paralelo de
verdad dentro de un mismo proceso, así que threading no aceleraría
nada acá. Varios procesos sí usan varios núcleos físicos.

Detalle importante de diseño: un multiprocessing.Event (o Lock) NO se
puede mandar como parte de una tarea normal a un Pool — Pool reusa un
grupo fijo de procesos y les manda tareas por una cola, y esa cola no
sabe serializar ese tipo de objeto. Los objetos de sincronización solo
se pueden transmitir en el momento exacto en que un proceso se está
creando. Por eso acá se los pasa una sola vez, vía el `initializer`
del Pool, y cada proceso los guarda en una variable global propia
(_worker_state) para reusarlos en cada tarea que le llegue después.

Sesión 6: se agregó un callback opcional on_progress, para que la CLI
pueda mostrar avance en vivo (intentos, tiempo, hashes/segundo)
mientras el ataque corre. Es un agregado aditivo — sin on_progress, el
comportamiento es idéntico al de las sesiones anteriores.
"""

import multiprocessing as mp
import os
import time
from collections.abc import Callable, Iterable

from hashcrack.attacks.base import Attack
from hashcrack.models import CrackResult

_worker_state: dict = {}


def _init_worker(attack: Attack, target_hash: str, found_event, counter) -> None:
    """Se ejecuta una única vez por proceso, al momento de crearlo."""
    _worker_state["attack"] = attack
    _worker_state["target_hash"] = target_hash
    _worker_state["found_event"] = found_event
    _worker_state["counter"] = counter


def _chunk(items: list[str], n_chunks: int) -> list[list[str]]:
    """Divide items en como mucho n_chunks partes, lo más parejas posible."""
    if n_chunks <= 0:
        n_chunks = 1
    size = max(1, -(-len(items) // n_chunks))
    return [items[i : i + size] for i in range(0, len(items), size)]


def _worker(candidates: list[str]) -> str | None:
    """Corre en un proceso separado: prueba cada candidato de su
    porción hasta encontrar una coincidencia, o hasta que otro
    proceso ya haya avisado (found_event) que la encontró primero.
    """
    attack: Attack = _worker_state["attack"]
    target_hash: str = _worker_state["target_hash"]
    found_event = _worker_state["found_event"]
    counter = _worker_state["counter"]

    for candidate in candidates:
        if found_event.is_set():
            return None

        with counter.get_lock():
            counter.value += 1

        if attack.hash_candidate(candidate) == target_hash:
            found_event.set()
            return candidate

    return None


def run_dictionary_attack(
    attack: Attack,
    target_hash: str,
    wordlist: Iterable[str],
    processes: int | None = None,
    on_progress: Callable[[int, float], None] | None = None,
    progress_interval: float = 0.2,
) -> CrackResult:
    """Prueba cada palabra de wordlist contra target_hash usando attack,
    repartiendo el trabajo entre varios procesos.

    Si se pasa on_progress, se llama periódicamente (cada
    progress_interval segundos) con (intentos_hasta_ahora,
    segundos_transcurridos) mientras el ataque sigue corriendo — útil
    para mostrar una barra o contador en vivo en la CLI.
    """
    candidates = [w.strip() for w in wordlist if w.strip()]

    if not candidates:
        return CrackResult(
            found=False, plaintext=None, attempts=0,
            elapsed_seconds=0.0, attack_name=attack.name,
        )

    processes = processes or os.cpu_count() or 1
    chunks = _chunk(candidates, processes)

    found_event = mp.Event()
    counter = mp.Value("l", 0)

    start = time.perf_counter()
    plaintext_found: str | None = None

    with mp.Pool(
        processes=len(chunks),
        initializer=_init_worker,
        initargs=(attack, target_hash, found_event, counter),
    ) as pool:
        async_results = [pool.apply_async(_worker, (chunk,)) for chunk in chunks]

        if on_progress is not None:
            while not all(ar.ready() for ar in async_results):
                on_progress(counter.value, time.perf_counter() - start)
                time.sleep(progress_interval)

        for async_result in async_results:
            result = async_result.get()
            if result is not None:
                plaintext_found = result

    elapsed = time.perf_counter() - start

    return CrackResult(
        found=plaintext_found is not None,
        plaintext=plaintext_found,
        attempts=counter.value,
        elapsed_seconds=elapsed,
        attack_name=attack.name,
    )