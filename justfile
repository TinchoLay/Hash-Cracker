# justfile — atajos de comandos para el proyecto hashcrack
# Uso: just <nombre-del-atajo>, ej. "just test"

install:
    uv sync

test:
    uv run pytest -v

demo:
    uv run hashcrack crack 5d41402abc4b2a76b9719d911017c592

demo-cisco:
    uv run hashcrack crack 094F471A1A0A

lint:
    uv run ruff check .

clean:
    Remove-Item -Recurse -Force .pytest_cache -ErrorAction SilentlyContinue
    Get-ChildItem -Recurse -Directory -Filter __pycache__ | Remove-Item -Recurse -Force