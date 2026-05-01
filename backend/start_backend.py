"""
Start FastAPI backend with auto worker scaling.

Worker selection priority:
1) WEB_CONCURRENCY env var (manual override)
2) Auto from CPU cores, clamped between MIN_WORKERS and MAX_WORKERS
"""
import os
import socket
import uvicorn


def _safe_int(value: str | None, default: int) -> int:
    try:
        if value is None:
            return default
        return int(value)
    except (TypeError, ValueError):
        return default


def pick_workers() -> int:
    # On Windows, uvicorn multi-worker mode can fail with socket errors
    # (e.g. WinError 10022) depending on Python/Uvicorn versions.
    # Use a single worker for reliable local development startup.
    if os.name == "nt":
        return 1

    # Manual override first (recommended in production if known).
    manual = _safe_int(os.getenv("WEB_CONCURRENCY"), 0)
    if manual > 0:
        return manual

    cpu_cores = os.cpu_count() or 2
    min_workers = max(1, _safe_int(os.getenv("MIN_WORKERS"), 2))
    max_workers = max(min_workers, _safe_int(os.getenv("MAX_WORKERS"), 8))

    # Balanced default for this app: 1 worker per core, clamped.
    return max(min_workers, min(cpu_cores, max_workers))


def _safe_host(host: str | None) -> str:
    """
    Validate bind host and fallback for invalid values.

    On Windows, a malformed HOST env var can raise getaddrinfo errors
    during uvicorn bind (e.g. [Errno 11001] getaddrinfo failed).
    """
    candidate = (host or "").strip()
    if not candidate:
        return "127.0.0.1" if os.name == "nt" else "0.0.0.0"

    try:
        socket.getaddrinfo(candidate, 0)
        return candidate
    except OSError:
        fallback = "127.0.0.1" if os.name == "nt" else "0.0.0.0"
        print(f"Invalid HOST='{candidate}', falling back to {fallback}")
        return fallback


if __name__ == "__main__":
    host = _safe_host(os.getenv("HOST", "0.0.0.0"))
    port = _safe_int(os.getenv("PORT"), 8000)
    workers = pick_workers()

    print(f"Starting backend on {host}:{port} with workers={workers}")
    uvicorn.run("app.main:app", host=host, port=port, workers=workers)

