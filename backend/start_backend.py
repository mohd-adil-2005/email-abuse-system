"""
Start FastAPI backend with auto worker scaling.

Worker selection priority:
1) WEB_CONCURRENCY env var (manual override)
2) Auto from CPU cores, clamped between MIN_WORKERS and MAX_WORKERS
"""
import os
import uvicorn


def _safe_int(value: str | None, default: int) -> int:
    try:
        if value is None:
            return default
        return int(value)
    except (TypeError, ValueError):
        return default


def pick_workers() -> int:
    # Manual override first (recommended in production if known).
    manual = _safe_int(os.getenv("WEB_CONCURRENCY"), 0)
    if manual > 0:
        return manual

    cpu_cores = os.cpu_count() or 2
    min_workers = max(1, _safe_int(os.getenv("MIN_WORKERS"), 2))
    max_workers = max(min_workers, _safe_int(os.getenv("MAX_WORKERS"), 8))

    # Balanced default for this app: 1 worker per core, clamped.
    return max(min_workers, min(cpu_cores, max_workers))


if __name__ == "__main__":
    host = os.getenv("HOST", "0.0.0.0")
    port = _safe_int(os.getenv("PORT"), 8000)
    workers = pick_workers()

    print(f"Starting backend on {host}:{port} with workers={workers}")
    uvicorn.run("app.main:app", host=host, port=port, workers=workers)

