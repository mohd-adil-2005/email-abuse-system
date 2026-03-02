import time
import random
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests


URL = "http://127.0.0.1:8000/check_registration"
TOTAL_REQUESTS = 500
MAX_WORKERS = 50


def make_request(i: int) -> int | None:
    """Send a single test request and return HTTP status or None on error."""
    email = f"loadtest{i}@example.com"
    phone = f"+9198{random.randint(10_000_000, 99_999_999)}"
    payload = {"email": email, "phone": phone}
    try:
        resp = requests.post(URL, json=payload, timeout=5)
        return resp.status_code
    except Exception:
        return None


def main() -> None:
    print(f"Target URL: {URL}")
    print(f"Total requests: {TOTAL_REQUESTS}, concurrency: {MAX_WORKERS}")

    start = time.perf_counter()
    statuses: list[int | None] = []

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = [executor.submit(make_request, i) for i in range(TOTAL_REQUESTS)]
        for f in as_completed(futures):
            statuses.append(f.result())

    duration = time.perf_counter() - start
    success = sum(1 for s in statuses if s is not None and 200 <= s < 500)
    failed = TOTAL_REQUESTS - success
    rps = TOTAL_REQUESTS / duration if duration > 0 else 0.0

    print(f"\nCompleted in {duration:.2f} seconds")
    print(f"Approx RPS: {rps:.1f}")
    print(f"Successful responses: {success}")
    print(f"Failed/errored requests: {failed}")


if __name__ == "__main__":
    main()

