# RPS Improvement Explanation (89 RPS to 351 RPS)

Great question - this is exactly the kind of thing faculty ask.

Here is an easy, complete explanation of how the system improved from around **89 RPS to 351 RPS**.

---

## First, what is RPS?

- **RPS = Requests Per Second**
- If RPS increases, your API handles more users in the same time.

---

## Main reasons RPS improved

## 1) Increased backend workers (biggest reason)

### Before
- Server was likely running with fewer workers (1 or 2).

### After
- Optimized run uses:
- `uvicorn ... --workers 4` (from `run_backend_optimized.bat`)

### Why it helps
- Each worker is a separate process.
- More workers = more requests handled in parallel.
- This usually gives the biggest throughput jump.

---

## 2) SQLite tuned for concurrency

In `database.py`, these SQLite optimizations are enabled:

- `PRAGMA journal_mode=WAL`
- `PRAGMA synchronous=NORMAL`
- Increased cache size

### Why it helps
- WAL mode improves simultaneous read/write behavior.
- Less lock waiting under load.
- Faster DB operations during high traffic.

Because `/check_registration` writes to DB, this optimization matters a lot.

---

## 3) ML model preloaded at startup

In `main.py` startup:
- `load_spam_model()` is called once.

### Why it helps
- Model is already in memory before traffic starts.
- No model-loading delay during active requests.
- Lower request latency.

---

## 4) High rate-limit for `/check_registration`

The route has a high limit (`10000/minute`) for throughput testing.

### Why it helps
- Requests are not throttled too early during load testing.
- Measured RPS reflects real backend capacity.

---

## 5) Efficient load-test client setup

In `load_test_rps.py`:
- 50 concurrent workers (`ThreadPoolExecutor(max_workers=50)`)
- Per-thread `requests.Session()` reuse

### Why it helps
- Reused HTTP connections reduce overhead.
- Better test quality, less client-side bottleneck.
- Server gets stressed properly, so measured throughput is more realistic.

---

## Easy summary formula

**Higher workers + DB concurrency tuning + model preload + proper load-test setup = large RPS gain**

---

## Why jump is roughly 4x (89 -> 351)?

- 351 is about **3.9x** of 89.
- This is consistent with moving close to 4-worker parallel processing (with practical overhead).
- So the result is technically believable.

---

## Viva-ready answer (30 seconds)

"RPS improve mainly because we changed runtime and concurrency setup. We run Uvicorn with 4 workers, so requests are processed in parallel. We also optimized SQLite using WAL mode and cache settings, reducing DB lock delays during heavy writes. We preload the ML model at startup so request-time latency is lower. In load testing we use concurrent threads and connection reuse, with a high route limit to avoid artificial throttling. Combined effect increased performance from around 89 RPS to about 351 RPS."

