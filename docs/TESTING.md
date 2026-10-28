# SecureTrack — Testing & Verification Guide

**Application:** SecureTrack — Login Activity Analyzer & Suspicious Login Detection System  
**Test Framework:** pytest $\ge 8.0$  
**Total Test Count:** **112 tests** (100% passing, 0 warnings with `-W error`)  
**Execution Time:** ~4.7 seconds

---

## 1. Test Setup & Execution

### Prerequisites

All test dependencies are specified in `requirements.txt`:
```powershell
pip install -r requirements.txt
```

### Running the Full Test Suite

Run pytest with warnings treated as errors to guarantee no deprecated calls or runtime warnings:

```powershell
# Standard quiet test run with strict warnings check
python -m pytest -q -W error

# Verbose test run displaying individual test cases
python -m pytest -v
```

### Running Specific Test Modules

```powershell
# Core parser tests
python -m pytest tests/test_parser.py -v

# Core detection algorithm tests
python -m pytest tests/test_detection.py -v

# Core export & formula sanitization tests
python -m pytest tests/test_export.py -v

# End-to-end integration tests
python -m pytest tests/test_integration.py -v

# UI filtering & helper tests
python -m pytest tests/test_ui_filters.py -v

# Streamlit AppTest interface tests
python -m pytest tests/test_app.py -v
```

---

## 2. Test Architecture & Coverage Breakdown

The test suite covers unit, integration, security, and presentation layers without mock shortcuts:

```text
tests/
├── test_parser.py       # 33 tests — Ingestion, bounds, encodings, malformed inputs
├── test_detection.py    # 41 tests — Sliding windows, episode merging, spray, types
├── test_export.py       # 21 tests — Spreadsheet formula injection, safe schemas
├── test_integration.py #  3 tests — End-to-end pipeline, mixed timezones, tracing
├── test_ui_filters.py   #  8 tests — Filter predicates, timeline bucketing, selection
└── test_app.py          #  6 tests — Streamlit AppTest lifecycle, state transitions
---------------------------------------------------------------------------------
Total:                  # 112 tests
```

### 2.1 Parser Tests (`tests/test_parser.py` — 33 tests)
- **Format & Encoding:** Valid UTF-8, UTF-8 with BOM, rejection of non-UTF8 bytes, rejection of NUL bytes (`\0`).
- **Resource Limits:** Enforcement of 5 MB upload limit, 50,000 data row limit, 50 column limit, and error list truncation at 500 rows.
- **Malformed Input Resilience:** Empty files, whitespace-only files, header-only files, duplicate headers (including case differences like `username` vs `Username`), missing required headers.
- **Field-Level Validation:** Rejection of IP addresses containing port numbers, acceptance of valid IPv4 and IPv6 addresses, control characters in usernames, overlong usernames (>256 characters), ambiguous dates.
- **Line Traceability & Invariants:** Strict rejection of multiline quoted fields in data and headers to ensure 1:1 physical line numbering; correct handling of blank lines without row skewing.

### 2.2 Detection Engine Tests (`tests/test_detection.py` — 41 tests)
- **Sliding-Window Boundaries:** Inclusive window boundaries ($(t_{right} - t_{left}) \le W$), events outside window boundary resulting in no alert.
- **Episode Segmentation:** Multiple qualifying episodes separated by quiet intervals produce distinct alerts; continuous qualifying bursts form one consolidated episode.
- **Peak Metrics & Severity Escalation:** Verification that peak counts reflect the densest sub-window; escalation to `High` severity when peak $\ge 2 \times \text{threshold}$, and `Medium` otherwise.
- **Account-Spray Rule:** Multiple accounts targeted from one IP, window expiry, repeated attempts against identical usernames not inflating distinct count, multi-episode spray scenarios.
- **Data Normalization & Input Validation:** Naive timestamps treated as UTC, mixed-offset timestamps normalized, strict rejection of non-DataFrame inputs, missing columns, null values, invalid statuses, non-positive integer/float thresholds.
- **Performance Guard:** Algorithmic verification that 1,000 events execute in under 0.5s.

### 2.3 Safe Export Tests (`tests/test_export.py` — 21 tests)
- **Formula Injection Matrix:** Tests against formula trigger prefixes (`=`, `+`, `-`, `@`, `\t`, `\r`).
- **Bypass Evasion Tests:** Leading whitespace bypasses (e.g. ` =1+1`), leading zero-width/BOM bypasses (e.g. `\ufeff=1+1`, `\u200b@SUM(A1)`).
- **In-Memory Immutability:** Verification that sanitization only modifies exported copies and leaves in-memory analysis DataFrames unmutated.
- **Export Formats:** UTF-8-BOM (`utf-8-sig`) header presence; schema stability for alert summaries and flattened evidence tables.

### 2.4 Integration Tests (`tests/test_integration.py` — 3 tests)
- **End-to-End Ingestion to Export:** Full workflow from parsing a CSV containing mixed UTC offsets through sliding-window detection to safe export generation.
- **Source-Row Integrity:** Verifies that physical CSV line numbers propagate accurately into alert evidence dictionaries and exported evidence CSVs.
- **Formula Preservation:** Verifies that a username like `=cmd|' /C calc'!A0` is analyzed accurately in memory without disruption, yet safely neutralized on export.

### 2.5 UI Filter Tests (`tests/test_ui_filters.py` — 8 tests)
- **Filter Logic:** Case-insensitive substring matching for usernames and IP addresses; status filtering.
- **Date Handling:** Inclusive UTC day boundaries for date range selection; empty status and reversed date range safety.
- **Alert Selection:** Ensuring exploration filters select which alerts are displayed without mutating or re-running core detection.
- **Timeline Bucketing:** Adaptive time-bucket selection (minute, 5-minute, 15-minute, hour, day) based on span duration.

### 2.6 Streamlit App Tests (`tests/test_app.py` — 6 tests)
- Utilizes Streamlit's official headless test framework (`streamlit.testing.v1.AppTest`).
- Verifies sample dataset loads cleanly without unhandled exceptions or rendering errors.
- Verifies alert summary tables and metric counts.
- Verifies that clearing the dataset and reloading the sample properly wipes stale state.
- Verifies interactive filtering by username and status within the live application environment.

---

## 3. Verified Test Suite Results

```text
============================= test session starts =============================
platform win32 -- Python 3.14.2, pytest-8.4.2, pluggy-1.6.0
rootdir: D:\SecureTrack_Project\SecureTrack
plugins: anyio-4.15.1, platformdirs-4.13.0
collected 112 items

tests/test_app.py ......                                                 [  5%]
tests/test_detection.py .........................................        [ 41%]
tests/test_export.py .....................                               [ 60%]
tests/test_integration.py ...                                            [ 63%]
tests/test_parser.py .................................                   [ 92%]
tests/test_ui_filters.py ........                                       [100%]

============================= 112 passed in 4.66s =============================
```

---

## 4. Performance Benchmark & Empirical Results

The empirical benchmark script `scripts/benchmark_detection.py` measures detection execution time against dense failed-login episodes (a single IP/account generating thousands of failures within a 100-second window):

```powershell
python scripts/benchmark_detection.py
```

### Benchmark Results Comparison

| Dense Event Count | Stage 1 Baseline (Audit) | Stage 4 Implemented | Speedup / Scale Factor |
|---|---|---|---|
| **1,000 events** | 3.14 s | **0.017 s** | ~184x faster |
| **3,000 events** | 34.71 s | **0.042 s** | ~826x faster |
| **6,000 events** | 137.34 s (app frozen) | **0.079 s** | ~1,738x faster |
| **10,000 events** | *Failed / Timeout* | **0.125 s** | Linear scaling |
| **50,000 events** | *Failed / Timeout* | **0.610 s** | Full dataset capacity |

### Benchmark Analysis
- The pre-optimization Stage 1 baseline suffered from quadratic complexity ($O(N^2)$) due to copying and appending evidence for every qualifying sub-window.
- The Stage 4 implementation uses a two-pointer sliding window with episode boundary detection, achieving true linear complexity ($O(N)$) for episode scanning and $O(N \log N)$ for the complete sorted pipeline.
- Even at the system's maximum capacity of 50,000 rows, detection completes in approximately 0.6 seconds.
