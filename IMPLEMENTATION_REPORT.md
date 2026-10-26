# SecureTrack — Stage 3 Implementation Report

**Date:** 2026-10-26

**Scope:** Stage 3 only — core parser, detection engine, export security, automated tests, and benchmarks.

**Status:** Stage 3 complete. No Stage 4 UI redesign has been started. Work is intentionally stopped pending approval.

---

## 1. Summary

Stage 3 replaces the original quadratic detection path with a transparent episode scanner, hardens CSV ingestion, adds safe CSV exports, and builds an adversarial test suite around the three modules.

The application behaviour is intentionally unchanged in scope:

- no AI/ML;
- no automatic blocking, account lockout, or response actions;
- no fabricated risk scores;
- thresholds and evidence remain visible and configurable;
- failed-login activity is reported as patterns for human review, not proof of an attack.

The current app remains a local academic prototype.

---

## 2. Environment and baseline

| Item | Value |
|---|---|
| Python | 3.14.2 |
| pandas | 2.3.3 |
| Streamlit | 1.50.0 |
| Plotly | 7.1.0 |
| pytest | 8.4.2 |
| NumPy | 2.5.3 |
| Platform | Windows (win32) |

Git was initialised before implementation. The rollback baseline is commit `4d5c686`:

```text
Baseline: SecureTrack before Stage 3 core optimization
```

All Stage 3 changes are committed in this repository; no Stage 4 UI work has been performed.

---

## 3. What changed

### 3.1 Parser — `core/parser.py`

The parser now has a documented, strict input contract:

- UTF-8 or UTF-8 with BOM only;
- comma-separated CSV;
- required columns: `timestamp`, `username`, `ip_address`, `status`;
- header names are trimmed and case-normalised;
- `status` is trimmed and uppercased, then restricted to `SUCCESS` or `FAILED`;
- usernames are trimmed, empty values rejected, control characters rejected, and length capped at 256 characters;
- IPv4 and IPv6 are accepted through `ipaddress.ip_address`; ports/CIDR values are rejected;
- timestamps must be ISO 8601 (`YYYY-MM-DD`, space or `T` separator, fractional seconds, `Z`, or numeric offset);
- naive timestamps are treated as UTC and all timestamps are normalised to `datetime64[ns, UTC]`.

Safety limits are enforced inside the parser as well as in the UI:

```text
MAX_UPLOAD_BYTES      5 MiB
MAX_DATA_ROWS         50,000
MAX_COLUMNS           50
MAX_ERRORS_RECORDED   500
MAX_USERNAME_LENGTH   256
```

Additional hardening:

- NUL bytes and invalid UTF-8 are rejected;
- duplicate headers are rejected before pandas can silently rename them;
- missing columns produce a specific error;
- blank lines are skipped without losing physical CSV line numbers;
- `source_row = original physical row` is preserved for evidence traceability;
- a malformed row with only an extra-column value is reported as invalid, not silently treated as blank;
- quoted newlines are rejected because they would make logical pandas row numbers diverge from physical CSV lines and corrupt `source_row`;
- per-row error reasons are capped at 500;
- parser error messages do not echo raw uploaded values.

The parser returns:

```text
data, errors, meta
```

where `meta` contains source name, byte size, data/valid/skipped/blank counts, error count, truncation flag, UTC time range, and `timezone="UTC"`.

### 3.2 Detection — `core/detection.py`

The detector now reports one alert per qualifying episode rather than one alert per qualifying event.

Implementation properties:

- failed events are grouped by entity;
- each group is sorted by timestamp and source row;
- a two-pointer scan finds maximal qualifying episodes;
- the strongest qualifying window is recorded separately as the peak window;
- evidence is materialised once per closed episode;
- scan work is linear in the number of failed events per group; the remaining sort is `O(n log n)`;
- input timestamps are normalised to UTC even for direct callers, so alerts and evidence always use UTC;
- alert IDs are assigned after sorting and are unique per analysis run.

Rules:

| Rule | Behaviour |
|---|---|
| `R1_IP_FAILURES` | Repeated failed logins from one IP |
| `R2_ACCOUNT_FAILURES` | Repeated failed logins against one username |
| `R3_ACCOUNT_SPRAY` | Multiple distinct usernames targeted by one IP |

Severity remains a transparent volume indicator:

- High when the peak reaches at least twice the configured threshold;
- Medium otherwise.

Alert fields include:

```text
alert_id, rule_id, alert_type, entity_type, entity_value,
severity, start_time, end_time, event_count,
peak_window_count / peak_distinct_accounts,
peak_window_start, peak_window_end,
distinct_source_ips / distinct_accounts,
threshold, window_minutes, description, evidence
```

Validation now raises a concise `ValueError` for:

- non-DataFrame input;
- missing required columns;
- non-datetime timestamps;
- null required values;
- invalid statuses;
- threshold/spray-user values below 2 or non-integers;
- non-positive or non-finite windows.

The app catches detection errors and displays an actionable message instead of a traceback.

### 3.3 Safe exports — `core/export.py`

New module with stable report builders:

- `alert_summary_frame()` — stable alert-summary columns, no evidence payload;
- `evidence_frame()` — long-form evidence table with `alert_id`, rule, severity, entity, source row, and event fields;
- `dataframe_to_safe_csv()` — UTF-8-with-BOM CSV bytes after sanitisation;
- `sanitize_spreadsheet_cell()` — prefixes formula-like text with an apostrophe.

Spreadsheet-injection handling:

- dangerous leading characters: `=`, `+`, `-`, `@`, tab, carriage return;
- leading whitespace is ignored when deciding;
- leading BOM and zero-width space are also ignored before checking;
- only string values are changed;
- exports operate on copies, so in-memory analysis data is never mutated;
- usernames beginning with a spreadsheet formula character remain intact for analysis but are neutralised in every CSV download.

Exports include:

- filtered log CSV;
- alert summary CSV;
- all-evidence CSV;
- per-alert evidence CSV.

### 3.4 Application wiring — `app.py`

The UI was only minimally rewired for the new core contracts; it was not redesigned.

- parser metadata shown near the header (source, valid/skipped counts, UTC range);
- upload size limit enforced before parsing;
- validation errors shown with a capped error table;
- detection errors caught;
- alert summary and evidence downloads use safe CSV exports;
- alert details show episode count, peak window, severity explanation, thresholds, and evidence;
- rule descriptions updated to reflect episode semantics and the absence of automatic blocking;
- Streamlit dataframe width calls updated to `width="stretch"` to remove deprecation warnings on the installed Streamlit version.

`requirements.txt` was updated from `streamlit>=1.35` to `streamlit>=1.50` to match the installed API used by the app.

---

## 4. Automated tests

Command:

```powershell
python -m pytest -q -W error
```

Result:

```text
100 passed
```

Coverage by area:

### Parser

- valid CSV, BOM, header/status normalisation, extra columns;
- blank lines with accurate `source_row`;
- naive timestamp = UTC, mixed offsets normalised to UTC;
- ISO 8601 variants, ambiguous `DD/MM` rejection;
- IPv4, IPv6, port/CIDR rejection;
- invalid UTF-8, NUL bytes, duplicate headers, missing columns;
- upload-size, row, column, and error-list caps;
- control characters, overlong usernames, multiline-field rejection;
- malformed extra-only rows;
- sample dataset metadata and unsupported source types.

### Detection

- exactly-threshold and below-threshold behaviour;
- inclusive window boundary;
- separate episodes with separate evidence;
- one long episode with complete evidence and correct peak;
- account rule with multiple source IPs;
- spray rule, repeated usernames, outside-window cases, severity escalation;
- alert IDs, stable schema, evidence consistency;
- duplicate timestamps, successes ignored, empty frame;
- naive and non-UTC-aware timestamp normalisation;
- optional `source_row`;
- invalid parameters, missing columns, non-datetime timestamps, nulls, invalid statuses, non-DataFrame input;
- 5,000-dense-event performance guard (`< 5 s`).

### Export

- formula prefixes, leading whitespace, BOM/zero-width bypass attempts;
- non-string values unchanged;
- UTF-8 BOM output;
- empty-frame headers;
- stable summary/evidence columns;
- flattening multiple alerts;
- injected values neutralised while in-memory data stays unchanged.

### Integration

- mixed-timezone CSV → parser → timeline operation that previously crashed;
- physical source rows flowing from CSV to alert evidence;
- formula-bearing username preserved for analysis but sanitised in both log and evidence exports.

### App

Streamlit `AppTest` runs the real `app.py`:

```text
exceptions: 0
errors: 0
metrics: Total events=12, Successful=4, Failed=8, Unique IPs=3, Alerts=3
tabs: Overview, Log Explorer, Security Alerts, Detection Rules
dataframes: 6
charts: 2
download buttons: 6
```

The only console message in bare AppTest mode is Streamlit's expected `missing ScriptRunContext` harness warning; it is not an application error.

---

## 5. Benchmarks

Reproduce with:

```powershell
python scripts/benchmark_detection.py
```

Methodology:

- synthetic failed-login events, all from one IP and one username;
- timestamps cycle through a 100-second span, so the dataset is a single dense episode;
- threshold 5 failures / 2 minutes;
- two alerts per run (IP rule and account rule), each carrying all events as evidence;
- median of three runs per size;
- audit baseline from `REPOSITORY_AUDIT.md` (single-run measurement on the same machine before the rewrite);
- 10,000 and 50,000 original-event measurements were not recorded, so they are marked `n/a` rather than estimated.

Final measured result:

| Events | Audit baseline | New median | New min | New max | Speed-up | New time per 1k events | Time ratio vs 1k |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 1,000 | 3.14 s | 0.0171 s | 0.0157 s | 0.0190 s | ≈184× | 17.1 ms | 1.00× |
| 3,000 | 34.71 s | 0.0396 s | 0.0382 s | 0.0401 s | ≈877× | 13.2 ms | 2.32× |
| 6,000 | 137.34 s | 0.0763 s | 0.0724 s | 0.0803 s | ≈1,800× | 12.7 ms | 4.46× |
| 10,000 | n/a | 0.1197 s | 0.1177 s | 0.1252 s | n/a | 12.0 ms | 7.00× |
| 50,000 | n/a | 0.6011 s | 0.5863 s | 0.7024 s | n/a | 12.0 ms | 35.2× |

Interpretation:

- 6,000 dense events now complete in **0.0763 s**, against the Stage 3 acceptance target of `< 2 s` and the audit baseline of **137.34 s**.
- 10,000 events take **0.1197 s**.
- 50,000 events, the parser's row limit, take **0.6011 s**.
- Ten times the events cost about seven times the runtime; fifty times the events cost about thirty-five times the runtime. Per-1,000-event cost is essentially flat at roughly 12–17 ms.
- The original implementation copied evidence on every qualifying event, producing approximately `O(n²)` work. The new implementation scans each entity's failed events with two pointers and materialises evidence once per episode; the measured scaling is consistent with near-linear behaviour.

An additional end-to-end check on 10,000 dense events measured approximately:

```text
parse:  0.045 s
detect: 0.130 s
export: 0.205 s
```

This is a sanity check, not a formal benchmark. It also shows that export size can grow because evidence is intentionally duplicated across rules that describe the same events.

---

## 6. Changed files

### Modified

| File | Diff |
|---|---|
| `app.py` | +132 / −23 |
| `core/detection.py` | +452 / −50 |
| `core/parser.py` | +381 / −28 |
| `requirements.txt` | +1 / −1 |
| `tests/test_detection.py` | +427 / −10 |
| `tests/test_parser.py` | +350 / −5 |

Tracked-file diff: **1,743 insertions, 117 deletions across 6 files**.

### New

| File | Lines | Purpose |
|---|---:|---|
| `core/export.py` | 98 | Safe CSV exports and report builders |
| `scripts/benchmark_detection.py` | 64 | Reproducible dense-event benchmark |
| `tests/test_export.py` | 175 | Export/sanitisation tests |
| `tests/test_app.py` | 34 | Streamlit smoke and alert-table tests |
| `tests/test_integration.py` | 68 | Parser → detection → export integration tests |

No changes were made to `README.md` or the Stage 1/2 reports in this stage; documentation updates are Stage 5 work.

---

## 7. Acceptance checklist

| Requirement | Status |
|---|---|
| Modular architecture preserved | Met — parser/detection/export remain separate core modules |
| No UI redesign | Met — only core wiring and deprecation cleanup |
| No unnecessary dependencies or AI/ML | Met — no new dependencies |
| No automatic blocking/lockout | Met — not implemented |
| Configurable thresholds | Met — IP/account threshold and window, spray threshold and window |
| Evidence for every alert | Met — episode evidence with `source_row` when available |
| Normal and adversarial inputs tested | Met — 100 tests including formula injection, malformed CSV, limits, invalid parameters |
| 1k/3k/6k/10k benchmark | Met — plus 50k row-limit check |
| Compare with audit measurements | Met — audit baseline included |
| No quadratic scaling | Met — two-pointer scanner and measured near-linear scaling |
| Full test suite | Met — 100 passed with warnings-as-errors |
| App smoke test | Met — AppTest reports zero exceptions/errors |
| Implementation report | Met — this document |
| Stop before Stage 4 | Met — no Stage 4 work started |

---

## 8. Unresolved issues and deliberate limitations

These are known, accepted, or deferred. None block Stage 3 acceptance.

1. **Stage 4 UI work is intentionally pending**
   - The sample/upload control still has the old no-op behaviour when an upload is active.
   - The app still auto-loads the sample dataset when no upload is present.
   - There is no upload reset/clear control.
   - Reparsing occurs on reruns; result caching is deferred.
   - The alert summary still exposes several rule-specific columns with empty values; presentation should be cleaned up in Stage 4.
   - No visual redesign or theme changes were made.

2. **Streamlit version floor**
   - `requirements.txt` now requires Streamlit `>=1.50` because the app uses `st.dataframe(width="stretch")`.
   - `st.plotly_chart` still uses `use_container_width=True`; it did not emit a deprecation warning with the installed version. Review this in Stage 4 when the UI is touched.

3. **Multiline CSV fields are rejected by design**
   - This preserves accurate physical `source_row` evidence.
   - Login activity logs do not need multiline field values; the limitation is explicit rather than silently corrupting traceability.

4. **Evidence duplication across rules**
   - An event can legitimately appear in the IP alert and the account alert for the same episode.
   - This is intentional for independent evidence, but exports can be larger than the input CSV. A 10,000-event dense case produced about 3.8 MB of evidence CSV in the sanity check.

5. **No live monitoring or response**
   - SecureTrack analyses uploaded/sample files only.
   - It does not monitor live traffic, block addresses, lock accounts, or confirm attacks.

6. **Local prototype assumptions**
   - No authentication, multi-user isolation, or production deployment hardening is included.
   - The recommendation to use only synthetic or authorised anonymised logs remains in force.

---

## 9. Reproduce

```powershell
python -m pytest -q -W error
python scripts\benchmark_detection.py
streamlit run app.py
```

For a rollback point before Stage 3, use the Git baseline `4d5c686`. Stage 3 changes are ready for review and have not been followed by any Stage 4 work.
