# SecureTrack — Stage 3 and Stage 4 Implementation Report

**Date:** 2026-10-28

**Scope:** Stage 3 core hardening (parser, detection, and export) plus Stage 4 UI/UX delivery. Stage 4 changes only the presentation layer and its tests; the approved `core/` modules were not modified.

**Status:** Stage 4 complete. Work is intentionally stopped before Stage 5 (README and final documentation).

---

## 1. Summary

Stage 3 replaces the original quadratic detection path with a transparent episode scanner, hardens CSV ingestion, adds safe CSV exports, and builds an adversarial test suite around the three core modules.

Stage 4 adds a restrained light interface for dataset selection, exploration, alert review, and evidence inspection. It fixes the sample/upload/clear state machine, removes stale-result paths, adds filters and responsive layouts, and makes every alert auditable from the screen.

The application behaviour remains intentionally limited:

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

Stage 3 is committed as `eea9586`. Stage 4 is the follow-up change set in this working tree and is committed separately after this report. No `core/` file changed during Stage 4.

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

### 3.4 Stage 3 application wiring — `app.py`

Stage 3 minimally rewired the UI for the new core contracts:

- parser metadata shown near the header (source, valid/skipped counts, UTC range);
- upload size limit enforced before parsing;
- validation errors shown with a capped error table;
- detection errors caught;
- alert summary and evidence downloads use safe CSV exports;
- alert details show episode count, peak window, severity explanation, thresholds, and evidence;
- rule descriptions updated to reflect episode semantics and the absence of automatic blocking;
- Streamlit dataframe width calls updated to `width="stretch"` to remove deprecation warnings on the installed Streamlit version.

`requirements.txt` was updated from `streamlit>=1.35` to `streamlit>=1.50` to match the installed API used by the app.

### 3.5 Stage 4 UI/UX — `app.py`, `ui/`, `.streamlit/`

Stage 4 replaces the temporary Stage 3 presentation with a complete, restrained exploration interface. The approved parser, detector, and export builders are untouched.

**Dataset lifecycle and stale-result prevention**

- A session state machine has three explicit modes: `sample` (default), `upload`, and `none`.
- An uploaded file takes precedence over the sample.
- `Load sample` increments the uploader nonce, clears the file input, and returns to the sample. It now genuinely loads the sample from every state.
- `Clear dataset` returns a true empty state; it does not silently fall back to the sample.
- Removing an active upload moves to `none` and clears results, filters, and dataset identity.
- Dataset identity is `sample:<mtime_ns>:<size>` or `upload:<sha256>`, so replacing a file invalidates results.
- Parsing is cached with `st.cache_data` keyed by raw bytes and source name.
- Detection is memoized by `(dataset_id, threshold, window, spray_users, spray_window)`. Threshold changes re-run detection; filter changes do not.
- Invalid, header-only, oversized, and unreadable datasets show a validation state only. Stale metrics, charts, filters, and alert cards are never rendered.
- The sample is identified as `Sample dataset (fictional)`; uploads show their filename, size, row counts, UTC coverage, and active source badge.

**Exploration filters**

- Username substring search and IP substring search, both case-insensitive.
- Status multiselect with explicit empty-selection behaviour (no events, not all events).
- Inclusive UTC date range using full days.
- Reset Filters callback removes every `filter_` session key.
- Filter state is scoped by a dataset token, so a new dataset starts clean.
- Filters affect Overview metrics captions, both charts, top-source tables, Log Explorer, and which already-detected alerts are displayed.
- Detection always runs on the full active dataset. Evidence in each alert remains the complete episode, even when filters hide some rows.
- A clear caption states that filters do not change top-line metrics.

**Alert presentation**

- Alert summary with stable IDs, priority, rule, entity, start/end, event count, peak, threshold, and window.
- Severity counts for High and Medium priority, plus displayed-alert count.
- Informational badges explain that alerts are review indicators, not confirmed attacks.
- Each alert card states why it fired, the affected IP or account, episode range, peak window, threshold, event count, and relevant distinct-IP/account count.
- Every alert has a separate evidence expander containing source rows, timestamps, accounts, IPs, statuses, and its own safe CSV download.
- No-match and no-alert states explain that no alert does not prove the absence of an attack.

**Visual and responsive treatment**

- Light cybersecurity-academic styling: white surfaces, muted slate text, a restrained blue primary colour, and green/orange status colours.
- No gradients, shadows, oversized metrics, decorative icons, emojis, animations, fake real-time indicators, or AI styling.
- Consistent 8 px card radius, visible borders, readable type scale, and meaningful badges.
- Five metric cards at desktop width; two per row between 480 and 1000 px; one per row below 480 px.
- Dataset and filter blocks wrap naturally on phones; tab labels remain reachable at 390 px.
- Plotly charts use a shared theme, readable fonts, integer event ticks for small datasets, adaptive time buckets, and hidden mode bars.
- The Streamlit toolbar is hidden, the theme is fixed to light, and uploads are capped at 5 MB in `.streamlit/config.toml`.

**Compatibility and accessibility**

- All `use_container_width` usage is gone, including chart calls.
- `width="stretch"` is used for stretch layout where supported.
- Alert and source text is escaped before Markdown rendering.
- `st.badge` is used consistently: dataset/rule/informational states, High = red, Medium = orange.
- The empty state exposes a visible `Load sample dataset` action; every error state offers recovery actions.
- `initial_sidebar_state="auto"` keeps the sidebar usable on desktop and collapsed on narrow phones.

---

## 4. Automated tests

Command:

```powershell
python -m pytest -q -W error
```

Result:

```text
112 passed in 4.79s
```

Stage 3 finished with 100 tests. Stage 4 adds twelve presentation-layer tests and keeps the full suite warnings-as-errors clean.

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

### App and UI

Streamlit `AppTest` runs the real `app.py`:

```text
exceptions: 0
errors: 0
top metrics: Total events=12, Successful=4, Failed=8, Unique IPs=3, Alerts=3
tabs: Overview, Log Explorer, Security Alerts, Detection Rules
dataframes: 7
charts: 2
download buttons: 6
```

The AppTest suite covers the sample smoke path, alert summary rows, clear → reload sample, username filtering across log and alert views, success-only status filtering, and filter reset. Additional pure tests in `tests/test_ui_filters.py` cover status/search/date filtering, full-UTC-day boundaries, source-row preservation, alert selection, display-summary units, and timeline bucket choice.

The only console message in bare AppTest mode is Streamlit's expected `missing ScriptRunContext` harness warning; it is not an application error.

### Stage 4 browser validation

Headless Chrome (Selenium) was used for interaction checks and documentation screenshots:

| Scenario | Result |
|---|---|
| Sample dataset | 12 events, 4 successes, 8 failures, 3 IPs, 3 alerts |
| Sample → upload (`stage4_mixed_alerts.csv`) | 23 events, 3 successes, 20 failures, 5 IPs, 5 alerts; 2 High and 3 Medium |
| Upload → Clear dataset | No dataset state; zero metrics |
| Clear → Load sample | Sample restored with the original metrics |
| Username filter `alex` | 6 of 12 events; 2 of 3 alerts displayed |
| Success-only status filter | 0 alerts displayed; clear recovery action shown |
| Small upload (1 row) | 1 event, 1 success, 0 failures, 1 IP, 0 alerts |
| Large upload (10,000 rows) | 10,000 events, 9,900 successes, 100 failures, 50 IPs, 0 alerts; no qualifying-episode state |
| Header-only upload | Validation error only; no stale metrics |
| Invalid upload | `invalid IP address`; no stale metrics; recovery actions available |
| Downloads | 6 download buttons in the default view; exports use the Stage 3 safe CSV path |
| Narrow phone (390 px) | Sidebar collapsed, single-column metrics, readable filters, all four tabs reachable, charts stacked |
| Tablet (860 px) | Two metric cards per row with full labels; charts remain side by side |

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

### Stage 3 modified

| File | Diff |
|---|---|
| `app.py` | +132 / −23 |
| `core/detection.py` | +452 / −50 |
| `core/parser.py` | +381 / −28 |
| `requirements.txt` | +1 / −1 |
| `tests/test_detection.py` | +427 / −10 |
| `tests/test_parser.py` | +350 / −5 |

Stage 3 tracked-file diff: **1,743 insertions, 117 deletions across 6 files**.

### Stage 4 modified

| File | Diff |
|---|---|
| `app.py` | +1,101 / −158 |
| `tests/test_app.py` | +105 / −0 |
| `IMPLEMENTATION_REPORT.md` | Updated for Stage 4 |

Stage 4 text diff: **1,206 insertions, 158 deletions across the two tracked Python files**, plus the new presentation-layer files below. No `core/` file changed in Stage 4.

### Stage 4 new files

| File | Lines | Purpose |
|---|---:|---|
| `.streamlit/config.toml` | 14 | Light theme, hidden usage stats, 5 MB upload cap |
| `ui/__init__.py` | 1 | UI package marker |
| `ui/filters.py` | 224 | Pure exploration filters, timeline buckets, alert display helpers |
| `ui/theme.py` | 238 | Restrained light CSS, chart styling, Markdown escaping |
| `tests/test_ui_filters.py` | 181 | Filter, alert-selection, display-summary, timeline tests |
| `UI_REPORT.md` | 335 | Stage 4 design, validation, and screenshot report |
| `docs/screenshots/*.png` | 14 images | Desktop, tablet, phone, empty, invalid, filtered, and mixed-alert views |

Stage 3 new files remain part of the repository:

| File | Lines | Purpose |
|---|---:|---|
| `core/export.py` | 98 | Safe CSV exports and report builders |
| `scripts/benchmark_detection.py` | 64 | Reproducible dense-event benchmark |
| `tests/test_export.py` | 175 | Export/sanitisation tests |
| `tests/test_integration.py` | 68 | Parser → detection → export integration tests |

`README.md` and the Stage 1/2 reports remain untouched; final documentation is Stage 5 work.

---

## 7. Acceptance checklist

### Stage 3 core

| Requirement | Status |
|---|---|
| Modular architecture preserved | Met — parser/detection/export remain separate core modules |
| No unnecessary dependencies or AI/ML | Met — no new runtime dependencies |
| No automatic blocking/lockout | Met — not implemented |
| Configurable thresholds | Met — IP/account threshold and window, spray threshold and window |
| Evidence for every alert | Met — episode evidence with `source_row` when available |
| Normal and adversarial inputs tested | Met — parser, detection, export, and integration suites |
| 1k/3k/6k/10k benchmark | Met — plus 50k row-limit check |
| Compare with audit measurements | Met — audit baseline included |
| No quadratic scaling | Met — two-pointer scanner and measured near-linear scaling |

### Stage 4 UI/UX

| Requirement | Status |
|---|---|
| Sample button genuinely loads the sample | Met — increments uploader key and clears upload state |
| Upload/sample precedence unambiguous | Met — upload wins; Load sample clears it |
| Stale results prevented after dataset changes | Met — dataset identity and analysis key reset |
| Accessible reset/clear controls | Met — sidebar Clear dataset and error-state recovery actions |
| Active source and useful metadata | Met — source, badge, UTC range, rows, size, settings |
| Empty and invalid datasets handled | Met — dedicated empty/error states with no metrics |
| Username/IP search, status and date filters | Met — shared filters across Overview, Log Explorer, and displayed alerts |
| Source-row traceability and evidence access | Met — source row shown in log, tables, and every alert evidence expander |
| Alert reasons, entity, episode, threshold, count | Met — alert summary and per-alert cards |
| High/Medium/Informational distinction | Met — badges and severity guide |
| No confirmed-attack claims | Met — repeated review-only language |
| Deprecated parameters removed | Met — no `use_container_width`; charts use shared `config` |
| Caching and invalidation | Met — parse cache by bytes; detection memoized by dataset/settings |
| Restrained, responsive presentation | Met — light theme, no decoration/animation, desktop/tablet/phone layouts |
| Full test suite | Met — **112 passed** with warnings-as-errors |
| App smoke test | Met — AppTest reports zero exceptions/errors |
| Browser validation and screenshots | Met — sample/upload/clear/invalid/small/large/filter/responsive flows |
| Implementation and UI reports | Met — this document plus `UI_REPORT.md` |
| Stop after Stage 4 | Met — Stage 5 not started |

---

## 8. Unresolved issues and deliberate limitations

These are known, accepted, or deferred. None block Stage 4 acceptance.

1. **Streamlit version floor**
   - `requirements.txt` requires Streamlit `>=1.50` because the app uses `st.dataframe(width="stretch")`, `st.badge`, bordered metrics, and the configured upload cap.
   - All `use_container_width` usage has been removed. Plotly charts pass only supported `theme` and `config` arguments.

2. **Evidence display cap**
   - The browser evidence table displays the first 500 rows per alert to keep large episodes responsive.
   - The complete episode remains available in the per-alert evidence CSV download; the event count and threshold are always based on the full episode.

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

7. **Filters are presentation-only**
   - Detection always runs on the full active dataset.
   - Overview charts and tables show the filtered exploration view, while top-line metrics remain dataset-wide by design.

---

## 9. Reproduce

```powershell
python -m pytest -q -W error
python scripts\benchmark_detection.py
streamlit run app.py
```

The Stage 4 screenshots are in `docs/screenshots/` and are referenced in `UI_REPORT.md`. They were captured from the live app in headless Chrome; the capture tooling is not part of the application runtime or test suite.

For a rollback point before Stage 3, use Git baseline `4d5c686`. Stage 3 is commit `eea9586`. Stage 4 is the follow-up UI commit; no Stage 5 work has started.
