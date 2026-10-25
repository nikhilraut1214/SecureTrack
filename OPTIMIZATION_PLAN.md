# SecureTrack — Optimization Plan

**Based on:** `REPOSITORY_AUDIT.md` (2026-10-25)  
**Status:** Proposal — no application code will change until approval  
**Scope discipline:** No AI/ML, no fake risk scoring, no automatic blocking/lockout, no unnecessary database, no new heavyweight dependencies.

---

## 1. Objectives

1. Make detection **correct and complete**: one alert per real episode, with evidence that matches the alert.
2. Make analysis **fast and bounded**: linear-time detection, explicit input limits, no UI freezes.
3. Make parsing **predictable and safe**: strict timestamp policy, source-row traceability, specific errors.
4. Make exports **safe and useful**: spreadsheet-injection protection plus evidence export.
5. Meet the missing functional requirement: **log search and date/time filtering**.
6. Raise the UI to a **professional, restrained security-console standard** without changing correct backend behaviour.
7. Expand tests and documentation so the submission's claims are verifiable.

**Non-goals:** ML anomaly detection, threat scores, live monitoring, automatic response actions, SQLite persistence, user accounts/authentication, external enrichment APIs, or large visual redesigns that add fragility.

---

## 2. Recommended policy decisions

These decisions drive the implementation. They are called out here so they can be approved or changed before Stage 3.

| # | Decision | Recommendation | Why |
|---|---|---|---|
| D1 | Timestamp contract | Accept **ISO 8601 only**; timestamps without an offset are interpreted as **UTC**; all timestamps normalised to **UTC**; display "UTC" in the UI | Removes locale ambiguity, prevents mixed-dtype crashes, makes evidence reproducible |
| D2 | Episode semantics | **One alert per maximal qualifying episode** per entity and rule; keep overlapping alerts from different rules | Preserves separate bursts, makes evidence internally consistent, avoids false merging |
| D3 | Alert evidence | Include every event in the episode plus `source_row`; report the **peak qualifying window** separately | Directly supports "traceable supporting evidence" |
| D4 | Severity | Keep 2× threshold = High for IP/account rules; **also apply 2× distinct accounts = High to spray**; document that severity reflects volume, not certainty | Removes the unexplained "spray is always Medium" inconsistency |
| D5 | Input limits | 5 MB upload, **50,000 data rows**, 50 columns, first 500 validation errors retained with a total count | Prevents memory/UI denial of service while remaining generous for coursework |
| D6 | Dataset source | Explicit source selector: **Sample dataset** or **Upload CSV**; show active dataset metadata | Eliminates the no-op sample button and stale-data ambiguity |
| D7 | Visual theme | Restrained **light** theme with slate/teal palette and semantic red/amber for failures and severity; native Streamlit components over custom CSS | Professional, readable, projector-friendly, low maintenance risk |
| D8 | Optional hardening | Defer IP canonicalisation and case-insensitive username grouping to an optional follow-up unless approved now | They improve evasion resistance but change grouping semantics and need careful testing |

If any recommendation is unacceptable, Stage 3 will use the stated alternative before implementation begins.

---

## 3. Prioritised work packages

### Priority summary

| Priority | Work package | Audit findings | Stage |
|---|---|---|---|
| **P0 — Critical** | WP1 Detection correctness and linear performance | AUD-01, AUD-02, AUD-08, AUD-10 | 3 |
| **P0 — Critical** | WP2 Parsing, timestamps, traceability, limits | AUD-03, AUD-07, AUD-09 | 3 |
| **P0 — Critical** | WP3 Safe and complete exports | AUD-05 | 3 |
| **P1 — High** | WP4 Search, date filtering, caching, provenance | AUD-04, AUD-06, AUD-11 | 3/4 |
| **P1 — High** | WP5 Alert/dashboard UX and visual system | AUD-12 | 4 |
| **P1 — High** | WP6 Test expansion and QA | AUD-13 | 3–5 |
| **P2 — Medium** | WP7 Configuration, documentation, dependency hygiene | AUD-14, AUD-15 | 5 |
| **P3 — Optional** | WP8 Evasion hardening and extra context | AUD-16 | Post-approval |

---

## 4. WP1 — Detection correctness and linear performance

**Findings addressed:** AUD-01, AUD-02, AUD-08, AUD-10  
**Files:** `core/detection.py`, `tests/test_detection.py`

### 4.1 Episode model

Replace the current "keep updating the last alert" logic with an explicit episode scanner.

For a rule over one entity:

1. Sort events by `timestamp`, then `source_row` (when present).
2. Maintain a sliding window with `left` and `right`.
3. Move `left` while `timestamp[right] - timestamp[left] > window` (the existing inclusive `<=` boundary is preserved).
4. If the window meets the rule condition:
   - open an episode if none is open;
   - extend the episode to `right`;
   - record the peak window count and its boundaries.
5. When the condition no longer holds, close the episode at the last qualifying event.
6. Copy evidence **once** at close, not on every event.
7. Emit one alert per episode.

This turns the current `O(n²)` evidence copying into `O(n + evidence)` per group.

### 4.2 Rule-specific implementation

| Rule | Condition | Evidence | Extra fields |
|---|---|---|---|
| `R1_IP_FAILURES` | ≥ `threshold` failed events from one IP in `window` | Episode events | `peak_window_count`, `peak_window_start`, `peak_window_end` |
| `R2_ACCOUNT_FAILURES` | ≥ `threshold` failed events for one username in `window` | Episode events | Same, plus `distinct_source_ips` |
| `R3_ACCOUNT_SPRAY` | ≥ `spray_users` distinct usernames from one IP in `spray_window` | Episode events | `distinct_accounts`, `peak_distinct_accounts`, peak window fields |

The spray rule will use a two-pointer scan plus a `collections.Counter` for distinct usernames, replacing the repeated `nunique()` calls and the early `break`.

### 4.3 Alert schema (consistent contract)

Every alert will expose:

```
alert_id             ST-0001 (assigned after deterministic sorting)
rule_id              R1_IP_FAILURES | R2_ACCOUNT_FAILURES | R3_ACCOUNT_SPRAY
alert_type           human-readable rule name
entity_type          "ip" | "username"
entity_value         IP or username
ip_address           present for IP/spray alerts (compatibility)
username             present for account alerts (compatibility)
severity             "High" | "Medium"
start_time           ISO UTC string
end_time             ISO UTC string
event_count          number of events in the episode
peak_window_count    IP/account rules
peak_distinct_accounts  spray rule
peak_window_start    ISO UTC string
peak_window_end      ISO UTC string
distinct_source_ips  account rule
distinct_accounts    spray rule
threshold             applied threshold
window_minutes        applied window
description           generated from actual counts and times
evidence              list of event records, each with source_row when available
```

Alert IDs are assigned per analysis run after sorting. The UI and exports will label them accordingly.

### 4.4 Stable ordering and severity

- Sort by severity rank (`High` before `Medium`), then episode start timestamp, then `rule_id`, then entity value.
- Severity remains transparent:
  - IP/account: `High` when `peak_window_count >= 2 × threshold`, otherwise `Medium`.
  - Spray: `High` when `peak_distinct_accounts >= 2 × spray_users`, otherwise `Medium`.
- Document that severity is a **volume indicator**, not a probability or confirmation.

### 4.5 Input validation

`detect_suspicious_activity` will validate:

- required columns exist;
- `timestamp` is datetime-like (timezone-aware or naive);
- `status` contains only `SUCCESS`/`FAILED`;
- `threshold`, `spray_users` are integers ≥ 2;
- windows are positive;
- the DataFrame is non-empty (return `[]` for no failed events, not an exception).

Invalid input raises a concise `ValueError`; the app catches it and displays an actionable error instead of a traceback.

### 4.6 Tests

- exactly-threshold and one-below-threshold;
- inclusive window boundary at exactly `window` minutes;
- two separate episodes → two alerts with separate evidence;
- one long episode → one alert with correct start/end and peak window;
- account rule with multiple source IPs → correct `distinct_source_ips`;
- spray rule: two episodes, distinct counts, repeated usernames, no `nunique` blow-up;
- severity mapping at 1× and 2× thresholds;
- alert IDs unique and sequential after sorting;
- evidence rows match source rows and `event_count`;
- invalid inputs raise clear errors;
- performance guard: 5,000 dense events complete well under the old 100+ second behaviour (generous CI cap, e.g. 5 seconds);
- 10,000+ events benchmark recorded manually in the final audit.

**Acceptance:** no episode loss, evidence count equals episode length, 6,000 dense events complete in < 2 seconds on the audit machine, all detection tests pass.

---

## 5. WP2 — Parsing, timestamps, traceability, limits

**Findings addressed:** AUD-03, AUD-07, AUD-09  
**Files:** `core/parser.py`, `tests/test_parser.py`

### 5.1 Explicit parsing contract

Use one documented input policy:

- CSV, comma-delimited, UTF-8 or UTF-8 with BOM.
- Required columns, case-insensitive and whitespace-trimmed: `timestamp`, `username`, `ip_address`, `status`.
- Extra columns are ignored; missing required columns produce a clear error.
- `status` is trimmed and uppercased; only `SUCCESS` or `FAILED` accepted.
- `username` is trimmed; empty values rejected; control characters and overlong values rejected.
- `ip_address` is validated with `ipaddress.ip_address`; IPv4 and IPv6 accepted, CIDR/ports rejected with a clear reason.
- Timestamps use **ISO 8601** (`YYYY-MM-DD`, `YYYY-MM-DD HH:MM:SS`, `T` separator, fractional seconds, `Z`/offset). Naive values are treated as UTC.
- No locale-dependent `DD/MM` vs `MM/DD` guessing.

### 5.2 Safety limits enforced in the parser

Add module constants:

```
MAX_UPLOAD_BYTES = 5 * 1024 * 1024
MAX_DATA_ROWS = 50_000
MAX_COLUMNS = 50
MAX_ERRORS_RECORDED = 500
```

The app limit remains, but the parser is independently safe if reused. Exceeding a limit returns a structured error, not a crash. The UI will show "showing first 500 of N invalid rows" when errors are capped.

### 5.3 Traceability

- Preserve a `source_row` for every valid event. Blank lines are skipped while preserving accurate physical line numbers (read with `skip_blank_lines=False`, detect blank rows, drop them silently, and compute `source_row = index + 2`).
- Include `source_row` in evidence and in the evidence export.
- Return metadata:

```
source_name, size_bytes, data_rows, valid_rows, skipped_rows,
blank_rows, error_count, start_time, end_time, timezone="UTC"
```

- The UI will show dataset name, valid/skipped counts, time range, and "UTC" near the header.

### 5.4 Error handling

Specific messages for:

- empty file;
- header-only file ("no data rows");
- missing columns;
- duplicate normalized headers (detect where feasible; otherwise document);
- wrong encoding (UTF-8 required);
- binary/NUL content;
- too many rows/columns;
- oversized file;
- invalid timestamp with accepted format example;
- invalid IP/status/username.

Do not echo raw uploaded values in error messages. Cap exception text.

### 5.5 Performance

Vectorise timestamp parsing (`format="ISO8601", utc=True, errors="coerce"`), status normalisation, and IP validation (validate unique IPs once, then map). Avoid `iterrows()` for the common path. Keep per-row error reasons only for invalid rows.

### 5.6 Tests

- valid ISO variants, `Z`, offsets, fractional seconds;
- naive values normalised to UTC;
- mixed offsets produce one consistent datetime dtype and no UI crash;
- ambiguous `01/02/2026` rejected;
- short date-only accepted with midnight semantics;
- BOM, blank lines, extra columns, header-only, empty, wrong encoding, NUL bytes;
- missing columns, duplicate header policy;
- size/row/column caps;
- `NA`/`null`-like usernames preserved where valid;
- `source_row` accuracy across blank lines;
- error count/truncation metadata;
- IP validation includes IPv4/IPv6 and rejects ports/CIDR.

**Acceptance:** no valid timezone file crashes; all valid events have a source row; limits are enforced at the parser boundary; 50,000 rows parse without pathological delay.

---

## 6. WP3 — Safe and complete exports

**Findings addressed:** AUD-05  
**Files:** new `core/export.py`; `app.py` download calls; new `tests/test_export.py`

### 6.1 Spreadsheet-injection sanitiser

Add a pure function that prefixes a single quote when a string cell begins with a formula trigger:

```
=  +  -  @  \t  \r
```

Check the first non-whitespace character to reduce trivial bypasses. Apply it only to string/object columns in a **copy** used for export; never mutate analysis data.

Use UTF-8 with BOM (`utf-8-sig`) so Excel opens names and timestamps correctly, and return bytes to Streamlit.

### 6.2 Report exports

| Export | Contents |
|---|---|
| Filtered logs | Current filtered event table, including `source_row`; sanitised |
| Alert summary | Alert ID, rule, entity, severity, start/end, episode count, peak count, distinct counts, thresholds; sanitised |
| Evidence (long form) | One row per evidence event, with alert metadata repeated; includes `source_row`; sanitised |
| CSV template | Header plus one harmless example row, downloadable from the upload area |

All filenames are static or derived from a sanitised dataset stem. No formula-capable content is left untouched.

### 6.3 Tests

- values starting with each dangerous prefix are prefixed;
- leading-whitespace bypass is neutralised;
- normal usernames/IPs/timestamps are unchanged;
- export does not mutate the input DataFrame;
- evidence export row count equals total evidence count;
- header/columns are stable;
- UTF-8 BOM is present;
- empty filtered/alert sets export a header-only file rather than failing.

**Acceptance:** opening an exported CSV cannot interpret a username as a formula; evidence export is complete and traceable.

---

## 7. WP4 — Search, date filtering, caching, provenance

**Findings addressed:** AUD-04, AUD-06, AUD-11  
**Files:** `app.py`; optionally new `core/filters.py`; `tests/test_filters.py` or AppTest coverage

### 7.1 Explicit data source

Replace the ambiguous `if upload / elif sample` ordering with:

- a source selector (`Sample dataset` / `Upload CSV`), or an equivalent explicit state;
- sample metadata labelled "Sample dataset (fictional)";
- uploaded file name, size, row counts, and time range;
- a clear empty state when "Upload CSV" is selected but no file is present;
- no "Load sample" no-op while an upload remains active.

### 7.2 Search and time filter

Log Explorer additions:

- case-insensitive free-text search across username and IP (literal matching, no regex injection);
- date/time range filter in UTC;
- existing status/username/IP filters retained or simplified;
- result count ("X of Y events");
- "Reset filters" control;
- empty state when no events match;
- export reflects the filtered view.

Extract filtering into a pure helper (`core/filters.py`) so it can be unit-tested independently of Streamlit.

### 7.3 Caching

Add cached analysis keyed by:

- raw file bytes / sample identity;
- all four detection thresholds.

Recommended structure:

```
@st.cache_data(show_spinner=False)
def analyze(raw_bytes, source_name, threshold, window, spray_users, spray_window):
    parsed = parse_login_csv(raw_bytes)
    alerts = detect_suspicious_activity(...) if not parsed["data"].empty else []
    return parsed, alerts
```

Changing a display filter must not re-parse or re-detect. Show a spinner on a cache miss. Provide a small "Re-run analysis" action only if it adds real value; otherwise rely on key changes.

### 7.4 Tests

- search is case-insensitive and literal;
- search matches username and IP;
- time range boundaries are inclusive;
- combined filters behave as AND;
- reset restores all rows;
- no-match state returns zero rows;
- AppTest smoke test verifies sample loads, metrics are correct, tabs render, and no exception occurs;
- if AppTest supports file upload, add a valid and an invalid upload case; otherwise verify parser/error helpers directly and document the manual check.

**Acceptance:** a user can find a username/IP and narrow by time in one step; filter changes return instantly after the first analysis; the active dataset is always visible.

---

## 8. WP5 — Professional UI/UX and visual system

**Findings addressed:** AUD-12  
**Files:** `app.py`, new `.streamlit/config.toml`, possibly a small `assets/favicon` (optional)

### 8.1 Design direction

A calm security-operations console, not a marketing dashboard:

- light background, slate text, teal/blue accent;
- semantic colours: failed = muted red, success = teal, high severity = red, medium = amber, neutral = slate;
- consistent typography and spacing; no gradients, glow, animation, oversized cards, or fake live badges;
- native Streamlit components (`st.metric(border=True)`, `st.badge`, `st.container(border=True)`, `st.segmented_control`, `st.dataframe(column_config=...)`);
- minimal or no custom CSS; no fragile selectors;
- remove the shield emoji from the H1; use plain "SecureTrack" with a subtitle.

### 8.2 Layout

- **Header:** product name, one-line purpose, a compact "Rule-based · Local analysis · Not live monitoring" caption. Keep the academic/suspicious-vs-confirmed disclaimer visible without dominating the page.
- **Dataset strip:** source name, valid/skipped rows, time range (UTC), current thresholds summary.
- **Sidebar:** data source, detection settings grouped as "IP failures", "Account failures", "Account spray"; help tooltips; limits note. Avoid duplicate labels.
- **Overview:** two rows of metrics instead of five squeezed columns:
  - Total events, failed attempts, success rate, rule matches;
  - unique IPs, targeted accounts, high-severity matches (all derived; no risk score).
  - Full-width outcome bar chart and adaptive timeline, then top-IP profile table.
- **Log Explorer:** search/time controls, result count, table with column config, safe export.
- **Security Alerts:** filter row (severity, rule, search); compact summary table; alert detail cards with native severity badge, rule/entity, time range, episode/peak counts, distinct context, evidence table with source rows, and per-alert evidence download.
- **Detection Rules:** current rule table with rule ID, logic, thresholds, real hit count for the current dataset, severity rubric, and a "limits" section covering NAT/shared IPs, mistyped passwords, and overlapping findings.

### 8.3 Chart corrections

- Replace the two-category pie with a horizontal bar chart (counts and percentages).
- Timeline:
  - adaptive bucket: minute for short spans, hour for multi-hour/day spans, day for long spans;
  - cap buckets at a readable number;
  - stacked bars by status;
  - `rangemode="tozero"` on the count axis;
  - explicit UTC/bucket caption;
  - no fake "live" update.
- Top IP table: IP, failed attempts, successful attempts, distinct accounts targeted, last seen; top 10 by failures; explicit empty state.
- Use a fixed semantic colour map shared by charts and badges.

### 8.4 Alerts and terminology

- Keep "Security Alerts" as the tab name, with a subtitle: "Rule matches requiring analyst review — not confirmed attacks."
- Explain severity as volume-based, not probability.
- State that different rules may describe the same events.
- Show `High`/`Medium` with native badges and text, never colour alone.
- Provide a rule-hit count and "no matches" state per rule.

### 8.5 Configuration

`.streamlit/config.toml`:

```toml
[server]
address = "localhost"
maxUploadSize = 5

[browser]
gatherUsageStats = false

[client]
toolbarMode = "minimal"
showErrorDetails = "none"

[theme]
base = "light"
primaryColor = "#0f766e"
backgroundColor = "#f8fafc"
secondaryBackgroundColor = "#ffffff"
textColor = "#0f172a"
font = "sans serif"
```

Notes:

- This aligns the uploader's advertised limit with the real 5 MB limit.
- `showErrorDetails = "none"` is supported by Streamlit 1.50; it prevents raw tracebacks from reaching users.
- Localhost binding is appropriate for the academic scope; README will explain how to override intentionally.
- Usage statistics are disabled; no privacy claim will exceed what is actually configured.

### 8.6 Empty and error states

| Situation | Presentation |
|---|---|
| No upload selected | Info panel with required columns, limit, template download, privacy note |
| Empty/header-only CSV | Specific error, not a generic "no events" |
| Invalid rows | Warning with count and expandable capped error table |
| No failed logins | Empty state for failure charts/IP table; success metrics remain |
| No rule matches | Positive/neutral state plus rule explanation; no implied "all clear" guarantee |
| No search results | "No events match these filters" with reset action |
| Detection input error | Actionable error with no traceback |
| Oversized file | Clear limit and split guidance |

### 8.7 Accessibility and responsiveness

- Maintain Lighthouse accessibility at 100 (or ≥ 95 if a chart limitation requires it).
- Text labels accompany severity/status colours.
- Verify at 742 px (narrow) and 1440 px (desktop).
- Avoid five-column rows; stack metrics in two rows.
- Charts full-width; tables scroll horizontally within Streamlit's container.
- No custom keyboard traps or motion.

**Acceptance:** the page reads as a restrained security tool; charts are honest and legible; all states are explicit; no default-red-accent/emoji-title look; a11y score remains high.

---

## 9. WP6 — Test expansion and QA

**Files:** `tests/test_parser.py`, `tests/test_detection.py`, new `tests/test_export.py`, new `tests/test_filters.py`, new `tests/test_app.py`, possibly `tests/conftest.py`

### Test matrix

| Area | Tests |
|---|---|
| Parser | valid ISO, offsets, naive→UTC, mixed offsets, ambiguous dates, BOM, blank lines, extra columns, header-only, empty, encoding, NUL, limits, source rows, error cap |
| Detection | threshold boundaries, window boundary, episodes, peak windows, evidence counts, account/spray rules, distinct counts, severity, ordering, IDs, invalid input, empty failures |
| Export | formula prefixes, leading-whitespace bypass, non-string preservation, no mutation, UTF-8 BOM, evidence row count, empty exports |
| Filters | literal case-insensitive search, username/IP match, inclusive time range, combined filters, reset |
| App | AppTest sample smoke, no exceptions, metrics, tabs, source state, empty/error state where testable |
| Performance | 5,000 dense events under a generous cap; manual 10k/50k benchmark recorded |

### Quality gates

- `python -m pytest -q` passes with zero warnings.
- No tests assert invented metrics or fabricated alerts.
- Performance test catches a return to quadratic behaviour.
- Manual desktop/narrow viewport check and Lighthouse run.
- All exports opened in a spreadsheet application during manual QA to confirm sanitisation.

**Acceptance:** at least ~30 meaningful tests; the two critical audit defects would fail the suite if reintroduced; app smoke test passes.

---

## 10. WP7 — Documentation, configuration, and dependency hygiene

**Files:** `README.md`, `.streamlit/config.toml`, `requirements.txt`, optional `pyproject.toml`, optional `.gitignore`

### README structure

1. Purpose and academic scope.
2. Screenshot/description of the dashboard.
3. Architecture and data flow.
4. Setup (Windows PowerShell) and tested versions.
5. CSV specification with an example and timestamp/timezone policy.
6. Detection rules, episode semantics, severity rubric, and evidence explanation.
7. Dashboard guide (search, filters, exports, alert details).
8. Security and privacy: local processing, no blocking, no live monitoring, usage-statistics setting, safe-use guidance.
9. Limitations: rule-based, NAT/shared IPs, overlapping findings, no authentication, no persistence.
10. Tests and performance notes.
11. Project structure.
12. Troubleshooting.

### Dependency policy

- Add upper bounds to prevent silent major-version breakage, for example `streamlit>=1.50,<2`, `pandas>=2.2,<3`, `plotly>=5.18,<8`, `pytest>=8,<9`.
- Raise the Streamlit minimum if `width="stretch"`/`st.badge`/`st.container(border=True)` are used.
- No new runtime dependencies.
- `plotly_chart` still uses `use_container_width` in 1.50; replace only where the installed API supports `width`.

### Configuration and repo hygiene

- Add `.streamlit/config.toml`.
- Add `.gitignore` for `.venv/`, `__pycache__/`, `.pytest_cache/`, `.streamlit/secrets.toml`, and local exports.
- Initialize Git before Stage 3 so changes can be diffed/reverted (recommended; requires approval because the directory is not currently a repository).
- License: ask whether the submission needs one; do not add silently.
- No SQLite, no service files, no CI requirement for the academic scope.

---

## 11. WP8 — Optional hardening (only if approved)

| Item | Benefit | Cost/risk |
|---|---|---|
| Canonicalise IPs before grouping | Stops equivalent IPv6 spellings from splitting episodes | Changes displayed values or requires a separate canonical key; add tests |
| Optional case-insensitive username grouping | Reduces trivial evasion via `Alice`/`alice` | Can merge genuinely distinct accounts; make it an explicit setting and show original values |
| Duplicate-event indicator | Warns that repeated identical rows may inflate counts | Does not auto-drop data; needs a clear policy |
| IP success/failure profile | Adds context to "suspicious IP" analysis | Already partially planned via top-IP table; avoid risk scoring |
| Deterministic alert IDs across runs | Better report stability | Requires a stable hash of rule/entity/time; sequential IDs are simpler and sufficient |
| Advanced evidence export formats | Easier external analysis | JSON/PDF would add scope; CSV long-form is enough |
| Timezone display selector | Local-time convenience | More UI complexity; UTC-only is academically cleaner |

Recommendation: **defer WP8** until P0/P1 work is complete and reviewed.

---

## 12. File-by-file change map

| File | Change |
|---|---|
| `core/parser.py` | Rewrite validation flow; limits; ISO timestamps/UTC; source rows; metadata; specific errors; vectorised validation |
| `core/detection.py` | Episode scanner; spray Counter; consistent schema; validation; severity/IDs; linear performance |
| `core/export.py` | **New** — formula sanitiser, safe CSV builders, evidence long-form export |
| `core/filters.py` | **New** (optional but recommended) — pure search/time/status filters |
| `app.py` | Source selector, caching, metadata, search/time filters, safe exports, alerts UX, charts, rules tab, error states, theme-compatible layout |
| `.streamlit/config.toml` | **New** — upload limit, localhost, telemetry off, error details, theme |
| `tests/test_parser.py` | Expand parser cases |
| `tests/test_detection.py` | Expand rules/episodes/performance cases; remove deprecation warnings |
| `tests/test_export.py` | **New** — sanitisation and export tests |
| `tests/test_filters.py` | **New** — search/time filter tests |
| `tests/test_app.py` | **New** — AppTest smoke/state tests |
| `README.md` | Rewrite to match delivered behaviour |
| `requirements.txt` | Version ranges aligned with used APIs |
| `REPOSITORY_AUDIT.md` | Keep as Stage 1 record |
| `OPTIMIZATION_PLAN.md` | This document |
| `FINAL_AUDIT.md` | **New** in Stage 6 |

No existing file will be deleted without explicit approval.

---

## 13. Implementation sequence and checkpoints

### Stage 3 — Core implementation (after approval)

1. Add safe export module and tests first (independent, low risk).
2. Rewrite parser with timestamp policy, limits, source rows, metadata; update tests.
3. Rewrite detection with episode scanning and validation; update tests, including performance.
4. Wire parser/detection into the app with caching and error handling; keep the existing layout temporarily.
5. Run the full suite; verify sample counts and mixed-timezone behaviour.

**Checkpoint:** review core behaviour and test output before UI changes.

### Stage 4 — UI/UX optimization

1. Add `.streamlit/config.toml` and theme.
2. Add source selector, dataset metadata, empty/error states.
3. Add search/time filters and alert filters.
4. Rework metrics, charts, alert cards, rules tab.
5. Add safe export buttons and evidence download.
6. Run AppTest, manual narrow/desktop checks, Lighthouse.

**Checkpoint:** review screenshots and UX before documentation/final testing.

### Stage 5 — Testing and documentation

1. Expand/polish tests; zero warnings.
2. Run full suite and manual spreadsheet/export checks.
3. Update README, requirements, config docs.
4. Record performance numbers.

### Stage 6 — Final review

1. Re-check every requirement and audit finding.
2. Produce `FINAL_AUDIT.md` with evidence, residual limitations, and test results.
3. Confirm no fabricated metrics, no blocking/lockout, no scope creep.

---

## 14. Acceptance criteria

### Correctness

- [ ] Separate episodes produce separate alerts with distinct, correct evidence.
- [ ] `event_count` equals evidence length; peak window fields are consistent.
- [ ] Account/spray distinct counts are correct and displayed.
- [ ] Mixed-timezone input is normalised and never crashes the UI.
- [ ] Every valid event carries `source_row`; evidence references it.
- [ ] Sample dataset still yields 12 events / 4 success / 8 failed and the expected three rule matches (verify after episode rewrite).

### Performance and safety

- [ ] 6,000 dense events detect in < 2 seconds on the audit machine.
- [ ] 5 MB / 50,000-row limits enforced with clear messages.
- [ ] Filter changes do not re-parse or re-detect.
- [ ] All CSV exports neutralise formula triggers.
- [ ] No raw traceback is shown to the user.

### Functional

- [ ] Log search and date/time filtering work.
- [ ] Source dataset is always visible and unambiguous.
- [ ] Alert summary, filters, details, and evidence export work.
- [ ] Empty/error/no-match states are useful.
- [ ] Rules tab shows current thresholds and real hit counts.

### UI/UX

- [ ] Restrained professional theme; no default red accent/emoji-title look.
- [ ] Semantic, colour-blind-considerate chart palette with text labels.
- [ ] Timeline is meaningful for short and long datasets; count axis starts at zero.
- [ ] Layout works at 742 px and 1440 px.
- [ ] Lighthouse accessibility ≥ 95 (target 100).
- [ ] No gradients, glow, fake live indicators, or oversized cards.

### Quality

- [ ] ~30+ tests pass; zero warnings.
- [ ] README matches actual behaviour and limitations.
- [ ] No new unnecessary dependencies.
- [ ] No SQLite, AI/ML, blocking, or lockout added.
- [ ] All audit findings either fixed or explicitly deferred with rationale.

---

## 15. Risks and mitigations

| Risk | Mitigation |
|---|---|
| Alert counts change because episodes are now separate | Document the semantic fix; add tests; re-check sample; explain in final audit |
| Strict ISO timestamps reject previously accepted CSVs | Clear error with examples; README documents the policy; offer a template |
| Theme forces light mode | Deliberate for consistency/projector readability; document; can follow system if requested |
| Caching hides threshold changes | Include all thresholds in the cache key; verify with tests/manual checks |
| Performance test flaky on slow machines | Use a generous cap (e.g., 5 s for 5k) that still fails the old 90+ s behaviour |
| AppTest cannot simulate every upload/UI interaction | Combine AppTest smoke tests with pure helper tests and manual QA |
| No Git history | Initialize Git before Stage 3 if approved; otherwise keep backups |
| Large refactor introduces regressions | Incremental stages, tests after each work package, preserve existing public function names where practical |
| Over-designing the UI | Native components, restrained palette, no custom CSS beyond configuration, review at two widths |

---

## 16. Explicitly rejected additions

To protect the academic scope, this plan will **not** add:

- machine learning, anomaly scoring, or "AI insights";
- a composite threat/risk score that implies certainty;
- live log tailing, SIEM integration, or fake real-time status;
- automatic IP blocking, account lockout, or firewall changes;
- user authentication, multi-tenancy, or a production database;
- SQLite simply for the sake of using SQLite;
- PDF/JSON reporting frameworks;
- unnecessary dependencies or frontend build tooling;
- decorative animations, gradients, or glowing cards;
- synthetic "attack prevented" metrics.

---

## 17. Approval request

Stage 3 will begin only after explicit approval. Please confirm the recommended policy decisions in Section 2, especially:

1. **Timestamps:** ISO 8601 only, naive = UTC, all normalised/displayed as UTC.
2. **Episodes:** one alert per qualifying episode, with peak-window evidence; overlapping rules retained.
3. **Severity:** spray also escalates to High at 2× the distinct-account threshold.
4. **Limits:** 5 MB, 50,000 rows, 50 columns, 500 recorded errors.
5. **Theme:** restrained light theme.
6. **Optional hardening (WP8):** defer for now.
7. **Git:** initialise a repository before code changes for rollback (recommended), or proceed without it.

No application code has been modified in Stages 1–2. `REPOSITORY_AUDIT.md` and this plan are the only workspace additions.
