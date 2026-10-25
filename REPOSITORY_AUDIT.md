# SecureTrack — Repository Audit

**Project:** SecureTrack — Login Activity Analyzer & Suspicious Login Detection System  
**Audit date:** 2026-10-25  
**Audit type:** Read-only repository, runtime, security, UI/UX, and test audit  
**Scope:** All files in the repository; application code was not modified during this stage.

---

## 1. Executive summary

SecureTrack is a small, readable Streamlit prototype with a sensible separation between CSV parsing (`core/parser.py`), rule-based detection (`core/detection.py`), and presentation (`app.py`). It already satisfies the academic safe-use requirement: it analyzes supplied logs only, uses fictional sample data, does not block IPs or lock accounts, and clearly states that alerts are patterns for review rather than proof of an attack.

The project is **not yet reliable enough for a polished submission**. Four issues are material:

1. **Detection episodes are collapsed.** All qualifying windows for the same IP or account are merged into one alert, and each new qualifying window overwrites the previous evidence. Earlier episodes disappear entirely. The account-spray rule also stops after the first episode per IP.
2. **Detection is quadratic in practice.** A one-IP episode of 6,000 events took **137 seconds** because full evidence is copied on every qualifying event. A small CSV can make the app appear frozen.
3. **Mixed timezone offsets crash the dashboard.** A valid CSV containing timestamps with different UTC offsets produces an object-dtype timestamp column, and the timeline calls `.dt.floor()`, raising `AttributeError`.
4. **A required capability is missing.** The Log Explorer supports multi-select filters but has no free-text search or date-range filtering, despite the requirement for "Log filtering and search."

In addition, CSV exports are vulnerable to spreadsheet formula injection, and exported evidence lacks source-row identifiers or dataset provenance. The current UI is functional and accessible, but it uses default Streamlit styling, semantically weak chart colours, an hourly timeline that collapses short datasets, and a five-column metric row that is cramped at narrow widths.

The six existing tests pass, but they cover only a small part of the parser and detection behaviour. There are no tests for the account-spray rule, evidence quality, episode separation, timezone handling, export safety, or the Streamlit app itself.

**Recommendation:** Fix the core correctness, performance, and export-safety problems before the UI work. Stage 2 proposes a concrete, prioritised plan.

---

## 2. Repository inventory

| Path | Size / lines | Purpose |
|---|---:|---|
| `app.py` | 105 lines, 5.46 KB | Streamlit UI, thresholds, upload/sample handling, tabs, charts, exports |
| `core/parser.py` | 34 lines | CSV reading, header normalisation, row validation |
| `core/detection.py` | 57 lines | Sliding-window rules for IP failures, account failures, and account spray |
| `core/__init__.py` | empty | Package marker |
| `tests/test_parser.py` | 13 lines, 3 tests | Basic valid/invalid/missing-column parser cases |
| `tests/test_detection.py` | 18 lines, 3 tests | Basic IP threshold and window cases |
| `data/sample_login_logs.csv` | 13 lines, 12 events | Fictional sample data using TEST-NET-1 (`192.0.2.0/24`) |
| `README.md` | 39 lines | Setup, tests, CSV format, defaults, safe-use limitations |
| `requirements.txt` | 4 dependencies | Streamlit, pandas, Plotly, pytest |

No SQLite database, background service, authentication layer, or external API integration is present. That is appropriate for the stated academic scope.

The directory is **not a Git repository**, so there is no version history or diff-based rollback. This is a process risk, not an application defect.

---

## 3. Architecture and data flow

```
CSV upload bytes ─┐
                  ├─> core.parser.parse_login_csv() ─> {data: DataFrame, errors: list}
sample file path ─┘                                        │
                                                           ▼
                                      core.detection.detect_suspicious_activity()
                                                           │
                                                           ▼
                                      app.py → metrics, charts, tables, downloads
```

**Strengths**

- Parser and detection logic are separated from the UI and are independently testable.
- Parser returns both valid rows and structured validation errors instead of crashing.
- Detection is transparent and rule-based; there is no pseudo-ML or opaque scoring.
- Alert objects carry the supporting event records.
- Sample data is clearly fictional.
- No automatic blocking, account lockout, or live-monitoring claim exists.
- Dependencies are minimal and appropriate.

**Weaknesses**

- The parser returns an untyped dictionary and has no documented input contract or size/row limits of its own.
- Detection assumes a cleaned, datetime-typed DataFrame but does not validate that contract.
- The alert schema is inconsistent: some alerts have `ip_address`, others `username`; only some have `distinct_source_ips` or `distinct_accounts`.
- A significant amount of rule metadata (names, thresholds, descriptions) is duplicated between detection and UI text.
- Parsed events do not retain their original CSV line number, so evidence cannot be traced back to a precise source row.
- The app re-parses and re-runs detection on every Streamlit rerun, including filter changes.

---

## 4. Environment and dependency status

Audit environment:

| Component | Version |
|---|---|
| Python | 3.14.2 |
| Streamlit | 1.50.0 |
| pandas | 2.3.3 |
| Plotly | 7.1.0 |
| pytest | 8.4.2 |
| NumPy | 2.5.3 |

`requirements.txt` declares:

```
streamlit>=1.35
pandas>=2.0
plotly>=5.18
pytest>=8.0
```

`plotly` was not installed in the active environment at the start of the audit; it is declared in `requirements.txt`. It was installed during the audit so the app could be smoke-tested. No repository dependency file was changed.

**Observations**

- Dependencies have lower bounds but no upper bounds, so a future major release can silently break the app.
- The app uses `use_container_width`, which Streamlit 1.50 reports as deprecated and scheduled for removal after 2025-12-31. It still works today, but it is a compatibility risk.
- The declared minimum Streamlit version (`1.35`) does not guarantee support for APIs that may be introduced during the UI stage; if newer APIs are used, the minimum must be raised.
- No `.streamlit/config.toml` exists. Consequently, Streamlit displays a 200 MB upload limit while the app rejects files over 5 MB (`app.py:25`), and usage statistics are not explicitly disabled.

---

## 5. Functional coverage

| Requirement | Status | Evidence / gap |
|---|---|---|
| CSV authentication-log upload | Implemented | `app.py:20-28`, 5 MB guard |
| Input validation and error handling | Partial | Per-row validation exists (`core/parser.py:19-31`), but detection/app error handling is incomplete and some valid timezone data crashes the UI |
| Successful and failed login analysis | Implemented | Counts (`app.py:43-49`), outcome chart (`app.py:60-61`) |
| Repeated failed-login detection | Implemented, flawed | IP rule (`core/detection.py:30-33`) and account rule (`core/detection.py:34-40`); episodes collapse and earlier evidence is overwritten |
| Suspicious IP activity analysis | Partial | IP failure rule plus top-10 failed-attempt table (`app.py:65-67`); no IP profile such as success/failure ratio or distinct targeted accounts |
| Multiple-account targeting | Partial | Spray rule (`core/detection.py:41-57`) but it reports at most **one** episode per IP (`break` at line 56) |
| Configurable thresholds | Implemented | Sidebar inputs (`app.py:12-18`); no validation in the core detection function itself |
| Evidence-backed alerts | Partial | Evidence records are attached (`core/detection.py:22,55`), but no source row IDs, dataset identity, rule ID, or parameters |
| Interactive activity dashboard | Implemented, basic | Tabs, Plotly charts, tables (`app.py:56-93`) |
| Log filtering and search | Partial / gap | Multi-select filters only (`app.py:69-79`); no text search and no date range |
| CSV report export | Partial | Filtered logs and alert summaries (`app.py:79,93`); formula-injection risk; no evidence export |
| Configurable rule documentation | Implemented | Detection Rules tab (`app.py:95-104`) |
| Local-only/no blocking | Implemented | README and UI disclaimer; no block/lockout code |
| Fictional sample data | Implemented | `data/sample_login_logs.csv` uses documentation IP ranges |
| Distinguish suspicion from attack | Implemented | Persistent info banner and safe-use wording |
| SQLite | Not used | Correctly unnecessary for the current scope |

---

## 6. Findings

Severity scale:

- **Critical** — breaks required behaviour, makes the tool unreliable, or creates a serious security/performance risk.
- **High** — significant correctness, security, or requirement gap that should be fixed before submission.
- **Medium** — meaningful quality, maintainability, usability, or robustness issue.
- **Low** — hygiene, documentation, or optional improvement.

### AUD-01 — Critical — Detection episodes are merged and earlier evidence is lost

**Location:** `core/detection.py:3-23`, especially `14-17`

The sliding-window function updates the previous alert whenever the current group value matches:

```python
if alerts and alerts[-1][field] == value:
    alerts[-1].update(
        start_time=str(times[left]),
        end_time=str(times[right]),
        event_count=int(count),
        evidence=evidence.to_dict("records"),
    )
```

Because `_sliding_alerts` is called once per IP (or once per username), every alert in that call has the same value. Therefore the condition is effectively always true. The function produces **at most one alert per IP** and **at most one alert per username** for the entire file. Each qualifying window replaces the previous window's start time, end time, count, and evidence.

**Verified reproduction**

Two separate five-event bursts from the same IP/account, one hour apart, produced only:

```
Repeated failed logins from one IP
  events: 5
  start: 2026-10-24 11:00:00
  end:   2026-10-24 11:00:40
Repeated failed logins against one account
  events: 5
  start: 2026-10-24 11:00:00
  end:   2026-10-24 11:00:40
```

The first episode at 10:00 is absent from the alert list and from the evidence.

**Impact**

- Missed episodes in an investigation.
- Alert count understates the number of distinct periods of suspicious activity.
- Evidence no longer explains the alert's stated start/end time.
- Directly conflicts with the requirement that every alert have traceable supporting evidence.
- Account-spray rule has a related defect (AUD-02).

**Required direction:** Define and implement one alert per qualifying episode, preserve all supporting events, and include the strongest/peak window explicitly. Add tests for multiple episodes.

---

### AUD-02 — Critical — Quadratic detection performance

**Location:** `core/detection.py:12-17`, `core/detection.py:44-55`

For every qualifying event after the threshold, the code calls `group.iloc[left:right+1].to_dict("records")` and stores that full list in the alert. With `n` events in one episode, this copies approximately `O(n²)` records. The same events are processed twice, once by the IP rule and once by the account rule. The spray rule calls `window.username.nunique()` for every right-hand pointer, which is also expensive in dense windows.

**Measured worst case**

Synthetic events, all from one IP and one username, within 100 seconds, default thresholds (5 failures / 2 minutes):

| Events | Detection time |
|---:|---:|
| 1,000 | 3.14 s |
| 3,000 | 34.71 s |
| 6,000 | 137.34 s |

This is a single-run measurement on the audit machine, not a formal benchmark, but the scaling is unambiguous. A 6,000-row CSV is far below the 5 MB upload limit, yet it freezes the app for over two minutes.

**Impact**

- Dashboard appears hung or crashes for legitimate files.
- Trivial denial of service against a local deployment.
- Reruns on every filter change multiply the cost.
- Makes the app impractical for realistic authentication logs.

**Required direction:** Use a linear two-pointer scan; build evidence once per episode; track peak window separately; add a performance regression test.

---

### AUD-03 — High — Valid mixed-timezone CSV crashes the dashboard

**Location:** `core/parser.py:20`, `app.py:63`

`pd.to_datetime(row["timestamp"], errors="coerce")` returns timezone-aware Timestamps when offsets are present. A file mixing offsets produces an `object` dtype column rather than `datetime64[ns]`.

**Verified reproduction**

Input:

```csv
timestamp,username,ip_address,status
2026-10-24 10:00:00+00:00,u1,192.0.2.1,FAILED
2026-10-24 10:01:00+02:00,u1,192.0.2.1,FAILED
```

Parser result: 2 valid rows, no errors, timestamp dtype `object`.

App timeline:

```
AttributeError: Can only use .dt accessor with datetimelike values
```

`app.py:63` calls `df.timestamp.dt.floor("h")` unconditionally. Detection itself happens to work, but the UI crashes after it.

**Related issues**

- Naive and offset timestamps can be mixed without a clear policy.
- `start_time`/`end_time` strings have inconsistent offset representations.
- Ambiguous date formats such as `01/02/2026` are silently accepted with a pandas-chosen interpretation.
- There is no visible indication of the timezone used by the analysis.

**Required direction:** Choose one timestamp contract, normalise consistently, validate it, and display the policy. The proposed default is ISO 8601 input, naive values interpreted as UTC, all values normalised to UTC.

---

### AUD-04 — High — "Search" requirement is not implemented

**Location:** `app.py:69-79`

The Log Explorer provides status, username, and IP multi-selects. It has no free-text search and no date-range filter. Users cannot quickly locate a specific username or IP in a large log, and cannot narrow analysis to an incident window.

**Impact:** A stated functional requirement is unmet. Multi-selects also become unusable when a log contains hundreds or thousands of unique usernames/IPs.

**Required direction:** Add case-insensitive username/IP search and a date/time range filter, with a clear reset action and a visible result count.

---

### AUD-05 — High — CSV exports are vulnerable to spreadsheet formula injection

**Location:** `app.py:79`, `app.py:93`

Filtered logs and alert summaries are exported directly with `to_csv()`. User-controlled values such as `username` are not neutralised. A cell beginning with `=`, `+`, `-`, or `@` can be interpreted as a formula by spreadsheet applications when the exported CSV is opened.

Example username:

```
=cmd|' /C calc'!A0
```

The parser accepts it because it is a non-empty username. It is then exported verbatim.

**Impact:** Opening an exported report in Excel/LibreOffice can execute a formula or trigger external content. This is a genuine client-side risk even though the Streamlit app never executes uploaded content.

**Required direction:** Sanitise formula-triggering cells on export (prefix with `'` or equivalent), cover all text columns, and add tests. Keep sanitiser separate from in-memory analysis data.

---

### AUD-06 — High — Dataset provenance is ambiguous and the sample button can be a no-op

**Location:** `app.py:24-33`

The data-source logic is:

```python
if upload:
    ...
elif sample or "result" not in st.session_state:
    result = parse_login_csv(sample_path)
else:
    result = st.session_state["result"]
```

Consequences:

1. If a file remains in the uploader, clicking **Load sample dataset** has no effect because the `if upload` branch always wins. The user must clear the uploader first.
2. If the uploader is cleared later, the app silently keeps displaying the previously uploaded result from session state.
3. The UI never shows which file is being analyzed, its size, its time range, or when it was loaded.
4. The sample loads automatically on first run, making the "Load sample dataset" button redundant on that first view.

**Impact:** Users can analyze the wrong dataset without noticing. For an evidence-oriented tool, this is a correctness and traceability problem, not just a UI annoyance.

**Required direction:** Make the source explicit (for example, a source selector), show dataset metadata (name, valid/skipped rows, time range, UTC note), and remove the precedence ambiguity.

---

### AUD-07 — Medium — Evidence lacks source-row traceability

**Location:** `core/parser.py:31`, `core/detection.py:22,55`

Valid rows are rebuilt as new dictionaries containing only `timestamp`, `username`, `ip_address`, and `status`. The original CSV line number is discarded. Alert evidence therefore contains event values but no stable reference to the uploaded file's rows. Identical events cannot be distinguished.

**Impact:** An investigator can see suspicious events but cannot point to the exact source rows in the evidence table or report. This weakens the "traceable supporting evidence" requirement, especially for duplicate or near-duplicate events.

**Required direction:** Preserve a `source_row` (or equivalent) for each valid event, include it in evidence, and show it in the alert detail and evidence export.

---

### AUD-08 — Medium — Account-spray rule reports only the first episode per IP

**Location:** `core/detection.py:41-57`

The spray loop appends an alert and immediately executes `break` once the first qualifying window is found for an IP. Any later, separate spray episode from the same IP is never reported.

**Verified reproduction:** Two separate three-account episodes one hour apart produced exactly one spray alert with three evidence rows.

**Impact:** Missed multi-account targeting episodes; inconsistent with the IP/account rules' intended episode behaviour.

**Required direction:** Continue scanning after the first episode and emit one alert per distinct episode, using an efficient distinct-username counter.

---

### AUD-09 — Medium — Parser is not defensive independently of the UI

**Location:** `core/parser.py:7-34`

The 5 MB check exists only in `app.py`. The parser itself will read any size of bytes or file path. It also:

- accepts header-only CSV files with **no error message** (empty data, empty errors), producing a vague "No valid events found" screen;
- uses pandas' default NA handling, so a username such as `NA` may be converted to a missing value;
- accepts extra columns silently and has no policy for duplicate/oversized fields;
- relies on pandas' permissive date parsing, which accepts ambiguous locale-dependent formats;
- uses `iterrows()` and per-row `pd.to_datetime`, which is slower than necessary;
- reports approximate row numbers because pandas skips blank lines by default;
- may include raw exception text from pandas in the error table.

**Impact:** Inconsistent validation, surprising rejection of legitimate values, slower parsing, and weaker guarantees if the parser is reused outside the Streamlit app.

**Required direction:** Enforce size/row/column limits in the parser, use an explicit ISO timestamp policy, preserve source row numbers, use `keep_default_na=False`, and give specific empty/header-only/binary/encoding errors.

---

### AUD-10 — Medium — Detection API lacks input validation and a consistent alert contract

**Location:** `core/detection.py:25-57`

`detect_suspicious_activity` assumes:

- `timestamp` is sortable and supports subtraction;
- `status` contains exactly `SUCCESS`/`FAILED`;
- thresholds and windows are positive;
- required columns exist.

No validation is performed. Calling it with a non-datetime column, a negative threshold, or a missing column raises an uncontrolled exception. Alert dictionaries also have inconsistent keys: `ip_address` vs `username`; only account alerts have `distinct_source_ips`; only spray alerts have `distinct_accounts`. The `account_threshold` parameter actually controls **distinct accounts for spray**, not the per-account failure threshold, which is a confusing name.

**Impact:** Brittle library behaviour and awkward UI/report code. The computed `distinct_source_ips` value is not even shown in the alert expander (`app.py:87-92`).

**Required direction:** Validate inputs and raise clear `ValueError`s; define and test a consistent alert schema; display the computed distinct-IP/account context.

---

### AUD-11 — Medium — No caching; every interaction re-parses and re-detects

**Location:** `app.py:24-42`, all widgets

Streamlit reruns the script for every widget change. With an uploaded file, the app re-reads the CSV and re-runs detection on every filter change, tab interaction, or threshold update. There is no `st.cache_data` use.

**Impact:** Slow interactions, particularly with the current quadratic detector. Even after the detector is fixed, repeated parsing of a 5 MB file is unnecessary.

**Required direction:** Cache parsing/analysis by content and settings, show a spinner, and ensure changing a filter does not re-run detection.

---

### AUD-12 — Medium — UI is functional but still default/generic and has data-visualisation problems

**Location:** `app.py:7-104`

Verified with a Streamlit AppTest and a live headless run:

- AppTest: no exceptions; 12 total / 4 successful / 8 failed / 3 unique IPs / 3 alerts; 2 charts; 6 dataframes.
- Lighthouse at a 742 px viewport: Accessibility **100**, Best Practices **100**.
- Visual inspection at 742 px: the sidebar auto-collapses; five metric cards remain in one row and are cramped; default Streamlit dark theme and red accent are used; the title uses a shield emoji.

Specific issues:

| Issue | Detail |
|---|---|
| Chart colours | Both outcomes use blue shades; success/failure are not semantically distinguishable. |
| Timeline granularity | `floor("h")` collapses the 12-event sample (18:30–18:38) into a single hourly bucket, so the "activity over time" line is effectively a point per status. |
| Timeline axis | Plotly auto-ranges the y-axis starting at 4 rather than 0, exaggerating change in a small dataset. |
| Pie chart | Two-category pie is less precise than a bar chart for counts. |
| Metric row | Five columns do not adapt at narrow widths; labels become tight. |
| Alert summary | Raw `description` and varying optional keys produce a wide, inconsistent table. |
| Empty states | Top-IP table has no explicit "no failed logins" state; empty/header-only upload gets a generic message. |
| Source context | No label showing which dataset is active or its time range. |
| Upload messaging | Uploader advertises 200 MB; app enforces 5 MB. |
| Visual tone | Default red accent, emoji title, and stock Plotly styling read as a generic tutorial dashboard rather than a restrained security console. |

**Impact:** The interface works and is accessible, but it does not yet meet the professional presentation requirement.

**Required direction:** Use a restrained theme, semantic colours, responsive metric grouping, honest chart axes, clearer alert summaries, useful empty states, and explicit dataset context. Prefer native Streamlit components over fragile CSS hacks.

---

### AUD-13 — Medium — Test coverage is too thin for the claims being made

**Location:** `tests/test_parser.py`, `tests/test_detection.py`

Current coverage:

- 6 tests, all passing in 0.49 s.
- Parser: one valid row, one invalid row, one missing-column case.
- Detection: IP rule exactly at threshold, one below threshold, outside window.

Not covered:

- account rule;
- account-spray rule;
- multiple separate episodes;
- evidence contents and counts;
- exact window boundary (`==` minutes);
- severity mapping;
- mixed timezones;
- datetime dtype validation;
- header-only/empty/oversized input;
- source-row traceability;
- threshold validation;
- CSV export sanitisation;
- Streamlit app behaviour;
- performance regression.

**Impact:** The two most severe defects (AUD-01, AUD-02) are invisible to the current suite. A passing test run therefore overstates confidence.

**Required direction:** Expand to focused unit tests plus an app smoke test, and add a performance guard.

---

### AUD-14 — Low — Deprecation and test-hygiene warnings

- Streamlit 1.50 emits repeated warnings for `use_container_width` (used at `app.py:39,54,61,64,67,78,86,92`). The warning states removal after 2025-12-31.
- Pytest emits 14 `DeprecationWarning`s from `tests/test_detection.py:5` due to NumPy/Pandas timedelta handling.

**Impact:** Cosmetic today; future breakage and noisy output.

**Required direction:** Replace with `width="stretch"` when the minimum Streamlit version is raised; update the test helper.

---

### AUD-15 — Low — Documentation and operational hygiene

`README.md` is honest about scope and safe use, which is a strength. It does not document:

- project architecture;
- the detection episode/window semantics;
- severity meaning;
- evidence interpretation;
- accepted timestamp formats and timezone policy;
- search/filter/export workflow;
- security/privacy behaviour (local processing, no upload to a third party, Streamlit usage-statistics setting);
- troubleshooting and tested versions.

Other hygiene gaps:

- no `.gitignore`;
- no `.streamlit/config.toml` (upload limit, localhost binding, usage statistics, theme);
- no license (optional for an academic submission);
- no packaging/pytest configuration;
- dependencies have no upper bounds.

---

### AUD-16 — Low — Optional detection-quality considerations

These are **not** defects against the current requirements, but they affect real-world robustness and should be acknowledged or deliberately deferred:

- **IP canonicalisation:** `2001:0db8::1` and `2001:db8::1` are treated as different IPs. IPv4-mapped IPv6 addresses are also distinct.
- **Username case sensitivity:** `Alice` and `alice` are separate accounts; an attacker can evade per-account thresholds by changing case.
- **Duplicate events:** identical CSV rows are counted as separate attempts, which can inflate alerts. No duplicate policy is documented.
- **No success/failure ratio analysis per IP:** the top-IP table counts only failures, so a busy legitimate IP is not contextualised by its successes.
- **No timezone selector:** all timestamps will be normalised (recommended) but only one display convention is supported.
- **No source-row/evidence export:** alerts are visible but not directly downloadable as a long-form evidence report.

These can be addressed selectively without adding AI/ML or scope creep.

---

## 7. Security assessment

### What is already sound

| Control | Assessment |
|---|---|
| Uploaded content execution | Uploaded bytes are parsed as CSV only; no `eval`, no subprocess, no template execution. |
| File extension | Uploader restricts to `.csv`. |
| Upload size | 5 MB guard is present in the app. |
| Malformed rows | Invalid timestamp/IP/status/username rows are skipped with reasons. |
| PII handling | No passwords/tokens are requested or logged by the app; sample data is fictional. |
| Automatic response | No IP blocking, account lockout, or remediation is implemented. |
| Alert wording | UI states that alerts are patterns for review, not proof of attack. |
| Local scope | No external API calls or database persistence in application code. |
| HTML safety | Data values are rendered through Streamlit dataframes, not raw HTML. |

### Risks and gaps

| Risk | Severity | Current state |
|---|---|---|
| Spreadsheet formula injection in exported CSV | High | Unmitigated (AUD-05) |
| Parser accepts unbounded input if called directly | Medium | UI-only limit (AUD-09) |
| Detection denial of service via small dense log | High | Quadratic behaviour (AUD-02) |
| Timezone-induced UI crash | High | Unmitigated (AUD-03) |
| Incorrect/misleading alert evidence | Critical | Episodes overwritten (AUD-01) |
| Analysis of unintended dataset | Medium | Ambiguous source (AUD-06) |
| No authentication if deployed publicly | Low for local scope | README should explicitly require localhost-only use |
| Streamlit usage statistics | Low | Not explicitly disabled |
| Error messages may expose parser details | Low | Generic exception text is shown |
| CSV delimiter/field ambiguity | Low | Comma-only by implication; document it |

**Overall security posture:** Safe-by-construction for local academic use, but the export and performance issues must be fixed. There is no evidence of fabricated security metrics or simulated live monitoring, which is a notable strength.

---

## 8. UI/UX assessment

### What works

- Clear page title and subtitle.
- Persistent academic/safe-use disclaimer.
- Logical four-tab structure: Overview, Log Explorer, Security Alerts, Detection Rules.
- Threshold controls are grouped in the sidebar.
- Validation errors are shown in an expander rather than blocking silently.
- Alerts include an evidence table.
- Download buttons exist for filtered logs and alerts.
- Empty state for no alerts is explicit ("No configured detection rules were triggered").
- Accessibility score of 100 at the tested viewport.
- No excessive animation, gradients, or fake live-monitoring indicators.

### What needs improvement

1. **Semantic colour mapping** — failed events should be visually distinct from successful events (e.g., red/amber vs teal/blue), not two shades of blue.
2. **Timeline correctness** — use an adaptive bucket (minute/hour/day) so short incident logs remain meaningful; start the count axis at zero.
3. **Responsive metrics** — replace the single five-column row with a grouped layout that remains readable on narrow screens.
4. **Alert presentation** — show a compact summary table; expose severity, rule, entity, window, evidence count, and peak count; provide filters.
5. **Evidence usability** — show source rows, distinct source IPs for account alerts, distinct accounts for spray alerts, and a direct evidence download.
6. **Search and date filtering** — required and currently absent.
7. **Dataset context** — show the active file/sample name, valid/skipped counts, time range, and UTC policy.
8. **Consistent terminology** — "Alerts" can be read as incidents; "Rule matches" or a short explanation of severity would be clearer.
9. **Professional visual system** — restrained palette, neutral accent, consistent spacing/typography, no emoji-led title.
10. **Empty/error states** — specific messages for header-only files, oversized files, no failures, no search results, and no alerts.
11. **Upload guidance** — align the displayed 5 MB limit with Streamlit's configured limit; offer a CSV template.
12. **Rules tab** — show current thresholds and real hit counts per rule, plus a clear severity/limits explanation.

---

## 9. Test and QA results

### Existing test suite

```text
python -m pytest -q --durations=10
6 passed, 14 warnings in 0.49s
```

Warnings are from the test helper's timedelta construction, not from application logic.

### App smoke test (`streamlit.testing.v1.AppTest`)

```text
exception count: 0
error count: 0
metrics: Total 12, Successful 4, Failed 8, Unique IPs 3, Alerts 3
tabs: Overview, Log Explorer, Security Alerts, Detection Rules
dataframes: 6
plotly charts: 2
```

The default sample path works and renders the expected counts.

### Live UI check

- Headless Streamlit server on `localhost:8501`.
- Narrow viewport (742 × 624) rendered without functional errors.
- Lighthouse accessibility 100, best practices 100.
- Observed deprecated `use_container_width` warnings.
- Observed the default five-column metric compression and blue-on-blue status charts.

### Targeted probes

| Probe | Result |
|---|---|
| Valid CSV | 1 row, no errors |
| Missing required column | Clear "Missing columns" error |
| Invalid timestamp/IP/status | Row rejected with combined reasons |
| Mixed timezone offsets | 2 rows, `object` dtype; UI timeline crash |
| Header-only | Empty data, **no error reason** |
| BOM-prefixed CSV | Accepted |
| Semicolon-delimited CSV | Rejected as missing columns (acceptable, but undocumented) |
| Future timestamp | Accepted (no policy) |
| Formula-like username | Accepted and exported verbatim |
| Two IP episodes | One alert, latest episode only |
| Two spray episodes | One alert, first episode only |
| 6,000 dense events | 137.34 s detection |

### Audit limitations

- One synthetic performance environment; no formal load test.
- One narrow viewport for visual inspection; wide-screen review still needed.
- No fuzzing or external penetration test.
- No multi-user/concurrent-upload testing.
- No production deployment review.
- UI assessed through code, AppTest, Lighthouse, and a headless browser screenshot; not a full design review.

---

## 10. Requirements compliance summary

| Area | Verdict |
|---|---|
| Python / Streamlit / Pandas / Plotly / Pytest | Compliant |
| SQLite only if necessary | Compliant (not used) |
| CSV upload, validation, success/failure analysis | Mostly compliant |
| Repeated failures, IP activity, multi-account targeting | Implemented but correctness gaps (AUD-01, AUD-02, AUD-08) |
| Configurable thresholds | Compliant |
| Evidence-backed alerts | Partial (AUD-01, AUD-07) |
| Interactive dashboard | Compliant, basic |
| Log filtering and search | **Not compliant** (AUD-04) |
| CSV report export | Present but unsafe/limited (AUD-05) |
| Professional UI/UX | Partial (AUD-12) |
| Input/security requirements | Partial (AUD-05, AUD-09) |
| No AI/ML, no blocking, no fake metrics | Compliant |
| Modular, readable architecture | Mostly compliant; detection module needs structural repair |

---

## 11. What should be preserved

The optimization work must not discard these strengths:

- Rule-based, transparent detection with no pseudo-AI.
- Direct evidence records attached to every alert.
- Clear academic disclaimer: suspicious pattern ≠ confirmed attack.
- No automatic blocking or account lockout.
- Fictional sample data in documentation IP ranges.
- Minimal dependency set.
- Parser/detection/UI separation.
- Plain CSV output without unnecessary database or service infrastructure.
- Existing valid behaviours: case-insensitive status, IP validation, invalid-row reporting, threshold configuration, and two-way log filtering.

---

## 12. Conclusion

SecureTrack has a sound academic concept, a clean small architecture, and honest security framing. Its main weaknesses are not cosmetic: detection loses episodes, performance collapses on modest logs, mixed-timezone input can crash the dashboard, and reports are unsafe to open in a spreadsheet. The UI is serviceable but not yet at the required professional standard, and the test suite does not protect the behaviours the project claims.

The next stage proposes a prioritised optimization plan. No application code has been changed in Stage 1.
