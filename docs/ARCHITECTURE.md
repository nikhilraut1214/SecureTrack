# SecureTrack — System Architecture

**Project:** SecureTrack — Login Activity Analyzer & Suspicious Login Detection System  
**Classification:** Academic Cybersecurity Local Prototype  
**Technology Stack:** Python 3.10+, Streamlit, Pandas, Plotly, pytest  

---

## 1. Architectural Overview & Philosophy

SecureTrack is designed as a modular, local-first analytical prototype for security analysts and researchers. The architecture enforces strict separation of concerns:

- **Presentation Decoupling:** The Streamlit user interface (`app.py`, `ui/`) handles rendering, layout, session state, and filters. It contains **no detection algorithms or CSV parsing logic**.
- **Stateless Core Modules:** All computational logic resides in `core/`. These modules are pure Python/pandas functions that are completely agnostic of Streamlit, web requests, or database drivers. They can be imported and executed in CLI scripts, automated pipelines, or test suites.
- **Defensive Data Ingestion:** Input data is treated as untrusted. Files are parsed via strict validation schemas, bounded by memory and row caps, and normalized to UTC before any analysis begins.
- **Traceable Evidence Chain:** Every valid event retains its physical 1-based CSV line number (`source_row`). This identifier flows uninterrupted from raw input to alert generation, UI display, and final CSV exports.
- **Safe Export Guarantees:** Any CSV exported from the system is neutralised against Spreadsheet Formula Injection (CSV Injection) to protect analyst workstations.

---

## 2. System Architecture Diagram

```mermaid
flowchart TD
    subgraph UI_Layer ["Presentation & Interaction Layer (app.py, ui/)"]
        UI_Upload["File Uploader / Sample Loader"]
        UI_State["Session State Machine (sample | upload | none)"]
        UI_Filters["Exploration Filters (Status, User, IP, Date)"]
        UI_Views["Tabbed Views: Overview, Explorer, Alerts, Rules"]
        UI_Export["Download Handlers"]
    end

    subgraph Core_Parser ["Core Parser (core/parser.py)"]
        P_Validate["Strict Validation (UTF-8, Bounds, IP, ISO8601)"]
        P_Normalize["UTC Normalization & Header Sanitization"]
        P_Trace["Source-Row Numbering (1-based physical lines)"]
    end

    subgraph Core_Detector ["Core Detection Engine (core/detection.py)"]
        D_Validate["DataFrame Schema & Type Validation"]
        D_Sort["Chronological Mergesort (timestamp, source_row)"]
        D_Scan_IP["R1: IP Failure Sliding Window (Two-Pointer)"]
        D_Scan_User["R2: Account Failure Sliding Window (Two-Pointer)"]
        D_Scan_Spray["R3: Account Spray Window (Sliding Counter)"]
        D_Episodes["Episode Grouping & Peak Tracking"]
    end

    subgraph Core_Exporter ["Core Exporter (core/export.py)"]
        E_Sanitize["Spreadsheet Formula Sanitization (=, +, -, @)"]
        E_Summary["Alert Summary Builder"]
        E_Evidence["Evidence Table Flattening"]
        E_Encoding["UTF-8-BOM Encoding"]
    end

    %% Data Flow Connections
    UI_Upload -->|Raw Bytes & Source Name| Core_Parser
    Core_Parser -->|Validated DataFrame & Metadata| UI_State
    UI_State -->|Full Validated DataFrame| Core_Detector
    Core_Detector -->|Alerts with Episodes & Evidence| UI_State
    UI_State -->|Filtered Views| UI_Views
    UI_Filters -.->|Predicate Filtering (Display Only)| UI_Views
    UI_Views -->|Export Requests| Core_Exporter
    Core_Exporter -->|Safe CSV Bytes| UI_Export
```

---

## 3. Component Responsibilities

The codebase is organized into clean, single-responsibility modules:

```text
SecureTrack/
├── app.py                     # Streamlit application entry point and layout
├── core/
│   ├── __init__.py            # Core package marker
│   ├── parser.py              # Strict CSV parser, line validator, UTC normalizer
│   ├── detection.py           # Linear-time sliding-window detection engine
│   └── export.py              # Formula-safe CSV export generation
├── ui/
│   ├── __init__.py            # UI package marker
│   ├── filters.py             # Exploration filters, alert selection, timeline buckets
│   └── theme.py               # Light cybersecurity aesthetic, CSS, chart themes
├── data/
│   └── sample_login_logs.csv  # Fictional TEST-NET-1 demonstration log dataset
├── docs/                      # Comprehensive technical and user documentation
├── scripts/
│   └── benchmark_detection.py # Empirical detection performance benchmark
└── tests/                     # Comprehensive pytest test suite (112 tests)
```

### 3.1 `core/parser.py` (Parser & Validator)
- Reads raw bytes from uploaded files or local disk.
- Enforces strict input boundaries:
  - Max upload size: 5 MB (`MAX_UPLOAD_BYTES`).
  - Max data rows: 50,000 (`MAX_DATA_ROWS`).
  - Max columns: 50 (`MAX_COLUMNS`).
  - Max username length: 256 characters (`MAX_USERNAME_LENGTH`).
- Rejects invalid encodings, NUL bytes, ASCII control characters, duplicate headers, and multiline CSV fields.
- Normalizes ISO 8601 timestamps with arbitrary offsets or naive values into standardized UTC `datetime64[ns, UTC]`.
- Assigns 1-based `source_row` indices to preserve traceability back to the original CSV file.
- Separates valid records from skipped malformed rows without aborting execution on minor errors.

### 3.2 `core/detection.py` (Detection Engine)
- Receives a validated pandas DataFrame and configurable thresholds.
- Validates column presence, datatypes, absence of nulls, and allowed status values (`SUCCESS`, `FAILED`).
- Sorts records chronologically using stable mergesort (`timestamp`, `source_row`).
- Executes three independent, linear-time sliding-window rules:
  - `R1_IP_FAILURES`: Repeated failed logins from a single source IP.
  - `R2_ACCOUNT_FAILURES`: Repeated failed logins against a single account.
  - `R3_ACCOUNT_SPRAY`: Multiple distinct accounts targeted from a single source IP.
- Groups contiguous qualifying windows into distinct, non-overlapping **episodes**.
- Tracks peak intensity (events per window or distinct usernames per window).
- Computes severity tiers (`High` if peak $\ge 2 \times$ threshold, else `Medium`).
- Bundles complete supporting evidence records into each alert dictionary.

### 3.3 `core/export.py` (Export Generation)
- Formats alert dictionaries and raw events into clean, tabular structures for download.
- Protects downstream analysts against Spreadsheet Formula Injection (CSV Injection) via `sanitize_spreadsheet_cell`.
- Prepends an apostrophe (`'`) to any string field beginning with dangerous characters (`=`, `+`, `-`, `@`, `\t`, `\r`, or whitespace-bypassed variants).
- Generates UTF-8 with BOM (`utf-8-sig`) CSV bytes so that Microsoft Excel and other desktop tools open files with correct character encoding and inactive formula cells.

### 3.4 `ui/filters.py` & `ui/theme.py` (Presentation Helpers)
- `ui/filters.py`: Implements pure predicate filtering for username substring search, IP substring search, status selection, and UTC date ranges. Maps filter predicates to alert visibility without modifying underlying detection alerts or evidence.
- `ui/theme.py`: Configures light-theme styles, consistent typography, responsive card borders, Plotly chart layout overrides, integer tick formatting for small datasets, and HTML/Markdown character escaping.

### 3.5 `app.py` (Streamlit Orchestration)
- Manages the application lifecycle and session state machine (`sample`, `upload`, `none`).
- Enforces predictable precedence: uploaded files take immediate precedence over the sample dataset.
- Coordinates caching via `@st.cache_data` for byte parsing and memoizes detection runs against dataset checksums.
- Renders four responsive tabs: **Overview**, **Log Explorer**, **Security Alerts**, and **Detection Rules**.

---

## 4. Application Workflow & Data Flow

```mermaid
sequenceDiagram
    autonumber
    actor Analyst as Security Analyst
    participant App as Streamlit App (app.py)
    participant Parser as Core Parser (parser.py)
    participant Detector as Core Detector (detection.py)
    participant UI as Filter & Render (ui/)
    participant Exporter as Core Exporter (export.py)

    Analyst->>App: Launch App / Upload CSV / Load Sample
    App->>App: Evaluate State Machine (upload > sample > none)
    App->>Parser: parse_login_csv(raw_bytes, source_name)
    Note over Parser: Enforce limits, reject multiline,<br/>parse timestamps, assign source_row
    Parser-->>App: {data: DataFrame, errors: list, meta: dict}
    
    App->>Detector: detect_suspicious_activity(data, thresholds)
    Note over Detector: Filter FAILED, sort chronologically,<br/>scan sliding windows, group episodes
    Detector-->>App: list[AlertDict] (with full evidence)

    Analyst->>App: Adjust Exploration Filters (User, IP, Date, Status)
    App->>UI: build_filtered_dataframe() & filter_alerts_for_display()
    Note over UI: Filter views ONLY;<br/>Detection engine is NOT re-run
    UI-->>Analyst: Render Metrics, Charts, Tables, and Alert Cards

    Analyst->>App: Click Download Safe CSV
    App->>Exporter: dataframe_to_safe_csv() / evidence_frame()
    Note over Exporter: Sanitize formula prefixes (=, +, -, @),<br/>encode to utf-8-sig
    Exporter-->>Analyst: Downloaded Safe CSV File
```

### Step-by-Step Data Flow

1. **Dataset Ingestion:**
   When an analyst uploads a CSV file or clicks "Load sample", `app.py` computes an identity hash (`upload:<sha256>` or `sample:<mtime>:<size>`). The raw file bytes are passed to `parse_login_csv()`.

2. **Parsing & Validation:**
   The parser inspects headers, checks line count and byte size against caps, rejects multiline fields, and parses timestamps. Valid rows are packaged into a typed pandas DataFrame with a guaranteed `source_row` integer column. Malformed rows are returned in an `errors` list and rendered in a collapsible UI warning table.

3. **Detection Execution:**
   The full validated dataset is passed to `detect_suspicious_activity()` along with the detection settings from the sidebar. The detection engine filters out successful logins, segments failed logins by IP and username, and performs two-pointer sliding-window scans. Results are memoized so that re-renders with unchanged parameters execute instantaneously.

4. **Interactive Exploration & Filtering:**
   The analyst can filter records in the sidebar and main view by username, IP address, login outcome, and UTC date range. Crucially, **filters apply only to the presentation layer**. They filter rows in the Log Explorer and select which alerts are displayed on screen. Filters **never** alter the underlying detection run or truncate alert evidence.

5. **Safe Export:**
   When an analyst exports filtered logs, alert summaries, or alert evidence, the selected DataFrame is passed to `dataframe_to_safe_csv()`. Formula prefixes are neutralized in an in-memory copy, encoded with UTF-8 BOM, and returned to the browser.

---

## 5. Caching & State Management

Streamlit applications re-execute the entire script on every user interaction. To provide high performance and prevent stale state, SecureTrack implements a rigorous caching architecture:

### 5.1 Parsing Cache (`@st.cache_data`)
```python
@st.cache_data(show_spinner=False, max_entries=8)
def _parse_cached(raw: bytes, source_name: str) -> dict[str, Any]:
    return parse_login_csv(raw, source_name=source_name)
```
- **Key:** Exact raw bytes of the file and source filename.
- **Invalidation:** Changing or uploading a new file automatically generates a new cache key. Replacing the sample CSV on disk invalidates the cache based on file modification timestamp and size.

### 5.2 Detection Memoization
- Detection results are cached in `st.session_state` under `analysis_key`:
  $$\text{analysis\_key} = (\text{dataset\_id}, \text{threshold}, \text{window}, \text{spray\_users}, \text{spray\_window})$$
- When any threshold or the underlying dataset changes, `analysis_key` changes, prompting a fresh detection execution.
- When the user merely modifies UI filters (e.g. searching for a username or changing a date range), `analysis_key` remains identical; detection is **not** re-run, ensuring immediate UI responsiveness.

### 5.3 Stale Result Prevention
- Clearing the dataset via "Clear dataset" transitions the session state to `none`, immediately wiping `analysis_key`, `alerts`, `dataset_id`, and all filter state keys.
- Removing an uploaded file clears previous analysis artifacts rather than falling back to stale memory state.
- Uploading an invalid or oversized file switches the app to an error display state, immediately suppressing previous metrics, charts, and alert cards.
