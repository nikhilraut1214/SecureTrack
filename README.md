# SecureTrack — Login Activity Analyzer & Suspicious Login Detection System

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Streamlit](https://img.shields.io/badge/streamlit-1.50+-FF4B4B.svg)](https://streamlit.io/)
[![pytest](https://img.shields.io/badge/pytest-8.0+-green.svg)](https://docs.pytest.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

> **Academic Prototype Notice:**  
> SecureTrack is a local academic cybersecurity software prototype for analyzing static authentication log CSV files. It identifies potentially suspicious patterns (repeated failed logins, targeted accounts, and account-spray activity) to assist analysts during triage.  
> **It does not monitor live networks, block IP addresses, or lock user accounts.**

---

## 1. Problem Statement & Objectives

Authentication logs are the first line of forensic detection in cybersecurity operations. However, small teams, educational institutions, and junior analysts often lack access to complex enterprise SIEM systems or find them overly complex for quick, ad-hoc forensic triage.

### Objectives
1. **Automate Triage:** Rapidly detect brute-force, password-guessing, and credential-spraying patterns in exported authentication logs.
2. **Deterministic, Transparent Rules:** Provide 100% explainable, rule-based sliding-window detection without opaque black-box machine learning models.
3. **End-to-End Auditability:** Preserve physical line-number traceability (`source_row`) from input CSV to visual alert cards and exported reports.
4. **Analyst Safety:** Safeguard investigating analysts by neutralizing Spreadsheet Formula Injection (CSV Injection) in all exported reports.

---

## 2. Key Features

- **Strict, Defensive CSV Ingestion:**
  - Fast single-pass parsing with memory and row caps (up to 5 MB, 50,000 data rows).
  - Strict validation of ISO 8601 timestamps, IPv4/IPv6 addresses, and authentication statuses (`SUCCESS`/`FAILED`).
  - Automatic UTC normalization of naive or mixed-timezone records.
  - Immediate rejection of NUL bytes, duplicate headers, and multiline CSV fields to guarantee physical line-number traceability.
- **High-Performance Rule-Based Detection Engine ($O(N)$ Scanning, $O(N \log N)$ Pipeline):**
  - **Rule 1 (`R1_IP_FAILURES`):** Repeated failed logins from a single IP address within a configurable sliding window.
  - **Rule 2 (`R2_ACCOUNT_FAILURES`):** Repeated failed logins against a single user account within a configurable sliding window.
  - **Rule 3 (`R3_ACCOUNT_SPRAY`):** Multiple distinct accounts targeted from a single IP address within a configurable sliding window.
  - **Episode Consolidation:** Contiguous qualifying sliding windows are merged into single distinct episodes with peak metrics, eliminating alert fatigue.
  - **Two-Tier Severity:** Deterministic `High` (peak $\ge 2 \times$ threshold) and `Medium` severity badges.
- **Interactive Presentation & Exploration UI:**
  - Professional, restrained cybersecurity light theme (built with Streamlit and Plotly).
  - Clear dataset lifecycle state machine: sample data, uploaded files, and clean empty states.
  - Exploration filters for username substring, IP substring, login status, and UTC date ranges.
  - Responsive layouts optimized for desktop, tablet, and mobile viewports.
- **Safe CSV Report Exports:**
  - Automatic sanitization against Spreadsheet Formula Injection (CWE-1236) targeting characters `=`, `+`, `-`, `@`, `\t`, `\r`.
  - UTF-8 with BOM (`utf-8-sig`) encoding for seamless Microsoft Excel compatibility.
  - Export filtered log views, high-level alert summaries, or comprehensive flattened evidence tables.

---

## 3. Technology Stack

- **Language:** Python 3.10+ (Tested through Python 3.14.2)
- **Web UI & Dashboard:** [Streamlit](https://streamlit.io/) ($\ge 1.50$)
- **Data Analysis & Processing:** [Pandas](https://pandas.pydata.org/) ($\ge 2.0$)
- **Interactive Visualizations:** [Plotly](https://plotly.com/python/) ($\ge 5.18$)
- **Testing Framework:** [pytest](https://docs.pytest.org/) ($\ge 8.0$)

---

## 4. System Requirements & Installation

### Requirements
- **OS:** Windows 10/11, macOS 12+, or modern Linux (Ubuntu 22.04+, Debian 12+)
- **Python:** Python 3.10 or higher
- **Browser:** Any modern Chromium-based browser (Chrome, Edge, Brave), Firefox, or Safari

### Installation Steps

1. **Clone the repository:**
   ```bash
   git clone https://github.com/nikhilraut1214/SecureTrack.git
   cd SecureTrack
   ```

2. **Create and activate a virtual environment:**

   *Windows PowerShell:*
   ```powershell
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1
   ```
   *(If PowerShell script execution is restricted, run: `Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process` or invoke via `.\.venv\Scripts\python.exe`)*

   *Linux / macOS Bash:*
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

---

## 5. How to Run the Application

With your virtual environment activated, run:

```bash
streamlit run app.py
```

The application will start the local web server and launch your default browser at:
```text
http://localhost:8501
```

---

## 6. Using the Application (Quickstart)

1. **Review Sample Data:** SecureTrack launches with a built-in fictional dataset (`data/sample_login_logs.csv`) demonstrating failed login episodes and account-spray patterns using RFC 5737 TEST-NET-1 IP addresses (`192.0.2.0/24`).
2. **Upload Your Logs:** In the sidebar, drag and drop an authentication CSV file (up to 5 MB). Uploads immediately take precedence over sample data.
3. **Configure Detection Parameters:** Adjust the failure thresholds and sliding-window durations in the sidebar as needed.
4. **Explore Logs:** Switch to the **Log Explorer** tab to inspect event records, search by username or IP, or filter by date range.
5. **Triage Alerts:** Switch to the **Security Alerts** tab to inspect flagged episodes, read incident descriptions, view peak metrics, and expand supporting evidence.
6. **Download Reports:** Click **Download alert summary (CSV)** or **Download all alert evidence (CSV)** to export safe, formula-sanitized reports for further analysis.
7. **Reset:** Click **Clear dataset** to enter a clean state, or click **Load sample** to restore the demonstration log set.

---

## 7. Expected CSV Format

Input CSV files must be comma-separated UTF-8 text containing at least the following four columns:

```csv
timestamp,username,ip_address,status
2026-10-24 18:30:00,alex,192.0.2.20,SUCCESS
2026-10-24 18:31:10,priya,192.0.2.21,SUCCESS
2026-10-24 18:32:00,alex,192.0.2.20,FAILED
2026-10-24 18:32:25,alex,192.0.2.20,FAILED
2026-10-24 18:32:50,alex,192.0.2.20,FAILED
2026-10-24 18:33:05,alex,192.0.2.20,FAILED
2026-10-24 18:33:20,alex,192.0.2.20,FAILED
2026-10-24 18:35:00,admin,192.0.2.30,FAILED
2026-10-24 18:35:30,student01,192.0.2.30,FAILED
2026-10-24 18:36:00,faculty,192.0.2.30,FAILED
```

- **Timestamp:** ISO 8601 string (e.g. `YYYY-MM-DD HH:MM:SS` or `YYYY-MM-DDTHH:MM:SSZ`).
- **Username:** Alphanumeric / printable string (up to 256 characters).
- **IP Address:** Valid IPv4 or IPv6 address (no port suffixes).
- **Status:** Case-insensitive `SUCCESS` or `FAILED`.

For complete ingestion rules and edge cases, refer to [docs/CSV_FORMAT.md](docs/CSV_FORMAT.md).

---

## 8. Testing & Verification

SecureTrack includes a comprehensive automated test suite of **112 test cases** covering parser boundaries, sliding-window algorithms, spreadsheet sanitization, integration pipelines, and Streamlit UI interactions.

### Run Automated Tests
```powershell
python -m pytest -q -W error
```
*(All 112 tests pass cleanly with zero warnings).*

### Run Empirical Detection Benchmark
```powershell
python scripts/benchmark_detection.py
```
*(Demonstrates linear-time $O(N)$ sliding-window scanning across dense datasets up to 50,000 events in ~0.61s).*

For complete testing details and benchmarks, see [docs/TESTING.md](docs/TESTING.md).

---

## 9. Project Structure

```text
SecureTrack/
├── app.py                         # Streamlit application entry point and dashboard
├── requirements.txt               # Pinned package dependencies
├── README.md                      # Primary project overview and instructions
│
├── core/                          # Stateless core business logic modules
│   ├── __init__.py                # Package marker
│   ├── parser.py                  # Defensive CSV parser, validator & UTC normalizer
│   ├── detection.py               # Linear-time sliding-window detection engine
│   └── export.py                  # Formula-safe CSV export generation
│
├── ui/                            # Presentation and styling helpers
│   ├── __init__.py                # Package marker
│   ├── filters.py                 # Pure filter predicates and alert display selectors
│   └── theme.py                   # Light UI theme, responsive CSS, Plotly styling
│
├── data/
│   └── sample_login_logs.csv      # Fictional RFC 5737 demonstration dataset
│
├── docs/                          # Comprehensive technical and user documentation
│   ├── ARCHITECTURE.md            # System architecture, data flow, sequence diagrams
│   ├── DETECTION_LOGIC.md         # Sliding-window rules, episode merging, severity
│   ├── CSV_FORMAT.md              # Input CSV specifications and validation rules
│   ├── TESTING.md                 # Test suite breakdown, coverage, benchmark report
│   ├── SECURITY_AND_LIMITATIONS.md# Threat model, formula injection, limitations
│   ├── USER_GUIDE.md              # Visual step-by-step walkthrough with screenshots
│   └── screenshots/               # Real UI screenshots across viewports
│
├── scripts/
│   └── benchmark_detection.py     # Empirical detection performance benchmark
│
└── tests/                         # Pytest test suite (112 tests)
    ├── test_parser.py             # Parser boundary, limit, and encoding tests (33)
    ├── test_detection.py          # Window, episode, severity, and spray tests (41)
    ├── test_export.py             # Spreadsheet formula injection protection tests (21)
    ├── test_integration.py        # End-to-end ingestion-to-export tests (3)
    ├── test_ui_filters.py         # UI filter predicates and helper tests (8)
    └── test_app.py                # Streamlit AppTest interface tests (6)
```

---

## 10. Complete Documentation Index

For in-depth technical documentation, refer to the following guides in the `docs/` folder:

| Document | Description |
|---|---|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | High-level system architecture, component breakdown, sequence diagrams, and data flows. |
| [docs/DETECTION_LOGIC.md](docs/DETECTION_LOGIC.md) | Sliding-window mathematical logic, episode grouping, peak tracking, and severity classification. |
| [docs/CSV_FORMAT.md](docs/CSV_FORMAT.md) | Ingestion schema, field limits, UTC normalization, and error handling. |
| [docs/TESTING.md](docs/TESTING.md) | Comprehensive test suite documentation, edge cases, and performance benchmarks. |
| [docs/SECURITY_AND_LIMITATIONS.md](docs/SECURITY_AND_LIMITATIONS.md) | Threat model, CSV formula injection defense, privacy boundaries, and explicit limitations. |
| [docs/USER_GUIDE.md](docs/USER_GUIDE.md) | Complete user guide and walkthrough featuring real UI screenshots across desktop and mobile. |

---

## 11. Limitations & Safe Use

- **Academic Prototype Scope:** SecureTrack is a local academic prototype. It is not an enterprise SIEM or Intrusion Prevention System (IPS).
- **No Network Ingestion:** SecureTrack does not capture live packets, listen on network interfaces, or intercept authentication streams.
- **No Active Countermeasures:** SecureTrack never blocks IP addresses, modifies firewalls, or locks user accounts.
- **Triage Indicator Only:** Flagged alerts indicate statistical deviations requiring human review; they do not establish that an attack or security compromise definitely occurred.
- **Data Privacy:** Users should only upload synthetic logs or authorized, anonymized logs. Never upload files containing plaintext passwords, session tokens, or private user data.

---

## 12. Future Scope

Potential enhancements for future iterations:
1. **Syslog RFC 5424 / Windows Event Log (EVTX) Support:** Ingest syslog streams and Windows Security event logs directly.
2. **Threat Intelligence Correlation:** Cross-reference flagged IP addresses with reputation databases (e.g., AbuseIPDB, AlienVault OTX, Tor exit lists).
3. **Adaptive Dynamic Baselines:** Calculate per-user and per-IP baseline failure rates to reduce false positives during legitimate enterprise password reset periods.
4. **Export Formats:** Add structured JSON-LD and STIX 2.1 threat intelligence export formats.
