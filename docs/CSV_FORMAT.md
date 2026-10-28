# SecureTrack — CSV Format Specification & Ingestion Rules

**Module:** `core/parser.py`  
**Application:** SecureTrack — Login Activity Analyzer  
**Scope:** Specification for input log CSV files, schema rules, normalization behavior, limits, and error handling.

---

## 1. Required Schema

Input CSV files must be comma-separated, UTF-8 encoded text files containing at least the following four columns:

| Column Name | Required Type | Description & Format | Valid Example |
|---|---|---|---|
| `timestamp` | Datetime / String | ISO 8601 date and time. May include timezone offset or be naive. | `2026-10-24 18:30:00`<br>`2026-10-24T18:30:00Z`<br>`2026-10-24T18:30:00+05:30` |
| `username` | String | Account identity attempted (1 to 256 characters). No ASCII control characters. | `alex`, `admin`, `faculty01` |
| `ip_address` | String | Valid IPv4 or IPv6 address. Port numbers are strictly rejected. | `192.0.2.20`<br>`2001:db8::1` |
| `status` | String | Outcome of the authentication attempt. Case-insensitive. | `SUCCESS`, `FAILED` |

### Sample Valid CSV

```csv
timestamp,username,ip_address,status
2026-10-24 18:30:00,alex,192.0.2.20,SUCCESS
2026-10-24 18:31:10,priya,192.0.2.21,SUCCESS
2026-10-24 18:32:00,alex,192.0.2.20,FAILED
2026-10-24 18:32:25,alex,192.0.2.20,FAILED
2026-10-24 18:32:50,alex,192.0.2.20,FAILED
2026-10-24 18:33:05,alex,192.0.2.20,FAILED
2026-10-24 18:33:20,alex,192.0.2.20,FAILED
2026-10-24 18:34:00,priya,192.0.2.21,SUCCESS
2026-10-24 18:35:00,admin,192.0.2.30,FAILED
2026-10-24 18:35:30,student01,192.0.2.30,FAILED
2026-10-24 18:36:00,faculty,192.0.2.30,FAILED
2026-10-24 18:38:00,admin,192.0.2.30,SUCCESS
```

*(This example file is bundled at `data/sample_login_logs.csv` using RFC 5737 TEST-NET-1 IP addresses).*

---

## 2. Ingestion & Validation Rules

### 2.1 File Limits & Safeguards

To protect the local analysis environment from resource exhaustion and Denial of Service (DoS):

| Bound | Limit | Constant in `core/parser.py` | Behavior on Violation |
|---|---|---|---|
| Maximum Upload Size | **5 MB** (5,242,880 bytes) | `MAX_UPLOAD_BYTES` | File rejected immediately with a fatal error. |
| Maximum Data Rows | **50,000 rows** | `MAX_DATA_ROWS` | File rejected with a fatal error if data rows exceed cap. |
| Maximum Columns | **50 columns** | `MAX_COLUMNS` | File rejected if header column count exceeds cap. |
| Maximum Recorded Errors | **500 errors** | `MAX_ERRORS_RECORDED` | Ingestion records up to 500 row errors; summary indicates truncation. |
| Maximum Username Length | **256 characters** | `MAX_USERNAME_LENGTH` | Row rejected if username length exceeds 256 chars. |

### 2.2 Character Encoding & Special Byte Handling

- **UTF-8 Support:** Files must be encoded in UTF-8 or UTF-8 with Byte Order Mark (BOM / `utf-8-sig`).
- **NUL Byte Rejection:** Any file containing NUL bytes (`\x00`) is rejected immediately as non-text / corrupt.
- **Control Character Filtering:** Usernames containing ASCII control characters (such as `\n`, `\r`, `\t`, `\x00-\x1f`) are rejected at the row level.

### 2.3 Header Normalization & Validation

- Header names are trimmed of leading/trailing whitespace and converted to lowercase for internal matching.
- **Duplicate Header Rejection:** Duplicate header names (e.g. `username` and `Username`, or two `status` columns) are rejected immediately.
- **Extra Columns:** Additional columns beyond the four required columns (e.g. `user_agent`, `city`) are accepted and ignored, ensuring compatibility with standard SIEM/firewall export formats.

### 2.4 Multiline Field Prohibition

Multiline CSV fields (e.g. quoted strings spanning multiple lines) are **strictly rejected**:
```csv
timestamp,username,ip_address,status
2026-10-24 18:30:00,"alex
attacker",192.0.2.20,FAILED
```
**Rationale:** Preserving physical line number correspondence is essential for security auditing. Disallowing embedded newlines ensures that the internal `source_row` index matches the exact line number an analyst sees in text editors or `grep`.

### 2.5 Timestamp Normalization to UTC

- The parser accepts standard ISO 8601 timestamp formats.
- Timestamps with timezone offsets (e.g., `+05:30`, `-04:00`, `Z`) are converted to **UTC**.
- Naive timestamps (without timezone indicators) are assumed to be in **UTC**.
- Ambiguous date formats (such as `10/11/12`) that cannot be parsed unambiguously without a localized format string are rejected to prevent date/month confusion.
- The output DataFrame `timestamp` column is typed as `datetime64[ns, UTC]`.

### 2.6 IP Address Verification

- Validated using Python's standard `ipaddress.ip_address` module.
- Both IPv4 (e.g. `192.0.2.1`) and IPv6 (e.g. `2001:db8::1`) are accepted.
- IP addresses with port numbers (e.g. `192.0.2.1:8080`) are rejected because ports are transport-layer attributes that fragment source host clustering.

---

## 3. Source-Row Traceability

SecureTrack maintains end-to-end evidence traceability:
1. When parsing, physical line numbers in the CSV start at line 1 (header is line 1).
2. Blank lines are skipped without resetting or skewing line numbers.
3. Every valid row is tagged with a `source_row` column containing its exact 1-based CSV line number.
4. When suspicious episodes are detected, `source_row` is preserved in the alert evidence dictionary and displayed in the UI.
5. In CSV exports (`evidence_frame`), `source_row` is included as a primary audit column.

---

## 4. Error Handling & Ingestion Resilience

The parser separates fatal errors from row-level warnings:

### Fatal File-Level Errors (No Analysis Possible)
- File is completely empty or contains only whitespace.
- File exceeds the 5 MB limit.
- File contains NUL bytes or invalid UTF-8 bytes.
- Required columns are missing.
- Duplicate column headers are present.
- Header line contains multiline quoted text.
- File contains only the header row without data events.

*Action:* The UI presents a clear red error banner detailing the reason, suppresses all charts/metrics/alerts, and displays recovery options ("Load sample" or "Clear dataset").

### Row-Level Validation Errors (Partial Ingestion)
- Specific row has missing fields, malformed IP address, invalid timestamp, or unrecognized status.
- Multiline data field encountered on a specific line.

*Action:* The parser skips the invalid row, increments `skipped_rows`, records the line number and specific reason in `errors`, and continues ingesting subsequent valid rows. The UI displays an amber warning banner with an expandable table of skipped lines and reasons.
