# SecureTrack — Security Model & Limitations

**Application:** SecureTrack — Login Activity Analyzer & Suspicious Login Detection System  
**Classification:** Academic Cybersecurity Local Prototype  

---

## 1. Security Architecture & Threat Model

SecureTrack is designed as a local forensic analysis tool for security analysts, incident responders, and students. Its security architecture follows defensive-in-depth principles:

```text
Untrusted CSV Upload
        │
        ▼
[ Resource Caps ] ───────► Max 5 MB, Max 50,000 rows, Max 50 columns
        │
        ▼
[ Ingestion Guard ] ─────► UTF-8 validation, NUL byte check, No multiline fields
        │
        ▼
[ Field Validation ] ────► IP address parsing, ISO8601 validation, UTC normalization
        │
        ▼
[ In-Memory Analysis ] ──► Linear-time detection, Source-row traceability preserved
        │
        ▼
[ Export Sanitizer ] ────► Neutralizes Spreadsheet Formula Injection (=, +, -, @)
        │
        ▼
Safe CSV Download
```

---

## 2. Defensive Controls & Safeguards

### 2.1 Denial-of-Service & Resource Exhaustion Protection
Parsing and analyzing large or malicious files can cause high CPU utilization or Out-Of-Memory (OOM) crashes. SecureTrack enforces strict boundaries at the parser layer (`core/parser.py`):
- **Upload Size Limit:** Capped at **5 MB** (`MAX_UPLOAD_BYTES = 5 * 1024 * 1024`). Files exceeding this size are rejected before being loaded into memory.
- **Row Limit:** Capped at **50,000 rows** (`MAX_DATA_ROWS = 50_000`).
- **Column Limit:** Capped at **50 columns** (`MAX_COLUMNS = 50`).
- **Error Truncation:** To prevent unbounded memory consumption from malformed files, the parser records a maximum of **500 error messages** (`MAX_ERRORS_RECORDED = 500`) while reporting the true total error count in metadata.

### 2.2 Character Encoding & Input Validation
- **NUL Byte Defense:** Binary payloads containing `\x00` bytes are rejected immediately to prevent string-termination bugs or null-byte injection.
- **Control Character Stripping:** Usernames containing ASCII control characters (`\x00-\x1f`, `\x7f`) are rejected at the row level.
- **Strict IP Parsing:** IP addresses are validated using Python's standard `ipaddress.ip_address` module. Addresses containing port suffixes (e.g. `192.0.2.1:8080`) or hostnames are rejected.
- **Multiline Field Rejection:** Multiline quoted CSV fields are strictly rejected. This prevents line-count desynchronization and ensures a 1:1 match between physical file line numbers and recorded `source_row` values.

---

## 3. Spreadsheet Formula Injection Protection (CSV Injection / CWE-1236)

### 3.1 The Vulnerability
When a security analyst exports logs or alert summaries to inspect them in Microsoft Excel, LibreOffice Calc, or Google Sheets, cells beginning with formula trigger symbols (`=`, `+`, `-`, `@`, `\t`, `\r`) can be executed as active formulas.

In a cybersecurity tool, untrusted authentication logs may contain crafted usernames (such as `=HYPERLINK(...)` or `-1+1`) designed to execute dynamic operations or exfiltrate data when an analyst opens an exported CSV report in spreadsheet software.

### 3.2 SecureTrack Mitigation (`core/export.py`)
SecureTrack implements rigorous sanitization:
1. **Targeted Sanitization:** Before exporting any DataFrame to CSV, `dataframe_to_safe_csv()` inspects text values.
2. **Dangerous Prefix Detection:** If a value's first non-whitespace character begins with `=, +, -, @, \t, \r`, an apostrophe (`'`) is prepended to force spreadsheet programs to treat the cell as raw text.
3. **Evasion Resistance:** The sanitizer strips leading whitespace, UTF-8 BOM (`\ufeff`), and zero-width spaces (`\u200b`) before checking prefixes, neutralizing evasion attempts (e.g., `  =1+1` or `\u200b@SUM(A1)`).
4. **Analysis Immutability:** Sanitization is applied only to an export copy. The in-memory analysis DataFrame remains untampered, ensuring search and detection accuracy.
5. **UTF-8 BOM Output:** CSV bytes are encoded with `utf-8-sig` to ensure Microsoft Excel correctly interprets Unicode characters without garbling.

---

## 4. Data Privacy & Confidentiality Considerations

- **Local Execution:** SecureTrack operates **entirely offline** within the local Python runtime. No log events, usernames, IP addresses, or metadata are transmitted across external networks or third-party APIs.
- **Synthetic Log Recommendations:** Users should analyze synthetic logs (such as `data/sample_login_logs.csv`) or authorized, anonymized logs.
- **Password & Secret Prohibition:** Authentication logs should **never** contain passwords, hashes, session tokens, or API keys. SecureTrack rejects files that do not adhere to the required 4-column schema (`timestamp, username, ip_address, status`).

---

## 5. Explicit Scope & Non-Capabilities

SecureTrack is an academic offline log analyzer. To avoid misrepresentation, note the following explicit non-capabilities:

| What SecureTrack DOES | What SecureTrack DOES NOT DO |
|---|---|
| Analyzes static, uploaded CSV log files | Does **not** monitor live networks or sniff packets |
| Evaluates failed login events against sliding-window rules | Does **not** inspect firewalls, syslog streams, or Windows Event Logs |
| Highlights suspicious source IPs and target accounts | Does **not** block IP addresses via firewalls or iptables |
| Highlights multi-account spray activity | Does **not** lock user accounts in Active Directory or LDAP |
| Formats auditable evidence with source-row line numbers | Does **not** establish that an attack or breach definitely occurred |
| Exports formula-safe CSV reports | Does **not** provide automated SIEM SOAR remediation actions |

---

## 6. Known Limitations

1. **In-Memory Single-Node Processing:** SecureTrack processes datasets in memory using Pandas. It is not designed for distributed big-data engines (e.g. Apache Spark).
2. **CSV-Only Ingestion:** The current parser only supports CSV format. Formats like JSON-lines, EVTX, Syslog RFC 5424, or CEF require pre-conversion to CSV.
3. **Static Thresholds:** The detection rules rely on user-configured static thresholds. They do not dynamically adapt to seasonal user traffic patterns or baseline organization behavior.
4. **Timezone Assumptions for Naive Timestamps:** Naive timestamps without explicit UTC offsets are assumed to be in UTC. In environments with local timestamps and daylight saving transitions, offsets should be included in the source CSV.

---

## 7. Potential Future Security Improvements

For production or enterprise-grade environments, the following enhancements are recommended:
1. **Syslog / Streaming Ingestion:** Add an authenticated TLS/UDP syslog listener to stream authentication events continuously.
2. **Threat Intelligence Correlation:** Correlate detected IP addresses with external threat feeds (e.g. AbuseIPDB, AlienVault OTX, Tor exit lists) to provide reputation context.
3. **Role-Based Access Control (RBAC):** If deployed as a shared web portal, introduce multi-factor authentication and role-based permissions to restrict report viewing.
4. **Automated Hashing & Log Integrity:** Calculate cryptographic hashes (SHA-256) of ingested log files at upload time and store them in an immutable audit ledger to verify forensic chain of custody.
