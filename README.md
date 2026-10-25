# SecureTrack — Login Activity Analyzer

A local academic cybersecurity prototype. It analyzes uploaded authentication CSV logs and flags potentially suspicious repeated failed-login patterns.

## Requirements
- Python 3.10+
- pip

## Setup — Windows PowerShell
```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
streamlit run app.py
```

If PowerShell blocks environment activation:
```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m streamlit run app.py
```

## Tests
```powershell
python -m pytest -q
```

## CSV format
Required columns: `timestamp`, `username`, `ip_address`, `status`. Status must be `SUCCESS` or `FAILED`. A sample file is in `data/sample_login_logs.csv`.

## Detection defaults
- 5 failures from one IP within 2 minutes.
- 5 failures against one username within 2 minutes.
- 3 distinct usernames attempted from one IP within 5 minutes.

These are demonstration thresholds, not universal standards.

## Limitations and safe use
SecureTrack analyzes only supplied records. It does not monitor live traffic, block IP addresses, lock accounts, or prove an attack occurred. Use synthetic or authorized anonymized logs only. Never upload passwords, tokens, or confidential production data.
