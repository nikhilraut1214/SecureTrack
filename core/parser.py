from io import BytesIO
import ipaddress
import pandas as pd

REQUIRED = {"timestamp", "username", "ip_address", "status"}

def parse_login_csv(source):
    try:
        frame = pd.read_csv(BytesIO(source), dtype=str) if isinstance(source, (bytes, bytearray)) else pd.read_csv(source, dtype=str)
    except Exception as exc:
        return {"data": pd.DataFrame(columns=["timestamp","username","ip_address","status"]),
                "errors": [{"row": "-", "reason": f"Could not read CSV: {exc}"}]}
    frame.columns = [str(c).strip().lower() for c in frame.columns]
    missing = REQUIRED - set(frame.columns)
    if missing:
        return {"data": pd.DataFrame(columns=["timestamp","username","ip_address","status"]),
                "errors": [{"row": "-", "reason": "Missing columns: " + ", ".join(sorted(missing))}]}
    valid, errors = [], []
    for idx, row in frame.iterrows():
        ts = pd.to_datetime(row["timestamp"], errors="coerce")
        user, ip, status = str(row["username"]).strip(), str(row["ip_address"]).strip(), str(row["status"]).strip().upper()
        problems = []
        if pd.isna(ts): problems.append("invalid timestamp")
        if not user or user.lower() == "nan": problems.append("empty username")
        try: ipaddress.ip_address(ip)
        except ValueError: problems.append("invalid IP address")
        if status not in {"SUCCESS", "FAILED"}: problems.append("status must be SUCCESS or FAILED")
        if problems:
            errors.append({"row": idx + 2, "reason": "; ".join(problems)})
        else:
            valid.append({"timestamp": ts, "username": user, "ip_address": ip, "status": status})
    data = pd.DataFrame(valid, columns=["timestamp","username","ip_address","status"])
    if not data.empty: data = data.sort_values("timestamp").reset_index(drop=True)
    return {"data": data, "errors": errors}
