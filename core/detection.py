import pandas as pd

def _sliding_alerts(group, field, threshold, minutes, alert_name, description):
    group = group.sort_values("timestamp").reset_index(drop=True)
    times = group.timestamp.tolist()
    alerts, left = [], 0
    for right in range(len(group)):
        while left <= right and (times[right] - times[left]).total_seconds() > minutes * 60:
            left += 1
        count = right - left + 1
        if count >= threshold:
            evidence = group.iloc[left:right+1]
            value = str(group.iloc[right][field])
            if alerts and alerts[-1][field] == value:
                alerts[-1].update(start_time=str(times[left]), end_time=str(times[right]),
                                  event_count=int(count), evidence=evidence.to_dict("records"))
            else:
                alerts.append({"alert_type": alert_name, field: value,
                    "severity": "High" if count >= threshold * 2 else "Medium",
                    "start_time": str(times[left]), "end_time": str(times[right]),
                    "event_count": int(count), "description": description,
                    "evidence": evidence.to_dict("records")})
    return alerts

def detect_suspicious_activity(df, threshold=5, window_minutes=2,
                               account_threshold=3, account_window_minutes=5):
    failed = df[df.status == "FAILED"].copy()
    alerts = []
    if failed.empty: return alerts
    for _, group in failed.groupby("ip_address"):
        alerts += _sliding_alerts(group, "ip_address", threshold, window_minutes,
            "Repeated failed logins from one IP",
            f"At least {threshold} failed attempts from this IP occurred within {window_minutes} minutes.")
    for _, group in failed.groupby("username"):
        account_alerts = _sliding_alerts(group, "username", threshold, window_minutes,
            "Repeated failed logins against one account",
            f"At least {threshold} failed attempts against this account occurred within {window_minutes} minutes.")
        for alert in account_alerts:
            alert["distinct_source_ips"] = len({x["ip_address"] for x in alert["evidence"]})
        alerts += account_alerts
    for ip, group in failed.groupby("ip_address"):
        group = group.sort_values("timestamp").reset_index(drop=True)
        times, left = group.timestamp.tolist(), 0
        for right in range(len(group)):
            while left <= right and (times[right] - times[left]).total_seconds() > account_window_minutes * 60:
                left += 1
            window = group.iloc[left:right+1]
            distinct = window.username.nunique()
            if distinct >= account_threshold:
                alerts.append({"alert_type": "Multiple accounts targeted by one IP",
                    "ip_address": str(ip), "severity": "Medium",
                    "start_time": str(times[left]), "end_time": str(times[right]),
                    "event_count": len(window), "distinct_accounts": int(distinct),
                    "description": f"This IP generated failed attempts against at least {account_threshold} accounts within {account_window_minutes} minutes.",
                    "evidence": window.to_dict("records")})
                break
    return sorted(alerts, key=lambda x: (x["severity"] != "High", x["start_time"]))
