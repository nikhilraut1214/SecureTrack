import pandas as pd
from core.detection import detect_suspicious_activity

def dataset(seconds):
    return pd.DataFrame([{"timestamp": pd.Timestamp("2026-10-24 10:00:00")+pd.Timedelta(seconds=s),
        "username":"demo", "ip_address":"192.0.2.10", "status":"FAILED"} for s in seconds])

def test_detects_threshold():
    alerts = detect_suspicious_activity(dataset([0,20,40,60,80]), 5, 2)
    assert any(a["alert_type"] == "Repeated failed logins from one IP" for a in alerts)

def test_below_threshold_no_ip_alert():
    alerts = detect_suspicious_activity(dataset([0,20,40,60]), 5, 2)
    assert not any(a["alert_type"] == "Repeated failed logins from one IP" for a in alerts)

def test_outside_window_no_ip_alert():
    alerts = detect_suspicious_activity(dataset([0,100,200,300,400]), 5, 2)
    assert not any(a["alert_type"] == "Repeated failed logins from one IP" for a in alerts)
