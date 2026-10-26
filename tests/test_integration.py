from core.detection import RULE_IP_FAILURES, detect_suspicious_activity
from core.export import dataframe_to_safe_csv, evidence_frame
from core.parser import parse_login_csv


def test_mixed_timezone_csv_parses_and_detects_without_crashing():
    raw = (
        b"timestamp,username,ip_address,status\n"
        b"2026-10-24 10:00:00+00:00,u1,192.0.2.1,FAILED\n"
        b"2026-10-24 12:00:10+02:00,u1,192.0.2.1,FAILED\n"
        b"2026-10-24 12:00:20+02:00,u1,192.0.2.1,FAILED\n"
        b"2026-10-24 12:00:30+02:00,u1,192.0.2.1,FAILED\n"
        b"2026-10-24 12:00:40+02:00,u1,192.0.2.1,FAILED\n"
    )
    result = parse_login_csv(raw)
    assert not result["errors"]
    assert str(result["data"]["timestamp"].dtype) == "datetime64[ns, UTC]"

    # This is the operation that previously raised AttributeError.
    buckets = result["data"]["timestamp"].dt.floor("h")
    assert len(buckets) == 5

    alerts = detect_suspicious_activity(result["data"], 5, 2)
    ip_alerts = [alert for alert in alerts if alert["rule_id"] == RULE_IP_FAILURES]
    assert len(ip_alerts) == 1
    assert ip_alerts[0]["event_count"] == 5
    assert [event["source_row"] for event in ip_alerts[0]["evidence"]] == [
        2,
        3,
        4,
        5,
        6,
    ]


def test_source_rows_flow_from_csv_to_alert_evidence():
    raw = (
        b"timestamp,username,ip_address,status\n"
        b"\n"
        b"2026-10-24 10:00:00,alice,192.0.2.1,FAILED\n"
        b"2026-10-24 10:00:10,alice,192.0.2.1,FAILED\n"
        b"2026-10-24 10:00:20,alice,192.0.2.1,FAILED\n"
        b"2026-10-24 10:00:30,alice,192.0.2.1,FAILED\n"
        b"2026-10-24 10:00:40,alice,192.0.2.1,FAILED\n"
    )
    result = parse_login_csv(raw)
    assert [row["source_row"] for row in result["data"].to_dict("records")] == [
        3,
        4,
        5,
        6,
        7,
    ]

    alerts = detect_suspicious_activity(result["data"], 5, 2)
    alert = [item for item in alerts if item["rule_id"] == RULE_IP_FAILURES][0]
    assert [event["source_row"] for event in alert["evidence"]] == [3, 4, 5, 6, 7]


def test_formula_username_is_preserved_for_analysis_but_sanitized_on_export():
    raw = (
        b"timestamp,username,ip_address,status\n"
        b"2026-10-24 10:00:00,=cmd|' /C calc'!A0,192.0.2.1,FAILED\n"
        b"2026-10-24 10:00:10,=cmd|' /C calc'!A0,192.0.2.1,FAILED\n"
        b"2026-10-24 10:00:20,=cmd|' /C calc'!A0,192.0.2.1,FAILED\n"
        b"2026-10-24 10:00:30,=cmd|' /C calc'!A0,192.0.2.1,FAILED\n"
        b"2026-10-24 10:00:40,=cmd|' /C calc'!A0,192.0.2.1,FAILED\n"
    )
    result = parse_login_csv(raw)
    assert not result["errors"]
    assert result["data"].iloc[0]["username"] == "=cmd|' /C calc'!A0"

    alerts = detect_suspicious_activity(result["data"], 5, 2)
    output = dataframe_to_safe_csv(evidence_frame(alerts)).decode("utf-8-sig")
    assert "'=cmd|' /C calc'!A0" in output

    logs = dataframe_to_safe_csv(result["data"]).decode("utf-8-sig")
    assert "'=cmd|' /C calc'!A0" in logs
    assert result["data"].iloc[0]["username"] == "=cmd|' /C calc'!A0"
