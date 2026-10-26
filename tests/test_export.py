import pandas as pd
import pytest

from core.export import (
    ALERT_SUMMARY_COLUMNS,
    EVIDENCE_COLUMNS,
    alert_summary_frame,
    dataframe_to_safe_csv,
    evidence_frame,
    sanitize_spreadsheet_cell,
)


@pytest.mark.parametrize(
    "value,expected",
    [
        ("=1+1", "'=1+1"),
        ("+SUM(A1)", "'+SUM(A1)"),
        ("-1+1", "'-1+1"),
        ("@SUM(A1)", "'@SUM(A1)"),
        ("\t=1+1", "'\t=1+1"),
        ("\r=1+1", "'\r=1+1"),
        (" =1+1", "' =1+1"),
        ("\n=1+1", "'\n=1+1"),
        ("\ufeff=1+1", "'\ufeff=1+1"),
        ("\u200b@SUM(A1)", "'\u200b@SUM(A1)"),
        ("alice", "alice"),
        ("192.0.2.1", "192.0.2.1"),
        ("2026-10-24T10:00:00+00:00", "2026-10-24T10:00:00+00:00"),
    ],
)
def test_sanitize_spreadsheet_cell(value, expected):
    assert sanitize_spreadsheet_cell(value) == expected


def test_sanitize_non_string_values_are_unchanged():
    for value in (1, 2.5, None, True):
        assert sanitize_spreadsheet_cell(value) is value


def test_safe_csv_neutralises_formula_values_and_preserves_originals():
    frame = pd.DataFrame(
        {
            "username": ["=cmd|' /C calc'!A0", "alice"],
            "ip_address": ["192.0.2.1", "@evil"],
            "attempts": [1, 2],
        }
    )
    output = dataframe_to_safe_csv(frame)
    text = output.decode("utf-8-sig")

    assert "'=cmd|' /C calc'!A0" in text
    assert "'@evil" in text
    assert "alice" in text
    assert "attempts" in text
    # The in-memory data is unchanged.
    assert frame.iloc[0]["username"] == "=cmd|' /C calc'!A0"
    assert frame.iloc[1]["ip_address"] == "@evil"


def test_safe_csv_has_utf8_bom():
    output = dataframe_to_safe_csv(pd.DataFrame({"username": ["alice"]}))
    assert output.startswith(b"\xef\xbb\xbf")


def test_safe_csv_empty_frame_has_header_only():
    frame = pd.DataFrame(columns=["username", "ip_address"])
    output = dataframe_to_safe_csv(frame)
    text = output.decode("utf-8-sig")
    assert text.strip() == "username,ip_address"


def test_alert_summary_frame_has_stable_columns_and_no_evidence():
    alerts = [
        {
            "alert_id": "ST-0001",
            "rule_id": "R1_IP_FAILURES",
            "alert_type": "Repeated failed logins from one IP",
            "entity_type": "ip",
            "entity_value": "192.0.2.1",
            "severity": "Medium",
            "start_time": "2026-10-24T10:00:00+00:00",
            "end_time": "2026-10-24T10:00:40+00:00",
            "event_count": 5,
            "peak_window_count": 5,
            "distinct_source_ips": None,
            "distinct_accounts": None,
            "peak_distinct_accounts": None,
            "peak_window_start": "2026-10-24T10:00:00+00:00",
            "peak_window_end": "2026-10-24T10:00:40+00:00",
            "threshold": 5,
            "window_minutes": 2,
            "description": "test",
            "evidence": [{"timestamp": "ignored"}],
        }
    ]
    frame = alert_summary_frame(alerts)
    assert list(frame.columns) == ALERT_SUMMARY_COLUMNS
    assert len(frame) == 1
    assert frame.iloc[0]["alert_id"] == "ST-0001"
    assert "evidence" not in frame.columns


def test_alert_summary_frame_empty_still_has_columns():
    frame = alert_summary_frame([])
    assert frame.empty
    assert list(frame.columns) == ALERT_SUMMARY_COLUMNS


def test_evidence_frame_flattens_all_alerts_with_source_rows():
    alerts = [
        {
            "alert_id": "ST-0001",
            "rule_id": "R1_IP_FAILURES",
            "alert_type": "Repeated failed logins from one IP",
            "severity": "Medium",
            "entity_type": "ip",
            "entity_value": "192.0.2.1",
            "start_time": "2026-10-24T10:00:00+00:00",
            "end_time": "2026-10-24T10:00:20+00:00",
            "evidence": [
                {
                    "source_row": 2,
                    "timestamp": "2026-10-24T10:00:00+00:00",
                    "username": "alice",
                    "ip_address": "192.0.2.1",
                    "status": "FAILED",
                },
                {
                    "source_row": 3,
                    "timestamp": "2026-10-24T10:00:20+00:00",
                    "username": "alice",
                    "ip_address": "192.0.2.1",
                    "status": "FAILED",
                },
            ],
        },
        {
            "alert_id": "ST-0002",
            "rule_id": "R3_ACCOUNT_SPRAY",
            "alert_type": "Multiple accounts targeted by one IP",
            "severity": "Medium",
            "entity_type": "ip",
            "entity_value": "192.0.2.2",
            "start_time": "2026-10-24T11:00:00+00:00",
            "end_time": "2026-10-24T11:00:10+00:00",
            "evidence": [
                {
                    "source_row": 9,
                    "timestamp": "2026-10-24T11:00:00+00:00",
                    "username": "bob",
                    "ip_address": "192.0.2.2",
                    "status": "FAILED",
                }
            ],
        },
    ]
    frame = evidence_frame(alerts)
    assert list(frame.columns) == EVIDENCE_COLUMNS
    assert len(frame) == 3
    assert frame["alert_id"].tolist() == ["ST-0001", "ST-0001", "ST-0002"]
    assert frame["source_row"].tolist() == [2, 3, 9]


def test_evidence_frame_empty_still_has_columns():
    frame = evidence_frame([])
    assert frame.empty
    assert list(frame.columns) == EVIDENCE_COLUMNS


def test_evidence_export_is_safe_and_complete():
    alerts = [
        {
            "alert_id": "ST-0001",
            "rule_id": "R2_ACCOUNT_FAILURES",
            "alert_type": "Repeated failed logins against one account",
            "severity": "Medium",
            "entity_type": "username",
            "entity_value": "=evil",
            "start_time": "2026-10-24T10:00:00+00:00",
            "end_time": "2026-10-24T10:00:00+00:00",
            "evidence": [
                {
                    "source_row": 2,
                    "timestamp": "2026-10-24T10:00:00+00:00",
                    "username": "=evil",
                    "ip_address": "192.0.2.1",
                    "status": "FAILED",
                }
            ],
        }
    ]
    output = dataframe_to_safe_csv(evidence_frame(alerts))
    text = output.decode("utf-8-sig")
    assert "'=evil" in text
    assert "source_row" in text
    assert "ST-0001" in text
