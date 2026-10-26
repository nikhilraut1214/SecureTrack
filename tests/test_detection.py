import time

import pandas as pd
import pytest

from core.detection import (
    ALERT_ACCOUNT_FAILURES,
    ALERT_ACCOUNT_SPRAY,
    ALERT_IP_FAILURES,
    RULE_ACCOUNT_FAILURES,
    RULE_ACCOUNT_SPRAY,
    RULE_IP_FAILURES,
    detect_suspicious_activity,
)

BASE = pd.Timestamp("2026-10-24T10:00:00Z")
NAIVE_BASE = pd.Timestamp("2026-10-24 10:00:00")


def make_frame(
    offsets,
    *,
    users=None,
    ips=None,
    statuses=None,
    source_rows=True,
    tz=True,
):
    count = len(offsets)
    base = BASE if tz else NAIVE_BASE
    data = {
        "timestamp": base + pd.to_timedelta(offsets, unit="s"),
        "username": users if users is not None else ["user"] * count,
        "ip_address": ips if ips is not None else ["192.0.2.10"] * count,
        "status": statuses if statuses is not None else ["FAILED"] * count,
    }
    if source_rows:
        data["source_row"] = list(range(2, count + 2))
    return pd.DataFrame(data)


def rule_alerts(alerts, rule_id):
    return [alert for alert in alerts if alert["rule_id"] == rule_id]


def test_detects_threshold():
    alerts = detect_suspicious_activity(make_frame([0, 20, 40, 60, 80]), 5, 2)
    ip_alerts = rule_alerts(alerts, RULE_IP_FAILURES)
    assert len(ip_alerts) == 1
    assert ip_alerts[0]["alert_type"] == ALERT_IP_FAILURES
    assert ip_alerts[0]["event_count"] == 5
    assert ip_alerts[0]["peak_window_count"] == 5
    assert ip_alerts[0]["severity"] == "Medium"


def test_below_threshold_no_ip_alert():
    alerts = detect_suspicious_activity(make_frame([0, 20, 40, 60]), 5, 2)
    assert not rule_alerts(alerts, RULE_IP_FAILURES)


def test_outside_window_no_ip_alert():
    alerts = detect_suspicious_activity(
        make_frame([0, 100, 200, 300, 400]), 5, 2
    )
    assert not rule_alerts(alerts, RULE_IP_FAILURES)


def test_window_boundary_is_inclusive():
    alerts = detect_suspicious_activity(
        make_frame([0, 30, 60, 90, 120]), 5, 2
    )
    assert len(rule_alerts(alerts, RULE_IP_FAILURES)) == 1


def test_separate_episodes_produce_separate_alerts_and_evidence():
    offsets = [0, 10, 20, 30, 40, 3600, 3610, 3620, 3630, 3640]
    alerts = rule_alerts(
        detect_suspicious_activity(make_frame(offsets), 5, 2),
        RULE_IP_FAILURES,
    )
    assert len(alerts) == 2
    assert alerts[0]["start_time"] == "2026-10-24T10:00:00+00:00"
    assert alerts[0]["end_time"] == "2026-10-24T10:00:40+00:00"
    assert alerts[1]["start_time"] == "2026-10-24T11:00:00+00:00"
    assert alerts[1]["end_time"] == "2026-10-24T11:00:40+00:00"
    assert [event["source_row"] for event in alerts[0]["evidence"]] == [2, 3, 4, 5, 6]
    assert [event["source_row"] for event in alerts[1]["evidence"]] == [7, 8, 9, 10, 11]


def test_one_long_episode_keeps_all_evidence():
    offsets = list(range(0, 100, 10))  # 10 events over 90 seconds
    alerts = rule_alerts(
        detect_suspicious_activity(make_frame(offsets), 5, 2),
        RULE_IP_FAILURES,
    )
    assert len(alerts) == 1
    assert alerts[0]["event_count"] == 10
    assert alerts[0]["peak_window_count"] == 10
    assert len(alerts[0]["evidence"]) == 10


def test_account_rule_and_distinct_source_ips():
    alerts = detect_suspicious_activity(
        make_frame(
            [0, 10, 20, 30, 40],
            users=["alice"] * 5,
            ips=["192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4", "192.0.2.5"],
        ),
        5,
        2,
    )
    account_alerts = rule_alerts(alerts, RULE_ACCOUNT_FAILURES)
    assert len(account_alerts) == 1
    assert account_alerts[0]["alert_type"] == ALERT_ACCOUNT_FAILURES
    assert account_alerts[0]["entity_value"] == "alice"
    assert account_alerts[0]["distinct_source_ips"] == 5


def test_account_episodes_are_separate():
    alerts = rule_alerts(
        detect_suspicious_activity(
            make_frame([0, 10, 20, 30, 40, 3600, 3610, 3620, 3630, 3640]),
            5,
            2,
        ),
        RULE_ACCOUNT_FAILURES,
    )
    assert len(alerts) == 2


def test_spray_rule():
    alerts = detect_suspicious_activity(
        make_frame(
            [0, 10, 20],
            users=["alice", "bob", "carol"],
        ),
        5,
        2,
        3,
        5,
    )
    spray = rule_alerts(alerts, RULE_ACCOUNT_SPRAY)
    assert len(spray) == 1
    assert spray[0]["alert_type"] == ALERT_ACCOUNT_SPRAY
    assert spray[0]["distinct_accounts"] == 3
    assert spray[0]["peak_distinct_accounts"] == 3
    assert spray[0]["event_count"] == 3


def test_spray_below_distinct_threshold():
    alerts = detect_suspicious_activity(
        make_frame([0, 10, 20, 30], users=["alice", "alice", "bob", "bob"]),
        5,
        2,
        3,
        5,
    )
    assert not rule_alerts(alerts, RULE_ACCOUNT_SPRAY)


def test_spray_repeated_username_does_not_inflate_distinct_count():
    alerts = detect_suspicious_activity(
        make_frame(
            [0, 10, 20, 30, 40],
            users=["alice", "alice", "bob", "carol", "dave"],
        ),
        10,
        2,
        3,
        5,
    )
    spray = rule_alerts(alerts, RULE_ACCOUNT_SPRAY)
    assert len(spray) == 1
    assert spray[0]["distinct_accounts"] == 4


def test_spray_outside_window_no_alert():
    alerts = detect_suspicious_activity(
        make_frame([0, 400, 800], users=["alice", "bob", "carol"]),
        10,
        2,
        3,
        5,
    )
    assert not rule_alerts(alerts, RULE_ACCOUNT_SPRAY)


def test_spray_two_episodes_are_reported():
    alerts = detect_suspicious_activity(
        make_frame(
            [0, 10, 20, 3600, 3610, 3620],
            users=["alice", "bob", "carol", "dave", "erin", "frank"],
        ),
        10,
        2,
        3,
        5,
    )
    spray = rule_alerts(alerts, RULE_ACCOUNT_SPRAY)
    assert len(spray) == 2
    assert spray[0]["start_time"] == "2026-10-24T10:00:00+00:00"
    assert spray[1]["start_time"] == "2026-10-24T11:00:00+00:00"


def test_severity_escalates_at_twice_threshold():
    medium = rule_alerts(
        detect_suspicious_activity(make_frame([0, 10, 20, 30, 40]), 5, 2),
        RULE_IP_FAILURES,
    )[0]
    high = rule_alerts(
        detect_suspicious_activity(
            make_frame(list(range(0, 100, 10))), 5, 2
        ),
        RULE_IP_FAILURES,
    )[0]
    assert medium["severity"] == "Medium"
    assert high["severity"] == "High"


def test_spray_severity_escalates_at_twice_threshold():
    medium = rule_alerts(
        detect_suspicious_activity(
            make_frame([0, 10, 20], users=["alice", "bob", "carol"]),
            10,
            2,
            3,
            5,
        ),
        RULE_ACCOUNT_SPRAY,
    )[0]
    high = rule_alerts(
        detect_suspicious_activity(
            make_frame(
                [0, 10, 20, 30, 40, 50],
                users=["alice", "bob", "carol", "dave", "erin", "frank"],
            ),
            10,
            2,
            3,
            5,
        ),
        RULE_ACCOUNT_SPRAY,
    )[0]
    assert medium["severity"] == "Medium"
    assert high["severity"] == "High"


def test_overlapping_rules_are_both_preserved():
    alerts = detect_suspicious_activity(make_frame([0, 10, 20, 30, 40]), 5, 2)
    assert len(rule_alerts(alerts, RULE_IP_FAILURES)) == 1
    assert len(rule_alerts(alerts, RULE_ACCOUNT_FAILURES)) == 1


def test_duplicate_timestamps_form_one_episode():
    alerts = rule_alerts(
        detect_suspicious_activity(make_frame([0, 0, 0, 0, 0]), 5, 2),
        RULE_IP_FAILURES,
    )
    assert len(alerts) == 1
    assert alerts[0]["event_count"] == 5


def test_successes_are_ignored():
    alerts = detect_suspicious_activity(
        make_frame([0, 10, 20], statuses=["SUCCESS"] * 3),
        5,
        2,
    )
    assert alerts == []


def test_empty_frame_returns_no_alerts():
    frame = make_frame([])
    assert detect_suspicious_activity(frame) == []


def test_naive_timestamps_are_supported():
    alerts = detect_suspicious_activity(
        make_frame([0, 10, 20, 30, 40], tz=False),
        5,
        2,
    )
    assert len(rule_alerts(alerts, RULE_IP_FAILURES)) == 1
    assert alerts[0]["start_time"].endswith("+00:00")
    assert str(alerts[0]["evidence"][0]["timestamp"].tz) == "UTC"


def test_non_utc_aware_timestamps_are_normalised_in_alerts_and_evidence():
    frame = make_frame([0, 10, 20, 30, 40])
    frame["timestamp"] = frame["timestamp"].dt.tz_convert("Europe/Berlin")
    alerts = detect_suspicious_activity(frame, 5, 2)
    assert alerts[0]["start_time"].endswith("+00:00")
    assert str(alerts[0]["evidence"][0]["timestamp"].tz) == "UTC"
    assert alerts[0]["start_time"] == "2026-10-24T10:00:00+00:00"


def test_source_row_is_optional():
    alerts = detect_suspicious_activity(
        make_frame([0, 10, 20, 30, 40], source_rows=False),
        5,
        2,
    )
    ip_alert = rule_alerts(alerts, RULE_IP_FAILURES)[0]
    assert "source_row" not in ip_alert["evidence"][0]


def test_alert_schema_and_evidence_consistency():
    alerts = detect_suspicious_activity(
        make_frame([0, 10, 20, 30, 40], users=["alice"] * 5),
        5,
        2,
    )
    assert alerts
    expected_keys = {
        "alert_id",
        "rule_id",
        "alert_type",
        "entity_type",
        "entity_value",
        "severity",
        "start_time",
        "end_time",
        "event_count",
        "peak_window_start",
        "peak_window_end",
        "threshold",
        "window_minutes",
        "description",
        "evidence",
    }
    for alert in alerts:
        assert expected_keys.issubset(alert)
        assert alert["event_count"] == len(alert["evidence"])
        assert alert["start_time"] == alert["evidence"][0]["timestamp"].isoformat()
        assert alert["end_time"] == alert["evidence"][-1]["timestamp"].isoformat()
        assert all(event["status"] == "FAILED" for event in alert["evidence"])
        assert all("source_row" in event for event in alert["evidence"])
        assert "_sort_start" not in alert
        if "peak_window_count" in alert:
            assert alert["peak_window_count"] <= alert["event_count"]
        if "peak_distinct_accounts" in alert:
            assert alert["peak_distinct_accounts"] <= alert["distinct_accounts"]


def test_alert_ids_are_sequential_and_high_severity_first():
    offsets = list(range(0, 100, 10)) + list(range(3600, 3650, 10))
    ips = ["192.0.2.1"] * 10 + ["192.0.2.2"] * 5
    users = [f"u{i}" for i in range(15)]
    alerts = detect_suspicious_activity(
        make_frame(offsets, users=users, ips=ips),
        5,
        2,
        99,
        5,
    )
    ip_alerts = rule_alerts(alerts, RULE_IP_FAILURES)
    assert [alert["severity"] for alert in ip_alerts] == ["High", "Medium"]
    assert [alert["alert_id"] for alert in alerts] == [
        f"ST-{index:04d}" for index in range(1, len(alerts) + 1)
    ]


def test_custom_thresholds_are_configurable():
    alerts = detect_suspicious_activity(make_frame([0, 30]), 2, 1)
    assert len(rule_alerts(alerts, RULE_IP_FAILURES)) == 1


@pytest.mark.parametrize(
    "threshold,window,spray_users,spray_window",
    [
        (1, 2, 3, 5),
        (0, 2, 3, 5),
        (True, 2, 3, 5),
        (2.5, 2, 3, 5),
        (5, 0, 3, 5),
        (5, -1, 3, 5),
        (5, float("nan"), 3, 5),
        (5, float("inf"), 3, 5),
        (5, 2, 1, 5),
        (5, 2, 3, 0),
    ],
)
def test_invalid_parameters_raise(threshold, window, spray_users, spray_window):
    with pytest.raises(ValueError):
        detect_suspicious_activity(
            make_frame([0, 10]),
            threshold,
            window,
            spray_users,
            spray_window,
        )


def test_missing_columns_raise():
    with pytest.raises(ValueError, match="Missing columns"):
        detect_suspicious_activity(pd.DataFrame({"timestamp": []}))


def test_non_datetime_timestamp_raises():
    frame = make_frame([0, 10, 20, 30, 40])
    frame["timestamp"] = frame["timestamp"].astype(str)
    with pytest.raises(ValueError, match="datetime64"):
        detect_suspicious_activity(frame)


def test_null_values_raise():
    frame = make_frame([0, 10, 20, 30, 40])
    frame.loc[0, "username"] = None
    with pytest.raises(ValueError, match="null"):
        detect_suspicious_activity(frame)


def test_invalid_status_raises():
    frame = make_frame([0, 10, 20, 30, 40], statuses=["OK"] * 5)
    with pytest.raises(ValueError, match="SUCCESS or FAILED"):
        detect_suspicious_activity(frame)


def test_non_dataframe_raises():
    with pytest.raises(ValueError, match="DataFrame"):
        detect_suspicious_activity([1, 2, 3])  # type: ignore[arg-type]


def test_detection_performance_guard():
    count = 5_000
    offsets = [index % 100 for index in range(count)]
    frame = make_frame(offsets)

    start = time.perf_counter()
    alerts = detect_suspicious_activity(frame, 5, 2)
    elapsed = time.perf_counter() - start

    assert len(rule_alerts(alerts, RULE_IP_FAILURES)) == 1
    assert len(rule_alerts(alerts, RULE_ACCOUNT_FAILURES)) == 1
    assert elapsed < 5.0
