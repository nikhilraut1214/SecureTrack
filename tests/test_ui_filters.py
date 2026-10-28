from dataclasses import replace
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

import pandas as pd

from core.detection import (
    RULE_ACCOUNT_FAILURES,
    RULE_ACCOUNT_SPRAY,
    RULE_IP_FAILURES,
    detect_suspicious_activity,
)
from core.parser import parse_login_csv
from ui.filters import (
    ExplorationFilters,
    alert_display_frame,
    build_filtered_dataframe,
    choose_timeline_bucket,
    filter_alerts_for_display,
)

SAMPLE_PATH = Path(__file__).resolve().parents[1] / "data" / "sample_login_logs.csv"


def _sample_data():
    result = parse_login_csv(SAMPLE_PATH)
    assert not result["errors"]
    return result["data"]


def _sample_alerts():
    return detect_suspicious_activity(_sample_data(), 5, 2, 3, 5)


def test_status_and_username_filters_keep_source_rows():
    data = _sample_data()
    filters = ExplorationFilters(
        statuses=("FAILED",),
        username_query="ALEX",
        ip_query="",
        start_date=date(2026, 10, 24),
        end_date=date(2026, 10, 24),
    )

    filtered = build_filtered_dataframe(data, filters)

    assert len(filtered) == 5
    assert list(filtered["username"].unique()) == ["alex"]
    assert list(filtered["source_row"]) == [4, 5, 6, 7, 8]


def test_ip_filter_is_case_insensitive_substring_search():
    data = _sample_data()
    filters = ExplorationFilters(
        statuses=("SUCCESS", "FAILED"),
        username_query="",
        ip_query="192.0.2.30",
        start_date=date(2026, 10, 24),
        end_date=date(2026, 10, 24),
    )

    filtered = build_filtered_dataframe(data, filters)

    assert len(filtered) == 4
    assert list(filtered["source_row"]) == [10, 11, 12, 13]


def test_empty_status_and_reversed_dates_show_no_rows():
    data = _sample_data()

    no_status = build_filtered_dataframe(
        data,
        ExplorationFilters(statuses=(), start_date=date(2026, 10, 24), end_date=date(2026, 10, 24)),
    )
    reversed_dates = build_filtered_dataframe(
        data,
        ExplorationFilters(
            statuses=("SUCCESS", "FAILED"),
            start_date=date(2026, 10, 25),
            end_date=date(2026, 10, 24),
        ),
    )

    assert no_status.empty
    assert reversed_dates.empty


def test_date_filter_uses_full_utc_days():
    data = _sample_data()
    same_day = build_filtered_dataframe(
        data,
        ExplorationFilters(
            statuses=("SUCCESS", "FAILED"),
            start_date=date(2026, 10, 24),
            end_date=date(2026, 10, 24),
        ),
    )
    next_day = build_filtered_dataframe(
        data,
        ExplorationFilters(
            statuses=("SUCCESS", "FAILED"),
            start_date=date(2026, 10, 25),
            end_date=date(2026, 10, 25),
        ),
    )

    assert len(same_day) == 12
    assert next_day.empty


def test_alert_filters_match_entity_or_evidence_text():
    alerts = _sample_alerts()
    base = ExplorationFilters(
        statuses=("SUCCESS", "FAILED"),
        start_date=date(2026, 10, 24),
        end_date=date(2026, 10, 24),
    )

    all_alerts = filter_alerts_for_display(alerts, base)
    alex_alerts = filter_alerts_for_display(
        alerts, replace(base, username_query="alex")
    )
    spray_ip_alerts = filter_alerts_for_display(
        alerts, replace(base, ip_query="192.0.2.30")
    )

    assert len(all_alerts) == 3
    assert {alert["rule_id"] for alert in alex_alerts} == {
        RULE_IP_FAILURES,
        RULE_ACCOUNT_FAILURES,
    }
    assert [alert["rule_id"] for alert in spray_ip_alerts] == [RULE_ACCOUNT_SPRAY]


def test_alert_filters_respect_status_and_date_range():
    alerts = _sample_alerts()

    success_only = filter_alerts_for_display(
        alerts,
        ExplorationFilters(
            statuses=("SUCCESS",),
            start_date=date(2026, 10, 24),
            end_date=date(2026, 10, 24),
        ),
    )
    next_day = filter_alerts_for_display(
        alerts,
        ExplorationFilters(
            statuses=("SUCCESS", "FAILED"),
            start_date=date(2026, 10, 25),
            end_date=date(2026, 10, 25),
        ),
    )

    assert success_only == []
    assert next_day == []


def test_alert_display_frame_keeps_traceable_id_and_peak_units():
    frame = alert_display_frame(_sample_alerts())

    assert "alert_id" in frame.columns
    assert list(frame["alert_id"]) == ["ST-0001", "ST-0002", "ST-0003"]
    assert "5 events" in set(frame["peak"])
    assert "3 accounts" in set(frame["peak"])
    assert "2 min" in set(frame["window"])
    assert "5 min" in set(frame["window"])


def test_timeline_bucket_scales_with_span():
    def frame_with_span(minutes: int) -> pd.DataFrame:
        start = datetime(2026, 1, 1, tzinfo=timezone.utc)
        end = start + timedelta(minutes=minutes)
        return pd.DataFrame({"timestamp": pd.to_datetime([start, end], utc=True)})

    assert choose_timeline_bucket(pd.DataFrame()).frequency == "1min"
    assert choose_timeline_bucket(frame_with_span(7)).frequency == "1min"
    assert choose_timeline_bucket(frame_with_span(300)).frequency == "15min"
    assert choose_timeline_bucket(frame_with_span(24 * 60)).frequency == "1h"
    assert choose_timeline_bucket(frame_with_span(10 * 24 * 60)).frequency == "6h"
    assert choose_timeline_bucket(frame_with_span(30 * 24 * 60)).frequency == "1D"
