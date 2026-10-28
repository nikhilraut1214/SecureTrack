"""Pure filtering and presentation helpers for the SecureTrack UI.

Keeping these functions independent of Streamlit makes the exploration rules
testable without a browser session. Detection is intentionally not performed
here: filters only change what is displayed, never which rules run.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from typing import Any, Iterable

import pandas as pd

DEFAULT_STATUSES = ("SUCCESS", "FAILED")


@dataclass(frozen=True)
class ExplorationFilters:
    """User-selected exploration filters."""

    statuses: tuple[str, ...] = DEFAULT_STATUSES
    username_query: str = ""
    ip_query: str = ""
    start_date: date | None = None
    end_date: date | None = None


@dataclass(frozen=True)
class TimelineBucket:
    """A Plotly/pandas floor frequency and its human-readable label."""

    frequency: str
    label: str


def build_filtered_dataframe(
    frame: pd.DataFrame,
    filters: ExplorationFilters,
) -> pd.DataFrame:
    """Return the rows that satisfy every active exploration filter.

    The returned frame keeps the original columns, including ``source_row``.
    An empty status selection intentionally produces no rows rather than
    silently treating "nothing selected" as "everything selected".
    """
    if frame.empty:
        return frame.copy()

    if not filters.statuses:
        return frame.iloc[0:0].copy()

    mask = frame["status"].isin(filters.statuses)

    username_query = filters.username_query.strip()
    if username_query:
        mask &= frame["username"].astype(str).str.contains(
            username_query, case=False, regex=False, na=False
        )

    ip_query = filters.ip_query.strip()
    if ip_query:
        mask &= frame["ip_address"].astype(str).str.contains(
            ip_query, case=False, regex=False, na=False
        )

    if filters.start_date is not None or filters.end_date is not None:
        if (
            filters.start_date is not None
            and filters.end_date is not None
            and filters.start_date > filters.end_date
        ):
            return frame.iloc[0:0].copy()

        event_dates = frame["timestamp"].dt.date
        if filters.start_date is not None:
            mask &= event_dates >= filters.start_date
        if filters.end_date is not None:
            mask &= event_dates <= filters.end_date

    return frame.loc[mask].copy()


def _matches(value: Any, query: str) -> bool:
    return query.casefold() in str(value).casefold()


def _alert_matches_text(alert: dict[str, Any], query: str, field: str) -> bool:
    entity_type = "username" if field == "username" else "ip"
    if alert.get("entity_type") == entity_type and _matches(
        alert.get("entity_value", ""), query
    ):
        return True

    event_field = "username" if field == "username" else "ip_address"
    return any(
        _matches(event.get(event_field, ""), query)
        for event in alert.get("evidence", [])
    )


def filter_alerts_for_display(
    alerts: Iterable[dict[str, Any]],
    filters: ExplorationFilters,
) -> list[dict[str, Any]]:
    """Select alerts whose entity, evidence, or episode matches the filters.

    Detection always runs on the full active dataset. These filters only choose
    which of the already-detected alerts are shown. Every alert's evidence stays
    complete so its event count and threshold remain auditable.
    """
    if "FAILED" not in filters.statuses:
        return []

    selected: list[dict[str, Any]] = []
    username_query = filters.username_query.strip()
    ip_query = filters.ip_query.strip()

    for alert in alerts:
        if username_query and not _alert_matches_text(
            alert, username_query, "username"
        ):
            continue
        if ip_query and not _alert_matches_text(alert, ip_query, "ip"):
            continue

        if filters.start_date is not None or filters.end_date is not None:
            alert_start = pd.Timestamp(alert["start_time"]).date()
            alert_end = pd.Timestamp(alert["end_time"]).date()
            if filters.end_date is not None and alert_start > filters.end_date:
                continue
            if filters.start_date is not None and alert_end < filters.start_date:
                continue

        selected.append(alert)

    return selected


def choose_timeline_bucket(frame: pd.DataFrame) -> TimelineBucket:
    """Choose a readable time bucket for the active dataset's time span."""
    if frame.empty:
        return TimelineBucket("1min", "1-minute")

    span_seconds = (
        frame["timestamp"].max() - frame["timestamp"].min()
    ).total_seconds()
    if span_seconds <= 15 * 60:
        return TimelineBucket("1min", "1-minute")
    if span_seconds <= 2 * 60 * 60:
        return TimelineBucket("5min", "5-minute")
    if span_seconds <= 12 * 60 * 60:
        return TimelineBucket("15min", "15-minute")
    if span_seconds <= 2 * 24 * 60 * 60:
        return TimelineBucket("1h", "hourly")
    if span_seconds <= 14 * 24 * 60 * 60:
        return TimelineBucket("6h", "6-hour")
    return TimelineBucket("1D", "daily")


def _display_utc(value: Any) -> str:
    if value is None:
        return "n/a"
    try:
        if bool(pd.isna(value)):
            return "n/a"
    except (TypeError, ValueError):
        pass
    timestamp = pd.Timestamp(value)
    if timestamp.tzinfo is not None:
        timestamp = timestamp.tz_convert("UTC")
    return timestamp.strftime("%Y-%m-%d %H:%M:%S")


def alert_display_frame(alerts: Iterable[dict[str, Any]]) -> pd.DataFrame:
    """Build a compact, human-readable alert summary for the UI.

    The full, stable summary is still produced by ``core.export`` for CSV
    downloads. This frame keeps ``alert_id`` so table checks and visual
    inspection can link every row to its evidence.
    """
    rows: list[dict[str, Any]] = []
    for alert in alerts:
        if "peak_window_count" in alert:
            peak = f"{alert['peak_window_count']} events"
            threshold = f"{alert['threshold']} events"
        else:
            peak = f"{alert.get('peak_distinct_accounts', 0)} accounts"
            threshold = f"{alert['threshold']} accounts"

        rows.append(
            {
                "alert_id": alert.get("alert_id"),
                "severity": alert.get("severity"),
                "rule_id": alert.get("rule_id"),
                "entity": (
                    f"{alert.get('entity_type', 'entity')}: "
                    f"{alert.get('entity_value', '')}"
                ),
                "start_time": _display_utc(alert.get("start_time")),
                "end_time": _display_utc(alert.get("end_time")),
                "event_count": alert.get("event_count"),
                "peak": peak,
                "threshold": threshold,
                "window": f"{alert.get('window_minutes', 0):g} min",
            }
        )

    return pd.DataFrame(
        rows,
        columns=[
            "alert_id",
            "severity",
            "rule_id",
            "entity",
            "start_time",
            "end_time",
            "event_count",
            "peak",
            "threshold",
            "window",
        ],
    )
