"""Safe CSV report builders.

Spreadsheet applications can interpret cells beginning with formula
characters even when the file is nominally plain CSV. Exports therefore
neutralise formula-like text in a copy of the data; the in-memory analysis
data is never mutated.
"""

from __future__ import annotations

from typing import Any, Iterable

import pandas as pd

DANGEROUS_PREFIXES = ("=", "+", "-", "@", "\t", "\r")

ALERT_SUMMARY_COLUMNS = [
    "alert_id",
    "rule_id",
    "alert_type",
    "entity_type",
    "entity_value",
    "severity",
    "start_time",
    "end_time",
    "event_count",
    "peak_window_count",
    "peak_distinct_accounts",
    "distinct_source_ips",
    "distinct_accounts",
    "peak_window_start",
    "peak_window_end",
    "threshold",
    "window_minutes",
]

EVIDENCE_COLUMNS = [
    "alert_id",
    "rule_id",
    "alert_type",
    "severity",
    "entity_type",
    "entity_value",
    "alert_start",
    "alert_end",
    "source_row",
    "timestamp",
    "username",
    "ip_address",
    "status",
]


def sanitize_spreadsheet_cell(value: Any) -> Any:
    """Prefix formula-triggering text with an apostrophe.

    The check uses the first non-whitespace character so a leading space does
    not provide a trivial bypass. Non-string values are returned unchanged.
    """
    if not isinstance(value, str):
        return value

    stripped = value.lstrip("\ufeff\u200b").lstrip()
    if stripped.startswith(DANGEROUS_PREFIXES):
        return "'" + value
    return value


def _sanitize_frame(frame: pd.DataFrame) -> pd.DataFrame:
    safe = frame.copy()
    for column in safe.columns:
        series = safe[column]
        if pd.api.types.is_object_dtype(series) or pd.api.types.is_string_dtype(
            series
        ):
            safe[column] = series.map(sanitize_spreadsheet_cell)
    return safe


def dataframe_to_safe_csv(frame: pd.DataFrame) -> bytes:
    """Return UTF-8-with-BOM CSV bytes after spreadsheet sanitisation."""
    safe = _sanitize_frame(frame)
    return safe.to_csv(index=False).encode("utf-8-sig")


def alert_summary_frame(alerts: Iterable[dict[str, Any]]) -> pd.DataFrame:
    """Build a stable, evidence-free alert summary table."""
    rows = [
        {column: alert.get(column) for column in ALERT_SUMMARY_COLUMNS}
        for alert in alerts
    ]
    return pd.DataFrame(rows, columns=ALERT_SUMMARY_COLUMNS)


def evidence_frame(alerts: Iterable[dict[str, Any]]) -> pd.DataFrame:
    """Flatten alert evidence into a long-form, traceable report."""
    rows: list[dict[str, Any]] = []
    for alert in alerts:
        for event in alert.get("evidence", []):
            rows.append(
                {
                    "alert_id": alert.get("alert_id"),
                    "rule_id": alert.get("rule_id"),
                    "alert_type": alert.get("alert_type"),
                    "severity": alert.get("severity"),
                    "entity_type": alert.get("entity_type"),
                    "entity_value": alert.get("entity_value"),
                    "alert_start": alert.get("start_time"),
                    "alert_end": alert.get("end_time"),
                    "source_row": event.get("source_row"),
                    "timestamp": event.get("timestamp"),
                    "username": event.get("username"),
                    "ip_address": event.get("ip_address"),
                    "status": event.get("status"),
                }
            )
    return pd.DataFrame(rows, columns=EVIDENCE_COLUMNS)
