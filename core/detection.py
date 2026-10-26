"""Rule-based suspicious-login detection.

The detector is deliberately transparent. It reports episodes of failed
authentication activity that satisfy configurable thresholds; it does not score
risk, predict attacks, or trigger automatic responses.

Detection is linear in the number of failed events per entity: a two-pointer
window records the strongest qualifying window in each episode, and evidence is
materialised once when the episode closes.
"""

from __future__ import annotations

import math
from collections import Counter
from dataclasses import dataclass
from numbers import Integral, Real
from typing import Any

import pandas as pd

REQUIRED_COLUMNS = ("timestamp", "username", "ip_address", "status")
ALLOWED_STATUSES = {"SUCCESS", "FAILED"}

RULE_IP_FAILURES = "R1_IP_FAILURES"
RULE_ACCOUNT_FAILURES = "R2_ACCOUNT_FAILURES"
RULE_ACCOUNT_SPRAY = "R3_ACCOUNT_SPRAY"

ALERT_IP_FAILURES = "Repeated failed logins from one IP"
ALERT_ACCOUNT_FAILURES = "Repeated failed logins against one account"
ALERT_ACCOUNT_SPRAY = "Multiple accounts targeted by one IP"


@dataclass(frozen=True)
class _Episode:
    """Indexes and peak information for one qualifying episode."""

    start: int
    end: int
    peak: int
    peak_start: int
    peak_end: int


def _validate_positive_int(value: Any, name: str, minimum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, Integral):
        raise ValueError(f"{name} must be an integer >= {minimum}.")
    if int(value) < minimum:
        raise ValueError(f"{name} must be an integer >= {minimum}.")
    return int(value)


def _validate_positive_number(value: Any, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, Real):
        raise ValueError(f"{name} must be a positive number.")
    number = float(value)
    if not math.isfinite(number) or number <= 0:
        raise ValueError(f"{name} must be a positive number.")
    return number


def _validate_frame(frame: pd.DataFrame) -> None:
    if not isinstance(frame, pd.DataFrame):
        raise ValueError("Input must be a pandas DataFrame.")

    missing = [column for column in REQUIRED_COLUMNS if column not in frame.columns]
    if missing:
        raise ValueError("Missing columns: " + ", ".join(missing))

    if frame.empty:
        return

    if not pd.api.types.is_datetime64_any_dtype(frame["timestamp"]):
        raise ValueError(
            "The timestamp column must be datetime64; parse the CSV with "
            "parse_login_csv first."
        )

    if frame[list(REQUIRED_COLUMNS)].isna().any().any():
        raise ValueError("Required columns must not contain null values.")

    statuses = {str(value) for value in frame["status"].unique()}
    if not statuses.issubset(ALLOWED_STATUSES):
        raise ValueError(
            "The status column must contain only SUCCESS or FAILED."
        )


def _normalise_timestamps(frame: pd.DataFrame) -> pd.DataFrame:
    """Return a copy with every timestamp expressed in UTC."""
    timestamps = frame["timestamp"]
    if timestamps.dt.tz is None:
        return frame.assign(timestamp=timestamps.dt.tz_localize("UTC"))
    return frame.assign(timestamp=timestamps.dt.tz_convert("UTC"))


def _sorted_events(frame: pd.DataFrame) -> pd.DataFrame:
    sort_columns = ["timestamp"]
    if "source_row" in frame.columns:
        sort_columns.append("source_row")
    return frame.sort_values(sort_columns, kind="mergesort").reset_index(drop=True)


def _iso(value: Any) -> str:
    timestamp = pd.Timestamp(value)
    if timestamp.tzinfo is not None:
        timestamp = timestamp.tz_convert("UTC")
    return timestamp.isoformat()


def _scan_threshold_episodes(
    times: list[pd.Timestamp],
    threshold: int,
    window_seconds: float,
) -> list[_Episode]:
    """Find maximal runs of qualifying count-based windows."""
    episodes: list[_Episode] = []
    left = 0
    current: dict[str, int] | None = None

    for right, current_time in enumerate(times):
        while (
            left <= right
            and (current_time - times[left]).total_seconds() > window_seconds
        ):
            left += 1

        count = right - left + 1
        if count >= threshold:
            if current is None:
                current = {
                    "start": left,
                    "end": right,
                    "peak": count,
                    "peak_start": left,
                    "peak_end": right,
                }
            else:
                current["end"] = right
                if count > current["peak"]:
                    current["peak"] = count
                    current["peak_start"] = left
                    current["peak_end"] = right
        elif current is not None:
            episodes.append(_Episode(**current))
            current = None

    if current is not None:
        episodes.append(_Episode(**current))

    return episodes


def _scan_spray_episodes(
    times: list[pd.Timestamp],
    usernames: list[str],
    threshold: int,
    window_seconds: float,
) -> list[_Episode]:
    """Find maximal runs of windows containing enough distinct accounts."""
    episodes: list[_Episode] = []
    counts: Counter[str] = Counter()
    distinct = 0
    left = 0
    current: dict[str, int] | None = None

    for right, current_time in enumerate(times):
        username = usernames[right]
        if counts[username] == 0:
            distinct += 1
        counts[username] += 1

        while (
            left <= right
            and (current_time - times[left]).total_seconds() > window_seconds
        ):
            expired = usernames[left]
            counts[expired] -= 1
            if counts[expired] == 0:
                del counts[expired]
                distinct -= 1
            left += 1

        if distinct >= threshold:
            if current is None:
                current = {
                    "start": left,
                    "end": right,
                    "peak": distinct,
                    "peak_start": left,
                    "peak_end": right,
                }
            else:
                current["end"] = right
                if distinct > current["peak"]:
                    current["peak"] = distinct
                    current["peak_start"] = left
                    current["peak_end"] = right
        elif current is not None:
            episodes.append(_Episode(**current))
            current = None

    if current is not None:
        episodes.append(_Episode(**current))

    return episodes


def _evidence(group: pd.DataFrame, episode: _Episode) -> list[dict[str, Any]]:
    return group.iloc[episode.start : episode.end + 1].to_dict("records")


def _base_alert(
    *,
    rule_id: str,
    alert_type: str,
    entity_type: str,
    entity_value: str,
    severity: str,
    times: list[pd.Timestamp],
    episode: _Episode,
    evidence: list[dict[str, Any]],
    threshold: int,
    window_minutes: float,
    description: str,
) -> dict[str, Any]:
    alert: dict[str, Any] = {
        "alert_id": None,
        "rule_id": rule_id,
        "alert_type": alert_type,
        "entity_type": entity_type,
        "entity_value": entity_value,
        "severity": severity,
        "start_time": _iso(times[episode.start]),
        "end_time": _iso(times[episode.end]),
        "event_count": len(evidence),
        "peak_window_start": _iso(times[episode.peak_start]),
        "peak_window_end": _iso(times[episode.peak_end]),
        "threshold": int(threshold),
        "window_minutes": window_minutes,
        "description": description,
        "evidence": evidence,
    }
    return alert


def _build_ip_alert(
    ip_address: str,
    group: pd.DataFrame,
    times: list[pd.Timestamp],
    episode: _Episode,
    threshold: int,
    window_minutes: float,
) -> dict[str, Any]:
    evidence = _evidence(group, episode)
    severity = "High" if episode.peak >= threshold * 2 else "Medium"
    alert = _base_alert(
        rule_id=RULE_IP_FAILURES,
        alert_type=ALERT_IP_FAILURES,
        entity_type="ip",
        entity_value=ip_address,
        severity=severity,
        times=times,
        episode=episode,
        evidence=evidence,
        threshold=threshold,
        window_minutes=window_minutes,
        description=(
            f"{len(evidence)} failed login events from {ip_address}; peak "
            f"{episode.peak} events within a {window_minutes:g}-minute window "
            f"(threshold {threshold})."
        ),
    )
    alert["ip_address"] = ip_address
    alert["peak_window_count"] = episode.peak
    return alert


def _build_account_alert(
    username: str,
    group: pd.DataFrame,
    times: list[pd.Timestamp],
    episode: _Episode,
    threshold: int,
    window_minutes: float,
) -> dict[str, Any]:
    evidence = _evidence(group, episode)
    distinct_source_ips = len({str(record["ip_address"]) for record in evidence})
    severity = "High" if episode.peak >= threshold * 2 else "Medium"
    alert = _base_alert(
        rule_id=RULE_ACCOUNT_FAILURES,
        alert_type=ALERT_ACCOUNT_FAILURES,
        entity_type="username",
        entity_value=username,
        severity=severity,
        times=times,
        episode=episode,
        evidence=evidence,
        threshold=threshold,
        window_minutes=window_minutes,
        description=(
            f"{len(evidence)} failed login events against {username}; "
            f"{distinct_source_ips} distinct source IP(s); peak {episode.peak} "
            f"events within a {window_minutes:g}-minute window "
            f"(threshold {threshold})."
        ),
    )
    alert["username"] = username
    alert["peak_window_count"] = episode.peak
    alert["distinct_source_ips"] = distinct_source_ips
    return alert


def _build_spray_alert(
    ip_address: str,
    group: pd.DataFrame,
    times: list[pd.Timestamp],
    episode: _Episode,
    threshold: int,
    window_minutes: float,
) -> dict[str, Any]:
    evidence = _evidence(group, episode)
    distinct_accounts = len({str(record["username"]) for record in evidence})
    severity = "High" if episode.peak >= threshold * 2 else "Medium"
    alert = _base_alert(
        rule_id=RULE_ACCOUNT_SPRAY,
        alert_type=ALERT_ACCOUNT_SPRAY,
        entity_type="ip",
        entity_value=ip_address,
        severity=severity,
        times=times,
        episode=episode,
        evidence=evidence,
        threshold=threshold,
        window_minutes=window_minutes,
        description=(
            f"{len(evidence)} failed login events from {ip_address} targeting "
            f"{distinct_accounts} distinct account(s); peak {episode.peak} "
            f"distinct accounts within a {window_minutes:g}-minute window "
            f"(threshold {threshold})."
        ),
    )
    alert["ip_address"] = ip_address
    alert["distinct_accounts"] = distinct_accounts
    alert["peak_distinct_accounts"] = episode.peak
    return alert


def detect_suspicious_activity(
    frame: pd.DataFrame,
    threshold: int = 5,
    window_minutes: float = 2,
    spray_users: int = 3,
    spray_window_minutes: float = 5,
) -> list[dict[str, Any]]:
    """Detect suspicious failed-login episodes.

    Args:
        frame: Validated events with timestamp, username, ip_address, status.
        threshold: Failed events required for IP/account rules (>= 2).
        window_minutes: Time window for IP/account rules (> 0).
        spray_users: Distinct accounts required for the spray rule (>= 2).
        spray_window_minutes: Time window for the spray rule (> 0).

    Returns:
        A list of alert dictionaries, one per qualifying episode, sorted by
        severity and then episode start. Each alert contains its evidence.
    """
    threshold = _validate_positive_int(threshold, "threshold", 2)
    spray_users = _validate_positive_int(spray_users, "spray_users", 2)
    window_minutes_validated = _validate_positive_number(
        window_minutes, "window_minutes"
    )
    spray_window_validated = _validate_positive_number(
        spray_window_minutes, "spray_window_minutes"
    )

    _validate_frame(frame)
    if frame.empty:
        return []
    frame = _normalise_timestamps(frame)

    failed = frame[frame["status"] == "FAILED"].copy()
    if failed.empty:
        return []

    window_seconds = window_minutes_validated * 60
    spray_window_seconds = spray_window_validated * 60
    alerts: list[dict[str, Any]] = []

    for ip_address, group in failed.groupby("ip_address", sort=True):
        ordered = _sorted_events(group)
        times = ordered["timestamp"].tolist()
        for episode in _scan_threshold_episodes(
            times, threshold, window_seconds
        ):
            alerts.append(
                _build_ip_alert(
                    str(ip_address),
                    ordered,
                    times,
                    episode,
                    threshold,
                    window_minutes_validated,
                )
            )

    for username, group in failed.groupby("username", sort=True):
        ordered = _sorted_events(group)
        times = ordered["timestamp"].tolist()
        for episode in _scan_threshold_episodes(
            times, threshold, window_seconds
        ):
            alerts.append(
                _build_account_alert(
                    str(username),
                    ordered,
                    times,
                    episode,
                    threshold,
                    window_minutes_validated,
                )
            )

    for ip_address, group in failed.groupby("ip_address", sort=True):
        ordered = _sorted_events(group)
        times = ordered["timestamp"].tolist()
        usernames = ordered["username"].astype(str).tolist()
        for episode in _scan_spray_episodes(
            times, usernames, spray_users, spray_window_seconds
        ):
            alerts.append(
                _build_spray_alert(
                    str(ip_address),
                    ordered,
                    times,
                    episode,
                    spray_users,
                    spray_window_validated,
                )
            )

    for alert in alerts:
        alert["_sort_start"] = pd.Timestamp(alert["start_time"])

    alerts.sort(
        key=lambda alert: (
            0 if alert["severity"] == "High" else 1,
            alert["_sort_start"],
            alert["rule_id"],
            alert["entity_value"],
        )
    )

    for index, alert in enumerate(alerts, start=1):
        alert["alert_id"] = f"ST-{index:04d}"
        del alert["_sort_start"]

    return alerts
