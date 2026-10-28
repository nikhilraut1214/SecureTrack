"""SecureTrack Streamlit application.

The parser, detection engine, and export builders are deliberately kept in
``core``. This module owns only the interactive presentation layer: dataset
selection, exploration filters, chart rendering, alert review, and downloads.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

import pandas as pd
import plotly.express as px
import streamlit as st

from core.detection import detect_suspicious_activity
from core.export import (
    alert_summary_frame,
    dataframe_to_safe_csv,
    evidence_frame,
)
from core.parser import MAX_UPLOAD_BYTES, parse_login_csv
from ui.filters import (
    DEFAULT_STATUSES,
    ExplorationFilters,
    alert_display_frame,
    build_filtered_dataframe,
    choose_timeline_bucket,
    filter_alerts_for_display,
)
from ui.theme import apply_theme, escape_markdown, style_figure

SAMPLE_PATH = Path(__file__).resolve().parent / "data" / "sample_login_logs.csv"
SAMPLE_SOURCE_NAME = "Sample dataset (fictional)"
STATUS_COLORS = {"SUCCESS": "#2f7d6d", "FAILED": "#b54708"}
SEVERITY_COLORS = {"High": "red", "Medium": "orange"}
EVIDENCE_DISPLAY_LIMIT = 500

st.set_page_config(
    page_title="SecureTrack | Login activity analysis",
    layout="wide",
    initial_sidebar_state="auto",
)
apply_theme()


@st.cache_data(show_spinner=False, max_entries=8)
def _parse_cached(raw: bytes, source_name: str) -> dict[str, Any]:
    """Cache parsing by file bytes.

    The bytes are the cache key, so replacing an upload or the sample file
    invalidates the entry automatically.
    """
    return parse_login_csv(raw, source_name=source_name)


def _init_state() -> None:
    st.session_state.setdefault("dataset_mode", "sample")
    st.session_state.setdefault("uploader_nonce", 0)
    st.session_state.setdefault("analysis_key", None)
    st.session_state.setdefault("alerts", [])
    st.session_state.setdefault("dataset_id", None)


def _clear_filter_keys() -> None:
    for key in list(st.session_state.keys()):
        if str(key).startswith("filter_"):
            st.session_state.pop(key, None)


def _load_sample() -> None:
    st.session_state["dataset_mode"] = "sample"
    st.session_state["uploader_nonce"] = (
        int(st.session_state.get("uploader_nonce", 0)) + 1
    )
    st.session_state["analysis_key"] = None
    st.session_state["alerts"] = []
    st.session_state["dataset_id"] = None
    _clear_filter_keys()


def _clear_dataset() -> None:
    st.session_state["dataset_mode"] = "none"
    st.session_state["uploader_nonce"] = (
        int(st.session_state.get("uploader_nonce", 0)) + 1
    )
    st.session_state["analysis_key"] = None
    st.session_state["alerts"] = []
    st.session_state["dataset_id"] = None
    _clear_filter_keys()


def _reset_filters() -> None:
    _clear_filter_keys()


def _format_utc(value: Any) -> str:
    if value is None:
        return "n/a"
    try:
        if pd.isna(value):
            return "n/a"
    except (TypeError, ValueError):
        pass
    timestamp = pd.Timestamp(value)
    if timestamp.tzinfo is not None:
        timestamp = timestamp.tz_convert("UTC")
    return timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")


def _format_bytes(size: int | None) -> str:
    if not size:
        return "0 B"
    if size < 1024:
        return f"{size} B"
    if size < 1024 * 1024:
        return f"{size / 1024:.1f} KB"
    return f"{size / (1024 * 1024):.1f} MB"


def _dataset_token(dataset_id: str) -> str:
    return hashlib.sha1(dataset_id.encode("utf-8")).hexdigest()[:12]


def _render_sidebar() -> tuple[Any, int, int, int, int]:
    with st.sidebar:
        st.markdown("## Dataset")
        nonce = int(st.session_state.get("uploader_nonce", 0))
        upload = st.file_uploader(
            "Upload login CSV",
            type=["csv"],
            key=f"uploader_{nonce}",
            help=(
                "UTF-8 CSV with timestamp, username, ip_address and status "
                f"columns. Maximum {MAX_UPLOAD_BYTES // (1024 * 1024)} MB."
            ),
        )

        mode = st.session_state.get("dataset_mode", "sample")
        if upload is not None:
            if mode != "upload":
                st.session_state["dataset_mode"] = "upload"
                st.session_state["analysis_key"] = None
            mode = "upload"
        elif mode == "upload":
            # Removing the active upload must not leave its results or filters
            # visible when a later upload is selected.
            st.session_state["dataset_mode"] = "none"
            st.session_state["analysis_key"] = None
            st.session_state["alerts"] = []
            st.session_state["dataset_id"] = None
            _clear_filter_keys()
            mode = "none"

        if mode == "sample":
            st.badge("Sample active", color="blue")
        elif mode == "upload":
            st.badge("Upload active", color="green")
        else:
            st.badge("No dataset", color="gray")

        button_cols = st.columns(2, gap="small")
        button_cols[0].button(
            "Load sample",
            on_click=_load_sample,
            key="load_sample_sidebar",
            width="stretch",
        )
        button_cols[1].button(
            "Clear dataset",
            on_click=_clear_dataset,
            key="clear_dataset_sidebar",
            width="stretch",
            disabled=mode == "none",
        )
        st.caption(
            "An uploaded file takes precedence over the sample. "
            "Use Load sample to clear the upload."
        )

        st.divider()
        st.markdown("## Detection settings")
        threshold = st.number_input(
            "Failed attempts threshold",
            min_value=2,
            max_value=50,
            value=5,
            key="threshold",
            help="Failed events from one IP or against one account.",
        )
        window = st.number_input(
            "Time window (minutes)",
            min_value=1,
            max_value=60,
            value=2,
            key="window",
            help="Window for the IP and account failure rules.",
        )
        spray_users = st.number_input(
            "Distinct accounts threshold",
            min_value=2,
            max_value=50,
            value=3,
            key="spray_users",
            help="Distinct usernames attempted from one IP.",
        )
        spray_window = st.number_input(
            "Account-spray window (minutes)",
            min_value=1,
            max_value=120,
            value=5,
            key="spray_window",
            help="Window for the account-spray rule.",
        )
        st.caption(
            "Failed events: one IP or one account within the first window. "
            "Account spray: distinct usernames from one IP within the second window."
        )
        st.divider()
        st.caption(
            "Alerts are indicators for human review, not confirmed attacks. "
            "SecureTrack never blocks an address or locks an account."
        )

    return upload, int(threshold), int(window), int(spray_users), int(spray_window)


def _error_result(source_name: str, size_bytes: int, reason: str) -> dict[str, Any]:
    return {
        "data": pd.DataFrame(),
        "errors": [{"row": "-", "reason": reason}],
        "meta": {
            "source_name": source_name,
            "size_bytes": size_bytes,
            "valid_rows": 0,
            "skipped_rows": 0,
            "data_rows": 0,
            "error_count": 1,
            "errors_truncated": False,
            "start_time": None,
            "end_time": None,
            "timezone": "UTC",
        },
    }


def _load_active_dataset(
    upload: Any,
    mode: str,
) -> tuple[dict[str, Any], str, str]:
    if mode == "sample":
        try:
            stat = SAMPLE_PATH.stat()
            raw = SAMPLE_PATH.read_bytes()
        except OSError as exc:
            reason = exc.strerror or "could not be read"
            return (
                _error_result(
                    SAMPLE_SOURCE_NAME,
                    0,
                    f"Could not read the sample dataset: {reason}.",
                ),
                "sample:unavailable",
                SAMPLE_SOURCE_NAME,
            )
        dataset_id = f"sample:{stat.st_mtime_ns}:{stat.st_size}"
        return _parse_cached(raw, SAMPLE_SOURCE_NAME), dataset_id, SAMPLE_SOURCE_NAME

    if mode == "upload" and upload is not None:
        source_name = upload.name or "Uploaded CSV"
        if upload.size > MAX_UPLOAD_BYTES:
            limit_mb = MAX_UPLOAD_BYTES / (1024 * 1024)
            return (
                _error_result(
                    source_name,
                    int(upload.size),
                    f"File exceeds the {limit_mb:g} MB upload limit.",
                ),
                f"upload:oversize:{upload.size}:{source_name}",
                source_name,
            )
        raw = upload.getvalue()
        dataset_id = f"upload:{hashlib.sha256(raw).hexdigest()}"
        return _parse_cached(raw, source_name), dataset_id, source_name

    return (
        _error_result("No dataset", 0, "No active dataset."),
        "none",
        "No dataset",
    )


def _render_dataset_bar(
    meta: dict[str, Any],
    mode: str,
    threshold: int,
    window: int,
    spray_users: int,
    spray_window: int,
) -> None:
    with st.container(border=True):
        source, coverage, quality, settings = st.columns(
            [2.4, 1.9, 1.6, 1.9], gap="medium"
        )
        with source:
            st.caption("ACTIVE DATASET")
            st.markdown(
                f"**{escape_markdown(meta.get('source_name', 'Unknown CSV'))}**"
            )
            st.badge(
                "Sample" if mode == "sample" else "Uploaded",
                color="blue" if mode == "sample" else "green",
            )
        with coverage:
            st.caption("TIME RANGE (UTC)")
            st.write(_format_utc(meta.get("start_time")))
            st.caption("to " + _format_utc(meta.get("end_time")))
        with quality:
            st.caption("ROWS")
            st.write(f"{int(meta.get('valid_rows', 0)):,} valid")
            skipped = int(meta.get("skipped_rows", 0))
            if skipped:
                st.badge(f"{skipped:,} skipped", color="orange")
            st.caption(
                f"{_format_bytes(meta.get('size_bytes'))} file · "
                f"{int(meta.get('data_rows', 0)):,} data rows"
            )
        with settings:
            st.caption("DETECTION SETTINGS")
            st.write(f"{threshold} failures / {window:g} min")
            st.caption(
                f"Account spray: {spray_users} accounts / {spray_window:g} min"
            )


def _render_metrics(df: pd.DataFrame, alerts: list[dict[str, Any]]) -> None:
    total = len(df)
    successful = int((df["status"] == "SUCCESS").sum())
    failed = int((df["status"] == "FAILED").sum())
    unique_ips = int(df["ip_address"].nunique())
    unique_users = int(df["username"].nunique())

    metric_cols = st.columns(5, gap="small")
    metric_cols[0].metric(
        "Total events",
        f"{total:,}",
        border=True,
        help="Valid events in the full active dataset.",
    )
    metric_cols[1].metric(
        "Successful",
        f"{successful:,}",
        border=True,
        help="Events with status SUCCESS.",
    )
    metric_cols[2].metric(
        "Failed",
        f"{failed:,}",
        border=True,
        help="Events with status FAILED.",
    )
    metric_cols[3].metric(
        "Unique IPs",
        f"{unique_ips:,}",
        border=True,
        help="Distinct source addresses in the full active dataset.",
    )
    metric_cols[4].metric(
        "Alerts",
        f"{len(alerts):,}",
        border=True,
        help="One alert per qualifying detection episode.",
    )
    failure_rate = (failed / total) if total else 0.0
    st.caption(
        f"Failure rate {failure_rate:.1%} · Unique accounts {unique_users:,} · "
        "Metrics summarize the full active dataset; exploration filters do not change them."
    )


def _render_validation(result: dict[str, Any]) -> None:
    errors = result.get("errors", [])
    if not errors:
        return

    meta = result.get("meta", {})
    error_count = int(meta.get("error_count", len(errors)))
    st.warning(
        f"{error_count:,} invalid row(s) were skipped. "
        "Valid rows are still included in the analysis."
    )
    with st.expander("View validation issues"):
        error_frame = pd.DataFrame(errors).rename(
            columns={"row": "CSV row", "reason": "Reason"}
        )
        st.dataframe(error_frame, width="stretch", hide_index=True)
        if meta.get("errors_truncated"):
            st.caption(
                f"Showing the first {len(errors):,} of {error_count:,} issues."
            )


def _render_filters(
    df: pd.DataFrame,
    dataset_id: str,
) -> tuple[ExplorationFilters, pd.DataFrame, bool]:
    token = _dataset_token(dataset_id)
    min_date = df["timestamp"].min().date()
    max_date = df["timestamp"].max().date()

    with st.container(border=True):
        header = st.columns([4, 1], gap="medium")
        with header[0]:
            st.markdown("**Explore filters**")
            st.caption(
                "Search accounts and addresses, restrict status, and select a UTC date range."
            )
        with header[1]:
            st.button(
                "Reset filters",
                on_click=_reset_filters,
                key="reset_exploration_filters",
                width="stretch",
            )

        row = st.columns([1.5, 1.0, 1.0], gap="medium")
        statuses = row[0].multiselect(
            "Status",
            ["SUCCESS", "FAILED"],
            default=list(DEFAULT_STATUSES),
            key=f"filter_status_{token}",
            help="Clear the selection to show no events.",
        )
        username_query = row[1].text_input(
            "Username contains",
            key=f"filter_username_{token}",
            placeholder="e.g. alex",
            help="Case-insensitive substring search.",
        )
        ip_query = row[2].text_input(
            "IP address contains",
            key=f"filter_ip_{token}",
            placeholder="e.g. 192.0.2",
            help="Case-insensitive substring search.",
        )

        date_row = st.columns([1, 1, 1.2], gap="medium")
        start_date = date_row[0].date_input(
            "From date (UTC)",
            value=min_date,
            min_value=min_date,
            max_value=max_date,
            key=f"filter_start_{token}",
        )
        end_date = date_row[1].date_input(
            "To date (UTC)",
            value=max_date,
            min_value=min_date,
            max_value=max_date,
            key=f"filter_end_{token}",
        )
        with date_row[2]:
            st.caption(
                "Dates are inclusive full UTC days. Detection and episode evidence "
                "always use the full active dataset."
            )

    if start_date > end_date:
        st.warning(
            "The start date is after the end date, so no events are shown."
        )
    elif not statuses:
        st.warning("No status is selected, so no events are shown.")

    filters = ExplorationFilters(
        statuses=tuple(statuses),
        username_query=username_query,
        ip_query=ip_query,
        start_date=start_date,
        end_date=end_date,
    )
    filtered_df = build_filtered_dataframe(df, filters)
    filters_active = (
        set(statuses) != set(DEFAULT_STATUSES)
        or bool(username_query.strip())
        or bool(ip_query.strip())
        or start_date != min_date
        or end_date != max_date
    )
    if filters_active:
        st.caption(
            f"Showing {len(filtered_df):,} of {len(df):,} valid events in the exploration views."
        )
    else:
        st.caption(f"Showing all {len(df):,} valid events in the exploration views.")
    return filters, filtered_df, filters_active


def _render_overview(filtered_df: pd.DataFrame) -> None:
    if filtered_df.empty:
        st.info("No events match the current filters.")
        return

    left, right = st.columns(2, gap="medium")
    with left:
        st.subheader("Login outcomes")
        counts = (
            filtered_df["status"]
            .value_counts()
            .reindex(["SUCCESS", "FAILED"], fill_value=0)
            .rename_axis("status")
            .reset_index(name="events")
        )
        figure = px.bar(
            counts,
            x="status",
            y="events",
            color="status",
            text="events",
            color_discrete_map=STATUS_COLORS,
        )
        figure.update_traces(textposition="outside", cliponaxis=False)
        figure.update_layout(
            showlegend=False,
            xaxis_title=None,
            yaxis_title="Events",
            bargap=0.45,
        )
        figure.update_yaxes(
            range=[0, max(float(counts["events"].max()) * 1.25, 1.0)],
            tickformat="d",
        )
        if float(counts["events"].max()) <= 10:
            figure.update_yaxes(dtick=1)
        st.plotly_chart(
            style_figure(figure, height=300),
            theme="streamlit",
            config={"displayModeBar": False},
        )
        st.caption("Counts in the current exploration view.")

    with right:
        st.subheader("Activity timeline")
        bucket = choose_timeline_bucket(filtered_df)
        timeline = (
            filtered_df.assign(
                bucket=filtered_df["timestamp"].dt.floor(bucket.frequency)
            )
            .groupby(["bucket", "status"])
            .size()
            .reset_index(name="events")
        )
        if not timeline.empty and len(timeline) <= 24:
            timeline = timeline.assign(label=timeline["events"].astype(str))

        figure = px.line(
            timeline,
            x="bucket",
            y="events",
            color="status",
            markers=True,
            text="label" if "label" in timeline.columns else None,
            color_discrete_map=STATUS_COLORS,
            labels={"bucket": "Time (UTC)", "events": "Events", "status": "Status"},
        )
        if "label" in timeline.columns:
            figure.update_traces(textposition="top center", cliponaxis=False)
        figure.update_layout(
            xaxis_title=None,
            yaxis_title="Events",
            hovermode="x unified",
        )
        figure.update_yaxes(tickformat="d")
        if float(timeline["events"].max()) <= 10:
            figure.update_yaxes(dtick=1)
        if bucket.frequency.endswith("min"):
            figure.update_xaxes(tickformat="%H:%M")
        elif bucket.frequency == "1h":
            figure.update_xaxes(tickformat="%b %d %H:%M")
        else:
            figure.update_xaxes(tickformat="%b %d")
        st.plotly_chart(
            style_figure(figure, height=300),
            theme="streamlit",
            config={"displayModeBar": False},
        )
        st.caption(f"{bucket.label} buckets, UTC.")

    st.subheader("Most active failed sources")
    failed = filtered_df[filtered_df["status"] == "FAILED"]
    top_ips_col, top_users_col = st.columns(2, gap="medium")
    with top_ips_col:
        st.markdown("**Top IP addresses**")
        if failed.empty:
            st.caption("No failed events in the current view.")
        else:
            top_ips = (
                failed.groupby("ip_address")
                .size()
                .sort_values(ascending=False)
                .head(10)
                .reset_index(name="failed_attempts")
            )
            st.dataframe(
                top_ips,
                width="stretch",
                hide_index=True,
                column_config={
                    "ip_address": st.column_config.TextColumn("IP address"),
                    "failed_attempts": st.column_config.NumberColumn(
                        "Failed events", format="%d"
                    ),
                },
            )
    with top_users_col:
        st.markdown("**Top accounts**")
        if failed.empty:
            st.caption("No failed events in the current view.")
        else:
            top_users = (
                failed.groupby("username")
                .size()
                .sort_values(ascending=False)
                .head(10)
                .reset_index(name="failed_attempts")
            )
            st.dataframe(
                top_users,
                width="stretch",
                hide_index=True,
                column_config={
                    "username": st.column_config.TextColumn("Account"),
                    "failed_attempts": st.column_config.NumberColumn(
                        "Failed events", format="%d"
                    ),
                },
            )
    st.caption(
        "Top 10 sources by failed events in the current view. "
        "Counts are not risk scores."
    )


def _render_log_explorer(filtered_df: pd.DataFrame, total_rows: int) -> None:
    st.subheader("Event log")
    st.caption(
        f"Showing {len(filtered_df):,} of {total_rows:,} valid events. "
        "Source row identifies the original CSV line."
    )
    if filtered_df.empty:
        st.info("No events match the current filters.")
        return

    view = filtered_df.sort_values(
        ["timestamp", "source_row"], ascending=[False, True]
    )
    st.dataframe(
        view,
        width="stretch",
        hide_index=True,
        column_order=["source_row", "timestamp", "username", "ip_address", "status"],
        column_config={
            "source_row": st.column_config.NumberColumn(
                "Source row", format="%d", width="small"
            ),
            "timestamp": st.column_config.DatetimeColumn(
                "Timestamp (UTC)", format="YYYY-MM-DD HH:mm:ss"
            ),
            "username": st.column_config.TextColumn("Account"),
            "ip_address": st.column_config.TextColumn("IP address"),
            "status": st.column_config.TextColumn("Status"),
        },
    )
    st.download_button(
        "Download filtered logs CSV",
        dataframe_to_safe_csv(view),
        "securetrack_filtered_logs.csv",
        "text/csv",
        key="download_filtered_logs",
        width="content",
    )
    st.caption(
        "Downloads are CSV-safe: formula-like cells are neutralised without "
        "changing the in-memory analysis."
    )


def _render_alert_card(alert: dict[str, Any]) -> None:
    with st.container(border=True):
        heading, priority = st.columns([4, 1], gap="medium")
        with heading:
            st.markdown(
                f"**{escape_markdown(alert.get('alert_id', 'Alert'))} · "
                f"{escape_markdown(alert.get('alert_type', 'Detection alert'))}**"
            )
            st.badge(
                f"{alert.get('entity_type', 'entity')}: "
                f"{alert.get('entity_value', '')}",
                color="gray",
            )
        with priority:
            st.badge(
                f"{alert.get('severity', 'Medium')} priority",
                color=SEVERITY_COLORS.get(alert.get("severity"), "orange"),
            )

        st.markdown(
            "**Why this alert was generated:** "
            + escape_markdown(alert.get("description", "No description available."))
        )

        detail_cols = st.columns(4, gap="small")
        detail_cols[0].metric(
            "Episode events", int(alert.get("event_count", 0)), border=True
        )
        if "peak_window_count" in alert:
            detail_cols[1].metric(
                "Peak events", int(alert["peak_window_count"]), border=True
            )
        else:
            detail_cols[1].metric(
                "Peak accounts",
                int(alert.get("peak_distinct_accounts", 0)),
                border=True,
            )
        detail_cols[2].metric(
            "Threshold", int(alert.get("threshold", 0)), border=True
        )
        detail_cols[3].metric(
            "Window", f"{float(alert.get('window_minutes', 0)):g} min", border=True
        )

        st.caption(
            f"Episode: {_format_utc(alert.get('start_time'))} to "
            f"{_format_utc(alert.get('end_time'))} · Peak window: "
            f"{_format_utc(alert.get('peak_window_start'))} to "
            f"{_format_utc(alert.get('peak_window_end'))}"
        )
        if "distinct_source_ips" in alert:
            st.caption(
                f"Distinct source IPs in episode: {alert['distinct_source_ips']}"
            )
        if "distinct_accounts" in alert:
            st.caption(
                f"Distinct accounts in episode: {alert['distinct_accounts']}"
            )

        with st.expander("Supporting evidence and export"):
            evidence = pd.DataFrame(alert.get("evidence", []))
            if evidence.empty:
                st.info("No evidence rows are available for this alert.")
            else:
                st.caption(
                    "Evidence shows the complete episode, regardless of exploration "
                    "filters, so the event count and threshold remain auditable."
                )
                shown = evidence.head(EVIDENCE_DISPLAY_LIMIT)
                if len(shown) < len(evidence):
                    st.caption(
                        f"Showing the first {len(shown):,} of "
                        f"{len(evidence):,} evidence rows."
                    )
                st.dataframe(
                    shown,
                    width="stretch",
                    hide_index=True,
                    column_order=[
                        column
                        for column in [
                            "source_row",
                            "timestamp",
                            "username",
                            "ip_address",
                            "status",
                        ]
                        if column in shown.columns
                    ],
                    column_config={
                        "source_row": st.column_config.NumberColumn(
                            "Source row", format="%d", width="small"
                        ),
                        "timestamp": st.column_config.DatetimeColumn(
                            "Timestamp (UTC)", format="YYYY-MM-DD HH:mm:ss"
                        ),
                        "username": st.column_config.TextColumn("Account"),
                        "ip_address": st.column_config.TextColumn("IP address"),
                        "status": st.column_config.TextColumn("Status"),
                    },
                )
                st.download_button(
                    "Download this alert's evidence CSV",
                    dataframe_to_safe_csv(evidence_frame([alert])),
                    f"{alert.get('alert_id', 'alert')}_evidence.csv",
                    "text/csv",
                    key=f"download_evidence_{alert.get('alert_id', 'alert')}",
                    width="content",
                )


def _render_alerts(
    alerts: list[dict[str, Any]],
    displayed_alerts: list[dict[str, Any]],
    filters_active: bool,
) -> None:
    st.subheader("Alert summary")
    with st.container(border=True):
        note, marker = st.columns([4, 1], gap="medium")
        with note:
            st.badge("Informational", color="blue")
            st.caption(
                "Alerts identify patterns for human review. They do not confirm an "
                "attack. Detection uses the full active dataset; filters only choose "
                "which alerts are displayed."
            )
        with marker:
            st.badge("UTC", color="gray")

    if not alerts:
        with st.container(border=True):
            st.badge("Informational", color="blue")
            st.subheader("No qualifying episodes")
            st.write(
                "No configured detection rule was triggered by the active dataset "
                "and current thresholds."
            )
            st.caption(
                "No alert does not prove the absence of an attack. Shared networks, "
                "test accounts, and mistyped passwords can also produce failures."
            )
        return

    high_count = sum(1 for alert in displayed_alerts if alert["severity"] == "High")
    medium_count = sum(
        1 for alert in displayed_alerts if alert["severity"] == "Medium"
    )
    count_cols = st.columns(3, gap="small")
    count_cols[0].metric(
        "High priority",
        high_count,
        border=True,
        help="Peak window reached at least twice the configured threshold.",
    )
    count_cols[1].metric(
        "Medium priority",
        medium_count,
        border=True,
        help="Threshold met without reaching twice the threshold.",
    )
    count_cols[2].metric(
        "Displayed alerts",
        len(displayed_alerts),
        border=True,
        help="Alerts matching the current exploration filters.",
    )

    if filters_active:
        st.caption(
            f"Showing {len(displayed_alerts):,} of {len(alerts):,} detected alerts. "
            "Detection is not re-run on the filtered view."
        )

    if not displayed_alerts:
        with st.container(border=True):
            st.badge("Informational", color="blue")
            st.write("No detected alerts match the current filters.")
            st.caption(
                f"{len(alerts):,} alert(s) were detected across the full dataset. "
                "Change the filters or reset them to inspect the full result."
            )
            st.button(
                "Clear filters",
                on_click=_reset_filters,
                key="clear_alert_filters",
            )
        return

    display = alert_display_frame(displayed_alerts)
    st.dataframe(
        display,
        width="stretch",
        hide_index=True,
        column_config={
            "alert_id": st.column_config.TextColumn("Alert", width="small"),
            "severity": st.column_config.TextColumn("Priority", width="small"),
            "rule_id": st.column_config.TextColumn("Rule", width="medium"),
            "entity": st.column_config.TextColumn("Entity", width="medium"),
            "start_time": st.column_config.TextColumn("Start (UTC)", width="medium"),
            "end_time": st.column_config.TextColumn("End (UTC)", width="medium"),
            "event_count": st.column_config.NumberColumn("Events", format="%d"),
            "peak": st.column_config.TextColumn("Peak"),
            "threshold": st.column_config.TextColumn("Threshold"),
            "window": st.column_config.TextColumn("Window"),
        },
    )

    summary = alert_summary_frame(displayed_alerts)
    download_cols = st.columns(2, gap="small")
    with download_cols[0]:
        st.download_button(
            "Download displayed alerts CSV",
            dataframe_to_safe_csv(summary),
            "securetrack_alerts.csv",
            "text/csv",
            key="download_alerts_summary",
            width="stretch",
        )
    with download_cols[1]:
        st.download_button(
            "Download displayed evidence CSV",
            dataframe_to_safe_csv(evidence_frame(displayed_alerts)),
            "securetrack_evidence.csv",
            "text/csv",
            key="download_all_evidence",
            width="stretch",
        )
    st.caption(
        "Downloads reflect the displayed alerts. Evidence can repeat an event "
        "when different rules describe the same episode."
    )

    st.subheader("Alert details")
    for alert in displayed_alerts:
        _render_alert_card(alert)


def _render_rules(
    threshold: int,
    window: int,
    spray_users: int,
    spray_window: int,
) -> None:
    st.subheader("Configured rules")
    rule_cols = st.columns(3, gap="medium")
    with rule_cols[0]:
        with st.container(border=True):
            st.badge("Rule 1", color="blue")
            st.markdown("**Repeated failures from one IP**")
            st.write(
                f"At least **{threshold}** failed events from one IP within "
                f"**{window:g} minutes**."
            )
    with rule_cols[1]:
        with st.container(border=True):
            st.badge("Rule 2", color="blue")
            st.markdown("**Repeated failures against one account**")
            st.write(
                f"At least **{threshold}** failed events for one username within "
                f"**{window:g} minutes**."
            )
    with rule_cols[2]:
        with st.container(border=True):
            st.badge("Rule 3", color="blue")
            st.markdown("**Multiple accounts targeted by one IP**")
            st.write(
                f"At least **{spray_users}** distinct usernames from one IP within "
                f"**{spray_window:g} minutes**."
            )

    st.subheader("Episode and severity semantics")
    st.write(
        "Each separate qualifying episode produces one alert. Evidence contains "
        "every event in that episode, and the peak qualifying window is reported "
        "separately. High priority means the peak reached at least twice the "
        "configured threshold; otherwise the alert is Medium priority. Severity "
        "reflects event volume, not the probability that an attack occurred."
    )

    st.subheader("Severity guide")
    guide_cols = st.columns(3, gap="medium")
    with guide_cols[0]:
        st.badge("High priority", color="red")
        st.caption(
            "The peak window reached at least twice the threshold. Review first, "
            "but treat it as a volume indicator, not a verdict."
        )
    with guide_cols[1]:
        st.badge("Medium priority", color="orange")
        st.caption(
            "The configured threshold was met. Review the affected account or "
            "address and the supporting evidence."
        )
    with guide_cols[2]:
        st.badge("Informational", color="blue")
        st.caption(
            "Scope notes, filter state, and no-match outcomes. Informational "
            "messages are not detection findings."
        )

    st.subheader("Scope and limitations")
    st.write(
        "These are configurable classroom demonstration thresholds, not universal "
        "standards. Shared networks, NAT, testing, or mistyped passwords can also "
        "cause repeated failures. SecureTrack never blocks an IP, locks an account, "
        "or proves that an attack occurred. Use only synthetic or authorized "
        "anonymized logs."
    )


def _render_empty_state() -> None:
    with st.container(border=True):
        st.subheader("No dataset loaded")
        st.write(
            "Load the fictional sample dataset to explore the interface, or upload "
            "a CSV from the sidebar."
        )
        st.caption(
            "Expected columns: timestamp, username, ip_address, status. "
            f"Maximum {MAX_UPLOAD_BYTES // (1024 * 1024)} MB and 50,000 data rows."
        )
        st.button(
            "Load sample dataset",
            on_click=_load_sample,
            key="load_sample_empty",
            type="primary",
        )


def _render_dataset_error(result: dict[str, Any]) -> None:
    meta = result.get("meta", {})
    st.error("The active dataset cannot be analyzed.")
    st.caption(
        "No analysis results are shown for this dataset. Load the sample or upload "
        "a corrected CSV to continue."
    )
    st.markdown(
        f"**Source:** {escape_markdown(meta.get('source_name', 'Unknown CSV'))}"
    )
    st.caption(
        f"File size: {_format_bytes(meta.get('size_bytes'))} · "
        "All timestamps must be ISO 8601 and are treated as UTC when no offset is supplied."
    )

    errors = result.get("errors", [])
    if errors:
        first_reason = str(errors[0].get("reason", "Unknown validation error"))
        st.markdown(f"**First issue:** {escape_markdown(first_reason)}")
        with st.expander("Validation details", expanded=True):
            error_frame = pd.DataFrame(errors).rename(
                columns={"row": "CSV row", "reason": "Reason"}
            )
            st.dataframe(error_frame, width="stretch", hide_index=True)
            if meta.get("errors_truncated"):
                st.caption(
                    f"Showing the first {len(errors):,} of "
                    f"{int(meta.get('error_count', len(errors))):,} issues."
                )

    action_cols = st.columns(2, gap="small")
    with action_cols[0]:
        st.button(
            "Load sample dataset",
            on_click=_load_sample,
            key="load_sample_error",
            width="stretch",
        )
    with action_cols[1]:
        st.button(
            "Clear dataset",
            on_click=_clear_dataset,
            key="clear_dataset_error",
            width="stretch",
        )


def main() -> None:
    _init_state()

    st.title("SecureTrack")
    st.caption(
        "Login activity analysis for suspicious-pattern review · "
        "Academic prototype · All timestamps UTC"
    )
    st.caption(
        "Alerts highlight patterns for human review. They do not confirm an attack "
        "and never trigger automatic blocking."
    )

    upload, threshold, window, spray_users, spray_window = _render_sidebar()
    mode = st.session_state.get("dataset_mode", "sample")

    if mode == "none":
        _render_empty_state()
        st.stop()

    result, dataset_id, _source_name = _load_active_dataset(upload, mode)
    meta = result.get("meta", {})
    df = result.get("data")
    if df is None or df.empty:
        _render_dataset_error(result)
        st.stop()

    analysis_key = (
        dataset_id,
        threshold,
        window,
        spray_users,
        spray_window,
    )
    if st.session_state.get("analysis_key") != analysis_key:
        try:
            alerts = detect_suspicious_activity(
                df,
                threshold,
                window,
                spray_users,
                spray_window,
            )
        except ValueError as exc:
            st.session_state["analysis_key"] = None
            st.session_state["alerts"] = []
            st.error(f"Unable to analyze the dataset: {exc}")
            st.stop()
        st.session_state["analysis_key"] = analysis_key
        st.session_state["alerts"] = alerts
        st.session_state["dataset_id"] = dataset_id
    else:
        alerts = st.session_state.get("alerts", [])

    _render_dataset_bar(
        meta,
        mode,
        threshold,
        window,
        spray_users,
        spray_window,
    )
    _render_metrics(df, alerts)
    _render_validation(result)

    filters, filtered_df, filters_active = _render_filters(df, dataset_id)
    displayed_alerts = filter_alerts_for_display(alerts, filters)

    overview_tab, log_tab, alerts_tab, rules_tab = st.tabs(
        ["Overview", "Log Explorer", "Security Alerts", "Detection Rules"]
    )
    with overview_tab:
        _render_overview(filtered_df)
    with log_tab:
        _render_log_explorer(filtered_df, len(df))
    with alerts_tab:
        _render_alerts(alerts, displayed_alerts, filters_active)
    with rules_tab:
        _render_rules(threshold, window, spray_users, spray_window)

    st.divider()
    st.caption(
        "SecureTrack · Local academic prototype · "
        "Use synthetic or authorized anonymized logs only."
    )


if __name__ == "__main__":
    main()
else:
    main()
