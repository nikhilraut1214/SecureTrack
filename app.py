from pathlib import Path

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

SAMPLE_PATH = Path(__file__).resolve().parent / "data" / "sample_login_logs.csv"

st.set_page_config(page_title="SecureTrack", page_icon="🛡️", layout="wide")
st.title("🛡️ SecureTrack")
st.caption("Login Activity Analyzer & Suspicious Login Detection System")
st.info("Academic prototype: analyzes uploaded/sample logs. Alerts indicate patterns for review; they do not prove an attack.")

with st.sidebar:
    st.header("Detection settings")
    threshold = st.number_input("Failed attempts threshold", 2, 50, 5)
    window = st.number_input("Time window (minutes)", 1, 60, 2)
    spray_users = st.number_input("Distinct accounts threshold", 2, 50, 3)
    spray_window = st.number_input("Account-spray window (minutes)", 1, 120, 5)
    st.caption("CSV columns: timestamp, username, ip_address, status")

upload = st.file_uploader("Upload login activity CSV", type=["csv"])
sample = st.button("Load sample dataset")

if upload:
    if upload.size > MAX_UPLOAD_BYTES:
        st.error(f"Maximum upload size is {MAX_UPLOAD_BYTES // (1024 * 1024)} MB.")
        st.stop()
    result = parse_login_csv(upload.getvalue(), source_name=upload.name)
elif sample or "result" not in st.session_state:
    result = parse_login_csv(
        SAMPLE_PATH,
        source_name="Sample dataset (fictional)",
    )
else:
    result = st.session_state["result"]
st.session_state["result"] = result

df = result["data"]
meta = result.get("meta", {})
if df.empty:
    st.error("No valid events found. Check the CSV columns and row values.")
    if result["errors"]:
        st.caption(f"First validation issue: {result['errors'][0]['reason']}")
        st.dataframe(pd.DataFrame(result["errors"]), width="stretch")
    st.stop()

try:
    alerts = detect_suspicious_activity(
        df,
        int(threshold),
        int(window),
        int(spray_users),
        int(spray_window),
    )
except ValueError as exc:
    st.error(f"Unable to analyze the dataset: {exc}")
    st.stop()
if meta:
    st.caption(
        f"Dataset: {meta.get('source_name', 'Unknown CSV')} · "
        f"{meta.get('valid_rows', len(df)):,} valid / "
        f"{meta.get('skipped_rows', 0):,} skipped · "
        f"{meta.get('start_time') or 'n/a'} to {meta.get('end_time') or 'n/a'} (UTC)"
    )

total, success, failed = len(df), int((df.status == "SUCCESS").sum()), int((df.status == "FAILED").sum())
a, b, c, d, e = st.columns(5)
a.metric("Total events", total)
b.metric("Successful", success)
c.metric("Failed", failed)
d.metric("Unique IPs", df.ip_address.nunique())
e.metric("Alerts", len(alerts))

if result["errors"]:
    error_count = meta.get("error_count", len(result["errors"]))
    st.warning(f"{error_count} invalid row(s) skipped.")
    with st.expander("View validation issues"):
        st.dataframe(pd.DataFrame(result["errors"]), width="stretch")
        if meta.get("errors_truncated"):
            st.caption(
                f"Showing the first {len(result['errors'])} of "
                f"{error_count} issues."
            )

t1, t2, t3, t4 = st.tabs(["Overview", "Log Explorer", "Security Alerts", "Detection Rules"])
with t1:
    left, right = st.columns(2)
    with left:
        counts = df.status.value_counts().rename_axis("status").reset_index(name="events")
        st.plotly_chart(px.pie(counts, names="status", values="events", hole=.5, title="Login outcomes"), use_container_width=True)
    with right:
        timeline = df.assign(hour=df.timestamp.dt.floor("h")).groupby(["hour", "status"]).size().reset_index(name="events")
        st.plotly_chart(px.line(timeline, x="hour", y="events", color="status", markers=True, title="Login activity over time"), use_container_width=True)
    top = df[df.status == "FAILED"].groupby("ip_address").size().sort_values(ascending=False).head(10).reset_index(name="failed_attempts")
    st.subheader("Top IP addresses by failed attempts")
    st.dataframe(top, width="stretch", hide_index=True)

with t2:
    c1, c2, c3 = st.columns(3)
    statuses = c1.multiselect("Status", ["SUCCESS", "FAILED"], ["SUCCESS", "FAILED"])
    users = c2.multiselect("Username", sorted(df.username.unique()))
    ips = c3.multiselect("IP address", sorted(df.ip_address.unique()))
    view = df[df.status.isin(statuses)]
    if users: view = view[view.username.isin(users)]
    if ips: view = view[view.ip_address.isin(ips)]
    view = view.sort_values("timestamp", ascending=False)
    st.caption(f"{len(view)} of {len(df)} valid events")
    st.dataframe(view, width="stretch", hide_index=True)
    st.download_button(
        "Download filtered logs",
        dataframe_to_safe_csv(view),
        "filtered_logs.csv",
        "text/csv",
    )

with t3:
    if not alerts:
        st.success("No configured detection rules were triggered.")
    else:
        summary = alert_summary_frame(alerts)
        st.caption(
            "One alert is reported per qualifying episode. Different rules may "
            "describe the same events; a rule match is not a confirmed attack."
        )
        st.dataframe(summary, width="stretch", hide_index=True)
        for alert in alerts:
            entity = alert.get("entity_value", alert.get("ip_address", alert.get("username")))
            with st.expander(
                f"{alert.get('alert_id')}. {alert['alert_type']} — {entity}"
            ):
                st.write(alert["description"])
                st.write(
                    f"**Severity:** {alert['severity']} (volume indicator, "
                    "not a probability)"
                )
                st.write(
                    f"**Time range (UTC):** {alert['start_time']} to "
                    f"{alert['end_time']}"
                )
                if "peak_window_count" in alert:
                    peak = f"{alert['peak_window_count']} events"
                else:
                    peak = f"{alert.get('peak_distinct_accounts')} distinct accounts"
                st.write(
                    f"**Episode events:** {alert['event_count']} · "
                    f"**Peak window:** {peak}"
                )
                st.write(
                    f"**Peak window time (UTC):** {alert['peak_window_start']} "
                    f"to {alert['peak_window_end']}"
                )
                if "distinct_source_ips" in alert:
                    st.write(
                        f"**Distinct source IPs in episode:** "
                        f"{alert['distinct_source_ips']}"
                    )
                if "distinct_accounts" in alert:
                    st.write(
                        f"**Distinct accounts in episode:** "
                        f"{alert['distinct_accounts']}"
                    )
                st.write(
                    f"**Rule threshold:** {alert['threshold']} in "
                    f"{alert['window_minutes']:g} minutes"
                )
                st.dataframe(
                    pd.DataFrame(alert["evidence"]),
                    width="stretch",
                    hide_index=True,
                )
                st.download_button(
                    "Download evidence CSV",
                    dataframe_to_safe_csv(evidence_frame([alert])),
                    f"{alert['alert_id']}_evidence.csv",
                    "text/csv",
                    key=f"download_evidence_{alert['alert_id']}",
                )
        st.download_button(
            "Download alerts CSV",
            dataframe_to_safe_csv(summary),
            "securetrack_alerts.csv",
            "text/csv",
        )
        st.download_button(
            "Download all evidence CSV",
            dataframe_to_safe_csv(evidence_frame(alerts)),
            "securetrack_evidence.csv",
            "text/csv",
        )

with t4:
    st.markdown(f"""
    **Rule 1 — Repeated failures from one IP:** at least {threshold} failed events in {window} minutes.

    **Rule 2 — Repeated failures against one account:** at least {threshold} failed events for one username in {window} minutes.

    **Rule 3 — Multiple accounts targeted by one IP:** at least {spray_users} distinct usernames from one IP in {spray_window} minutes.

    **Episodes:** each separate qualifying episode produces its own alert. Evidence contains every event in that episode, and the peak qualifying window is reported separately.

    **Severity:** High when the peak reaches twice the configured threshold, otherwise Medium. Severity reflects event volume, not the probability that an attack occurred.

    These are configurable classroom demonstration thresholds, not universal standards. Shared networks, NAT, testing, or mistyped passwords can also cause repeated failures. No alert proves an attack, and SecureTrack never blocks an IP or locks an account.
    """)
st.caption("SecureTrack • Local academic prototype • Use synthetic or authorized anonymized logs only.")
