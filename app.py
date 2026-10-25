import streamlit as st
import pandas as pd
import plotly.express as px
from core.parser import parse_login_csv
from core.detection import detect_suspicious_activity

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
sample_path = "data/sample_login_logs.csv"

if upload:
    if upload.size > 5 * 1024 * 1024:
        st.error("Maximum upload size is 5 MB.")
        st.stop()
    result = parse_login_csv(upload.getvalue())
elif sample or "result" not in st.session_state:
    result = parse_login_csv(sample_path)
else:
    result = st.session_state["result"]
st.session_state["result"] = result

df = result["data"]
if df.empty:
    st.error("No valid events found. Check the CSV columns and row values.")
    if result["errors"]:
        st.dataframe(pd.DataFrame(result["errors"]), use_container_width=True)
    st.stop()

alerts = detect_suspicious_activity(df, int(threshold), int(window), int(spray_users), int(spray_window))
total, success, failed = len(df), int((df.status == "SUCCESS").sum()), int((df.status == "FAILED").sum())
a, b, c, d, e = st.columns(5)
a.metric("Total events", total)
b.metric("Successful", success)
c.metric("Failed", failed)
d.metric("Unique IPs", df.ip_address.nunique())
e.metric("Alerts", len(alerts))

if result["errors"]:
    st.warning(f"{len(result['errors'])} invalid row(s) skipped.")
    with st.expander("View validation issues"):
        st.dataframe(pd.DataFrame(result["errors"]), use_container_width=True)

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
    st.dataframe(top, use_container_width=True, hide_index=True)

with t2:
    c1, c2, c3 = st.columns(3)
    statuses = c1.multiselect("Status", ["SUCCESS", "FAILED"], ["SUCCESS", "FAILED"])
    users = c2.multiselect("Username", sorted(df.username.unique()))
    ips = c3.multiselect("IP address", sorted(df.ip_address.unique()))
    view = df[df.status.isin(statuses)]
    if users: view = view[view.username.isin(users)]
    if ips: view = view[view.ip_address.isin(ips)]
    st.caption(f"{len(view)} of {len(df)} valid events")
    st.dataframe(view.sort_values("timestamp", ascending=False), use_container_width=True, hide_index=True)
    st.download_button("Download filtered logs", view.to_csv(index=False), "filtered_logs.csv", "text/csv")

with t3:
    if not alerts:
        st.success("No configured detection rules were triggered.")
    else:
        public_alerts = [{k:v for k,v in x.items() if k != "evidence"} for x in alerts]
        st.dataframe(pd.DataFrame(public_alerts), use_container_width=True, hide_index=True)
        for i, alert in enumerate(alerts, 1):
            with st.expander(f"{i}. {alert['alert_type']} — {alert.get('ip_address', alert.get('username'))}"):
                st.write(alert["description"])
                st.write(f"**Time range:** {alert['start_time']} to {alert['end_time']}")
                st.write(f"**Matching events:** {alert['event_count']}")
                st.dataframe(pd.DataFrame(alert["evidence"]), use_container_width=True, hide_index=True)
        st.download_button("Download alerts CSV", pd.DataFrame(public_alerts).to_csv(index=False), "securetrack_alerts.csv", "text/csv")

with t4:
    st.markdown(f"""
    **Rule 1 — Repeated failures from one IP:** at least {threshold} failed events in {window} minutes.

    **Rule 2 — Repeated failures against one account:** at least {threshold} failed events for one username in {window} minutes.

    **Rule 3 — Multiple accounts targeted by one IP:** at least {spray_users} distinct usernames from one IP in {spray_window} minutes.

    These are configurable classroom demonstration thresholds, not universal standards. Shared networks, NAT, testing, or mistyped passwords can also cause repeated failures.
    """)
st.caption("SecureTrack • Local academic prototype • Use synthetic or authorized anonymized logs only.")
