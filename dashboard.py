"""
Step 6: LogSentinel dashboard.

Shows everything we built as a web page:
    python -m streamlit run dashboard.py

(Run detect_rules.py and detect_ml.py first, so the alerts table is filled.)
"""
import pandas as pd
import streamlit as st

from db import get_connection

st.set_page_config(page_title="LogSentinel", page_icon="🛡️", layout="wide")


@st.cache_data
def query(sql):
    """Run a SQL query and return a table (this is where your SQL skills show)."""
    conn = get_connection()
    df = pd.read_sql(sql, conn)
    conn.close()
    return df


# ---------- Load data with SQL ----------
alerts = query("""
    SELECT a.alert_id, a.event_id, a.rule, a.severity, a.details,
           e.timestamp, e.username, e.ip_address, e.country, e.status
    FROM alerts a
    JOIN login_events e ON e.event_id = a.event_id
    ORDER BY e.timestamp
""")
totals = query("""
    SELECT COUNT(*) AS events,
           SUM(CASE WHEN status = 'FAILED' THEN 1 ELSE 0 END) AS failed
    FROM login_events
""")

st.title("🛡️ LogSentinel")
st.caption("Suspicious login detection: SQL + rules + machine learning")

if alerts.empty:
    st.warning("No alerts found. Run `python detect_rules.py` and `python detect_ml.py` first.")
    st.stop()

alerts["timestamp"] = pd.to_datetime(alerts["timestamp"])

# ---------- Sidebar filters ----------
st.sidebar.header("Filters")
rules_pick = st.sidebar.multiselect("Detection method", sorted(alerts["rule"].unique()),
                                    default=sorted(alerts["rule"].unique()))
sev_pick = st.sidebar.multiselect("Severity", ["HIGH", "MEDIUM", "LOW"],
                                  default=["HIGH", "MEDIUM", "LOW"])
view = alerts[alerts["rule"].isin(rules_pick) & alerts["severity"].isin(sev_pick)]

# ---------- Top numbers ----------
c1, c2, c3, c4 = st.columns(4)
c1.metric("Login events", f"{int(totals['events'][0]):,}")
c2.metric("Failed logins", f"{int(totals['failed'][0]):,}")
c3.metric("Alerts shown", f"{len(view):,}")
c4.metric("Accounts affected", view["username"].nunique())

st.divider()

# ---------- Charts ----------
left, right = st.columns(2)
with left:
    st.subheader("Alerts by detection method")
    st.bar_chart(view["rule"].value_counts())
with right:
    st.subheader("Alerts per day")
    per_day = view.groupby(view["timestamp"].dt.date).size()
    st.line_chart(per_day)

left, right = st.columns(2)
with left:
    st.subheader("Where attacks come from (country)")
    st.bar_chart(view["country"].value_counts())
with right:
    st.subheader("Alerts by hour of day")
    st.caption("A spike at night means logins at odd hours")
    by_hour = view.groupby(view["timestamp"].dt.hour).size().reindex(range(24), fill_value=0)
    st.bar_chart(by_hour)

st.divider()

# ---------- Top suspicious IPs and users ----------
left, right = st.columns(2)
with left:
    st.subheader("Most suspicious IP addresses")
    st.dataframe(view.groupby("ip_address").size().sort_values(ascending=False)
                 .head(10).rename("alerts").reset_index(), hide_index=True,
                 width="stretch")
with right:
    st.subheader("Most targeted accounts")
    st.dataframe(view.groupby("username").size().sort_values(ascending=False)
                 .head(10).rename("alerts").reset_index(), hide_index=True,
                 width="stretch")

# ---------- Full alert list ----------
st.subheader("All alerts")
st.dataframe(view[["timestamp", "severity", "rule", "username", "ip_address",
                   "country", "status", "details"]],
             hide_index=True, width="stretch")
