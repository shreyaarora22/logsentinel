"""
Step 3: Rule-based detection.

Three rules, each saves alerts into the `alerts` table:
  1. brute_force       - many failed logins from one IP in a short time
  2. odd_hours         - successful login at night from a country the user never uses
  3. impossible_travel - same user logs in from two countries within an hour

Then we score ourselves against ground_truth.csv (precision / recall).

Run:  python detect_rules.py
"""
import csv
import pandas as pd
from db import get_connection, placeholder

# ---- Tunable thresholds (try changing these and re-running!) ----
BRUTE_FORCE_FAILS = 10      # failed attempts ...
BRUTE_FORCE_WINDOW = "5min" # ... within this window
NIGHT_START, NIGHT_END = 0, 5
TRAVEL_WINDOW_MIN = 60


def load_events(conn):
    df = pd.read_sql("SELECT * FROM login_events ORDER BY timestamp", conn)
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    return df


def rule_brute_force(df):
    alerts = []
    failed = df[df["status"] == "FAILED"].set_index("timestamp").sort_index()
    for ip, grp in failed.groupby("ip_address"):
        counts = grp["event_id"].rolling(BRUTE_FORCE_WINDOW).count()
        if (counts >= BRUTE_FORCE_FAILS).any():
            first_hit = counts[counts >= BRUTE_FORCE_FAILS].index[0]
            last_hit = counts[counts >= BRUTE_FORCE_FAILS].index[-1]
            # everything this IP did around the burst belongs to the attack
            burst = df[(df["ip_address"] == ip)
                       & (df["timestamp"] >= first_hit - pd.Timedelta(BRUTE_FORCE_WINDOW))
                       & (df["timestamp"] <= last_hit + pd.Timedelta("10min"))]
            for _, r in burst.iterrows():
                if r["status"] == "SUCCESS":
                    alerts.append((r["event_id"], "brute_force", "HIGH",
                                   f"Successful login after brute force from {ip} (account may be compromised)"))
                else:
                    alerts.append((r["event_id"], "brute_force", "MEDIUM",
                                   f"{BRUTE_FORCE_FAILS}+ failed logins from {ip} within {BRUTE_FORCE_WINDOW}"))
    return alerts


def rule_odd_hours(df):
    alerts = []
    home = df.groupby("username")["country"].agg(lambda s: s.mode().iloc[0])
    ok = df[df["status"] == "SUCCESS"]
    night = ok[(ok["timestamp"].dt.hour >= NIGHT_START) & (ok["timestamp"].dt.hour < NIGHT_END)]
    for _, r in night.iterrows():
        if r["country"] != home[r["username"]]:
            alerts.append((r["event_id"], "odd_hours", "MEDIUM",
                           f"Night login ({r['timestamp']:%H:%M}) from {r['country']}, usual country is {home[r['username']]}"))
    return alerts


def rule_impossible_travel(df):
    alerts = []
    ok = df[df["status"] == "SUCCESS"].sort_values(["username", "timestamp"])
    for user, grp in ok.groupby("username"):
        prev = None
        for _, r in grp.iterrows():
            if prev is not None and r["country"] != prev["country"]:
                gap = (r["timestamp"] - prev["timestamp"]).total_seconds() / 60
                if gap <= TRAVEL_WINDOW_MIN:
                    alerts.append((r["event_id"], "impossible_travel", "HIGH",
                                   f"{prev['country']} then {r['country']} only {gap:.0f} min apart"))
            prev = r
    return alerts


def save_alerts(conn, alerts):
    cur = conn.cursor()
    cur.execute("DELETE FROM alerts")
    ph = placeholder()
    cur.executemany(
        f"INSERT INTO alerts (event_id, rule, severity, details) VALUES ({ph},{ph},{ph},{ph})",
        [(int(e), r, s, d) for e, r, s, d in alerts])
    conn.commit()


def evaluate(alerts):
    """Compare flagged events with the real attacks we injected."""
    truth = pd.read_csv("data/ground_truth.csv")
    real = set(truth.loc[truth["is_attack"] == 1, "event_id"])
    flagged = {int(a[0]) for a in alerts}
    tp = len(real & flagged)
    precision = tp / len(flagged) if flagged else 0
    recall = tp / len(real) if real else 0
    print("\n=== How good is the detector? ===")
    print(f"Real attack events : {len(real)}")
    print(f"Events we flagged  : {len(flagged)}")
    print(f"Correctly caught   : {tp}")
    print(f"Precision {precision:.0%}  (of what we flagged, how much was real)")
    print(f"Recall    {recall:.0%}  (of real attacks, how many we caught)")
    missed = truth[truth["event_id"].isin(real - flagged)]
    if len(missed):
        print("Missed, by attack type:", missed["attack_type"].value_counts().to_dict())


def main():
    conn = get_connection()
    df = load_events(conn)

    alerts = rule_brute_force(df) + rule_odd_hours(df) + rule_impossible_travel(df)
    save_alerts(conn, alerts)

    by_rule = pd.Series([a[1] for a in alerts]).value_counts()
    print(f"Saved {len(alerts)} alerts to the database:")
    print(by_rule.to_string())
    evaluate(alerts)
    conn.close()


if __name__ == "__main__":
    main()
