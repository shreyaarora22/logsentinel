"""
Step 5: Machine-learning detection (Isolation Forest).

Rules only catch attacks that a human thought of in advance.
Isolation Forest is UNSUPERVISED: nobody tells it what an attack looks like.
It simply learns what "normal" looks like and flags events that are unusual.

How it works (simple version):
  - For every login event we build a few numbers (features), e.g. "what hour",
    "how many failures from this IP in 5 min", "is this a new country for this user".
  - The model draws random cut lines through the data. Normal events are packed
    together and take many cuts to isolate. Weird events sit alone and get isolated
    fast. Fast to isolate = anomaly.

Run:  python detect_ml.py
"""
import pandas as pd
from sklearn.ensemble import IsolationForest

import detect_rules as rules
from db import get_connection, placeholder

# Roughly what share of events we expect to be suspicious (a tunable guess)
EXPECTED_ANOMALY_SHARE = 0.07

FEATURES = [
    "hour", "is_night", "is_failed",
    "fails_ip_5min", "events_ip_10min",
    "country_not_home", "agent_not_usual",
    "minutes_since_prev", "country_changed",
]


def build_features(df):
    df = df.sort_values("timestamp").reset_index(drop=True)

    df["hour"] = df["timestamp"].dt.hour
    df["is_night"] = (df["hour"] < 6).astype(int)
    df["is_failed"] = (df["status"] == "FAILED").astype(int)

    # How busy / how many failures is this IP in a short window?
    df["fails_ip_5min"] = 0.0
    df["events_ip_10min"] = 0.0
    df["one"] = 1
    for _, g in df.groupby("ip_address"):
        gi = g.set_index("timestamp")
        df.loc[g.index, "fails_ip_5min"] = gi["is_failed"].rolling("5min").sum().values
        df.loc[g.index, "events_ip_10min"] = gi["one"].rolling("10min").sum().values

    # Is this normal for THIS user? (country, device)
    home_country = df.groupby("username")["country"].agg(lambda s: s.mode().iloc[0])
    home_agent = df.groupby("username")["user_agent"].agg(lambda s: s.mode().iloc[0])
    df["country_not_home"] = (df["country"] != df["username"].map(home_country)).astype(int)
    df["agent_not_usual"] = (df["user_agent"] != df["username"].map(home_agent)).astype(int)

    # Time since this user's previous event, and did the country change?
    prev_time = df.groupby("username")["timestamp"].shift()
    df["minutes_since_prev"] = ((df["timestamp"] - prev_time).dt.total_seconds() / 60).fillna(1440).clip(upper=1440)
    prev_country = df.groupby("username")["country"].shift()
    df["country_changed"] = ((prev_country.notna()) & (prev_country != df["country"])).astype(int)
    return df


def score(flagged, truth_real):
    tp = len(flagged & truth_real)
    p = tp / len(flagged) if flagged else 0
    r = tp / len(truth_real) if truth_real else 0
    return len(flagged), tp, p, r


def main():
    conn = get_connection()
    df = rules.load_events(conn)
    df = build_features(df)

    model = IsolationForest(n_estimators=200,
                            contamination=EXPECTED_ANOMALY_SHARE,
                            random_state=42)
    df["ml_flag"] = model.fit_predict(df[FEATURES]) == -1   # -1 means anomaly
    df["ml_score"] = -model.score_samples(df[FEATURES])      # higher = weirder

    truth = pd.read_csv("data/ground_truth.csv")
    real = set(truth.loc[truth["is_attack"] == 1, "event_id"])

    ml_set = set(df.loc[df["ml_flag"], "event_id"].astype(int))
    rule_alerts = (rules.rule_brute_force(df) + rules.rule_odd_hours(df)
                   + rules.rule_impossible_travel(df))
    rule_set = {int(a[0]) for a in rule_alerts}

    print(f"Real attack events: {len(real)}\n")
    print(f"{'Method':<14}{'Flagged':>9}{'Caught':>8}{'Precision':>11}{'Recall':>9}")
    for name, s in [("Rules only", rule_set), ("ML only", ml_set), ("Rules + ML", rule_set | ml_set)]:
        n, tp, p, r = score(s, real)
        print(f"{name:<14}{n:>9}{tp:>8}{p:>10.0%}{r:>9.0%}")

    extra = (ml_set - rule_set) & real
    print(f"\nAttack events the ML caught that the rules missed: {len(extra)}")

    # Save ML alerts next to the rule alerts (keep existing rule alerts)
    cur = conn.cursor()
    cur.execute("DELETE FROM alerts WHERE rule = 'ml_anomaly'")
    ph = placeholder()
    new_alerts = []
    for _, r in df[df["ml_flag"]].iterrows():
        sev = "HIGH" if r["ml_score"] > df.loc[df["ml_flag"], "ml_score"].median() else "MEDIUM"
        new_alerts.append((int(r["event_id"]), "ml_anomaly", sev,
                           f"Unusual behaviour score {r['ml_score']:.2f}"))
    cur.executemany(
        f"INSERT INTO alerts (event_id, rule, severity, details) VALUES ({ph},{ph},{ph},{ph})",
        new_alerts)
    conn.commit()
    print(f"Saved {len(new_alerts)} ML alerts to the database.")
    conn.close()


if __name__ == "__main__":
    main()
