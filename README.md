# 🛡️ LogSentinel

**Suspicious login detection using SQL, rule-based detection and machine learning.**

LogSentinel reads authentication logs, stores them in a SQL database, flags attacks with detection rules and an Isolation Forest model, and shows everything in an interactive dashboard.

![Dashboard overview](Screenshots/dashboard1.png)
![Dashboard charts and alerts](Screenshots/dashboard2.png)

## What it detects

| Detection | Type | What it looks for |
|---|---|---|
| Brute force | Rule | 10+ failed logins from one IP within 5 minutes, plus any successful login right after |
| Odd hours | Rule | Successful login between 00:00 and 05:00 from a country the user never normally uses |
| Impossible travel | Rule | Same user logging in from two different countries within 60 minutes |
| ML anomaly | Isolation Forest | Unusual behaviour across 9 features (hour, failures per IP, new country, new device, time since last login, ...) |

## Results

The project generates synthetic login logs (1,857 events, 60 users, 14 days) with 123 injected attack events, so detection can be measured against a known answer key.

| Method | Precision | Recall |
|---|---|---|
| Rules only | 98% | 100% |
| ML only (unsupervised) | 84% | 89% |
| Rules + ML | 84% | 100% |

**Threshold experiment:** raising the brute-force threshold from 10 to 30 failed logins dropped rule-based recall from 100% to **38%** (attackers who gave up before 30 attempts slipped through). Adding the ML model brought recall back up to **97%**, because it does not depend on a hand-picked threshold.

> Note: the data is synthetic and the attacks were written to match the rules, so the rule results are optimistic. The point of the project is the pipeline and the trade-off analysis, not a claim about real-world accuracy.

## How it works

```
generate_logs.py  ->  data/logs.csv          fake login logs with hidden attacks
load_logs.py      ->  SQL database           login_events + alerts tables
detect_rules.py   ->  alerts table           3 rules + precision/recall check
detect_ml.py      ->  alerts table           Isolation Forest anomaly detection
dashboard.py      ->  web dashboard          charts, filters, alert list (Streamlit)
```

## Run it

```
pip install -r requirements.txt
python generate_logs.py
python load_logs.py
python detect_rules.py
python detect_ml.py
python -m streamlit run dashboard.py
```

By default it uses SQLite (no setup). A MySQL schema is included in `schema.sql`; set `LS_DB=mysql` and the `LS_MYSQL_*` variables described in `db.py` to use it.

## Tech
Python, SQL (SQLite / MySQL), pandas, scikit-learn (Isolation Forest), Streamlit

## What I learned
- How brute force, impossible travel and odd-hour attacks appear in login logs
- Why detection thresholds trade false alarms against missed attacks
- Why rules and unsupervised ML work better together
- Measuring a detector with precision and recall

## Author
**Shreya Arora** · BCA student interested in cybersecurity and AI/ML
[LinkedIn](https://linkedin.com/in/shreya-arora-12a698343)
