"""
Step 1: Generate realistic fake login logs.

Creates two files:
  data/logs.csv          -> what a real system would give you
  data/ground_truth.csv  -> which rows are attacks (ONLY used to measure our detector)

Run:  python generate_logs.py
"""
import random
import csv
from datetime import datetime, timedelta

random.seed(42)  # same data every run, so results are reproducible

NUM_USERS = 60
DAYS = 14
START = datetime(2026, 9, 1, 0, 0, 0)

# country -> list of IP prefixes (fake, for demo only)
COUNTRIES = {
    "India": ["103.21", "49.36", "117.200"],
    "USA": ["34.201", "52.14"],
    "UK": ["81.2", "86.150"],
    "Germany": ["85.214"],
    "Russia": ["95.173"],
    "Brazil": ["177.54"],
    "China": ["114.114"],
}
USER_AGENTS = [
    "Chrome/Windows", "Chrome/Android", "Safari/iPhone",
    "Firefox/Linux", "Edge/Windows", "Safari/Mac",
]


def random_ip(country):
    prefix = random.choice(COUNTRIES[country])
    return f"{prefix}.{random.randint(1, 254)}.{random.randint(1, 254)}"


def build_users():
    """Each user has a 'normal' home country, working hours and device."""
    users = []
    for i in range(NUM_USERS):
        users.append({
            "name": f"user{i:02d}",
            "country": random.choices(
                ["India", "USA", "UK", "Germany"], weights=[60, 20, 12, 8])[0],
            "start_hour": random.choice([8, 9, 10]),
            "end_hour": random.choice([17, 18, 19]),
            "agent": random.choice(USER_AGENTS),
        })
    return users


def normal_events(users):
    """Normal behaviour: logins during work hours, from home country, mostly successful."""
    rows = []
    for u in users:
        for d in range(DAYS):
            day = START + timedelta(days=d)
            if day.weekday() >= 5 and random.random() < 0.7:
                continue  # most people don't work weekends
            for _ in range(random.randint(1, 4)):
                hour = random.randint(u["start_hour"], u["end_hour"])
                ts = day.replace(hour=hour, minute=random.randint(0, 59),
                                 second=random.randint(0, 59))
                # people sometimes mistype a password (about 4%)
                status = "FAILED" if random.random() < 0.04 else "SUCCESS"
                rows.append((ts, u["name"], random_ip(u["country"]),
                             u["country"], status, u["agent"], 0, ""))
    return rows


def attack_brute_force(users):
    """One IP hammers one account with many failed logins in a few minutes."""
    rows = []
    for _ in range(4):
        victim = random.choice(users)
        attacker_country = random.choice(["Russia", "China", "Brazil"])
        ip = random_ip(attacker_country)
        start = START + timedelta(days=random.randint(1, DAYS - 2),
                                  hours=random.randint(0, 23),
                                  minutes=random.randint(0, 50))
        n = random.randint(15, 40)
        for k in range(n):
            ts = start + timedelta(seconds=k * random.randint(2, 6))
            rows.append((ts, victim["name"], ip, attacker_country,
                         "FAILED", "python-requests", 1, "brute_force"))
        # sometimes the attacker finally gets in
        if random.random() < 0.6:
            ts = start + timedelta(seconds=n * 6 + 5)
            rows.append((ts, victim["name"], ip, attacker_country,
                         "SUCCESS", "python-requests", 1, "brute_force"))
    return rows


def attack_odd_hours(users):
    """A successful login at 2-4 AM from an unusual country."""
    rows = []
    for _ in range(8):
        victim = random.choice(users)
        country = random.choice(["Russia", "China", "Brazil"])
        day = START + timedelta(days=random.randint(1, DAYS - 1))
        ts = day.replace(hour=random.randint(2, 4), minute=random.randint(0, 59),
                         second=random.randint(0, 59))
        rows.append((ts, victim["name"], random_ip(country), country,
                     "SUCCESS", "Unknown/Headless", 1, "odd_hours"))
    return rows


def attack_impossible_travel(users):
    """Same user logs in from two far-apart countries within minutes."""
    rows = []
    for _ in range(6):
        victim = random.choice([u for u in users if u["country"] in ("India", "USA")])
        far = "USA" if victim["country"] == "India" else "India"
        day = START + timedelta(days=random.randint(1, DAYS - 1))
        t1 = day.replace(hour=random.randint(10, 16), minute=random.randint(0, 30))
        t2 = t1 + timedelta(minutes=random.randint(5, 25))
        rows.append((t1, victim["name"], random_ip(victim["country"]),
                     victim["country"], "SUCCESS", victim["agent"], 0, ""))
        rows.append((t2, victim["name"], random_ip(far), far,
                     "SUCCESS", "Chrome/Windows", 1, "impossible_travel"))
    return rows


def main():
    users = build_users()
    rows = (normal_events(users) + attack_brute_force(users)
            + attack_odd_hours(users) + attack_impossible_travel(users))
    rows.sort(key=lambda r: r[0])

    with open("data/logs.csv", "w", newline="") as f_logs, \
         open("data/ground_truth.csv", "w", newline="") as f_truth:
        w_logs, w_truth = csv.writer(f_logs), csv.writer(f_truth)
        w_logs.writerow(["event_id", "timestamp", "username", "ip_address",
                         "country", "status", "user_agent"])
        w_truth.writerow(["event_id", "is_attack", "attack_type"])
        for i, (ts, user, ip, country, status, agent, is_attack, kind) in enumerate(rows, 1):
            w_logs.writerow([i, ts.strftime("%Y-%m-%d %H:%M:%S"), user, ip,
                             country, status, agent])
            w_truth.writerow([i, is_attack, kind])

    attacks = sum(r[6] for r in rows)
    print(f"Created {len(rows)} log events ({attacks} are injected attacks)")
    print("Files: data/logs.csv, data/ground_truth.csv")


if __name__ == "__main__":
    main()
