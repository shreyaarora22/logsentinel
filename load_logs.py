"""
Step 2: Load logs.csv into the database.

Run:  python load_logs.py
"""
import csv
from db import get_connection, placeholder, reset_schema


def main():
    conn = get_connection()
    reset_schema(conn)
    cur = conn.cursor()

    if placeholder() == "%s":  # MySQL: clear old rows
        cur.execute("DELETE FROM alerts")
        cur.execute("DELETE FROM login_events")

    ph = placeholder()
    sql = (f"INSERT INTO login_events "
           f"(event_id, timestamp, username, ip_address, country, status, user_agent) "
           f"VALUES ({ph},{ph},{ph},{ph},{ph},{ph},{ph})")

    with open("data/logs.csv") as f:
        rows = [tuple(r.values()) for r in csv.DictReader(f)]

    cur.executemany(sql, rows)
    conn.commit()

    cur.execute("SELECT COUNT(*) FROM login_events")
    print(f"Loaded {cur.fetchone()[0]} events into the database")

    # A first SQL query so you can see the data is really there
    cur.execute("""
        SELECT status, COUNT(*) FROM login_events GROUP BY status
    """)
    for status, n in cur.fetchall():
        print(f"  {status}: {n}")
    conn.close()


if __name__ == "__main__":
    main()
