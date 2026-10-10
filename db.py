"""
Database helper.

By default uses SQLite (zero setup, a single file) so the project runs anywhere.
To use MySQL (what you'll show on your resume), set these environment variables:

    export LS_DB=mysql
    export LS_MYSQL_USER=root
    export LS_MYSQL_PASSWORD=yourpassword
    export LS_MYSQL_HOST=localhost        # optional
    pip install mysql-connector-python
    mysql -u root -p < schema.sql         # create the tables once
"""
import os
import sqlite3

BACKEND = os.environ.get("LS_DB", "sqlite").lower()
SQLITE_FILE = "logsentinel.db"

SQLITE_SCHEMA = """
DROP TABLE IF EXISTS alerts;
DROP TABLE IF EXISTS login_events;
CREATE TABLE login_events (
    event_id   INTEGER PRIMARY KEY,
    timestamp  TEXT NOT NULL,
    username   TEXT NOT NULL,
    ip_address TEXT NOT NULL,
    country    TEXT,
    status     TEXT NOT NULL,
    user_agent TEXT
);
CREATE INDEX idx_user_time ON login_events(username, timestamp);
CREATE INDEX idx_ip_time   ON login_events(ip_address, timestamp);
CREATE TABLE alerts (
    alert_id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id INTEGER NOT NULL,
    rule     TEXT NOT NULL,
    severity TEXT NOT NULL,
    details  TEXT,
    FOREIGN KEY (event_id) REFERENCES login_events(event_id)
);
"""


def get_connection():
    if BACKEND == "mysql":
        import mysql.connector  # pip install mysql-connector-python
        return mysql.connector.connect(
            host=os.environ.get("LS_MYSQL_HOST", "localhost"),
            user=os.environ.get("LS_MYSQL_USER", "root"),
            password=os.environ.get("LS_MYSQL_PASSWORD", ""),
            database="logsentinel",
        )
    return sqlite3.connect(SQLITE_FILE)


def placeholder():
    """MySQL uses %s, SQLite uses ?"""
    return "%s" if BACKEND == "mysql" else "?"


def reset_schema(conn):
    """Create fresh tables. For MySQL, run schema.sql yourself instead."""
    if BACKEND == "mysql":
        return
    conn.executescript(SQLITE_SCHEMA)
    conn.commit()
