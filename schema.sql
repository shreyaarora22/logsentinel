-- MySQL schema for LogSentinel
-- Run once:  mysql -u root -p < schema.sql

CREATE DATABASE IF NOT EXISTS logsentinel;
USE logsentinel;

DROP TABLE IF EXISTS alerts;
DROP TABLE IF EXISTS login_events;

CREATE TABLE login_events (
    event_id    INT PRIMARY KEY,
    timestamp   DATETIME     NOT NULL,
    username    VARCHAR(50)  NOT NULL,
    ip_address  VARCHAR(45)  NOT NULL,
    country     VARCHAR(50),
    status      VARCHAR(10)  NOT NULL,   -- SUCCESS or FAILED
    user_agent  VARCHAR(100),
    INDEX idx_user_time (username, timestamp),
    INDEX idx_ip_time (ip_address, timestamp)
);

CREATE TABLE alerts (
    alert_id    INT AUTO_INCREMENT PRIMARY KEY,
    event_id    INT          NOT NULL,
    rule        VARCHAR(50)  NOT NULL,   -- brute_force, odd_hours, impossible_travel, ml_anomaly
    severity    VARCHAR(10)  NOT NULL,   -- LOW, MEDIUM, HIGH
    details     VARCHAR(255),
    FOREIGN KEY (event_id) REFERENCES login_events(event_id)
);
