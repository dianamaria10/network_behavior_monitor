from __future__ import annotations

import sqlite3
import time
from pathlib import Path
from typing import Any, Iterable

DB_SCHEMA = """
CREATE TABLE IF NOT EXISTS packets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    src_ip TEXT,
    dst_ip TEXT,
    protocol TEXT,
    src_port INTEGER,
    dst_port INTEGER,
    length INTEGER NOT NULL,
    tcp_flags TEXT
);

CREATE INDEX IF NOT EXISTS idx_packets_ts ON packets(ts);
CREATE INDEX IF NOT EXISTS idx_packets_src ON packets(src_ip);

CREATE TABLE IF NOT EXISTS features (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    window_start REAL NOT NULL,
    window_end REAL NOT NULL,
    flow_key TEXT NOT NULL,
    src_ip TEXT,
    dst_ip TEXT,
    total_packets INTEGER NOT NULL,
    total_bytes INTEGER NOT NULL,
    avg_packet_size REAL NOT NULL,
    tcp_count INTEGER NOT NULL,
    udp_count INTEGER NOT NULL,
    icmp_count INTEGER NOT NULL,
    syn_count INTEGER NOT NULL,
    ack_count INTEGER NOT NULL,
    unique_dst_ports INTEGER NOT NULL,
    unique_dst_ips INTEGER NOT NULL,
    duration REAL NOT NULL,
    packets_per_second REAL NOT NULL,
    bytes_per_second REAL NOT NULL,
    syn_ratio REAL NOT NULL,
    udp_ratio REAL NOT NULL,
    icmp_ratio REAL NOT NULL,
    mean_iat REAL NOT NULL,
    created_at REAL NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_features_window ON features(window_start, window_end);
CREATE INDEX IF NOT EXISTS idx_features_src ON features(src_ip);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    severity TEXT NOT NULL,
    alert_type TEXT NOT NULL,
    src_ip TEXT,
    dst_ip TEXT,
    message TEXT NOT NULL,
    anomaly_score REAL,
    feature_id INTEGER,
    FOREIGN KEY(feature_id) REFERENCES features(id)
);

CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts);
CREATE INDEX IF NOT EXISTS idx_alerts_src ON alerts(src_ip);
"""


def connect(db_path: str | Path) -> sqlite3.Connection:
    path = Path(db_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    return conn


def initialize_database(db_path: str | Path) -> None:
    with connect(db_path) as conn:
        conn.executescript(DB_SCHEMA)
        conn.commit()


def reset_database(db_path: str | Path) -> None:
    initialize_database(db_path)
    with connect(db_path) as conn:
        conn.execute("DELETE FROM alerts")
        conn.execute("DELETE FROM features")
        conn.execute("DELETE FROM packets")
        conn.commit()


def insert_packet(db_path: str | Path, packet: dict[str, Any]) -> None:
    initialize_database(db_path)
    with connect(db_path) as conn:
        conn.execute(
            """
            INSERT INTO packets (ts, src_ip, dst_ip, protocol, src_port, dst_port, length, tcp_flags)
            VALUES (:ts, :src_ip, :dst_ip, :protocol, :src_port, :dst_port, :length, :tcp_flags)
            """,
            packet,
        )
        conn.commit()


def insert_packets(db_path: str | Path, packets: Iterable[dict[str, Any]]) -> None:
    initialize_database(db_path)
    with connect(db_path) as conn:
        conn.executemany(
            """
            INSERT INTO packets (ts, src_ip, dst_ip, protocol, src_port, dst_port, length, tcp_flags)
            VALUES (:ts, :src_ip, :dst_ip, :protocol, :src_port, :dst_port, :length, :tcp_flags)
            """,
            packets,
        )
        conn.commit()


def insert_feature_row(db_path: str | Path, row: dict[str, Any]) -> int:
    initialize_database(db_path)
    row = dict(row)
    row.setdefault("created_at", time.time())
    columns = ", ".join(row.keys())
    placeholders = ", ".join([f":{key}" for key in row.keys()])
    with connect(db_path) as conn:
        cur = conn.execute(f"INSERT INTO features ({columns}) VALUES ({placeholders})", row)
        conn.commit()
        return int(cur.lastrowid)


def insert_alert(db_path: str | Path, alert: dict[str, Any]) -> int:
    initialize_database(db_path)
    alert = dict(alert)
    alert.setdefault("ts", time.time())
    columns = ", ".join(alert.keys())
    placeholders = ", ".join([f":{key}" for key in alert.keys()])
    with connect(db_path) as conn:
        cur = conn.execute(f"INSERT INTO alerts ({columns}) VALUES ({placeholders})", alert)
        conn.commit()
        return int(cur.lastrowid)


def fetch_dataframe(db_path: str | Path, query: str, params: tuple[Any, ...] = ()):  # pragma: no cover - thin wrapper
    import pandas as pd

    initialize_database(db_path)
    with connect(db_path) as conn:
        return pd.read_sql_query(query, conn, params=params)
