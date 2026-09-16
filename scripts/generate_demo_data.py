from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import argparse
import random
import time
from pathlib import Path

from network_monitor.database import initialize_database, insert_packets, reset_database
from network_monitor.detector import evaluate_recent_features
from network_monitor.feature_extractor import aggregate_and_store

NORMAL_CLIENTS = ["192.168.56.20", "192.168.56.21", "192.168.56.22"]
SERVERS = ["192.168.56.10", "192.168.56.1", "8.8.8.8"]
ATTACKER = "192.168.56.66"
TARGET = "192.168.56.10"


def normal_packet(ts: float) -> dict:
    proto = random.choices(["TCP", "UDP", "ICMP"], weights=[0.72, 0.22, 0.06], k=1)[0]
    src = random.choice(NORMAL_CLIENTS)
    dst = random.choice(SERVERS)
    if proto == "TCP":
        return {
            "ts": ts,
            "src_ip": src,
            "dst_ip": dst,
            "protocol": proto,
            "src_port": random.randint(20000, 65000),
            "dst_port": random.choice([80, 443, 22, 53]),
            "length": random.randint(60, 1400),
            "tcp_flags": random.choice(["A", "PA", "S", "FA"]),
        }
    if proto == "UDP":
        return {
            "ts": ts,
            "src_ip": src,
            "dst_ip": dst,
            "protocol": proto,
            "src_port": random.randint(20000, 65000),
            "dst_port": random.choice([53, 123, 500]),
            "length": random.randint(60, 600),
            "tcp_flags": None,
        }
    return {
        "ts": ts,
        "src_ip": src,
        "dst_ip": dst,
        "protocol": proto,
        "src_port": None,
        "dst_port": None,
        "length": random.randint(60, 120),
        "tcp_flags": None,
    }


def scan_packet(ts: float, port: int) -> dict:
    return {
        "ts": ts,
        "src_ip": ATTACKER,
        "dst_ip": TARGET,
        "protocol": "TCP",
        "src_port": random.randint(20000, 65000),
        "dst_port": port,
        "length": random.randint(54, 74),
        "tcp_flags": "S",
    }


def generate(db_path: str | Path, reset: bool = False) -> None:
    if reset:
        reset_database(db_path)
    else:
        initialize_database(db_path)

    now = time.time()
    start = now - 30 * 60
    packets = []

    for second in range(0, 30 * 60):
        ts_base = start + second
        for _ in range(random.randint(2, 8)):
            packets.append(normal_packet(ts_base + random.random()))

    # Synthetic scan-like anomaly in two short windows.
    anomaly_start = now - 10 * 60
    for i, port in enumerate(range(1, 160)):
        packets.append(scan_packet(anomaly_start + i * 0.03, port))

    anomaly_start_2 = now - 4 * 60
    for i, port in enumerate(range(2000, 2140)):
        packets.append(scan_packet(anomaly_start_2 + i * 0.025, port))

    insert_packets(db_path, packets)

    # Aggregate historical windows and run rule detection.
    for offset in range(30 * 60, 0, -10):
        end_ts = now - offset + 10
        features = aggregate_and_store(db_path, window_seconds=10, end_ts=end_ts)
        if not features.empty:
            evaluate_recent_features(db_path, use_ml=False)

    print(f"Generated {len(packets)} synthetic packets in {db_path}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate synthetic traffic for dashboard/demo without root privileges.")
    parser.add_argument("--db", default="data/traffic_monitor.db")
    parser.add_argument("--reset", action="store_true")
    args = parser.parse_args()
    generate(args.db, args.reset)


if __name__ == "__main__":
    main()
