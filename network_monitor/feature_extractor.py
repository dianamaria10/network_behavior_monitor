from __future__ import annotations

import argparse
import time
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

from .database import fetch_dataframe, insert_feature_row


def _flag_contains(flags: Any, char: str) -> bool:
    if flags is None or pd.isna(flags):
        return False
    return char in str(flags)


def aggregate_window(
    db_path: str | Path,
    window_seconds: int = 10,
    end_ts: float | None = None,
    group_by: str = "src_ip",
) -> pd.DataFrame:
    """Aggregate raw packets into behavioral feature vectors.

    The default grouping by source IP highlights hosts that behave unusually within
    a time window, which is useful for detecting scans and floods in a LAN lab.
    """

    end_ts = end_ts or time.time()
    start_ts = end_ts - window_seconds
    packets = fetch_dataframe(
        db_path,
        """
        SELECT ts, src_ip, dst_ip, protocol, src_port, dst_port, length, tcp_flags
        FROM packets
        WHERE ts >= ? AND ts < ?
        ORDER BY ts ASC
        """,
        (start_ts, end_ts),
    )

    if packets.empty:
        return pd.DataFrame()

    rows: list[dict[str, Any]] = []
    group_cols = [group_by] if group_by in packets.columns else ["src_ip"]

    for key, grp in packets.groupby(group_cols, dropna=False):
        src_ip = str(key[0] if isinstance(key, tuple) else key)
        dst_values = grp["dst_ip"].dropna().astype(str)
        protocol_counts = grp["protocol"].value_counts()
        tcp_count = int(protocol_counts.get("TCP", 0))
        udp_count = int(protocol_counts.get("UDP", 0))
        icmp_count = int(protocol_counts.get("ICMP", 0))
        total_packets = int(len(grp))
        total_bytes = int(grp["length"].sum())
        duration = float(max(window_seconds, 1))

        syn_count = int(grp["tcp_flags"].apply(lambda flags: _flag_contains(flags, "S") and not _flag_contains(flags, "A")).sum())
        ack_count = int(grp["tcp_flags"].apply(lambda flags: _flag_contains(flags, "A")).sum())
        unique_dst_ports = int(grp["dst_port"].dropna().nunique())
        unique_dst_ips = int(dst_values.nunique())

        ts_sorted = grp["ts"].sort_values().to_numpy()
        if len(ts_sorted) > 1:
            mean_iat = float(np.diff(ts_sorted).mean())
        else:
            mean_iat = float(window_seconds)

        rows.append(
            {
                "window_start": float(start_ts),
                "window_end": float(end_ts),
                "flow_key": f"src:{src_ip}",
                "src_ip": src_ip,
                "dst_ip": ",".join(dst_values.unique()[:3]),
                "total_packets": total_packets,
                "total_bytes": total_bytes,
                "avg_packet_size": float(grp["length"].mean()),
                "tcp_count": tcp_count,
                "udp_count": udp_count,
                "icmp_count": icmp_count,
                "syn_count": syn_count,
                "ack_count": ack_count,
                "unique_dst_ports": unique_dst_ports,
                "unique_dst_ips": unique_dst_ips,
                "duration": duration,
                "packets_per_second": float(total_packets / duration),
                "bytes_per_second": float(total_bytes / duration),
                "syn_ratio": float(syn_count / total_packets) if total_packets else 0.0,
                "udp_ratio": float(udp_count / total_packets) if total_packets else 0.0,
                "icmp_ratio": float(icmp_count / total_packets) if total_packets else 0.0,
                "mean_iat": mean_iat,
                "created_at": time.time(),
            }
        )

    return pd.DataFrame(rows)


def aggregate_and_store(db_path: str | Path, window_seconds: int = 10, end_ts: float | None = None) -> pd.DataFrame:
    features = aggregate_window(db_path, window_seconds=window_seconds, end_ts=end_ts)
    if features.empty:
        return features

    feature_ids = []
    for row in features.to_dict(orient="records"):
        feature_ids.append(insert_feature_row(db_path, row))
    features.insert(0, "feature_id", feature_ids)
    return features


def main() -> None:
    parser = argparse.ArgumentParser(description="Aggregate packet metadata into behavioral feature vectors.")
    parser.add_argument("--db", required=True, help="SQLite database path")
    parser.add_argument("--window", type=int, default=10, help="Window size in seconds")
    args = parser.parse_args()
    df = aggregate_and_store(args.db, args.window)
    print(df if not df.empty else "No packets found for the selected window.")


if __name__ == "__main__":
    main()
