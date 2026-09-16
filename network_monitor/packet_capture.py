from __future__ import annotations

import argparse
import logging
import time
from pathlib import Path
from typing import Any

from .config import get_config
from .database import initialize_database, insert_packet

LOGGER = logging.getLogger(__name__)


def parse_packet(packet: Any) -> dict[str, Any] | None:
    """Convert a Scapy packet into a normalized metadata dictionary.

    Only header-level metadata is extracted. Payload content is not stored.
    """

    try:
        from scapy.layers.inet import ICMP, IP, TCP, UDP
    except ImportError as exc:  # pragma: no cover - depends on optional runtime package
        raise RuntimeError("Scapy is required for live packet capture. Install requirements.txt.") from exc

    if IP not in packet:
        return None

    ip_layer = packet[IP]
    protocol = "OTHER"
    src_port: int | None = None
    dst_port: int | None = None
    tcp_flags: str | None = None

    if TCP in packet:
        protocol = "TCP"
        src_port = int(packet[TCP].sport)
        dst_port = int(packet[TCP].dport)
        tcp_flags = str(packet[TCP].flags)
    elif UDP in packet:
        protocol = "UDP"
        src_port = int(packet[UDP].sport)
        dst_port = int(packet[UDP].dport)
    elif ICMP in packet:
        protocol = "ICMP"

    return {
        "ts": time.time(),
        "src_ip": ip_layer.src,
        "dst_ip": ip_layer.dst,
        "protocol": protocol,
        "src_port": src_port,
        "dst_port": dst_port,
        "length": int(len(packet)),
        "tcp_flags": tcp_flags,
    }


def start_capture(db_path: str | Path, interface: str | None = None, packet_filter: str = "ip", count: int = 0) -> None:
    """Start live packet capture and store metadata in SQLite.

    On Linux this usually requires root privileges or packet-capture capabilities.
    """

    try:
        from scapy.all import sniff
    except ImportError as exc:  # pragma: no cover - depends on optional runtime package
        raise RuntimeError("Scapy is required for live packet capture. Install requirements.txt.") from exc

    initialize_database(db_path)
    LOGGER.info("Starting capture: interface=%s filter=%s db=%s", interface or "default", packet_filter, db_path)

    def handle_packet(pkt: Any) -> None:
        metadata = parse_packet(pkt)
        if metadata is None:
            return
        insert_packet(db_path, metadata)
        LOGGER.debug("Stored packet: %s -> %s %s", metadata["src_ip"], metadata["dst_ip"], metadata["protocol"])

    sniff(iface=interface, filter=packet_filter, prn=handle_packet, store=False, count=count)


def main() -> None:
    cfg = get_config()
    parser = argparse.ArgumentParser(description="Capture LAN packet metadata using Scapy.")
    parser.add_argument("--db", default=str(cfg.db_path), help="SQLite database path")
    parser.add_argument("--interface", default=cfg.interface, help="Network interface, e.g. eth0")
    parser.add_argument("--filter", default=cfg.scapy_filter, help="BPF filter, default: ip")
    parser.add_argument("--count", type=int, default=0, help="Number of packets to capture; 0 means continuous")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    start_capture(args.db, args.interface, args.filter, args.count)


if __name__ == "__main__":
    main()
