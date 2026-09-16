from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DB_PATH = PROJECT_ROOT / "data" / "traffic_monitor.db"
DEFAULT_MODEL_PATH = PROJECT_ROOT / "models" / "isolation_forest.pkl"


@dataclass(frozen=True)
class Thresholds:
    """Rule-based thresholds used by the anomaly detector.

    Values are intentionally conservative for a lab environment and should be tuned
    after collecting baseline traffic from the monitored LAN.
    """

    min_packets_for_rule: int = int(os.getenv("NBM_MIN_PACKETS_FOR_RULE", "20"))
    max_packets_per_second: float = float(os.getenv("NBM_MAX_PACKETS_PER_SECOND", "80"))
    max_bytes_per_second: float = float(os.getenv("NBM_MAX_BYTES_PER_SECOND", "500000"))
    max_unique_dst_ports: int = int(os.getenv("NBM_MAX_UNIQUE_DST_PORTS", "15"))
    max_syn_ratio: float = float(os.getenv("NBM_MAX_SYN_RATIO", "0.60"))
    max_icmp_ratio: float = float(os.getenv("NBM_MAX_ICMP_RATIO", "0.80"))
    max_unique_dst_ips: int = int(os.getenv("NBM_MAX_UNIQUE_DST_IPS", "20"))


@dataclass(frozen=True)
class AppConfig:
    db_path: Path = Path(os.getenv("NBM_DB_PATH", str(DEFAULT_DB_PATH)))
    model_path: Path = Path(os.getenv("NBM_MODEL_PATH", str(DEFAULT_MODEL_PATH)))
    window_seconds: int = int(os.getenv("NBM_WINDOW_SECONDS", "10"))
    analyzer_interval_seconds: int = int(os.getenv("NBM_ANALYZER_INTERVAL_SECONDS", "10"))
    scapy_filter: str = os.getenv("NBM_SCAPY_FILTER", "ip")
    interface: str | None = os.getenv("NBM_INTERFACE") or None
    thresholds: Thresholds = Thresholds()
    telegram_bot_token: str | None = os.getenv("TELEGRAM_BOT_TOKEN") or None
    telegram_chat_id: str | None = os.getenv("TELEGRAM_CHAT_ID") or None


def get_config() -> AppConfig:
    return AppConfig()
