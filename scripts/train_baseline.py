from __future__ import annotations

import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import argparse

from network_monitor.config import DEFAULT_MODEL_PATH
from network_monitor.detector import train_from_database


def main() -> None:
    parser = argparse.ArgumentParser(description="Train Isolation Forest baseline from stored feature vectors.")
    parser.add_argument("--db", default="data/traffic_monitor.db")
    parser.add_argument("--model", default=str(DEFAULT_MODEL_PATH))
    parser.add_argument("--limit", type=int, default=2000)
    args = parser.parse_args()
    train_from_database(args.db, args.model, args.limit)
    print(f"Baseline model saved to {args.model}")


if __name__ == "__main__":
    main()
