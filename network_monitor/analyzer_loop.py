from __future__ import annotations

import argparse
import logging
import time

from .alerting import TelegramNotifier, format_alert
from .config import get_config
from .detector import evaluate_recent_features
from .feature_extractor import aggregate_and_store

LOGGER = logging.getLogger(__name__)


def run_loop(db_path: str, window_seconds: int, interval_seconds: int, use_ml: bool = True) -> None:
    cfg = get_config()
    notifier = TelegramNotifier(cfg.telegram_bot_token, cfg.telegram_chat_id)
    LOGGER.info("Starting analyzer loop: window=%ss interval=%ss db=%s", window_seconds, interval_seconds, db_path)
    while True:
        features = aggregate_and_store(db_path, window_seconds=window_seconds)
        if not features.empty:
            alerts = evaluate_recent_features(db_path, use_ml=use_ml)
            for alert in alerts:
                LOGGER.warning("%s", alert["message"])
                notifier.send(format_alert(alert))
        time.sleep(interval_seconds)


def main() -> None:
    cfg = get_config()
    parser = argparse.ArgumentParser(description="Aggregate traffic and run detection periodically.")
    parser.add_argument("--db", default=str(cfg.db_path))
    parser.add_argument("--window", type=int, default=cfg.window_seconds)
    parser.add_argument("--interval", type=int, default=cfg.analyzer_interval_seconds)
    parser.add_argument("--no-ml", action="store_true")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    run_loop(args.db, args.window, args.interval, use_ml=not args.no_ml)


if __name__ == "__main__":
    main()
