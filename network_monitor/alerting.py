from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

import requests

LOGGER = logging.getLogger(__name__)


@dataclass
class TelegramNotifier:
    bot_token: str | None
    chat_id: str | None

    @property
    def enabled(self) -> bool:
        return bool(self.bot_token and self.chat_id)

    def send(self, message: str) -> bool:
        if not self.enabled:
            LOGGER.debug("Telegram notifier is not configured.")
            return False
        url = f"https://api.telegram.org/bot{self.bot_token}/sendMessage"
        try:
            response = requests.post(url, json={"chat_id": self.chat_id, "text": message}, timeout=10)
            response.raise_for_status()
            return True
        except requests.RequestException as exc:
            LOGGER.warning("Telegram alert failed: %s", exc)
            return False


def format_alert(alert: dict[str, Any]) -> str:
    return (
        f"[Network Behavior Monitor]\n"
        f"Severity: {alert.get('severity')}\n"
        f"Type: {alert.get('alert_type')}\n"
        f"Source: {alert.get('src_ip')}\n"
        f"Destination: {alert.get('dst_ip')}\n"
        f"Details: {alert.get('message')}"
    )
