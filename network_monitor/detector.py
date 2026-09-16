from __future__ import annotations

import argparse
import time
from pathlib import Path
from typing import Any

import joblib
import pandas as pd

try:
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    from sklearn.pipeline import Pipeline

    SKLEARN_AVAILABLE = True
except ImportError:
    IsolationForest = None
    StandardScaler = None
    Pipeline = None

    SKLEARN_AVAILABLE = False

from .config import Thresholds, get_config
from .database import fetch_dataframe, insert_alert


FEATURE_COLUMNS = [
    "total_packets",
    "total_bytes",
    "avg_packet_size",
    "tcp_count",
    "udp_count",
    "icmp_count",
    "syn_count",
    "ack_count",
    "unique_dst_ports",
    "unique_dst_ips",
    "packets_per_second",
    "bytes_per_second",
    "syn_ratio",
    "udp_ratio",
    "icmp_ratio",
    "mean_iat",
]


class RuleBasedDetector:
    def __init__(self, thresholds: Thresholds | None = None) -> None:
        self.thresholds = thresholds or Thresholds()

    def evaluate(self, row: dict[str, Any]) -> list[dict[str, Any]]:
        alerts: list[dict[str, Any]] = []

        total_packets = int(row.get("total_packets", 0) or 0)

        if total_packets < self.thresholds.min_packets_for_rule:
            return alerts

        src_ip = row.get("src_ip")
        dst_ip = row.get("dst_ip")
        feature_id = row.get("feature_id") or row.get("id")

        def add(
            severity: str,
            alert_type: str,
            message: str,
            score: float | None = None,
        ) -> None:
            alerts.append(
                {
                    "ts": time.time(),
                    "severity": severity,
                    "alert_type": alert_type,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "message": message,
                    "anomaly_score": score,
                    "feature_id": feature_id,
                }
            )

        if float(row.get("packets_per_second", 0)) > self.thresholds.max_packets_per_second:
            add(
                "HIGH",
                "PACKET_RATE",
                f"High packet rate from {src_ip}: "
                f"{row.get('packets_per_second'):.2f} packets/s",
            )

        if float(row.get("bytes_per_second", 0)) > self.thresholds.max_bytes_per_second:
            add(
                "MEDIUM",
                "BYTE_RATE",
                f"High traffic volume from {src_ip}: "
                f"{row.get('bytes_per_second'):.2f} bytes/s",
            )

        if int(row.get("unique_dst_ports", 0)) > self.thresholds.max_unique_dst_ports:
            add(
                "HIGH",
                "PORT_SCAN",
                f"Possible port scan from {src_ip}: "
                f"{row.get('unique_dst_ports')} destination ports",
            )

        if int(row.get("unique_dst_ips", 0)) > self.thresholds.max_unique_dst_ips:
            add(
                "MEDIUM",
                "HOST_SCAN",
                f"Possible host scan from {src_ip}: "
                f"{row.get('unique_dst_ips')} destination hosts",
            )

        if float(row.get("syn_ratio", 0)) > self.thresholds.max_syn_ratio:
            add(
                "HIGH",
                "SYN_ANOMALY",
                f"High SYN ratio from {src_ip}: "
                f"{row.get('syn_ratio'):.2f}",
            )

        if float(row.get("icmp_ratio", 0)) > self.thresholds.max_icmp_ratio:
            add(
                "MEDIUM",
                "ICMP_SPIKE",
                f"High ICMP ratio from {src_ip}: "
                f"{row.get('icmp_ratio'):.2f}",
            )

        return alerts


class IsolationForestDetector:
    def __init__(
        self,
        model_path: str | Path,
        contamination: float = 0.08,
        random_state: int = 42,
    ) -> None:
        self.model_path = Path(model_path)
        self.contamination = contamination
        self.random_state = random_state
        self.pipeline: Any = None

    def fit(self, features: pd.DataFrame) -> None:
        if not SKLEARN_AVAILABLE:
            raise RuntimeError(
                "scikit-learn is not available on this system. "
                "Isolation Forest cannot be trained."
            )

        missing = [
            col for col in FEATURE_COLUMNS
            if col not in features.columns
        ]

        if missing:
            raise ValueError(f"Missing feature columns: {missing}")

        x = features[FEATURE_COLUMNS].fillna(0)

        self.pipeline = Pipeline(
            steps=[
                ("scaler", StandardScaler()),
                (
                    "model",
                    IsolationForest(
                        n_estimators=150,
                        contamination=self.contamination,
                        random_state=self.random_state,
                    ),
                ),
            ]
        )

        self.pipeline.fit(x)

        self.model_path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self.pipeline, self.model_path)

    def load(self) -> bool:
        if not SKLEARN_AVAILABLE:
            return False

        if not self.model_path.exists():
            return False

        self.pipeline = joblib.load(self.model_path)
        return True

    def predict(self, features: pd.DataFrame) -> pd.DataFrame:
        if self.pipeline is None and not self.load():
            raise FileNotFoundError(
                f"Model not found: {self.model_path}. "
                "Train it first or use rule-based mode."
            )

        assert self.pipeline is not None

        x = features[FEATURE_COLUMNS].fillna(0)

        prediction = self.pipeline.predict(x)
        decision = self.pipeline.decision_function(x)

        result = features.copy()
        result["is_anomaly_ml"] = prediction == -1
        result["anomaly_score"] = -decision

        return result


def evaluate_recent_features(
    db_path: str | Path,
    model_path: str | Path | None = None,
    use_ml: bool = True,
) -> list[dict[str, Any]]:
    cfg = get_config()
    model_path = model_path or cfg.model_path

    features = fetch_dataframe(
        db_path,
        "SELECT * FROM features ORDER BY id DESC LIMIT 100",
    )

    if features.empty:
        return []

    rule_detector = RuleBasedDetector(cfg.thresholds)
    alerts: list[dict[str, Any]] = []

    if (
        use_ml
        and SKLEARN_AVAILABLE
        and Path(model_path).exists()
    ):
        ml_detector = IsolationForestDetector(model_path)
        scored = ml_detector.predict(features)

        for row in scored.to_dict(orient="records"):
            if bool(row.get("is_anomaly_ml")):
                alerts.append(
                    {
                        "ts": time.time(),
                        "severity": "MEDIUM",
                        "alert_type": "ML_ANOMALY",
                        "src_ip": row.get("src_ip"),
                        "dst_ip": row.get("dst_ip"),
                        "message": (
                            "Isolation Forest anomaly detected "
                            f"for {row.get('src_ip')}"
                        ),
                        "anomaly_score": float(
                            row.get("anomaly_score", 0)
                        ),
                        "feature_id": int(row.get("id")),
                    }
                )

    for row in features.to_dict(orient="records"):
        alerts.extend(rule_detector.evaluate(row))

    inserted = []

    for alert in alerts:
        alert_id = insert_alert(db_path, alert)
        alert["id"] = alert_id
        inserted.append(alert)

    return inserted


def train_from_database(
    db_path: str | Path,
    model_path: str | Path,
    limit: int = 2000,
) -> None:
    if not SKLEARN_AVAILABLE:
        raise RuntimeError(
            "scikit-learn is not available on this system. "
            "Isolation Forest cannot be trained."
        )

    features = fetch_dataframe(
        db_path,
        f"SELECT * FROM features ORDER BY id DESC LIMIT {int(limit)}",
    )

    if features.empty:
        raise ValueError(
            "No feature rows found. Capture/aggregate traffic first "
            "or generate demo data."
        )

    detector = IsolationForestDetector(model_path)
    detector.fit(features)


def main() -> None:
    cfg = get_config()

    parser = argparse.ArgumentParser(
        description="Train or run anomaly detection."
    )

    parser.add_argument("--db", default=str(cfg.db_path))
    parser.add_argument("--model", default=str(cfg.model_path))

    parser.add_argument(
        "--train",
        action="store_true",
        help="Train Isolation Forest from stored feature rows",
    )

    parser.add_argument(
        "--detect",
        action="store_true",
        help="Evaluate recent feature rows and insert alerts",
    )

    parser.add_argument(
        "--no-ml",
        action="store_true",
        help="Use only rule-based detection",
    )

    args = parser.parse_args()

    if args.train:
        train_from_database(args.db, args.model)
        print(f"Model saved to {args.model}")

    if args.detect:
        alerts = evaluate_recent_features(
            args.db,
            args.model,
            use_ml=not args.no_ml,
        )
        print(f"Inserted {len(alerts)} alerts")


if __name__ == "__main__":
    main()