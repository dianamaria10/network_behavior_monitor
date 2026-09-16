# Network Behavior Monitor

Open-source module for monitoring and behavioral analysis of network traffic in a local network, developed as part of a bachelor's thesis.

The application implements a complete monitoring workflow: it captures traffic metadata, stores it in SQLite, builds behavioral indicators over time windows, applies explainable detection rules, and displays the results in a Streamlit dashboard. The architecture also includes optional support for Isolation Forest.

> **Purpose:** laboratory and academic research. Traffic tests must be performed only in isolated networks and on systems for which authorization has been obtained.

## Features

- packet metadata capture with **Scapy**;
- storage in **SQLite**;
- time-window aggregation and feature engineering with **Pandas/NumPy**;
- explainable rule-based detection:
  - `PORT_SCAN`;
  - `SYN_ANOMALY`;
  - `ICMP_SPIKE`;
  - `PACKET_RATE`;
  - `BYTE_RATE`;
  - `HOST_SCAN`;
- optional **Isolation Forest** support through `scikit-learn`;
- interactive dashboard with **Streamlit + Plotly**;
- optional **Telegram** notifications;
- synthetic data generator for demonstrations, without live capture and without root privileges.

## Architecture

```text
LAN Traffic
    │
    ▼
Scapy – metadata capture
    │
    ▼
SQLite / packets
    │
    ▼
Feature extraction
(Pandas + NumPy)
    │
    ▼
SQLite / features
    │
    ▼
Detector
 ┌───────────────────┬────────────────────┐
 │ Explainable rules │ Isolation Forest   │
 │                   │ optional           │
 └───────────────────┴────────────────────┘
    │
    ▼
SQLite / alerts
    │
    ├──────────────► Telegram (optional)
    │
    ▼
Streamlit + Plotly
```

The dashboard is the visualization component: it reads data from SQLite and does not replace the capture or detection modules.

## Technologies

| Technology | Role in the project |
|---|---|
| Python | main programming language |
| Scapy | traffic metadata capture and parsing |
| SQLite | storage for packets, features, and alerts |
| Pandas | data aggregation and processing |
| NumPy | numerical operations |
| scikit-learn | Isolation Forest |
| joblib | saving/loading the ML model |
| Streamlit | dashboard |
| Plotly | interactive charts |
| python-dotenv | `.env` configuration |
| requests | Telegram notifications |

## Project Structure

```text
network_behavior_monitor/
├── network_monitor/
│   ├── config.py
│   ├── database.py
│   ├── packet_capture.py
│   ├── feature_extractor.py
│   ├── detector.py
│   ├── alerting.py
│   └── analyzer_loop.py
├── dashboard/
│   └── app.py
├── scripts/
│   ├── generate_demo_data.py
│   └── train_baseline.py
├── docs/
│   ├── SAFE_LAB.md
│   ├── THESIS_MAPPING.md
│   └── CAPITOL_4_SNIPPETS.tex
├── tests/
├── data/
├── models/
├── run_capture.py
├── run_analyzer.py
├── requirements.txt
├── .env.example
├── .gitignore
├── LICENSE
└── README.md
```

## Installation

On Ubuntu/Debian:

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

For configuration:

```bash
cp .env.example .env
```

The `.env` file is ignored by Git and must not be published.

## Demo Without Live Capture

To test the dashboard without root access:

```bash
source .venv/bin/activate
python scripts/generate_demo_data.py --reset
streamlit run dashboard/app.py
```

The generator creates synthetic traffic and controlled scenarios, then populates SQLite and runs rule-based detection.

## Live Capture in a Laboratory

First identify the network interface:

```bash
ip a
```

Then start the capture. Example:

```bash
source .venv/bin/activate
sudo .venv/bin/python run_capture.py --interface ens33 --filter "ip" --db data/traffic_monitor.db
```

`ens33` is only an example; use the interface available on your system.

In a second terminal, start the analyzer:

```bash
source .venv/bin/activate
python3 run_analyzer.py --window 10 --interval 10 --db data/traffic_monitor.db
```

In a third terminal:

```bash
source .venv/bin/activate
export PYTHONPATH=$PWD
streamlit run dashboard/app.py
```

## Detection

In the current implementation, the main experimental results are generated using explainable rules.

Examples:

- `PORT_SCAN` – large number of distinct destination ports;
- `SYN_ANOMALY` – high SYN ratio;
- `ICMP_SPIKE` – high ICMP proportion;
- `PACKET_RATE` – high packet rate;
- `BYTE_RATE` – high traffic volume;
- `HOST_SCAN` – large number of distinct destination hosts.

Thresholds are configurable through `.env`.

## Isolation Forest

The project includes an optional Isolation Forest-based detection component. The model is trained on feature vectors stored in the `features` table.

Training:

```bash
python scripts/train_baseline.py --db data/traffic_monitor.db
```

The model is saved to:

```text
models/isolation_forest.pkl
```

The model file is not included in the repository; it can be generated locally after collecting data.

> Isolation Forest is an extension of the architecture and is not the main mechanism behind the experimental results presented in the thesis.

## Configuration

Examples of variables available in `.env.example`:

```text
NBM_DB_PATH
NBM_MODEL_PATH
NBM_WINDOW_SECONDS
NBM_ANALYZER_INTERVAL_SECONDS
NBM_SCAPY_FILTER
NBM_INTERFACE
NBM_MAX_PACKETS_PER_SECOND
NBM_MAX_BYTES_PER_SECOND
NBM_MAX_UNIQUE_DST_PORTS
NBM_MAX_SYN_RATIO
NBM_MAX_ICMP_RATIO
NBM_MAX_UNIQUE_DST_IPS
TELEGRAM_BOT_TOKEN
TELEGRAM_CHAT_ID
```

The Telegram token, if used, must be kept only in `.env`.

## Database

SQLite contains three main categories of data:

- `packets` – metadata of captured packets;
- `features` – indicators calculated over time windows;
- `alerts` – events generated by the detector.

No external database is required for local execution.

## Limitations

- default thresholds are fixed and require calibration for other networks;
- false positives may occur in the case of unusual legitimate traffic;
- the experiments in the thesis were performed in a virtualized environment;
- real network behavior can be more complex than the controlled scenarios;
- the ML component requires suitable training data for the monitored environment;
- SQLite is suitable for a local prototype, not for a large-scale distributed monitoring system.

## Future Directions

- automatic threshold calibration based on baseline traffic;
- reduction and correlation of duplicate alerts;
- systematic evaluation of Isolation Forest on more diverse datasets;
- comparison of rule-based detection with ML methods;
- testing in a real authorized network;
- extending the dashboard with more advanced filters and correlations;
- possible migration to a database better suited for large data volumes.

## Laboratory Environment

For reproducing the experiments, an isolated virtualized network is recommended, for example:

```text
Ubuntu Monitor  ←→  Kali Linux
```

See `docs/SAFE_LAB.md` for recommendations on isolating the environment.

## Own Contribution

The project contribution consists of integrating the following components into a single modular workflow:

1. metadata capture;
2. behavioral aggregation;
3. explainable detection rules;
4. result storage and auditing;
5. monitoring dashboard;
6. optional alerting;
7. an ML extension through Isolation Forest.

The project does not propose a new detection algorithm; the emphasis is on integration, modularity, explainability, and extensibility.

## License

The project is distributed under the MIT License. See the `LICENSE` file.

## Safety and Responsible Use

Use packet capture and testing tools only on networks and systems for which you have explicit permission. Do not perform scans or generate test traffic against external systems, institutional networks, or the Internet without authorization.
