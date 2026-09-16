# Network Behavior Monitor

Modul open-source pentru monitorizarea și analiza comportamentală a traficului într-o rețea locală, dezvoltat în cadrul unei lucrări de licență.

Aplicația realizează un flux complet de monitorizare: captează metadatele traficului, le stochează în SQLite, construiește indicatori comportamentali pe ferestre temporale, aplică reguli explicabile de detecție și afișează rezultatele într-un dashboard Streamlit. Arhitectura include și suport opțional pentru Isolation Forest.

> **Scop:** laborator și cercetare academică. Testele de trafic trebuie efectuate numai în rețele izolate și asupra sistemelor pentru care există autorizație.

## Funcționalități

- captură de metadate ale pachetelor cu **Scapy**;
- stocare în **SQLite**;
- agregare pe ferestre temporale și feature engineering cu **Pandas/NumPy**;
- detecție bazată pe reguli explicabile:
  - `PORT_SCAN`;
  - `SYN_ANOMALY`;
  - `ICMP_SPIKE`;
  - `PACKET_RATE`;
  - `BYTE_RATE`;
  - `HOST_SCAN`;
- suport opțional pentru **Isolation Forest** prin `scikit-learn`;
- dashboard interactiv cu **Streamlit + Plotly**;
- notificări **Telegram** opționale;
- generator de date sintetice pentru demo, fără captură live și fără privilegii root.

## Arhitectură

```text
Trafic LAN
    │
    ▼
Scapy – captură metadate
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
 ┌───────────────┬────────────────────┐
 │ Reguli        │ Isolation Forest   │
 │ explicabile   │ opțional           │
 └───────────────┴────────────────────┘
    │
    ▼
SQLite / alerts
    │
    ├──────────────► Telegram (opțional)
    │
    ▼
Streamlit + Plotly
```

Dashboard-ul este componenta de vizualizare: citește datele din SQLite și nu înlocuiește modulele de captură sau detecție.

## Tehnologii

| Tehnologie | Rol în proiect |
|---|---|
| Python | limbajul principal |
| Scapy | captură și parsare a metadatelor de trafic |
| SQLite | stocarea pachetelor, features și alertelor |
| Pandas | agregare și prelucrare a datelor |
| NumPy | operații numerice |
| scikit-learn | Isolation Forest |
| joblib | salvarea/încărcarea modelului ML |
| Streamlit | dashboard |
| Plotly | grafice interactive |
| python-dotenv | configurare prin `.env` |
| requests | notificări Telegram |

## Structura proiectului

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

## Instalare

Pe Ubuntu/Debian:

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Pentru configurare:

```bash
cp .env.example .env
```

Fișierul `.env` este ignorat de Git și nu trebuie publicat.

## Demo fără captură live

Pentru a testa dashboard-ul fără acces root:

```bash
source .venv/bin/activate
python scripts/generate_demo_data.py --reset
streamlit run dashboard/app.py
```

Generatorul creează trafic sintetic și scenarii controlate, apoi populează SQLite și rulează detecția bazată pe reguli.

## Captură live în laborator

Identifică mai întâi interfața de rețea:

```bash
ip a
```

Apoi pornește captura. Exemplu:

```bash
source .venv/bin/activate
sudo .venv/bin/python run_capture.py --interface ens33 --filter "ip" --db data/traffic_monitor.db
```

`ens33` este doar un exemplu; folosește interfața disponibilă pe sistemul tău.

Într-un al doilea terminal pornește analyzer-ul:

```bash
source .venv/bin/activate
python3 run_analyzer.py --window 10 --interval 10 --db data/traffic_monitor.db
```

Într-un al treilea terminal:

```bash
source .venv/bin/activate
export PYTHONPATH=$PWD
streamlit run dashboard/app.py
```

## Detecție

În implementarea actuală, rezultatele experimentelor principale sunt generate prin reguli interpretabile.

Exemple:

- `PORT_SCAN` – număr mare de porturi destinație distincte;
- `SYN_ANOMALY` – raport SYN ridicat;
- `ICMP_SPIKE` – pondere ICMP ridicată;
- `PACKET_RATE` – rată mare de pachete;
- `BYTE_RATE` – volum mare de trafic;
- `HOST_SCAN` – număr mare de gazde destinație distincte.

Pragurile sunt configurabile prin `.env`.

## Isolation Forest

Proiectul include o componentă opțională de detecție bazată pe Isolation Forest. Modelul este antrenat pe vectorii de caracteristici din tabela `features`.

Antrenare:

```bash
python scripts/train_baseline.py --db data/traffic_monitor.db
```

Modelul este salvat în:

```text
models/isolation_forest.pkl
```

Fișierul modelului nu este inclus în repository; poate fi generat local după colectarea datelor.

> Isolation Forest este o extensie a arhitecturii și nu reprezintă mecanismul principal al rezultatelor experimentale prezentate în lucrare.

## Configurare

Exemple de variabile disponibile în `.env.example`:

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

Token-ul Telegram, dacă este folosit, trebuie păstrat numai în `.env`.

## Baza de date

SQLite conține trei categorii principale de date:

- `packets` – metadatele pachetelor capturate;
- `features` – indicatorii calculați pe ferestre temporale;
- `alerts` – evenimentele generate de detector.

Nu este necesară o bază de date externă pentru rularea locală.

## Limitări

- pragurile implicite sunt fixe și necesită calibrare pentru alte rețele;
- pot apărea false positive în cazul traficului legitim neobișnuit;
- experimentele din lucrare au fost realizate într-un mediu virtualizat;
- comportamentul real al unei rețele poate fi mai complex decât scenariile controlate;
- componenta ML necesită date de antrenare adecvate pentru mediul monitorizat;
- SQLite este potrivit pentru un prototip local, nu pentru un sistem distribuit de monitorizare la scară mare.

## Direcții viitoare

- calibrarea automată a pragurilor pe baza traficului de bază;
- reducerea și corelarea alertelor duplicate;
- evaluarea sistematică a Isolation Forest pe seturi de date mai variate;
- compararea regulilor cu metode ML;
- testare într-o rețea reală autorizată;
- extinderea dashboard-ului cu filtre și corelări mai avansate;
- posibilă migrare către o bază de date mai potrivită pentru volume mari.

## Mediu de laborator

Pentru reproducerea experimentelor este recomandată o rețea virtualizată izolată, de exemplu:

```text
Ubuntu Monitor  ←→  Kali Linux
```

Consultați `docs/SAFE_LAB.md` pentru recomandări privind izolarea mediului.

## Contribuție proprie

Contribuția proiectului constă în integrarea într-un singur flux modular a:

1. capturii de metadate;
2. agregării comportamentale;
3. regulilor explicabile de detecție;
4. stocării și auditării rezultatelor;
5. dashboard-ului de monitorizare;
6. alertării opționale;
7. unei extensii ML prin Isolation Forest.

Proiectul nu propune un algoritm nou de detecție; accentul este pus pe integrare, modularitate, explicabilitate și posibilitatea de extindere.

## Licență

Proiectul este distribuit sub licența MIT. Consultați fișierul `LICENSE`.

## Siguranță și utilizare responsabilă

Folosește instrumentele de captură și testare numai în rețele și sisteme pentru care ai permisiune explicită. Nu executa scanări sau trafic de test asupra unor sisteme externe, a rețelelor instituției sau a Internetului fără autorizare.
