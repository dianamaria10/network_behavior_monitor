# Demo rapid

## 1. Verificarea interfeței

```bash
ip a
```

Identifică interfața cu o adresă IPv4.

## 2. Captura

```bash
source .venv/bin/activate
sudo .venv/bin/python run_capture.py --interface <INTERFACE> --filter "ip" --db data/traffic_monitor.db
```

## 3. Analyzer

Într-un alt terminal:

```bash
source .venv/bin/activate
python3 run_analyzer.py --window 10 --interval 10 --db data/traffic_monitor.db
```

## 4. Dashboard

Într-un al treilea terminal:

```bash
source .venv/bin/activate
export PYTHONPATH=$PWD
streamlit run dashboard/app.py
```

## 5. Test ICMP controlat

Dintr-o a doua mașină din laborator:

```bash
ping -q -i 0.1 -c 100 <IP_MONITOR>
```

Analyzer-ul lucrează pe ferestre temporale, astfel încât alerta poate apărea după următoarea fereastră procesată.

## 6. Verificarea alertelor

```bash
sqlite3 data/traffic_monitor.db "SELECT severity, alert_type, src_ip, message FROM alerts ORDER BY id DESC LIMIT 5;"
```

Nu include în repository baze de date reale sau token-uri.
