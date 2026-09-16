# Arhitectura aplicației

## Flux principal

```text
Scapy
  ↓
packet_capture
  ↓
packets (SQLite)
  ↓
feature_extractor
  ↓
features (SQLite)
  ↓
detector
  ↓
alerts (SQLite)
  ↓
Streamlit dashboard
```

## Componente

### `packet_capture.py`
Capturează pachete cu Scapy și extrage metadate precum IP sursă/destinație, protocol, porturi, dimensiune și flag-uri TCP.

### `feature_extractor.py`
Agregă traficul pe ferestre temporale și surse, calculând indicatori precum rata de pachete, rata de bytes, porturile distincte, raportul SYN și raportul ICMP.

### `detector.py`
Conține detectorul bazat pe reguli și suportul opțional pentru Isolation Forest.

### `database.py`
Gestionează tabelele SQLite și operațiile de citire/scriere.

### `analyzer_loop.py`
Rulează periodic agregarea, detecția și notificarea.

### `dashboard/app.py`
Citește rezultatele din SQLite și le prezintă într-o interfață Streamlit cu metrici, grafice și tabele.

### `alerting.py`
Trimite notificări Telegram dacă sunt configurate `TELEGRAM_BOT_TOKEN` și `TELEGRAM_CHAT_ID`.
