# Mapare pe cerințele lucrării

| Cerință | Implementare în proiect |
|---|---|
| Captare trafic LAN | `network_monitor/packet_capture.py` cu Scapy |
| Grupare după pattern-uri comportamentale | `feature_extractor.py`, agregare pe fereastră de timp și IP sursă |
| Vizualizare top IP-uri/protocoale/surse suspecte | `dashboard/app.py` |
| Alertare și logare | `detector.py`, `database.py`, `alerting.py` |
| Profil normal | `scripts/train_baseline.py` + Isolation Forest |
| Open-source educațional | README, structură modulară, configurare `.env` |

## Metrici care pot fi raportate în licență

- număr de pachete analizate;
- număr de vectori de caracteristici generați;
- număr de alerte pe scenariu;
- timp mediu de detecție pe fereastră;
- număr de false positives în trafic normal;
- consum CPU/memorie observat în VM.

## Componente construite

1. Modul captură: extrage doar metadate, fără payload.
2. Modul feature engineering: transformă pachetele în vectori comportamentali.
3. Modul detecție: reguli + Isolation Forest.
4. Modul logare: SQLite.
5. Modul dashboard: Streamlit + Plotly.
6. Modul alertare: Telegram opțional.
