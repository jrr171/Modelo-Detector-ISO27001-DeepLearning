# 🛡 Evaluador de Madurez en Seguridad de la Información — ISO/IEC 27001:2022

## Descripción

Herramienta de análisis de madurez en seguridad de la información basada en **ISO/IEC 27001:2022** y Deep Learning. Analiza logs del sistema operativo, red y aplicaciones para evaluar el nivel de cumplimiento de los **93 controles** de la norma, distribuidos en 4 cláusulas.

### Estructura ISO/IEC 27001:2022

| Cláusula | Tipo | Controles | Dominios evaluados |
|----------|------|-----------|-------------------|
| **5** | Organizacionales | 37 (5.1–5.37) | Políticas, activos, cloud (5.23), threat intel (5.7), incidentes (5.24–5.28) |
| **6** | Personas | 8 (6.1–6.8) | Formación (6.3), teletrabajo (6.7), reporte (6.8) |
| **7** | Físicos | 14 (7.1–7.14) | CCTV/monitoreo físico **NUEVO** (7.4), equipos, medios |
| **8** | Tecnológicos | 34 (8.1–8.34) | Endpoints (8.1), MFA (8.5), DLP **NUEVO** (8.12), monitoreo **NUEVO** (8.16), config **NUEVO** (8.9) |

### 11 Controles NUEVOS respecto a ISO 27001:2013

- 5.7 — Inteligencia de amenazas
- 5.23 — Seguridad en servicios cloud
- 5.30 — Preparación TIC para continuidad
- 7.4 — Monitoreo de seguridad física
- 8.9 — Gestión de la configuración
- 8.10 — Eliminación de información
- 8.11 — Enmascaramiento de datos
- 8.12 — Prevención de fuga de datos (DLP)
- 8.16 — Actividades de monitoreo
- 8.23 — Filtrado web
- 8.28 — Codificación segura

## Arquitectura

```
security-maturity-analyzer/
├── streamlit_app.py          # Interfaz web principal
├── main.py                   # CLI
├── rules/
│   └── iso27001_controls.py  # Dominios ISO 27001:2022 (6 dominios, 4 cláusulas)
├── analyzer/
│   ├── log_parser.py         # Parser multi-formato
│   ├── event_classifier.py   # Clasificador por dominio 2022
│   ├── maturity_scorer.py    # Scorer COBIT (0-5)
│   ├── report_generator.py   # Reportes HTML/JSON/PDF
│   └── action_plan.py        # Plan de acción por control 2022
├── ml/
│   ├── feature_extractor.py  # Features numéricas + TF-IDF (63 dims)
│   ├── autoencoder_model.py  # Autoencoder — detección de anomalías
│   ├── lstm_model.py         # LSTM Bidireccional — detección temporal
│   ├── maturity_classifier.py# MLP — clasificación de nivel (0-5)
│   └── dl_pipeline.py        # Orquestador de los 3 modelos DL
└── samples/
    ├── generate_samples.py   # Generador de logs simulados (ISO 27001:2022)
    ├── sample_auth.log       # Logs auth (Cl.8: MFA, acceso, privilegios)
    ├── sample_apache.log     # Logs web (Cl.8: apps, DLP, filtrado web)
    ├── sample_syslog.log     # Logs sistema (Cl.8: malware, vuln, config)
    ├── sample_windows_events.csv  # Eventos Windows (Cl.8: logging, monitoring)
    └── sample_physical_people.log # Físicos + personas (Cl.6 y Cl.7)
```

## Modelos de Deep Learning

| Modelo | Función | Arquitectura |
|--------|---------|-------------|
| **Autoencoder** | Detección de anomalías (umbral P95) | Encoder 63→32→16, Decoder 16→32→63 |
| **LSTM Bidireccional** | Detección de amenazas temporales | BiLSTM(64) + Dense(32) + Sigmoid |
| **MLP Clasificador** | Clasificación nivel madurez 0–5 | Dense(128→64→32) + Softmax(6) |

## Gráficos incluidos (9 visualizaciones)

1. 🔄 Medidor gauge de madurez global
2. 🕸 Radar de dominios ISO 27001:2022 (Cláusulas 5–8)
3. 📊 Barras: eventos de riesgo vs seguros por dominio
4. 📦 Barras apiladas: desglose de componentes de score
5. 🥧 Distribución de eventos por dominio (pie)
6. 🔥 Mapa de calor: tasa de riesgo por dominio
7. 🚦 Escala de madurez tipo semáforo
8. ☀️ Sunburst de eventos clasificados
9. 📈 Histograma de niveles por dominio

## Niveles de Madurez (COBIT)

| Nivel | Nombre | Rango |
|-------|--------|-------|
| 0 | Inexistente | 0% |
| 1 | Inicial / Ad Hoc | 1–20% |
| 2 | Repetible pero Intuitivo | 21–40% |
| 3 | Proceso Definido | 41–60% |
| 4 | Administrado y Medible | 61–80% |
| 5 | Optimizado | 81–100% |

## Instalación y Uso

```bash
pip install -r requirements.txt
streamlit run streamlit_app.py
```

**Referencias:** ISO/IEC 27001:2022 · COBIT 5 · IEC/ISO 27002:2022
