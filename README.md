# 🔐 Evaluador de Madurez en Seguridad de la Información
### Basado en ISO/IEC 27001:2022 — Tesis: Modelo de Evaluación de Madurez en Seguridad de la Información

---

## 📋 Descripción

Aplicación Python que analiza **logs de servidores** y evalúa el **nivel de madurez en Seguridad de la Información** de una organización, basándose en los **93 controles de la ISO/IEC 27001:2022** y el modelo de madurez de 6 niveles (0–5).

El sistema detecta automáticamente incumplimientos de requisitos de seguridad a partir de los registros del servidor y clasifica a la empresa en uno de los siguientes niveles:

| Nivel | Nombre       | Descripción |
|-------|-------------|-------------|
| 0     | Inexistente  | Sin controles definidos |
| 1     | Inicial      | Actividades básicas informales |
| 2     | Gestionado   | Controles documentados, parcialmente implementados |
| 3     | Definido     | Procesos formalizados y aplicados |
| 4     | Medido       | Métricas, monitoreo y evaluación continua |
| 5     | Optimizado   | Mejora continua y automatización |

---

## 🏗️ Estructura del Proyecto

```
maturity_evaluator/
├── src/
│   ├── __init__.py
│   ├── log_parser.py          # Parseo de logs de servidor
│   ├── control_evaluator.py   # Evaluación de controles ISO 27001
│   ├── maturity_calculator.py # Cálculo del nivel de madurez
│   ├── report_generator.py    # Generación de reportes HTML/JSON
│   └── simulator.py           # Simulador de escenarios
├── logs_sample/
│   ├── access.log             # Ejemplo de log de acceso Apache/Nginx
│   ├── auth.log               # Ejemplo de log de autenticación
│   └── syslog.log             # Ejemplo de syslog
├── tests/
│   └── test_evaluator.py      # Pruebas unitarias
├── reports/                   # Reportes generados (gitignored)
├── main.py                    # Punto de entrada principal
├── requirements.txt
└── README.md
```

---

## ⚙️ Instalación

```bash
git clone https://github.com/tu-usuario/maturity_evaluator.git
cd maturity_evaluator
pip install -r requirements.txt
```

---

## 🚀 Uso

### Análisis de logs reales
```bash
python main.py --log /var/log/auth.log --type auth
python main.py --log /var/log/nginx/access.log --type access
python main.py --log /var/log/syslog --type syslog
```

### Analizar múltiples logs a la vez
```bash
python main.py --log /var/log/auth.log /var/log/syslog --type auth syslog
```

### Usar logs de muestra incluidos
```bash
python main.py --sample
```

### Modo simulador (genera escenarios de prueba)
```bash
python main.py --simulate --level 2   # Simula empresa en nivel 2
```

### Generar reporte HTML
```bash
python main.py --log /var/log/auth.log --type auth --report html
```

---

## 📊 Componentes Evaluados (ISO 27001:2022)

| Componente | Dominio | Controles |
|-----------|---------|-----------|
| Gestión Organizacional de Seguridad | A.5 | 37 |
| Gestión de Seguridad del Personal | A.6 | 8 |
| Gestión de Seguridad Física | A.7 | 14 |
| Gestión Tecnológica de Seguridad | A.8 | 34 |

---

## 🔍 Tipos de Log Soportados

- **access** — Logs de acceso HTTP (Apache / Nginx)
- **auth** — Logs de autenticación SSH / PAM (`/var/log/auth.log`)
- **syslog** — Logs del sistema (`/var/log/syslog`)
- **windows** — Event Logs exportados en formato texto
- **firewall** — Logs de firewall (iptables / UFW)

---

## 📈 Fórmula de Evaluación

El nivel de madurez por componente se calcula como:

```
NM = Σ(Ci) / N
```

Donde:
- `NM` = Nivel de Madurez del componente
- `Ci` = Valor asignado a cada control evaluado (0–5)
- `N`  = Total de controles evaluados en el componente

El nivel global es el promedio ponderado de los 4 componentes.

---

## 🧪 Tests

```bash
python -m pytest tests/ -v
```

---

## 📄 Licencia

MIT — Proyecto de tesis académica.
