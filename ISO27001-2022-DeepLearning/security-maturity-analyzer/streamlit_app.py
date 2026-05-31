"""
Streamlit Web App — Evaluador de Madurez en Seguridad de la Información
ISO/IEC 27001:2022 · Deep Learning · Rediseño Editorial Brutalista-Retro-Futurista

NUEVO DISEÑO: Estética brutalista-editorial-lujo
- Tipografía: DM Serif Display (títulos) + Syne (datos/UI) + JetBrains Mono (código/métricas)
- Paleta: Negro carbón (#0A0A0A) + Marfil (#F5F0E8) + Dorado (#C9A84C) + Carmesí (#8B1A1A)
- Composición: Grid asimétrico, bordes brutales, números monumentales
- Sin gradientes púrpura, sin Inter, sin layouts predecibles
"""

import sys, io, json, tempfile, os, math
from pathlib import Path

import streamlit as st
import plotly.graph_objects as go
import plotly.express as px
import pandas as pd

ROOT = Path(__file__).parent
sys.path.insert(0, str(ROOT))

from analyzer.log_parser       import LogParser
from analyzer.event_classifier import EventClassifier
from analyzer.maturity_scorer  import MaturityScorer, compute_gap_analysis, GapAnalysis
from analyzer.report_generator import export_html, export_json
from rules.iso27001_controls   import MATURITY_LEVELS, ISO27001_DOMAINS

# ────────────────────────────────────────────────────────────────────────────
# PALETA EDITORIAL-BRUTALISTA (nueva)
# ────────────────────────────────────────────────────────────────────────────
C = {
    "primary":   "#C9A84C",   # dorado editorial
    "secondary": "#1C1A17",   # pizarra oscura
    "success":   "#3B6D11",   # verde bosque
    "warning":   "#BA7517",   # ámbar cálido
    "danger":    "#A32D2D",   # rojo carmesí
    "bg":        "#F7F4EF",   # marfil fondo
    "surface":   "#fff",      # superficie tarjeta
    "ivory":     "#1C1A17",   # texto principal
    "level": {
        0: "#791F1F", 1: "#A32D2D", 2: "#BA7517",
        3: "#854F0B", 4: "#3B6D11", 5: "#0F6E56",
    },
    "domains": [
        "#C9A84C","#A32D2D","#3B6D11","#185FA5","#6B4F8B","#0F6E56",
    ],
}

def level_color(lvl): return C["level"].get(lvl, "#555")
LEVEL_COLORS = C["level"]

def score_color(s):
    if s >= 81: return C["level"][5]
    if s >= 61: return C["level"][4]
    if s >= 41: return C["level"][3]
    if s >= 21: return C["level"][2]
    if s >  0:  return C["level"][1]
    return C["level"][0]

def hex_rgba(hex_color: str, alpha: float = 1.0) -> str:
    h = hex_color.lstrip("#")
    r, g, b = int(h[0:2],16), int(h[2:4],16), int(h[4:6],16)
    return f"rgba({r},{g},{b},{alpha})"


# Plotly con tema claro editorial
PLOTLY_FONT = dict(family="'Syne', 'JetBrains Mono', sans-serif", size=11, color="#1C1A17")

def apply_editorial_theme(fig):
    """Aplica tema editorial claro (marfil) a gráficos Plotly."""
    fig.update_layout(
        paper_bgcolor="#FFFFFF",
        plot_bgcolor="#FFFFFF",
        font=PLOTLY_FONT,
    )
    chart_types = {type(t).__name__ for t in fig.data}
    cartesian = chart_types - {"Indicator","Pie","Sunburst","Scatterpolar","Barpolar"}
    if cartesian:
        try:
            fig.update_xaxes(
                tickfont=dict(color="#9A9790", size=10, family="'JetBrains Mono', monospace"),
                title_font=dict(color="#7A776F"),
                gridcolor="#EDE9E2",
                linecolor="#D8D3CA",
                zerolinecolor="#D8D3CA",
            )
            fig.update_yaxes(
                tickfont=dict(color="#9A9790", size=10, family="'JetBrains Mono', monospace"),
                title_font=dict(color="#7A776F"),
                gridcolor="#EDE9E2",
                linecolor="#D8D3CA",
                zerolinecolor="#D8D3CA",
            )
        except Exception:
            pass
    return fig


# ────────────────────────────────────────────────────────────────────────────
# PAGE CONFIG
# ────────────────────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="ISO 27001:2022 · Evaluador de Madurez",
    page_icon="◆",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ════════════════════════════════════════════════════════════════════════════
# CSS EDITORIAL-BRUTALISTA · PALETA MARFIL-PIZARRA-DORADO (sin sidebar)
# ════════════════════════════════════════════════════════════════════════════
st.markdown("""
<style>
  /* ── TIPOGRAFÍA EDITORIAL ── */
  @import url('https://fonts.googleapis.com/css2?family=DM+Serif+Display:ital@0;1&family=Syne:wght@400;500;600;700;800&family=JetBrains+Mono:wght@300;400;500&display=swap');

  /* ── RESET GLOBAL ── */
  html, body, [class*="css"] {
    font-family: 'Syne', sans-serif !important;
    background-color: #F7F4EF !important;
    color: #1C1A17 !important;
  }

  /* ── FONDO APP ── */
  .stApp {
    background: #F7F4EF !important;
  }

  /* ── OCULTAR SIDEBAR COMPLETAMENTE ── */
  [data-testid="stSidebar"] { display: none !important; }
  [data-testid="collapsedControl"] { display: none !important; }

  /* ── MAIN CONTENT FULL WIDTH ── */
  .main .block-container {
    max-width: 1400px;
    padding: 0 !important;
  }

  /* ── ENCABEZADO MONUMENTAL ── */
  .masthead {
    border-bottom: 3px solid #C9A84C;
    padding: 3rem 3rem 2.5rem 3rem;
    margin-bottom: 0;
    position: relative;
    overflow: hidden;
    background: #1C1A17;
  }
  .masthead::before {
    content: 'ISO 27001';
    position: absolute;
    right: -20px;
    top: 50%;
    transform: translateY(-50%);
    font-family: 'DM Serif Display', serif;
    font-size: 10rem;
    color: rgba(201,168,76,0.05);
    letter-spacing: -4px;
    pointer-events: none;
    white-space: nowrap;
  }
  .eyebrow {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.65rem;
    letter-spacing: 0.3em;
    text-transform: uppercase;
    color: #C9A84C !important;
    margin-bottom: 0.75rem;
  }
  .main-title {
    font-family: 'DM Serif Display', serif !important;
    font-size: 3.2rem !important;
    font-weight: 400 !important;
    color: #F7F4EF !important;
    line-height: 1.05 !important;
    letter-spacing: -1px !important;
    margin: 0 !important;
  }
  .main-title em {
    font-style: italic;
    color: #C9A84C;
  }
  .subtitle {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.72rem;
    color: #4A4740 !important;
    letter-spacing: 0.1em;
    margin-top: 1rem;
    text-transform: uppercase;
  }

  /* ── BANDA INFO (Anexo A + COBIT) ── */
  .info-band {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 1px;
    background: #D8D3CA;
    border-bottom: 1px solid #D8D3CA;
    margin-bottom: 0;
  }
  .info-half {
    background: #EDE9E2;
    padding: 1.25rem 3rem;
  }
  .info-label {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.58rem;
    letter-spacing: 0.28em;
    text-transform: uppercase;
    color: #9A9790;
    margin-bottom: 0.75rem;
  }
  .anexo-grid {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 6px;
  }
  .anexo-chip {
    background: #F7F4EF;
    border: 1px solid #D8D3CA;
    border-left: 2px solid;
    padding: 0.55rem 0.75rem;
  }
  .anexo-chip-label {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.7rem;
    letter-spacing: 0.08em;
    font-weight: 500;
    margin-bottom: 2px;
  }
  .anexo-chip-sub {
    font-family: 'Syne', sans-serif;
    font-size: 0.75rem;
    color: #7A776F;
  }
  .cobit-grid {
    display: grid;
    grid-template-columns: repeat(6, 1fr);
    gap: 4px;
  }
  .cobit-chip {
    padding: 0.5rem 0.6rem;
    border-left: 2px solid;
  }
  .cobit-num {
    font-family: 'DM Serif Display', serif;
    font-size: 1.15rem;
    font-weight: 400;
    line-height: 1;
  }
  .cobit-name {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.56rem;
    letter-spacing: 0.05em;
    color: #9A9790;
    margin-top: 2px;
  }
  .cobit-range {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.54rem;
    color: #C0BDB7;
    margin-top: 1px;
  }

  /* ── CONTENT WRAPPER ── */
  .content-wrap {
    padding: 2rem 3rem;
  }

  /* ── SECCIÓN HEADERS TIPO PERIÓDICO ── */
  .section-rule {
    display: flex;
    align-items: baseline;
    gap: 1rem;
    margin: 2.5rem 0 1.25rem 0;
    border-bottom: 1px solid #D8D3CA;
    padding-bottom: 0.75rem;
  }
  .section-num {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.65rem;
    color: #C9A84C;
    letter-spacing: 0.2em;
  }
  .section-hdr {
    font-family: 'DM Serif Display', serif !important;
    font-size: 1.4rem !important;
    font-weight: 400 !important;
    color: #1C1A17 !important;
    letter-spacing: -0.3px !important;
    margin: 0 !important;
    border: none !important;
    padding: 0 !important;
  }

  /* ── KPI CARDS BRUTALISTAS ── */
  .kpi-grid {
    display: grid;
    grid-template-columns: repeat(6, 1fr);
    gap: 1px;
    background: #D8D3CA;
    border: 1px solid #D8D3CA;
    margin: 1.5rem 0;
  }
  .kpi-card {
    background: #fff !important;
    padding: 1.5rem 1rem !important;
    text-align: left !important;
    border: none !important;
    border-radius: 0 !important;
    position: relative;
    transition: background 0.15s;
  }
  .kpi-card:hover {
    background: #F7F4EF !important;
  }
  .kpi-val {
    font-family: 'DM Serif Display', serif !important;
    font-size: 2.2rem !important;
    font-weight: 400 !important;
    line-height: 1 !important;
    margin-bottom: 0.4rem !important;
    display: block;
  }
  .kpi-lbl {
    font-family: 'JetBrains Mono', monospace !important;
    font-size: 0.6rem !important;
    letter-spacing: 0.2em !important;
    text-transform: uppercase !important;
    color: #9A9790 !important;
  }

  /* ── CHART BOX ── */
  .chart-box {
    background: #fff;
    border: 1px solid #D8D3CA;
    padding: 1.5rem;
    margin-bottom: 1px;
  }
  .chart-title {
    font-family: 'DM Serif Display', serif;
    font-size: 1.05rem;
    color: #1C1A17;
    margin-bottom: 0.25rem;
  }
  .chart-sub {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.62rem;
    letter-spacing: 0.15em;
    color: #9A9790;
    text-transform: uppercase;
    margin-bottom: 1rem;
  }

  /* ── FINDING/REC CARDS ── */
  .finding {
    background: #FCEBEB !important;
    border-left: 2px solid #A32D2D !important;
    border-radius: 0 !important;
    padding: 0.75rem 1rem !important;
    margin-bottom: 4px !important;
    font-family: 'Syne', sans-serif !important;
    font-size: 0.85rem !important;
    color: #1C1A17 !important;
  }
  .rec {
    background: #EAF3DE !important;
    border-left: 2px solid #3B6D11 !important;
    border-radius: 0 !important;
    padding: 0.75rem 1rem !important;
    margin-bottom: 4px !important;
    font-family: 'Syne', sans-serif !important;
    font-size: 0.85rem !important;
    color: #1C1A17 !important;
  }

  /* ── ALERT BOXES ── */
  .alert-critical {
    background: #FCEBEB;
    border: 1px solid #F09595;
    border-left: 3px solid #A32D2D;
    padding: 1.25rem 1.5rem;
    margin-bottom: 1.5rem;
  }
  .alert-ok {
    background: #EAF3DE;
    border: 1px solid #C0DD97;
    border-left: 3px solid #3B6D11;
    padding: 1.25rem 1.5rem;
    margin-bottom: 1.5rem;
  }
  .alert-title {
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.65rem;
    letter-spacing: 0.2em;
    text-transform: uppercase;
    margin-bottom: 0.5rem;
  }
  .alert-body {
    font-family: 'Syne', sans-serif;
    font-size: 0.9rem;
    color: #4A4740;
    line-height: 1.6;
  }

  /* ── NIVEL BADGE ── */
  .nivel-badge {
    display: inline-block;
    font-family: 'JetBrains Mono', monospace;
    font-size: 0.62rem;
    letter-spacing: 0.2em;
    text-transform: uppercase;
    padding: 3px 8px;
    border: 1px solid currentColor;
    margin-right: 4px;
  }

  /* ── TABS ── */
  /* ── TABS ── */
  [data-testid="stTabs"] [role="tab"] {
    font-family: 'JetBrains Mono', monospace !important;
    font-size: 0.68rem !important;
    letter-spacing: 0.15em !important;
    text-transform: uppercase !important;
    color: #9A9790 !important;
    border-bottom: 1px solid #D8D3CA !important;
    padding: 0.75rem 1.5rem !important;
    background: transparent !important;
  }
  [data-testid="stTabs"] [role="tab"][aria-selected="true"] {
    color: #1C1A17 !important;
    border-bottom-color: #C9A84C !important;
  }
  [data-testid="stTabs"] [role="tablist"] {
    border-bottom: 1px solid #D8D3CA !important;
    gap: 0 !important;
    background: #EDE9E2 !important;
    padding: 0 2rem !important;
  }

  /* ── INPUTS ── */
  [data-testid="stFileUploader"] {
    border: 1px dashed #C8C3BB !important;
    border-radius: 0 !important;
    background: #F7F4EF !important;
    padding: 1rem !important;
  }
  [data-testid="stTextArea"] textarea {
    background: #F7F4EF !important;
    border: 1px solid #D8D3CA !important;
    border-radius: 0 !important;
    color: #1C1A17 !important;
    font-family: 'JetBrains Mono', monospace !important;
    font-size: 0.8rem !important;
  }

  /* ── BUTTONS ── */
  .stButton button {
    background: #C9A84C !important;
    color: #1C1A17 !important;
    border: none !important;
    border-radius: 0 !important;
    font-family: 'JetBrains Mono', monospace !important;
    font-size: 0.65rem !important;
    letter-spacing: 0.2em !important;
    text-transform: uppercase !important;
    padding: 0.75rem 1.5rem !important;
    font-weight: 500 !important;
    transition: all 0.15s !important;
  }
  .stButton button:hover {
    background: #B8973B !important;
  }
  .stDownloadButton button {
    background: transparent !important;
    color: #854F0B !important;
    border: 1px solid #C9A84C !important;
    border-radius: 0 !important;
    font-family: 'JetBrains Mono', monospace !important;
    font-size: 0.65rem !important;
    letter-spacing: 0.2em !important;
    text-transform: uppercase !important;
  }
  .stDownloadButton button:hover { background: #FAEEDA !important; }

  /* ── SLIDERS ── */
  [data-testid="stSlider"] label {
    font-family: 'JetBrains Mono', monospace !important;
    font-size: 0.65rem !important;
    letter-spacing: 0.15em !important;
    text-transform: uppercase !important;
    color: #7A776F !important;
  }

  /* ── DATAFRAME ── */
  [data-testid="stDataFrame"] { border: 1px solid #D8D3CA !important; border-radius: 0 !important; }

  /* ── EXPANDERS ── */
  [data-testid="stExpander"] {
    border: 1px solid #D8D3CA !important;
    border-radius: 0 !important;
    background: #F7F4EF !important;
    margin-bottom: 1px !important;
  }
  [data-testid="stExpander"] summary {
    font-family: 'JetBrains Mono', monospace !important;
    font-size: 0.72rem !important;
    letter-spacing: 0.1em !important;
    color: #4A4740 !important;
    padding: 0.75rem 1rem !important;
    background: #F7F4EF !important;
  }

  /* ── METRICS ── */
  [data-testid="stMetric"] { background: #F7F4EF !important; border: 1px solid #D8D3CA !important; padding: 1rem !important; }
  [data-testid="stMetric"] label {
    font-family: 'JetBrains Mono', monospace !important;
    font-size: 0.62rem !important; letter-spacing: 0.15em !important;
    text-transform: uppercase !important; color: #9A9790 !important;
  }
  [data-testid="stMetricValue"] { font-family: 'DM Serif Display', serif !important; font-size: 1.6rem !important; color: #1C1A17 !important; }

  /* ── DIVIDER ── */
  hr { border: none !important; border-top: 1px solid #D8D3CA !important; margin: 2rem 0 !important; }

  /* ── SPINNER ── */
  [data-testid="stSpinner"] p { font-family: 'JetBrains Mono', monospace !important; font-size: 0.72rem !important; letter-spacing: 0.15em !important; color: #854F0B !important; }

  /* ── ALERTS ── */
  [data-testid="stAlert"] { border-radius: 0 !important; border-left-width: 2px !important; }
  [data-testid="stAlert"] p { font-family: 'Syne', sans-serif !important; font-size: 0.88rem !important; }

  /* ── CAPTION ── */
  [data-testid="stCaption"], .stCaption { font-family: 'JetBrains Mono', monospace !important; font-size: 0.62rem !important; letter-spacing: 0.1em !important; color: #9A9790 !important; }

  /* ── PROGRESS ── */
  [data-testid="stProgress"] { background: #EDE9E2 !important; border-radius: 0 !important; }
  [data-testid="stProgress"] > div { background: #C9A84C !important; border-radius: 0 !important; }

  /* ── FOOTER ── */
  footer { font-family: 'JetBrains Mono', monospace !important; font-size: 0.6rem !important; letter-spacing: 0.15em !important; color: #C0BDB7 !important; text-align: center !important; margin-top: 4rem !important; padding-top: 1.5rem !important; border-top: 1px solid #D8D3CA !important; text-transform: uppercase !important; }

</style>
""", unsafe_allow_html=True)


# ────────────────────────────────────────────────────────────────────────────
# MASTHEAD + BANDA INFO (sin sidebar — todo full width)
# ────────────────────────────────────────────────────────────────────────────
st.markdown("""
<div class="masthead">
  <div class="eyebrow">Evaluador de Madurez · Seguridad de la Información</div>
  <div class="main-title">Análisis de <em>Conformidad</em><br>ISO/IEC 27001:2022</div>
  <div class="subtitle">
    4 Cláusulas &nbsp;·&nbsp; 93 Controles &nbsp;·&nbsp; COBIT 6 Niveles &nbsp;·&nbsp; Deep Learning
  </div>
</div>
""", unsafe_allow_html=True)

# Banda de referencia: Anexo A + COBIT (antes en la sidebar)
_cobit_chips = ""
_cobit_colors = {
    0: ("#FCEBEB", "#A32D2D", "#791F1F"),
    1: ("#FAECE7", "#993C1D", "#712B13"),
    2: ("#FAEEDA", "#BA7517", "#633806"),
    3: ("#FDF8EE", "#C9A84C", "#854F0B"),
    4: ("#EAF3DE", "#3B6D11", "#27500A"),
    5: ("#E1F5EE", "#0F6E56", "#085041"),
}
for i in range(6):
    info = MATURITY_LEVELS[i]
    lo, hi = info["range"]
    rng = f"{lo}–{hi}%" if i > 0 else "0%"
    bg, border, txt = _cobit_colors[i]
    outline = "outline:2px solid #3B6D11;outline-offset:-2px;" if i == 3 else ""
    star = " ★" if i == 3 else ""
    _cobit_chips += (
        f'<div class="cobit-chip" style="border-color:{border};background:{bg};{outline}">'
        f'<div class="cobit-num" style="color:{txt};">N{i}{star}</div>'
        f'<div class="cobit-name">{info["name"]}</div>'
        f'<div class="cobit-range">{rng}</div>'
        f'</div>'
    )

_anexo_chips = ""
_anexo_data = [
    ("A.5", "37 Organizacionales", "#BA7517", "#854F0B"),
    ("A.6", "8 Personas",          "#3B6D11", "#27500A"),
    ("A.7", "14 Físicos",          "#185FA5", "#0C447C"),
    ("A.8", "34 Tecnológicos",     "#993C1D", "#712B13"),
]
for code, desc, border, txt in _anexo_data:
    _anexo_chips += (
        f'<div class="anexo-chip" style="border-color:{border};">'
        f'<div class="anexo-chip-label" style="color:{txt};">{code}</div>'
        f'<div class="anexo-chip-sub">{desc}</div>'
        f'</div>'
    )

st.markdown(f"""
<div class="info-band">
  <div class="info-half">
    <div class="info-label">Anexo A — 93 Controles</div>
    <div class="anexo-grid">{_anexo_chips}</div>
  </div>
  <div class="info-half">
    <div class="info-label">COBIT — 6 Niveles de Madurez</div>
    <div class="cobit-grid">{_cobit_chips}</div>
  </div>
</div>
""", unsafe_allow_html=True)


# ────────────────────────────────────────────────────────────────────────────
# TABS DE ENTRADA
# ────────────────────────────────────────────────────────────────────────────
tab_up, tab_demo, tab_paste, tab_compare = st.tabs([
    "01 · Subir Archivos",
    "02 · Demo ISO 27001",
    "03 · Pegar Texto",
    "04 · Comparar Logs",
])

entries, source_label = [], ""

with tab_up:
    st.markdown("""
    <div style="font-family:'JetBrains Mono',monospace;font-size:0.68rem;letter-spacing:0.1em;
                color:#9A9790;text-transform:uppercase;margin-bottom:1rem;">
      Formatos · Apache/Nginx .log · Linux syslog/auth.log · Windows Events .csv · JSON · .gz
    </div>
    """, unsafe_allow_html=True)
    uploaded = st.file_uploader(
        "Arrastra archivos de log",
        type=["log","txt","csv","json","gz"],
        accept_multiple_files=True,
        label_visibility="collapsed"
    )
    if uploaded:
        with tempfile.TemporaryDirectory() as d:
            for f in uploaded:
                (Path(d) / f.name).write_bytes(f.read())
            parser = LogParser()
            entries = parser.parse_path(d)
            source_label = f"{len(uploaded)} archivo(s)"
            st.success(f"✓ {parser.stats['parsed_ok']:,} eventos procesados de {len(uploaded)} archivo(s)")

with tab_demo:
    st.markdown("""
    <div style="font-family:'Syne',sans-serif;font-size:0.9rem;color:#7A776F;
                margin-bottom:1.5rem;line-height:1.6;">
      Logs simulados de empresa ISO 27001:2022 — declaraciones DUA, ERP aduanero,
      portal de importaciones, SIEM, Active Directory.
    </div>
    """, unsafe_allow_html=True)
    if st.button("▶ Ejecutar análisis con logs demo", type="primary"):
        sdir = ROOT / "samples"
        sample_files = list(sdir.glob("sample_*.log")) + list(sdir.glob("sample_*.csv"))
        if not sample_files:
            import subprocess
            subprocess.run([sys.executable, str(sdir / "generate_samples.py")], check=True)
            sample_files = list(sdir.glob("sample_*.log")) + list(sdir.glob("sample_*.csv"))
        parser = LogParser()
        entries = parser.parse_path(str(sdir))
        source_label = "Logs Demo — ISO 27001:2022"
        st.success(f"✓ {parser.stats['parsed_ok']:,} eventos procesados")
        st.session_state.update({"entries": entries, "source": source_label})

with tab_paste:
    pasted = st.text_area(
        "Contenido del log:",
        height=160,
        placeholder="Jan  1 10:00:00 srv sshd[1234]: Failed password for root from 10.0.0.1 port 22 ssh2",
        label_visibility="collapsed"
    )
    if st.button("▶ Analizar texto", type="primary") and pasted.strip():
        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as tf:
            tf.write(pasted); tf_path = tf.name
        parser = LogParser()
        entries = parser.parse_path(tf_path)
        os.unlink(tf_path)
        source_label = "Texto pegado"
        st.success(f"✓ {len(entries):,} eventos leídos")

with tab_compare:
    st.markdown("""
    <div style="font-family:'JetBrains Mono',monospace;font-size:0.68rem;letter-spacing:0.1em;
                color:#9A9790;text-transform:uppercase;margin-bottom:1rem;">
      Comparación de hasta 5 archivos · Radar superpuesto
    </div>
    """, unsafe_allow_html=True)
    compare_files = st.file_uploader(
        "Archivos a comparar",
        type=["log","txt","csv","json","gz"],
        accept_multiple_files=True,
        key="compare_uploader",
        label_visibility="collapsed"
    )
    if compare_files and len(compare_files) >= 2:
        import tempfile, os as _os
        compare_results = []
        for cf in compare_files[:5]:
            with tempfile.NamedTemporaryFile(suffix=_os.path.splitext(cf.name)[1] or ".log", delete=False) as tf:
                tf.write(cf.read()); tf_path = tf.name
            _p = LogParser(); _e = _p.parse_path(tf_path); _os.unlink(tf_path)
            _cls = EventClassifier().classify(_e); _s = _cls.domain_stats; _r = MaturityScorer().score(_cls)
            compare_results.append({"name": cf.name[:30], "result": _r, "entries": len(_e)})

        if compare_results:
            st.success(f"✓ {len(compare_results)} archivos analizados")
            COMPARE_COLORS = ["#C9A84C","#8B1A1A","#2D5A27","#4A6FA5","#6B4F8B"]
            DOMAIN_KEYS_C  = list(ISO27001_DOMAINS.keys())
            _CLBL = {
                "A5_organizational":"A.5 Org.",
                "A6_people":"A.6 Personas",
                "A7_physical":"A.7 Físico",
                "A8_technological":"A.8 Tecnológico"
            }
            labels_c = [_CLBL.get(k, k) for k in DOMAIN_KEYS_C]

            fig_compare = go.Figure()
            for i, cr in enumerate(compare_results):
                scores_c = [cr["result"].domain_scores[k].raw_score for k in DOMAIN_KEYS_C]
                col_c = COMPARE_COLORS[i % len(COMPARE_COLORS)]
                fig_compare.add_trace(go.Scatterpolar(
                    r=scores_c+[scores_c[0]], theta=labels_c+[labels_c[0]],
                    fill="toself", fillcolor=hex_rgba(col_c, 0.08),
                    line=dict(color=col_c, width=2),
                    name=f"{cr['name']}  (Nv.{cr['result'].overall_level} · {cr['result'].overall_score:.1f})",
                ))
            fig_compare.update_layout(
                polar=dict(
                    radialaxis=dict(visible=True, range=[0,100],
                                    tickfont=dict(size=9, color="#9A9790", family="'JetBrains Mono',monospace"),
                                    gridcolor="#EDE9E2", tickvals=[20,40,60,80,100]),
                    angularaxis=dict(tickfont=dict(size=11, color="#C8C4BC", family="'Syne',sans-serif")),
                    bgcolor="#FAFAF8",
                ),
                showlegend=True,
                legend=dict(orientation="h", y=-0.15, x=0.5, xanchor="center",
                            font=dict(size=10, color="#C8C4BC", family="'JetBrains Mono',monospace"),
                            bgcolor="rgba(255,255,255,0)"),
                height=520, margin=dict(l=80,r=80,t=80,b=120),
                paper_bgcolor="#FFFFFF",
                title=dict(text="Comparativa de Perfiles · ISO/IEC 27001:2022",
                           x=0.5, font=dict(size=14, color="#1C1A17", family="'DM Serif Display',serif")),
            )
            st.plotly_chart(fig_compare, use_container_width=True)

            comp_cols = st.columns(len(compare_results))
            for i, (cr, col) in enumerate(zip(compare_results, comp_cols)):
                r = cr["result"]; lc2 = level_color(r.overall_level)
                with col:
                    st.markdown(
                        f'<div style="border:1px solid {lc2};border-top:2px solid {lc2};'
                        f'padding:1rem;background:#FFFFFF;">'
                        f'<div style="font-family:\'JetBrains Mono\',monospace;font-size:0.6rem;'
                        f'letter-spacing:0.15em;text-transform:uppercase;color:#9A9790;margin-bottom:0.5rem;">'
                        f'{cr["name"]}</div>'
                        f'<div style="font-family:\'DM Serif Display\',serif;font-size:2rem;color:{lc2};">'
                        f'{r.overall_score:.1f}</div>'
                        f'<div style="font-family:\'JetBrains Mono\',monospace;font-size:0.62rem;'
                        f'letter-spacing:0.1em;color:{lc2};">Nivel {r.overall_level} — {r.overall_level_name}</div>'
                        f'</div>', unsafe_allow_html=True)
    elif compare_files and len(compare_files) < 2:
        st.info("Sube al menos 2 archivos para comparar.")
    else:
        st.markdown("""
        <div style="font-family:'Syne',sans-serif;font-size:0.88rem;color:#C0BDB7;
                    padding:2rem;border:1px dashed #1A1A1A;text-align:center;">
          Carga múltiples logs para superponer perfiles de madurez
        </div>
        """, unsafe_allow_html=True)


if not entries and "entries" in st.session_state:
    entries = st.session_state["entries"]
    source_label = st.session_state.get("source","")


# ────────────────────────────────────────────────────────────────────────────
# ESTADO VACÍO — INSTRUCCIONES
# ────────────────────────────────────────────────────────────────────────────
if not entries:
    st.markdown("""
    <div style="margin:3rem 0;">
      <div style="font-family:'JetBrains Mono',monospace;font-size:0.6rem;letter-spacing:0.2em;
                  text-transform:uppercase;color:#C9A84C;margin-bottom:1rem;">
        Instrucciones de uso
      </div>
      <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:1px;background:#1E1E1E;">
    """, unsafe_allow_html=True)

    pasos = [
        ("01", "Subir Logs", "Apache, syslog, Windows Events, JSON, .gz"),
        ("02", "Clasificación", "93 controles Anexo A · 4 dominios ISO"),
        ("03", "Score COBIT", "Niveles 0–5 con análisis de brecha"),
        ("04", "Exportar", "HTML · JSON · PDF con gráficos"),
    ]
    cols = st.columns(4)
    for col, (num, titulo, desc) in zip(cols, pasos):
        with col:
            st.markdown(
                f'<div style="background:#FFFFFF;padding:1.5rem;height:120px;">'
                f'<div style="font-family:\'DM Serif Display\',serif;font-size:2.5rem;'
                f'color:#1E1E1E;line-height:1;">{num}</div>'
                f'<div style="font-family:\'Syne\',sans-serif;font-size:0.85rem;'
                f'color:#F5F0E8;font-weight:600;margin:0.5rem 0 0.25rem;">{titulo}</div>'
                f'<div style="font-family:\'JetBrains Mono\',monospace;font-size:0.62rem;'
                f'color:#9A9790;letter-spacing:0.05em;">{desc}</div>'
                f'</div>',
                unsafe_allow_html=True
            )

    st.markdown("""
    <div style="margin-top:3rem;border-top:1px solid #1A1A1A;padding-top:2rem;">
      <div style="font-family:'JetBrains Mono',monospace;font-size:0.6rem;letter-spacing:0.2em;
                  text-transform:uppercase;color:#9A9790;margin-bottom:1rem;">
        Dominios ISO/IEC 27001:2022 — Anexo A
      </div>
    </div>
    """, unsafe_allow_html=True)

    for i, (key, dom) in enumerate(ISO27001_DOMAINS.items()):
        with st.expander(f"{dom.id} — {dom.name}  ·  peso {dom.weight:.0%}"):
            st.markdown(f'<div style="font-family:\'Syne\',sans-serif;font-size:0.88rem;color:#7A776F;">{dom.description}</div>', unsafe_allow_html=True)
    st.stop()


# ────────────────────────────────────────────────────────────────────────────
# PIPELINE DE ANÁLISIS
# ────────────────────────────────────────────────────────────────────────────
with st.spinner("Procesando eventos · Calculando madurez…"):
    _cls_result  = EventClassifier().classify(entries)
    domain_stats = _cls_result.domain_stats
    a8_sub_stats = _cls_result.a8_sub_stats
    result = MaturityScorer().score(_cls_result)
    gap    = compute_gap_analysis(result)
    st.session_state["_gap"] = gap

lvl      = result.overall_level
lvl_info = MATURITY_LEVELS[lvl]
lc       = level_color(lvl)
domains  = list(result.domain_scores.values())
dom_names = [d.domain_name for d in domains]


# ────────────────────────────────────────────────────────────────────────────
# KPIs — CUADRÍCULA BRUTALISTA
# ────────────────────────────────────────────────────────────────────────────
kpis = [
    (f"{result.overall_score:.1f}", "Score Global", lc),
    (f"N·{lvl}", lvl_info["name"][:14], lc),
    (f"{result.total_events:,}", "Eventos Totales", "#F5F0E8"),
    (f"{result.total_risk_events:,}", "Eventos de Riesgo", "#8B1A1A"),
    (f"{result.total_domains_active}/{len(result.domain_scores)}", "Dominios Activos", "#2D5A27"),
    (f"{result.total_risk_events/max(result.total_events,1):.1%}", "Tasa de Riesgo", "#C9A84C"),
]

kpi_html = '<div class="kpi-grid">'
for val, lbl, color in kpis:
    kpi_html += (
        f'<div class="kpi-card">'
        f'<span class="kpi-val" style="color:{color};">{val}</span>'
        f'<span class="kpi-lbl">{lbl}</span>'
        f'</div>'
    )
kpi_html += '</div>'
st.markdown(kpi_html, unsafe_allow_html=True)


# ────────────────────────────────────────────────────────────────────────────
# ANÁLISIS DE BRECHAS
# ────────────────────────────────────────────────────────────────────────────
if gap.has_critical_gap:
    st.markdown(
        f'<div class="alert-critical">'
        f'<div class="alert-title" style="color:#A32D2D;">⚠ Brecha de Madurez Detectada</div>'
        f'<div class="alert-body">{gap.audit_note}</div>'
        f'<div style="margin-top:0.75rem;font-family:\'JetBrains Mono\',monospace;'
        f'font-size:0.65rem;letter-spacing:0.1em;color:#A32D2D;text-transform:uppercase;">'
        f'Nivel Efectivo Auditoría: N{gap.effective_level} — {gap.effective_level_name} · {gap.effective_score}/100'
        f'</div></div>',
        unsafe_allow_html=True
    )
else:
    st.markdown(
        f'<div class="alert-ok">'
        f'<div class="alert-title" style="color:#3B6D11;">✓ Coherencia de Madurez Aceptable</div>'
        f'<div class="alert-body">{gap.audit_note}</div>'
        f'</div>',
        unsafe_allow_html=True
    )

with st.expander("Nota de Auditoría — Lista para presentar", expanded=gap.has_critical_gap):
    col_n1, col_n2, col_n3 = st.columns(3)
    with col_n1:
        st.metric("Score Global", f"{gap.overall_score:.1f}/100",
                  delta=f"Nivel {gap.overall_level} — {gap.overall_level_name}")
    with col_n2:
        delta_eff = gap.effective_level - gap.overall_level
        st.metric("Nivel Efectivo",
                  f"N{gap.effective_level} — {gap.effective_level_name}",
                  delta=f"{delta_eff:+d} niveles",
                  delta_color="inverse" if delta_eff < 0 else "normal")
    with col_n3:
        st.metric(f"Dominio débil: {gap.weakest_domain_id}",
                  f"{gap.weakest_score:.1f}/100",
                  delta=f"N{gap.weakest_level} — {gap.weakest_level_name}",
                  delta_color="inverse" if gap.weakest_level < gap.overall_level else "normal")


# ════════════════════════════════════════════════════════════════════════════
# SECCIÓN 01: RESULTADO GLOBAL
# ════════════════════════════════════════════════════════════════════════════
st.markdown("""
<div class="section-rule">
  <span class="section-num">01 —</span>
  <span class="section-hdr">Resultado Global</span>
</div>
""", unsafe_allow_html=True)

col_gauge, col_radar = st.columns([1, 1.2])

# GAUGE
with col_gauge:
    st.markdown('<div class="chart-box">', unsafe_allow_html=True)
    st.markdown('<div class="chart-title">Medidor de Nivel de Madurez</div>', unsafe_allow_html=True)
    st.markdown('<div class="chart-sub">Score global COBIT 0–5</div>', unsafe_allow_html=True)

    fig_gauge = go.Figure(go.Indicator(
        mode="gauge+number+delta",
        value=result.overall_score,
        delta={"reference": 60, "valueformat":".1f", "suffix":" pts",
               "font": {"color": "#C9A84C", "family": "'JetBrains Mono',monospace"}},
        title={"text": f"<b>N{lvl} — {lvl_info['name']}</b><br>"
                       f"<span style='font-size:.75em;color:#9A9790;font-family:JetBrains Mono,monospace'>"
                       f"{source_label}</span>",
               "font": {"size": 13, "color": "#1C1A17", "family": "'Syne',sans-serif"}},
        number={"suffix": " / 100",
                "font": {"size": 38, "color": lc, "family": "'DM Serif Display',serif"}},
        gauge={
            "axis": {"range":[0,100], "tickwidth":0.5, "tickcolor":"#2A2A2A",
                     "tickvals":[0,20,40,60,80,100],
                     "ticktext":["0","20","40","60","80","100"],
                     "tickfont": {"color":"#555550","size":9,"family":"'JetBrains Mono',monospace"}},
            "bar":  {"color": lc, "thickness":0.25},
            "bgcolor": "#0F0F0F",
            "borderwidth": 0,
            "steps": [
                {"range":[0,20],  "color":"#1A0000"},
                {"range":[20,40], "color":"#1A0A00"},
                {"range":[40,60], "color":"#1A1500"},
                {"range":[60,80], "color":"#0A1A00"},
                {"range":[80,100],"color":"#0A1A00"},
            ],
            "threshold": {"line":{"color":lc,"width":2}, "thickness":0.75, "value":result.overall_score},
        }
    ))
    fig_gauge.update_layout(
        height=300,
        margin=dict(l=20,r=20,t=70,b=10),
        paper_bgcolor="#FFFFFF",
        font=dict(family="'Syne',sans-serif", color="#1C1A17"),
    )
    st.plotly_chart(fig_gauge, use_container_width=True)
    st.markdown(
        f'<div style="background:rgba({int(lc[1:3],16)},{int(lc[3:5],16)},{int(lc[5:7],16)},0.08);'
        f'border-left:2px solid {lc};padding:0.75rem 1rem;margin-top:0.5rem;">'
        f'<div style="font-family:\'JetBrains Mono\',monospace;font-size:0.62rem;'
        f'letter-spacing:0.15em;text-transform:uppercase;color:{lc};margin-bottom:0.25rem;">'
        f'N{lvl} — {lvl_info["name"]}</div>'
        f'<div style="font-family:\'Syne\',sans-serif;font-size:0.82rem;color:#7A776F;line-height:1.5;">'
        f'{lvl_info["description"]}</div>'
        f'</div>',
        unsafe_allow_html=True
    )
    st.markdown('</div>', unsafe_allow_html=True)

# RADAR PRINCIPAL
with col_radar:
    st.markdown('<div class="chart-box">', unsafe_allow_html=True)
    st.markdown('<div class="chart-title">Radar — 4 Dominios Anexo A</div>', unsafe_allow_html=True)
    st.markdown('<div class="chart-sub">ISO/IEC 27001:2022 · A.5 / A.6 / A.7 / A.8</div>', unsafe_allow_html=True)

    scores_radar = [d.raw_score for d in domains]
    _RADAR_LBL = {
        "A5_organizational": "A.5 Org.",
        "A6_people":         "A.6 Personas",
        "A7_physical":       "A.7 Físico",
        "A8_technological":  "A.8 Tecnológico",
    }
    labels_radar = [_RADAR_LBL.get(d.domain_key, d.domain_id) for d in domains]

    fig_radar = go.Figure()
    fig_radar.add_trace(go.Scatterpolar(
        r=scores_radar + [scores_radar[0]],
        theta=labels_radar + [labels_radar[0]],
        fill="toself",
        fillcolor=hex_rgba(lc, 0.12),
        line=dict(color=lc, width=2),
        name="Score actual",
    ))
    fig_radar.add_trace(go.Scatterpolar(
        r=[60]*len(labels_radar)+[60], theta=labels_radar+[labels_radar[0]],
        mode="lines", line=dict(color="#D8D3CA", width=1, dash="dot"),
        name="Referencia N3", hoverinfo="skip",
    ))
    fig_radar.update_layout(
        polar=dict(
            radialaxis=dict(visible=True, range=[0,100],
                            tickfont=dict(size=8, color="#9A9790", family="'JetBrains Mono',monospace"),
                            gridcolor="#EDE9E2", tickvals=[20,40,60,80,100]),
            angularaxis=dict(tickfont=dict(size=10, color="#C8C4BC", family="'Syne',sans-serif")),
            bgcolor="#FAFAF8",
        ),
        showlegend=True,
        legend=dict(orientation="h", yanchor="bottom", y=-0.18, x=0.5, xanchor="center",
                    font=dict(size=9, color="#9A9790", family="'JetBrains Mono',monospace"),
                    bgcolor="rgba(255,255,255,0)"),
        height=360, margin=dict(l=60,r=60,t=40,b=60),
        paper_bgcolor="#FFFFFF",
    )
    st.plotly_chart(fig_radar, use_container_width=True)
    st.markdown('</div>', unsafe_allow_html=True)


# ════════════════════════════════════════════════════════════════════════════
# SECCIÓN 02: RADAR AMPLIADO
# ════════════════════════════════════════════════════════════════════════════
st.markdown("""
<div class="section-rule">
  <span class="section-num">02 —</span>
  <span class="section-hdr">Perfil de Madurez — Radar Completo</span>
</div>
""", unsafe_allow_html=True)

st.markdown("""
<div style="font-family:'Syne',sans-serif;font-size:0.88rem;color:#9A9790;
            margin-bottom:1.5rem;max-width:700px;line-height:1.7;">
  Perfil de madurez en los 4 dominios de control ISO/IEC 27001:2022 (Anexo A).
  Los anillos de referencia indican umbrales COBIT. La forma del polígono revela
  fortalezas y áreas de mejora prioritaria.
</div>
""", unsafe_allow_html=True)

LEVEL_RINGS = [
    (20, "N1", "#3D0000", "dot"),
    (40, "N2", "#8B1A1A", "dot"),
    (60, "N3", "#C9A84C", "dashdot"),
    (80, "N4", "#2D5A27", "dot"),
    (100,"N5", "#4A9F3F", "dash"),
]

fig_radar_big = go.Figure()
for ring_val, ring_name, ring_col, ring_dash in reversed(LEVEL_RINGS):
    fig_radar_big.add_trace(go.Scatterpolar(
        r=[ring_val]*len(labels_radar)+[ring_val],
        theta=labels_radar+[labels_radar[0]],
        mode="lines",
        line=dict(color=ring_col, width=0.8, dash=ring_dash),
        name=f"{ring_name} ({ring_val})", opacity=0.5,
    ))

fig_radar_big.add_trace(go.Scatterpolar(
    r=scores_radar+[scores_radar[0]],
    theta=labels_radar+[labels_radar[0]],
    fill="toself",
    fillcolor=hex_rgba(lc, 0.15),
    line=dict(color=lc, width=3),
    name=f"Perfil — N{lvl} ({result.overall_score:.1f})",
))

fig_radar_big.add_trace(go.Scatterpolar(
    r=scores_radar,
    theta=labels_radar,
    mode="markers+text",
    marker=dict(color=[C["domains"][i] for i in range(len(scores_radar))],
                size=10, symbol="circle",
                line=dict(color="#0A0A0A", width=2)),
    text=[f"<b>{s:.0f}</b>" for s in scores_radar],
    textposition="top center",
    textfont=dict(size=11, color="#1C1A17", family="'JetBrains Mono',monospace"),
    showlegend=False,
))

fig_radar_big.update_layout(
    polar=dict(
        domain=dict(x=[0.08, 0.92], y=[0.08, 0.88]),
        radialaxis=dict(
            visible=True, range=[0,115],
            tickfont=dict(size=9, color="#9A9790", family="'JetBrains Mono',monospace"),
            gridcolor="#EDE9E2", tickvals=[20,40,60,80,100],
            linecolor="#D8D3CA",
        ),
        angularaxis=dict(
            tickfont=dict(size=12, color="#1C1A17", family="'Syne',sans-serif", ),
            linecolor="#D8D3CA", gridcolor="#EDE9E2",
        ),
        bgcolor="#FAFAF8",
    ),
    showlegend=True,
    legend=dict(
        orientation="h", yanchor="bottom", y=-0.22,
        x=0.5, xanchor="center",
        font=dict(size=9, color="#9A9790", family="'JetBrains Mono',monospace"),
        bgcolor="rgba(255,255,255,0)",
    ),
    height=620,
    margin=dict(l=100, r=100, t=100, b=140),
    paper_bgcolor="#FFFFFF",
    title=dict(
        text=(f"<b>Perfil ISO/IEC 27001:2022</b>"
              f"<br><span style='color:{lc};font-size:12px;font-family:JetBrains Mono,monospace'>"
              f"N{lvl} — {lvl_info['name']} · Score: {result.overall_score:.1f}/100 · Nivel Efectivo: N{gap.effective_level}"
              f"</span>"),
        x=0.5, xanchor="center",
        font=dict(size=14, color="#1C1A17", family="'DM Serif Display',serif"),
    ),
)
st.plotly_chart(fig_radar_big, use_container_width=True)

# INTERPRETACIÓN DOMINIOS
st.markdown("""
<div style="font-family:'JetBrains Mono',monospace;font-size:0.6rem;letter-spacing:0.2em;
            text-transform:uppercase;color:#9A9790;margin:1.5rem 0 1rem;">
  Interpretación por Dominio
</div>
""", unsafe_allow_html=True)

DOMAIN_WEIGHT = {k: ISO27001_DOMAINS[k].weight for k in ISO27001_DOMAINS}
DOMAIN_BADGE_2022 = {
    "A5_organizational": "A.5 (37)",
    "A6_people":         "A.6 (8)",
    "A7_physical":       "A.7 (14)",
    "A8_technological":  "A.8 (34)",
}
DOMAIN_SHORT_2022 = {
    "A5_organizational": "A.5 Organizacional",
    "A6_people":         "A.6 Personas",
    "A7_physical":       "A.7 Físico",
    "A8_technological":  "A.8 Controles Tecnológicos",
}

radar_cols = st.columns(4)
for idx, (key, ds_score) in enumerate(result.domain_scores.items()):
    ds = domain_stats[key]
    with radar_cols[idx % 4]:
        score    = ds_score.raw_score
        sc_color = level_color(ds_score.level)
        risk_pct = ds.risk_rate * 100
        badge    = DOMAIN_BADGE_2022.get(key, ds_score.domain_id)
        bar_pct  = int(score)

        st.markdown(
            f'<div style="background:#FFFFFF;border:1px solid #D8D3CA;border-top:2px solid {sc_color};'
            f'padding:1.25rem;margin-bottom:1px;">'
            f'<div style="font-family:\'JetBrains Mono\',monospace;font-size:0.62rem;'
            f'letter-spacing:0.15em;text-transform:uppercase;color:{sc_color};margin-bottom:0.5rem;">'
            f'{badge}</div>'
            f'<div style="font-family:\'DM Serif Display\',serif;font-size:2rem;color:{sc_color};">'
            f'{score:.1f}</div>'
            f'<div style="background:#EDEAE4;height:2px;margin:0.5rem 0;">'
            f'<div style="width:{bar_pct}%;height:2px;background:{sc_color};"></div></div>'
            f'<div style="font-family:\'Syne\',sans-serif;font-size:0.78rem;color:#9A9790;">'
            f'N{ds_score.level} — {ds_score.level_name}</div>'
            f'<div style="font-family:\'JetBrains Mono\',monospace;font-size:0.62rem;'
            f'letter-spacing:0.05em;color:#C0BDB7;margin-top:0.5rem;">'
            f'{ds.total_events:,} eventos · {risk_pct:.1f}% riesgo</div>'
            f'</div>',
            unsafe_allow_html=True,
        )


# ════════════════════════════════════════════════════════════════════════════
# SECCIÓN 03: ANÁLISIS POR DOMINIO
# ════════════════════════════════════════════════════════════════════════════
st.markdown("""
<div class="section-rule">
  <span class="section-num">03 —</span>
  <span class="section-hdr">Análisis por Tema — Anexo A</span>
</div>
""", unsafe_allow_html=True)

col_bar1, col_bar2 = st.columns(2)

with col_bar1:
    st.markdown('<div class="chart-box">', unsafe_allow_html=True)
    st.markdown('<div class="chart-title">Riesgo vs Seguros por Dominio</div>', unsafe_allow_html=True)
    st.markdown('<div class="chart-sub">Distribución de eventos por clasificación</div>', unsafe_allow_html=True)

    dom_keys = list(domain_stats.keys())
    dom_names_short = [DOMAIN_SHORT_2022.get(d.domain_key, d.domain_name[:22]) for d in domains]
    safe_counts = [domain_stats[k].safe_events for k in dom_keys]
    risk_counts = [domain_stats[k].risk_events for k in dom_keys]

    fig_bar = go.Figure()
    fig_bar.add_trace(go.Bar(
        name="Eventos Seguros", x=dom_names_short, y=safe_counts,
        marker_color=hex_rgba("#2D5A27", 0.8),
        marker_line_width=0,
    ))
    fig_bar.add_trace(go.Bar(
        name="Eventos de Riesgo", x=dom_names_short, y=risk_counts,
        marker_color=hex_rgba("#8B1A1A", 0.8),
        marker_line_width=0,
    ))
    fig_bar.update_layout(
        barmode="group", height=300,
        margin=dict(l=10,r=10,t=20,b=80),
        legend=dict(orientation="h", y=-0.35, x=0.5, xanchor="center",
                    font=dict(size=9, color="#9A9790", family="'JetBrains Mono',monospace"),
                    bgcolor="rgba(255,255,255,0)"),
        yaxis=dict(title="N° eventos", gridcolor="#EDE9E2", tickfont=dict(color="#9A9790")),
        xaxis=dict(tickangle=-20, tickfont=dict(color="#9A9790", size=9, family="'Syne',sans-serif")),
    )
    apply_editorial_theme(fig_bar)
    st.plotly_chart(fig_bar, use_container_width=True)
    st.markdown('</div>', unsafe_allow_html=True)

with col_bar2:
    st.markdown('<div class="chart-box">', unsafe_allow_html=True)
    st.markdown('<div class="chart-title">Desglose del Score por Componente</div>', unsafe_allow_html=True)
    st.markdown('<div class="chart-sub">Contribución de cada factor al score final</div>', unsafe_allow_html=True)

    comps = ["Presencia Logs","Efectividad Controles","Ajuste Severidad","Cobertura"]
    comp_keys = ["logging_presence","control_effectiveness","severity_adjustment","coverage_bonus"]
    comp_colors = ["#C9A84C","#2D5A27","#8B1A1A","#4A6FA5"]

    fig_stack = go.Figure()
    for comp, key, color in zip(comps, comp_keys, comp_colors):
        vals = [max(0, d.breakdown.get(key, 0)) for d in domains]
        fig_stack.add_trace(go.Bar(
            name=comp, y=dom_names_short, x=vals,
            orientation="h", marker_color=hex_rgba(color, 0.85),
            marker_line_width=0,
        ))
    fig_stack.update_layout(
        barmode="stack", height=300,
        margin=dict(l=10,r=10,t=20,b=80),
        legend=dict(orientation="h", y=-0.35, x=0.5, xanchor="center",
                    font=dict(size=9, color="#9A9790", family="'JetBrains Mono',monospace"),
                    bgcolor="rgba(255,255,255,0)"),
        xaxis=dict(title="Puntos", range=[0,100], gridcolor="#EDE9E2"),
    )
    apply_editorial_theme(fig_stack)
    st.plotly_chart(fig_stack, use_container_width=True)
    st.markdown('</div>', unsafe_allow_html=True)


col_scores, col_pie = st.columns([1.4, 1])

with col_scores:
    st.markdown('<div class="chart-box">', unsafe_allow_html=True)
    st.markdown('<div class="chart-title">Score y Nivel por Dominio</div>', unsafe_allow_html=True)
    st.markdown('<div class="chart-sub">Barras horizontales con umbrales COBIT</div>', unsafe_allow_html=True)

    sorted_domains = sorted(domains, key=lambda d: d.raw_score)
    bar_colors  = [level_color(d.level) for d in sorted_domains]
    bar_names   = [f"{DOMAIN_SHORT_2022.get(d.domain_key, d.domain_name)}" for d in sorted_domains]
    bar_scores  = [d.raw_score for d in sorted_domains]
    bar_levels  = [f"N{d.level} — {d.level_name}" for d in sorted_domains]

    fig_h = go.Figure()
    fig_h.add_trace(go.Bar(
        y=bar_names, x=bar_scores, orientation="h",
        marker_color=bar_colors,
        marker_line_width=0,
        text=[f"{s:.1f}" for s in bar_scores],
        textposition="outside",
        textfont=dict(color="#9A9790", family="'JetBrains Mono',monospace", size=10),
        customdata=bar_levels,
    ))
    for threshold, label, color in [(20,"N1","#3D0000"),(40,"N2","#8B1A1A"),(60,"N3","#C9A84C"),(80,"N4","#2D5A27")]:
        fig_h.add_vline(x=threshold, line_dash="dot", line_color=color, line_width=0.8,
                        annotation_text=label, annotation_position="top",
                        annotation_font=dict(size=8, color=color,
                                             family="'JetBrains Mono',monospace"))
    fig_h.update_layout(
        height=320, margin=dict(l=10,r=60,t=30,b=10),
        xaxis=dict(range=[0,110], title="Score (0–100)", gridcolor="#EDE9E2"),
        showlegend=False,
    )
    apply_editorial_theme(fig_h)
    st.plotly_chart(fig_h, use_container_width=True)
    st.markdown('</div>', unsafe_allow_html=True)

with col_pie:
    st.markdown('<div class="chart-box">', unsafe_allow_html=True)
    st.markdown('<div class="chart-title">Distribución de Eventos</div>', unsafe_allow_html=True)
    st.markdown('<div class="chart-sub">Por dominio ISO 27001</div>', unsafe_allow_html=True)

    pie_vals  = [domain_stats[d.domain_key].total_events for d in domains]
    pie_names = [DOMAIN_SHORT_2022.get(d.domain_key, d.domain_name[:20]) for d in domains]
    fig_pie = go.Figure(go.Pie(
        labels=pie_names, values=pie_vals,
        marker=dict(colors=C["domains"], line=dict(color="#0A0A0A", width=2)),
        hole=0.5,
        textinfo="percent+label",
        textfont=dict(size=9, family="'JetBrains Mono',monospace", color="#1C1A17"),
        pull=[0.04 if domain_stats[d.domain_key].risk_events/max(domain_stats[d.domain_key].total_events,1) > 0.3 else 0 for d in domains],
    ))
    fig_pie.update_layout(
        height=340, margin=dict(l=10,r=10,t=30,b=30),
        paper_bgcolor="#FFFFFF",
        annotations=[dict(text=f"<b>{result.total_events:,}</b>",
                          x=0.5, y=0.5, font_size=16,
                          font=dict(color="#1C1A17", family="'DM Serif Display',serif"),
                          showarrow=False)],
        showlegend=False,
    )
    st.plotly_chart(fig_pie, use_container_width=True)
    st.markdown('</div>', unsafe_allow_html=True)


# ════════════════════════════════════════════════════════════════════════════
# SECCIÓN 04: MAPA DE RIESGO Y ESTRUCTURA
# ════════════════════════════════════════════════════════════════════════════
st.markdown("""
<div class="section-rule">
  <span class="section-num">04 —</span>
  <span class="section-hdr">Mapa de Riesgo y Estructura</span>
</div>
""", unsafe_allow_html=True)

col_heat, col_sun = st.columns(2)

with col_heat:
    st.markdown('<div class="chart-box">', unsafe_allow_html=True)
    st.markdown('<div class="chart-title">Mapa de Calor — Tasa de Riesgo</div>', unsafe_allow_html=True)
    st.markdown('<div class="chart-sub">Exposición por dominio</div>', unsafe_allow_html=True)

    categories = ["Tasa Riesgo %","Score (inv.)","Eventos Críticos","Cobertura IPs"]
    dom_short = [DOMAIN_SHORT_2022.get(d.domain_key, d.domain_name[:18]) for d in domains]
    heat_data = []
    for d in domains:
        ds = domain_stats[d.domain_key]
        rrate  = round(ds.risk_rate * 100, 1)
        inv_sc = round(100 - d.raw_score, 1)
        _crit_kws = ["CRITICAL","ransomware","breach","exfiltrat","zero.day","exploit","ddos","lateral_movement"]
        _n_crit = sum(1 for m in ds.raw_messages if any(k.lower() in m.lower() for k in _crit_kws))
        crit = min(100, _n_crit * 10 + ds.risk_events * 2)
        cov_ips = min(100, len(ds.unique_ips) * 5)
        heat_data.append([rrate, inv_sc, crit, cov_ips])

    df_heat = pd.DataFrame(heat_data, index=dom_short, columns=categories)
    fig_heat = go.Figure(go.Heatmap(
        z=df_heat.values.tolist(),
        x=categories, y=dom_short,
        colorscale=[
            [0.0,"#0A1A00"],[0.25,"#1A1500"],[0.5,"#1A0A00"],
            [0.75,"#1A0000"],[1.0,"#3D0000"],
        ],
        text=[[f"{v:.0f}" for v in row] for row in df_heat.values.tolist()],
        texttemplate="%{text}",
        textfont=dict(size=10, family="'JetBrains Mono',monospace", color="#1C1A17"),
        showscale=True,
        colorbar=dict(
            title="Riesgo",
            tickfont=dict(size=8, color="#9A9790", family="'JetBrains Mono',monospace"),
            titlefont=dict(size=9, color="#9A9790", family="'JetBrains Mono',monospace"),
        ),
    ))
    fig_heat.update_layout(
        height=310, margin=dict(l=10,r=10,t=20,b=10),
        xaxis=dict(tickangle=-15, tickfont=dict(size=8, color="#9A9790", family="'Syne',sans-serif")),
        yaxis=dict(tickfont=dict(size=9, color="#9A9790", family="'Syne',sans-serif")),
    )
    apply_editorial_theme(fig_heat)
    st.plotly_chart(fig_heat, use_container_width=True)
    st.markdown('</div>', unsafe_allow_html=True)

with col_sun:
    st.markdown('<div class="chart-box">', unsafe_allow_html=True)
    st.markdown('<div class="chart-title">Estructura Jerárquica de Eventos</div>', unsafe_allow_html=True)
    st.markdown('<div class="chart-sub">Distribución por dominio y clasificación</div>', unsafe_allow_html=True)

    sun_ids, sun_labels, sun_parents, sun_vals, sun_colors = [], [], [], [], []
    sun_ids.append("root"); sun_labels.append("Total"); sun_parents.append("")
    sun_vals.append(result.total_events); sun_colors.append(C["primary"])

    for i, (key, d) in enumerate(zip(list(domain_stats.keys()), domains)):
        ds = domain_stats[key]
        if ds.total_events == 0: continue
        did = f"dom_{key}"
        sun_ids.append(did); sun_labels.append(DOMAIN_SHORT_2022.get(d.domain_key, d.domain_name[:18]))
        sun_parents.append("root"); sun_vals.append(ds.total_events); sun_colors.append(C["domains"][i % len(C["domains"])])
        if ds.safe_events > 0:
            sun_ids.append(f"{did}_ok"); sun_labels.append("Seguros")
            sun_parents.append(did); sun_vals.append(ds.safe_events); sun_colors.append("#2D5A27")
        if ds.risk_events > 0:
            sun_ids.append(f"{did}_risk"); sun_labels.append("Riesgo")
            sun_parents.append(did); sun_vals.append(ds.risk_events); sun_colors.append("#8B1A1A")

    fig_sun = go.Figure(go.Sunburst(
        ids=sun_ids, labels=sun_labels, parents=sun_parents, values=sun_vals,
        marker=dict(colors=sun_colors, line=dict(width=1.5, color="#0A0A0A")),
        branchvalues="total",
        textfont=dict(size=9, family="'JetBrains Mono',monospace"),
        insidetextorientation="radial",
    ))
    fig_sun.update_layout(
        height=350, margin=dict(l=0,r=0,t=10,b=10),
        paper_bgcolor="#FFFFFF",
    )
    st.plotly_chart(fig_sun, use_container_width=True)
    st.markdown('</div>', unsafe_allow_html=True)


# ════════════════════════════════════════════════════════════════════════════
# SECCIÓN 05: ANÁLISIS DE BRECHAS
# ════════════════════════════════════════════════════════════════════════════
st.markdown("""
<div class="section-rule">
  <span class="section-num">05 —</span>
  <span class="section-hdr">Distribución y Análisis de Brechas</span>
</div>
""", unsafe_allow_html=True)

col_hist, col_prog = st.columns([1, 1.2])

with col_hist:
    st.markdown('<div class="chart-box">', unsafe_allow_html=True)
    st.markdown('<div class="chart-title">Distribución por Nivel COBIT</div>', unsafe_allow_html=True)
    st.markdown('<div class="chart-sub">Dominios por nivel de madurez</div>', unsafe_allow_html=True)

    _lv_names = ["Inexistente","Inicial","Repetible","Definido","Administrado","Optimizado"]
    level_names = [f"N{i}" for i in range(6)]
    level_counts = [sum(1 for d in domains if d.level == i) for i in range(6)]
    level_pcts   = [c/len(domains)*100 for c in level_counts]

    fig_hist = go.Figure(go.Bar(
        x=level_names, y=level_counts,
        marker_color=[level_color(i) for i in range(6)],
        marker_line_width=0,
        text=[f"{p:.0f}%\n({c})" for p,c in zip(level_pcts,level_counts)],
        textposition="outside",
        textfont=dict(size=9, color="#9A9790", family="'JetBrains Mono',monospace"),
    ))
    fig_hist.update_layout(
        height=300, margin=dict(l=10,r=10,t=30,b=50),
        yaxis=dict(title="Dominios", dtick=1, gridcolor="#EDE9E2", range=[0, len(domains)+0.8]),
        xaxis=dict(tickfont=dict(size=10, color="#9A9790", family="'JetBrains Mono',monospace")),
        showlegend=False,
    )
    apply_editorial_theme(fig_hist)
    st.plotly_chart(fig_hist, use_container_width=True)
    st.markdown('</div>', unsafe_allow_html=True)

with col_prog:
    st.markdown('<div class="chart-box">', unsafe_allow_html=True)
    st.markdown('<div class="chart-title">Brecha al Nivel 5</div>', unsafe_allow_html=True)
    st.markdown('<div class="chart-sub">Distancia al nivel óptimo por dominio</div>', unsafe_allow_html=True)

    target = 100
    gap_names  = [DOMAIN_SHORT_2022.get(d.domain_key, d.domain_name[:24]) for d in domains]
    gap_actual = [d.raw_score for d in domains]
    gap_needed = [max(0, target - d.raw_score) for d in domains]

    fig_gap = go.Figure()
    fig_gap.add_trace(go.Bar(
        name="Score actual", y=gap_names, x=gap_actual, orientation="h",
        marker_color=[level_color(d.level) for d in domains],
        marker_line_width=0,
    ))
    fig_gap.add_trace(go.Bar(
        name="Brecha al N5", y=gap_names, x=gap_needed, orientation="h",
        marker_color="#1A1A1A",
        marker_line=dict(color="#D8D3CA", width=0.5),
    ))
    fig_gap.update_layout(
        barmode="stack", height=290,
        margin=dict(l=10,r=10,t=20,b=40),
        xaxis=dict(title="Puntos (0–100)", range=[0,105], gridcolor="#EDE9E2"),
        showlegend=True,
        legend=dict(orientation="h", y=-0.3, x=0.5, xanchor="center",
                    font=dict(size=9, color="#9A9790", family="'JetBrains Mono',monospace"),
                    bgcolor="rgba(255,255,255,0)"),
    )
    apply_editorial_theme(fig_gap)
    st.plotly_chart(fig_gap, use_container_width=True)
    st.caption(f"Brecha global al N5: {100-result.overall_score:.1f} pts · Score: {result.overall_score:.1f}/100")
    st.markdown('</div>', unsafe_allow_html=True)


# ════════════════════════════════════════════════════════════════════════════
# SECCIÓN 06: TIMELINE DE EVENTOS
# ════════════════════════════════════════════════════════════════════════════
st.markdown("""
<div class="section-rule">
  <span class="section-num">06 —</span>
  <span class="section-hdr">Línea de Tiempo de Eventos</span>
</div>
""", unsafe_allow_html=True)

events_with_ts = [e for e in entries if e.timestamp is not None]
if events_with_ts:
    lvl_colors_tl = {
        "DEBUG":"#2A2A2A","INFO":"#2D5A27","WARNING":"#C9A84C",
        "ERROR":"#8B1A1A","CRITICAL":"#3D0000"
    }
    lvl_size_tl = {"DEBUG":4,"INFO":5,"WARNING":6,"ERROR":8,"CRITICAL":11}

    df_tl = pd.DataFrame([{
        "ts":    e.timestamp,
        "nivel": e.level,
        "msg":   (e.message or "")[:80],
        "color": lvl_colors_tl.get(e.level,"#555550"),
        "size":  lvl_size_tl.get(e.level,5),
        "y":     {"DEBUG":0,"INFO":1,"WARNING":2,"ERROR":3,"CRITICAL":4}.get(e.level,1),
    } for e in events_with_ts])
    df_tl = df_tl.sort_values("ts")

    fig_tl = go.Figure()
    for nivel, grp in df_tl.groupby("nivel"):
        col_tl = lvl_colors_tl.get(nivel,"#555550")
        fig_tl.add_trace(go.Scatter(
            x=grp["ts"], y=grp["y"],
            mode="markers", name=nivel,
            marker=dict(color=col_tl, size=grp["size"].tolist(), opacity=0.85,
                        line=dict(color="#0A0A0A", width=0.5)),
            customdata=grp["msg"].tolist(),
        ))
    fig_tl.update_layout(
        height=260,
        yaxis=dict(tickvals=[0,1,2,3,4],
                   ticktext=["DEBUG","INFO","WARNING","ERROR","CRITICAL"],
                   gridcolor="#EDE9E2", tickfont=dict(size=8, color="#9A9790", family="'JetBrains Mono',monospace")),
        xaxis=dict(gridcolor="#EDE9E2"),
        legend=dict(orientation="h", y=-0.3, x=0.5, xanchor="center",
                    font=dict(size=9, color="#9A9790", family="'JetBrains Mono',monospace"),
                    bgcolor="rgba(255,255,255,0)"),
        margin=dict(l=10,r=10,t=20,b=60),
    )
    apply_editorial_theme(fig_tl)
    st.plotly_chart(fig_tl, use_container_width=True)

    tl_c1, tl_c2, tl_c3, tl_c4 = st.columns(4)
    with tl_c1:
        st.metric("Con timestamp", f"{len(events_with_ts):,}")
    with tl_c2:
        st.metric("CRITICAL", sum(1 for e in events_with_ts if e.level == "CRITICAL"))
    with tl_c3:
        st.metric("ERROR", sum(1 for e in events_with_ts if e.level == "ERROR"))
    with tl_c4:
        if len(events_with_ts) > 1:
            span = events_with_ts[-1].timestamp - events_with_ts[0].timestamp if hasattr(events_with_ts[-1].timestamp, '__sub__') else None
            st.metric("Período", f"{span.days} días" if span else "—")
else:
    st.markdown("""
    <div style="font-family:'JetBrains Mono',monospace;font-size:0.72rem;letter-spacing:0.1em;
                color:#C0BDB7;padding:1.5rem;border:1px dashed #1A1A1A;text-align:center;">
      Los archivos no contienen timestamps parseables · El timeline requiere logs con fecha/hora
    </div>
    """, unsafe_allow_html=True)


# ════════════════════════════════════════════════════════════════════════════
# SECCIÓN 07: PLAN DE ACCIÓN
# ════════════════════════════════════════════════════════════════════════════
st.markdown("""
<div class="section-rule">
  <span class="section-num">07 —</span>
  <span class="section-hdr">Plan de Acción Prioritizado</span>
</div>
""", unsafe_allow_html=True)

from analyzer.action_plan import generate_action_plan
action_plan = generate_action_plan(result)

if not action_plan:
    st.markdown("""
    <div class="alert-ok">
      <div class="alert-title" style="color:#3B6D11;">Todos los dominios en niveles óptimos</div>
      <div class="alert-body">Mantén el programa de mejora continua.</div>
    </div>
    """, unsafe_allow_html=True)
else:
    for item in action_plan:
        effort_color = {"Bajo":"#2D5A27","Medio":"#C9A84C","Alto":"#8B1A1A"}.get(item["effort"],"#555550")
        lvl_c = level_color(item["level"])
        effort_icon = "▲" if item["effort"]=="Alto" else "◆" if item["effort"]=="Medio" else "▼"
        with st.expander(
            f"{effort_icon} #{item.get('priority',1)} — {item['domain_name']}  ·  "
            f"Score: {item['score']:.1f}  ·  N{item['level']} — {item['level_name']}  ·  "
            f"+{item.get('gap_to_next',0):.0f} pts al N{item['level']+1 if item['level']<5 else 5}",
            expanded=item.get("priority", 1) <= 2,
        ):
            a1, a2, a3 = st.columns(3)
            with a1:
                st.markdown(
                    f'<div style="background:#FFFFFF;border:1px solid #D8D3CA;border-top:2px solid {lvl_c};'
                    f'padding:1rem;text-align:center;">'
                    f'<div style="font-family:\'DM Serif Display\',serif;font-size:2rem;color:{lvl_c};">'
                    f'{item["score"]:.1f}</div>'
                    f'<div style="font-family:\'JetBrains Mono\',monospace;font-size:0.6rem;'
                    f'letter-spacing:0.15em;text-transform:uppercase;color:#9A9790;">Score Actual</div>'
                    f'</div>', unsafe_allow_html=True)
            with a2:
                st.markdown(
                    f'<div style="background:#FFFFFF;border:1px solid #D8D3CA;border-top:2px solid {effort_color};'
                    f'padding:1rem;text-align:center;">'
                    f'<div style="font-family:\'DM Serif Display\',serif;font-size:2rem;color:{effort_color};">'
                    f'{item["effort"]}</div>'
                    f'<div style="font-family:\'JetBrains Mono\',monospace;font-size:0.6rem;'
                    f'letter-spacing:0.15em;text-transform:uppercase;color:#9A9790;">Esfuerzo</div>'
                    f'</div>', unsafe_allow_html=True)
            with a3:
                st.markdown(
                    f'<div style="background:#FFFFFF;border:1px solid #D8D3CA;border-top:2px solid #C9A84C;'
                    f'padding:1rem;text-align:center;">'
                    f'<div style="font-family:\'DM Serif Display\',serif;font-size:1.6rem;color:#C9A84C;">'
                    f'{item["tiempo"]}</div>'
                    f'<div style="font-family:\'JetBrains Mono\',monospace;font-size:0.6rem;'
                    f'letter-spacing:0.15em;text-transform:uppercase;color:#9A9790;">Tiempo Est.</div>'
                    f'</div>', unsafe_allow_html=True)

            st.markdown(f'<div style="font-family:\'JetBrains Mono\',monospace;font-size:0.62rem;letter-spacing:0.15em;text-transform:uppercase;color:#9A9790;margin:1rem 0 0.5rem;">Acciones recomendadas</div>', unsafe_allow_html=True)
            for action in item["actions"]:
                st.markdown(
                    f'<div style="background:#FFFFFF;border-left:2px solid {lvl_c};padding:0.6rem 1rem;'
                    f'margin-bottom:2px;font-family:\'Syne\',sans-serif;font-size:0.85rem;color:#4A4740;">'
                    f'{action}</div>',
                    unsafe_allow_html=True
                )

    st.markdown("""
    <div style="font-family:'JetBrains Mono',monospace;font-size:0.6rem;letter-spacing:0.2em;
                text-transform:uppercase;color:#9A9790;margin:1.5rem 0 0.75rem;">
      Resumen de brechas
    </div>
    """, unsafe_allow_html=True)
    for item in action_plan:
        lc3 = level_color(item["level"])
        pct = int(item["score"])
        st.markdown(
            f'<div style="display:flex;align-items:center;gap:1rem;margin-bottom:4px;">'
            f'<span style="min-width:200px;font-family:\'JetBrains Mono\',monospace;'
            f'font-size:0.65rem;color:#7A776F;">{item["domain_name"][:32]}</span>'
            f'<div style="flex:1;background:#EDEAE4;height:2px;">'
            f'<div style="width:{pct}%;background:{lc3};height:2px;"></div></div>'
            f'<span style="min-width:60px;font-family:\'JetBrains Mono\',monospace;'
            f'font-size:0.65rem;color:{lc3};text-align:right;">{item["score"]:.1f}/100</span>'
            f'</div>',
            unsafe_allow_html=True,
        )


# ════════════════════════════════════════════════════════════════════════════
# SECCIÓN 08: HALLAZGOS Y RECOMENDACIONES
# ════════════════════════════════════════════════════════════════════════════
st.markdown("""
<div class="section-rule">
  <span class="section-num">08 —</span>
  <span class="section-hdr">Hallazgos Críticos y Recomendaciones</span>
</div>
""", unsafe_allow_html=True)

col_find, col_rec = st.columns(2)

with col_find:
    st.markdown("""
    <div style="font-family:'JetBrains Mono',monospace;font-size:0.62rem;letter-spacing:0.15em;
                text-transform:uppercase;color:#A32D2D;margin-bottom:0.75rem;">
      Hallazgos Críticos
    </div>
    """, unsafe_allow_html=True)
    if result.critical_findings:
        for f in result.critical_findings:
            st.markdown(f'<div class="finding">↳ {f}</div>', unsafe_allow_html=True)
    else:
        st.markdown("""
        <div class="alert-ok">
          <div class="alert-body">Sin hallazgos críticos detectados.</div>
        </div>
        """, unsafe_allow_html=True)

with col_rec:
    st.markdown("""
    <div style="font-family:'JetBrains Mono',monospace;font-size:0.62rem;letter-spacing:0.15em;
                text-transform:uppercase;color:#3B6D11;margin-bottom:0.75rem;">
      Recomendaciones
    </div>
    """, unsafe_allow_html=True)
    for i, rec in enumerate(result.recommendations, 1):
        st.markdown(f'<div class="rec"><span style="font-family:\'JetBrains Mono\',monospace;color:#3B6D11;">{i:02d}</span> · {rec}</div>', unsafe_allow_html=True)


# ════════════════════════════════════════════════════════════════════════════
# SECCIÓN 09: TABLA RESUMEN
# ════════════════════════════════════════════════════════════════════════════
st.markdown("""
<div class="section-rule">
  <span class="section-num">09 —</span>
  <span class="section-hdr">Tabla Resumen por Dominio</span>
</div>
""", unsafe_allow_html=True)

table_data = []
for key, d in result.domain_scores.items():
    ds = domain_stats[key]
    table_data.append({
        "Dominio": d.domain_name,
        "Cláusula": DOMAIN_BADGE_2022.get(d.domain_key, d.annex_ref.split('–')[0].strip()),
        "Peso": f"{d.weight:.0%}",
        "Score": f"{d.raw_score:.1f}",
        "Nivel": f"N{d.level} — {d.level_name}",
        "Total Eventos": ds.total_events,
        "Riesgo": ds.risk_events,
        "Tasa Riesgo": f"{ds.risk_rate:.1%}",
        "IPs Únicas": len(ds.unique_ips),
        "Usuarios": len(ds.unique_users),
    })
df_table = pd.DataFrame(table_data).sort_values("Score", ascending=False)
st.dataframe(df_table, use_container_width=True, hide_index=True)


# ════════════════════════════════════════════════════════════════════════════
# SECCIÓN 10: DEEP LEARNING
# ════════════════════════════════════════════════════════════════════════════
st.markdown("""
<div class="section-rule">
  <span class="section-num">10 —</span>
  <span class="section-hdr">Análisis Deep Learning</span>
</div>
""", unsafe_allow_html=True)

st.markdown("""
<div style="font-family:'Syne',sans-serif;font-size:0.88rem;color:#9A9790;
            margin-bottom:1.5rem;max-width:700px;line-height:1.7;">
  Tres modelos entrenados en tiempo real sobre los logs analizados: Autoencoder
  para detección de anomalías, LSTM bidireccional para patrones temporales,
  y MLP clasificador de nivel de madurez.
</div>
""", unsafe_allow_html=True)

with st.expander("Arquitectura de los Modelos", expanded=False):
    arch_cols = st.columns(3)
    arch_info = [
        ("Autoencoder", "63 → 32 → 16 → 8 → 16 → 32 → 63",
         "Reconstruye eventos normales. Alta pérdida = anomalía.",
         [("Entrada (63)", False),("Dense 32", False),("Dense 16", False),
          ("Bottleneck 8", True),("Dense 16", False),("Dense 32", False),("Salida (63)", False)],
         "#C9A84C"),
        ("LSTM Bidireccional", "(20×13) → BiLSTM(32) → LSTM(16) → Dense(8) → sigmoid",
         "Analiza secuencias temporales. Detecta patrones de ataque.",
         [("Seq (20,13)", False),("BiLSTM 32", False),("LSTM 16", False),
          ("Dense 8", False),("Prob amenaza", True)],
         "#8B1A1A"),
        ("MLP Clasificador", "24 → 64 → 32 → 16 → softmax(6)",
         "Clasifica el nivel de madurez ISO 27001 (0–5) directamente.",
         [("Features (24)", False),("Dense 64", False),("Dense 32", False),
          ("Dense 16", False),("Softmax (6)", True)],
         "#2D5A27"),
    ]
    for col, (title, arch, desc, layers_list, color) in zip(arch_cols, arch_info):
        with col:
            st.markdown(
                f'<div style="font-family:\'JetBrains Mono\',monospace;font-size:0.62rem;'
                f'letter-spacing:0.15em;text-transform:uppercase;color:{color};margin-bottom:0.5rem;">'
                f'{title}</div>'
                f'<div style="font-family:\'Syne\',sans-serif;font-size:0.78rem;'
                f'color:#9A9790;margin-bottom:0.75rem;line-height:1.5;">{desc}</div>',
                unsafe_allow_html=True
            )
            for lyr, is_key in layers_list:
                bg = color if is_key else "rgba(0,0,0,0)"
                fc = "#0A0A0A" if is_key else "#555550"
                border = f"border:1px solid {color}" if is_key else f"border:1px solid #D8D3CA"
                st.markdown(
                    f'<div style="background:{bg};color:{fc};{border};'
                    f'padding:4px 8px;text-align:center;margin-bottom:2px;'
                    f'font-family:\'JetBrains Mono\',monospace;font-size:0.65rem;">{lyr}</div>',
                    unsafe_allow_html=True,
                )

dl_col1, dl_col2, dl_col3, dl_col4 = st.columns([1,1,1,1])
with dl_col1:
    ae_epochs   = st.slider("Épocas Autoencoder", 5, 50, 25, 5)
with dl_col2:
    lstm_epochs = st.slider("Épocas LSTM", 5, 40, 20, 5)
with dl_col3:
    mlp_epochs  = st.slider("Épocas MLP", 10, 60, 35, 5)
with dl_col4:
    st.markdown("<br>", unsafe_allow_html=True)
    run_dl = st.button("▶ Entrenar y Analizar", type="primary", use_container_width=True)

if run_dl or "dl_result" in st.session_state:
    if run_dl:
        from ml.dl_pipeline import DLPipeline
        from rules.iso27001_controls import MATURITY_LEVELS as ML

        prog_bar = st.progress(0, text="Inicializando modelos…")

        @st.cache_resource(show_spinner=False)
        def get_pipeline():
            return DLPipeline()

        pipeline = get_pipeline()
        pipeline._trained = False

        prog_bar.progress(10, text="Entrenando Autoencoder…")
        pipeline.autoencoder = __import__('ml.autoencoder_model', fromlist=['LogAutoencoder']).LogAutoencoder()
        pipeline.autoencoder.fit(entries, epochs=ae_epochs, verbose=0)

        prog_bar.progress(40, text="Entrenando LSTM Bidireccional…")
        from ml.lstm_model import LSTMThreatDetector
        from ml.dl_pipeline import _separate_normal_attack, _augment_attack_entries
        pipeline.lstm = LSTMThreatDetector()
        pipeline.lstm.extractor = pipeline.autoencoder.extractor
        pipeline.lstm.extractor._fitted = True
        normal_e, attack_e = _separate_normal_attack(entries)
        if len(attack_e) < 30:
            attack_e = _augment_attack_entries(attack_e, normal_e)
        pipeline.lstm.fit(normal_e, attack_e, epochs=lstm_epochs, verbose=0)

        prog_bar.progress(70, text="Entrenando MLP Clasificador…")
        from ml.maturity_classifier import MaturityClassifier
        pipeline.classifier = MaturityClassifier()
        pipeline.classifier.fit(epochs=mlp_epochs, verbose=0)
        pipeline._trained = True

        prog_bar.progress(90, text="Calculando predicciones…")
        dl_res = pipeline.run(entries, domain_stats, result)
        st.session_state["dl_result"]  = dl_res
        st.session_state["dl_pipeline"] = pipeline
        prog_bar.progress(100, text="Completado")
        prog_bar.empty()
    else:
        dl_res = st.session_state["dl_result"]

    from rules.iso27001_controls import MATURITY_LEVELS as ML

    # KPIs DL
    kpis_dl = [
        (f"{dl_res.anomaly_rate:.1f}%", "Tasa de Anomalías", "#C9A84C"),
        (f"{dl_res.threat_level['mean_threat_prob']:.1%}", "Prob. Amenaza Media", "#8B1A1A"),
        (f"N{dl_res.dl_predicted_level}", "Nivel DL (MLP)", "#2D5A27"),
        (f"{dl_res.dl_confidence:.1f}%", "Confianza MLP", "#4A6FA5"),
        ("✓ Sí" if dl_res.agreement else "✗ No",
         "Acuerdo Reglas vs DL", "#2D5A27" if dl_res.agreement else "#8B1A1A"),
    ]

    kpi_dl_html = '<div class="kpi-grid" style="grid-template-columns:repeat(5,1fr);">'
    for val, lbl, color in kpis_dl:
        kpi_dl_html += (
            f'<div class="kpi-card">'
            f'<span class="kpi-val" style="color:{color};font-size:1.8rem;">{val}</span>'
            f'<span class="kpi-lbl">{lbl}</span>'
            f'</div>'
        )
    kpi_dl_html += '</div>'
    st.markdown(kpi_dl_html, unsafe_allow_html=True)

    # Curvas de entrenamiento
    st.markdown("""
    <div style="font-family:'JetBrains Mono',monospace;font-size:0.6rem;letter-spacing:0.2em;
                text-transform:uppercase;color:#9A9790;margin:1.5rem 0 0.75rem;">
      Curvas de Entrenamiento
    </div>
    """, unsafe_allow_html=True)

    tc1, tc2, tc3 = st.columns(3)

    def plot_loss_curve_dark(train_loss, val_loss, train_acc, val_acc, title, color):
        if not train_loss:
            fig = go.Figure()
            fig.add_annotation(text="Modelo no entrenado",
                               xref="paper", yref="paper", x=0.5, y=0.5,
                               showarrow=False, font=dict(size=12, color="#9A9790"))
            fig.update_layout(height=220, title=dict(text=title, font=dict(size=12, color=color,
                              family="'Syne',sans-serif")))
            apply_editorial_theme(fig)
            return fig
        epochs_ax = list(range(1, len(train_loss)+1))
        fig = go.Figure()
        fig.add_trace(go.Scatter(x=epochs_ax, y=train_loss, name="Train Loss",
            line=dict(color=color, width=2), mode="lines"))
        if val_loss:
            fig.add_trace(go.Scatter(x=epochs_ax, y=val_loss[:len(epochs_ax)], name="Val Loss",
                line=dict(color=color, width=1.5, dash="dot"), mode="lines", opacity=0.6))
        if train_acc:
            fig.add_trace(go.Scatter(
                x=epochs_ax, y=[a*100 for a in train_acc[:len(epochs_ax)]],
                name="Train Acc %", line=dict(color="#C9A84C", width=1.2, dash="dash"),
                mode="lines", yaxis="y2"))
        layout_args = dict(
            title=dict(text=title, font=dict(size=11, color=color, family="'Syne',sans-serif")),
            height=230, margin=dict(l=40,r=40,t=40,b=30),
            legend=dict(orientation="h", y=-0.3, font=dict(size=8, color="#9A9790",
                        family="'JetBrains Mono',monospace"), bgcolor="rgba(255,255,255,0)"),
            xaxis=dict(title="Época"),
            yaxis=dict(title="Pérdida"),
        )
        if train_acc:
            layout_args["yaxis2"] = dict(
                title="Acc %", overlaying="y", side="right",
                range=[0, 105], showgrid=False,
            )
        fig.update_layout(**layout_args)
        apply_editorial_theme(fig)
        return fig

    with tc1:
        st.markdown('<div class="chart-box">', unsafe_allow_html=True)
        st.markdown('<div class="chart-sub">Autoencoder — MSE</div>', unsafe_allow_html=True)
        fig = plot_loss_curve_dark(dl_res.ae_train_loss, dl_res.ae_val_loss, [], [], "Autoencoder", "#C9A84C")
        st.plotly_chart(fig, use_container_width=True)
        sm = dl_res.ae_summary
        st.caption(f"Parámetros: {sm['parameters']:,} · Loss: {sm['final_train_loss']}")
        st.markdown('</div>', unsafe_allow_html=True)

    with tc2:
        st.markdown('<div class="chart-box">', unsafe_allow_html=True)
        st.markdown('<div class="chart-sub">LSTM — Binary CE</div>', unsafe_allow_html=True)
        fig = plot_loss_curve_dark(dl_res.lstm_train_loss, dl_res.lstm_val_loss,
                                   dl_res.lstm_train_acc, dl_res.lstm_val_acc, "LSTM Bidireccional", "#8B1A1A")
        st.plotly_chart(fig, use_container_width=True)
        sm = dl_res.lstm_summary
        acc = f"{sm['final_val_acc']:.1%}" if sm.get('final_val_acc') else "N/A"
        st.caption(f"Parámetros: {sm['parameters']:,} · Acc val: {acc}")
        st.markdown('</div>', unsafe_allow_html=True)

    with tc3:
        st.markdown('<div class="chart-box">', unsafe_allow_html=True)
        st.markdown('<div class="chart-sub">MLP — Categorical CE</div>', unsafe_allow_html=True)
        fig = plot_loss_curve_dark(dl_res.mlp_train_loss, dl_res.mlp_val_loss,
                                   dl_res.mlp_train_acc, dl_res.mlp_val_acc, "MLP Clasificador", "#2D5A27")
        st.plotly_chart(fig, use_container_width=True)
        sm = dl_res.mlp_summary
        acc = f"{sm['final_val_acc']:.1%}" if sm.get('final_val_acc') else "N/A"
        st.caption(f"Parámetros: {sm['parameters']:,} · Acc val: {acc}")
        st.markdown('</div>', unsafe_allow_html=True)

    # Distribución de anomalías AE
    st.markdown("""
    <div style="font-family:'JetBrains Mono',monospace;font-size:0.6rem;letter-spacing:0.2em;
                text-transform:uppercase;color:#9A9790;margin:1.5rem 0 0.75rem;">
      Autoencoder — Detección de Anomalías
    </div>
    """, unsafe_allow_html=True)

    ae1, ae2 = st.columns(2)
    with ae1:
        import numpy as _np
        _raw = _np.array(dl_res.anomaly_scores, dtype=float)
        _thr = float(dl_res.autoencoder_threshold) if dl_res.autoencoder_threshold > 0 else float(_raw.max() or 0.1)
        scores_norm = _np.clip(_raw / _thr * 50, 0, 200)
        _mask = _np.array(dl_res.is_anomaly, dtype=bool)
        normal_scores = scores_norm[~_mask]
        anom_scores   = scores_norm[_mask]

        fig_hist_ae = go.Figure()
        if len(normal_scores):
            fig_hist_ae.add_trace(go.Histogram(
                x=normal_scores.tolist(), name="Normales",
                marker_color=hex_rgba("#2D5A27", 0.7), nbinsx=40,
            ))
        if len(anom_scores):
            fig_hist_ae.add_trace(go.Histogram(
                x=anom_scores.tolist(), name="Anomalías",
                marker_color=hex_rgba("#8B1A1A", 0.7), nbinsx=40,
            ))
        fig_hist_ae.add_vline(x=50, line_dash="dash", line_color="#C9A84C", line_width=1.5,
                               annotation_text=f"Umbral P95", annotation_font_color="#C9A84C")
        fig_hist_ae.update_layout(
            barmode="overlay", height=260,
            margin=dict(l=10,r=10,t=10,b=30),
            legend=dict(orientation="h", y=-0.3, font=dict(size=9, color="#9A9790"),
                        bgcolor="rgba(255,255,255,0)"),
            xaxis=dict(title="Score Anomalía (0–100)"),
            yaxis=dict(title="N° eventos"),
        )
        apply_editorial_theme(fig_hist_ae)
        st.plotly_chart(fig_hist_ae, use_container_width=True)
        st.info(f"Tasa: {dl_res.anomaly_rate:.1f}% · Umbral P95: {dl_res.autoencoder_threshold:.6f}")

    with ae2:
        step = max(1, len(scores_norm) // 300)
        idx_plot = list(range(0, len(scores_norm), step))
        scores_plot = scores_norm[idx_plot]
        colors_plot = ["#8B1A1A" if float(s) >= 50 else "#2D5A27" for s in scores_plot.tolist()]

        fig_time = go.Figure()
        fig_time.add_trace(go.Scatter(
            x=idx_plot, y=scores_plot.tolist(),
            mode="markers", name="Score por evento",
            marker=dict(color=colors_plot, size=3, opacity=0.6),
        ))
        fig_time.add_hline(y=50, line_dash="dash", line_color="#C9A84C",
                            annotation_text="Umbral", annotation_font_color="#C9A84C")
        fig_time.update_layout(
            height=260, margin=dict(l=10,r=10,t=10,b=30),
            xaxis=dict(title="N° evento"),
            yaxis=dict(title="Score (0–100)", range=[0,105]),
        )
        apply_editorial_theme(fig_time)
        st.plotly_chart(fig_time, use_container_width=True)

    st.success(
        f"Deep Learning completado · Total parámetros: "
        f"{dl_res.ae_summary.get('parameters',0)+dl_res.lstm_summary.get('parameters',0)+dl_res.mlp_summary.get('parameters',0):,} · "
        f"Score ajustado DL: {dl_res.dl_adjusted_score:.1f}/100"
    )
else:
    st.markdown("""
    <div style="font-family:'JetBrains Mono',monospace;font-size:0.72rem;letter-spacing:0.1em;
                color:#C0BDB7;padding:1.5rem;border:1px dashed #1A1A1A;text-align:center;">
      Configura épocas y presiona Entrenar para activar análisis neuronal
    </div>
    """, unsafe_allow_html=True)


# ════════════════════════════════════════════════════════════════════════════
# SECCIÓN 11: EXPORTAR
# ════════════════════════════════════════════════════════════════════════════
st.markdown("""
<div class="section-rule">
  <span class="section-num">11 —</span>
  <span class="section-hdr">Exportar Resultados</span>
</div>
""", unsafe_allow_html=True)

dl1, dl2, dl3 = st.columns(3)

with dl1:
    with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as tf:
        export_html(result, source_label, tf.name)
        html_bytes = Path(tf.name).read_bytes(); os.unlink(tf.name)
    st.download_button("↓ Reporte HTML completo", data=html_bytes,
        file_name="reporte_madurez_iso27001_2022.html", mime="text/html",
        use_container_width=True, type="primary")
    st.caption("Incluye gráficos, hallazgos y recomendaciones")

with dl2:
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tf:
        export_json(result, tf.name)
        json_bytes = Path(tf.name).read_bytes(); os.unlink(tf.name)
    st.download_button("↓ Datos JSON estructurado", data=json_bytes,
        file_name="resultado_madurez_iso27001_2022.json", mime="application/json",
        use_container_width=True)
    st.caption("Para integración con otras herramientas")

with dl3:
    if st.button("↓ Generar Reporte PDF", use_container_width=True, key="pdf_btn"):
        with st.spinner("Generando PDF…"):
            try:
                from analyzer.pdf_report  import generate_pdf
                from analyzer.action_plan import generate_action_plan as _gap
                _ap = _gap(result)
                pdf_bytes = generate_pdf(result, domain_stats, source_label, _ap)
                st.download_button("↓ Descargar PDF",
                    data=pdf_bytes,
                    file_name="reporte_madurez_iso27001_2022.pdf",
                    mime="application/pdf",
                    use_container_width=True,
                    key="pdf_dl")
            except Exception as _e:
                st.error(f"Error: {_e}")
    st.caption("PDF con portada, gráficos y plan de acción")


# ── FOOTER ──────────────────────────────────────────────────────────────────
st.markdown(f"""
<footer>
  ISO/IEC 27001:2022 &nbsp;·&nbsp; COBIT 5 &nbsp;·&nbsp; Deep Learning &nbsp;·&nbsp;
  Fuente: {source_label} &nbsp;·&nbsp; {result.total_events:,} eventos procesados
</footer>
""", unsafe_allow_html=True)
