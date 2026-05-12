"""
report_generator.py — Generación de reportes de madurez
Soporta formatos: consola (rich), HTML, JSON
"""

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Optional

from src.maturity_calculator import MaturityReport, MATURITY_LEVELS


class ReportGenerator:
    """Genera reportes del nivel de madurez en distintos formatos."""

    REPORTS_DIR = Path("reports")

    def __init__(self):
        self.REPORTS_DIR.mkdir(exist_ok=True)

    # ─────────────────────────────────────────
    # Reporte JSON
    # ─────────────────────────────────────────

    def to_json(self, report: MaturityReport, output_path: Optional[str] = None) -> str:
        """Genera reporte en formato JSON."""
        data = {
            "generated_at": datetime.now().isoformat(),
            "evaluation": {
                "global_score": report.global_score,
                "global_level": report.global_level,
                "level_name": report.level_name,
                "compliance_percentage": round(report.compliance_percentage, 2),
            },
            "components": {},
            "top_risks": [
                {"control_id": ctrl_id, "finding": finding}
                for ctrl_id, finding in report.top_risks
            ],
            "all_findings": report.all_findings,
            "recommendations": report.level_info.get('recommendations', []),
        }

        for domain, comp in report.component_results.items():
            data["components"][domain] = {
                "name": comp.component_name,
                "maturity_level": round(comp.maturity_level, 2),
                "compliance_pct": round(comp.compliance_pct, 2),
                "total_controls": comp.total_controls,
                "compliant_controls": comp.compliant_controls,
                "controls": [
                    {
                        "id": c.control_id,
                        "name": c.name,
                        "score": round(c.score, 2),
                        "compliant": c.compliant,
                        "findings": c.findings,
                    }
                    for c in comp.controls
                ]
            }

        json_str = json.dumps(data, ensure_ascii=False, indent=2)

        path = output_path or self.REPORTS_DIR / f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(path, 'w', encoding='utf-8') as f:
            f.write(json_str)

        return str(path)

    # ─────────────────────────────────────────
    # Reporte HTML
    # ─────────────────────────────────────────

    def to_html(self, report: MaturityReport, output_path: Optional[str] = None) -> str:
        """Genera reporte HTML completo e interactivo."""
        level_colors = {
            0: '#ef4444', 1: '#f97316', 2: '#eab308',
            3: '#3b82f6', 4: '#22c55e', 5: '#a855f7'
        }
        color = level_colors.get(report.global_level, '#6b7280')
        pct = report.compliance_percentage

        # Construir filas de componentes
        component_rows = ""
        for domain, comp in report.component_results.items():
            bar_pct = comp.compliance_pct
            bar_color = level_colors.get(int(comp.maturity_level), '#6b7280')
            component_rows += f"""
            <tr>
                <td><strong>{comp.component_name}</strong><br><small style="color:#6b7280">{domain}</small></td>
                <td style="text-align:center">{round(comp.maturity_level, 2):.2f} / 5.00</td>
                <td>
                    <div style="background:#e5e7eb;border-radius:8px;height:18px;width:100%">
                        <div style="background:{bar_color};border-radius:8px;height:18px;width:{bar_pct:.0f}%;min-width:4px"></div>
                    </div>
                    <small>{bar_pct:.1f}%</small>
                </td>
                <td style="text-align:center">{comp.compliant_controls} / {comp.total_controls}</td>
            </tr>"""

        # Construir hallazgos críticos
        findings_html = ""
        if report.top_risks:
            for ctrl_id, finding in report.top_risks:
                findings_html += f"""
                <div style="background:#fef2f2;border-left:4px solid #ef4444;padding:10px 14px;margin-bottom:8px;border-radius:0 6px 6px 0">
                    <strong style="color:#ef4444">[{ctrl_id}]</strong>
                    <span style="color:#374151;margin-left:8px">{finding}</span>
                </div>"""
        else:
            findings_html = '<p style="color:#22c55e">✅ No se detectaron hallazgos críticos.</p>'

        # Recomendaciones
        recs_html = ""
        for i, rec in enumerate(report.level_info.get('recommendations', []), 1):
            recs_html += f'<li style="margin-bottom:6px">{rec}</li>'

        # Control scores para la tabla detallada (top 20 controles con menor puntaje)
        all_controls = []
        for comp in report.component_results.values():
            for ctrl in comp.controls:
                all_controls.append(ctrl)
        all_controls.sort(key=lambda c: c.score)
        worst_controls = all_controls[:20]

        controls_rows = ""
        for ctrl in worst_controls:
            score_color = '#ef4444' if ctrl.score < 2 else '#f97316' if ctrl.score < 3 else '#eab308' if ctrl.score < 4 else '#22c55e'
            status = "❌ Incumplido" if not ctrl.compliant else "✅ Cumplido"
            controls_rows += f"""
            <tr>
                <td><code style="background:#f3f4f6;padding:2px 6px;border-radius:4px">{ctrl.control_id}</code></td>
                <td>{ctrl.name}</td>
                <td>{ctrl.domain}</td>
                <td style="text-align:center;font-weight:bold;color:{score_color}">{ctrl.score:.1f}</td>
                <td style="text-align:center">{status}</td>
            </tr>"""

        html = f"""<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reporte de Madurez en Seguridad — ISO/IEC 27001:2022</title>
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #f8fafc; color: #1e293b; }}
        .container {{ max-width: 1100px; margin: 0 auto; padding: 24px; }}
        .header {{ background: linear-gradient(135deg, #1e293b 0%, #334155 100%); color: white; padding: 32px; border-radius: 12px; margin-bottom: 24px; }}
        .header h1 {{ font-size: 1.6rem; font-weight: 700; margin-bottom: 6px; }}
        .header .subtitle {{ opacity: 0.75; font-size: 0.9rem; }}
        .card {{ background: white; border-radius: 12px; padding: 24px; margin-bottom: 20px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }}
        .level-badge {{ display: inline-block; background: {color}; color: white; padding: 6px 18px; border-radius: 20px; font-weight: 700; font-size: 1rem; margin-bottom: 12px; }}
        .score-big {{ font-size: 4rem; font-weight: 900; color: {color}; line-height: 1; }}
        .score-label {{ font-size: 0.85rem; color: #6b7280; margin-top: 4px; }}
        .progress-bar {{ background: #e5e7eb; border-radius: 12px; height: 24px; margin: 12px 0; }}
        .progress-fill {{ background: {color}; border-radius: 12px; height: 24px; width: {pct:.1f}%; transition: width 1s; }}
        table {{ width: 100%; border-collapse: collapse; }}
        th {{ background: #f8fafc; text-align: left; padding: 10px 12px; font-size: 0.85rem; color: #6b7280; text-transform: uppercase; letter-spacing: 0.05em; border-bottom: 2px solid #e5e7eb; }}
        td {{ padding: 10px 12px; border-bottom: 1px solid #f1f5f9; font-size: 0.9rem; }}
        tr:hover {{ background: #f8fafc; }}
        h2 {{ font-size: 1.1rem; font-weight: 700; margin-bottom: 16px; color: #1e293b; }}
        .grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }}
        .meta {{ font-size: 0.8rem; color: #6b7280; margin-top: 16px; }}
        @media (max-width: 700px) {{ .grid {{ grid-template-columns: 1fr; }} }}
    </style>
</head>
<body>
<div class="container">
    <div class="header">
        <h1>🔐 Evaluador de Madurez en Seguridad de la Información</h1>
        <div class="subtitle">Basado en ISO/IEC 27001:2022 — 93 Controles | Modelo de Madurez 0-5</div>
        <div class="meta">Generado: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}</div>
    </div>

    <!-- Score global -->
    <div class="card">
        <h2>📊 Nivel de Madurez Global</h2>
        <div class="level-badge">Nivel {report.global_level} — {report.level_name}</div>
        <div class="score-big">{report.global_score:.2f}</div>
        <div class="score-label">Puntuación sobre 5.00</div>
        <div class="progress-bar"><div class="progress-fill"></div></div>
        <p style="color:#6b7280;font-size:0.9rem">{report.compliance_percentage:.1f}% de cumplimiento — {report.level_info['description']}</p>
    </div>

    <div class="grid">
        <!-- Componentes -->
        <div class="card">
            <h2>🧩 Evaluación por Componente</h2>
            <table>
                <thead><tr>
                    <th>Componente</th>
                    <th>NM</th>
                    <th>Progreso</th>
                    <th>Controles</th>
                </tr></thead>
                <tbody>{component_rows}</tbody>
            </table>
        </div>

        <!-- Recomendaciones -->
        <div class="card">
            <h2>💡 Recomendaciones Prioritarias</h2>
            <ol style="padding-left:20px;color:#374151;font-size:0.9rem">{recs_html}</ol>
        </div>
    </div>

    <!-- Hallazgos críticos -->
    <div class="card">
        <h2>🚨 Hallazgos Críticos Detectados</h2>
        {findings_html}
    </div>

    <!-- Tabla de controles con menor puntaje -->
    <div class="card">
        <h2>📋 Controles con Mayor Brecha (Top 20)</h2>
        <table>
            <thead><tr>
                <th>Control</th>
                <th>Nombre</th>
                <th>Dominio</th>
                <th style="text-align:center">Puntuación</th>
                <th style="text-align:center">Estado</th>
            </tr></thead>
            <tbody>{controls_rows}</tbody>
        </table>
    </div>

    <!-- Escala de madurez -->
    <div class="card">
        <h2>📈 Escala de Madurez ISO 27001</h2>
        <table>
            <thead><tr><th>Nivel</th><th>Nombre</th><th>Rango</th><th>Descripción</th></tr></thead>
            <tbody>
            {"".join(f'<tr style="{"background:#f0fdf4" if lvl == report.global_level else ""}"><td style="text-align:center;font-weight:bold">{"⭐ " if lvl == report.global_level else ""}{lvl}</td><td><strong>{info["name"]}</strong></td><td>{info["range"][0]:.1f} – {info["range"][1]:.1f}</td><td style="color:#6b7280;font-size:0.85rem">{info["description"]}</td></tr>' for lvl, info in MATURITY_LEVELS.items())}
            </tbody>
        </table>
    </div>

    <div style="text-align:center;color:#9ca3af;font-size:0.8rem;margin-top:16px;padding:16px">
        Evaluador de Madurez en Seguridad de la Información — ISO/IEC 27001:2022<br>
        Tesis: Modelo de Evaluación de la Madurez en Seguridad de la Información usando Simulador
    </div>
</div>
</body>
</html>"""

        path = output_path or self.REPORTS_DIR / f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        with open(path, 'w', encoding='utf-8') as f:
            f.write(html)

        return str(path)
