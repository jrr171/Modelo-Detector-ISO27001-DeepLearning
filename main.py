#!/usr/bin/env python3
"""
main.py — Evaluador de Madurez en Seguridad de la Información
Tesis: Modelo de Evaluación de la Madurez en Seguridad de la Información
       usando Simulador para la Detección de Incumplimiento de Requisitos
       en una Empresa de Inteligencia Comercial — Sector Comercio Exterior

Uso:
    python main.py --log /var/log/auth.log --type auth
    python main.py --log /var/log/auth.log /var/log/syslog --type auth syslog
    python main.py --sample
    python main.py --simulate --level 2
    python main.py --log /var/log/auth.log --type auth --report html
"""

import argparse
import sys
from pathlib import Path

# ── Importaciones locales ──────────────────────
from src.log_parser import LogParser
from src.control_evaluator import ControlEvaluator
from src.maturity_calculator import MaturityCalculator, MATURITY_LEVELS
from src.report_generator import ReportGenerator
from src.simulator import LogSimulator


# ─────────────────────────────────────────────
# Salida a consola (sin dependencia de rich)
# ─────────────────────────────────────────────

COLORS = {
    'red':     '\033[91m',
    'orange':  '\033[93m',
    'yellow':  '\033[93m',
    'blue':    '\033[94m',
    'green':   '\033[92m',
    'purple':  '\033[95m',
    'cyan':    '\033[96m',
    'bold':    '\033[1m',
    'reset':   '\033[0m',
    'dim':     '\033[2m',
}

LEVEL_COLORS = {0: 'red', 1: 'orange', 2: 'yellow', 3: 'blue', 4: 'green', 5: 'purple'}


def c(text: str, color: str) -> str:
    """Colorea texto para la terminal."""
    return f"{COLORS.get(color,'')}{text}{COLORS['reset']}"


def bold(text: str) -> str:
    return f"{COLORS['bold']}{text}{COLORS['reset']}"


def print_banner():
    print()
    print(c("╔══════════════════════════════════════════════════════════════════════╗", 'cyan'))
    print(c("║  🔐  EVALUADOR DE MADUREZ EN SEGURIDAD DE LA INFORMACIÓN            ║", 'cyan'))
    print(c("║      ISO/IEC 27001:2022 — 93 Controles — Modelo de Madurez 0-5      ║", 'cyan'))
    print(c("╚══════════════════════════════════════════════════════════════════════╝", 'cyan'))
    print()


def print_progress_bar(value: float, max_val: float = 5.0, width: int = 40, color: str = 'green') -> str:
    filled = int((value / max_val) * width)
    bar = '█' * filled + '░' * (width - filled)
    return c(f"[{bar}]", color) + f" {value:.2f}/{max_val:.1f}"


def print_report(report):
    """Imprime el reporte completo en consola."""
    level = report.global_level
    color = LEVEL_COLORS.get(level, 'cyan')

    print()
    print(bold("═" * 70))
    print(bold("  📊  RESULTADO DE EVALUACIÓN DE MADUREZ"))
    print(bold("═" * 70))
    print()

    # Score global
    emoji = report.level_emoji
    print(f"  {emoji}  Nivel Global: {c(bold(f'NIVEL {level} — {report.level_name}'), color)}")
    print(f"  📈  Puntuación: {c(bold(f'{report.global_score:.2f} / 5.00'), color)}")
    print(f"  📊  Cumplimiento: {c(bold(f'{report.compliance_percentage:.1f}%'), color)}")
    print(f"  📝  {report.level_info['description']}")
    print()
    print(f"  {print_progress_bar(report.global_score, color=color)}")
    print()

    # Por componente
    print(bold("─" * 70))
    print(bold("  🧩  EVALUACIÓN POR COMPONENTE"))
    print(bold("─" * 70))
    print()

    for domain, comp in report.component_results.items():
        lvl = int(comp.maturity_level)
        comp_color = LEVEL_COLORS.get(lvl, 'cyan')
        print(f"  {bold(comp.component_name)} ({domain})")
        print(f"  {print_progress_bar(comp.maturity_level, color=comp_color)}")
        print(f"  Cumplimiento: {comp.compliance_pct:.1f}% | "
              f"Controles: {comp.compliant_controls}/{comp.total_controls} ✅")
        if comp.critical_findings:
            for finding in comp.critical_findings[:2]:
                print(f"  {c('  ⚠', 'red')} {finding[:90]}...")
        print()

    # Hallazgos críticos
    if report.top_risks:
        print(bold("─" * 70))
        print(bold(c("  🚨  HALLAZGOS CRÍTICOS (Controles con Mayor Brecha)", 'red')))
        print(bold("─" * 70))
        print()
        for ctrl_id, finding in report.top_risks[:8]:
            print(f"  {c(f'[{ctrl_id}]', 'red')} {finding[:80]}")
        print()

    # Recomendaciones
    print(bold("─" * 70))
    print(bold(c("  💡  RECOMENDACIONES PRIORITARIAS", 'cyan')))
    print(bold("─" * 70))
    print()
    for i, rec in enumerate(report.level_info.get('recommendations', []), 1):
        print(f"  {c(str(i), 'cyan')}. {rec}")
    print()

    # Escala de madurez
    print(bold("─" * 70))
    print(bold("  📈  ESCALA DE MADUREZ ISO/IEC 27001:2022"))
    print(bold("─" * 70))
    for lvl_num, info in MATURITY_LEVELS.items():
        marker = "◀ NIVEL ACTUAL" if lvl_num == level else ""
        lvl_color = LEVEL_COLORS.get(lvl_num, 'cyan')
        indicator = c(f"Nivel {lvl_num} — {info['name']:<15}", lvl_color)
        print(f"  {indicator}  {c(marker, color)}")
    print()
    print(bold("═" * 70))


# ─────────────────────────────────────────────
# Flujo principal
# ─────────────────────────────────────────────

def run_analysis(log_files: list, log_types: list, report_format: str = 'console') -> None:
    """Ejecuta el análisis completo sobre logs reales."""
    parser = LogParser()
    evaluator = ControlEvaluator()
    calculator = MaturityCalculator()
    reporter = ReportGenerator()

    print(c("  🔍 Analizando logs...", 'cyan'))
    parsed_logs = []

    for log_file, log_type in zip(log_files, log_types):
        print(f"  📂 [{log_type.upper()}] {log_file}")
        try:
            pl = parser.parse_file(log_file, log_type)
            parsed_logs.append(pl)
            print(f"     {pl.total_lines} líneas procesadas | "
                  f"{pl.total_events} eventos de seguridad detectados")
            if pl.auth_failures:
                print(c(f"     ⚠ Fallos de autenticación: {pl.auth_failures}", 'orange'))
            if pl.brute_force_attempts:
                print(c(f"     🚨 Intentos de fuerza bruta: {pl.brute_force_attempts}", 'red'))
            if pl.malware_indicators:
                print(c(f"     🦠 Indicadores de malware: {pl.malware_indicators}", 'red'))
        except FileNotFoundError as e:
            print(c(f"     ❌ Error: {e}", 'red'))
            sys.exit(1)

    print()
    print(c("  📐 Evaluando controles ISO 27001:2022...", 'cyan'))
    components = evaluator.evaluate(parsed_logs)

    print(c("  🧮 Calculando nivel de madurez...", 'cyan'))
    report = calculator.calculate(components)

    print_report(report)

    if report_format == 'html':
        path = reporter.to_html(report)
        print(c(f"  📄 Reporte HTML guardado en: {path}", 'green'))
    elif report_format == 'json':
        path = reporter.to_json(report)
        print(c(f"  📄 Reporte JSON guardado en: {path}", 'green'))


def run_simulation(target_level: int, report_format: str = 'console') -> None:
    """Ejecuta el análisis con logs simulados."""
    sim = LogSimulator()
    parser = LogParser()
    evaluator = ControlEvaluator()
    calculator = MaturityCalculator()
    reporter = ReportGenerator()

    print(c(f"  🤖 Generando escenario simulado para Nivel {target_level}...", 'cyan'))
    simulated = sim.generate(target_level)

    parsed_logs = []
    for log_type, log_text in simulated.items():
        pl = parser.parse_text(log_text, log_type, f"simulated_{log_type}")
        parsed_logs.append(pl)
        print(f"  📊 [{log_type.upper()}] {pl.total_lines} líneas | {pl.total_events} eventos")

    print()
    components = evaluator.evaluate(parsed_logs)
    report = calculator.calculate(components)

    print_report(report)

    if report_format == 'html':
        path = reporter.to_html(report)
        print(c(f"  📄 Reporte HTML guardado en: {path}", 'green'))
    elif report_format == 'json':
        path = reporter.to_json(report)
        print(c(f"  📄 Reporte JSON guardado en: {path}", 'green'))


def run_sample() -> None:
    """Ejecuta el análisis con logs de muestra incluidos."""
    sample_dir = Path("logs_sample")
    if not sample_dir.exists():
        print(c("  ❌ Directorio logs_sample/ no encontrado.", 'red'))
        print("  Usa --simulate para generar logs de prueba.")
        sys.exit(1)

    logs = []
    types = []
    for log_file in sample_dir.glob("*.log"):
        name = log_file.name
        if 'access' in name:
            logs.append(str(log_file)); types.append('access')
        elif 'auth' in name:
            logs.append(str(log_file)); types.append('auth')
        elif 'sys' in name:
            logs.append(str(log_file)); types.append('syslog')
        elif 'firewall' in name:
            logs.append(str(log_file)); types.append('firewall')

    if not logs:
        print(c("  ❌ No se encontraron logs de muestra.", 'red'))
        sys.exit(1)

    run_analysis(logs, types)


# ─────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────

def main():
    print_banner()

    parser = argparse.ArgumentParser(
        description='Evaluador de Madurez en Seguridad de la Información (ISO/IEC 27001:2022)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos:
  python main.py --log /var/log/auth.log --type auth
  python main.py --log /var/log/auth.log /var/log/syslog --type auth syslog
  python main.py --log /var/log/nginx/access.log --type access --report html
  python main.py --sample
  python main.py --simulate --level 0
  python main.py --simulate --level 3 --report json

Tipos de log soportados:
  access    — Logs HTTP Apache/Nginx (Combined Log Format)
  auth      — /var/log/auth.log (SSH, PAM, sudo)
  syslog    — /var/log/syslog
  firewall  — UFW/iptables logs
  windows   — Windows Event Logs exportados como texto
        """
    )

    # Modo análisis real
    parser.add_argument('--log', nargs='+', metavar='FILE',
                        help='Ruta(s) al archivo(s) de log')
    parser.add_argument('--type', nargs='+',
                        choices=['access', 'auth', 'syslog', 'firewall', 'windows'],
                        metavar='TYPE',
                        help='Tipo(s) de log (debe coincidir con --log en orden)')

    # Modo simulador
    parser.add_argument('--simulate', action='store_true',
                        help='Usa logs simulados en lugar de archivos reales')
    parser.add_argument('--level', type=int, choices=range(6), default=2,
                        metavar='0-5',
                        help='Nivel de madurez a simular (0=Inexistente, 5=Optimizado)')

    # Modo muestra
    parser.add_argument('--sample', action='store_true',
                        help='Usa los logs de muestra incluidos en logs_sample/')

    # Formato de reporte
    parser.add_argument('--report', choices=['console', 'html', 'json'], default='console',
                        help='Formato de reporte de salida (default: console)')

    args = parser.parse_args()

    # Validaciones
    if args.simulate:
        run_simulation(args.level, args.report)
    elif args.sample:
        run_sample()
    elif args.log:
        if not args.type:
            print(c("  ❌ Debes especificar --type para cada archivo en --log", 'red'))
            parser.print_help()
            sys.exit(1)
        if len(args.log) != len(args.type):
            print(c("  ❌ El número de --log y --type debe ser igual", 'red'))
            sys.exit(1)
        run_analysis(args.log, args.type, args.report)
    else:
        print(c("  ℹ  No se especificó ningún modo. Ejecutando simulación nivel 2...\n", 'cyan'))
        print("  Sugerencia: usa --help para ver todas las opciones.\n")
        run_simulation(2, args.report)


if __name__ == '__main__':
    main()
