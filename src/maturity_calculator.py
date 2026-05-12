"""
maturity_calculator.py — Cálculo del nivel global de madurez
Aplica la fórmula NM = Σ(Ci) / N y determina el nivel 0-5.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Tuple
from src.control_evaluator import ComponentResult


# ─────────────────────────────────────────────
# Definición de niveles de madurez
# ─────────────────────────────────────────────

MATURITY_LEVELS = {
    0: {
        'name': 'Inexistente',
        'color': 'red',
        'emoji': '🔴',
        'description': 'No existen controles definidos ni documentados.',
        'range': (0.0, 0.99),
        'recommendations': [
            'Definir una política de seguridad de la información de inmediato.',
            'Identificar y documentar todos los activos de información.',
            'Asignar un responsable de seguridad de la información.',
            'Implementar controles básicos de acceso.',
            'Comenzar con un inventario de riesgos.',
        ]
    },
    1: {
        'name': 'Inicial',
        'color': 'orange',
        'emoji': '🟠',
        'description': 'Existen actividades básicas ejecutadas de manera informal.',
        'range': (1.0, 1.99),
        'recommendations': [
            'Formalizar y documentar los procesos de seguridad existentes.',
            'Implementar gestión de contraseñas y autenticación segura.',
            'Establecer procedimientos de respuesta a incidentes básicos.',
            'Realizar capacitación inicial en seguridad al personal.',
            'Implementar copias de seguridad periódicas.',
        ]
    },
    2: {
        'name': 'Gestionado',
        'color': 'yellow',
        'emoji': '🟡',
        'description': 'Los controles se encuentran documentados y parcialmente implementados.',
        'range': (2.0, 2.99),
        'recommendations': [
            'Completar la implementación de los controles documentados.',
            'Establecer un proceso formal de gestión de vulnerabilidades.',
            'Implementar autenticación multifactor (MFA).',
            'Configurar sistemas de monitoreo de logs centralizados.',
            'Formalizar la gestión de acceso privilegiado.',
        ]
    },
    3: {
        'name': 'Definido',
        'color': 'blue',
        'emoji': '🔵',
        'description': 'Los procesos y controles son formalizados y aplicados.',
        'range': (3.0, 3.99),
        'recommendations': [
            'Implementar métricas de seguridad y KPIs.',
            'Establecer revisiones periódicas de cumplimiento.',
            'Integrar herramientas SIEM para correlación de eventos.',
            'Implementar pruebas de penetración anuales.',
            'Fortalecer el programa de concientización en seguridad.',
        ]
    },
    4: {
        'name': 'Medido',
        'color': 'green',
        'emoji': '🟢',
        'description': 'Existen métricas, monitoreo y evaluación continua.',
        'range': (4.0, 4.99),
        'recommendations': [
            'Avanzar hacia automatización de respuesta a incidentes.',
            'Implementar inteligencia de amenazas (Threat Intelligence).',
            'Optimizar procesos mediante análisis de datos de seguridad.',
            'Explorar integración de IA/ML para detección de anomalías.',
            'Establecer un programa de mejora continua formal (PDCA).',
        ]
    },
    5: {
        'name': 'Optimizado',
        'color': 'purple',
        'emoji': '🟣',
        'description': 'Los controles son mejorados continuamente mediante automatización y mejora continua.',
        'range': (5.0, 5.0),
        'recommendations': [
            'Mantener y fortalecer el programa de mejora continua.',
            'Compartir prácticas con el sector para elevar el estándar.',
            'Explorar certificación ISO/IEC 27001 formal.',
            'Implementar Zero Trust Architecture.',
            'Liderar iniciativas de ciberseguridad en el sector.',
        ]
    }
}

# Pesos de los componentes (pueden ajustarse según la organización)
COMPONENT_WEIGHTS = {
    'A5': 0.35,  # Organizacional (37 controles)
    'A6': 0.10,  # Personas (8 controles)
    'A7': 0.15,  # Física (14 controles)
    'A8': 0.40,  # Tecnológica (34 controles)
}


@dataclass
class MaturityReport:
    """Resultado completo de evaluación de madurez."""
    global_score: float
    global_level: int
    level_info: dict
    component_results: Dict[str, ComponentResult]
    all_findings: List[str] = field(default_factory=list)
    top_risks: List[Tuple[str, str]] = field(default_factory=list)  # (control_id, finding)

    @property
    def compliance_percentage(self) -> float:
        return (self.global_score / 5.0) * 100

    @property
    def level_name(self) -> str:
        return self.level_info['name']

    @property
    def level_emoji(self) -> str:
        return self.level_info['emoji']


# ─────────────────────────────────────────────
# Calculador principal
# ─────────────────────────────────────────────

class MaturityCalculator:
    """Calcula el nivel de madurez global a partir de los resultados de componentes."""

    def calculate(self, component_results: Dict[str, ComponentResult]) -> MaturityReport:
        """
        Calcula el nivel de madurez global usando promedio ponderado.

        Fórmula: NM_global = Σ(NM_componente * peso) / Σ(pesos)
        """
        weighted_sum = 0.0
        total_weight = 0.0

        for domain, component in component_results.items():
            weight = COMPONENT_WEIGHTS.get(domain, 0.25)
            weighted_sum += component.maturity_level * weight
            total_weight += weight

        global_score = weighted_sum / total_weight if total_weight > 0 else 0.0
        global_score = round(min(5.0, max(0.0, global_score)), 2)

        global_level = self._score_to_level(global_score)
        level_info = MATURITY_LEVELS[global_level]

        # Recopilar todos los hallazgos
        all_findings = []
        top_risks = []
        for component in component_results.values():
            for ctrl in component.controls:
                for finding in ctrl.findings:
                    all_findings.append(f"[{ctrl.control_id}] {finding}")
                    if ctrl.score < 2.0:
                        top_risks.append((ctrl.control_id, finding))

        # Ordenar top risks por severidad (score más bajo primero)
        top_risks = sorted(top_risks, key=lambda x: x[0])[:10]

        return MaturityReport(
            global_score=global_score,
            global_level=global_level,
            level_info=level_info,
            component_results=component_results,
            all_findings=all_findings,
            top_risks=top_risks,
        )

    def _score_to_level(self, score: float) -> int:
        """Convierte puntuación numérica a nivel de madurez (0-5)."""
        if score >= 5.0:
            return 5
        for level, info in MATURITY_LEVELS.items():
            low, high = info['range']
            if low <= score <= high:
                return level
        return 0

    def get_maturity_description(self, level: int) -> dict:
        return MATURITY_LEVELS.get(level, MATURITY_LEVELS[0])
