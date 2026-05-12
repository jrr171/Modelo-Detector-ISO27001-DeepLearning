"""
control_evaluator.py — Evaluación de controles ISO/IEC 27001:2022
Mapea eventos de log a los 93 controles y asigna puntuaciones de cumplimiento.
"""

from dataclasses import dataclass, field
from typing import Dict, List
from src.log_parser import ParsedLog


# ─────────────────────────────────────────────
# Estructuras de datos
# ─────────────────────────────────────────────

@dataclass
class ControlResult:
    """Resultado de evaluación de un control ISO 27001."""
    control_id: str          # e.g. "A.8.16"
    name: str
    domain: str              # A.5, A.6, A.7, A.8
    score: float             # 0.0 a 5.0
    max_score: float = 5.0
    findings: List[str] = field(default_factory=list)
    compliant: bool = False

    @property
    def compliance_pct(self) -> float:
        return (self.score / self.max_score) * 100


@dataclass
class ComponentResult:
    """Resultado de evaluación de un componente (dominio ISO)."""
    component_name: str
    domain: str
    controls: List[ControlResult] = field(default_factory=list)

    @property
    def maturity_level(self) -> float:
        """Nivel de madurez del componente: NM = Σ(Ci) / N"""
        if not self.controls:
            return 0.0
        return sum(c.score for c in self.controls) / len(self.controls)

    @property
    def compliance_pct(self) -> float:
        return (self.maturity_level / 5.0) * 100

    @property
    def total_controls(self) -> int:
        return len(self.controls)

    @property
    def compliant_controls(self) -> int:
        return sum(1 for c in self.controls if c.compliant)

    @property
    def critical_findings(self) -> List[str]:
        findings = []
        for ctrl in self.controls:
            if ctrl.score < 2.0:
                findings.extend(ctrl.findings)
        return findings


# ─────────────────────────────────────────────
# Evaluador principal
# ─────────────────────────────────────────────

class ControlEvaluator:
    """
    Evalúa los 93 controles de la ISO/IEC 27001:2022
    a partir de los eventos detectados en los logs.
    """

    def evaluate(self, parsed_logs: List[ParsedLog]) -> Dict[str, ComponentResult]:
        """
        Evalúa todos los componentes y retorna sus resultados.

        Args:
            parsed_logs: Lista de logs parseados.

        Returns:
            Diccionario {domain: ComponentResult}
        """
        # Agregar métricas de todos los logs
        metrics = self._aggregate_metrics(parsed_logs)

        return {
            'A5': self._evaluate_organizational(metrics),
            'A6': self._evaluate_people(metrics),
            'A7': self._evaluate_physical(metrics),
            'A8': self._evaluate_technological(metrics),
        }

    # ─────────────────────────────────────────
    # Agregación de métricas
    # ─────────────────────────────────────────

    def _aggregate_metrics(self, logs: List[ParsedLog]) -> dict:
        """Combina métricas de múltiples logs en un único diccionario."""
        m = {
            'auth_failures': 0,
            'brute_force_attempts': 0,
            'unauthorized_access': 0,
            'privilege_escalations': 0,
            'suspicious_ips': 0,
            'failed_services': 0,
            'malware_indicators': 0,
            'config_changes': 0,
            'data_exfiltration_hints': 0,
            'unencrypted_connections': 0,
            'total_events': 0,
            'critical_events': 0,
        }
        for log in logs:
            m['auth_failures'] += log.auth_failures
            m['brute_force_attempts'] += log.brute_force_attempts
            m['unauthorized_access'] += log.unauthorized_access
            m['privilege_escalations'] += log.privilege_escalations
            m['suspicious_ips'] += log.suspicious_ips
            m['failed_services'] += log.failed_services
            m['malware_indicators'] += log.malware_indicators
            m['config_changes'] += log.config_changes
            m['data_exfiltration_hints'] += log.data_exfiltration_hints
            m['unencrypted_connections'] += log.unencrypted_connections
            m['total_events'] += log.total_events
            m['critical_events'] += len(log.critical_events)
        return m

    # ─────────────────────────────────────────
    # A.5 — Gestión Organizacional (37 controles)
    # ─────────────────────────────────────────

    def _evaluate_organizational(self, m: dict) -> ComponentResult:
        comp = ComponentResult(
            component_name="Gestión Organizacional de Seguridad",
            domain="A.5"
        )

        # A.5.1 — Políticas de seguridad de la información
        score = 5.0
        findings = []
        if m['config_changes'] > 20:
            score -= 2.0
            findings.append(f"Cambios de configuración frecuentes detectados: {m['config_changes']}. Posible ausencia de política de gestión de cambios.")
        if m['config_changes'] > 5:
            score -= 1.0
        comp.controls.append(ControlResult('A.5.1', 'Políticas de seguridad de la información', 'A.5', max(0, score), findings=findings, compliant=score >= 3))

        # A.5.2 — Roles y responsabilidades
        score = 5.0
        findings = []
        if m['privilege_escalations'] > 10:
            score -= 2.0
            findings.append(f"Escalaciones de privilegios elevadas: {m['privilege_escalations']}. Rol/responsabilidades de acceso no definidos correctamente.")
        elif m['privilege_escalations'] > 3:
            score -= 1.0
        comp.controls.append(ControlResult('A.5.2', 'Roles y responsabilidades de seguridad', 'A.5', max(0, score), findings=findings, compliant=score >= 3))

        # A.5.7 — Inteligencia de amenazas
        score = 5.0
        findings = []
        if m['brute_force_attempts'] > 0:
            score -= 1.5
            findings.append(f"Intentos de fuerza bruta no bloqueados tempranamente: {m['brute_force_attempts']}. Sin inteligencia de amenazas activa.")
        if m['suspicious_ips'] > 5:
            score -= 1.5
            findings.append(f"IPs/escaneos de puertos sospechosos detectados: {m['suspicious_ips']}.")
        comp.controls.append(ControlResult('A.5.7', 'Inteligencia de amenazas', 'A.5', max(0, score), findings=findings, compliant=score >= 3))

        # A.5.14 — Transferencia de información
        score = 5.0
        findings = []
        if m['unencrypted_connections'] > 0:
            score -= 2.5
            findings.append(f"Conexiones sin cifrado detectadas: {m['unencrypted_connections']}. Riesgo de exposición de información en tránsito.")
        if m['data_exfiltration_hints'] > 0:
            score -= 2.5
            findings.append(f"Indicadores de exfiltración de datos: {m['data_exfiltration_hints']}.")
        comp.controls.append(ControlResult('A.5.14', 'Transferencia de información', 'A.5', max(0, score), findings=findings, compliant=score >= 3))

        # A.5.23 — Seguridad de servicios en la nube
        score = 4.0  # Sin evidencia directa en logs, asumimos implementación parcial
        comp.controls.append(ControlResult('A.5.23', 'Seguridad de servicios en la nube', 'A.5', score, findings=[], compliant=score >= 3))

        # A.5.24 — Planificación de gestión de incidentes
        score = 5.0
        findings = []
        if m['critical_events'] > 10:
            score -= 2.0
            findings.append(f"Alto número de eventos críticos sin respuesta aparente: {m['critical_events']}.")
        if m['malware_indicators'] > 0:
            score -= 1.5
            findings.append(f"Indicadores de malware sin contención: {m['malware_indicators']}.")
        comp.controls.append(ControlResult('A.5.24', 'Planificación de gestión de incidentes', 'A.5', max(0, score), findings=findings, compliant=score >= 3))

        # A.5.25 — Evaluación de incidentes
        score = 5.0 if m['critical_events'] < 5 else 3.0
        comp.controls.append(ControlResult('A.5.25', 'Evaluación y decisión sobre incidentes', 'A.5', score, compliant=score >= 3))

        # A.5.26 — Respuesta a incidentes
        score = 5.0
        findings = []
        if m['malware_indicators'] > 0 and m['critical_events'] > 5:
            score -= 3.0
            findings.append("Evidencia de incidentes críticos sin respuesta efectiva detectada en logs.")
        comp.controls.append(ControlResult('A.5.26', 'Respuesta a incidentes de seguridad', 'A.5', max(0, score), findings=findings, compliant=score >= 3))

        # A.5.28 — Recolección de evidencia
        score = 4.0 if m['total_events'] > 0 else 2.0
        findings = ["Logs disponibles para análisis forense." if m['total_events'] > 0 else "Sin logs suficientes para evidencia forense."]
        comp.controls.append(ControlResult('A.5.28', 'Recolección de evidencia', 'A.5', score, findings=findings, compliant=score >= 3))

        # A.5.29 — Continuidad de seguridad
        score = 5.0
        if m['failed_services'] > 5:
            score -= 2.0
        comp.controls.append(ControlResult('A.5.29', 'Seguridad de la información en continuidad', 'A.5', max(0, score), compliant=score >= 3))

        # Rellenar hasta 37 controles con evaluación genérica basada en métricas globales
        remaining_controls = [
            ('A.5.3', 'Segregación de funciones'), ('A.5.4', 'Responsabilidades de la dirección'),
            ('A.5.5', 'Contacto con autoridades'), ('A.5.6', 'Contacto con grupos de interés especial'),
            ('A.5.8', 'Seguridad en gestión de proyectos'), ('A.5.9', 'Inventario de información'),
            ('A.5.10', 'Uso aceptable de información'), ('A.5.11', 'Devolución de activos'),
            ('A.5.12', 'Clasificación de información'), ('A.5.13', 'Etiquetado de información'),
            ('A.5.15', 'Control de acceso'), ('A.5.16', 'Gestión de identidad'),
            ('A.5.17', 'Información de autenticación'), ('A.5.18', 'Derechos de acceso'),
            ('A.5.19', 'Seguridad en relaciones con proveedores'), ('A.5.20', 'Gestión de seguridad en cadena de suministro'),
            ('A.5.21', 'Gestión de seguridad en TIC'), ('A.5.22', 'Seguimiento de proveedores'),
            ('A.5.27', 'Aprendizaje de incidentes'), ('A.5.30', 'Preparación TIC para continuidad'),
            ('A.5.31', 'Requisitos legales y regulatorios'), ('A.5.32', 'Derechos de propiedad intelectual'),
            ('A.5.33', 'Protección de registros'), ('A.5.34', 'Privacidad y PII'),
            ('A.5.35', 'Revisión independiente de seguridad'), ('A.5.36', 'Cumplimiento de políticas'),
            ('A.5.37', 'Procedimientos de operación documentados'),
        ]
        base_score = self._base_score_from_metrics(m)
        for ctrl_id, ctrl_name in remaining_controls:
            comp.controls.append(ControlResult(ctrl_id, ctrl_name, 'A.5', base_score, compliant=base_score >= 3))

        return comp

    # ─────────────────────────────────────────
    # A.6 — Gestión de Personas (8 controles)
    # ─────────────────────────────────────────

    def _evaluate_people(self, m: dict) -> ComponentResult:
        comp = ComponentResult(
            component_name="Gestión de Seguridad del Personal",
            domain="A.6"
        )

        # A.6.1 — Selección
        score = 4.0
        comp.controls.append(ControlResult('A.6.1', 'Selección de personal', 'A.6', score, compliant=True))

        # A.6.2 — Términos y condiciones de empleo
        score = 4.0
        comp.controls.append(ControlResult('A.6.2', 'Términos y condiciones de empleo', 'A.6', score, compliant=True))

        # A.6.3 — Concienciación, educación y formación
        score = 5.0
        findings = []
        if m['auth_failures'] > 50:
            score -= 2.0
            findings.append(f"Alto número de fallos de autenticación ({m['auth_failures']}), posible falta de formación en seguridad.")
        if m['unencrypted_connections'] > 0:
            score -= 1.0
            findings.append("Uso de conexiones sin cifrar detectado, indica falta de concienciación.")
        comp.controls.append(ControlResult('A.6.3', 'Concienciación, educación y formación', 'A.6', max(0, score), findings=findings, compliant=score >= 3))

        # A.6.4 — Proceso disciplinario
        score = 3.5
        comp.controls.append(ControlResult('A.6.4', 'Proceso disciplinario', 'A.6', score, compliant=True))

        # A.6.5 — Responsabilidades tras el cese
        score = 3.0
        comp.controls.append(ControlResult('A.6.5', 'Responsabilidades tras el cese', 'A.6', score, compliant=True))

        # A.6.6 — Acuerdos de confidencialidad
        score = 4.0
        comp.controls.append(ControlResult('A.6.6', 'Acuerdos de confidencialidad', 'A.6', score, compliant=True))

        # A.6.7 — Trabajo remoto
        score = 5.0
        findings = []
        if m['unencrypted_connections'] > 2:
            score -= 2.0
            findings.append("Conexiones remotas sin cifrado detectadas. Riesgo en trabajo remoto.")
        comp.controls.append(ControlResult('A.6.7', 'Trabajo remoto', 'A.6', max(0, score), findings=findings, compliant=score >= 3))

        # A.6.8 — Reporte de eventos de seguridad
        score = 5.0
        findings = []
        if m['critical_events'] > 5 and m['total_events'] < 10:
            score -= 3.0
            findings.append("Eventos críticos detectados pero sin evidencia de reporte formal.")
        comp.controls.append(ControlResult('A.6.8', 'Reporte de eventos de seguridad', 'A.6', max(0, score), findings=findings, compliant=score >= 3))

        return comp

    # ─────────────────────────────────────────
    # A.7 — Seguridad Física (14 controles)
    # ─────────────────────────────────────────

    def _evaluate_physical(self, m: dict) -> ComponentResult:
        comp = ComponentResult(
            component_name="Gestión de Seguridad Física",
            domain="A.7"
        )

        physical_controls = [
            ('A.7.1', 'Perímetros de seguridad física', 4.0),
            ('A.7.2', 'Controles de entrada física', 4.0),
            ('A.7.3', 'Protección de oficinas y salas', 4.0),
            ('A.7.4', 'Monitoreo de seguridad física', 3.5),
            ('A.7.5', 'Protección contra amenazas físicas', 4.0),
            ('A.7.6', 'Trabajo en áreas seguras', 3.5),
            ('A.7.7', 'Escritorio y pantalla limpios', 3.0),
            ('A.7.8', 'Ubicación y protección de equipos', 4.0),
            ('A.7.9', 'Seguridad de activos fuera de las instalaciones', 3.5),
            ('A.7.10', 'Medios de almacenamiento', 3.5),
            ('A.7.11', 'Servicios de suministro', 3.5),
            ('A.7.12', 'Seguridad del cableado', 3.5),
            ('A.7.13', 'Mantenimiento de equipos', 3.5),
            ('A.7.14', 'Eliminación o reutilización segura de equipos', 3.0),
        ]

        # Ajustes basados en métricas de logs (indicadores indirectos)
        base_adjustment = 0
        findings_physical = []
        if m['suspicious_ips'] > 10:
            base_adjustment -= 0.5
            findings_physical.append("Actividad de red sospechosa podría indicar acceso físico no autorizado a infraestructura.")
        if m['failed_services'] > 5:
            base_adjustment -= 0.5
            findings_physical.append(f"Servicios fallidos ({m['failed_services']}) pueden indicar problemas de energía o hardware.")

        for ctrl_id, ctrl_name, base_score in physical_controls:
            adj_score = max(0, min(5, base_score + base_adjustment))
            comp.controls.append(ControlResult(
                ctrl_id, ctrl_name, 'A.7', adj_score,
                findings=findings_physical if base_adjustment < 0 else [],
                compliant=adj_score >= 3
            ))

        return comp

    # ─────────────────────────────────────────
    # A.8 — Seguridad Tecnológica (34 controles)
    # ─────────────────────────────────────────

    def _evaluate_technological(self, m: dict) -> ComponentResult:
        comp = ComponentResult(
            component_name="Gestión Tecnológica de Seguridad",
            domain="A.8"
        )

        # A.8.1 — Dispositivos de usuario final
        score = 5.0
        findings = []
        if m['unauthorized_access'] > 5:
            score -= 2.0
            findings.append(f"Accesos no autorizados desde dispositivos ({m['unauthorized_access']}). Control de endpoints deficiente.")
        comp.controls.append(ControlResult('A.8.1', 'Dispositivos de usuario final', 'A.8', max(0, score), findings=findings, compliant=score >= 3))

        # A.8.2 — Derechos de acceso privilegiado
        score = 5.0
        findings = []
        if m['privilege_escalations'] > 5:
            score -= 3.0
            findings.append(f"Escalaciones de privilegios excesivas: {m['privilege_escalations']}. Control de acceso privilegiado deficiente.")
        elif m['privilege_escalations'] > 2:
            score -= 1.5
        comp.controls.append(ControlResult('A.8.2', 'Derechos de acceso privilegiado', 'A.8', max(0, score), findings=findings, compliant=score >= 3))

        # A.8.3 — Restricción de acceso a información
        score = 5.0
        findings = []
        if m['unauthorized_access'] > 10:
            score -= 3.0
            findings.append(f"Múltiples accesos no autorizados: {m['unauthorized_access']}.")
        elif m['unauthorized_access'] > 3:
            score -= 1.5
        comp.controls.append(ControlResult('A.8.3', 'Restricción de acceso a información', 'A.8', max(0, score), findings=findings, compliant=score >= 3))

        # A.8.4 — Acceso al código fuente
        score = 4.0
        comp.controls.append(ControlResult('A.8.4', 'Acceso al código fuente', 'A.8', score, compliant=True))

        # A.8.5 — Autenticación segura
        score = 5.0
        findings = []
        if m['brute_force_attempts'] > 0:
            score -= 3.0
            findings.append(f"Intentos de fuerza bruta exitosos/sin bloqueo: {m['brute_force_attempts']}. Autenticación insegura.")
        if m['auth_failures'] > 100:
            score -= 1.5
            findings.append(f"Volumen alto de fallos de autenticación: {m['auth_failures']}. Sin MFA o bloqueo automático.")
        comp.controls.append(ControlResult('A.8.5', 'Autenticación segura', 'A.8', max(0, score), findings=findings, compliant=score >= 3))

        # A.8.6 — Gestión de capacidad
        score = 5.0
        if m['failed_services'] > 3:
            score -= 2.0
        comp.controls.append(ControlResult('A.8.6', 'Gestión de capacidad', 'A.8', max(0, score), compliant=score >= 3))

        # A.8.7 — Protección contra malware
        score = 5.0
        findings = []
        if m['malware_indicators'] > 0:
            score -= 4.0
            findings.append(f"¡Indicadores de malware detectados en logs!: {m['malware_indicators']}. Protección antimalware insuficiente.")
        comp.controls.append(ControlResult('A.8.7', 'Protección contra malware', 'A.8', max(0, score), findings=findings, compliant=score >= 3))

        # A.8.8 — Gestión de vulnerabilidades técnicas
        score = 5.0
        findings = []
        if m['suspicious_ips'] > 0:
            score -= 1.5
            findings.append(f"Escaneos de puertos detectados: {m['suspicious_ips']}. Posibles vulnerabilidades expuestas.")
        if m['unauthorized_access'] > 5:
            score -= 1.5
        comp.controls.append(ControlResult('A.8.8', 'Gestión de vulnerabilidades técnicas', 'A.8', max(0, score), findings=findings, compliant=score >= 3))

        # A.8.9 — Gestión de la configuración
        score = 5.0
        findings = []
        if m['config_changes'] > 10:
            score -= 2.5
            findings.append(f"Cambios de configuración no controlados: {m['config_changes']}. Sin baseline de configuración segura.")
        comp.controls.append(ControlResult('A.8.9', 'Gestión de la configuración', 'A.8', max(0, score), findings=findings, compliant=score >= 3))

        # A.8.10 — Eliminación de información
        score = 3.5
        comp.controls.append(ControlResult('A.8.10', 'Eliminación de información', 'A.8', score, compliant=True))

        # A.8.11 — Enmascaramiento de datos
        score = 3.5
        comp.controls.append(ControlResult('A.8.11', 'Enmascaramiento de datos', 'A.8', score, compliant=True))

        # A.8.12 — Prevención de fuga de información
        score = 5.0
        findings = []
        if m['data_exfiltration_hints'] > 0:
            score -= 4.0
            findings.append(f"Posible exfiltración de datos detectada: {m['data_exfiltration_hints']} indicadores. Sin DLP efectivo.")
        comp.controls.append(ControlResult('A.8.12', 'Prevención de fuga de información (DLP)', 'A.8', max(0, score), findings=findings, compliant=score >= 3))

        # A.8.13 — Copias de seguridad
        score = 4.0
        comp.controls.append(ControlResult('A.8.13', 'Copias de seguridad', 'A.8', score, compliant=True))

        # A.8.14 — Redundancia de instalaciones
        score = 5.0
        if m['failed_services'] > 5:
            score -= 2.5
        comp.controls.append(ControlResult('A.8.14', 'Redundancia de instalaciones de procesamiento', 'A.8', max(0, score), compliant=score >= 3))

        # A.8.15 — Registro de actividades (logging)
        score = 5.0
        findings = []
        if m['total_events'] == 0:
            score -= 4.0
            findings.append("Sin eventos en logs. El registro de actividades no está configurado.")
        elif m['total_events'] < 10:
            score -= 2.0
            findings.append("Muy pocos eventos registrados. Logging insuficiente.")
        comp.controls.append(ControlResult('A.8.15', 'Registro de actividades (Logging)', 'A.8', max(0, score), findings=findings, compliant=score >= 3))

        # A.8.16 — Monitoreo de actividades
        score = 5.0
        findings = []
        if m['brute_force_attempts'] > 0 and m['critical_events'] > 5:
            score -= 3.0
            findings.append("Ataques activos sin respuesta de monitoreo. Sistema de monitoreo inefectivo.")
        elif m['critical_events'] > 3:
            score -= 1.5
        comp.controls.append(ControlResult('A.8.16', 'Monitoreo de actividades', 'A.8', max(0, score), findings=findings, compliant=score >= 3))

        # A.8.17 — Sincronización de relojes
        score = 4.0
        comp.controls.append(ControlResult('A.8.17', 'Sincronización de relojes', 'A.8', score, compliant=True))

        # A.8.18 — Uso de programas utilitarios privilegiados
        score = 5.0
        if m['privilege_escalations'] > 3:
            score -= 2.0
        comp.controls.append(ControlResult('A.8.18', 'Uso de programas utilitarios privilegiados', 'A.8', max(0, score), compliant=score >= 3))

        # A.8.19 — Instalación de software
        score = 4.5
        comp.controls.append(ControlResult('A.8.19', 'Instalación de software en sistemas operativos', 'A.8', score, compliant=True))

        # A.8.20 — Seguridad en redes
        score = 5.0
        findings = []
        if m['suspicious_ips'] > 5:
            score -= 2.5
            findings.append(f"Escaneos/amenazas de red no bloqueadas: {m['suspicious_ips']}.")
        if m['unencrypted_connections'] > 0:
            score -= 1.5
            findings.append(f"Tráfico de red sin cifrar detectado: {m['unencrypted_connections']}.")
        comp.controls.append(ControlResult('A.8.20', 'Seguridad en redes', 'A.8', max(0, score), findings=findings, compliant=score >= 3))

        # A.8.21 — Seguridad de servicios de red
        score = 5.0
        if m['failed_services'] > 3:
            score -= 2.0
        comp.controls.append(ControlResult('A.8.21', 'Seguridad de servicios de red', 'A.8', max(0, score), compliant=score >= 3))

        # A.8.22 — Segregación de redes
        score = 4.0
        comp.controls.append(ControlResult('A.8.22', 'Segregación de redes', 'A.8', score, compliant=True))

        # A.8.23 — Filtrado Web
        score = 5.0
        if m['unauthorized_access'] > 5:
            score -= 2.0
        comp.controls.append(ControlResult('A.8.23', 'Filtrado Web', 'A.8', max(0, score), compliant=score >= 3))

        # A.8.24 — Uso de criptografía
        score = 5.0
        if m['unencrypted_connections'] > 3:
            score -= 3.0
        elif m['unencrypted_connections'] > 0:
            score -= 1.5
        comp.controls.append(ControlResult('A.8.24', 'Uso de criptografía', 'A.8', max(0, score), compliant=score >= 3))

        # A.8.25 — Ciclo de vida de desarrollo seguro
        score = 3.5
        comp.controls.append(ControlResult('A.8.25', 'Ciclo de vida de desarrollo seguro (SDLC)', 'A.8', score, compliant=True))

        # A.8.26 — Requisitos de seguridad en aplicaciones
        score = 4.0
        comp.controls.append(ControlResult('A.8.26', 'Requisitos de seguridad en aplicaciones', 'A.8', score, compliant=True))

        # A.8.27 — Principios de arquitectura segura
        score = 4.0
        comp.controls.append(ControlResult('A.8.27', 'Principios de arquitectura segura', 'A.8', score, compliant=True))

        # A.8.28 — Codificación segura
        score = 3.5
        comp.controls.append(ControlResult('A.8.28', 'Codificación segura', 'A.8', score, compliant=True))

        # A.8.29 — Pruebas de seguridad en desarrollo
        score = 3.5
        comp.controls.append(ControlResult('A.8.29', 'Pruebas de seguridad en desarrollo', 'A.8', score, compliant=True))

        # A.8.30 — Desarrollo externalizado
        score = 3.5
        comp.controls.append(ControlResult('A.8.30', 'Desarrollo externalizado', 'A.8', score, compliant=True))

        # A.8.31 — Separación de entornos
        score = 4.0
        comp.controls.append(ControlResult('A.8.31', 'Separación de entornos (dev/test/prod)', 'A.8', score, compliant=True))

        # A.8.32 — Gestión de cambios
        score = 5.0
        if m['config_changes'] > 15:
            score -= 2.5
        comp.controls.append(ControlResult('A.8.32', 'Gestión de cambios', 'A.8', max(0, score), compliant=score >= 3))

        # A.8.33 — Información de prueba
        score = 3.5
        comp.controls.append(ControlResult('A.8.33', 'Información de prueba', 'A.8', score, compliant=True))

        # A.8.34 — Protección de sistemas de información durante auditoría
        score = 4.0
        comp.controls.append(ControlResult('A.8.34', 'Protección durante auditoría', 'A.8', score, compliant=True))

        return comp

    # ─────────────────────────────────────────
    # Helpers
    # ─────────────────────────────────────────

    def _base_score_from_metrics(self, m: dict) -> float:
        """Calcula un puntaje base genérico a partir de métricas globales."""
        penalty = 0
        if m['auth_failures'] > 50:
            penalty += 0.5
        if m['brute_force_attempts'] > 0:
            penalty += 1.0
        if m['malware_indicators'] > 0:
            penalty += 1.5
        if m['data_exfiltration_hints'] > 0:
            penalty += 1.0
        if m['unencrypted_connections'] > 0:
            penalty += 0.5
        return max(1.0, 4.0 - penalty)
