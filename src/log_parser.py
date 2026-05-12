"""
log_parser.py — Parseo de logs de servidor
Soporta: access logs (Apache/Nginx), auth.log, syslog, firewall logs, Windows event logs
"""

import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import List, Optional


# ─────────────────────────────────────────────
# Estructuras de datos
# ─────────────────────────────────────────────

@dataclass
class LogEvent:
    """Representa un evento individual extraído de un log."""
    timestamp: Optional[datetime]
    source_ip: Optional[str]
    user: Optional[str]
    action: str
    status: Optional[str]         # success / failure / warning
    raw: str
    event_type: str               # auth_failure, access_denied, port_scan, etc.
    severity: int = 0             # 0=info, 1=low, 2=medium, 3=high, 4=critical


@dataclass
class ParsedLog:
    """Resultado del parseo de un archivo de log."""
    log_type: str
    file_path: str
    events: List[LogEvent] = field(default_factory=list)
    parse_errors: int = 0
    total_lines: int = 0

    # Conteos por categoría de evento
    auth_failures: int = 0
    brute_force_attempts: int = 0
    unauthorized_access: int = 0
    privilege_escalations: int = 0
    suspicious_ips: int = 0
    failed_services: int = 0
    malware_indicators: int = 0
    config_changes: int = 0
    data_exfiltration_hints: int = 0
    unencrypted_connections: int = 0

    @property
    def total_events(self) -> int:
        return len(self.events)

    @property
    def critical_events(self) -> List[LogEvent]:
        return [e for e in self.events if e.severity >= 3]


# ─────────────────────────────────────────────
# Patrones de detección
# ─────────────────────────────────────────────

class EventPatterns:
    """Patrones regex para detectar eventos de seguridad en logs."""

    # Auth / SSH
    AUTH_FAILURE = re.compile(
        r'(Failed password|authentication failure|Invalid user|'
        r'FAILED LOGIN|Autenticación fallida|pam_unix.*failure)',
        re.IGNORECASE
    )
    AUTH_SUCCESS = re.compile(
        r'(Accepted password|Accepted publickey|session opened|'
        r'successful login)',
        re.IGNORECASE
    )
    BRUTE_FORCE = re.compile(
        r'(repeated login failures|many authentication failures|'
        r'POSSIBLE BREAK-IN ATTEMPT|maximum authentication attempts)',
        re.IGNORECASE
    )
    SUDO_USE = re.compile(r'sudo.*COMMAND=', re.IGNORECASE)
    SU_ATTEMPT = re.compile(r'su\[.*\]', re.IGNORECASE)

    # Red / Acceso
    PORT_SCAN = re.compile(
        r'(nmap|port scan|SYN flood|XMAS scan|NULL scan)',
        re.IGNORECASE
    )
    UNENCRYPTED = re.compile(
        r'(telnet|ftp|http(?!s)|plain.*text|cleartext|unencrypted)',
        re.IGNORECASE
    )
    FIREWALL_BLOCK = re.compile(r'(UFW BLOCK|IPTABLES DROP|REJECT|DENY)', re.IGNORECASE)

    # Acceso web
    SQL_INJECTION = re.compile(
        r"(UNION SELECT|OR 1=1|DROP TABLE|INSERT INTO|--|/\*.*\*/|'.*'.*=.*')",
        re.IGNORECASE
    )
    XSS_ATTEMPT = re.compile(r'(<script|javascript:|onerror=|onload=)', re.IGNORECASE)
    PATH_TRAVERSAL = re.compile(r'(\.\./|\.\.\\|%2e%2e)', re.IGNORECASE)
    HTTP_403 = re.compile(r'" 403 ')
    HTTP_500 = re.compile(r'" 5\d\d ')

    # Sistema
    SERVICE_FAILURE = re.compile(
        r'(service.*failed|unit.*failed|error.*start|crash|'
        r'kernel panic|OOM killer)',
        re.IGNORECASE
    )
    CONFIG_CHANGE = re.compile(
        r'(configuration changed|config.*modified|sudoers|'
        r'passwd.*changed|crontab)',
        re.IGNORECASE
    )
    MALWARE_HINT = re.compile(
        r'(malware|virus|trojan|ransomware|rootkit|backdoor|'
        r'suspicious.*process|unknown.*binary)',
        re.IGNORECASE
    )
    DATA_EXFIL = re.compile(
        r'(large.*transfer|unusual.*traffic|outbound.*connection|'
        r'data.*leak|exfiltrat)',
        re.IGNORECASE
    )

    # IPs
    IP_PATTERN = re.compile(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b')
    USER_PATTERN = re.compile(r'(?:user|for|from)\s+(\w+)', re.IGNORECASE)


# ─────────────────────────────────────────────
# Parsers por tipo de log
# ─────────────────────────────────────────────

class LogParser:
    """Parsea distintos formatos de log y extrae eventos de seguridad."""

    # Meses abreviados para parseo de fechas estilo syslog
    _MONTH_MAP = {
        'Jan': 1, 'Feb': 2, 'Mar': 3, 'Apr': 4, 'May': 5, 'Jun': 6,
        'Jul': 7, 'Aug': 8, 'Sep': 9, 'Oct': 10, 'Nov': 11, 'Dec': 12
    }

    def parse_file(self, file_path: str, log_type: str) -> ParsedLog:
        """
        Parsea un archivo de log según su tipo.

        Args:
            file_path: Ruta al archivo de log.
            log_type: Tipo de log ('access', 'auth', 'syslog', 'firewall', 'windows').

        Returns:
            ParsedLog con todos los eventos detectados.
        """
        result = ParsedLog(log_type=log_type, file_path=file_path)
        path = Path(file_path)

        if not path.exists():
            raise FileNotFoundError(f"Archivo no encontrado: {file_path}")

        parser_map = {
            'access':   self._parse_access_log,
            'auth':     self._parse_auth_log,
            'syslog':   self._parse_syslog,
            'firewall': self._parse_firewall_log,
            'windows':  self._parse_windows_log,
        }

        parser_fn = parser_map.get(log_type, self._parse_generic)

        with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
            for line in f:
                result.total_lines += 1
                line = line.strip()
                if not line:
                    continue
                try:
                    event = parser_fn(line)
                    if event:
                        result.events.append(event)
                        self._update_counters(result, event)
                except Exception:
                    result.parse_errors += 1

        return result

    def parse_text(self, text: str, log_type: str, source_name: str = "simulated") -> ParsedLog:
        """Parsea texto directamente (usado por el simulador)."""
        result = ParsedLog(log_type=log_type, file_path=source_name)
        parser_map = {
            'access': self._parse_access_log,
            'auth': self._parse_auth_log,
            'syslog': self._parse_syslog,
            'firewall': self._parse_firewall_log,
        }
        parser_fn = parser_map.get(log_type, self._parse_generic)
        for line in text.splitlines():
            result.total_lines += 1
            line = line.strip()
            if not line:
                continue
            try:
                event = parser_fn(line)
                if event:
                    result.events.append(event)
                    self._update_counters(result, event)
            except Exception:
                result.parse_errors += 1
        return result

    # ── Parsers específicos ──────────────────────────

    def _parse_auth_log(self, line: str) -> Optional[LogEvent]:
        """Parsea /var/log/auth.log (SSH, PAM, sudo)."""
        p = EventPatterns
        timestamp = self._extract_syslog_date(line)
        ip = self._extract_ip(line)
        user = self._extract_user(line)

        if p.BRUTE_FORCE.search(line):
            return LogEvent(timestamp, ip, user, line, 'failure', line,
                            'brute_force', severity=4)
        if p.AUTH_FAILURE.search(line):
            return LogEvent(timestamp, ip, user, line, 'failure', line,
                            'auth_failure', severity=2)
        if p.SUDO_USE.search(line):
            return LogEvent(timestamp, ip, user, line, 'info', line,
                            'privilege_escalation', severity=2)
        if p.CONFIG_CHANGE.search(line):
            return LogEvent(timestamp, ip, user, line, 'warning', line,
                            'config_change', severity=3)
        if p.AUTH_SUCCESS.search(line):
            return LogEvent(timestamp, ip, user, line, 'success', line,
                            'auth_success', severity=0)
        return None

    def _parse_access_log(self, line: str) -> Optional[LogEvent]:
        """Parsea logs de acceso HTTP (Apache/Nginx Combined Log Format)."""
        p = EventPatterns
        # Patrón Combined Log Format
        pattern = re.compile(
            r'(?P<ip>[\d.]+)\s+\S+\s+(?P<user>\S+)\s+\[(?P<time>[^\]]+)\]\s+'
            r'"(?P<request>[^"]+)"\s+(?P<status>\d{3})\s+(?P<size>\S+)'
        )
        m = pattern.match(line)
        timestamp = None
        ip = None
        user = None
        request = line

        if m:
            ip = m.group('ip')
            user = m.group('user') if m.group('user') != '-' else None
            request = m.group('request')
            status_code = m.group('status')
            try:
                timestamp = datetime.strptime(m.group('time'), '%d/%b/%Y:%H:%M:%S %z')
            except ValueError:
                pass

            if p.SQL_INJECTION.search(request):
                return LogEvent(timestamp, ip, user, request, 'attack', line,
                                'sql_injection', severity=4)
            if p.XSS_ATTEMPT.search(request):
                return LogEvent(timestamp, ip, user, request, 'attack', line,
                                'xss_attempt', severity=3)
            if p.PATH_TRAVERSAL.search(request):
                return LogEvent(timestamp, ip, user, request, 'attack', line,
                                'path_traversal', severity=3)
            if status_code == '403':
                return LogEvent(timestamp, ip, user, request, 'failure', line,
                                'access_denied', severity=2)
            if status_code.startswith('5'):
                return LogEvent(timestamp, ip, user, request, 'error', line,
                                'server_error', severity=2)
        else:
            # Intentar detectar ataques aunque no sea formato estándar
            if p.SQL_INJECTION.search(line):
                ip = self._extract_ip(line)
                return LogEvent(None, ip, None, line, 'attack', line,
                                'sql_injection', severity=4)
        return None

    def _parse_syslog(self, line: str) -> Optional[LogEvent]:
        """Parsea /var/log/syslog."""
        p = EventPatterns
        timestamp = self._extract_syslog_date(line)
        ip = self._extract_ip(line)
        user = self._extract_user(line)

        if p.MALWARE_HINT.search(line):
            return LogEvent(timestamp, ip, user, line, 'critical', line,
                            'malware_indicator', severity=4)
        if p.SERVICE_FAILURE.search(line):
            return LogEvent(timestamp, ip, user, line, 'error', line,
                            'service_failure', severity=3)
        if p.DATA_EXFIL.search(line):
            return LogEvent(timestamp, ip, user, line, 'warning', line,
                            'data_exfiltration', severity=4)
        if p.UNENCRYPTED.search(line):
            return LogEvent(timestamp, ip, user, line, 'warning', line,
                            'unencrypted_connection', severity=2)
        if p.PORT_SCAN.search(line):
            return LogEvent(timestamp, ip, user, line, 'warning', line,
                            'port_scan', severity=3)
        return None

    def _parse_firewall_log(self, line: str) -> Optional[LogEvent]:
        """Parsea logs de firewall (UFW/iptables)."""
        p = EventPatterns
        timestamp = self._extract_syslog_date(line)
        ip = self._extract_ip(line)

        if p.FIREWALL_BLOCK.search(line):
            return LogEvent(timestamp, ip, None, line, 'blocked', line,
                            'firewall_block', severity=2)
        if p.PORT_SCAN.search(line):
            return LogEvent(timestamp, ip, None, line, 'warning', line,
                            'port_scan', severity=3)
        return None

    def _parse_windows_log(self, line: str) -> Optional[LogEvent]:
        """Parsea Event Logs de Windows exportados como texto."""
        p = EventPatterns
        # Detecta Event IDs clave de Windows
        win_patterns = {
            '4625': ('auth_failure', 2),    # Failed logon
            '4648': ('privilege_escalation', 2),  # Logon with explicit creds
            '4720': ('config_change', 3),   # User account created
            '4726': ('config_change', 3),   # User account deleted
            '4732': ('config_change', 3),   # Member added to group
            '4771': ('auth_failure', 2),    # Kerberos pre-auth failed
            '4776': ('auth_failure', 2),    # Credential validation failed
            '7045': ('malware_indicator', 4),  # New service installed
        }
        for event_id, (event_type, severity) in win_patterns.items():
            if f'Event ID: {event_id}' in line or f'EventID={event_id}' in line:
                ip = self._extract_ip(line)
                user = self._extract_user(line)
                return LogEvent(None, ip, user, line, 'failure', line,
                                event_type, severity=severity)
        if p.AUTH_FAILURE.search(line):
            ip = self._extract_ip(line)
            return LogEvent(None, ip, None, line, 'failure', line,
                            'auth_failure', severity=2)
        return None

    def _parse_generic(self, line: str) -> Optional[LogEvent]:
        """Parser genérico para logs no reconocidos."""
        p = EventPatterns
        ip = self._extract_ip(line)
        user = self._extract_user(line)

        for pattern, event_type, severity in [
            (p.AUTH_FAILURE, 'auth_failure', 2),
            (p.BRUTE_FORCE, 'brute_force', 4),
            (p.SQL_INJECTION, 'sql_injection', 4),
            (p.MALWARE_HINT, 'malware_indicator', 4),
            (p.SERVICE_FAILURE, 'service_failure', 3),
        ]:
            if pattern.search(line):
                return LogEvent(None, ip, user, line, 'detected', line,
                                event_type, severity=severity)
        return None

    # ── Helpers ─────────────────────────────────────

    def _extract_syslog_date(self, line: str) -> Optional[datetime]:
        """Extrae timestamp estilo syslog: 'Jan 15 12:34:56'."""
        pattern = re.compile(
            r'(\w{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})'
        )
        m = pattern.match(line)
        if m:
            month = self._MONTH_MAP.get(m.group(1))
            if month:
                try:
                    return datetime(
                        datetime.now().year,
                        month, int(m.group(2)),
                        int(m.group(3)), int(m.group(4)), int(m.group(5))
                    )
                except ValueError:
                    pass
        return None

    def _extract_ip(self, line: str) -> Optional[str]:
        m = EventPatterns.IP_PATTERN.search(line)
        return m.group(1) if m else None

    def _extract_user(self, line: str) -> Optional[str]:
        m = EventPatterns.USER_PATTERN.search(line)
        return m.group(1) if m else None

    def _update_counters(self, result: ParsedLog, event: LogEvent) -> None:
        """Actualiza contadores de categorías en el ParsedLog."""
        counters = {
            'auth_failure':         'auth_failures',
            'brute_force':          'brute_force_attempts',
            'access_denied':        'unauthorized_access',
            'privilege_escalation': 'privilege_escalations',
            'port_scan':            'suspicious_ips',
            'service_failure':      'failed_services',
            'malware_indicator':    'malware_indicators',
            'config_change':        'config_changes',
            'data_exfiltration':    'data_exfiltration_hints',
            'unencrypted_connection': 'unencrypted_connections',
            'sql_injection':        'unauthorized_access',
            'xss_attempt':          'unauthorized_access',
            'path_traversal':       'unauthorized_access',
        }
        attr = counters.get(event.event_type)
        if attr:
            setattr(result, attr, getattr(result, attr) + 1)
