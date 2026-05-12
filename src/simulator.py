"""
simulator.py — Simulador de escenarios de seguridad
Genera logs sintéticos que representan empresas en distintos niveles de madurez.
Útil para testing y demostraciones sin necesidad de logs reales.
"""

import random
from datetime import datetime, timedelta
from typing import List


def _ts(offset_hours: int = 0) -> str:
    """Genera timestamp estilo syslog."""
    dt = datetime.now() - timedelta(hours=offset_hours)
    return dt.strftime('%b %d %H:%M:%S')


class LogSimulator:
    """
    Genera logs sintéticos que simulan el estado de seguridad
    de una organización en un nivel de madurez específico (0-5).
    """

    def generate(self, target_level: int, num_lines: int = 200) -> dict:
        """
        Genera un conjunto de logs simulados.

        Args:
            target_level: Nivel de madurez objetivo (0-5).
            num_lines: Número aproximado de líneas por tipo de log.

        Returns:
            Diccionario {log_type: log_text}
        """
        generators = {
            0: self._level_0_logs,
            1: self._level_1_logs,
            2: self._level_2_logs,
            3: self._level_3_logs,
            4: self._level_4_logs,
            5: self._level_5_logs,
        }
        fn = generators.get(target_level, self._level_0_logs)
        return fn(num_lines)

    # ─────────────────────────────────────────
    # Nivel 0 — Inexistente
    # Caos total: ataques activos, sin controles, malware presente
    # ─────────────────────────────────────────

    def _level_0_logs(self, n: int) -> dict:
        auth_lines = []
        sys_lines = []

        for i in range(n):
            ip = f"185.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
            auth_lines += [
                f"{_ts(i//10)} server sshd[1234]: Failed password for root from {ip} port {random.randint(1024,65535)} ssh2",
                f"{_ts(i//10)} server sshd[1234]: Failed password for admin from {ip} port {random.randint(1024,65535)} ssh2",
                f"{_ts(i//10)} server sshd[1234]: Invalid user oracle from {ip}",
                f"{_ts(i//10)} server sshd[1234]: POSSIBLE BREAK-IN ATTEMPT! from {ip}",
                f"{_ts(i//10)} server sudo[999]: many authentication failures; logname=root uid=0 tty=/dev/pts/0",
            ]
            sys_lines += [
                f"{_ts(i//10)} server kernel: [UFW BLOCK] IN=eth0 SRC={ip} DST=10.0.0.1 PROTO=TCP DPT=22",
                f"{_ts(i//10)} server systemd[1]: Unit apache2.service entered failed state.",
                f"{_ts(i//10)} server kernel: nmap scan detected from {ip}",
                f"{_ts(i//10)} server clamav: Malware detected: Trojan.Generic in /tmp/.hidden_shell",
                f"{_ts(i//10)} server kernel: suspicious process detected: unknown binary running as root",
                f"{_ts(i//10)} server ftpd[555]: user anonymous connected from {ip} — cleartext FTP session",
                f"{_ts(i//10)} server rsyslog: large data transfer detected — possible data exfiltration from 10.0.0.5 to {ip}",
            ]

        return {
            'auth': '\n'.join(auth_lines[:n]),
            'syslog': '\n'.join(sys_lines[:n]),
        }

    # ─────────────────────────────────────────
    # Nivel 1 — Inicial
    # Problemas frecuentes pero sin controles formales
    # ─────────────────────────────────────────

    def _level_1_logs(self, n: int) -> dict:
        auth_lines = []
        sys_lines = []

        for i in range(n):
            ip = f"203.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
            auth_lines += [
                f"{_ts(i//5)} server sshd[1234]: Failed password for user{random.randint(1,10)} from {ip} port {random.randint(1024,65535)} ssh2",
                f"{_ts(i//5)} server sshd[1234]: Failed password for root from {ip} port 22 ssh2",
                f"{_ts(i//5)} server sudo[123]: user{random.randint(1,5)} : TTY=pts/0 ; PWD=/home ; COMMAND=/usr/bin/passwd",
            ]
            sys_lines += [
                f"{_ts(i//5)} server systemd[1]: Unit mysql.service entered failed state.",
                f"{_ts(i//5)} server kernel: [UFW BLOCK] IN=eth0 SRC={ip} PROTO=TCP DPT=3306",
                f"{_ts(i//5)} server telnetd: user admin connected from {ip} — unencrypted telnet session",
                f"{_ts(i//5)} server cron: crontab modified by user{random.randint(1,5)}",
            ]

        return {
            'auth': '\n'.join(auth_lines[:n]),
            'syslog': '\n'.join(sys_lines[:n]),
        }

    # ─────────────────────────────────────────
    # Nivel 2 — Gestionado
    # Controles básicos presentes pero incompletos
    # ─────────────────────────────────────────

    def _level_2_logs(self, n: int) -> dict:
        auth_lines = []
        access_lines = []

        for i in range(n // 2):
            ip = f"192.168.{random.randint(1,10)}.{random.randint(1,254)}"
            ext_ip = f"45.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
            auth_lines += [
                f"{_ts(i)} server sshd[1234]: Accepted password for deploy from {ip} port 22 ssh2",
                f"{_ts(i)} server sshd[1234]: Failed password for testuser from {ext_ip} port {random.randint(1024,65535)} ssh2",
                f"{_ts(i)} server sshd[1234]: Failed password for testuser from {ext_ip} port {random.randint(1024,65535)} ssh2",
                f"{_ts(i)} server sudo[123]: developer : TTY=pts/1 ; COMMAND=/bin/bash",
            ]
            access_lines += [
                f'192.168.1.{random.randint(1,50)} - - [{datetime.now().strftime("%d/%b/%Y:%H:%M:%S +0000")}] "GET /admin HTTP/1.1" 403 512',
                f'{ext_ip} - - [{datetime.now().strftime("%d/%b/%Y:%H:%M:%S +0000")}] "GET /index.php?id=1 UNION SELECT * FROM users-- HTTP/1.1" 200 1024',
                f'192.168.1.5 - user1 [{datetime.now().strftime("%d/%b/%Y:%H:%M:%S +0000")}] "GET /dashboard HTTP/1.1" 200 4096',
            ]

        return {
            'auth': '\n'.join(auth_lines[:n]),
            'access': '\n'.join(access_lines[:n]),
        }

    # ─────────────────────────────────────────
    # Nivel 3 — Definido
    # Controles formales, algunos incidentes menores
    # ─────────────────────────────────────────

    def _level_3_logs(self, n: int) -> dict:
        auth_lines = []
        access_lines = []

        for i in range(n // 3):
            ip = f"10.0.{random.randint(1,5)}.{random.randint(1,50)}"
            auth_lines += [
                f"{_ts(i)} server sshd[1234]: Accepted publickey for sysadmin from {ip} port 22 ssh2",
                f"{_ts(i)} server sshd[1234]: Accepted publickey for deploy from {ip} port 22 ssh2",
                f"{_ts(i)} server sudo[123]: sysadmin : TTY=pts/0 ; PWD=/etc ; COMMAND=/usr/sbin/service nginx restart",
                f"{_ts(i)} server sshd[1234]: Failed password for unknown from 198.51.100.{random.randint(1,254)} port 22 ssh2",
                f"{_ts(i)} server sshd[1234]: Failed password for unknown from 198.51.100.{random.randint(1,254)} port 22 ssh2",
            ]
            access_lines += [
                f'10.0.1.{random.randint(1,20)} - user{random.randint(1,20)} [{datetime.now().strftime("%d/%b/%Y:%H:%M:%S +0000")}] "GET /api/reports HTTP/2.0" 200 8192',
                f'10.0.1.{random.randint(1,20)} - user{random.randint(1,20)} [{datetime.now().strftime("%d/%b/%Y:%H:%M:%S +0000")}] "POST /api/data HTTP/2.0" 200 512',
                f'198.51.100.{random.randint(1,254)} - - [{datetime.now().strftime("%d/%b/%Y:%H:%M:%S +0000")}] "GET /admin HTTP/1.1" 403 128',
            ]

        return {
            'auth': '\n'.join(auth_lines[:n]),
            'access': '\n'.join(access_lines[:n]),
        }

    # ─────────────────────────────────────────
    # Nivel 4 — Medido
    # Bien gestionado, eventos mínimos, monitoreo activo
    # ─────────────────────────────────────────

    def _level_4_logs(self, n: int) -> dict:
        auth_lines = []
        access_lines = []

        for i in range(n // 4):
            ip = f"10.10.{random.randint(1,3)}.{random.randint(1,30)}"
            auth_lines += [
                f"{_ts(i)} server sshd[1234]: Accepted publickey for ops-{random.randint(1,5)} from {ip} port 22 ssh2",
                f"{_ts(i)} server sshd[1234]: session opened for user ops-{random.randint(1,5)}",
                f"{_ts(i)} server pam_unix: authentication success; logname=monitor uid=1001",
                f"{_ts(i)} server sudo[123]: ops-1 : TTY=pts/0 ; COMMAND=/usr/bin/journalctl -n 100",
            ]
            access_lines += [
                f'10.10.1.{random.randint(1,10)} - analyst{random.randint(1,5)} [{datetime.now().strftime("%d/%b/%Y:%H:%M:%S +0000")}] "GET /api/v2/metrics HTTP/2.0" 200 4096',
                f'10.10.1.{random.randint(1,10)} - analyst{random.randint(1,5)} [{datetime.now().strftime("%d/%b/%Y:%H:%M:%S +0000")}] "POST /api/v2/report HTTP/2.0" 201 1024',
            ]

        return {
            'auth': '\n'.join(auth_lines[:n]),
            'access': '\n'.join(access_lines[:n]),
        }

    # ─────────────────────────────────────────
    # Nivel 5 — Optimizado
    # Operación óptima, sin incidentes, todo automatizado
    # ─────────────────────────────────────────

    def _level_5_logs(self, n: int) -> dict:
        auth_lines = []
        access_lines = []

        for i in range(n // 5):
            ip = f"172.16.{random.randint(1,2)}.{random.randint(1,20)}"
            auth_lines += [
                f"{_ts(i)} server sshd[1234]: Accepted publickey for svc-account from {ip} port 22 ssh2",
                f"{_ts(i)} server pam_unix: authentication success; logname=automation uid=2001",
                f"{_ts(i)} server sshd[1234]: session opened for user monitor",
            ]
            access_lines += [
                f'172.16.1.{random.randint(1,5)} - svc-api [{datetime.now().strftime("%d/%b/%Y:%H:%M:%S +0000")}] "GET /health HTTP/2.0" 200 64',
                f'172.16.1.{random.randint(1,5)} - monitor [{datetime.now().strftime("%d/%b/%Y:%H:%M:%S +0000")}] "GET /metrics HTTP/2.0" 200 2048',
                f'172.16.1.{random.randint(1,5)} - automation [{datetime.now().strftime("%d/%b/%Y:%H:%M:%S +0000")}] "POST /api/v3/scan-results HTTP/2.0" 201 512',
            ]

        return {
            'auth': '\n'.join(auth_lines[:n]),
            'access': '\n'.join(access_lines[:n]),
        }
