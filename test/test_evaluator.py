"""
tests/test_evaluator.py — Pruebas unitarias del evaluador de madurez
"""

import pytest
import sys
from pathlib import Path

# Asegurar que el módulo raíz esté en el path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.log_parser import LogParser, LogEvent
from src.control_evaluator import ControlEvaluator
from src.maturity_calculator import MaturityCalculator
from src.simulator import LogSimulator


class TestLogParser:
    """Pruebas del parser de logs."""

    def setup_method(self):
        self.parser = LogParser()

    def test_parse_auth_failure(self):
        line = "May 11 08:01:12 server sshd[1234]: Failed password for root from 185.220.101.45 port 52341 ssh2"
        event = self.parser._parse_auth_log(line)
        assert event is not None
        assert event.event_type == 'auth_failure'
        assert event.severity == 2
        assert event.source_ip == '185.220.101.45'

    def test_parse_brute_force(self):
        line = "May 11 09:15:00 server sshd[1234]: POSSIBLE BREAK-IN ATTEMPT! from 45.33.32.156"
        event = self.parser._parse_auth_log(line)
        assert event is not None
        assert event.event_type == 'brute_force'
        assert event.severity == 4

    def test_parse_sql_injection(self):
        line = '185.1.2.3 - - [11/May/2026:08:00:00 +0000] "GET /index.php?id=1 UNION SELECT * FROM users-- HTTP/1.1" 200 512'
        event = self.parser._parse_access_log(line)
        assert event is not None
        assert event.event_type == 'sql_injection'
        assert event.severity == 4

    def test_parse_malware(self):
        line = "May 11 11:05:00 server clamav[2222]: Malware detected: Trojan.Generic in /tmp/.hidden"
        event = self.parser._parse_syslog(line)
        assert event is not None
        assert event.event_type == 'malware_indicator'
        assert event.severity == 4

    def test_parse_unencrypted(self):
        line = "May 11 12:00:00 server telnetd: user root connected from 10.0.0.1 — unencrypted telnet session"
        event = self.parser._parse_syslog(line)
        assert event is not None
        assert event.event_type == 'unencrypted_connection'

    def test_parse_text_auth(self):
        text = """May 11 08:01:12 server sshd[1234]: Failed password for root from 185.1.2.3 port 22 ssh2
May 11 08:01:13 server sshd[1234]: Failed password for admin from 185.1.2.3 port 22 ssh2
May 11 08:01:14 server sshd[1234]: POSSIBLE BREAK-IN ATTEMPT! from 185.1.2.3"""
        result = self.parser.parse_text(text, 'auth')
        assert result.auth_failures == 2
        assert result.brute_force_attempts == 1
        assert result.total_events == 3

    def test_parse_xss(self):
        line = '10.0.0.1 - - [11/May/2026:09:00:00 +0000] "GET /search?q=<script>alert(1)</script> HTTP/1.1" 200 256'
        event = self.parser._parse_access_log(line)
        assert event is not None
        assert event.event_type == 'xss_attempt'

    def test_counters_update(self):
        text = """May 11 08:01:00 server sshd[1234]: Failed password for root from 10.0.0.1 port 22 ssh2
May 11 08:02:00 server sshd[1234]: Failed password for user from 10.0.0.1 port 22 ssh2"""
        result = self.parser.parse_text(text, 'auth')
        assert result.auth_failures == 2


class TestControlEvaluator:
    """Pruebas del evaluador de controles ISO 27001."""

    def setup_method(self):
        self.parser = LogParser()
        self.evaluator = ControlEvaluator()

    def test_evaluate_returns_four_components(self):
        results = self.evaluator.evaluate([])
        assert len(results) == 4
        assert 'A5' in results
        assert 'A6' in results
        assert 'A7' in results
        assert 'A8' in results

    def test_a5_has_37_controls(self):
        results = self.evaluator.evaluate([])
        assert results['A5'].total_controls == 37

    def test_a6_has_8_controls(self):
        results = self.evaluator.evaluate([])
        assert results['A6'].total_controls == 8

    def test_a7_has_14_controls(self):
        results = self.evaluator.evaluate([])
        assert results['A7'].total_controls == 14

    def test_a8_has_34_controls(self):
        results = self.evaluator.evaluate([])
        assert results['A8'].total_controls == 34

    def test_malware_lowers_a8_score(self):
        log_text = "May 11 11:05:00 server clamav: Malware detected: Trojan.Generic in /tmp/.hidden"
        parsed = self.parser.parse_text(log_text, 'syslog')
        results_clean = self.evaluator.evaluate([])
        results_malware = self.evaluator.evaluate([parsed])
        # A8.7 (protección contra malware) debería tener puntaje más bajo
        a8_clean = results_clean['A8'].maturity_level
        a8_malware = results_malware['A8'].maturity_level
        assert a8_malware < a8_clean

    def test_brute_force_lowers_score(self):
        log_text = "May 11 09:15:00 server sshd[1234]: POSSIBLE BREAK-IN ATTEMPT! from 45.33.32.156"
        parsed = self.parser.parse_text(log_text, 'auth')
        results = self.evaluator.evaluate([parsed])
        # Con brute force, A8 debe tener puntaje bajo
        assert results['A8'].maturity_level < 5.0


class TestMaturityCalculator:
    """Pruebas del calculador de madurez."""

    def setup_method(self):
        self.evaluator = ControlEvaluator()
        self.calculator = MaturityCalculator()

    def test_score_range(self):
        results = self.evaluator.evaluate([])
        report = self.calculator.calculate(results)
        assert 0.0 <= report.global_score <= 5.0

    def test_level_range(self):
        results = self.evaluator.evaluate([])
        report = self.calculator.calculate(results)
        assert 0 <= report.global_level <= 5

    def test_compliance_percentage(self):
        results = self.evaluator.evaluate([])
        report = self.calculator.calculate(results)
        assert 0.0 <= report.compliance_percentage <= 100.0

    def test_score_to_level_mapping(self):
        calc = MaturityCalculator()
        assert calc._score_to_level(0.0) == 0
        assert calc._score_to_level(0.5) == 0
        assert calc._score_to_level(1.0) == 1
        assert calc._score_to_level(1.5) == 1
        assert calc._score_to_level(2.0) == 2
        assert calc._score_to_level(3.0) == 3
        assert calc._score_to_level(4.0) == 4
        assert calc._score_to_level(5.0) == 5


class TestSimulator:
    """Pruebas del simulador de logs."""

    def setup_method(self):
        self.sim = LogSimulator()
        self.parser = LogParser()
        self.evaluator = ControlEvaluator()
        self.calculator = MaturityCalculator()

    def _full_pipeline(self, level: int) -> float:
        logs = self.sim.generate(level, num_lines=50)
        parsed = []
        for log_type, log_text in logs.items():
            parsed.append(self.parser.parse_text(log_text, log_type))
        components = self.evaluator.evaluate(parsed)
        report = self.calculator.calculate(components)
        return report.global_score

    def test_level_0_lower_than_level_3(self):
        score_0 = self._full_pipeline(0)
        score_3 = self._full_pipeline(3)
        assert score_0 < score_3, f"Nivel 0 ({score_0:.2f}) debe ser menor que nivel 3 ({score_3:.2f})"

    def test_level_5_higher_than_level_1(self):
        score_1 = self._full_pipeline(1)
        score_5 = self._full_pipeline(5)
        assert score_5 > score_1, f"Nivel 5 ({score_5:.2f}) debe ser mayor que nivel 1 ({score_1:.2f})"

    def test_all_levels_generate_logs(self):
        for level in range(6):
            logs = self.sim.generate(level, num_lines=20)
            assert len(logs) > 0, f"Nivel {level} no generó logs"

    def test_simulate_produces_valid_report(self):
        for level in range(6):
            score = self._full_pipeline(level)
            assert 0.0 <= score <= 5.0


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
