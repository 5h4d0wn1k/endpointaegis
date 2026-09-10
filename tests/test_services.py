"""Tests for service/startup auditor."""

import unittest
from pathlib import Path

from endpointaegis.config import Config
from endpointaegis.auditors.services import audit_services

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "hosts"


class TestServicesGood(unittest.TestCase):
    """Good profile services should pass."""

    def setUp(self):
        self.config = Config()
        self.result = audit_services(FIXTURES / "good", self.config)

    def test_good_services_pass(self):
        self.assertTrue(self.result.passed)

    def test_good_has_units(self):
        self.assertGreaterEqual(self.result.metadata.get("unit_count", 0), 1)


class TestServicesBad(unittest.TestCase):
    """Bad profile should flag suspicious services."""

    def setUp(self):
        self.config = Config()
        self.result = audit_services(FIXTURES / "bad", self.config)

    def test_bad_services_fail(self):
        self.assertFalse(self.result.passed)

    def test_bad_flags_suspicious(self):
        titles = [f.title for f in self.result.findings]
        has_suspicious = any("Suspicious" in t for t in titles)
        self.assertTrue(has_suspicious, f"Expected suspicious service finding, got: {titles}")

    def test_bad_flags_update_helper(self):
        titles = [f.title for f in self.result.findings]
        has_update = any("update-helper" in t for t in titles)
        self.assertTrue(has_update, "Should flag update-helper service")

    def test_bad_flags_kworker(self):
        titles = [f.title for f in self.result.findings]
        has_kworker = any("kworker" in t for t in titles)
        self.assertTrue(has_kworker, "Should flag kworker service")


class TestServicesCron(unittest.TestCase):
    """Bad profile should flag suspicious cron entries."""

    def setUp(self):
        self.config = Config()
        self.result = audit_services(FIXTURES / "bad", self.config)

    def test_bad_flags_cron(self):
        titles = [f.title for f in self.result.findings]
        has_cron = any("suspicious" in t.lower() for t in titles)
        self.assertTrue(has_cron, "Should flag suspicious cron entries")


if __name__ == "__main__":
    unittest.main()
