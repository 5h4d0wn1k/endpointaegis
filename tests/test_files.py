"""Tests for file hygiene auditor."""

import unittest
from pathlib import Path

from endpointaegis.config import Config
from endpointaegis.auditors.files import audit_files

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "hosts"


class TestFilesGood(unittest.TestCase):
    """Good profile file hygiene should pass."""

    def setUp(self):
        self.config = Config()
        self.result = audit_files(FIXTURES / "good", self.config)

    def test_good_files_pass(self):
        self.assertTrue(self.result.passed)

    def test_good_no_suid_anomaly(self):
        titles = [f.title for f in self.result.findings]
        suid_issues = [t for t in titles if "SUID" in t and "allowlist" in t]
        self.assertEqual(len(suid_issues), 0, "Good profile should have no SUID anomalies")


class TestFilesBad(unittest.TestCase):
    """Bad profile — SUID anomalies, world-writable executables, secrets."""

    def setUp(self):
        self.config = Config()
        self.result = audit_files(FIXTURES / "bad", self.config)

    def test_bad_files_fail(self):
        self.assertFalse(self.result.passed)

    def test_bad_flags_suid_anomaly(self):
        titles = [f.title for f in self.result.findings]
        suid_issues = [t for t in titles if "SUID" in t and "allowlist" in t]
        self.assertGreater(len(suid_issues), 0, "Should flag SUID outside allowlist")

    def test_bad_flags_tmp_suid(self):
        titles = [f.title for f in self.result.findings]
        has_tmp = any("/tmp/" in t for t in titles)
        self.assertTrue(has_tmp, "Should flag SUID in /tmp/")

    def test_bad_flags_worldwritable(self):
        titles = [f.title for f in self.result.findings]
        has_ww = any("World-writable" in t for t in titles)
        self.assertTrue(has_ww, "Should flag world-writable executables")

    def test_bad_flags_secret_key(self):
        titles = [f.title for f in self.result.findings]
        has_secret = any("Secret" in t or "key" in t.lower() for t in titles)
        self.assertTrue(has_secret, "Should flag secret key in home directory")


if __name__ == "__main__":
    unittest.main()
