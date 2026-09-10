"""Tests for network/socket audit."""

import unittest
from pathlib import Path

from endpointaegis.config import Config
from endpointaegis.auditors.sockets import audit_sockets

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "hosts"


class TestSocketsGood(unittest.TestCase):
    """Good profile — services bound to localhost only."""

    def setUp(self):
        self.config = Config()
        self.result = audit_sockets(FIXTURES / "good", self.config)

    def test_good_sockets_pass(self):
        self.assertTrue(self.result.passed)

    def test_good_no_dangerous(self):
        self.assertEqual(self.result.metadata.get("dangerous_count", 0), 0,
                         "Good profile should have no dangerous exposed services")

    def test_good_has_listeners(self):
        self.assertGreater(self.result.metadata.get("total_listeners", 0), 0)


class TestSocketsBad(unittest.TestCase):
    """Bad profile — 0.0.0.0:22 and other high-risk ports exposed."""

    def setUp(self):
        self.config = Config()
        self.result = audit_sockets(FIXTURES / "bad", self.config)

    def test_bad_sockets_fail(self):
        self.assertFalse(self.result.passed)

    def test_bad_flags_22_on_0000(self):
        titles = [f.title for f in self.result.findings]
        has_22 = any("0.0.0.0:22" in t for t in titles)
        self.assertTrue(has_22, f"Should flag 0.0.0.0:22, got: {titles}")

    def test_bad_flags_telnet(self):
        titles = [f.title for f in self.result.findings]
        has_23 = any("0.0.0.0:23" in t for t in titles)
        self.assertTrue(has_23, "Should flag telnet on 0.0.0.0:23")

    def test_bad_flags_rdp(self):
        titles = [f.title for f in self.result.findings]
        has_3389 = any("0.0.0.0:3389" in t for t in titles)
        self.assertTrue(has_3389, "Should flag RDP on 0.0.0.0:3389")

    def test_bad_flags_redis(self):
        titles = [f.title for f in self.result.findings]
        has_6379 = any("0.0.0.0:6379" in t for t in titles)
        self.assertTrue(has_6379, "Should flag Redis on 0.0.0.0:6379")

    def test_bad_dangerous_count(self):
        self.assertGreaterEqual(self.result.metadata.get("dangerous_count", 0), 3)


if __name__ == "__main__":
    unittest.main()
