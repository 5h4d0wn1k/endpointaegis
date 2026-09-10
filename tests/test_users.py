"""Tests for user audit."""

import unittest
from pathlib import Path

from endpointaegis.config import Config
from endpointaegis.auditors.users import audit_users

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "hosts"


class TestUsersGood(unittest.TestCase):
    """Good profile users should pass."""

    def setUp(self):
        self.config = Config()
        self.result = audit_users(FIXTURES / "good", self.config)

    def test_good_users_pass(self):
        self.assertTrue(self.result.passed)

    def test_good_no_critical(self):
        critical = [f for f in self.result.findings if f.severity == "critical"]
        self.assertEqual(len(critical), 0, "Good profile should have no critical user findings")

    def test_good_user_count(self):
        self.assertGreater(self.result.metadata.get("user_count", 0), 0)


class TestUsersBad(unittest.TestCase):
    """Bad profile — empty password, UID 0 non-root, passwordless sudo."""

    def setUp(self):
        self.config = Config()
        self.result = audit_users(FIXTURES / "bad", self.config)

    def test_bad_users_fail(self):
        self.assertFalse(self.result.passed)

    def test_bad_flags_uid0_nonroot(self):
        titles = [f.title for f in self.result.findings]
        has_uid0 = any("UID 0" in t for t in titles)
        self.assertTrue(has_uid0, f"Should flag UID 0 non-root user, got: {titles}")

    def test_bad_flags_empty_password(self):
        titles = [f.title for f in self.result.findings]
        has_empty = any("Empty password" in t for t in titles)
        self.assertTrue(has_empty, "Should flag empty password user")

    def test_bad_flags_passwordless_sudo(self):
        titles = [f.title for f in self.result.findings]
        has_sudo = any("sudo" in t.lower() for t in titles)
        self.assertTrue(has_sudo, "Should flag passwordless sudo")

    def test_bad_flags_worldwritable_home(self):
        titles = [f.title for f in self.result.findings]
        has_home = any("World-writable" in t for t in titles)
        self.assertTrue(has_home, "Should flag world-writable home directory")


if __name__ == "__main__":
    unittest.main()
