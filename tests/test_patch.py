"""Tests for patch audit."""

import unittest
from pathlib import Path

from endpointaegis.config import Config
from endpointaegis.auditors.patch import audit_patch, _is_vulnerable

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "hosts"


class TestPatchGood(unittest.TestCase):
    """Good profile should have few/zero missing critical patches."""

    def setUp(self):
        self.config = Config()
        self.result = audit_patch(FIXTURES / "good", self.config)

    def test_good_patch_finds_packages(self):
        self.assertGreater(self.result.metadata.get("packages_found", 0), 0)

    def test_good_patch_no_critical(self):
        self.assertEqual(self.result.metadata.get("missing_critical", 0), 0,
                         "Good profile should have zero critical missing patches")


class TestPatchBad(unittest.TestCase):
    """Bad profile should have missing critical/high patches."""

    def setUp(self):
        self.config = Config()
        self.result = audit_patch(FIXTURES / "bad", self.config)

    def test_bad_patch_has_critical(self):
        self.assertGreater(self.result.metadata.get("missing_critical", 0), 0,
                           "Bad profile should have critical missing patches")

    def test_bad_patch_has_high(self):
        self.assertGreater(self.result.metadata.get("missing_high", 0), 0,
                           "Bad profile should have high missing patches")

    def test_bad_patch_flags_openssl(self):
        titles = [f.title for f in self.result.findings]
        has_openssl = any("openssl" in t.lower() for t in titles)
        self.assertTrue(has_openssl, "Should flag outdated openssl")


class TestVersionComparison(unittest.TestCase):
    """Version comparison works correctly."""

    def test_older_is_vulnerable(self):
        self.assertTrue(_is_vulnerable("3.0.8", "3.0.13"))

    def test_same_not_vulnerable(self):
        self.assertFalse(_is_vulnerable("3.0.13", "3.0.13"))

    def test_newer_not_vulnerable(self):
        self.assertFalse(_is_vulnerable("3.0.14", "3.0.13"))


if __name__ == "__main__":
    unittest.main()
