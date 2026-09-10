"""Tests for drift baseline audit."""

import unittest
import tempfile
from pathlib import Path

from endpointaegis.config import Config
from endpointaegis.auditors.baseline import (
    create_baseline, audit_baseline, save_baseline, load_baseline
)

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "hosts"


class TestBaselineNoBaseline(unittest.TestCase):
    """Without a baseline, baseline audit reports info."""

    def setUp(self):
        self.config = Config()
        self.result = audit_baseline(FIXTURES / "good", self.config, baseline=None)

    def test_no_baseline_info(self):
        titles = [f.title for f in self.result.findings]
        has_info = any("No baseline" in t for t in titles)
        self.assertTrue(has_info)


class TestBaselineNoDrift(unittest.TestCase):
    """Same profile as baseline = no drift."""

    def setUp(self):
        self.config = Config()
        self.host = FIXTURES / "good"
        self.baseline = create_baseline(self.host)
        self.result = audit_baseline(self.host, self.config, self.baseline)

    def test_no_drift(self):
        self.assertTrue(self.result.passed)

    def test_no_drift_findings(self):
        info_findings = [f for f in self.result.findings if f.severity == "info"]
        self.assertGreater(len(info_findings), 0, "Should report 'no drift detected'")


class TestBaselineWithDrift(unittest.TestCase):
    """Different profile = drift detected."""

    def setUp(self):
        self.config = Config()
        self.good_root = FIXTURES / "good"
        self.bad_root = FIXTURES / "bad"
        self.baseline = create_baseline(self.good_root)
        self.result = audit_baseline(self.bad_root, self.config, self.baseline)

    def test_drift_detected(self):
        self.assertFalse(self.result.passed)

    def test_files_added(self):
        self.assertGreater(self.result.metadata.get("files_added", 0), 0)

    def test_services_added(self):
        self.assertGreater(self.result.metadata.get("services_added", 0), 0)

    def test_users_added(self):
        self.assertGreater(self.result.metadata.get("users_added", 0), 0)

    def test_drift_flags_file(self):
        titles = [f.title for f in self.result.findings]
        has_file = any("File added" in t for t in titles)
        self.assertTrue(has_file, "Should detect added files")


class TestBaselineSaveLoad(unittest.TestCase):
    """Baseline save/load roundtrips correctly."""

    def test_save_load_roundtrip(self):
        bl = create_baseline(FIXTURES / "good")
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "bl.json"
            save_baseline(bl, path)
            loaded = load_baseline(path)
            self.assertIsNotNone(loaded)
            self.assertEqual(set(bl["files"].keys()), set(loaded["files"].keys()))

    def test_load_nonexistent(self):
        result = load_baseline(Path("/nonexistent/path.json"))
        self.assertIsNone(result)


if __name__ == "__main__":
    unittest.main()
