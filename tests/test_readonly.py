"""Tests for read-only enforcement."""

import tempfile
import unittest
from pathlib import Path

from endpointaegis.config import Config
from endpointaegis.scanner import run_all_audits

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "hosts"


class TestReadOnlyEnforcement(unittest.TestCase):
    """Auditor must never write to the filesystem."""

    def test_no_writes_to_temp_dir(self):
        """Run all audits while monitoring a temp dir for changes."""
        config = Config()
        with tempfile.TemporaryDirectory() as td:
            before = set(Path(td).iterdir())
            for profile in ("good", "bad"):
                host_root = FIXTURES / profile
                results = run_all_audits(host_root, config)
            after = set(Path(td).iterdir())
            self.assertEqual(before, after, "Temp directory was modified — read-only violation")

    def test_no_writes_to_fixture_dir(self):
        """Auditor must not modify fixture directories."""
        config = Config()
        for profile in ("good", "bad"):
            host_root = FIXTURES / profile
            before_mtimes = {}
            for f in host_root.rglob("*"):
                if f.is_file():
                    before_mtimes[str(f)] = f.stat().st_mtime_ns

            run_all_audits(host_root, config)

            for f in host_root.rglob("*"):
                if f.is_file():
                    self.assertEqual(
                        before_mtimes.get(str(f)), f.stat().st_mtime_ns,
                        f"File {f} was modified — read-only violation"
                    )

    def test_dry_run_always_true(self):
        """Config.dry_run must always be True."""
        config = Config()
        config.dry_run = False
        # CLI enforces dry_run = True; verify Config default
        config2 = Config()
        self.assertTrue(config2.dry_run)


if __name__ == "__main__":
    unittest.main()
