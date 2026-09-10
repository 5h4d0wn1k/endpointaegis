"""Tests for CLI interface."""

import subprocess
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


class TestCLIHelp(unittest.TestCase):
    """CLI --help works."""

    def test_help_exits_zero(self):
        result = subprocess.run(
            [sys.executable, "-m", "endpointaegis", "--help"],
            capture_output=True, text=True, cwd=str(REPO)
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("endpointaegis", result.stdout)

    def test_version(self):
        result = subprocess.run(
            [sys.executable, "-m", "endpointaegis", "--version"],
            capture_output=True, text=True, cwd=str(REPO)
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("1.0.0", result.stdout)


class TestCLIScore(unittest.TestCase):
    """CLI score subcommand works."""

    def test_score_good(self):
        result = subprocess.run(
            [sys.executable, "-m", "endpointaegis", "score", "--profile", "good"],
            capture_output=True, text=True, cwd=str(REPO)
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("Score:", result.stdout)

    def test_score_bad(self):
        result = subprocess.run(
            [sys.executable, "-m", "endpointaegis", "score", "--profile", "bad"],
            capture_output=True, text=True, cwd=str(REPO)
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("Score:", result.stdout)


class TestCLIScan(unittest.TestCase):
    """CLI scan subcommand works."""

    def test_scan_good(self):
        result = subprocess.run(
            [sys.executable, "-m", "endpointaegis", "scan", "--profile", "good"],
            capture_output=True, text=True, cwd=str(REPO)
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("Full Scan", result.stdout)

    def test_scan_bad(self):
        result = subprocess.run(
            [sys.executable, "-m", "endpointaegis", "scan", "--profile", "bad"],
            capture_output=True, text=True, cwd=str(REPO)
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("Full Scan", result.stdout)


class TestCLIDemo(unittest.TestCase):
    """CLI demo exits 0."""

    def test_demo_exits_zero(self):
        result = subprocess.run(
            [sys.executable, "-m", "endpointaegis", "demo"],
            capture_output=True, text=True, cwd=str(REPO)
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("Demo complete", result.stdout)


if __name__ == "__main__":
    unittest.main()
