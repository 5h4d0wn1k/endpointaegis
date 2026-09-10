"""Tests for report generation."""

import json
import tempfile
import unittest
from pathlib import Path

from endpointaegis.config import Config
from endpointaegis.scoring import compute_score, summarize_findings
from endpointaegis.reports import (
    generate_json_report, write_json_report, write_html_report,
    write_markdown_report, render_html_to_string
)
from endpointaegis.scanner import run_all_audits

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "hosts"


class TestJsonReport(unittest.TestCase):
    """JSON report is valid and contains expected fields."""

    def test_json_report_structure(self):
        config = Config()
        results = run_all_audits(FIXTURES / "good", config)
        score, cat_scores = compute_score(results, config)
        fs = summarize_findings(results)
        report = generate_json_report(score, cat_scores, results, fs, "good")
        self.assertEqual(report["tool"], "endpointaegis")
        self.assertEqual(report["profile"], "good")
        self.assertIn("score", report)
        self.assertIn("modules", report)
        self.assertIn("findings_summary", report)

    def test_json_report_write(self):
        config = Config()
        results = run_all_audits(FIXTURES / "good", config)
        score, cat_scores = compute_score(results, config)
        fs = summarize_findings(results)
        report = generate_json_report(score, cat_scores, results, fs, "good")
        with tempfile.TemporaryDirectory() as td:
            path = write_json_report(report, Path(td))
            self.assertTrue(path.exists())
            data = json.loads(path.read_text())
            self.assertEqual(data["tool"], "endpointaegis")


class TestHtmlReport(unittest.TestCase):
    """HTML report is well-formed and contains score + findings."""

    def test_html_contains_score(self):
        config = Config()
        results = run_all_audits(FIXTURES / "good", config)
        score, cat_scores = compute_score(results, config)
        fs = summarize_findings(results)
        report = generate_json_report(score, cat_scores, results, fs, "good")
        html = render_html_to_string(report)
        self.assertIn("endpointaegis", html)
        self.assertIn(str(score), html)
        self.assertIn("DOCTYPE html", html)
        self.assertIn("Module Results", html)

    def test_html_report_write(self):
        config = Config()
        results = run_all_audits(FIXTURES / "good", config)
        score, cat_scores = compute_score(results, config)
        fs = summarize_findings(results)
        report = generate_json_report(score, cat_scores, results, fs, "good")
        with tempfile.TemporaryDirectory() as td:
            path = write_html_report(report, Path(td))
            self.assertTrue(path.exists())
            html = path.read_text()
            self.assertIn("DOCTYPE html", html)


class TestMarkdownReport(unittest.TestCase):
    """Markdown report contains score."""

    def test_md_report(self):
        config = Config()
        results = run_all_audits(FIXTURES / "good", config)
        score, cat_scores = compute_score(results, config)
        fs = summarize_findings(results)
        report = generate_json_report(score, cat_scores, results, fs, "good")
        with tempfile.TemporaryDirectory() as td:
            path = write_markdown_report(report, Path(td))
            self.assertTrue(path.exists())
            md = path.read_text()
            self.assertIn("Score", md)
            self.assertIn(str(score), md)


if __name__ == "__main__":
    unittest.main()
