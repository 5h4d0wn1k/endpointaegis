"""Tests for hardening score computation."""

import unittest
from pathlib import Path

from endpointaegis.config import Config
from endpointaegis.scoring import AuditResult, Finding, compute_score, summarize_findings
from endpointaegis.auditors import services, patch, sockets, users, files
from endpointaegis.auditors.baseline import audit_baseline

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "hosts"


class TestScoringGoodProfile(unittest.TestCase):
    """Good profile should score > 85."""

    def setUp(self):
        self.config = Config()
        self.host_root = FIXTURES / "good"

    def test_good_score_above_85(self):
        results = {}
        results["services"] = services.audit_services(self.host_root, self.config)
        results["patch"] = patch.audit_patch(self.host_root, self.config)
        results["sockets"] = sockets.audit_sockets(self.host_root, self.config)
        results["users"] = users.audit_users(self.host_root, self.config)
        results["files"] = files.audit_files(self.host_root, self.config)
        results["baseline"] = audit_baseline(self.host_root, self.config)
        score, cat_scores = compute_score(results, self.config)
        self.assertGreater(score, 85, f"Good profile score {score} should be > 85")

    def test_good_findings_minimal(self):
        results = {}
        results["services"] = services.audit_services(self.host_root, self.config)
        results["patch"] = patch.audit_patch(self.host_root, self.config)
        results["sockets"] = sockets.audit_sockets(self.host_root, self.config)
        results["users"] = users.audit_users(self.host_root, self.config)
        results["files"] = files.audit_files(self.host_root, self.config)
        results["baseline"] = audit_baseline(self.host_root, self.config)
        summary = summarize_findings(results)
        self.assertLessEqual(summary["critical"], 0, "Good profile should have no critical findings")
        self.assertLessEqual(summary["high"], 1, "Good profile should have minimal high findings")


class TestScoringBadProfile(unittest.TestCase):
    """Bad profile should score < 45."""

    def setUp(self):
        self.config = Config()
        self.host_root = FIXTURES / "bad"

    def test_bad_score_below_45(self):
        results = {}
        results["services"] = services.audit_services(self.host_root, self.config)
        results["patch"] = patch.audit_patch(self.host_root, self.config)
        results["sockets"] = sockets.audit_sockets(self.host_root, self.config)
        results["users"] = users.audit_users(self.host_root, self.config)
        results["files"] = files.audit_files(self.host_root, self.config)
        results["baseline"] = audit_baseline(self.host_root, self.config)
        score, cat_scores = compute_score(results, self.config)
        self.assertLess(score, 45, f"Bad profile score {score} should be < 45")

    def test_bad_has_critical_and_high(self):
        results = {}
        results["services"] = services.audit_services(self.host_root, self.config)
        results["patch"] = patch.audit_patch(self.host_root, self.config)
        results["sockets"] = sockets.audit_sockets(self.host_root, self.config)
        results["users"] = users.audit_users(self.host_root, self.config)
        results["files"] = files.audit_files(self.host_root, self.config)
        results["baseline"] = audit_baseline(self.host_root, self.config)
        summary = summarize_findings(results)
        self.assertGreater(summary["critical"], 0, "Bad profile should have critical findings")
        self.assertGreater(summary["high"], 0, "Bad profile should have high findings")


class TestScoreRange(unittest.TestCase):
    """Score must always be 0-100."""

    def test_score_bounds(self):
        config = Config()
        for profile in ("good", "bad"):
            host_root = FIXTURES / profile
            results = {}
            results["services"] = services.audit_services(host_root, config)
            results["patch"] = patch.audit_patch(host_root, config)
            results["sockets"] = sockets.audit_sockets(host_root, config)
            results["users"] = users.audit_users(host_root, config)
            results["files"] = files.audit_files(host_root, config)
            results["baseline"] = audit_baseline(host_root, config)
            score, _ = compute_score(results, config)
            self.assertGreaterEqual(score, 0)
            self.assertLessEqual(score, 100)


class TestSummarizeFindings(unittest.TestCase):
    """Finding summary counts correctly."""

    def test_empty_results(self):
        summary = summarize_findings({})
        self.assertEqual(summary["critical"], 0)
        self.assertEqual(summary["high"], 0)

    def test_counts_findings(self):
        r = AuditResult(module="test")
        r.add("critical", "c1")
        r.add("high", "h1")
        r.add("high", "h2")
        r.add("medium", "m1")
        summary = summarize_findings({"test": r})
        self.assertEqual(summary["critical"], 1)
        self.assertEqual(summary["high"], 2)
        self.assertEqual(summary["medium"], 1)


class TestFindingPenalty(unittest.TestCase):
    """Finding severity penalties are correct."""

    def test_penalties(self):
        self.assertEqual(Finding("t", "critical", "x").penalty, 6)
        self.assertEqual(Finding("t", "high", "x").penalty, 4)
        self.assertEqual(Finding("t", "medium", "x").penalty, 2)
        self.assertEqual(Finding("t", "low", "x").penalty, 1)
        self.assertEqual(Finding("t", "info", "x").penalty, 0)


if __name__ == "__main__":
    unittest.main()
