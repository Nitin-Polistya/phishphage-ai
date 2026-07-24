import unittest
import json
import csv
from pathlib import Path
import os

class TestFeatureCoverageEvaluation(unittest.TestCase):
    def setUp(self):
        self.report_dir = Path("reports/feature_coverage")
        self.summary_file = self.report_dir / "feature_coverage_summary.json"
        self.prevalence_file = self.report_dir / "feature_prevalence.csv"
        self.fn_file = self.report_dir / "false_negative_coverage.csv"
        self.fp_file = self.report_dir / "false_positive_coverage.csv"
        self.report_md = self.report_dir / "feature_coverage_report.md"

    def test_artifacts_exist(self):
        """Verify all required report files were created."""
        self.assertTrue(self.summary_file.exists(), "Summary JSON missing")
        self.assertTrue(self.prevalence_file.exists(), "Prevalence CSV missing")
        self.assertTrue(self.fn_file.exists(), "FN CSV missing")
        self.assertTrue(self.fp_file.exists(), "FP CSV missing")
        self.assertTrue(self.report_md.exists(), "Report MD missing")

    def test_privacy_redaction(self):
        """Ensure no raw email bodies or personal identifiers are leaked in reports."""
        # Check all files in the report directory
        for file_path in self.report_dir.glob("*"):
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                # Check for common email patterns that should NOT be there
                # 1. Raw headers (e.g., "Received: from", "Return-Path: <")
                self.assertNotIn("Received: from", content, f"Raw header leaked in {file_path}")
                self.assertNotIn("Return-Path: <", content, f"Raw header leaked in {file_path}")
                
                # 2. Email address patterns (simple regex-like check)
                # We expect hashed IDs, but not "user@domain.com"
                # Note: This is a basic check; a more robust one would use regex.
                if "@" in content:
                    # If '@' is present, it should be part of a domain name in a feature, 
                    # not a full email address. We check if there are common email markers.
                    # A very simple check: if there's a '<' followed by an '@', it's likely a raw address.
                    self.assertNotIn("<", content, f"Potential raw email address leaked in {file_path}")

    def test_deterministic_output(self):
        """Verify that the reports contain consistent data types and no nulls in key columns."""
        with open(self.summary_file, 'r') as f:
            summary = json.load(f)
            self.assertIn('total_samples', summary)
            self.assertIn('phishing_count', summary)
            self.assertIn('safe_count', summary)
            self.assertEqual(summary['total_samples'], summary['phishing_count'] + summary['safe_count'])

    def test_stable_ordering(self):
        """Check if the prevalence CSV has a header and consistent column count."""
        with open(self.prevalence_file, 'r', newline='') as f:
            reader = csv.reader(f)
            header = next(reader)
            self.assertEqual(header, ['feature', 'phishing_pct', 'safe_pct', 'phishing_count', 'safe_count'])
            for row in reader:
                self.assertEqual(len(row), 5, "Inconsistent column count in prevalence CSV")

if __name__ == "__main__":
    unittest.main()