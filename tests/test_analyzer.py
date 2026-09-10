from datetime import date
import unittest
from patch_gap.analyzer import assess
from patch_gap.models import PatchRecord, Severity


def rec(**overrides):
    data = dict(asset_id="srv-01", cve="CVE-2026-1000", severity=Severity.HIGH, cvss=8.1,
                patch_available=date(2026, 7, 1), detected=date(2026, 7, 2), installed=None,
                internet_exposed=False, kev=False, criticality=3, owner="Platform")
    data.update(overrides)
    return PatchRecord(**data)

class AnalyzerTests(unittest.TestCase):
    def test_open_gap_is_reported(self):
        self.assertEqual(len(assess([rec()], date(2026, 9, 1))), 1)
    def test_installed_patch_is_closed(self):
        self.assertEqual(assess([rec(installed=date(2026, 8, 1))], date(2026, 9, 1)), [])
    def test_kev_increases_score(self):
        base = assess([rec()], date(2026, 9, 1))[0].risk_score
        kev = assess([rec(kev=True)], date(2026, 9, 1))[0].risk_score
        self.assertGreater(kev, base)
    def test_internet_exposure_increases_score(self):
        base = assess([rec()], date(2026, 9, 1))[0].risk_score
        exposed = assess([rec(internet_exposed=True)], date(2026, 9, 1))[0].risk_score
        self.assertGreater(exposed, base)
    def test_exception_does_not_hide_finding(self):
        f = assess([rec(exception_until=date(2026, 10, 1))], date(2026, 9, 1))
        self.assertEqual(len(f), 1)
        self.assertIn("active exception", f[0].reason)
    def test_duplicate_asset_cve_rejected(self):
        with self.assertRaises(ValueError):
            assess([rec(), rec()], date(2026, 9, 1))
    def test_priority_is_bounded(self):
        f = assess([rec(severity=Severity.CRITICAL, criticality=5, kev=True, internet_exposed=True)], date(2027, 9, 1))[0]
        self.assertEqual(f.risk_score, 100)
        self.assertEqual(f.priority, "P0")
    def test_invalid_cvss_rejected(self):
        with self.assertRaises(ValueError):
            rec(cvss=11.0)

if __name__ == "__main__":
    unittest.main()
