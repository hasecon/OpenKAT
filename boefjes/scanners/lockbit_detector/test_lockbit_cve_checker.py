"""
Unit tests voor de LockBit CVE Detector
Ontwikkeld door Hasecon
"""

import unittest
from lockbit_cve_checker import is_lockbit_cve, get_lockbit_cves


class TestLockBitCVEChecker(unittest.TestCase):
    
    def test_is_lockbit_cve_positive(self):
        """Test dat bekende LockBit CVEs correct worden geïdentificeerd."""
        self.assertTrue(is_lockbit_cve("CVE-2021-44228"))
        self.assertTrue(is_lockbit_cve("cve-2021-44228"))  # Test case-insensitivity
    
    def test_is_lockbit_cve_negative(self):
        """Test dat niet-LockBit CVEs correct worden geïdentificeerd."""
        self.assertFalse(is_lockbit_cve("CVE-2099-99999"))
    
    def test_get_lockbit_cves(self):
        """Test dat de functie een niet-lege set teruggeeft."""
        cves = get_lockbit_cves()
        self.assertIsInstance(cves, set)
        self.assertGreater(len(cves), 0)
        self.assertIn("CVE-2021-44228", cves)


if __name__ == "__main__":
    unittest.main()
