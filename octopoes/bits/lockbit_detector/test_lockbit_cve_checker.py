"""
Unit tests for the LockBit CVE Detector Bit
Developed by Edward Hasekamp
"""

import unittest
from octopoes.bits.lockbit_detector.lockbit_cve_checker import is_lockbit_cve, get_lockbit_cves


class TestLockBitCVEChecker(unittest.TestCase):
    
    def test_is_lockbit_cve_positive(self):
        """Test that known LockBit CVEs are correctly identified."""
        self.assertTrue(is_lockbit_cve("CVE-2021-44228"))
        self.assertTrue(is_lockbit_cve("cve-2021-44228"))  # Test case-insensitivity
    
    def test_is_lockbit_cve_negative(self):
        """Test that non-LockBit CVEs are correctly identified."""
        self.assertFalse(is_lockbit_cve("CVE-2099-99999"))
    
    def test_get_lockbit_cves(self):
        """Test that the function returns a non-empty set."""
        cves = get_lockbit_cves()
        self.assertIsInstance(cves, set)
        self.assertGreater(len(cves), 0)
        self.assertIn("CVE-2021-44228", cves)


if __name__ == "__main__":
    unittest.main()
