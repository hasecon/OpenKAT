"""
LockBit CVE Detector Bit for OpenKAT
"""

from octopoes.bits.lockbit_detector.lockbit_cve_checker import is_lockbit_cve, get_lockbit_cves
from octopoes.bits.lockbit_detector.plugin import enrich_cve

__all__ = ["is_lockbit_cve", "get_lockbit_cves", "enrich_cve"]
