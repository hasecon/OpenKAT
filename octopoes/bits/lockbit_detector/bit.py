"""
LockBit CVE Detector Bit for OpenKAT
Developed by Edward Hasekamp

This bit provides integration with OpenKAT for detecting CVEs exploited by LockBit ransomware.
"""

from octopoes.models import CVE
from octopoes.bits.lockbit_detector.lockbit_cve_checker import is_lockbit_cve

__author__ = "Edward Hasekamp"
__version__ = "1.0.0"


def process(cve: CVE) -> CVE:
    """
    Process a CVE object to check if it's exploited by LockBit ransomware.
    
    Args:
        cve: The CVE object to check
        
    Returns:
        The enriched CVE object with LockBit information if applicable
    """
    if is_lockbit_cve(cve.id):
        # Add LockBit tag to the CVE
        if not hasattr(cve, 'tags'):
            cve.tags = []
        cve.tags.append("lockbit")
        
        # Add LockBit information to the description
        if cve.description:
            cve.description += "\n\n[WARNING: This CVE is actively exploited by LockBit ransomware. Patching priority is HIGH.]"
    
    return cve
