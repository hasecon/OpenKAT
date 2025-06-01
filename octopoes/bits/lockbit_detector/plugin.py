"""
LockBit CVE Detector Plugin for OpenKAT
Developed by Edward Hasekamp

This plugin integrates the LockBit CVE checker with OpenKAT's vulnerability scanning.
"""

from octopoes.bits.lockbit_detector.lockbit_cve_checker import is_lockbit_cve


def enrich_cve(cve_obj):
    """
    Enriches a CVE object with LockBit information.

    Args:
        cve_obj: The CVE object to enrich.

    Returns:
        The enriched CVE object.
    """
    if hasattr(cve_obj, 'id') and is_lockbit_cve(cve_obj.id):
        # Add LockBit tag to the CVE
        if not hasattr(cve_obj, 'tags'):
            cve_obj.tags = []
        cve_obj.tags.append("lockbit")
        
        # Add LockBit information to the description
        if hasattr(cve_obj, 'description') and cve_obj.description:
            cve_obj.description += "\n\n[WARNING: This CVE is actively exploited by LockBit ransomware. Patching priority is HIGH.]"
    
    return cve_obj
