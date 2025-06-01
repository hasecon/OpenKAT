"""
LockBit CVE Detector Plugin for OpenKAT
Developed by Hasecon

This plugin integrates the LockBit CVE checker with OpenKAT's vulnerability scanning.
"""

from lockbit_cve_checker import is_lockbit_cve


def enrich_cve(cve_obj):
    """
    Verrijkt een CVE object met LockBit informatie.

    Args:
        cve_obj: Het CVE object om te verrijken.

    Returns:
        Het verrijkte CVE object.
    """
    if hasattr(cve_obj, 'id') and is_lockbit_cve(cve_obj.id):
        # Voeg LockBit tag toe aan de CVE
        if not hasattr(cve_obj, 'tags'):
            cve_obj.tags = []
        cve_obj.tags.append("lockbit")
        
        # Voeg LockBit informatie toe aan de beschrijving
        if hasattr(cve_obj, 'description') and cve_obj.description:
            cve_obj.description += "\n\n[WAARSCHUWING: Deze CVE wordt actief misbruikt door LockBit ransomware. Prioriteit voor patching is HOOG.]"
    
    return cve_obj
