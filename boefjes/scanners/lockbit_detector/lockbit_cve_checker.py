"""
LockBit CVE Detector for OpenKAT
Developed by Hasecon

This module checks if CVEs are known to be exploited by LockBit ransomware.
"""

__author__ = "Hasecon"
__copyright__ = "Copyright 2025, Hasecon"
__license__ = "EUPL-1.2"


def is_lockbit_cve(cve_id: str) -> bool:
    """
    Controleert of een CVE-ID bekend staat als misbruikt door LockBit.

    Args:
        cve_id (str): CVE-ID om te controleren.

    Returns:
        bool: True als de CVE-ID in de LockBit-lijst zit.
    """
    lockbit_cves = {
        "CVE-2023-4966",
        "CVE-2023-27351",
        "CVE-2023-27350",
        "CVE-2023-0669",
        "CVE-2022-36537",
        "CVE-2022-22965",
        "CVE-2022-21999",
        "CVE-2021-44228",
        "CVE-2021-36942",
        "CVE-2021-34523",
        "CVE-2021-34473",
        "CVE-2021-31207",
        "CVE-2021-22986",
        "CVE-2021-20028",
        "CVE-2020-1472",
        "CVE-2019-7481",
        "CVE-2019-19781",
        "CVE-2019-11510",
        "CVE-2019-0708",
        "CVE-2018-13379",
    }
    return cve_id.upper() in lockbit_cves


def get_lockbit_cves() -> set:
    """
    Geeft de set van bekende LockBit CVEs terug.

    Returns:
        set: Set van CVE-IDs die bekend staan als misbruikt door LockBit.
    """
    return {
        "CVE-2023-4966",
        "CVE-2023-27351",
        "CVE-2023-27350",
        "CVE-2023-0669",
        "CVE-2022-36537",
        "CVE-2022-22965",
        "CVE-2022-21999",
        "CVE-2021-44228",
        "CVE-2021-36942",
        "CVE-2021-34523",
        "CVE-2021-34473",
        "CVE-2021-31207",
        "CVE-2021-22986",
        "CVE-2021-20028",
        "CVE-2020-1472",
        "CVE-2019-7481",
        "CVE-2019-19781",
        "CVE-2019-11510",
        "CVE-2019-0708",
        "CVE-2018-13379",
    }
