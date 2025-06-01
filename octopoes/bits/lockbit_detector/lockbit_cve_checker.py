"""
LockBit CVE Detector Bit for OpenKAT
Developed by Edward Hasekamp

This bit checks if CVEs are known to be exploited by LockBit ransomware.
"""

__author__ = "Edward Hasekamp"
__copyright__ = "Copyright 2025, Edward Hasekamp"
__license__ = "EUPL-1.2"


def is_lockbit_cve(cve_id: str) -> bool:
    """
    Checks if a CVE-ID is known to be exploited by LockBit.

    Args:
        cve_id (str): CVE-ID to check.

    Returns:
        bool: True if the CVE-ID is in the LockBit list.
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
    Returns the set of known LockBit CVEs.

    Returns:
        set: Set of CVE-IDs known to be exploited by LockBit.
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
