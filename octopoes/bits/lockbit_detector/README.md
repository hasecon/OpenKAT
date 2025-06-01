# LockBit CVE Detector Bit

Developed by: **Edward Hasekamp**

## Description

This bit checks if CVEs are known to be exploited by LockBit ransomware. It helps organizations prioritize vulnerabilities that are actively being exploited by this ransomware group.

## Functionality

- Checks CVE-IDs against a list of known LockBit-related vulnerabilities
- Enriches CVE objects in OpenKAT with LockBit-specific tags and warnings
- Provides an API to retrieve all known LockBit CVEs

## Usage

```python
from octopoes.bits.lockbit_detector.lockbit_cve_checker import is_lockbit_cve, get_lockbit_cves

# Check if a specific CVE is exploited by LockBit
if is_lockbit_cve("CVE-2021-44228"):
    print("This CVE is exploited by LockBit!")

# Get all known LockBit CVEs
all_lockbit_cves = get_lockbit_cves()
```

## Integration with OpenKAT

The bit can be integrated with OpenKAT via the plugin interface:

```python
from octopoes.bits.lockbit_detector.plugin import enrich_cve

# Enrich a CVE object with LockBit information
enriched_cve = enrich_cve(cve_object)
```

## Sources

The list of CVEs is compiled based on threat intelligence reports and analyses of LockBit ransomware attacks.

## License

This bit is distributed under the EUPL-1.2 license.

## Contact

For questions or suggestions, please contact Edward Hasekamp.
