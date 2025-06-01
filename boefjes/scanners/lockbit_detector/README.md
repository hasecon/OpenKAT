# LockBit CVE Detector

Ontwikkeld door: **Edward Hasekamp**

## Beschrijving

Deze module controleert of CVEs bekend staan als misbruikt door LockBit ransomware. Het helpt organisaties om kwetsbaarheden te prioriteren die actief worden uitgebuit door deze ransomware groep.

## Functionaliteit

- Controleert CVE-IDs tegen een lijst van bekende LockBit-gerelateerde kwetsbaarheden
- Verrijkt CVE-objecten in OpenKAT met LockBit-specifieke tags en waarschuwingen
- Biedt een API om alle bekende LockBit CVEs op te vragen

## Gebruik

```python
from boefjes.scanners.lockbit_detector.lockbit_cve_checker import is_lockbit_cve, get_lockbit_cves

# Controleer of een specifieke CVE door LockBit wordt misbruikt
if is_lockbit_cve("CVE-2021-44228"):
    print("Deze CVE wordt misbruikt door LockBit!")

# Haal alle bekende LockBit CVEs op
all_lockbit_cves = get_lockbit_cves()
```

## Integratie met OpenKAT

De module kan worden geïntegreerd met OpenKAT via de plugin interface:

```python
from boefjes.scanners.lockbit_detector.plugin import enrich_cve

# Verrijk een CVE object met LockBit informatie
enriched_cve = enrich_cve(cve_object)
```

## Bronnen

De lijst van CVEs is samengesteld op basis van threat intelligence rapporten en analyses van LockBit ransomware aanvallen.

## Licentie

Deze module wordt gedistribueerd onder de EUPL-1.2 licentie.

## Contact

Voor vragen of suggesties, neem contact op met Edward Hasekamp via info@hasecon.com.
