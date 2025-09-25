# Saos-Recon_Scanner
This is a lightweight GUI tool for quick reconnaissance of domains, IPs, or URLs. It combines passive OSINT lookups with optional active checks (DNS, WHOIS, TLS, headers, endpoints) in an organised, educational interface.

**Educational use only — use only on assets you own or have explicit permission to test.**

---

## Features

- **Targets**: domains, subdomains, IPs, or full URLs.
- **Passive Recon**:
  - DNS record lookup (A, AAAA, MX, TXT, NS, CNAME, SOA, CAA, DS).
  - WHOIS registrar and domain info.
  - crt.sh & BufferOver subdomain collection.
  - HTTP fingerprinting (headers, server, security headers scoring).
  - TLS certificate parsing & weak protocol probing.
  - Wayback Machine page counts.
- **Active Recon (opt-in)**:
  - Small wordlist subdomain brute-force.
  - DNS AXFR (zone transfer) attempts.
  - Banner grabbing on chosen ports.
  - MX banner grabbing (25/tcp).
- **Extras**:
  - IP enrichment (reverse DNS, ASN, geo, optional Shodan).
  - SPF, DKIM, DMARC parsing and expansion.
  - JavaScript pre-crawl + endpoint extraction (grouped by `/api/`, `/rest/`, `/wallet/`).
  - JSON export and comparison (diff).
  - GUI tabs for Activity Log, Summary, JSON (with search), Endpoints, Diff, and Help.
  - Proxy support (HTTP/SOCKS).
  - Anonymise mode: disables external APIs & uses minimal User-Agent.
  - Built-in Help tab explaining all options and ethics.

---

## Screenshots



---

## Requirements

  - Python 3.9+

  - CustomTkinter

  - requests

  - dnspython

  - python-whois

  - tldextract

  - beautifulsoup4

  - cryptography

  - mmh3

-----

## Usage

python main.py

1) Enter a target (domain, IP, or URL).
2) Choose options (bruteforce, AXFR, geo, ports, MX banners, Shodan).
3) Run recon.
4) Review results in the Summary/JSON/Endpoints tabs.
Save or compare JSON files for later analysis.

## Notes on Anonymise Mode

When enabled:

Skips crt.sh, BufferOver, Wayback, and JS pre-crawl.

Disables external API enrichments (Shodan, Geo).

Uses a minimal User-Agent: Recon_Scanner/anon.

Intended for lab/testing.
Do not use anonymise to evade detection on systems without permission.

----
## Ethics

Use only on systems you own or have explicit written permission to test.

Active checks (brute-force, AXFR, banners) may be logged by the target.

For educational purposes, you can test safely against:

OWASP Juice Shop

bWAPP

HackTheBox
 labs

Misuse of this tool is strictly discouraged.

----

## Installation

```bash
git clone https://github.com/JamesSao/Saos-Recon_Scanner.git
cd Saos-Recon_Scanner
pip install -r requirements.txt



