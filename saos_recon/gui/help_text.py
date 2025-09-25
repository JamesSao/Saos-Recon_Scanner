from .. import APP_NAME, VERSION

HELP_TEXT = f"""\
{APP_NAME} — Help & Guide

Overview
- Quick reconnaissance on a target domain, IP, or URL.
- Combines passive OSINT lookups with optional active checks.

Options
- Target: Domain (example.com), subdomain, IP (1.2.3.4), or full URL (https://site.com).
- Small subdomain brute (active): Tries a small wordlist (www, mail, api, …). Skipped for known shared-hosting roots.
- Try DNS AXFR (active): Attempts zone transfer on NS records.
- IP geolocation: Uses IP-API to get rough location and ISP.
- Active MX banners: Connects to mail servers (25/tcp) to read greeting banner.
- Banner ports: Comma-separated ports to grab simple banners from (e.g., 22,80,443). Blank = none.
- Shodan API key: If provided, enriches IP data. Skipped in Anonymise mode.
- Proxy: Route traffic via http:// or socks5:// (e.g., Burp/Tor).
- Anonymise: Disables external OSINT APIs and uses a minimal User-Agent.

Tabs
- Activity Log: Real-time actions during the run.
- Summary: Human-readable recap (IPs, DNS, headers, endpoints, etc.).
- JSON: Raw results with a search box.
- Endpoints: All discovered endpoints (grouped).
- Diff: Compare a previous JSON file with current results.

Ethics
- Use only on systems you own or have explicit permission to test.
- Active checks may be logged by targets.
- For learning, the OWASP Juice Shop instance is a safe target.

Defaults & Behavior
- Timeout: 6s | Request pause: 0.4s | UA: {APP_NAME}/GUI-{VERSION} (minimal UA in Anonymise)
- Shared-hosting roots (e.g., herokuapp.com) skip noisy brute-force by default.
- Anonymise mode skips crt.sh, BufferOver, Wayback, and JS precrawl.
"""
