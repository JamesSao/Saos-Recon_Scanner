import re
import socket
import ssl
import time
from collections import defaultdict
from urllib.parse import urljoin
from datetime import datetime, timezone

# Third-party deps
import requests
import dns.resolver, dns.query, dns.zone
import whois
import tldextract
from bs4 import BeautifulSoup
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import mmh3

# Local modules
from .config import get_anonymise, user_agent
from .utils import safe_get
from .constants import (
    SEC_HEADERS, ENDPOINT_RE, DEFAULT_BRUTE_WORDS, SHARED_ROOTS,
    CRT_SH_URL, BUFFEROVER_URL, IP_GEO_URL, BGPVIEW_IP_URL,
    WAYBACK_COUNT_ROOT, WAYBACK_COUNT_WC
)

# ---------- primitives ----------
def precrawl_js_and_extract(hostname, log=lambda s: None, timeout=6):
    if get_anonymise():
        log("[precrawl] skipped due to anonymise mode")
        return {"homepage_fetched": False, "scripts": [], "endpoints": []}

    results = {"homepage_fetched": False, "scripts": [], "endpoints": []}
    headers = {"User-Agent": user_agent()}
    for scheme in ("https://", "http://"):
        base = f"{scheme}{hostname}"
        r = safe_get(base, headers=headers, timeout=timeout)
        if not r or r.status_code >= 400:
            continue
        results["homepage_fetched"] = True
        log(f"[precrawl] fetched homepage ({base}) status={r.status_code}")
        soup = BeautifulSoup(r.text, "html.parser")

        scripts = []
        for s in soup.find_all("script"):
            src = s.get("src")
            if src:
                scripts.append(urljoin(r.url, src))

        endpoints = set()
        for m in ENDPOINT_RE.finditer(r.text):
            g = m.groupdict()
            for k in ("url","abs","fetchpath"):
                if g.get(k): endpoints.add(g.get(k))

        headers_js = {"User-Agent": user_agent(), "Referer": r.url}
        if scripts:
            log(f"[precrawl] found {len(scripts)} script(s); fetching up to 12")
        for s_url in scripts[:12]:
            rr = safe_get(s_url, headers=headers_js, timeout=timeout)
            if rr and rr.status_code == 200:
                for m in ENDPOINT_RE.finditer(rr.text):
                    g = m.groupdict()
                    for k in ("url","abs","fetchpath"):
                        if g.get(k): endpoints.add(g.get(k))
            else:
                log(f"[precrawl] script fetch {s_url} -> status {rr.status_code if rr else 'no response'}")

        results["scripts"] = scripts
        results["endpoints"] = sorted(endpoints)
        return results

    log("[precrawl] homepage fetch failed or non-200")
    return results

def get_dns_records(domain):
    resolver = dns.resolver.Resolver()
    resolver.timeout = 3
    resolver.lifetime = 6
    types = ["A","AAAA","MX","NS","TXT","CNAME","SOA","CAA","DS"]
    results = defaultdict(list)
    ttls = {}
    for t in types:
        try:
            answers = resolver.resolve(domain, t)
            if answers.rrset is not None and hasattr(answers.rrset, "ttl"):
                ttls[t] = int(answers.rrset.ttl)
            for r in answers:
                results[t].append(r.to_text().strip('"'))
        except Exception:
            pass
    return dict(results), ttls

def attempt_axfr(ns, domain):
    try:
        axfr = dns.query.xfr(ns, domain, lifetime=8)
        z = dns.zone.from_xfr(axfr)
        records = []
        for name, node in z.nodes.items():
            for rdataset in node.rdatasets:
                for rdata in rdataset.items:
                    records.append(f"{name.to_text()} {rdataset.rdtype} {rdata.to_text()}")
        return records
    except Exception:
        return None

def query_crtsh_subdomains(domain):
    if get_anonymise(): return []
    r = safe_get(CRT_SH_URL.format(domain=domain))
    if not r or r.status_code != 200: return []
    subs = set()
    try:
        for entry in r.json():
            for n in (entry.get("name_value","") or "").splitlines():
                n = n.strip().lower()
                if n.endswith(domain): subs.add(n)
    except Exception:
        return []
    return sorted(subs)

def query_bufferover_subdomains(domain):
    if get_anonymise(): return []
    r = safe_get(BUFFEROVER_URL.format(domain=domain))
    if not r or r.status_code != 200: return []
    agg = set()
    try:
        j = r.json()
        for key in ("FDNS_A","RDNS","FDNS_CNAME"):
            for line in j.get(key, []) or []:
                try:
                    host = line.split(",")[1].strip().lower()
                    if host.endswith(domain): agg.add(host)
                except Exception:
                    pass
    except Exception:
        return []
    return sorted(agg)

def brute_subdomains(domain, wordlist, log=None):
    results = []
    resolver = dns.resolver.Resolver()
    resolver.timeout = 2
    resolver.lifetime = 4
    for w in wordlist:
        host = f"{w}.{domain}"
        try:
            answers = resolver.resolve(host, "A")
            ips = [r.to_text() for r in answers]
            results.append({"subdomain": host, "ips": ips})
            if log: log(f"[brute] {host} -> {ips}")
        except Exception:
            pass
    return results

def get_whois(domain):
    try:
        w = whois.whois(domain)
        return {
            "domain_name": w.get("domain_name"),
            "registrar": w.get("registrar"),
            "whois_server": w.get("whois_server"),
            "creation_date": str(w.get("creation_date")),
            "expiration_date": str(w.get("expiration_date")),
            "name_servers": w.get("name_servers"),
            "emails": w.get("emails"),
        }
    except Exception:
        return {"error": "whois lookup failed or rate-limited"}

def summarize_security_headers(headers):
    h = {k.lower(): v for k,v in headers.items()}
    present = {k: h.get(k) for k in SEC_HEADERS}
    score = 0
    if h.get("strict-transport-security"): score += 2
    if h.get("content-security-policy"): score += 3
    if h.get("x-frame-options") or ("content-security-policy" in h and "frame-ancestors" in h["content-security-policy"].lower()): score += 1
    if h.get("x-content-type-options"): score += 1
    if h.get("referrer-policy"): score += 1
    if h.get("permissions-policy"): score += 1
    if h.get("cross-origin-opener-policy"): score += 1
    if h.get("cross-origin-embedder-policy"): score += 1
    if h.get("cross-origin-resource-policy"): score += 1
    grade = "F"
    if score >= 9: grade = "A"
    elif score >= 7: grade = "B"
    elif score >= 5: grade = "C"
    elif score >= 3: grade = "D"
    cors = h.get("access-control-allow-origin")
    cors_flag = "wildcard (*)" if cors == "*" else (cors if cors else "none")
    return {"present": present, "score": score, "grade": grade, "cors": cors_flag}

def fetch_http_info(hostname):
    headers = {"User-Agent": user_agent()}
    info = {}
    for scheme in ("https://", "http://"):
        url = f"{scheme}{hostname}"
        r = safe_get(url, headers=headers, timeout=8)
        if not r: continue
        info["url"] = r.url
        info["status_code"] = r.status_code
        info["server_headers"] = {k: v for k,v in r.headers.items()
                                  if k.lower() in ("server","x-powered-by","content-type","via","x-cache","x-akamai-transformed")}
        info["security_headers"] = summarize_security_headers(r.headers)
        soup = BeautifulSoup(r.content, "html.parser")
        info["title"] = soup.title.string.strip() if soup.title and soup.title.string else ""

        tech = set()
        gen = soup.find("meta", attrs={"name":"generator"})
        if gen and gen.get("content"): tech.add(gen.get("content"))
        html_text = r.text.lower()
        hints = [
            ("wp-content", "WordPress"), ("wp-includes","WordPress"),
            ("drupal.settings","Drupal"), ("/sites/all/","Drupal"),
            ("/static/","Generic Static"), ("x-drupal-cache","Drupal"),
            ("x-varnish", "Varnish"), ("cloudflare","Cloudflare")
        ]
        for token,label in hints:
            if token in html_text or token in " ".join([f"{k}:{v}".lower() for k,v in r.headers.items()]):
                tech.add(label)
        info["tech_fingerprint"] = sorted(list(tech))

        cookies = r.headers.get("set-cookie", "")
        info["cookies_check"] = {
            "secure": "secure" in cookies.lower(),
            "httponly": "httponly" in cookies.lower(),
            "samesite": ("samesite" in cookies.lower())
        }

        robots = safe_get(urljoin(r.url, "/robots.txt"))
        info["robots_txt"] = robots.text[:1500] if robots and robots.status_code == 200 else None
        disallow, allow = [], []
        if robots and robots.status_code == 200:
            for line in robots.text.splitlines():
                line=line.strip()
                if line.lower().startswith("disallow:"):
                    disallow.append(line.split(":",1)[1].strip())
                if line.lower().startswith("allow:"):
                    allow.append(line.split(":",1)[1].strip())
        info["robots_parsed"] = {"disallow": disallow[:50], "allow": allow[:50]}

        sm = safe_get(urljoin(r.url, "/sitemap.xml"))
        if sm and sm.status_code == 200:
            txt = sm.text
            info["sitemap"] = txt[:2000]
            info["sitemap_url_count_est"] = txt.count("<url>")
        else:
            info["sitemap"] = None

        fav = safe_get(urljoin(r.url, "/favicon.ico"), stream=True)
        if fav and fav.status_code == 200:
            raw = fav.content
            try:
                info["favicon_mmh3"] = mmh3.hash(raw)
            except Exception:
                info["favicon_mmh3"] = None
        else:
            info["favicon_mmh3"] = None
        return info
    return {"error": "no http(s) response"}

def get_cert_info(hostname):
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
            s.settimeout(6)
            s.connect((hostname, 443))
            der = s.getpeercert(True)
        cert = x509.load_der_x509_certificate(der, default_backend())
        nb = cert.not_valid_before.replace(tzinfo=timezone.utc).isoformat()
        na = cert.not_valid_after.replace(tzinfo=timezone.utc).isoformat()
        issuer = cert.issuer.rfc4514_string()
        subject = cert.subject.rfc4514_string()
        sans = []
        try:
            ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            sans = ext.value.get_values_for_type(x509.DNSName)
        except Exception:
            pass
        return {"issuer": issuer,"subject": subject,"not_before": nb,"not_after": na,"san": sans}
    except Exception:
        return {"error": "tls fetch failed"}

def probe_weak_tls(hostname):
    out = {"tls1_0": False, "tls1_1": False}
    for proto, field in ((ssl.PROTOCOL_TLSv1, "tls1_0"), (ssl.PROTOCOL_TLSv1_1, "tls1_1")):
        try:
            ctx = ssl.SSLContext(proto)
            with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
                s.settimeout(5)
                s.connect((hostname,443))
                s.recv(1)
            out[field] = True
        except Exception:
            out[field] = False
    return out

def reverse_ip_lookup(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None

def ip_geolocate(ip):
    r = safe_get(IP_GEO_URL.format(ip=ip))
    if not r: return {"error": "geo lookup failed"}
    try:
        data = r.json()
        if data.get("status") != "success":
            return {"error": data.get("message", "fail")}
        return data
    except Exception:
        return {"error": "geo lookup failed"}

def ip_asn(ip):
    r = safe_get(BGPVIEW_IP_URL.format(ip=ip))
    if r and r.status_code == 200:
        try:
            j = r.json().get("data") or {}
            prefixes = j.get("prefixes") or []
            if prefixes:
                p = prefixes[0]
                asn = p.get("asn") or {}
                return {"asn": asn.get("asn"), "asn_name": asn.get("name"), "prefix": p.get("prefix")}
        except Exception:
            pass
    return {}

def parse_spf_dmarc(txt_records):
    spf = None
    for t in txt_records:
        low = t.lower()
        if low.startswith("v=spf1"):
            spf = t; break
    details = {}
    if spf:
        tokens = spf.split()
        details["mechanisms"] = [tok for tok in tokens if ":" in tok or tok.endswith("all")]
        details["enforcement"] = next((tok for tok in tokens if tok.endswith("all")), None)
    return {"spf": spf, "spf_details": details}

def expand_spf(domain, depth=0, seen=None, resolver=None):
    if seen is None: seen = set()
    if resolver is None:
        resolver = dns.resolver.Resolver(); resolver.timeout = 3; resolver.lifetime = 6
    if depth > 5: return {"includes": [], "ip4": [], "ip6": []}
    spf_txt = None
    try:
        ans = resolver.resolve(domain, "TXT")
        for r in ans:
            txt = r.to_text().strip('"')
            if txt.lower().startswith("v=spf1"): spf_txt = txt; break
    except Exception:
        return {"includes": [], "ip4": [], "ip6": []}
    if not spf_txt: return {"includes": [], "ip4": [], "ip6": []}
    includes, ip4, ip6 = [], [], []
    for tok in spf_txt.split():
        if tok.startswith("include:"):
            sub = tok.split(":",1)[1]
            if sub not in seen:
                seen.add(sub); includes.append(sub)
                subexp = expand_spf(sub, depth+1, seen, resolver)
                includes += subexp.get("includes",[]); ip4 += subexp.get("ip4",[]); ip6 += subexp.get("ip6",[])
        elif tok.startswith("ip4:"):
            ip4.append(tok.split(":",1)[1])
        elif tok.startswith("ip6:"):
            ip6.append(tok.split(":",1)[1])
    return {"includes": sorted(set(includes)), "ip4": sorted(set(ip4)), "ip6": sorted(set(ip6))}

def get_dmarc_policy(domain):
    try:
        name = f"_dmarc.{domain}"
        answers = dns.resolver.resolve(name, "TXT")
        txt_pieces = []
        for a in answers:
            if hasattr(a, "strings") and a.strings:
                for b in a.strings:
                    txt_pieces.append(b.decode() if isinstance(b, bytes) else b)
            else:
                txt_pieces.append(a.to_text().strip('"'))
        txt = " ".join(txt_pieces).strip()
        policy = {}
        for kv in txt.split(";"):
            kv = kv.strip()
            if "=" in kv:
                k, v = kv.split("=", 1)
                policy[k.strip().lower()] = v.strip()
        policy["_raw"] = txt
        return policy
    except Exception:
        return {}

def try_common_dkim_selectors(domain):
    selectors = ["default","google","selector1","selector2","s1","s2","m1","m2"]
    results = {}
    for sel in selectors:
        name = f"{sel}._domainkey.{domain}"
        try:
            ans = dns.resolver.resolve(name, "TXT")
            cur = []
            for r in ans:
                txt = r.to_text().strip('"').replace('" "','')
                cur.append(txt)
            joined = " ".join(cur)
            m = re.search(r"p=([A-Za-z0-9+/=]+)", joined)
            if m:
                key_b64 = m.group(1)
                bits = int(len(key_b64) * 6 * 0.75)
                results[sel] = {"approx_bits": bits, "_raw": joined[:200]}
        except Exception:
            pass
    return results

def banner_grab(ip, port, timeout=4):
    try:
        s = socket.socket(); s.settimeout(timeout); s.connect((ip, port))
        if port in (80, 8080):
            s.sendall(b"GET / HTTP/1.0\r\nHost: %b\r\nUser-Agent: %b\r\n\r\n" %
                      (ip.encode(), user_agent().encode()))
        if port == 443:
            ctx = ssl.create_default_context()
            s_tls = ctx.wrap_socket(s, server_hostname=ip)
            s_tls.sendall(b"GET / HTTP/1.0\r\nHost: %b\r\nUser-Agent: %b\r\n\r\n" %
                          (ip.encode(), user_agent().encode()))
            data = s_tls.recv(1024); s_tls.close(); return data.decode(errors="ignore").strip()
        data = s.recv(1024); s.close(); return data.decode(errors="ignore").strip()
    except Exception:
        return None

def mx_banner(host, timeout=4):
    try:
        s = socket.socket(); s.settimeout(timeout); s.connect((host, 25))
        data = s.recv(200).decode(errors="ignore").strip(); s.close(); return data
    except Exception:
        return None

def shodan_enrich(ip, api_key):
    if not api_key: return {"error": "no api key provided"}
    try:
        url = f"https://api.shodan.io/shodan/host/{ip}?key={api_key}"
        r = safe_get(url); 
        if not r or r.status_code != 200:
            return {"error": f"shodan failed ({r.status_code if r else 'no response'})"}
        return r.json()
    except Exception:
        return {"error": "shodan request failed"}

def wayback_counts(domain):
    def fetch(url):
        r = safe_get(url, timeout=8)
        if r and r.status_code == 200:
            m = re.search(r"(\d+)", r.text)
            return int(m.group(1)) if m else 0
        return 0
    if get_anonymise(): 
        return {"root_pages": 0, "wildcard_pages": 0}
    return {
        "root_pages": fetch(WAYBACK_COUNT_ROOT.format(domain=domain)),
        "wildcard_pages": fetch(WAYBACK_COUNT_WC.format(domain=domain)),
    }

# ---------- coordinator ----------
def run_recon(target, flags, log=lambda s: None):
    ts = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    out = {"target": target, "timestamp": ts, "tool_version": "Saos-Recon_Scanner-gui-2.2"}

    is_ip = re.match(r"^\d{1,3}(\.\d{1,3}){3}$", target) is not None or ":" in target
    host = target
    root_domain = None
    if not is_ip:
        te = tldextract.extract(host)
        root_domain = f"{te.domain}.{te.suffix}" if te.suffix else host
        out["root_domain"] = root_domain
    out["host"] = host

    # 1) Pre-crawl
    out["precrawl"] = {}
    if not is_ip:
        log("[*] Pre-crawl (homepage + JS asset extraction)...")
        out["precrawl"] = precrawl_js_and_extract(host, log=log)

    # 2) DNS
    out["dns"], out["dns_ttls"] = {}, {}
    if root_domain:
        log("[+] DNS lookup (root domain)...")
        dnsrec, ttls = get_dns_records(root_domain)
        out["dns"] = dnsrec; out["dns_ttls"] = ttls

    # 3) Passive subs
    out["crtsh_subdomains"] = []
    out["bufferover_subdomains"] = []
    out["subdomains_all"] = []
    if root_domain:
        log("[+] Subdomains (crt.sh + BufferOver)...")
        crt = query_crtsh_subdomains(root_domain)
        bo  = query_bufferover_subdomains(root_domain)
        out["crtsh_subdomains"] = crt; out["bufferover_subdomains"] = bo
        out["subdomains_all"] = sorted(set(crt) | set(bo))

    # 4) Brute
    out["bruteforce_results"] = []
    if flags.get("bruteforce") and root_domain:
        if root_domain in SHARED_ROOTS:
            log("[!] Skipping brute: shared hosting root detected")
        else:
            log("[*] Brute-forcing small subdomain list...")
            words = flags.get("brute_words") or DEFAULT_BRUTE_WORDS
            out["bruteforce_results"] = brute_subdomains(root_domain, words, log=log)

    # 5) WHOIS
    if not flags.get("skip_whois") and root_domain:
        log("[+] WHOIS lookup..."); out["whois"] = get_whois(root_domain)
    else:
        out["whois"] = {"skipped": True}

    # 6) HTTP
    out["http"] = fetch_http_info(host) if not is_ip else {}

    # 7) TLS
    if not is_ip:
        log("[+] TLS certificate..."); out["tls_cert"] = get_cert_info(host)
        log("[+] TLS weak protocol probe..."); out["tls_weak_protocols"] = probe_weak_tls(host)
    else:
        out["tls_cert"] = {}; out["tls_weak_protocols"] = {"tls1_0": False, "tls1_1": False}

    # 8) Mail policies
    out["mail_policy"] = {}
    if root_domain:
        txts = out["dns"].get("TXT", [])
        out["mail_policy"] = parse_spf_dmarc(txts)
        out["mail_policy"]["spf_expanded"] = expand_spf(root_domain)
        out["mail_policy"]["dmarc_record"] = get_dmarc_policy(root_domain)
        out["mail_policy"]["dkim_guess"] = try_common_dkim_selectors(root_domain)

    # 9) AXFR
    out["axfr"] = {}
    if flags.get("axfr") and root_domain:
        log("[*] Attempting AXFR (zone transfer) on NS...")
        ns_records = out["dns"].get("NS", [])
        axfr_map = {}
        for ns in ns_records:
            try:
                ns_ip = socket.gethostbyname(ns)
            except Exception:
                ns_ip = ns
            records = attempt_axfr(ns_ip, root_domain)
            if records: log(f"[axfr] SUCCESS on {ns} ({len(records)} records)")
            axfr_map[ns] = records
        out["axfr"] = axfr_map

    # 10) Resolve host A/AAAA -> ips
    ips = []
    if is_ip:
        ips = [host]
    else:
        try:
            res = dns.resolver.Resolver()
            for qtype in ("A","AAAA"):
                try:
                    ans = res.resolve(host, qtype)
                    for r in ans: ips.append(r.to_text())
                except Exception:
                    pass
        except Exception:
            pass

    # 11) IP enrichment
    ip_info = {}
    for ip in set(ips):
        ipdict = {"reverse_dns": reverse_ip_lookup(ip)}
        if get_anonymise(): asn_info, org = {}, None
        else:
            asn_info = ip_asn(ip) or {}; org = asn_info.get("asn_name")
        ipdict["org"] = org; ipdict["asn"] = asn_info

        if flags.get("geo") and not get_anonymise():
            ipdict["geo"] = ip_geolocate(ip)
        if flags.get("shodan_key") and not get_anonymise():
            log(f"[*] Shodan enrich {ip}..."); ipdict["shodan"] = shodan_enrich(ip, flags["shodan_key"])
        ip_info[ip] = ipdict
    out["ip_info"] = ip_info

    # 12) Banners
    out["banners"] = {}
    ports = flags.get("ports") or []
    if ports and ips:
        log("[*] Banner grabbing (light)...")
        for ip in set(ips):
            banners = {}
            for p in ports:
                banners[str(p)] = banner_grab(ip, p)
                if banners[str(p)]: log(f"[banner] {ip}:{p} -> {banners[str(p)][:90]}")
            out["banners"][ip] = banners

    # 13) MX banners
    out["mx_banners"] = {}
    if flags.get("mx_banners") and root_domain and out["dns"].get("MX"):
        log("[*] MX banners (25/tcp)...")
        for mx in out["dns"]["MX"]:
            host_mx = mx.split()[-1].strip(".")
            out["mx_banners"][host_mx] = mx_banner(host_mx)

    # 14) Wayback
    out["wayback"] = wayback_counts(root_domain) if root_domain else {}

    # Summary
    out["summary"] = {
        "target": target,
        "ips": list(sorted(set(ips))),
        "subdomain_count": len(out.get("subdomains_all", [])),
        "http_title": out.get("http", {}).get("title"),
        "whois_registrar": out.get("whois", {}).get("registrar") if out.get("whois") else None,
        "sec_headers_grade": (out.get("http", {}).get("security_headers") or {}).get("grade"),
        "tls_weak": out.get("tls_weak_protocols"),
    }
    log("[✓] Done."); return out
