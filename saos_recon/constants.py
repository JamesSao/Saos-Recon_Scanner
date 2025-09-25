# Static constants that don't change at runtime.
from re import compile, VERBOSE, IGNORECASE

USER_AGENT_BASE = "Saos-Recon_Scanner/GUI-2.2"
DEFAULT_TIMEOUT = 6
QPAUSE = 0.4

CRT_SH_URL = "https://crt.sh/?q=%25.{domain}&output=json"
BUFFEROVER_URL = "https://dns.bufferover.run/dns?q={domain}"
IP_GEO_URL = "http://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,lat,lon,isp,org,as,query"
BGPVIEW_IP_URL = "https://api.bgpview.io/ip/{ip}"
WAYBACK_COUNT_ROOT = "https://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&limit=0&showNumPages=true"
WAYBACK_COUNT_WC   = "https://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&limit=0&showNumPages=true"

DEFAULT_BRUTE_WORDS = [
    "www","mail","smtp","admin","webmail","api","dev","stage",
    "shop","blog","portal","auth","db","vpn"
]

# Common shared hosting roots — don't brute-force these by default.
SHARED_ROOTS = {
    "herokuapp.com", "github.io", "cloudfront.net", "azurewebsites.net",
    "netlify.app", "vercel.app", "pages.dev", "firebaseapp.com",
    "appspot.com", "onrender.com", "glitch.me"
}

SEC_HEADERS = [
    "strict-transport-security","content-security-policy","x-frame-options",
    "x-content-type-options","referrer-policy","permissions-policy","x-xss-protection",
    "cross-origin-opener-policy","cross-origin-embedder-policy","cross-origin-resource-policy",
    "access-control-allow-origin"
]

# JS endpoint regex
ENDPOINT_RE = compile(
    r"""(?:
        (?:"|')(?P<url>/[A-Za-z0-9_\-./]{2,200})(?:"|')|
        (?:"|')(?P<abs>https?://[A-Za-z0-9_.:/?=%&\-\+]{4,400})(?:"|')|
        (?P<fetch>fetch\(\s*['"](?P<fetchpath>/[A-Za-z0-9_\-./?=%&\[\]\(\)]{2,300})['"])|
        (?P<xhr>XMLHttpRequest\(|new\s+XMLHttpRequest)
    )""",
    VERBOSE | IGNORECASE
)
