import time
import requests
from urllib.parse import urlparse
from .config import user_agent, get_proxies
from .constants import QPAUSE, DEFAULT_TIMEOUT

def normalize_target(raw: str) -> str:
    if not raw:
        return raw
    t = raw.strip()
    try:
        if "://" in t or t.startswith("//"):
            p = urlparse(t)
            if p.hostname:
                return p.hostname
    except Exception:
        pass
    if "/" in t:
        t = t.split("/", 1)[0]
    if t.startswith("//"):
        t = t.lstrip("//").split("/", 1)[0]
    if ":" in t and t.count(":") == 1 and "[" not in t:
        host, maybe_port = t.split(":", 1)
        if maybe_port.isdigit():
            return host
    return t

def safe_get(url: str, headers=None, timeout: int = DEFAULT_TIMEOUT,
             allow_redirects: bool = True, stream: bool = False):
    headers = headers or {"User-Agent": user_agent()}
    try:
        r = requests.get(
            url, headers=headers, timeout=timeout,
            allow_redirects=allow_redirects, stream=stream,
            proxies=get_proxies()
        )
        time.sleep(QPAUSE)  # be polite
        return r
    except Exception:
        return None
