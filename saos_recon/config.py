"""
Mutable runtime configuration (global state) with tiny helpers.
Keeps 'anonymise' and proxy settings in one place.
"""
from typing import Optional, Dict
from .constants import USER_AGENT_BASE

_ANONYMISE = False
_PROXIES: Optional[Dict[str, str]] = None

def set_anonymise(enabled: bool) -> None:
    global _ANONYMISE
    _ANONYMISE = bool(enabled)

def get_anonymise() -> bool:
    return _ANONYMISE

def set_proxy(url: Optional[str]) -> None:
    """Set a single proxy URL for http/https or clear with None/''."""
    global _PROXIES
    _PROXIES = {"http": url, "https": url} if url else None

def get_proxies() -> Optional[Dict[str, str]]:
    return _PROXIES

def user_agent() -> str:
    return "Recon_Scanner/anon" if _ANONYMISE else USER_AGENT_BASE
