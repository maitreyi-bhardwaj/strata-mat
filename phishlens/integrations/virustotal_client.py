"""
Optional VirusTotal URL reputation lookups.

Privacy and safety decisions
----------------------------
* Off by default. Runs only if VIRUSTOTAL_API_KEY is set AND the user ticks
  the consent box for that investigation.
* Sends ONLY the individual URL, never the email.
* Uses the *lookup* endpoint (has VirusTotal seen this URL before?). It does
  not submit new URLs for scanning, because submitted URLs become visible
  to other VirusTotal users, which could leak private links (e.g. password
  reset tokens).
* PhishLens itself still never visits the URL; VirusTotal's servers hold
  the reputation data.
* "Not found" and "error" are reported as such, never as "clean".
* Free API keys allow 4 requests/minute; we enforce that locally and cache
  results for an hour to avoid repeat requests.
"""

from __future__ import annotations

import base64
import hashlib
import logging
import threading
import time
from dataclasses import dataclass

from integrations.settings import get_secret

logger = logging.getLogger(__name__)

API_URL = "https://www.virustotal.com/api/v3/urls/{}"
TIMEOUT_SECONDS = 10
MAX_REQUESTS_PER_MINUTE = 4
CACHE_TTL_SECONDS = 3600
MAX_URLS_PER_INVESTIGATION = 4


@dataclass(frozen=True)
class ReputationResult:
    url: str
    status: str            # "malicious" | "suspicious" | "no_detections" | "not_found" | "rate_limited" | "unavailable"
    malicious: int = 0
    suspicious: int = 0
    harmless: int = 0
    undetected: int = 0
    message: str = ""

    @property
    def label(self) -> str:
        return {
            "malicious": f"Flagged as malicious by {self.malicious} security vendor(s)",
            "suspicious": f"Flagged as suspicious by {self.suspicious} vendor(s)",
            "no_detections": "No vendor flagged this URL (not proof of safety; new phishing sites are often unknown)",
            "not_found": "Unknown to VirusTotal (no previous analysis); not a clean result",
            "rate_limited": "Not checked: rate limit reached, try again in a minute",
            "unavailable": f"Check unavailable: {self.message}",
        }.get(self.status, self.status)


class _RateLimiter:
    def __init__(self, per_minute: int) -> None:
        self.per_minute = per_minute
        self.calls: list[float] = []
        self.lock = threading.Lock()

    def try_acquire(self) -> bool:
        with self.lock:
            now = time.monotonic()
            self.calls = [t for t in self.calls if now - t < 60]
            if len(self.calls) >= self.per_minute:
                return False
            self.calls.append(now)
            return True


_limiter = _RateLimiter(MAX_REQUESTS_PER_MINUTE)
_cache: dict[str, tuple[float, ReputationResult]] = {}


def is_configured() -> bool:
    return bool(get_secret("VIRUSTOTAL_API_KEY"))


def _url_id(url: str) -> str:
    """VirusTotal identifies a URL by its unpadded URL-safe base64 encoding."""
    return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")


def lookup_url(url: str) -> ReputationResult:
    key = get_secret("VIRUSTOTAL_API_KEY")
    if not key:
        return ReputationResult(url, "unavailable", message="no API key configured")

    cache_key = hashlib.sha256(url.encode()).hexdigest()
    cached = _cache.get(cache_key)
    if cached and time.time() - cached[0] < CACHE_TTL_SECONDS:
        return cached[1]

    if not _limiter.try_acquire():
        return ReputationResult(url, "rate_limited")

    import requests  # imported lazily so the app runs without it

    try:
        resp = requests.get(
            API_URL.format(_url_id(url)),
            headers={"x-apikey": key, "accept": "application/json"},
            timeout=TIMEOUT_SECONDS,
            allow_redirects=False,
        )
    except requests.Timeout:
        return ReputationResult(url, "unavailable", message="VirusTotal timed out")
    except requests.RequestException as exc:
        logger.warning("VirusTotal request failed: %s", type(exc).__name__)
        return ReputationResult(url, "unavailable", message="network error")

    # Log the status code only; the URL itself may be private.
    logger.info("VirusTotal lookup status=%d", resp.status_code)
    if resp.status_code == 404:
        result = ReputationResult(url, "not_found")
    elif resp.status_code == 429:
        return ReputationResult(url, "rate_limited")
    elif resp.status_code in (401, 403):
        return ReputationResult(url, "unavailable", message="API key rejected")
    elif resp.status_code != 200:
        return ReputationResult(url, "unavailable", message=f"HTTP {resp.status_code}")
    else:
        try:
            stats = resp.json()["data"]["attributes"]["last_analysis_stats"]
        except (ValueError, KeyError, TypeError):
            return ReputationResult(url, "unavailable", message="unexpected response format")
        mal, sus = int(stats.get("malicious", 0)), int(stats.get("suspicious", 0))
        status = "malicious" if mal else "suspicious" if sus else "no_detections"
        result = ReputationResult(url, status, mal, sus, int(stats.get("harmless", 0)),
                                  int(stats.get("undetected", 0)))

    if len(_cache) > 500:
        _cache.clear()
    _cache[cache_key] = (time.time(), result)
    return result


def lookup_urls(urls: list[str]) -> list[ReputationResult]:
    """Look up at most MAX_URLS_PER_INVESTIGATION distinct URLs."""
    unique = list(dict.fromkeys(urls))[:MAX_URLS_PER_INVESTIGATION]
    return [lookup_url(u) for u in unique]
