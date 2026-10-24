"""Passive version-fingerprint detector for PHP2Shell (CVE-2026-109618 / CVE-2026-109619).

This module sends a single, ordinary HTTP request and reads the `X-Powered-By`
response header. It never sends malformed input and never attempts to trigger
the underlying memory-exhaustion condition — see `nuclei_runner.py` for the
opt-in active probe. This file is safe to run broadly against infrastructure
you are authorized to inventory.
"""

from __future__ import annotations

import re
import socket
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Optional

# Earliest patched patch-version per PHP minor branch, per the 2026-10-21 advisory.
# A version is vulnerable if it matches a known-affected branch and its patch
# number is below the fixed one. Any branch older than the oldest one listed
# here is end-of-life upstream and has no fixed version to compare against; a
# PHP signal on one of those branches is reported as "confirmed" directly.
FIXED_VERSIONS = {
    (8, 2): 35,
    (8, 3): 36,
    (8, 4): 27,
    (8, 5): 12,
}

# The oldest branch with a fixed version above. Every branch strictly older
# (by tuple comparison — this covers 8.1, 8.0, 7.x, 5.x, 4.x, ... with no
# upper bound) is EOL and reported "confirmed" directly, rather than relying
# on an enumerated set that would need updating every time an older branch
# needed to be added.
_OLDEST_SUPPORTED_BRANCH = min(FIXED_VERSIONS)

_POWERED_BY_RE = re.compile(r"^PHP/(\d+)\.(\d+)\.(\d+)", re.IGNORECASE)

USER_AGENT = "php2shell-probe/0.1 (+https://github.com/ZiarenEASM/php2shell-probe)"

VERDICT_CONFIRMED = "confirmed"
VERDICT_PROBABLE = "probable"
VERDICT_NOT_DETECTED = "not_detected"
VERDICT_UNKNOWN = "unknown"


@dataclass
class Result:
    target: str
    verdict: str
    php_version: Optional[str]
    detail: str


def _parse_php_version(powered_by: str) -> Optional[tuple]:
    m = _POWERED_BY_RE.match(powered_by.strip())
    if not m:
        return None
    return (int(m.group(1)), int(m.group(2)), int(m.group(3)))


def _version_verdict(version: tuple) -> str:
    major, minor, patch = version
    branch = (major, minor)
    fixed_patch = FIXED_VERSIONS.get(branch)
    if fixed_patch is not None:
        return VERDICT_CONFIRMED if patch < fixed_patch else VERDICT_NOT_DETECTED
    if branch < _OLDEST_SUPPORTED_BRANCH:
        # Any branch older than our oldest fixed-version entry (5.x, 6.x,
        # 7.x, 8.0, 8.1, ...) is EOL upstream with no patched release to
        # compare against.
        return VERDICT_CONFIRMED
    # A branch newer than everything in our table (e.g. a future 8.6) —
    # don't claim a verdict we can't support from the advisory data we have.
    return VERDICT_PROBABLE


def fingerprint(target: str, timeout: float = 10.0) -> Result:
    """Send one ordinary GET request and classify the target from its headers.

    Never raises for network/HTTP errors — those are folded into `unknown`,
    since a blocked or erroring request carries no reliable PHP signal either
    way (it is not evidence of absence).
    """
    url = target if "://" in target else f"https://{target}"
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    ctx = ssl.create_default_context()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            headers = resp.headers
    except urllib.error.HTTPError as exc:
        # A non-2xx/3xx response (e.g. a WAF returning 403) still carries
        # response headers, and the backend may well have stamped
        # X-Powered-By before the WAF intercepted the body. Reading those
        # headers can turn an apparent block into a real verdict instead of
        # discarding the signal as a plain network failure.
        headers = exc.headers
    except (urllib.error.URLError, socket.timeout, ssl.SSLError, ValueError) as exc:
        return Result(target, VERDICT_UNKNOWN, None, f"request failed: {exc}")

    powered_by = headers.get("X-Powered-By", "") if headers else ""
    server = headers.get("Server", "") if headers else ""

    if powered_by:
        version = _parse_php_version(powered_by)
        if version is not None:
            verdict = _version_verdict(version)
            version_str = ".".join(str(p) for p in version)
            return Result(target, verdict, version_str, f"X-Powered-By: {powered_by}")
        # Header present but didn't match the PHP/<version> shape.
        if "php" in powered_by.lower():
            return Result(target, VERDICT_PROBABLE, None, f"X-Powered-By: {powered_by} (unparsed version)")
        return Result(target, VERDICT_NOT_DETECTED, None, f"X-Powered-By: {powered_by} (not PHP)")

    # No X-Powered-By header: most PHP installs ship it by default, but it's
    # routinely stripped by reverse proxies, CDNs and WAFs. A missing header
    # is not evidence the backend isn't PHP, so we never report "clean" here.
    if _looks_php_by_other_signals(server):
        return Result(target, VERDICT_PROBABLE, None, "PHP-like signal without version header")
    return Result(target, VERDICT_UNKNOWN, None, "no X-Powered-By header; version undetermined")


def _looks_php_by_other_signals(server_header: str) -> bool:
    # Conservative: only flag "probable" on signals that specifically imply a
    # PHP-serving stack, not generic web-server banners.
    return "php" in server_header.lower()
