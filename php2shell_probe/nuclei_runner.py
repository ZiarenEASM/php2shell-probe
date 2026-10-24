"""Opt-in active crash probe: thin wrapper around Nuclei running the vendored,
community-curated PHP2Shell template.

This module does not implement the memory-exhaustion technique itself — it
shells out to `nuclei` with the unmodified template vendored at
`php2shell_probe/templates/CVE-2026-109618.yaml` (sourced from assetnote/php2shell-scanner,
see that file's header for full attribution and its upstream signature). That
separation is deliberate: the detection logic for an actively exploitable,
recently-disclosed RCE lives in one reviewable, upstream-signed YAML file,
not scattered across this project's Python code.

Calling anything in this module sends a crafted request designed to trigger
the PHP2Shell out-of-memory condition and can crash the target PHP worker.
The CLI only reaches this module when the caller passed both `--active` and
`--i-have-authorization`.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional
from urllib.parse import urlparse

# Lives inside the package itself (not repo-root) so it's included in both
# the sdist and the built wheel via [tool.setuptools.package-data] — a
# repo-root templates/ directory is outside the installed package tree and
# would silently vanish from a real `pip install`.
TEMPLATE_PATH = Path(__file__).resolve().parent / "templates" / "CVE-2026-109618.yaml"


class NucleiNotFound(RuntimeError):
    pass


class NucleiRunError(RuntimeError):
    pass


def _host_key(target: str) -> str:
    """Normalize a target/host string for matching, stripping scheme, port
    and trailing slash so 'example.org', 'https://example.org/' and
    'https://example.org:443' all compare equal. Nuclei reports matched
    hosts with scheme (and often a default port) attached regardless of how
    the target was originally supplied."""
    value = target.strip().rstrip("/")
    parsed = urlparse(value if "://" in value else f"//{value}")
    host = parsed.hostname or parsed.netloc or parsed.path
    return host.lower()


@dataclass
class ActiveResult:
    target: str
    verdict: str  # "confirmed" or "not_detected"
    cve_id: Optional[str]
    detail: str


def _require_nuclei() -> str:
    path = shutil.which("nuclei")
    if not path:
        raise NucleiNotFound(
            "nuclei was not found on PATH. Install it from "
            "https://github.com/projectdiscovery/nuclei to use --active."
        )
    return path


def run_active_probe(
    targets: List[str],
    timeout: float = 30.0,
    *,
    confirmed_authorization: bool = False,
) -> List[ActiveResult]:
    """Run the vendored Nuclei template against `targets` and return one
    ActiveResult per target. Targets with no finding are reported as
    `not_detected`, not `unknown` — this mode either triggers the condition
    or it doesn't; there is no passive "can't tell" state here (that belongs
    to detector.fingerprint for hosts you're not authorized to actively test).

    `confirmed_authorization` is the same guardrail the CLI enforces via
    `--active --i-have-authorization`, repeated here so a caller importing
    this module directly (bypassing the CLI) can't fire the crash probe
    without the same explicit acknowledgement.
    """
    if not confirmed_authorization:
        raise PermissionError(
            "run_active_probe() sends a crash-triggering probe and requires "
            "confirmed_authorization=True as an explicit acknowledgement that "
            "you are authorized to actively test every target passed in."
        )

    nuclei_path = _require_nuclei()
    if not TEMPLATE_PATH.is_file():
        raise FileNotFoundError(f"vendored template missing: {TEMPLATE_PATH}")

    cmd = [
        nuclei_path,
        "-t", str(TEMPLATE_PATH),
        "-l", "-",
        "-jsonl",
        "-silent",
        "-timeout", str(max(1, round(timeout))),
    ]
    proc = subprocess.run(
        cmd,
        input="\n".join(targets),
        capture_output=True,
        text=True,
        timeout=timeout * max(len(targets), 1) + 30,
    )
    if proc.returncode != 0:
        raise NucleiRunError(
            f"nuclei exited with status {proc.returncode}: {proc.stderr.strip() or '(no stderr)'}"
        )

    confirmed = {}
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        host = event.get("host") or event.get("matched-at") or event.get("ip")
        if not host:
            continue
        cve_ids = (event.get("info", {}) or {}).get("classification", {}).get("cve-id") or []
        confirmed[_host_key(host)] = ActiveResult(
            target=host,
            verdict="confirmed",
            cve_id=cve_ids[0] if cve_ids else "CVE-2026-109618",
            detail=event.get("matcher-name", "nuclei match"),
        )

    results = []
    for target in targets:
        hit = confirmed.get(_host_key(target))
        if hit is not None:
            results.append(ActiveResult(target, hit.verdict, hit.cve_id, hit.detail))
        else:
            results.append(ActiveResult(target, "not_detected", None, "no nuclei match"))
    return results
