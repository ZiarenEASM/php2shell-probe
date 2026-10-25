# Security Policy

This tool is a vulnerability *detector*, not the vulnerability itself — but bugs in how it
constructs requests or parses responses could still have security implications for someone
running it against infrastructure they don't fully trust (e.g. SSRF-style redirect handling, or a
malformed-response parsing issue).

## Reporting

Please report security issues in this project **privately** using GitHub's
[private vulnerability reporting](https://github.com/ZiarenEASM/php2shell-probe/security/advisories/new)
(Security tab → "Report a vulnerability") rather than opening a public issue. Include:
- Affected version/commit.
- Steps to reproduce.
- Impact as you see it.

We'll acknowledge within a few business days.

## Reporting the underlying PHP2Shell CVEs

This project does not handle disclosure for CVE-2026-109618 / CVE-2026-109619 themselves — those
are already public. See the [PHP security advisory](https://www.php.net/index.php#2026-10-21-5)
and upgrade to a patched version if you haven't already.
