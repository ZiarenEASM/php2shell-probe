# php2shell-probe

A focused, open-source scanning probe for **CVE-2026-109618 / CVE-2026-109619** ("PHP2Shell") —
the PHP `longjmp()` out-of-memory handling flaw that can corrupt process memory and, under the
right conditions, lead to remote code execution as the web worker account.

This tool exists because general-purpose scanners either miss this class of bug entirely or only
cover it behind a paywall/plugin. `php2shell-probe` gives defenders and researchers a single,
auditable, standalone way to answer one question across a fleet of hosts: **"is this endpoint
running a PHP version affected by PHP2Shell, and can I tell from the outside?"**

## What it does

Two independent detection modes, run separately so you always know which one you used:

1. **Version fingerprint (default, non-intrusive).** Sends an ordinary request, reads the
   `X-Powered-By` header (when the server exposes it), and compares the PHP version against the
   vendor-fixed versions (8.2.35, 8.3.36, 8.4.27, 8.5.12). No malformed input, no load, no crash
   risk. This is the mode you run against anything you don't have explicit, written permission to
   actively probe.
2. **Active crash probe (opt-in, intrusive).** Delegates to [Nuclei](https://github.com/projectdiscovery/nuclei)
   running the official, community-curated detection template from
   [assetnote/php2shell-scanner](https://github.com/assetnote/php2shell-scanner), vendored here
   unmodified under `php2shell_probe/templates/CVE-2026-109618.yaml` with its original attribution
   and signature intact. This mode sends the memory-exhaustion probe described in the public
   PHP2Shell write-ups and **can crash the target PHP worker**. It requires `--active` *and* an
   explicit `--i-have-authorization` flag — the CLI refuses to run it otherwise, and the same
   guardrail is enforced in the library function (`run_active_probe(..., confirmed_authorization=True)`)
   for anyone importing `php2shell_probe` directly instead of going through the CLI.

Every host gets one of four verdicts: `confirmed`, `probable` (fixed-version string not present
but server fingerprint strongly PHP), `not_detected`, or `unknown` (no reliable signal — e.g. a
WAF/CDN stripped the header). `unknown` is never collapsed into "clean": the whole point of the
tri-state model is to surface what you can't see, not hide it.

## Why this exists as its own repo

This detector for CVE-2026-109618 / CVE-2026-109619 was built as part of a larger internal asset
inventory tool and is republished here standalone, under a permissive license, so it's useful to
anyone running a PHP fleet. It has no dependency on anything else and no telemetry.

## Install

From source (the only installation path until a tagged release is published to PyPI):

```bash
git clone https://github.com/ZiarenEASM/php2shell-probe.git
cd php2shell-probe
pip install -e .
```

Once a release is published:

```bash
pip install php2shell-probe
```

The active crash-probe mode additionally requires [Nuclei](https://github.com/projectdiscovery/nuclei)
(`v3+`) on `PATH`. The version-fingerprint mode has no external dependencies beyond the Python
standard library.

## Usage

Safe, default mode — version fingerprint only:

```bash
php2shell-probe scan --targets hosts.txt --output results.csv
```

`hosts.txt` is one hostname or URL per line. Output is CSV with columns
`target,verdict,php_version,detail`.

Single host, human-readable:

```bash
php2shell-probe scan --targets https://example.org --format table
```

Active crash probe — **only against hosts you are authorized to actively test**:

```bash
php2shell-probe scan --targets hosts.txt --active --i-have-authorization \
  --output results.csv
```

Full option list:

```bash
php2shell-probe scan --help
```

### Exit codes

| Code | Meaning |
|------|---------|
| `0`  | Ran to completion, no `confirmed` verdicts |
| `1`  | Error — bad/missing targets file, `--active` without `--i-have-authorization`, Nuclei not found or failed |
| `2`  | Argparse usage error (bad/missing CLI arguments) — this is Python's own `argparse` behavior, not ours |
| `3`  | Ran to completion, at least one target came back `confirmed` — useful for CI gating |

Note `2` and `3` are deliberately different codes: a malformed command line (`2`) must never be
mistaken for a confirmed vulnerability (`3`) by a CI pipeline gating on exit status.

## Detection details

See [`docs/DETECTION.md`](docs/DETECTION.md) for the exact header parsing rules, the fixed-version
table, and why a missing `X-Powered-By` header produces `unknown` rather than `not_detected`.

## Responsible use

- The version-fingerprint mode is passive from the target's perspective (one ordinary HTTP
  request) and safe to run broadly against infrastructure you're authorized to inventory.
- The active crash probe sends a crafted multipart body designed to trigger the exact
  out-of-memory condition described in the public advisories. It is **not** safe to run against
  production systems you don't own or have a written testing agreement for. Treat a positive
  result the same way you'd treat a live RCE finding — notify the owner, don't pivot further.
- This tool performs **detection only**. It does not include, and will not add, a post-exploitation
  or shell-acquisition component.

## References

- [PHP security advisory, 2026-10-21](https://www.php.net/index.php#2026-10-21-5)
- [GHSA-w8hw-w9fx-j79w](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w) / [GHSA-6wmf-4rv5-p3rp](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)
- [Wiz Research: PHP2Shell](https://www.wiz.io/blog/php2shell-php-rce)
- [assetnote/php2shell-scanner](https://github.com/assetnote/php2shell-scanner) (source of the vendored Nuclei template)

## License

MIT — see [`LICENSE`](LICENSE). The vendored Nuclei template under
`php2shell_probe/templates/CVE-2026-109618.yaml` is itself from the MIT-licensed
[assetnote/php2shell-scanner](https://github.com/assetnote/php2shell-scanner) (attribution:
`assetnote`, `lcfr_hax`, `princechaddha`), compatible with this project's MIT license, and is
included unmodified.

## Contributing

Issues and PRs welcome — see [`CONTRIBUTING.md`](CONTRIBUTING.md). Please report suspected false
positives/negatives with the target's PHP version and server headers (sanitized) attached.

## Security

Found a bug in the *probe itself* (e.g. it mishandles a response in a way that could affect a
third party)? See [`SECURITY.md`](SECURITY.md) for how to report it privately.
