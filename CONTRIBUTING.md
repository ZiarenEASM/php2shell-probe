# Contributing

Issues and pull requests are welcome.

## Reporting false positives / negatives

Please include:
- The target's actual PHP version (`php -v` on the host, or another independent confirmation).
- The raw response headers the probe saw (redact hostnames/IPs if needed).
- Which mode you ran (`scan` default vs. `--active`).

## Development

```bash
pip install -e ".[dev]"
pytest
```

The codebase is plain-stdlib Python for the passive detector (no runtime dependencies). Please
keep it that way for `detector.py` — the whole point of this tool is to be auditable in a few
minutes.

## Scope

This repo is intentionally narrow: detection for CVE-2026-109618 / CVE-2026-109619 only. PRs that
add unrelated CVEs or turn this into a general-purpose scanner will likely be redirected elsewhere
rather than merged. PRs that add a post-exploitation/shell component will not be merged — this is
a detection tool.

## DCO

Commits should be signed off (`git commit -s`) certifying you wrote the change or otherwise have
the right to submit it under this project's license (MIT).
