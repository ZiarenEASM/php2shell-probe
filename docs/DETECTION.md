# Detection details

## Passive version fingerprint (`detector.py`)

One ordinary `GET`/`urlopen` request. We read the `X-Powered-By` response header and parse it
against `^PHP/(\d+)\.(\d+)\.(\d+)`.

Fixed patch versions per the 2026-10-21 PHP security advisory:

| Branch | Fixed at |
|--------|----------|
| 8.2    | 8.2.35   |
| 8.3    | 8.3.36   |
| 8.4    | 8.4.27   |
| 8.5    | 8.5.12   |

PHP 8.1 and older are end-of-life upstream and received no fixed version — any of those branches
is reported `confirmed` directly, since there is no patched release to compare against.

### Verdicts

- **`confirmed`** — parsed version is on an affected branch below the fixed patch, or on an EOL
  branch.
- **`not_detected`** — parsed version is at or above the fixed patch.
- **`probable`** — a PHP signal was present (header says "PHP" or a PHP-specific `Server` banner)
  but we couldn't parse an exact version, or the branch isn't in the table above (e.g. a future
  8.6).
- **`unknown`** — no `X-Powered-By` header and no other PHP signal. This is the common case
  behind a reverse proxy, CDN or WAF that strips the header. **We deliberately never report
  `unknown` as `not_detected`** — a missing header is absence of evidence, not evidence of
  absence. If you need a verdict here, you need either direct access or the active probe.
- Any network/TLS/timeout error also maps to `unknown` for the same reason. A non-2xx/3xx HTTP
  response (e.g. a WAF returning 403) is **not** treated as a network error: we still read that
  response's headers, since a WAF in front of a PHP origin frequently passes `X-Powered-By`
  through on a blocked request. Only a response with no usable headers at all falls back to
  `unknown`.

## Active crash probe (`nuclei_runner.py` + `php2shell_probe/templates/CVE-2026-109618.yaml`)

This mode does not reimplement the PHP2Shell technique in this project's own code. It shells out
to Nuclei with the template vendored under `php2shell_probe/templates/CVE-2026-109618.yaml`, taken unmodified from
[assetnote/php2shell-scanner](https://github.com/assetnote/php2shell-scanner) (attribution:
`lcfr_hax`, `assetnote`, `princechaddha`; see the file's own `digest:` line for its signed upstream
provenance). The template sends a sequence of oversized multipart bodies designed to trigger the
PHP `longjmp()` out-of-memory handling bug, then checks the response for either the known PHP
memory-exhaustion error string or — if the server stops responding to probes before crashing —
falls back to the same version comparison described above, scoped to Nuclei's own matcher logic.

Only two outcomes are reported in this mode: `confirmed` (Nuclei matched) or `not_detected` (it
didn't). There's no `unknown` state here, because the probe either gets a reaction from the target
or it doesn't — if you can't reach the target to send the probe at all, that's a connectivity
problem, not a detection outcome.

This mode is opt-in behind `--active --i-have-authorization` for the reasons in the main
[README](../README.md#responsible-use).
