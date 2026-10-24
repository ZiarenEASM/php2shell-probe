import email.message
from unittest.mock import patch

import pytest

from php2shell_probe.detector import (
    VERDICT_CONFIRMED,
    VERDICT_NOT_DETECTED,
    VERDICT_PROBABLE,
    VERDICT_UNKNOWN,
    _parse_php_version,
    _version_verdict,
    fingerprint,
)


def _fake_response(headers: dict):
    class FakeResponse:
        def __init__(self):
            msg = email.message.Message()
            for k, v in headers.items():
                msg[k] = v
            self.headers = msg

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    return FakeResponse()


@pytest.mark.parametrize(
    "header,expected",
    [
        ("PHP/8.2.34", (8, 2, 34)),
        ("PHP/8.4.27", (8, 4, 27)),
        ("php/7.4.3", (7, 4, 3)),
        ("not php at all", None),
        ("", None),
    ],
)
def test_parse_php_version(header, expected):
    assert _parse_php_version(header) == expected


@pytest.mark.parametrize(
    "version,expected",
    [
        ((8, 2, 34), VERDICT_CONFIRMED),   # below fixed 8.2.35
        ((8, 2, 35), VERDICT_NOT_DETECTED),  # exactly fixed
        ((8, 2, 40), VERDICT_NOT_DETECTED),  # above fixed
        ((8, 4, 26), VERDICT_CONFIRMED),
        ((8, 4, 27), VERDICT_NOT_DETECTED),
        ((7, 4, 99), VERDICT_CONFIRMED),   # EOL branch
        ((8, 1, 99), VERDICT_CONFIRMED),   # EOL branch
        ((5, 6, 40), VERDICT_CONFIRMED),   # EOL branch well below our table, not enumerated
        ((4, 4, 9), VERDICT_CONFIRMED),    # arbitrarily old EOL branch
        ((8, 9, 0), VERDICT_PROBABLE),     # branch newer than everything in the table
    ],
)
def test_version_verdict(version, expected):
    assert _version_verdict(version) == expected


def test_fingerprint_reads_headers_from_http_error_response():
    """A WAF/CDN returning a non-2xx status can still carry a legitimate
    X-Powered-By header from the PHP origin — this must not be discarded as
    a plain network failure."""
    import email.message

    import urllib.error

    with patch("php2shell_probe.detector.urllib.request.urlopen") as mock_urlopen:
        headers = email.message.Message()
        headers["X-Powered-By"] = "PHP/8.2.10"
        mock_urlopen.side_effect = urllib.error.HTTPError(
            "https://example.org", 403, "Forbidden", headers, None
        )
        result = fingerprint("example.org")
    assert result.verdict == VERDICT_CONFIRMED
    assert result.php_version == "8.2.10"


def test_fingerprint_confirmed_vulnerable_version():
    with patch("php2shell_probe.detector.urllib.request.urlopen") as mock_urlopen:
        mock_urlopen.return_value = _fake_response({"X-Powered-By": "PHP/8.2.30"})
        result = fingerprint("example.org")
    assert result.verdict == VERDICT_CONFIRMED
    assert result.php_version == "8.2.30"


def test_fingerprint_not_detected_patched_version():
    with patch("php2shell_probe.detector.urllib.request.urlopen") as mock_urlopen:
        mock_urlopen.return_value = _fake_response({"X-Powered-By": "PHP/8.3.36"})
        result = fingerprint("example.org")
    assert result.verdict == VERDICT_NOT_DETECTED


def test_fingerprint_unknown_when_header_missing():
    with patch("php2shell_probe.detector.urllib.request.urlopen") as mock_urlopen:
        mock_urlopen.return_value = _fake_response({"Server": "nginx"})
        result = fingerprint("example.org")
    assert result.verdict == VERDICT_UNKNOWN
    assert result.php_version is None


def test_fingerprint_probable_when_php_signal_without_version():
    with patch("php2shell_probe.detector.urllib.request.urlopen") as mock_urlopen:
        mock_urlopen.return_value = _fake_response({"X-Powered-By": "PHP"})
        result = fingerprint("example.org")
    assert result.verdict == VERDICT_PROBABLE


def test_fingerprint_unknown_on_network_error():
    import urllib.error

    with patch("php2shell_probe.detector.urllib.request.urlopen") as mock_urlopen:
        mock_urlopen.side_effect = urllib.error.URLError("boom")
        result = fingerprint("example.org")
    assert result.verdict == VERDICT_UNKNOWN
