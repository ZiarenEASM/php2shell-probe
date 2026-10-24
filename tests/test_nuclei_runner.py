import json
from unittest.mock import MagicMock, patch

import pytest

from php2shell_probe.nuclei_runner import NucleiRunError, _host_key, run_active_probe


def test_host_key_normalizes_scheme_and_trailing_slash():
    assert _host_key("example.org") == "example.org"
    assert _host_key("https://example.org") == "example.org"
    assert _host_key("https://example.org/") == "example.org"
    assert _host_key("HTTPS://Example.org") == "example.org"


def test_run_active_probe_requires_explicit_authorization():
    with pytest.raises(PermissionError):
        run_active_probe(["example.org"])  # confirmed_authorization defaults to False


@patch("php2shell_probe.nuclei_runner._require_nuclei", return_value="/usr/bin/nuclei")
@patch("php2shell_probe.nuclei_runner.TEMPLATE_PATH")
@patch("php2shell_probe.nuclei_runner.subprocess.run")
def test_run_active_probe_matches_normalized_host(mock_run, mock_template_path, mock_require):
    mock_template_path.is_file.return_value = True
    event = {
        "host": "https://example.org:443",
        "matcher-name": "memory-exhaustion",
        "info": {"classification": {"cve-id": ["CVE-2026-109618"]}},
    }
    mock_run.return_value = MagicMock(returncode=0, stdout=json.dumps(event) + "\n", stderr="")

    results = run_active_probe(["example.org"], confirmed_authorization=True)

    assert len(results) == 1
    assert results[0].verdict == "confirmed"
    assert results[0].target == "example.org"  # original input target, not nuclei's normalized form


@patch("php2shell_probe.nuclei_runner._require_nuclei", return_value="/usr/bin/nuclei")
@patch("php2shell_probe.nuclei_runner.TEMPLATE_PATH")
@patch("php2shell_probe.nuclei_runner.subprocess.run")
def test_run_active_probe_raises_on_nonzero_exit(mock_run, mock_template_path, mock_require):
    mock_template_path.is_file.return_value = True
    mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="template compile error")

    with pytest.raises(NucleiRunError, match="template compile error"):
        run_active_probe(["example.org"], confirmed_authorization=True)


@patch("php2shell_probe.nuclei_runner._require_nuclei", return_value="/usr/bin/nuclei")
@patch("php2shell_probe.nuclei_runner.TEMPLATE_PATH")
@patch("php2shell_probe.nuclei_runner.subprocess.run")
def test_run_active_probe_rounds_subsecond_timeout_up(mock_run, mock_template_path, mock_require):
    mock_template_path.is_file.return_value = True
    mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

    run_active_probe(["example.org"], timeout=0.4, confirmed_authorization=True)

    called_cmd = mock_run.call_args.args[0]
    timeout_index = called_cmd.index("-timeout") + 1
    assert called_cmd[timeout_index] == "1"  # never silently truncated to 0
