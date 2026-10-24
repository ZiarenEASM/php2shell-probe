"""The vendored Nuclei template is treated as read-only upstream content:
these tests only check it's present and correctly identified, never its
internal probe logic (that's assetnote's to maintain upstream)."""

from pathlib import Path

from php2shell_probe.nuclei_runner import TEMPLATE_PATH


def test_template_present():
    assert TEMPLATE_PATH.is_file()


def test_template_declares_expected_cve():
    content = TEMPLATE_PATH.read_text()
    assert "CVE-2026-109618" in content
    assert "CVE-2026-109619" in content


def test_template_attributes_upstream_authors():
    content = TEMPLATE_PATH.read_text()
    assert "assetnote" in content
