import pytest

from php2shell_probe.cli import EXIT_CONFIRMED, EXIT_ERROR, EXIT_OK, _load_targets, build_parser, main


def test_exit_confirmed_does_not_collide_with_argparse_usage_error():
    # argparse itself exits with status 2 on a malformed command line —
    # EXIT_CONFIRMED must never equal that or a CI pipeline could mistake a
    # typo'd invocation for a confirmed vulnerability.
    assert EXIT_CONFIRMED not in (0, 1, 2)
    assert {EXIT_OK, EXIT_ERROR, EXIT_CONFIRMED} == {0, 1, EXIT_CONFIRMED}


def test_load_targets_accepts_bare_url_without_a_file():
    assert _load_targets("https://example.org") == ["https://example.org"]


def test_load_targets_missing_file_is_a_clean_error(capsys):
    with pytest.raises(SystemExit) as exc_info:
        _load_targets("/no/such/targets/file.txt")
    assert exc_info.value.code == EXIT_ERROR
    assert "could not read targets file" in capsys.readouterr().err


def test_active_without_authorization_refused(tmp_path, capsys):
    targets_file = tmp_path / "targets.txt"
    targets_file.write_text("example.org\n")

    rc = main(["scan", "--targets", str(targets_file), "--active"])
    assert rc == 1
    captured = capsys.readouterr()
    assert "--i-have-authorization" in captured.err


def test_empty_targets_file_rejected(tmp_path, capsys):
    targets_file = tmp_path / "targets.txt"
    targets_file.write_text("\n# just a comment\n")

    rc = main(["scan", "--targets", str(targets_file)])
    assert rc == 1


def test_parser_builds():
    parser = build_parser()
    args = parser.parse_args(["scan", "--targets", "-"])
    assert args.active is False
    assert args.i_have_authorization is False
