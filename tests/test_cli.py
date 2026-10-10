from logwatch.cli import main


def test_no_args():
    assert main([]) == 2


def test_exit_code_1_on_low_alert(tmp_path):
    log_file = tmp_path / "access.log"

    log_file.write_text(
        "192.168.1.10 - - [10/Oct/2026:12:00:00 +0000] "
        '"GET /login HTTP/1.1" 200 123 "-" "sqlmap/1.8"\n'
    )

    result = main(["--web", str(log_file), "--fail-on", "low"])

    assert result == 1


def test_exit_code_0_when_alert_below_threshold(tmp_path):
    log_file = tmp_path / "access.log"

    log_file.write_text(
        "192.168.1.10 - - [10/Oct/2026:12:00:00 +0000] "
        '"GET /login HTTP/1.1" 200 123 "-" "sqlmap/1.8"\n'
    )

    result = main(["--web", str(log_file), "--fail-on", "high"])

    assert result == 0


def test_alert_count_in_output(tmp_path, capsys):
    log_file = tmp_path / "access.log"

    log_file.write_text(
        "192.168.1.10 - - [10/Oct/2026:12:00:00 +0000] "
        '"GET /login HTTP/1.1" 200 123 "-" "sqlmap/1.8"\n'
    )

    main(["--web", str(log_file), "--fail-on", "low"])

    captured = capsys.readouterr()

    assert "ALERTS: 1" in captured.out
