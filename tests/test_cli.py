import json
import subprocess
import sys
from pathlib import Path

from busy_port.cli import run
from busy_port.lookup import Listener

ROOT = Path(__file__).resolve().parents[1]


def _boom(port, proto):
    raise AssertionError(f"lookup should not run for {port} {proto}")


def test_found_human(capsys):
    listeners = [Listener(8080, "tcp", "LISTEN", 1234, "python")]

    code = run(["8080"], finder=lambda port, proto: listeners)

    captured = capsys.readouterr()
    assert code == 0
    assert captured.out == "tcp 8080 LISTEN pid=1234 cmd=python\n"
    assert captured.err == ""


def test_found_json(capsys):
    listeners = [
        Listener(53, "udp", "UNCONN", 2, "named"),
        Listener(53, "tcp", "LISTEN", 2, "named"),
    ]

    code = run(["53", "--proto", "both", "--json"], finder=lambda port, proto: listeners)

    captured = capsys.readouterr()
    assert code == 0
    assert json.loads(captured.out) == [
        {"port": 53, "proto": "tcp", "state": "LISTEN", "pid": 2, "cmd": "named"},
        {"port": 53, "proto": "udp", "state": "UNCONN", "pid": 2, "cmd": "named"},
    ]
    assert list(json.loads(captured.out)[0]) == ["port", "proto", "state", "pid", "cmd"]
    assert captured.err == ""


def test_empty_human(capsys):
    code = run(["8080"], finder=lambda port, proto: [])

    captured = capsys.readouterr()
    assert code == 1
    assert captured.out == "nothing is listening on tcp port 8080\n"
    assert captured.err == ""


def test_empty_udp_and_both(capsys):
    assert run(["53", "--proto", "udp"], finder=lambda port, proto: []) == 1
    first = capsys.readouterr()
    assert first.out == "nothing is listening on udp port 53\n"

    assert run(["53", "--proto", "both"], finder=lambda port, proto: []) == 1
    second = capsys.readouterr()
    assert second.out == "nothing is listening on tcp or udp port 53\n"


def test_empty_json(capsys):
    code = run(["8080", "--json"], finder=lambda port, proto: [])

    captured = capsys.readouterr()
    assert code == 1
    assert json.loads(captured.out) == []
    assert captured.err.strip() == "nothing is listening on tcp port 8080"


def test_unknown_pid_is_not_invented(capsys):
    listeners = [Listener(8080, "tcp", "LISTEN", None, None)]

    code = run(["--port", "8080", "--json"], finder=lambda port, proto: listeners)

    captured = capsys.readouterr()
    assert code == 0
    assert json.loads(captured.out) == [
        {"port": 8080, "proto": "tcp", "state": "LISTEN", "pid": None, "cmd": None}
    ]
    assert "root" in captured.err

    code = run(["8080"], finder=lambda port, proto: listeners)
    captured = capsys.readouterr()
    assert code == 0
    assert captured.out == "tcp 8080 LISTEN pid=? cmd=?\n"
    assert "1234" not in captured.out
    assert "rerun as root" in captured.err


def test_forwards_port_and_proto():
    seen = {}

    def finder(port, proto):
        seen["port"] = port
        seen["proto"] = proto
        return []

    assert run(["--port", "53", "--proto", "UDP"], finder=finder) == 1
    assert seen == {"port": 53, "proto": "udp"}

    assert run(["443", "--port", "443", "--proto", "both"], finder=finder) == 1
    assert seen == {"port": 443, "proto": "both"}


def test_bad_args_exit_2(capsys):
    assert run(["nope"], finder=_boom) == 2
    assert run([], finder=_boom) == 2
    assert run(["0"], finder=_boom) == 2
    assert run(["65536"], finder=_boom) == 2
    assert run(["-1"], finder=_boom) == 2
    assert run(["80", "--proto", "sctp"], finder=_boom) == 2
    assert run(["80", "--port", "81"], finder=_boom) == 2
    captured = capsys.readouterr()
    assert "conflicting ports" in captured.err
    assert "between 1 and 65535" in captured.err
    assert "missing port" in captured.err


def test_lookup_failure_exit_2(capsys):
    def finder(port, proto):
        raise LookupError("ss lookup failed: ss: not found")

    assert run(["80"], finder=finder) == 2
    assert "ss lookup failed" in capsys.readouterr().err


def test_help_exits_0():
    assert run(["--help"]) == 0


def test_module_entrypoint_bad_args():
    completed = subprocess.run(
        [sys.executable, "-m", "busy_port"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 2
    assert "missing port" in completed.stderr
