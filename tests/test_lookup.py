import sys
from pathlib import Path

import pytest

from busy_port.lookup import (
    CmdResult,
    Listener,
    find_listeners,
    parse_lsof,
    parse_netstat,
    parse_proc_net,
    parse_ss,
    parse_tasklist_name,
)

HEADER = (
    "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when "
    "retrnsmt   uid  timeout inode\n"
)


def proc_line(port: int, state: str, inode: str, ipv6: bool = False) -> str:
    addr = ("0" * 32) if ipv6 else "0100007F"
    remote = ("0" * 32 + ":0000") if ipv6 else "00000000:0000"
    return (
        f"   0: {addr}:{port:04X} {remote} {state} 00000000:00000000 "
        f"00:00000000 00000000     0        0 {inode} 1 "
        "0000000000000000 100 0 0 10 0\n"
    )


def make_proc(tmp_path: Path, net: dict[str, str], processes: dict[int, dict]) -> Path:
    proc = tmp_path / "proc"
    net_dir = proc / "net"
    net_dir.mkdir(parents=True)
    for name, text in net.items():
        (net_dir / name).write_text(text, encoding="utf-8")
    for pid, spec in processes.items():
        proc_dir = proc / str(pid)
        fd_dir = proc_dir / "fd"
        fd_dir.mkdir(parents=True)
        cmdline = spec.get("cmdline", f"/usr/bin/{spec.get('cmd', 'unknown')}")
        if isinstance(cmdline, bytes):
            (proc_dir / "cmdline").write_bytes(cmdline)
        else:
            (proc_dir / "cmdline").write_bytes(cmdline.encode() + b"\0")
        if "comm" in spec:
            (proc_dir / "comm").write_text(spec["comm"], encoding="utf-8")
        elif "cmd" in spec:
            (proc_dir / "comm").write_text(spec["cmd"] + "\n", encoding="utf-8")
        for index, inode in enumerate(spec.get("sockets", []), start=3):
            (fd_dir / str(index)).symlink_to(f"socket:[{inode}]")
        for index, inode in enumerate(spec.get("pipes", []), start=30):
            (fd_dir / str(index)).symlink_to(f"pipe:[{inode}]")
    return proc


def test_parse_proc_net_tcp_listen_only():
    text = (
        HEADER
        + proc_line(8080, "0A", "999")
        + proc_line(8080, "01", "1000")
        + proc_line(80, "0A", "1001")
        + proc_line(8080, "0a", "1002", ipv6=True)
    )

    assert parse_proc_net(text, 8080, "tcp") == [("LISTEN", "999"), ("LISTEN", "1002")]
    assert parse_proc_net(text, 80, "tcp") == [("LISTEN", "1001")]
    assert parse_proc_net(text, 81, "tcp") == []


def test_parse_proc_net_udp_states():
    text = HEADER + proc_line(53, "07", "555") + proc_line(53, "01", "556")

    assert parse_proc_net(text, 53, "udp") == [("UNCONN", "555"), ("ESTAB", "556")]


def test_parse_proc_net_real_kernel_line():
    # Copied from a live /proc/net/tcp row (127.0.0.1:5901, LISTEN, inode 4769).
    text = (
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when "
        "retrnsmt   uid  timeout inode\n"
        "   1: 0100007F:170D 00000000:0000 0A 00000000:00000000 00:00000000 "
        "00000000  1000        0 4769 1 00000000d41f7ee4 100 0 0 10 0\n"
    )
    assert parse_proc_net(text, 5901, "tcp") == [("LISTEN", "4769")]
    assert parse_proc_net(text, 5902, "tcp") == []


@pytest.mark.skipif(sys.platform == "win32", reason="fixture uses symlinks")
def test_linux_maps_inode_to_pid_and_ignores_pipes(tmp_path):
    proc = make_proc(
        tmp_path,
        {
            "tcp": HEADER + proc_line(8080, "0A", "999") + proc_line(8080, "01", "1000"),
            "tcp6": HEADER + proc_line(8080, "0A", "999", ipv6=True),
        },
        {
            1234: {"cmd": "python", "cmdline": "/usr/bin/python", "sockets": ["999"]},
            6: {"cmd": "bash", "sockets": [], "pipes": ["999"]},
            7: {"cmd": "should-not-appear", "sockets": ["1000"]},
        },
    )

    def fail_run(argv):
        raise AssertionError(f"unexpected command: {argv}")

    found = find_listeners(8080, "tcp", system="linux", proc_root=proc, run=fail_run)
    assert found == [Listener(8080, "tcp", "LISTEN", 1234, "python")]


@pytest.mark.skipif(sys.platform == "win32", reason="fixture uses symlinks")
def test_linux_reports_unknown_pid_without_inventing_one(tmp_path):
    proc = make_proc(
        tmp_path,
        {"tcp": HEADER + proc_line(8080, "0A", "42")},
        {8: {"cmd": "unrelated", "sockets": ["99"]}},
    )

    found = find_listeners(
        8080,
        "tcp",
        system="linux",
        proc_root=proc,
        run=lambda argv: CmdResult(127, "", "ss: not found"),
    )
    assert found == [Listener(8080, "tcp", "LISTEN", None, None)]


@pytest.mark.skipif(sys.platform == "win32", reason="fixture uses symlinks")
def test_linux_keeps_unmapped_socket_when_another_pid_is_known(tmp_path):
    proc = make_proc(
        tmp_path,
        {"tcp": HEADER + proc_line(8080, "0A", "1") + proc_line(8080, "0A", "2")},
        {10: {"cmd": "python", "sockets": ["1"]}},
    )

    def fail_run(argv):
        raise AssertionError(argv)

    found = find_listeners(8080, "tcp", system="linux", proc_root=proc, run=fail_run)
    assert found == [
        Listener(8080, "tcp", "LISTEN", 10, "python"),
        Listener(8080, "tcp", "LISTEN", None, None),
    ]


@pytest.mark.skipif(sys.platform == "win32", reason="fixture uses symlinks")
def test_linux_udp_and_comm_fallback(tmp_path):
    proc = make_proc(
        tmp_path,
        {"udp": HEADER + proc_line(53, "07", "7")},
        {15: {"cmdline": "", "comm": "nginx\n", "sockets": ["7"]}},
    )
    found = find_listeners(
        53,
        "udp",
        system="linux",
        proc_root=proc,
        run=lambda argv: (_ for _ in ()).throw(AssertionError(argv)),
    )
    assert found == [Listener(53, "udp", "UNCONN", 15, "nginx")]


@pytest.mark.skipif(sys.platform == "win32", reason="fixture uses symlinks")
def test_linux_both_protocols(tmp_path):
    proc = make_proc(
        tmp_path,
        {
            "tcp": HEADER + proc_line(53, "0A", "1"),
            "udp": HEADER + proc_line(53, "07", "2"),
        },
        {
            3: {"cmd": "named", "sockets": ["1"]},
            4: {"cmd": "named", "sockets": ["2"]},
        },
    )
    found = find_listeners(
        53,
        "both",
        system="linux",
        proc_root=proc,
        run=lambda argv: (_ for _ in ()).throw(AssertionError(argv)),
    )
    assert found == [
        Listener(53, "tcp", "LISTEN", 3, "named"),
        Listener(53, "udp", "UNCONN", 4, "named"),
    ]


@pytest.mark.skipif(sys.platform == "win32", reason="fixture uses symlinks")
def test_ss_fills_pid_when_proc_cannot(tmp_path):
    proc = make_proc(tmp_path, {"tcp": HEADER + proc_line(8080, "0A", "42")}, {})
    calls = []

    def run(argv):
        calls.append(argv)
        return CmdResult(
            0,
            "State Recv-Q Send-Q Local Address:Port Peer Address:PortProcess\n"
            "LISTEN 0 128 127.0.0.1:8080 0.0.0.0:* "
            'users:(("python",pid=1234,fd=3))\n'
            "LISTEN 0 128 [::1]:8080 [::]:* "
            'users:(("python",pid=1234,fd=4))\n',
        )

    found = find_listeners(8080, "tcp", system="linux", proc_root=proc, run=run)
    assert calls == [["ss", "-lptn"]]
    assert found == [Listener(8080, "tcp", "LISTEN", 1234, "python")]


def test_ss_used_when_proc_net_is_missing(tmp_path):
    proc = tmp_path / "empty-proc"
    proc.mkdir()

    def run(argv):
        assert argv == ["ss", "-lpun"]
        return CmdResult(
            0,
            "Netid State Recv-Q Send-Q Local Address:Port Peer Address:PortProcess\n"
            "udp UNCONN 0 0 0.0.0.0:53 0.0.0.0:* "
            'users:(("named",pid=8,fd=2),("named",pid=9,fd=2))\n'
            'udp UNCONN 0 0 0.0.0.0:54 0.0.0.0:* users:(("named",pid=1,fd=1))\n',
        )

    found = find_listeners(53, "udp", system="linux", proc_root=proc, run=run)
    assert found == [
        Listener(53, "udp", "UNCONN", 8, "named"),
        Listener(53, "udp", "UNCONN", 9, "named"),
    ]


def test_missing_proc_and_ss_is_an_error(tmp_path):
    proc = tmp_path / "empty-proc"
    proc.mkdir()

    def run(argv):
        return CmdResult(127, "", "ss: not found")

    with pytest.raises(LookupError, match="ss lookup failed"):
        find_listeners(80, "tcp", system="linux", proc_root=proc, run=run)


def test_parse_ss_skips_other_ports_and_closed_tcp():
    text = (
        "LISTEN 0 128 127.0.0.1:22 0.0.0.0:*\n"
        "ESTAB 0 0 127.0.0.1:8080 127.0.0.1:50000\n"
        'LISTEN 0 128 *:8080 *:* users:(("nginx",pid=10,fd=5),("nginx",pid=11,fd=5))\n'
    )
    assert parse_ss(text, 8080, "tcp") == [
        Listener(8080, "tcp", "LISTEN", 10, "nginx"),
        Listener(8080, "tcp", "LISTEN", 11, "nginx"),
    ]
    assert parse_ss(text, 22, "tcp") == [Listener(22, "tcp", "LISTEN", None, None)]


def test_parse_lsof_tcp_and_udp():
    tcp = (
        "COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME\n"
        "Xtigervnc 2169 ubuntu 9u IPv4 4769 0t0 TCP 127.0.0.1:5901 (LISTEN)\n"
        "Xtigervnc 2169 ubuntu 10u IPv6 4770 0t0 TCP [::1]:5901 (LISTEN)\n"
        "python 99 user 3u IPv4 1 0t0 TCP 127.0.0.1:5901->127.0.0.1:1 (ESTABLISHED)\n"
        "python 100 user 3u IPv4 1 0t0 TCP *:80 (LISTEN)\n"
    )
    udp = (
        "COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME\n"
        "caddy 50 user 4u IPv4 9 0t0 UDP *:2019\n"
    )
    assert parse_lsof(tcp, 5901, "tcp") == [
        Listener(5901, "tcp", "LISTEN", 2169, "Xtigervnc"),
        Listener(5901, "tcp", "LISTEN", 2169, "Xtigervnc"),
    ]
    assert parse_lsof(tcp, 80, "tcp") == [Listener(80, "tcp", "LISTEN", 100, "python")]
    # The IPv6 address [::1] must not count as port 1.
    assert parse_lsof(tcp, 1, "tcp") == []
    assert parse_lsof(udp, 2019, "udp") == [Listener(2019, "udp", "UNCONN", 50, "caddy")]


def test_darwin_uses_lsof_and_ps():
    def run(argv):
        if argv[:2] == ["lsof", "-nP"] and argv[2] == "-iTCP:8080":
            assert argv == ["lsof", "-nP", "-iTCP:8080", "-sTCP:LISTEN"]
            return CmdResult(
                0,
                "COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME\n"
                "python3.1 1234 user 3u IPv4 1 0t0 TCP *:8080 (LISTEN)\n",
            )
        if argv[0] == "ps":
            assert argv == ["ps", "-p", "1234", "-o", "comm="]
            return CmdResult(0, "/usr/local/bin/python\n")
        return CmdResult(127, "", "missing")

    found = find_listeners(8080, "tcp", system="darwin", run=run)
    assert found == [Listener(8080, "tcp", "LISTEN", 1234, "python")]


def test_darwin_keeps_lsof_name_when_ps_fails():
    def run(argv):
        if argv[0] == "lsof":
            return CmdResult(
                1,
                "COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME\n"
                "caddy 50 user 4u IPv4 9 0t0 UDP *:2019\n",
            )
        return CmdResult(1, "", "ps failed")

    found = find_listeners(2019, "udp", system="darwin", run=run)
    assert found == [Listener(2019, "udp", "UNCONN", 50, "caddy")]


def test_darwin_missing_lsof():
    with pytest.raises(LookupError):
        find_listeners(
            80,
            "tcp",
            system="darwin",
            run=lambda argv: CmdResult(127, "", "lsof: not found"),
        )


def test_parse_netstat_and_tasklist():
    text = (
        "Active Connections\n"
        "  Proto  Local Address          Foreign Address        State           PID\n"
        "  TCP    0.0.0.0:8080           0.0.0.0:0              LISTENING       1234\n"
        "  TCP    0.0.0.0:80             0.0.0.0:0              LISTENING       1\n"
        "  TCP    10.0.0.2:8080          10.0.0.3:50000         ESTABLISHED     99\n"
        "  TCP    [::]:8080              [::]:0                 LISTENING       1234\n"
        "  UDP    0.0.0.0:53             *:*                                    8\n"
        "  UDP    0.0.0.0:0              *:*                                    0\n"
    )
    assert parse_netstat(text, 8080, {"tcp"}) == [
        Listener(8080, "tcp", "LISTEN", 1234, None),
        Listener(8080, "tcp", "LISTEN", 1234, None),
    ]
    assert parse_netstat(text, 53, {"udp"}) == [Listener(53, "udp", "UNCONN", 8, None)]
    assert parse_netstat(text, 80, {"tcp", "udp"}) == [Listener(80, "tcp", "LISTEN", 1, None)]
    assert parse_tasklist_name('"python.exe","1234","Console","1","12,345 K"\n') == "python"
    assert parse_tasklist_name("INFO: No tasks are running which match the specified criteria.\n") is None


def test_windows_netstat_and_tasklist():
    def run(argv):
        if argv[0] == "netstat":
            assert argv == ["netstat", "-ano"]
            return CmdResult(
                0,
                "  TCP    127.0.0.1:8080    0.0.0.0:0    LISTENING    1234\n"
                "  UDP    0.0.0.0:8080      *:*                       50\n",
            )
        if argv[0] == "tasklist":
            pid = argv[2].split()[-1]
            if pid == "1234":
                return CmdResult(0, '"python.exe","1234","Console","1","1 K"\n')
            return CmdResult(1, "", "no such process")
        return CmdResult(127, "", "missing")

    found = find_listeners(8080, "both", system="win32", run=run)
    assert found == [
        Listener(8080, "tcp", "LISTEN", 1234, "python"),
        Listener(8080, "udp", "UNCONN", 50, None),
    ]


def test_windows_netstat_missing():
    with pytest.raises(LookupError, match="netstat"):
        find_listeners(
            80,
            "tcp",
            system="windows",
            run=lambda argv: CmdResult(127, "", "netstat: not found"),
        )


def test_unsupported_platform():
    with pytest.raises(LookupError, match="unsupported platform"):
        find_listeners(80, "tcp", system="freebsd", run=lambda argv: CmdResult(0, ""))


def test_real_proc_tcp_parses_when_present():
    path = Path("/proc/net/tcp")
    if not path.exists():
        pytest.skip("no /proc/net/tcp")
    text = path.read_text(encoding="utf-8", errors="replace")
    for port in (1, 22, 80, 443, 8080, 65535):
        rows = parse_proc_net(text, port, "tcp")
        assert isinstance(rows, list)
        for state, inode in rows:
            assert state == "LISTEN"
            assert inode.isdigit()
            assert inode != "0"
