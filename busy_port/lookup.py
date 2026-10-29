"""Find listeners in /proc, or via ss, lsof, and netstat.

PIDs are copied from the system. They are never guessed. On Linux a listening
socket is world-readable in /proc/net, but the owning PID comes from
/proc/<pid>/fd, which other users cannot read. Callers should say when a PID
is missing.
"""

from __future__ import annotations

import csv
import errno
import os
import re
import subprocess
import sys
from collections.abc import Callable
from dataclasses import dataclass, replace
from pathlib import Path

# /proc/net/{tcp,udp} columns, after whitespace split:
# 0 sl, 1 local_address, 2 rem_address, 3 st, 4 tx:rx,
# 5 tr:when, 6 retrnsmt, 7 uid, 8 timeout, 9 inode
_INODE_INDEX = 9
_SOCKET_PREFIX = "socket:["

_USERS_RE = re.compile(r"users:\(\((.*)\)\)\s*$")
_PROC_RE = re.compile(r'"((?:\\.|[^"\\])*)",pid=(\d+),fd=\d+')


@dataclass(frozen=True)
class Listener:
    port: int
    proto: str
    state: str
    pid: int | None
    cmd: str | None


@dataclass(frozen=True)
class CmdResult:
    returncode: int
    stdout: str
    stderr: str = ""


Runner = Callable[[list[str]], CmdResult]


def default_run(argv: list[str]) -> CmdResult:
    try:
        completed = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=5,
            check=False,
        )
    except FileNotFoundError:
        return CmdResult(127, "", f"{argv[0]}: not found")
    except subprocess.TimeoutExpired:
        return CmdResult(124, "", f"{argv[0]}: timed out")
    except OSError as exc:
        return CmdResult(127, "", str(exc))
    return CmdResult(completed.returncode, completed.stdout, completed.stderr)


def dedupe(listeners: list[Listener]) -> list[Listener]:
    seen: set[tuple[str, int, str, int | None, str | None]] = set()
    unique: list[Listener] = []
    for item in listeners:
        key = (item.proto, item.port, item.state, item.pid, item.cmd)
        if key in seen:
            continue
        seen.add(key)
        unique.append(item)
    unique.sort(
        key=lambda item: (
            item.proto != "tcp",
            item.pid is None,
            item.pid or 0,
            item.cmd or "",
        )
    )
    return unique


def protos_for(proto: str) -> set[str]:
    if proto == "both":
        return {"tcp", "udp"}
    if proto in {"tcp", "udp"}:
        return {proto}
    raise LookupError(f"unknown protocol: {proto}")


def clean_pid(pid: int | None) -> int | None:
    if pid is None or pid <= 0:
        return None
    return pid


def command_basename(name: str) -> str | None:
    text = name.strip().strip("\x00")
    if not text:
        return None
    base = os.path.basename(text)
    if base.lower().endswith(".exe"):
        base = base[:-4]
    return base or None


def normalize_state(proto: str, state: str) -> str | None:
    token = state.upper()
    if proto == "tcp":
        if token in {"LISTEN", "LISTENING"}:
            return "LISTEN"
        return None
    if token in {"UNCONN", "UNCONNECTED", "CLOSE", "07"}:
        return "UNCONN"
    if token in {"ESTAB", "ESTABLISHED", "01"}:
        return "ESTAB"
    return token


def port_from_addr(addr: str) -> int | None:
    text = addr.strip()
    if text.startswith("["):
        marker = text.rfind("]:")
        if marker == -1:
            return None
        port_text = text[marker + 2 :]
    else:
        if ":" not in text:
            return None
        port_text = text.rsplit(":", 1)[1]
    if not port_text.isdigit():
        return None
    return int(port_text)


def parse_proc_net(text: str, port: int, proto: str) -> list[tuple[str, str]]:
    """Return (state, inode) for sockets bound to `port`."""
    found: list[tuple[str, str]] = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) <= _INODE_INDEX or not parts[0].endswith(":"):
            continue
        local = parts[1]
        if ":" not in local:
            continue
        try:
            local_port = int(local.rsplit(":", 1)[1], 16)
        except ValueError:
            continue
        if local_port != port:
            continue
        state_hex = parts[3].upper()
        if proto == "tcp":
            if state_hex != "0A":
                continue
            state = "LISTEN"
        else:
            if state_hex == "07":
                state = "UNCONN"
            elif state_hex == "01":
                state = "ESTAB"
            else:
                state = state_hex
        inode = parts[_INODE_INDEX]
        if not inode.isdigit() or inode == "0":
            continue
        found.append((state, inode))
    return found


def command_from_proc(proc_dir: Path) -> str | None:
    try:
        raw = (proc_dir / "cmdline").read_bytes()
    except OSError:
        raw = b""
    for part in raw.split(b"\0"):
        if not part:
            continue
        name = command_basename(part.decode("utf-8", "replace"))
        if name:
            return name
        break
    try:
        comm = (proc_dir / "comm").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    return command_basename(comm)


def command_from_ps(pid: int, run: Runner) -> str | None:
    result = run(["ps", "-p", str(pid), "-o", "comm="])
    if result.returncode != 0:
        return None
    for line in result.stdout.splitlines():
        name = command_basename(line)
        if name:
            return name
    return None


def map_socket_inodes(
    proc_root: Path,
    inodes: set[str],
    run: Runner,
) -> tuple[dict[str, list[tuple[int, str | None]]], bool]:
    """Map socket inodes to (pid, cmd). The bool is true if a scan was denied."""
    owners: dict[str, list[tuple[int, str | None]]] = {}
    denied = False
    if not inodes:
        return owners, False
    try:
        with os.scandir(proc_root) as scan:
            pid_dirs = [(entry.name, entry.path) for entry in scan if entry.name.isdigit()]
    except OSError as exc:
        return owners, exc.errno in (errno.EACCES, errno.EPERM)

    seen: set[tuple[str, int]] = set()
    for name, path in pid_dirs:
        pid = int(name)
        fd_dir = Path(path) / "fd"
        try:
            with os.scandir(fd_dir) as scan:
                fd_paths = [fd.path for fd in scan]
        except OSError as exc:
            if exc.errno in (errno.EACCES, errno.EPERM):
                denied = True
            continue
        matched: list[str] = []
        for fd_path in fd_paths:
            try:
                target = os.readlink(fd_path)
            except OSError:
                continue
            if not (target.startswith(_SOCKET_PREFIX) and target.endswith("]")):
                continue
            inode = target[len(_SOCKET_PREFIX) : -1]
            if inode in inodes and (inode, pid) not in seen:
                seen.add((inode, pid))
                matched.append(inode)
        if not matched:
            continue
        cmd = command_from_proc(Path(path))
        if cmd is None:
            cmd = command_from_ps(pid, run)
        for inode in matched:
            owners.setdefault(inode, []).append((pid, cmd))
    return owners, denied


def listeners_from_proc(
    port: int,
    protos: set[str],
    proc_root: Path,
    run: Runner,
) -> list[Listener] | None:
    """Return listeners, or None when no /proc/net file for the request exists."""
    files: list[tuple[str, Path]] = []
    if "tcp" in protos:
        files.append(("tcp", proc_root / "net" / "tcp"))
        files.append(("tcp", proc_root / "net" / "tcp6"))
    if "udp" in protos:
        files.append(("udp", proc_root / "net" / "udp"))
        files.append(("udp", proc_root / "net" / "udp6"))

    rows: list[tuple[str, str, str]] = []
    readable = False
    for proto, path in files:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        readable = True
        for state, inode in parse_proc_net(text, port, proto):
            rows.append((proto, state, inode))
    if not readable:
        return None

    inodes = {inode for _, _, inode in rows}
    owners, _denied = map_socket_inodes(proc_root, inodes, run)
    listeners: list[Listener] = []
    for proto, state, inode in rows:
        found = owners.get(inode) or []
        if not found:
            listeners.append(Listener(port, proto, state, None, None))
            continue
        for pid, cmd in found:
            listeners.append(Listener(port, proto, state, clean_pid(pid), cmd))
    return dedupe(listeners)


def parse_ss(text: str, port: int, assumed_proto: str) -> list[Listener]:
    listeners: list[Listener] = []
    for line in text.splitlines():
        raw = line.strip()
        if not raw:
            continue
        proc_blob = ""
        users = _USERS_RE.search(raw)
        if users:
            proc_blob = users.group(1)
            raw = raw[: users.start()].strip()
        parts = raw.split()
        if not parts or parts[0] in {"State", "Netid", "Recv-Q"}:
            continue
        proto = assumed_proto
        if parts[0].lower() in {"tcp", "udp"}:
            proto = parts[0].lower()
            parts = parts[1:]
        if len(parts) < 4:
            continue
        state = normalize_state(proto, parts[0])
        if state is None:
            continue
        local_port = port_from_addr(parts[3] if len(parts) > 3 else "")
        if local_port != port:
            continue
        processes = _PROC_RE.findall(proc_blob)
        if not processes:
            listeners.append(Listener(port, proto, state, None, None))
            continue
        seen_pids: set[int] = set()
        for raw_cmd, raw_pid in processes:
            pid = clean_pid(int(raw_pid))
            if pid is None or pid in seen_pids:
                continue
            seen_pids.add(pid)
            cmd = command_basename(raw_cmd.replace("\\", ""))
            listeners.append(Listener(port, proto, state, pid, cmd))
    return listeners


def listeners_from_ss(
    port: int,
    protos: set[str],
    run: Runner,
) -> tuple[list[Listener], bool]:
    """Return (listeners, any_command_succeeded)."""
    commands = []
    if "tcp" in protos:
        commands.append(("tcp", ["ss", "-lptn"]))
    if "udp" in protos:
        commands.append(("udp", ["ss", "-lpun"]))
    listeners: list[Listener] = []
    ok = False
    errors: list[str] = []
    for proto, argv in commands:
        result = run(argv)
        if result.returncode == 0:
            ok = True
            listeners.extend(parse_ss(result.stdout, port, proto))
            continue
        detail = result.stderr.strip() or f"exit {result.returncode}"
        errors.append(f"{' '.join(argv)}: {detail}")
    if not ok and errors:
        raise LookupError("ss lookup failed: " + "; ".join(errors))
    return dedupe(listeners), ok


def parse_lsof(text: str, port: int, proto: str) -> list[Listener]:
    """Parse default lsof -nP output.

    Internet rows look like:
    COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
    The NODE column is TCP or UDP. NAME starts with the local address.
    """
    listeners: list[Listener] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("COMMAND"):
            continue
        parts = stripped.split()
        if len(parts) < 9 or not parts[1].isdigit():
            continue
        if parts[7].lower() != proto:
            continue
        local = parts[8].split("->", 1)[0]
        if port_from_addr(local) != port:
            continue
        if proto == "tcp" and "(LISTEN)" not in " ".join(parts[8:]).upper():
            continue
        pid = clean_pid(int(parts[1]))
        cmd = command_basename(parts[0])
        state = "LISTEN" if proto == "tcp" else "UNCONN"
        listeners.append(Listener(port, proto, state, pid, cmd))
    return listeners


def parse_netstat(text: str, port: int, protos: set[str]) -> list[Listener]:
    listeners: list[Listener] = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        proto = parts[0].lower()
        if proto not in {"tcp", "udp"} or proto not in protos:
            continue
        local = parts[1]
        if local.rsplit(":", 1)[-1] != str(port):
            continue
        if proto == "tcp":
            if len(parts) < 5:
                continue
            state = normalize_state("tcp", parts[3])
            if state is None:
                continue
            pid = _maybe_int(parts[4])
        else:
            state = "UNCONN"
            pid = _maybe_int(parts[-1])
        listeners.append(Listener(port, proto, state, clean_pid(pid), None))
    return listeners


def parse_tasklist_name(text: str) -> str | None:
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.lower().startswith("info:"):
            return None
        try:
            row = next(csv.reader([stripped]))
        except csv.Error:
            return None
        if not row:
            return None
        name = row[0].strip()
        if not name or name.lower() == "image name" or name.lower().startswith("info:"):
            return None
        return command_basename(name)
    return None


def _maybe_int(value: str) -> int | None:
    try:
        return int(value)
    except ValueError:
        return None


def _attach_ps(listeners: list[Listener], run: Runner) -> list[Listener]:
    cache: dict[int, str | None] = {}
    updated: list[Listener] = []
    for item in listeners:
        cmd = item.cmd
        if item.pid is not None:
            if item.pid not in cache:
                cache[item.pid] = command_from_ps(item.pid, run)
            ps_cmd = cache[item.pid]
            if ps_cmd:
                cmd = ps_cmd
        updated.append(replace(item, cmd=cmd))
    return updated


def _attach_tasklist(listeners: list[Listener], run: Runner) -> list[Listener]:
    cache: dict[int, str | None] = {}
    updated: list[Listener] = []
    for item in listeners:
        cmd = item.cmd
        if item.pid is not None and cmd is None:
            if item.pid not in cache:
                result = run(
                    [
                        "tasklist",
                        "/FI",
                        f"PID eq {item.pid}",
                        "/FO",
                        "CSV",
                        "/NH",
                    ]
                )
                if result.returncode == 0:
                    cache[item.pid] = parse_tasklist_name(result.stdout)
                else:
                    cache[item.pid] = None
            cmd = cache[item.pid]
        updated.append(replace(item, cmd=cmd))
    return updated


def find_linux(
    port: int,
    proto: str,
    proc_root: Path,
    run: Runner,
) -> list[Listener]:
    protos = protos_for(proto)
    from_proc = listeners_from_proc(port, protos, proc_root, run)
    if from_proc is None:
        from_ss, _ok = listeners_from_ss(port, protos, run)
        return from_ss
    if not from_proc:
        return []
    if any(item.pid is not None for item in from_proc):
        return from_proc
    try:
        from_ss, ok = listeners_from_ss(port, protos, run)
    except LookupError:
        return from_proc
    with_pid = [item for item in from_ss if item.pid is not None]
    if ok and with_pid:
        return dedupe(with_pid)
    return from_proc


def find_darwin(port: int, proto: str, run: Runner) -> list[Listener]:
    protos = protos_for(proto)
    listeners: list[Listener] = []
    failures: list[str] = []
    saw_lsof = False
    commands: list[tuple[str, list[str]]] = []
    if "tcp" in protos:
        commands.append(("tcp", ["lsof", "-nP", f"-iTCP:{port}", "-sTCP:LISTEN"]))
    if "udp" in protos:
        commands.append(("udp", ["lsof", "-nP", f"-iUDP:{port}"]))
    for kind, argv in commands:
        result = run(argv)
        if result.returncode == 127:
            failures.append(result.stderr.strip() or "lsof: not found")
            continue
        saw_lsof = True
        # lsof exits 1 when nothing matches. That is an empty result.
        listeners.extend(parse_lsof(result.stdout, port, kind))
    if not saw_lsof:
        detail = "; ".join(failures) if failures else "lsof is not available"
        raise LookupError(detail)
    return dedupe(_attach_ps(listeners, run))


def find_windows(port: int, proto: str, run: Runner) -> list[Listener]:
    protos = protos_for(proto)
    result = run(["netstat", "-ano"])
    if result.returncode != 0 and not result.stdout.strip():
        detail = result.stderr.strip() or f"exit {result.returncode}"
        raise LookupError(f"netstat lookup failed: {detail}")
    listeners = parse_netstat(result.stdout, port, protos)
    return dedupe(_attach_tasklist(listeners, run))


def platform_kind(system: str) -> str:
    name = system.lower()
    if name.startswith("linux"):
        return "linux"
    if name == "darwin":
        return "darwin"
    if name in {"win32", "windows"}:
        return "windows"
    raise LookupError(f"unsupported platform: {system}")


def find_listeners(
    port: int,
    proto: str,
    *,
    system: str | None = None,
    proc_root: str | Path = "/proc",
    run: Runner | None = None,
) -> list[Listener]:
    runner = run if run is not None else default_run
    kind = platform_kind(system if system is not None else sys.platform)
    if kind == "linux":
        return find_linux(port, proto, Path(proc_root), runner)
    if kind == "darwin":
        return find_darwin(port, proto, runner)
    return find_windows(port, proto, runner)
