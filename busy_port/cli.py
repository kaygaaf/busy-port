"""Command line interface for busy-port."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Callable, Sequence

from busy_port.lookup import Listener, dedupe, find_listeners

UNKNOWN_PID_NOTE = (
    "could not resolve a pid; rerun as root if another user owns the socket"
)

Finder = Callable[[int, str], list[Listener]]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="busy-port",
        description="Show which process is using a TCP or UDP port.",
        epilog=(
            "examples:\n"
            "  busy-port 8080\n"
            "  busy-port --port 53 --proto udp\n"
            "  busy-port 8080 --json"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "port_pos",
        nargs="?",
        type=int,
        metavar="PORT",
        help="port number, 1-65535",
    )
    parser.add_argument(
        "--port",
        dest="port_opt",
        type=int,
        metavar="PORT",
        help="port number, 1-65535",
    )
    parser.add_argument(
        "--proto",
        default="tcp",
        type=str.lower,
        choices=("tcp", "udp", "both"),
        help="protocol to check (default: tcp)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="print a JSON list",
    )
    return parser


def resolve_port(port_pos: int | None, port_opt: int | None) -> int | str:
    """Return the port, or an error string."""
    if port_pos is not None and port_opt is not None and port_pos != port_opt:
        return f"conflicting ports: {port_pos} and {port_opt}"
    port = port_pos if port_pos is not None else port_opt
    if port is None:
        return "missing port (usage: busy-port <port> or busy-port --port <port>)"
    if port < 1 or port > 65535:
        return "port must be between 1 and 65535"
    return port


def format_human(item: Listener) -> str:
    pid = "?" if item.pid is None else str(item.pid)
    cmd = item.cmd if item.cmd else "?"
    return f"{item.proto} {item.port} {item.state} pid={pid} cmd={cmd}"


def empty_message(proto: str, port: int) -> str:
    family = "tcp or udp" if proto == "both" else proto
    return f"nothing is listening on {family} port {port}"


def emit(listeners: list[Listener], port: int, proto: str, as_json: bool) -> int:
    listeners = dedupe(listeners)
    if not listeners:
        message = empty_message(proto, port)
        if as_json:
            print(message, file=sys.stderr)
            print("[]")
        else:
            print(message)
        return 1

    if any(item.pid is None for item in listeners):
        print(UNKNOWN_PID_NOTE, file=sys.stderr)

    if as_json:
        payload = [
            {
                "port": item.port,
                "proto": item.proto,
                "state": item.state,
                "pid": item.pid,
                "cmd": item.cmd,
            }
            for item in listeners
        ]
        print(json.dumps(payload, ensure_ascii=False))
        return 0

    for item in listeners:
        print(format_human(item))
    return 0


def run(
    argv: Sequence[str] | None = None,
    finder: Finder | None = None,
) -> int:
    parser = build_parser()
    try:
        args = parser.parse_args(list(argv) if argv is not None else None)
    except SystemExit as exc:
        code = exc.code
        return code if isinstance(code, int) else 2

    resolved = resolve_port(args.port_pos, args.port_opt)
    if isinstance(resolved, str):
        print(f"busy-port: {resolved}", file=sys.stderr)
        return 2

    lookup = finder if finder is not None else find_listeners
    try:
        listeners = lookup(resolved, args.proto)
    except LookupError as exc:
        print(f"busy-port: {exc}", file=sys.stderr)
        return 2

    return emit(listeners, resolved, args.proto, args.json)


def main(argv: Sequence[str] | None = None) -> None:
    sys.exit(run(argv))
