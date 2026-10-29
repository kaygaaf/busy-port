# busy-port

Shows which process is using a TCP or UDP port.

Use it when a program cannot bind because something else already has the port. You get the PID and command without remembering `lsof` or `ss` flags.

## Install

Requires Python 3.10 or newer. The tool uses the standard library only.

```bash
python -m pip install .
```

From a git checkout:

```bash
python -m pip install -e ".[dev]"
pytest
```

Run it without installing:

```bash
python -m busy_port 8080
```

## Usage

```text
busy-port <port>
busy-port --port <port>
```

Options:

- `--proto tcp|udp|both` selects the protocol. Default is `tcp`.
- `--json` prints a JSON list instead of text lines.

## Examples

```bash
busy-port 8080
busy-port --port 53 --proto udp
busy-port 443 --proto both
busy-port 8080 --json
```

When something is listening, a text line looks like this:

```text
tcp 8080 LISTEN pid=1234 cmd=python
```

JSON is a list of objects with `port`, `proto`, `state`, `pid`, and `cmd`:

```json
[{"port": 8080, "proto": "tcp", "state": "LISTEN", "pid": 1234, "cmd": "python"}]
```

When the port is free:

```text
nothing is listening on tcp port 8080
```

With `--json` and a free port, stdout is `[]` and the same message goes to stderr.

If the socket is visible but the PID is not, the line uses `pid=?` and `cmd=?`. busy-port does not invent a PID. On Linux that usually means another user owns the process. Run the command as root to read their `/proc/<pid>/fd` entries.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Found at least one listener |
| 1 | Nothing is listening |
| 2 | Bad arguments, or the lookup could not run |

## Where the data comes from

On Linux, busy-port reads `/proc/net/tcp`, `/proc/net/tcp6`, `/proc/net/udp`, and `/proc/net/udp6`. It maps the socket inode to a PID by scanning `/proc/<pid>/fd`. That works without root for processes you own. If those files are missing, it falls back to `ss -lptn` and `ss -lpun`.

On macOS it runs `lsof -nP -iTCP:<port> -sTCP:LISTEN`, and `lsof -nP -iUDP:<port>` for UDP.

On Windows it runs `netstat -ano` and, when that returns a PID, `tasklist`. This path is limited. It expects English `netstat` output, and some sockets still hide the process name.

## Support

If this helps: https://ko-fi.com/kayorama
