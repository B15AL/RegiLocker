#!/usr/bin/env python3
"""Command-line client for the encrypted file vault daemon (vaultd).

    vault_client.py put  <file> [--name NAME]
    vault_client.py get  <name> [-o PATH | -o -] [--force]
    vault_client.py del  <name>

Standard library only. Needs Python 3.8+.
"""
import argparse
import os
import re
import socket
import sys

MAX_SIZE = 1024 * 1024                      # must match VAULT_MAX_PLAIN in the daemon
NAME_RE = re.compile(r"^[A-Za-z0-9_-][A-Za-z0-9._-]{0,63}$")   # 1-64 chars, no leading '.'


class VaultError(Exception):
    pass


def check_name(name: str) -> str:
    if not NAME_RE.match(name):
        raise VaultError(
            f"invalid name {name!r}: use 1-64 characters from A-Z a-z 0-9 . _ - "
            "and do not start with '.'"
        )
    return name


def _connect(host: str, port: int, timeout: float) -> socket.socket:
    try:
        return socket.create_connection((host, port), timeout=timeout)
    except OSError as e:
        raise VaultError(f"cannot connect to {host}:{port} ({e}). Is vaultd running?")


def _read_line(sock: socket.socket) -> str:
    buf = bytearray()
    while len(buf) < 200:
        c = sock.recv(1)
        if not c:
            raise VaultError("server closed the connection unexpectedly")
        if c == b"\n":
            return buf.decode("ascii", "replace")
        buf += c
    raise VaultError("malformed response from server")


def _read_exact(sock: socket.socket, n: int) -> bytes:
    chunks, got = [], 0
    while got < n:
        d = sock.recv(min(65536, n - got))
        if not d:
            raise VaultError("connection lost while receiving data")
        chunks.append(d)
        got += len(d)
    return b"".join(chunks)


def _expect_ok(line: str) -> str:
    if line.startswith("ERR "):
        raise VaultError(line[4:])
    if line == "OK" or line.startswith("OK "):
        return line[3:]
    raise VaultError(f"unexpected response: {line!r}")


def vault_put(host, port, timeout, name: str, data: bytes) -> None:
    check_name(name)
    if len(data) > MAX_SIZE:
        raise VaultError(f"file is {len(data)} bytes; the vault limit is {MAX_SIZE} (1 MiB)")
    with _connect(host, port, timeout) as s:
        try:
            s.sendall(f"PUT {name} {len(data)}\n".encode() + data)
            s.shutdown(socket.SHUT_WR)
        except OSError:
            pass                      # server may reply with an error and hang up early; read it below
        _expect_ok(_read_line(s))


def vault_get(host, port, timeout, name: str) -> bytes:
    check_name(name)
    with _connect(host, port, timeout) as s:
        s.sendall(f"GET {name}\n".encode())
        rest = _expect_ok(_read_line(s))
        try:
            size = int(rest)
        except ValueError:
            raise VaultError(f"unexpected response: OK {rest!r}")
        if not 0 <= size <= MAX_SIZE:
            raise VaultError("server announced an invalid size")
        return _read_exact(s, size)


def vault_del(host, port, timeout, name: str) -> None:
    check_name(name)
    with _connect(host, port, timeout) as s:
        s.sendall(f"DEL {name}\n".encode())
        _expect_ok(_read_line(s))


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Client for the encrypted file vault daemon.")
    p.add_argument("--host", default=os.environ.get("VAULT_HOST", "127.0.0.1"),
                   help="server address (env VAULT_HOST, default 127.0.0.1)")
    p.add_argument("--port", type=int, default=int(os.environ.get("VAULT_PORT", "8080")),
                   help="server port (env VAULT_PORT, default 8080)")
    p.add_argument("--timeout", type=float, default=15.0, help="network timeout in seconds")
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("put", help="encrypt and store a file (use '-' to read stdin)")
    sp.add_argument("file")
    sp.add_argument("--name", help="name in the vault (default: the file's name; required for stdin)")

    sg = sub.add_parser("get", help="retrieve and decrypt a file")
    sg.add_argument("name")
    sg.add_argument("-o", "--output", help="where to write it (default: ./<name>; '-' = stdout)")
    sg.add_argument("--force", action="store_true", help="overwrite the output file if it exists")

    sd = sub.add_parser("del", help="delete a file from the vault")
    sd.add_argument("name")

    a = p.parse_args(argv)

    try:
        if a.cmd == "put":
            if a.file == "-":
                if not a.name:
                    raise VaultError("--name is required when reading from stdin")
                data = sys.stdin.buffer.read(MAX_SIZE + 1)
                name = a.name
            else:
                if not os.path.isfile(a.file):
                    raise VaultError(f"no such file: {a.file}")
                if os.path.getsize(a.file) > MAX_SIZE:
                    raise VaultError(f"{a.file} is larger than the 1 MiB vault limit")
                with open(a.file, "rb") as f:
                    data = f.read()
                name = a.name or os.path.basename(a.file)
            vault_put(a.host, a.port, a.timeout, name, data)
            print(f"stored '{name}' ({len(data)} bytes)", file=sys.stderr)

        elif a.cmd == "get":
            data = vault_get(a.host, a.port, a.timeout, a.name)
            out = a.output or a.name
            if out == "-":
                sys.stdout.buffer.write(data)
                sys.stdout.buffer.flush()
            else:
                if os.path.exists(out) and not a.force:
                    raise VaultError(f"{out} already exists (use --force to overwrite or -o to choose another path)")
                with open(out, "wb") as f:
                    f.write(data)
                print(f"saved '{a.name}' to {out} ({len(data)} bytes)", file=sys.stderr)

        elif a.cmd == "del":
            vault_del(a.host, a.port, a.timeout, a.name)
            print(f"deleted '{a.name}'", file=sys.stderr)

    except VaultError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
