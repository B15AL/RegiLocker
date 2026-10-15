#!/usr/bin/env python3
"""End-to-end test: starts vaultd in a temp dir and talks to it over TCP."""
import os, shutil, socket, subprocess, sys, tempfile, time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PORT = 18080
fails = 0

def check(label, cond):
    global fails
    print(("PASS  " if cond else "FAIL  ") + label)
    if not cond: fails += 1

def request(payload: bytes) -> bytes:
    s = socket.create_connection(("127.0.0.1", PORT), timeout=5)
    buf = b""
    try:                       # the server may reject a request and hang up before we finish sending the body
        s.sendall(payload)
        s.shutdown(socket.SHUT_WR)
        while True:
            d = s.recv(65536)
            if not d: break
            buf += d
    except OSError:
        pass
    s.close()
    return buf

def put(name, data): return request(f"PUT {name} {len(data)}\n".encode() + data)
def get(name):       return request(f"GET {name}\n".encode())

tmp = tempfile.mkdtemp()
store = os.path.join(tmp, "store"); os.mkdir(store)
jail = os.path.join(tmp, "jail"); os.mkdir(jail)
os.chmod(tmp, 0o755)
if os.geteuid() == 0:            # daemon will chroot + drop to uid 65534: give it the storage dir
    os.chown(store, 65534, 65534)
key = os.path.join(tmp, "vault.key")
with open(key, "wb") as f: f.write(os.urandom(32))
os.chmod(key, 0o600)

# --- key permission check: group-readable key must be refused
badkey = os.path.join(tmp, "bad.key")
with open(badkey, "wb") as f: f.write(os.urandom(32))
os.chmod(badkey, 0o644)
r = subprocess.run([f"{ROOT}/vaultd", "-p", str(PORT), "-s", store, "-k", badkey, "-j", jail],
                   capture_output=True, text=True, timeout=5)
check("refuses key file readable by group/other", r.returncode != 0)

proc = subprocess.Popen([f"{ROOT}/vaultd", "-p", str(PORT), "-s", store, "-k", key, "-j", jail],
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
for _ in range(50):
    try: socket.create_connection(("127.0.0.1", PORT), timeout=0.2).close(); break
    except OSError: time.sleep(0.1)

try:
    secret = b"top secret payload " * 50
    check("PUT ok", put("report.txt", secret) == b"OK\n")
    check("GET round-trips", get("report.txt") == b"OK %d\n" % len(secret) + secret)

    raw = open(os.path.join(store, "report.txt"), "rb").read()
    check("plaintext not on disk", b"top secret" not in raw)
    check("on-disk size = plaintext + 32 bytes overhead", len(raw) == len(secret) + 32)
    check("no temp files left behind", not [f for f in os.listdir(store) if f.startswith(".tmp")])

    put("a.txt", secret)
    r1 = open(os.path.join(store, "a.txt"), "rb").read()
    put("a.txt", secret)
    r2 = open(os.path.join(store, "a.txt"), "rb").read()
    check("same data re-stored gets a fresh nonce", r1 != r2)

    check("empty file works", put("empty", b"") == b"OK\n" and get("empty") == b"OK 0\n")

    p = os.path.join(store, "report.txt")
    b = bytearray(open(p, "rb").read()); b[20] ^= 1; open(p, "wb").write(b)
    check("tampered ciphertext rejected", get("report.txt").startswith(b"ERR integrity"))

    put("one", b"AAAA"); put("two", b"BBBB")
    shutil.copy(os.path.join(store, "one"), os.path.join(store, "two"))
    check("blob swapped under another name rejected", get("two").startswith(b"ERR integrity"))

    for bad in ["../etc/passwd", "a/b", "..", ".hidden", "a b", "x" * 65, "na\\me"]:
        resp = request(f"GET {bad}\n".encode())
        check(f"bad name rejected: {bad[:20]!r}", resp.startswith(b"ERR"))
    check("path traversal on PUT rejected", put("../evil", b"x").startswith(b"ERR"))
    check("oversize PUT rejected", request(b"PUT big 99999999\n").startswith(b"ERR invalid"))
    check("short body rejected", request(b"PUT short 100\nabc").startswith(b"ERR short body"))
    check("garbage rejected", request(b"HELLO\n").startswith(b"ERR bad request"))
    check("missing file", get("nope") == b"ERR not found\n")

    os.symlink("/etc/passwd", os.path.join(store, "link"))
    check("symlink in vault dir not followed", get("link").startswith(b"ERR"))

    check("DEL ok", request(b"DEL a.txt\n") == b"OK\n" and get("a.txt") == b"ERR not found\n")

    s = socket.create_connection(("127.0.0.1", PORT)); s.sendall(b"GET " + b"A" * 5000)  # no newline, overlong
    s.settimeout(15)
    check("overlong header line rejected", s.recv(100).startswith(b"ERR"))
    s.close()
    check("server still alive after abuse", put("alive", b"1") == b"OK\n")
finally:
    proc.terminate(); proc.wait(timeout=5)
    shutil.rmtree(tmp, ignore_errors=True)

print("\nALL PASSED" if not fails else f"\n{fails} FAILED")
sys.exit(1 if fails else 0)
