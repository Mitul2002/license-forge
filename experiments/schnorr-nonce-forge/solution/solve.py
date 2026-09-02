#!/usr/bin/env python3
"""Reference solution for schnorr-nonce-forge.

Fetches PUBKEY and LICENSES, detects which two of the six served
license records share an identical R (the nonce-reuse bug), recovers
the private key x algebraically, then forges a fresh signature over the
fixed target message GRANT:FULL-ACCESS using x exactly as the real
signer would, and submits it via ACTIVATE.
"""
from __future__ import annotations

import argparse
import hashlib
import os
import re
import secrets
import socket
from collections import defaultdict

FLAG_RE = re.compile(r"flag\{[a-f0-9]{32}\}")
TARGET_MESSAGE = b"GRANT:FULL-ACCESS"


class Session:
    def __init__(self, host: str, port: int, timeout: float = 10.0):
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.buf = b""

    def readline(self) -> str:
        while b"\n" not in self.buf:
            chunk = self.sock.recv(4096)
            if not chunk:
                break
            self.buf += chunk
        line, _, self.buf = self.buf.partition(b"\n")
        return line.decode(errors="replace")

    def send(self, text: str) -> None:
        self.sock.sendall((text + "\n").encode())


def schnorr_hash(R: int, message: bytes, p_byte_len: int, q: int) -> int:
    R_bytes = R.to_bytes(p_byte_len, "big")
    digest = hashlib.sha256(R_bytes + message).digest()
    return int.from_bytes(digest, "big") % q


def solve(host: str, port: int) -> str:
    s = Session(host, port)
    s.readline()  # welcome banner

    s.send("PUBKEY")
    p = int(s.readline().split("=", 1)[1], 16)
    q = int(s.readline().split("=", 1)[1], 16)
    g = int(s.readline().split("=", 1)[1], 16)
    y = int(s.readline().split("=", 1)[1], 16)
    p_byte_len = (p.bit_length() + 7) // 8

    s.send("LICENSES")
    records = []
    for _ in range(6):
        line = s.readline()
        # message=REQ-xxxx R=<hex> s=<hex>
        parts = dict(kv.split("=", 1) for kv in line.split())
        records.append(
            {"message": parts["message"].encode(), "R": int(parts["R"], 16), "s": int(parts["s"], 16)}
        )

    # Detect the two records sharing an identical R.
    by_R = defaultdict(list)
    for rec in records:
        by_R[rec["R"]].append(rec)
    colliding = next(v for v in by_R.values() if len(v) >= 2)
    rec1, rec2 = colliding[0], colliding[1]

    R = rec1["R"]
    e1 = schnorr_hash(R, rec1["message"], p_byte_len, q)
    e2 = schnorr_hash(R, rec2["message"], p_byte_len, q)
    if e1 == e2:
        raise RuntimeError("unexpected hash collision on distinct messages")

    x = ((rec1["s"] - rec2["s"]) * pow((e1 - e2) % q, -1, q)) % q

    if pow(g, x, p) != y:
        raise RuntimeError("recovered private key does not match public key -- derivation is wrong")

    # Forge a signature over the target message using the recovered key,
    # exactly as the real signer would.
    r_forge = secrets.randbelow(q - 1) + 1
    R_f = pow(g, r_forge, p)
    e_f = schnorr_hash(R_f, TARGET_MESSAGE, p_byte_len, q)
    s_f = (r_forge + e_f * x) % q

    s.send(f"ACTIVATE {R_f:x} {s_f:x}")
    activate_line = s.readline()
    if not activate_line.startswith("OK"):
        raise RuntimeError(f"activation failed: {activate_line!r}")

    s.send("CHALLENGE")
    challenge_line = s.readline()
    match = FLAG_RE.search(challenge_line)
    if not match:
        raise RuntimeError(f"no flag in challenge response: {challenge_line!r}")

    s.send("QUIT")
    return match.group(0)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=5000)
    ap.add_argument("--out", default="output/flag.txt")
    args = ap.parse_args()

    flag = solve(args.host, args.port)
    print(flag)

    out_dir = os.path.dirname(args.out)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    with open(args.out, "w") as fh:
        fh.write(flag + "\n")


if __name__ == "__main__":
    main()
