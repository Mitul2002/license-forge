#!/usr/bin/env python3
"""Reference solution for license-forge.

Connects to the License Forge server and forges an RSA signature over the FULL
license target using a textbook blind-signature attack:

    sig(F) = sig(r^e * F mod n) * r^-1 mod n

The server will sign anything except F itself, and RSA's raw (unpadded)
signing is multiplicatively homomorphic, so blinding F by a random factor
r^e lets the oracle sign it without ever seeing F. Unblinding afterwards
recovers a valid signature over F.

Writes the captured flag to --out (default output/flag.txt).
"""
from __future__ import annotations

import argparse
import os
import re
import secrets
import socket

FLAG_RE = re.compile(r"flag\{[a-f0-9]{32}\}")


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
        if b"\n" not in self.buf:
            line, self.buf = self.buf, b""
        else:
            line, self.buf = self.buf.split(b"\n", 1)
        return line.decode(errors="replace")

    def send(self, text: str) -> None:
        self.sock.sendall((text + "\n").encode())


def solve(host: str, port: int) -> str:
    s = Session(host, port)
    s.readline()  # welcome banner

    s.send("PUBKEY")
    n = int(s.readline().split("=", 1)[1], 16)
    e = int(s.readline().split("=", 1)[1], 16)

    s.send("PRODUCTS")
    s.readline()  # TRIAL line
    full_line = s.readline()
    f_target = int(full_line.split("target=", 1)[1].split()[0], 16)

    while True:
        r = secrets.randbelow(n - 2) + 2
        blinded = (pow(r, e, n) * f_target) % n
        if blinded != f_target:
            break

    s.send(f"SIGN {blinded:x}")
    sig_line = s.readline()
    if not sig_line.startswith("SIG="):
        raise RuntimeError(f"unexpected SIGN response: {sig_line!r}")
    s1 = int(sig_line.split("=", 1)[1], 16)

    r_inv = pow(r, -1, n)
    forged = (s1 * r_inv) % n
    if pow(forged, e, n) != f_target:
        raise RuntimeError("forged signature failed local verification")

    s.send(f"ACTIVATE {forged:x}")
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
