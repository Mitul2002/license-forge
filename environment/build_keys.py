#!/usr/bin/env python3
"""Build-time key/flag generator for the License Forge server.

Runs exactly once, during `docker build`. Produces /app/keys.json baked
into the image: an RSA keypair, the forbidden FULL-license target integer,
and the flag. Nothing here is regenerated at container start, so every run
against the same built image is byte-for-byte identical -- required for the
16-run reliability check in the calibration report.

Stdlib only, no third-party dependencies.
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets

KEYS_PATH = os.environ.get("LICENSE_FORGE_KEYS_PATH", "/app/keys.json")


def _sieve(limit: int) -> list[int]:
    is_composite = bytearray(limit + 1)
    primes = []
    for i in range(2, limit + 1):
        if not is_composite[i]:
            primes.append(i)
            for j in range(i * i, limit + 1, i):
                is_composite[j] = 1
    return primes


_SMALL_PRIMES = _sieve(4000)


def is_probable_prime(n: int, rounds: int = 40) -> bool:
    if n < 2:
        return False
    for p in _SMALL_PRIMES:
        if n % p == 0:
            return n == p
    d = n - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def gen_prime(bits: int) -> int:
    while True:
        candidate = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if is_probable_prime(candidate):
            return candidate


def generate_rsa(bits: int = 2048) -> tuple[int, int, int]:
    e = 65537
    while True:
        p = gen_prime(bits // 2)
        q = gen_prime(bits // 2)
        if p == q:
            continue
        n = p * q
        if not (bits - 1 <= n.bit_length() <= bits):
            continue
        phi = (p - 1) * (q - 1)
        if phi % e == 0:
            continue
        d = pow(e, -1, phi)
        return n, e, d


def main() -> None:
    n, e, d = generate_rsa(2048)

    build_secret = secrets.token_bytes(32)
    f_target = int.from_bytes(
        hashlib.sha256(b"LICENSE-FORGE-FULL-UNLOCK::" + build_secret).digest(), "big"
    ) % n

    flag = f"flag{{{secrets.token_hex(16)}}}"

    keys = {"n": n, "e": e, "d": d, "f_target": f_target, "flag": flag}
    with open(KEYS_PATH, "w") as fh:
        json.dump(keys, fh)


if __name__ == "__main__":
    main()
