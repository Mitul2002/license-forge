#!/usr/bin/env python3
"""Build-time domain-parameter, key, and challenge-data generator for the
License Forge Identity Authority (Schnorr nonce-reuse challenge).

Runs once, at `docker build` time. Produces /app/keys.json baked into the
image: DSA-style domain parameters (p ~2048-bit, q ~256-bit, matching
FIPS 186-4 L=2048,N=256), a Schnorr keypair, six pre-signed "license"
records (four with fresh nonces, two that deliberately reuse the same
nonce -- the bug), the fixed target message, and the flag.

Everything here is deterministic given the parameters; nothing is
regenerated at container start, so every run against the same built
image is byte-identical.

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


def gen_dsa_domain(p_bits: int = 2048, q_bits: int = 256):
    """FIPS 186-4 style Schnorr/DSA domain parameters: q prime, p prime
    with q | (p-1), g a generator of the order-q subgroup of Z_p^*."""
    q = gen_prime(q_bits)
    k_bits = p_bits - q_bits
    while True:
        k = secrets.randbits(k_bits) | (1 << (k_bits - 1))
        p = k * q + 1
        if p.bit_length() != p_bits:
            continue
        if not is_probable_prime(p):
            continue
        # find a generator of the order-q subgroup
        for _ in range(50):
            h = secrets.randbelow(p - 3) + 2
            g = pow(h, (p - 1) // q, p)
            if g != 1:
                return p, q, g


def schnorr_hash(R: int, message: bytes, p_byte_len: int, q: int) -> int:
    R_bytes = R.to_bytes(p_byte_len, "big")
    digest = hashlib.sha256(R_bytes + message).digest()
    return int.from_bytes(digest, "big") % q


def schnorr_sign(p: int, q: int, g: int, x: int, message: bytes, p_byte_len: int, r: int | None = None):
    if r is None:
        r = secrets.randbelow(q - 1) + 1
    R = pow(g, r, p)
    e = schnorr_hash(R, message, p_byte_len, q)
    s = (r + e * x) % q
    return R, s


def main() -> None:
    p, q, g = gen_dsa_domain(2048, 256)
    p_byte_len = (p.bit_length() + 7) // 8

    x = secrets.randbelow(q - 1) + 1
    y = pow(g, x, p)

    target_message = b"GRANT:FULL-ACCESS"

    # Six license records: four fresh, independent nonces; two that
    # deliberately reuse the same nonce (the bug). Order is shuffled so
    # position never reveals which pair is vulnerable.
    n_fresh = 4
    messages = [f"REQ-{secrets.token_hex(4)}".encode() for _ in range(n_fresh + 2)]

    records = []
    for i in range(n_fresh):
        R, s = schnorr_sign(p, q, g, x, messages[i], p_byte_len)
        records.append({"message": messages[i].decode(), "R": f"{R:x}", "s": f"{s:x}"})

    shared_r = secrets.randbelow(q - 1) + 1
    for i in range(n_fresh, n_fresh + 2):
        R, s = schnorr_sign(p, q, g, x, messages[i], p_byte_len, r=shared_r)
        records.append({"message": messages[i].decode(), "R": f"{R:x}", "s": f"{s:x}"})

    order = list(range(len(records)))
    _shuffled = order[:]
    for i in range(len(_shuffled) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        _shuffled[i], _shuffled[j] = _shuffled[j], _shuffled[i]
    licenses = [records[i] for i in _shuffled]

    flag = f"flag{{{secrets.token_hex(16)}}}"

    keys = {
        "p": f"{p:x}",
        "q": f"{q:x}",
        "g": f"{g:x}",
        "x": f"{x:x}",
        "y": f"{y:x}",
        "p_byte_len": p_byte_len,
        "target_message": target_message.decode(),
        "licenses": licenses,
        "flag": flag,
    }
    with open(KEYS_PATH, "w") as fh:
        json.dump(keys, fh)


if __name__ == "__main__":
    main()
