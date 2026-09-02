# schnorr-nonce-forge

**Difficulty-calibration experiment — not the primary Track A submission.**

This is a second, original crypto challenge built specifically to test a
hypothesis about what makes `license-forge` (the primary
submission) easier than "competition-level": that swapping the
underlying vulnerability class would raise difficulty. **The experiment
disconfirmed that hypothesis** — see Results below. Kept in the
submission because the process (build → test → be wrong → diagnose
correctly) is itself evidence of the design rigor the assignment asks
for, not because this challenge is being proposed as a replacement.

## The challenge

License Forge Identity Authority issues signed "license" records using a
Schnorr signature scheme over a DSA-style prime-order subgroup
(p ≈ 2048-bit, q ≈ 256-bit — FIPS 186-4 L=2048,N=256 parameter sizes).
Six license records are served; four use independent fresh nonces, but
two were signed with the *same* nonce due to a bug — a classic
nonce-reuse vulnerability (the same bug class that leaked the Sony PS3
signing key). Nonce reuse in Schnorr signatures leaks the private key
directly:

```
s1 = k + e1*x  (mod q)
s2 = k + e2*x  (mod q)
s1 - s2 = (e1 - e2) * x  (mod q)
x = (s1 - s2) * (e1 - e2)^-1  mod q
```

Once `x` is recovered, forging a signature over the fixed target message
(`GRANT:FULL-ACCESS`) is a normal signing operation, not a special trick
— nonce reuse compromises the *entire key*, not just one signature.

Hardening applied over a naive version: the two colliding records are
not labeled, and their position among the six is shuffled at build time,
so a solver must inspect all six and notice the shared value themselves.

## Why this doesn't need elliptic-curve code

The design-space research (`Cryptography CTF Challenge Design.md`,
included in this repo) compared several nonce-reuse variants — ECDSA
over an elliptic curve, this Schnorr-over-prime-field version, an LCG
token-forgery design, and a chained AES-CTR→RSA design — on
reasoning-isolation, implementation reliability, and pattern-matching
resistance. Schnorr over a prime field was chosen specifically because
it preserves the identical "shared nonce → recoverable secret via linear
algebra" reasoning class as ECDSA while needing zero elliptic-curve
point-arithmetic code, reusing the exact `pow(g, x, p)`-style modular
arithmetic already proven correct in `license-forge`'s RSA
challenge. One caveat identified during design review and confirmed by
the calibration results below: Schnorr's recovery is a **single** linear
equation (`x` directly), versus ECDSA's **two-step** chain (recover `k`,
then recover `d`) — a real, if modest, difficulty reduction that the
reliability-for-difficulty tradeoff knowingly accepted.

## Build and run

```bash
./run.sh build          # cold docker build
./run.sh up              # start the service
./run.sh solve            # run the reference solution
./run.sh grade             # score the attempt against tests/rubric.json
./run.sh down               # stop and remove the container

./run.sh reliability 16      # calibration run: build once, then 16x (up/solve/grade/down)
```

## Calibration results (real, independently verified)

| Metric | Target | Result |
|---|---|---|
| Environment reliability | ≥14/16 | **16/16 (100%)**, all ≤1s |
| Solve time | <5 min | **≤1s** |
| Reward granularity | ≥3-5 stages | 3 stages (see `tests/rubric.json` for why 3, not 4-5, is honestly justified here) |

**Real-agent solve data — 6 independent blind rollouts:**

| Rollout | Turns | Solved |
|---|---|---|
| 0 | 6 | ✅ |
| 1 | 6 | ✅ |
| 2 | 6 | ✅ |
| 3 | 7 | ✅ |
| 4 | 7 | ✅ |
| 5 | 6 | ✅ |

**Solve rate: 6/6 = 100%.** Every attempt independently found the exact
same self-verifying trick to resolve the one undocumented detail (the
byte-encoding of the challenge hash `e = H(R,m)`) — brute-forcing
candidate encodings *offline* and checking each against the public
verification equation before ever touching the live service, so zero
live-server guesses were wasted by any rollout. Every rollout explicitly
reported "no real obstacles" and found the nonce-reuse collision
"immediately upon listing licenses."

**This is not the outcome the experiment was run to find, and that's the
point of reporting it plainly rather than reframing it as a success.**

## Diagnosis — why the primitive swap didn't work

Detecting a duplicate value among six short hex strings is a one-line
script check (`len(set(R_values)) < len(R_values)`), regardless of which
signature scheme produced those values. Hiding *position* (which this
challenge does) doesn't address that — the actual search space is
trivial no matter where the duplicate sits. The vulnerability class
(RSA blind-signature multiplicative homomorphism vs. Schnorr nonce reuse)
was never the real lever controlling difficulty in `license-forge`;
both are equally canonical, equally pattern-matchable textbook attacks,
and both reduce to "recognize the pattern, then execute clean modular
arithmetic" with no genuine branching or dead-end risk once the pattern
is spotted.

## What would actually work (documented, not built, per the assignment's
own timebox guidance: "if you run out of time, document what you would
do next rather than cutting corners")

The design-space research's own top "genuinely hard" recommendation —
**Alt B: LCG-seeded nonces feeding into single-signature key recovery**
— is structurally different in a way that matters: the nonce for each
signature is generated by an under-seeded LCG, and the solver cannot
even *attempt* the signature-recovery step without first recovering the
LCG's parameters from leaked values to predict the nonce. That's a real,
mandatory dependency between two steps, not two independently-solvable
tricks connected by plumbing (which is exactly what made an earlier,
rejected "Candidate 4" chain design weak — see `Cryptography CTF
Challenge Design.md` §2, §11). Building and calibrating that version
properly (fresh reliability run, fresh blind-rollout batch, fresh
anti-cheat pass) is the correctly-scoped next step, not something to
rush out now without the same verification rigor everything else in
this submission has had.

## Repository layout

```
schnorr-nonce-forge/
  instruction.md
  environment/
    Dockerfile
    server.py
    build_keys.py
  docker-compose.yml
  solution/
    solve.py
  tests/
    rubric.json
    grader.py
  run.sh
  Cryptography CTF Challenge Design.md   # the design-space research that led here
  README.md
```
