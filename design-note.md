# Design note

## Track and category

Chose **Track A (CTF)** over Track B (CVE) mainly on reliability grounds.
Track B mandates an Intermediate tier that bypasses NX/ASLR, real
exploit-dev infrastructure (ROP chains, address leaks, libc pinning) that
is inherently sensitive to stack layout and ASLR entropy, which fights
directly against the assignment's own ≥14/16 reliability bar. Track A lets
the category be chosen, so I picked **crypto** specifically to avoid that
class of flakiness entirely: an oracle-based crypto challenge is either
mathematically exploitable or it isn't, with no environmental variance in
between. That bet paid off in practice: 16/16 reliability, achieved on
the first calibration run with no retries needed.

## The vulnerability

RSA blind-signature forgery: the server signs raw (unpadded) integers, and
raw RSA is multiplicatively homomorphic, so `sig(F)` is recoverable from
`sig(r^e * F mod n)` without the server ever agreeing to sign `F` directly.
This is a well-known technique; what's original is the packaging: the
License Forge narrative, the protocol, the specific refusal/oracle shape,
the flag mechanism. A novel-but-undiscoverable primitive would fail the
"not impossible" calibration bar, while a recognizable technique executed
against an unfamiliar live protocol (spec deliberately withheld, see
`instruction.md`) still forces real multi-turn work: the live blind-agent
data confirms this (mean 5.7 turns, minimum 3, across 20 independent
solves, full data in `README.md`).

## Trust architecture

Borrowed the shape of Parsewave's `ar_2.0/autoresearch-pipeline` trust
model (hidden ground truth lives behind a boundary the builder/solver
never crosses, a verifier reads that ground truth out-of-band, nothing is
LLM-graded) without borrowing its weight. Their system needs S3 lending,
GitHub PR reconciliation, and nine checkpointed finalization stages
because it runs continuously across a team. This deliverable needs exactly
two files (`progress.json`, written by the service as milestones occur;
`keys.json`, the build-time ground truth) and one flat rubric JSON. Same
principle, radically smaller footprint.

## What was verified live, not just claimed

Full numbers are in `README.md`'s calibration report; the short version:
16/16 environment reliability, sub-second solve time, 20/20 independent
blind-agent solves (mean 5.7 turns), and a real adversarial anti-cheat
rollout that scored 25/100 against a 100/100 genuine solve. None of this
is estimated; every number was independently re-verified by reading each
container's own server-side state, never trusted from an agent's
self-report.

A second, independent experiment (`experiments/schnorr-nonce-forge/`)
tested whether swapping the underlying vulnerability class would raise
difficulty. It didn't (6/6 solved, same speed) — a real, informative
negative result, written up in full in `README.md`'s
"Difficulty-calibration experiment" section rather than repeated here.

## What I'd improve with more time

1. **Tighten the difficulty band.** 100% solve rate across 20 real runs
   exceeds the ≥60% floor but leaves no headroom above it. The tuning
   lever is the `SIGN` rate limit or the hints in `PRODUCTS`, not the
   underlying vulnerability.
2. **Real structural coupling as the actual difficulty lever.** The
   Schnorr experiment ruled out "just use different crypto." The correct
   next step is a nonce recoverable only via a separate, mandatory
   precursor (e.g. an under-seeded LCG), so the signature-recovery step
   cannot even be attempted until that precursor is solved. Scoped, not
   built, to avoid rushing a third challenge without the same
   verification rigor everything else here has had.
3. **Stress-test `progress.json` under concurrent connections.** Fine for
   the intended single-agent-at-a-time grading model, untested beyond it.
