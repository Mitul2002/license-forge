# Design note

## Track and category

Chose **Track A (CTF)** over Track B (CVE) mainly on reliability grounds.
Track B mandates an Intermediate tier that bypasses NX/ASLR — real
exploit-dev infrastructure (ROP chains, address leaks, libc pinning) that
is inherently sensitive to stack layout and ASLR entropy, which fights
directly against the assignment's own ≥14/16 reliability bar. Track A lets
the category be chosen, so I picked **crypto** specifically to avoid that
class of flakiness entirely: an oracle-based crypto challenge is either
mathematically exploitable or it isn't, with no environmental variance in
between. That bet paid off in practice — 16/16 reliability, achieved on
the first calibration run with no retries needed.

## The vulnerability

RSA blind-signature forgery: the server signs raw (unpadded) integers, and
raw RSA is multiplicatively homomorphic, so `sig(F)` is recoverable from
`sig(r^e * F mod n)` without the server ever agreeing to sign `F` directly.
This is a well-known *technique*; what's original is the packaging — the
License Forge narrative, the protocol, the specific refusal/oracle
shape, the flag mechanism. I judged this the right tradeoff: a novel-but-
undiscoverable primitive would fail the "not impossible" calibration bar,
while a recognizable technique executed against an unfamiliar live
protocol (spec deliberately withheld — see `instruction.md`) still forces
real multi-turn work. The live blind-agent test confirmed this: 8 turns
used, including one genuine wrong turn (calling `SIGN` before `PUBKEY` in
the same session) that had to be diagnosed and fixed.

## Trust architecture

Borrowed the *shape* of Parsewave's `ar_2.0/autoresearch-pipeline` trust
model — hidden ground truth lives behind a boundary the builder/solver
never crosses, a verifier reads that ground truth out-of-band, nothing is
LLM-graded — without borrowing its weight. Their system needs S3 lending,
GitHub PR reconciliation, and nine checkpointed finalization stages
because it runs continuously across a team. This deliverable needs exactly
two files (`progress.json`, written by the service as milestones occur;
`keys.json`, the build-time ground truth) and one flat rubric JSON. Same
principle, radically smaller footprint — "no fancy riff raff" was a
direct steer against over-borrowing Parsewave's machinery wholesale.

## What I verified live vs. what I'd still do

Given no Docker daemon at the start of this session, I first proved the
core logic host-side (server + solver run directly against each other,
outside Docker) before Docker was available, then re-verified everything
against the real containerized image once it was: 16/16 reliability,
sub-second solve time, and — the part I think matters most for an RL-data
submission — **two live, independently graded agent solves**, one of them
genuinely blind (a fresh subagent with only `instruction.md` and a
host:port, explicitly forbidden from touching this repo's source, whose
reported flag was cross-checked against its own container's ground truth
rather than trusted on self-report).

**What I'd do next with more time**, in priority order — updated after
checking what Parsewave's own pipeline actually has to offer for each gap:

1. ~~A formal anti-cheat run~~ — **done.** Parsewave's
   `anti_cheat.py` had a real, production adversarial-brief system
   (7 named cheat categories, a structured self-report, and the exact
   rule `passed if adversarial_score < genuine_score else failed`) that
   adapted directly. Ran it live against an isolated fourth container:
   **25/100 vs. 100/100, passed.** See README.
2. ~~Full ≥16-rollout blind-agent calibration~~ — **done.** Parsewave had
   no reusable methodology for this (their model is a single long
   Karpathy-style session per attempt, not short discrete turn-budgeted
   rollouts sampled many times), so the harness under `calibration/` was
   built from scratch: a pluggable `AgentDriver` interface, a scripted
   baseline used to prove the orchestration/isolation/grading plumbing
   before spending real agent time, then **20 genuinely blind Claude
   rollouts** against 20 isolated containers, each independently
   re-verified against real server-side state afterward.
   **Result: 20/20 solved (100%), mean 5.7 turns, range 3–9.**
3. ~~A second category~~ — **done.** Also absent in Parsewave (every task
   in their portfolio is ML/NLP benchmark work, zero security categories)
   so built from scratch: `second-category/` is a working web/LFI
   challenge (path traversal → source disclosure → token theft → admin
   takeover) with the same trust-split scaffold, its own rubric, and its
   own anti-cheat run (10/100 vs 100/100, passed). Explicitly kept as a
   labeled bonus, not co-equal with the crypto challenge — the assignment
   asks for one deeply-thought-through example, not volume; this answers
   Track A's "extend to other categories" bonus line with a real
   implementation instead of just a paragraph.
4. Stress-test `progress.json` under concurrent connections — fine for
   the intended single-agent-at-a-time grading model, untested beyond it.
5. **The "is this too easy for competition-level" question, tested
   empirically, not just noted.** 100% solve rate at a mean of 5.7 turns
   is honest evidence this sits closer to easy-to-medium than
   competition-hard. Rather than leave that as an unaddressed caveat, I
   tested the obvious hypothesis: would swapping the underlying
   vulnerability class (RSA blind-signature forgery → a different
   nonce-reuse family) raise difficulty? Built a second original
   challenge, `experiments/schnorr-nonce-forge/` — a Schnorr-signature
   service with a nonce-reuse bug, chosen after a real design-space
   comparison against ECDSA/elliptic-curve, LCG-token-forgery, and
   chained AES-CTR→RSA alternatives (the comparison document is included
   in that folder) — built it to the same standard as this challenge
   (16/16 reliability, real blind-agent rollouts, independent
   verification), and ran it.
   **The hypothesis was disconfirmed**: 6/6 blind rollouts solved it,
   6-8 turns each, uniformly reporting no real obstacles. The
   vulnerability class was never the actual lever — detecting a
   duplicate value among a handful of served records is trivial
   regardless of which signature scheme produced it, and the one
   genuinely undocumented implementation detail (hash byte-encoding) had
   a workaround every single rollout independently rediscovered
   (offline brute-force against the public verification equation, no
   live guesses wasted). This is a real, useful negative result: it
   correctly rules out "just use different crypto" as the fix, and
   points at the actual lever instead -- genuine structural coupling
   between two mandatory steps (an LCG-seeded nonce that must itself be
   recovered before the signature-recovery step is even attemptable),
   not a different flavor of the same single-step pattern-matchable
   attack. That's the correctly-scoped next step, deliberately not
   rushed out now without the same verification rigor everything else
   here has had -- consistent with this document's own timebox guidance
   about documenting next steps rather than cutting corners under time
   pressure.
