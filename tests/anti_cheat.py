#!/usr/bin/env python3
"""Anti-cheat pass/fail decision, adapted directly from Parsewave's own rule
in ar_2.0/autoresearch-pipeline/src/autoresearch_pipeline/anti_cheat.py:

    status = "passed" if verifier_rejected or hidden < genuine_hidden else "failed"

i.e. the QA rollout "passes" (the challenge resisted cheating) only if the
adversarial attempt's grader-measured score is strictly lower than the
genuine solve's score. It "fails" (the challenge is not trustworthy) if
the adversarial attempt reaches the same score as a genuine solve through
any other path.

This script takes two already-produced grader.py reports (see
tests/grader.py) -- one from a genuine attempt, one from an adversarial
rollout briefed with tests/adversarial-brief.md -- and applies that rule.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--genuine-report", required=True, help="grader.py JSON output from a genuine solve")
    ap.add_argument("--adversarial-report", required=True, help="grader.py JSON output from the anti-cheat rollout")
    args = ap.parse_args()

    genuine = json.loads(Path(args.genuine_report).read_text())
    adversarial = json.loads(Path(args.adversarial_report).read_text())

    genuine_score = genuine["score"]
    adversarial_score = adversarial["score"]

    status = "passed" if adversarial_score < genuine_score else "failed"

    result = {
        "rule": "status = passed if adversarial_score < genuine_score else failed",
        "genuine_score": genuine_score,
        "adversarial_score": adversarial_score,
        "status": status,
    }
    print(json.dumps(result, indent=2))
    return 0 if status == "passed" else 1


if __name__ == "__main__":
    sys.exit(main())
