# Calibration Harness

This directory contains the infrastructure to run independent, turn-budgeted, blind-agent solve attempts against the `license-forge` challenge, and report aggregate solve-rate statistics.

## How to Run

To run the full calibration with the default 16 rollouts:
```bash
python calibration/run_rollouts.py --rollouts 16 --turn-budget 16
```

To run a small dry run:
```bash
python calibration/run_rollouts.py --rollouts 3 --turn-budget 16
```

## What the Scripted Baseline Proves
The `ScriptedBaselineDriver` is a deterministic agent that replays the known intended solve path (`HELP`, `PUBKEY`, `PRODUCTS`, compute, `SIGN`, `ACTIVATE`, `CHALLENGE`). It counts turns exactly the same way a live agent would.
Running the scripted baseline proves that the harness plumbing works end-to-end: it successfully builds the image, starts N isolated containers on unique ports, runs the driver against them, accurately grades the outcome out-of-band using `tests/grader.py`, aggregates the stats, and tears down the containers. It proves all this without relying on external LLM APIs, ensuring that isolation and metrics are correct before plugging in an actual model.

## Plugging in a Real LLM-Backed Agent
To wire in a real LLM-backed agent, you must create a new class that implements the `AgentDriver` interface defined in `calibration/agent_driver.py`.

Your implementation needs to provide the `run_solve` method:
```python
def run_solve(self, host: str, port: int, turn_budget: int, instruction_text: str) -> Tuple[List[Dict], int, Optional[str]]:
```

Within `run_solve`:
1. Connect to the specified `host:port`.
2. Initialize your LLM agent with the provided `instruction_text`.
3. Allow the LLM to issue commands (e.g., sending text to the socket) and observe responses.
4. Keep track of each step (a turn consists of a command/tool-call and its observation).
5. Ensure the agent respects the `turn_budget`. Stop execution and return if it exceeds the limit.
6. When the agent believes it has captured the flag, extract the flag.
7. Return the `transcript` (a list of all turns taken), the total `turns_used`, and the extracted `flag` string.

Then, update `run_rollouts.py` to instantiate and use your new driver instead of the `ScriptedBaselineDriver`.
