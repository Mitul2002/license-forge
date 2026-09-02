#!/usr/bin/env python3
import argparse
import json
import subprocess
import time
import os
import sys
import socket

# Ensure we can import calibration.* when run directly
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

from calibration.scripted_baseline_driver import ScriptedBaselineDriver

def run_cmd(cmd_args):
    result = subprocess.run(cmd_args, capture_output=True, text=True)
    return result

def build_driver(name, model):
    if name == "scripted":
        return ScriptedBaselineDriver()
    raise ValueError(f"unknown driver: {name}")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--rollouts", type=int, default=16)
    parser.add_argument("--turn-budget", type=int, default=16)
    parser.add_argument("--driver", choices=["scripted"], default="scripted")
    parser.add_argument("--start-index", type=int, default=0, help="first rollout_id to use -- lets a top-up run write fresh container names/ports/transcript files without touching an earlier batch's results")
    args = parser.parse_args()

    print("Building base image...")
    build_res = run_cmd(["docker", "build", "-f", "environment/Dockerfile", "-t", "license-forge", "."])
    if build_res.returncode != 0:
        print("Failed to build image:", build_res.stderr)
        return

    results = []
    solved_count = 0
    total_turns_among_solves = 0

    driver = build_driver(args.driver, None)
    print(f"Using driver: {args.driver}")

    with open(os.path.join(ROOT, "instruction.md"), "r") as f:
        instruction_text = f.read()

    for offset in range(args.rollouts):
        i = args.start_index + offset
        container_name = f"license-forge-calib-r{i:02d}"
        port = 5000 + i

        print(f"[{offset+1}/{args.rollouts}] Starting rollout {i} on {container_name}:{port}...")
        start_time = time.time()
        
        # Start container
        run_cmd(["docker", "run", "-d", "--name", container_name, "-p", f"{port}:5000", "license-forge"])
        
        # Wait for port to be ready
        port_ready = False
        for _ in range(50):
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                    port_ready = True
                    time.sleep(1.0) # wait for python app to be ready
                    break
            except OSError:
                time.sleep(0.2)
                
        if not port_ready:
            print(f"Port {port} not ready in time.")
            run_cmd(["docker", "rm", "-f", container_name])
            results.append({
                "rollout_id": i,
                "turns_used": 0,
                "solved": False,
                "score": 0,
                "wall_seconds": round(time.time() - start_time, 2),
                "error": "port not ready"
            })
            continue
        
        transcript = []
        turns_used = 0
        flag = None
        solved = False
        score = 0
        error = None
        
        try:
            transcript, turns_used, flag = driver.run_solve("127.0.0.1", port, args.turn_budget, instruction_text)

            # Persist the transcript so runs are debuggable/auditable, not just an aggregate score.
            os.makedirs("calibration/transcripts", exist_ok=True)
            with open(f"calibration/transcripts/rollout_{i:02d}.json", "w") as f:
                json.dump({"rollout_id": i, "turns_used": turns_used, "flag": flag, "transcript": transcript}, f, indent=2)

            # Write flag for grader
            os.makedirs("output", exist_ok=True)
            flag_path = f"output/flag_{container_name}.txt"
            with open(flag_path, "w") as f:
                if flag:
                    f.write(flag + "\n")
                else:
                    f.write("")
            
            # Grade
            grader_cmd = [sys.executable, "tests/grader.py", "--container", container_name, "--flag-file", flag_path]
            grader_result = run_cmd(grader_cmd)
            
            try:
                report = json.loads(grader_result.stdout)
                score = report.get("score", 0)
                solved = report.get("solved", False)
            except json.JSONDecodeError:
                error = f"Grader failed to output JSON: {grader_result.stdout}\n{grader_result.stderr}"
                
            # Clean up flag file
            if os.path.exists(flag_path):
                os.remove(flag_path)
        except Exception as e:
            import traceback
            error = traceback.format_exc()
            
        wall_seconds = time.time() - start_time
        
        if solved:
            solved_count += 1
            total_turns_among_solves += turns_used
            
        results.append({
            "rollout_id": i,
            "turns_used": turns_used,
            "solved": solved,
            "score": score,
            "wall_seconds": round(wall_seconds, 2),
            "error": error
        })
        
        # Teardown container
        run_cmd(["docker", "rm", "-f", container_name])
        
    solve_rate = solved_count / args.rollouts if args.rollouts > 0 else 0.0
    mean_turns = total_turns_among_solves / solved_count if solved_count > 0 else 0.0
    passed_target = solve_rate >= 0.60
    
    final_report = {
        "rollouts": results,
        "aggregate": {
            "count": args.rollouts,
            "solve_rate": solve_rate,
            "mean_turns_among_solves": round(mean_turns, 2),
            "pass_60_percent_target": passed_target
        }
    }
    
    print("\n--- Final Report ---")
    print(json.dumps(final_report, indent=2))
    
    with open("calibration/report.json", "w") as f:
        json.dump(final_report, f, indent=2)

if __name__ == "__main__":
    main()
