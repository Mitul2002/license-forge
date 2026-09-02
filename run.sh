#!/usr/bin/env bash
# Single documented entry point for license-forge.
set -euo pipefail

# No-op on Linux/macOS; on Windows Git Bash this stops MSYS from mangling
# the container-internal /app/... paths passed to `docker exec`.
export MSYS_NO_PATHCONV=1

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

IMAGE=license-forge
CONTAINER=license-forge
PORT=5000

# Try each candidate for real (Windows can have a `python3` on PATH that
# is just a Microsoft Store install-shim which "exists" but fails to run),
# not just check PATH presence.
PYTHON=""
for candidate in python3 python py; do
  if command -v "$candidate" >/dev/null 2>&1 && "$candidate" --version >/dev/null 2>&1; then
    PYTHON="$candidate"
    break
  fi
done
if [ -z "$PYTHON" ]; then
  echo "no working python interpreter found (tried python3, python, py)" >&2
  exit 1
fi

usage() {
  cat <<'EOF'
Usage: ./run.sh <command>

  build           docker build the challenge image (single command, cold build)
  up              start the challenge service (detached), wait until it accepts connections
  down            stop and remove the challenge container
  solve           run the reference solution against the running service, write output/flag.txt
  grade           grade the last solve attempt (reads server-side progress + the real flag)
  verify          build + up + solve + grade + down, one end-to-end pass
  reliability N   build once, then run up/solve/grade/down N times (default 16), report pass rate + timings
  clean           remove the image and any leftover container
EOF
}

cmd_build() {
  docker build -f environment/Dockerfile -t "$IMAGE" .
}

cmd_up() {
  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
  docker run -d --name "$CONTAINER" -p "$PORT:5000" \
    --memory=512m --cpus=1 --network bridge "$IMAGE" >/dev/null
  for _ in $(seq 1 50); do
    if (exec 3<>"/dev/tcp/127.0.0.1/$PORT") 2>/dev/null; then
      exec 3<&- 3>&- 2>/dev/null || true
      return 0
    fi
    sleep 0.2
  done
  echo "service did not become ready within 10s" >&2
  return 1
}

cmd_down() {
  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
}

cmd_solve() {
  "$PYTHON" solution/solve.py --host 127.0.0.1 --port "$PORT" --out output/flag.txt
}

cmd_grade() {
  "$PYTHON" tests/grader.py --container "$CONTAINER" --flag-file output/flag.txt
}

cmd_verify() {
  cmd_build
  cmd_up
  cmd_solve
  cmd_grade
  cmd_down
}

cmd_reliability() {
  local n="${1:-16}"
  cmd_build
  local pass=0
  for i in $(seq 1 "$n"); do
    cmd_up
    SECONDS=0
    if cmd_solve >/tmp/solve_$i.log 2>&1 && cmd_grade >/tmp/grade_$i.json 2>&1; then
      pass=$((pass + 1))
      echo "run $i: PASS (${SECONDS}s)"
    else
      echo "run $i: FAIL (${SECONDS}s) -- see /tmp/solve_$i.log /tmp/grade_$i.json"
    fi
    cmd_down
  done
  echo "passed $pass / $n"
}

cmd_clean() {
  cmd_down
  docker rmi -f "$IMAGE" >/dev/null 2>&1 || true
}

case "${1:-}" in
  build) cmd_build ;;
  up) cmd_up ;;
  down) cmd_down ;;
  solve) cmd_solve ;;
  grade) cmd_grade ;;
  verify) cmd_verify ;;
  reliability) cmd_reliability "${2:-16}" ;;
  clean) cmd_clean ;;
  *) usage; exit 1 ;;
esac
