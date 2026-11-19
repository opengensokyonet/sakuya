#!/usr/bin/env bash
# Runs the QUIC interop runner between sakuya and one peer.
#
# Usage: run.sh checkout
#        run.sh <peer>
#
#   checkout  clone the runner at RUNNER_COMMIT into RUNNER_DIR, when it is
#             not there yet, and check that it is at that commit
#   <peer>    a name in the runner's implementations_quic.json, or sakuya.
#             Runs sakuya's server against the peer's client and the peer's
#             server against sakuya's client, in the roles the peer has; for
#             sakuya, one run of sakuya against itself.
#
# Environment:
#   RUNNER_DIR    the runner's checkout (default ./quic-interop-runner)
#   RUNNER_REPO   where to clone it from (default the runner on GitHub)
#   SAKUYA_IMAGE  the tag of sakuya's endpoint image, built from Dockerfile
#                 in this directory (default sakuya-interop:runner)
#   TESTS         comma-separated test cases (default the ones below)
#   OUT           output directory (default ./runner-out). Each run of a
#                 server and a client writes
#                 results/<server>_<client>_results.json, the runner's
#                 result, and logs/<server>_<client>/: the runner's logs of
#                 each test case it ran, and output.txt
#   PYTHON        a Python with requirements.txt installed (default python3)
#
# sakuya is added to the checkout's implementations_quic.json with
# SAKUYA_IMAGE as its image; the peers' images are the tags the file names
# at RUNNER_COMMIT. The runner uses the fixed container names sim, server
# and client, so only one run at a time can use a docker daemon.
#
# The exit status is 0 when the runner wrote a result for every run, whether
# or not the test cases passed, and 1 otherwise; 2 is a usage error.
set -euo pipefail

# quic-interop-runner, 2026-11-10.
RUNNER_COMMIT=f4d1e9350e24e394cf0d795908a1ef4a041e4a77
# The runner's test cases that sakuya_interop supports. The runner hands a
# program the names it reads (handshake, transfer, multiconnect, chacha20,
# retry, resumption, zerortt, ecn, connectionmigration); the other test
# cases differ in the network or in what the runner checks.
DEFAULT_TESTS=handshake,transfer,longrtt,chacha20,multiplexing,retry,resumption,zerortt,amplificationlimit,blackhole,handshakeloss,transferloss,handshakecorruption,transfercorruption,ecn,ipv6,rebind-port,rebind-addr,connectionmigration

if [ $# -ne 1 ]; then
  echo "usage: $0 checkout | <peer>" >&2
  exit 2
fi

runner_dir=${RUNNER_DIR:-./quic-interop-runner}
runner_repo=${RUNNER_REPO:-https://github.com/quic-interop/quic-interop-runner.git}
sakuya_image=${SAKUYA_IMAGE:-sakuya-interop:runner}
tests=${TESTS:-$DEFAULT_TESTS}
python=${PYTHON:-python3}

checkout() {
  if [ ! -d "$runner_dir/.git" ]; then
    git clone --quiet "$runner_repo" "$runner_dir"
    git -C "$runner_dir" checkout --quiet --detach "$RUNNER_COMMIT"
  fi
  local head
  head=$(git -C "$runner_dir" rev-parse HEAD)
  if [ "$head" != "$RUNNER_COMMIT" ]; then
    echo "$runner_dir is at $head, not $RUNNER_COMMIT" >&2
    exit 1
  fi
}

if [ "$1" = checkout ]; then
  checkout
  exit 0
fi
peer=$1

checkout
runner_dir=$(cd "$runner_dir" && pwd)
out=${OUT:-./runner-out}
mkdir -p "$out/results" "$out/logs"
out=$(cd "$out" && pwd)

# Add sakuya to the checkout's list of implementations, and read the roles
# the peer has.
roles=$("$python" - "$runner_dir/implementations_quic.json" "$sakuya_image" "$peer" <<'PY'
import json
import sys

path, image, peer = sys.argv[1:]
with open(path) as f:
    implementations = json.load(f)
implementations["sakuya"] = {
    "image": image,
    "url": "https://github.com/opengensokyonet/sakuya",
    "role": "both",
}
with open(path, "w") as f:
    json.dump(implementations, f, indent=2)
    f.write("\n")
if peer not in implementations:
    sys.exit(f"unknown implementation: {peer}")
print(implementations[peer]["role"])
PY
) || exit 2

pairs=()
if [ "$peer" = sakuya ]; then
  pairs=("sakuya sakuya")
else
  case $roles in both | client) pairs+=("sakuya $peer") ;; esac
  case $roles in both | server) pairs+=("$peer sakuya") ;; esac
fi

# One run of the runner: <server> <client>.
run_pair() {
  local server=$1 client=$2
  local name=${server}_${client}
  local json=$out/results/${name}_results.json
  local logs=$out/logs/$name
  # The runner refuses a log directory that exists.
  local run_logs=$out/runner-logs-$name
  # The runner stops its containers at the end of a test case and leaves
  # them; running ones belong to a run that is not over.
  local running
  running=$(docker ps --quiet --filter name='^(sim|server|client)$')
  if [ -n "$running" ]; then
    echo "a container named sim, server or client is running; another run is using this docker daemon" >&2
    return 1
  fi
  rm -rf "$json" "$logs" "$run_logs"
  mkdir -p "$logs"
  echo "== $server (server) and $client (client): $tests"
  (cd "$runner_dir" && "$python" run.py --protocol quic --server "$server" --client "$client" \
    --test "$tests" --log-dir "$run_logs" --json "$json") 2>&1 | tee "$logs/output.txt" || true
  if [ -d "$run_logs/$name" ]; then
    cp -a "$run_logs/$name/." "$logs/"
  fi
  rm -rf "$run_logs"
  if [ ! -f "$json" ]; then
    echo "the runner wrote no result for $name" >&2
    return 1
  fi
}

status=0
for pair in "${pairs[@]}"; do
  # shellcheck disable=SC2086 # two words, a server and a client
  run_pair $pair || status=1
done
exit $status
