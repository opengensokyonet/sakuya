#!/usr/bin/env bash
# Runs every combination of run.sh and prints a summary.
#
#   sakuya server  <- sakuya client    all seven test cases
#   quic-go server <- sakuya client    the test cases both support
#   sakuya server  <- quic-go client   the test cases both support
#
# quic-go's own interop programs support handshake, transfer, multiconnect,
# chacha20 and retry; quic-go-ext-peer adds datagram and resetstreamat, so
# every test case is supported on both sides. A combination listed in
# SKIP (a space-separated list of "server:client:testcase") is not run.
#
# Takes the environment of run.sh. The exit status is 0 when every run
# passes.
set -u
here=$(cd "$(dirname "$0")" && pwd)
cases="handshake transfer multiconnect chacha20 retry datagram resetstreamat"
SKIP=${SKIP:-}

pairs=("sakuya sakuya" "quic-go sakuya" "sakuya quic-go")
results=()
failed=0
for pair in "${pairs[@]}"; do
  set -- $pair
  for tc in $cases; do
    case " $SKIP " in
      *" $1:$2:$tc "*) results+=("SKIP|$1|$2|$tc"); continue ;;
    esac
    if "$here/run.sh" "$1" "$2" "$tc"; then
      results+=("PASS|$1|$2|$tc")
    else
      results+=("FAIL|$1|$2|$tc")
      failed=$((failed + 1))
    fi
  done
done

echo
echo "Summary"
printf '%-6s %-9s %-9s %s\n' RESULT SERVER CLIENT TESTCASE
for r in "${results[@]}"; do
  IFS='|' read -r verdict s c t <<<"$r"
  printf '%-6s %-9s %-9s %s\n' "$verdict" "$s" "$c" "$t"
done
echo
echo "${#results[@]} runs, $failed failed"
[ $failed = 0 ]
