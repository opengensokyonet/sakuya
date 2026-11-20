#!/usr/bin/env bash
# Runs one interop test case between two programs in docker containers.
#
# Usage: run.sh <server> <client> <testcase>
#   server, client: sakuya | quic-go
#   testcase: handshake | transfer | multiconnect | chacha20 | retry |
#             datagram | resetstreamat
#
# Environment:
#   SAKUYA_BIN_DIR   directory with sakuya-interop-server and
#                    sakuya-interop-client
#   QUIC_GO_BIN_DIR  directory with server and client (quic-go's interop
#                    programs) and ext-peer (quic-go-ext-peer)
#   OUT              run directory (default ./interop-out); this run writes
#                    to $OUT/<server>-to-<client>-<testcase>/
#   CERTS            certificate directory (default $OUT/certs); made with
#                    certs.sh when missing
#   IMAGE            container image (default archlinux:latest)
#
# Both programs run in containers on one docker network, the server under
# the name `server`, with no network simulator. The exit status is 0 when
# the test case passes and 1 when it fails; 2 is a usage error.
set -u

here=$(cd "$(dirname "$0")" && pwd)

if [ $# -ne 3 ]; then
  echo "usage: $0 <sakuya|quic-go> <sakuya|quic-go> <testcase>" >&2
  exit 2
fi
srv=$1; cli=$2; tc=$3
case $srv in sakuya | quic-go) ;; *) echo "unknown server: $srv" >&2; exit 2 ;; esac
case $cli in sakuya | quic-go) ;; *) echo "unknown client: $cli" >&2; exit 2 ;; esac
case $tc in
  handshake | transfer | multiconnect | chacha20 | retry | datagram | resetstreamat) ;;
  *) echo "unknown test case: $tc" >&2; exit 2 ;;
esac

image=${IMAGE:-archlinux:latest}
out=${OUT:-./interop-out}
mkdir -p "$out"
out=$(cd "$out" && pwd)
certs=${CERTS:-$out/certs}
if [ ! -f "$certs/cert.pem" ]; then
  "$here/certs.sh" "$certs" || exit 2
fi

# The program to run in each role.
program() { # <implementation> <role: server|client>
  case $1 in
    sakuya)
      echo "${SAKUYA_BIN_DIR:?SAKUYA_BIN_DIR is not set}/sakuya-interop-$2" ;;
    quic-go)
      case $tc in
        datagram | resetstreamat) echo "${QUIC_GO_BIN_DIR:?QUIC_GO_BIN_DIR is not set}/ext-peer" ;;
        *) echo "${QUIC_GO_BIN_DIR:?QUIC_GO_BIN_DIR is not set}/$2" ;;
      esac ;;
  esac
}
# The command line of that program inside the container.
command_of() { # <implementation> <role>
  if [ "$1" = quic-go ]; then
    case $tc in datagram | resetstreamat) echo "/prog $2"; return ;; esac
  fi
  echo "/prog"
}
srv_bin=$(program "$srv" server) || exit 2
cli_bin=$(program "$cli" client) || exit 2
for f in "$srv_bin" "$cli_bin"; do
  [ -x "$f" ] || { echo "not an executable file: $f" >&2; exit 2; }
done
srv_cmd=$(command_of "$srv" server)
cli_cmd=$(command_of "$cli" client)

run=$out/$srv-to-$cli-$tc
nfiles=2
kib=1024
rm -rf "$run"
mkdir -p "$run"/{www,downloads,logs-s,logs-c}
requests=""
for i in $(seq 1 $nfiles); do
  head -c $((kib * 1024)) /dev/urandom >"$run/www/f$i.bin"
  requests="$requests https://server:443/f$i.bin"
done
chmod -R a+rwX "$run"
# quic-go's own client takes the URLs as arguments, not from REQUESTS.
if [ "$cli" = quic-go ]; then
  case $tc in datagram | resetstreamat) ;; *) cli_cmd="$cli_cmd$requests" ;; esac
fi

net=interop-net-$$
server_name=interop-server-$$
cleanup() {
  docker rm -f "$server_name" >/dev/null 2>&1
  docker network rm "$net" >/dev/null 2>&1
}
trap cleanup EXIT
docker network create "$net" >/dev/null || exit 2

common=(--user "$(id -u):$(id -g)" -v "$certs:/certs:ro"
  -e "TESTCASE=$tc" -e SSLKEYLOGFILE=/logs/keys.log -e QLOGDIR=/logs/qlog/
  -e RUST_BACKTRACE=1)

docker run -d --name "$server_name" --network "$net" --network-alias server \
  "${common[@]}" -v "$srv_bin:/prog:ro" -v "$run/www:/www:ro" \
  -v "$run/logs-s:/logs" "$image" \
  sh -c "mkdir -p /logs/qlog; exec $srv_cmd" >/dev/null || exit 2
sleep 2

timeout 120 docker run --rm --network "$net" "${common[@]}" \
  -e "REQUESTS=$requests" -v "$cli_bin:/prog:ro" \
  -v "$run/downloads:/downloads" -v "$run/logs-c:/logs" "$image" \
  sh -c "mkdir -p /logs/qlog; exec $cli_cmd" >"$run/client.out" 2>&1
rc=$?
sleep 0.5
docker logs "$server_name" >"$run/server.out" 2>&1
cat "$run/logs-s/keys.log" "$run/logs-c/keys.log" >"$run/keys.log" 2>/dev/null

# Verdict.
ok=1
detail=""
case $tc in
  datagram)
    # The client's summary must list no missing, mismatched or unexpected
    # datagram.
    [ $rc = 0 ] || ok=0
    detail=$(cat "$run/downloads/datagram.txt" 2>/dev/null || echo "no datagram.txt")
    echo "$detail" | grep -q 'missing \[\]' || ok=0
    echo "$detail" | grep -q 'mismatched 0 unexpected 0' || ok=0
    ;;
  resetstreamat)
    # Each answer ends with a reset with code 0x52, and what the client
    # saved is a prefix of the file at least half its size.
    [ $rc = 0 ] || ok=0
    for i in $(seq 1 $nfiles); do
      w=$run/www/f$i.bin
      d=$run/downloads/f$i.bin
      size=$(stat -c %s "$w")
      got=$(stat -c %s "$d" 2>/dev/null || echo 0)
      end=$(cat "$d.end" 2>/dev/null || echo "no end")
      fok=1
      echo "$end" | grep -q '^reset 82 ' || fok=0
      { [ "$got" -ge $((size / 2)) ] && [ "$got" -le "$size" ]; } || fok=0
      cmp -s -n "$got" "$w" "$d" || fok=0
      [ $fok = 1 ] || ok=0
      detail="$detail f$i: size=$size got=$got end=[$(echo $end)] ok=$fok;"
    done
    ;;
  *)
    # Every file arrives, byte for byte.
    [ $rc = 0 ] || ok=0
    for i in $(seq 1 $nfiles); do
      cmp -s "$run/www/f$i.bin" "$run/downloads/f$i.bin" || ok=0
    done
    count=$(ls "$run/downloads" | wc -l)
    [ "$count" = $nfiles ] || ok=0
    detail="downloads=$count/$nfiles"
    ;;
esac

if [ $ok = 1 ]; then verdict=PASS; else verdict=FAIL; fi
echo "$verdict $srv(server) <- $cli(client) $tc: client_exit=$rc $detail"
[ $ok = 1 ]
