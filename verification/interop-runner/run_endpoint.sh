#!/bin/bash
# The entry point of sakuya's endpoint image. The runner sets ROLE,
# TESTCASE, REQUESTS, SSLKEYLOGFILE and QLOGDIR; the programs read them and
# end with exit code 127 for a test case they do not support.
set -e

# The endpoint image's routes through the network simulator.
/setup.sh

case "$ROLE" in
  server)
    exec /sakuya-interop-server
    ;;
  client)
    # The simulator opens this port once it is ready.
    /wait-for-it.sh sim:57832 -s -t 30
    exec /sakuya-interop-client
    ;;
  *)
    echo "unknown ROLE: $ROLE" >&2
    exit 1
    ;;
esac
