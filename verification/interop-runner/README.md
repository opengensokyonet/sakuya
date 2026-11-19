# interop-runner

Runs of the [QUIC Interop Runner](https://github.com/quic-interop/quic-interop-runner)
between sakuya and other QUIC implementations, through the runner's network
simulator, with sakuya's endpoint image built from this repository. The
`Interop runner` workflow runs them daily and on demand; they do not gate
pushes, and a failed test case does not fail the workflow. GitHub turns off
a public repository's scheduled workflows after 60 days without activity in
it; the daily runs then stop until the workflow is turned on again.

sakuya is not in the runner's public matrix: its image is built inside the
workflow, kept as an artifact of the run for a day and pushed to no registry,
and sakuya is added to the runner's `implementations_quic.json` only in the
workflow's checkout of the runner.

## Results

- **The workflow run's summary**: a matrix for sakuya as the server and as
  the client, a row for each peer and a column for each test case: ✓
  passed, ✗ failed, with the test case's log directory
  (`<server>_<client>/<test case>`), – unsupported (the program ended with
  exit code 127), ? no result. The peers' image digests are listed with it.
- **The artifacts of the run**: `runner-logs-<peer>`, the runner's logs of
  every test case it ran, with the simulator's packet captures and the TLS
  key logs; `runner-results-<peer>`, the runner's results as JSON. They
  are kept for 14 days.
- **The web pages at <https://opengensokyo.net/interop/>**: the runner's
  own web pages, showing the latest run and the results of up to 25 earlier
  runs of the workflow, with the logs of the latest run (files larger than
  2 MiB left out). Only runs on `main` publish them: the `deploy` job reads
  the earlier runs from the site as it is, keeping those whose result names
  a workflow run, and deploys the whole site with wrangler 4.157.0 as the
  static assets of the Cloudflare Worker `ogn-interop`, which
  `wrangler.jsonc` describes and which serves `opengensokyo.net/interop`
  and `opengensokyo.net/interop/*`. It needs the repository secrets
  `CLOUDFLARE_API_TOKEN`, a token that may edit the account's Workers and
  the zone's Workers routes, and `CLOUDFLARE_ACCOUNT_ID`.

## Peers and test cases

The workflow's default peers are the implementations of the runner's
`implementations_quic.json` that ran `handshake` and `transfer` against
sakuya in both roles on a developer machine (2026-11-18): quic-go, quinn,
quiche, ngtcp2, picoquic, lsquic, mvfst, neqo, msquic, s2n-quic, aioquic,
kwik, xquic, go-x-net, rama, and haproxy, which is only a server. sakuya
also runs against itself. Their images are the tags the file names, which
are not pinned; the summary lists the digests each run used.

Left out of the defaults:

- nginx (only a server): its image, from 2025-11, closes the connection
  with INTERNAL_ERROR when sakuya's first ACK carries ECN counts (ACK frame
  type 0x03; nginx logs "quic missing frame handler"), so both test cases
  fail before the handshake ends.
- chrome (only a client): it speaks HTTP/3 only and ends `handshake` and
  `transfer` as unsupported.

In that check, with mvfst as the server and sakuya as the client,
`transfer` failed in all four runs, with mvfst resetting the stream of the
largest file (error code 0x3fffffffffffffff) after about 1.9 MB. mvfst's
HTTP/0.9 server gives up on a write that the stream's credit holds back
for 5 s; sakuya_interop now gives each bidirectional stream credit for a
whole file at once, and the test case passes (2026-11-19).

The test cases are those `run.sh` names: `handshake`, `transfer`,
`longrtt`, `chacha20`, `multiplexing`, `retry`, `resumption`, `zerortt`,
`keyupdate`, `amplificationlimit`, `blackhole`, `handshakeloss`, `transferloss`,
`handshakecorruption`, `transfercorruption`, `ecn`, `ipv6`, `rebind-port`,
`rebind-addr` and `connectionmigration`. A manual run can choose other
peers and test cases.

Some of them fail for what the peer does, as a run on a developer machine
found (2026-11-19):

- `connectionmigration` with sakuya as the server fails against clients that
  do not move to the server's preferred address: quic-go, quinn and quiche
  (quiche does not read the transport parameter). The runner then sees a
  single path.
- `rebind-port` and `rebind-addr` with quiche as the server fail against
  sakuya and quic-go alike: quiche keeps a recovery state for each path,
  and never declares lost the packets sent to the address the client left,
  so the stream stops at the first of them.
- `multiplexing` with quiche as the client fails against sakuya and quic-go
  alike: its client keeps a file open for each request, and ends when the
  container's limit of open files is reached.

`zerortt` with sakuya as the client ends as unsupported, and so does `ecn`
with quic-go and quiche.

## Files

- `Dockerfile`: sakuya's endpoint image, in two stages: the toolchain that
  `rust-toolchain.toml` pins builds `sakuya_interop` with the feature
  `extensions` on Ubuntu 24.04, and the programs go onto the runner's
  endpoint image `martenseemann/quic-network-simulator-endpoint`, whose
  glibc is that of Ubuntu 24.04. Both base images are pinned by digest.
  `Dockerfile.dockerignore` keeps `target/` and `.cargo/` out of the build,
  so a local `.cargo/config.toml` does not patch the Git dependencies.
- `run_endpoint.sh`: the image's entry point. It sets up the routes through
  the simulator (`/setup.sh`) and starts the server or, once the simulator
  is ready, the client, as `ROLE` says.
- `run.sh`: checks out the runner at a fixed commit, adds sakuya to it and
  runs it between sakuya and one peer, in both roles.
- `summarize.py`: the Markdown matrix of the runner's results, and the
  results as one result in the format of the runner's web pages.
- `pages.py`: the static site of the runner's web pages, changed to work
  from a subdirectory, with the results and logs of a run and the results of
  earlier ones.
- `wrangler.jsonc`: the Cloudflare Worker that serves the site, static
  assets only, from `site/` in this directory, where the `deploy` job puts
  the site as `site/interop/`.
- `requirements.txt`: the runner's Python packages, pinned.

## Running

Prerequisites: docker with Docker Engine 28.1 or newer and Docker Compose
2.36 or newer, without `sudo`; tshark 4.5.0 or newer; Python 3.12 or 3.13
(pyshark 0.6 does not run on 3.14); git.

From the repository root:

```sh
docker build -f verification/interop-runner/Dockerfile -t sakuya-interop:runner .

python3 -m venv target/runner-venv
target/runner-venv/bin/pip install -r verification/interop-runner/requirements.txt

export RUNNER_DIR=$PWD/target/quic-interop-runner
export OUT=$PWD/target/runner-out
export PYTHON=$PWD/target/runner-venv/bin/python

# sakuya against itself, then against quic-go in both roles
verification/interop-runner/run.sh sakuya
verification/interop-runner/run.sh quic-go

# fewer test cases
TESTS=handshake,transfer verification/interop-runner/run.sh quinn

# the matrix and the web pages
verification/interop-runner/summarize.py --results "$OUT/results" --run local --result "$OUT/result.json" \
  --implementations "$RUNNER_DIR/implementations_quic.json"
verification/interop-runner/pages.py logs "$OUT/logs" "$OUT/pages-logs"
verification/interop-runner/pages.py site --web "$RUNNER_DIR/web" --result "$OUT/result.json" \
  --logs "$OUT/pages-logs" --out "$OUT/site"
(cd "$OUT/site" && python3 -m http.server 8000)   # http://localhost:8000/
```

The runner names its containers `sim`, `server` and `client`, so only one
run at a time can use a docker daemon; `run.sh` stops when they are
running. It writes temporary files under `/tmp`.

## On GitHub's hosted runners

The jobs run on `ubuntu-24.04`, as the runner's own workflow does:

- The hosted image's Docker Engine (28.0.4) is older than the runner's
  `docker-compose.yml` needs, so the job installs 28.3.0 with
  `docker/setup-docker-action`, before loading any image.
- The runner's networks have IPv6, for which the job loads
  `ip6table_filter`; the simulator needs `NET_ADMIN`, which the compose file
  grants and the hosted runners allow.
- tshark comes from the Wireshark stable PPA, which carries only its latest
  release, so its version is not pinned; the job checks that it is 4.5.0 or
  newer. The `image` job fetches its packages from the PPA once, retrying
  when Launchpad answers 503, and hands them to the runner jobs as the
  artifact `tshark-debs`; sixteen jobs fetching from the PPA at once had half
  of them refused.
- A runner job that fails leaves its peer without results in the matrix; the
  summary and the web pages are still made from the other jobs.
- The peers run in parallel jobs, at most eight at once (`max-parallel`),
  so that the other workflows keep some of the 20 jobs a public repository
  on the Free plan can run at once; with sakuya against itself there are
  17 jobs, in three rounds. On a developer machine the twelve test cases
  took about 5 minutes for one server and client (sakuya and quic-go, either
  way round), and `handshake` and `transfer` in both roles about 80 seconds
  for each peer. Hosted runners are slower and each job first installs
  Docker and tshark and loads the images, so a job should take some 15 to
  30 minutes and a whole run, with building the image, one to two hours.
  These are estimates; the workflow has not run on GitHub yet.
- Logs: most pairs of `handshake` and `transfer` left 20 to 120 MB, but
  haproxy's server log of one `transfer` was about 450 MB, so its job may
  come near the hosted runner's free disk with all twelve test cases. The
  job compresses files larger than 50 MB with zstd before uploading them. Test cases
  under loss and corruption can fail now and then on a slow runner; the
  matrix shows each run as it came out.
