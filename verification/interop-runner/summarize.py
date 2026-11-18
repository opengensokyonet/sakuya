#!/usr/bin/env python3
"""Reads the runner's results of the runs of run.sh and writes them as one
Markdown matrix and as one result in the runner's format.

Usage: summarize.py --results DIR --run NAME [--peers LIST] [--markdown FILE]
                    [--result FILE] [--implementations FILE] [--note TEXT]...
                    [--images FILE...] [--run-url URL]

  --results   directory with <server>_<client>_results.json files, the
              runner's --json output of each run
  --run       the name of the run; the result's log directory, and the name
              the web pages give it
  --peers     comma-separated implementations, in the order of the
              matrix's rows after sakuya; each has a row in both tables,
              of "?" where it has no run. Implementations with runs that
              are not listed follow by name
  --markdown  where to write the Markdown matrix (default standard output)
  --result    where to write the result in the runner's format: every server
              and client of the runs, a list of results for each pair of
              them (client by client, server by server, empty for a pair
              that did not run), as the runner's web pages read it
  --implementations
              the runner's implementations_quic.json: a peer that is only a
              server or only a client has a row only in the table where it
              has that role
  --note      a line to write under the Markdown heading; may be repeated
  --images    files with an image reference on each line, listed under
              the notes
  --run-url   the web address of the workflow run, written into the result
              as run_url; `pages.py history` keeps an earlier run only when
              its result has one, so runs made elsewhere are not kept

The exit status is 0 whether or not test cases failed.
"""

import argparse
import json
import sys
from pathlib import Path

SAKUYA = "sakuya"
MARKS = {"succeeded": "✓", "failed": "✗", "unsupported": "–"}


def read_runs(directory):
    """The runs by (server, client)."""
    runs = {}
    for path in sorted(Path(directory).glob("*_results.json")):
        with open(path) as f:
            data = json.load(f)
        if len(data["servers"]) != 1 or len(data["clients"]) != 1:
            sys.exit(f"{path}: expected one server and one client")
        runs[(data["servers"][0], data["clients"][0])] = data
    if not runs:
        sys.exit(f"no results in {directory}")
    return runs


def test_order(runs):
    """The test cases as (abbreviation, name), in the order of the runs."""
    order = []
    for data in runs.values():
        for item in data["results"][0]:
            entry = (item["abbr"], item["name"])
            if entry not in order:
                order.append(entry)
    return order


def cell(data, server, client, abbr):
    if data is None:
        return "?"
    for item in data["results"][0]:
        if item["abbr"] == abbr:
            result = item["result"]
            if result is None:
                return "?"
            mark = MARKS.get(result, result)
            if result == "failed":
                mark += f" `{server}_{client}/{item['name']}`"
            return mark
    return " "


def markdown(runs, peers, run, notes, images, roles):
    tests = test_order(runs)
    counts = {}
    for data in runs.values():
        for item in data["results"][0]:
            counts[item["result"]] = counts.get(item["result"], 0) + 1
    lines = [f"## Interop runner: {run}", ""]
    for note in notes:
        lines += [note, ""]
    if images:
        lines += ["Images: " + ", ".join(f"`{image}`" for image in images) + ".", ""]
    lines += [
        "✓ passed, ✗ failed (with the test case's log directory in the run's"
        " logs), – unsupported (the program ended with exit code 127),"
        " ? no result (the runner skipped it or did not finish).",
        "",
        f"{counts.get('succeeded', 0)} passed, {counts.get('failed', 0)} failed,"
        f" {counts.get('unsupported', 0)} unsupported,"
        f" {counts.get(None, 0)} without a result.",
        "",
    ]
    header = "| | " + " | ".join(abbr for abbr, _ in tests) + " |"
    rule = "| --- |" + " --- |" * len(tests)
    for title, role, pair in (
        ("sakuya as the server", "client", lambda peer: (SAKUYA, peer)),
        ("sakuya as the client", "server", lambda peer: (peer, SAKUYA)),
    ):
        # A peer without a run in this role has a row of "?", unless it
        # does not take the role.
        rows = [peer for peer in peers if roles.get(peer, "both") in ("both", role)]
        if role == "server":
            # sakuya against itself is in the first table.
            rows = [peer for peer in rows if peer != SAKUYA]
        if not rows:
            continue
        lines += [f"### {title}", "", header.replace("| |", f"| {role} |", 1), rule]
        for peer in rows:
            server, client = pair(peer)
            data = runs.get((server, client))
            cells = [cell(data, server, client, abbr) for abbr, _ in tests]
            lines.append(f"| {peer} | " + " | ".join(cells) + " |")
        lines.append("")
    lines.append(
        "Test cases: " + ", ".join(f"{abbr} {name}" for abbr, name in tests) + "."
    )
    return "\n".join(lines) + "\n"


def result(runs, peers, run, run_url):
    servers = [p for p in peers if any(s == p for s, _ in runs)]
    clients = [p for p in peers if any(c == p for _, c in runs)]
    out = {
        "servers": servers,
        "clients": clients,
        "log_dir": run,
        "start_time": min(d["start_time"] for d in runs.values()),
        "end_time": max(d["end_time"] for d in runs.values()),
        "results": [],
        "measurements": [],
        "tests": {},
        "urls": {},
    }
    if run_url:
        out["run_url"] = run_url
    for data in runs.values():
        out["tests"].update(data["tests"])
        out["urls"].update(data["urls"])
        out["quic_version"] = data["quic_version"]
    for client in clients:
        for server in servers:
            data = runs.get((server, client))
            out["results"].append(data["results"][0] if data else [])
            out["measurements"].append(data["measurements"][0] if data else [])
    return out


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--results", required=True)
    parser.add_argument("--run", required=True)
    parser.add_argument("--peers")
    parser.add_argument("--markdown")
    parser.add_argument("--result")
    parser.add_argument("--note", action="append", default=[])
    parser.add_argument("--images", nargs="*", default=[])
    parser.add_argument("--implementations")
    parser.add_argument("--run-url")
    args = parser.parse_args()

    runs = read_runs(args.results)
    names = sorted({name for pair in runs for name in pair} - {SAKUYA})
    peers = [SAKUYA]
    if args.peers:
        peers += [p for p in args.peers.split(",") if p and p != SAKUYA]
    peers += [p for p in names if p not in peers]

    images = []
    for path in args.images:
        # An unmatched glob reaches here as itself.
        if not Path(path).is_file():
            continue
        for line in Path(path).read_text().splitlines():
            if line.strip() and line.strip() not in images:
                images.append(line.strip())
    roles = {}
    if args.implementations:
        with open(args.implementations) as f:
            roles = {name: value["role"] for name, value in json.load(f).items()}
    text = markdown(runs, peers, args.run, args.note, sorted(images), roles)
    if args.markdown:
        Path(args.markdown).write_text(text)
    else:
        sys.stdout.write(text)
    if args.result:
        with open(args.result, "w") as f:
            json.dump(result(runs, peers, args.run, args.run_url), f)


if __name__ == "__main__":
    main()
