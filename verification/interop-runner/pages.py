#!/usr/bin/env python3
"""Makes a static site of the runner's web pages with the results of
run.sh, for the Cloudflare Worker that wrangler.jsonc describes.

Usage:
  pages.py logs SRC DST [--max-bytes N]
  pages.py site --web DIR --result FILE --logs DIR --out DIR
                [--repository URL] [--runner-commit COMMIT]
  pages.py history --site DIR --previous URL [--keep N]

  logs     copy the directories in a logs directory of run.sh (OUT/logs, a
           directory for each server and client) to DST, leaving out files
           larger than N bytes (default 2 MiB), and write an index.html into
           each directory copied that lists its files and the files left
           out. The Worker lists no directories, and the web pages link
           each test case to its log directory.
  site     write the site to --out: the runner's web pages from --web
           (index.html, script.js and styles.css of its web/ directory,
           changed as below, and its LICENSE.md), --result (the result of
           summarize.py --result) as logs/quic/<run>/result.json and
           logs/quic/latest/result.json, the directories that `pages.py
           logs` wrote under logs/quic/<run>/, and logs/quic/logs.json
           listing the run. --repository (the repository's web address) and
           --runner-commit go into the page's description of the runs.
  history  add the runs that the site at URL lists in its logs.json to the
           site at --site: their result.json only, so their test cases link
           to no logs, and only the runs whose result has a run_url (see
           summarize.py --run-url), so that a run made elsewhere and
           published by hand is not kept. Keeps the last N runs, this one
           included (default 26). A site at URL without logs.json (HTTP 404)
           has no earlier runs; any other failure to read it ends the
           command with an error, so that a deployment does not drop the
           earlier runs.

The runner's web pages expect to be served at the root of a host, at /quic,
from a server that answers /quic with index.html. `site` changes them to
work from any directory; drops the runner's analytics script, the
WebTransport choice, the empty table of measurements, and the corner ribbon,
the invitation to join and the sponsor box of the runner's public site; and
describes these runs in place of the runner's own public matrix.
"""

import argparse
import html
import json
import re
import shutil
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

RUN_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
# Cloudflare refuses urllib's own User-Agent.
USER_AGENT = "sakuya-interop-runner-pages (+https://github.com/opengensokyonet/sakuya)"

# (file, text in the runner's web pages, replacement). Each text must appear
# exactly once, so that a change of the runner's pages fails here instead of
# making a site that does not work.
PATCHES = [
    (
        "script.js",
        'return "/" + sanitizeProtocol(protocol);',
        "return window.location.pathname;",
    ),
    (
        "script.js",
        "var protocolInPath = window.location.pathname.match(/^\\/(quic|webtransport)\\/?$/);",
        "var protocolInPath = true;",
    ),
    (
        "index.html",
        '  <script async src="https://analytics.seemann.io/script.js"'
        ' data-website-id="32c427b0-bba6-4367-931f-f6d38ce26e9e"></script>\n',
        "",
    ),
    (
        "index.html",
        '              <option value="webtransport">WebTransport</option>\n',
        "",
    ),
    (
        "index.html",
        "<title>QUIC Interop Runner</title>",
        "<title>sakuya: QUIC Interop Runner results</title>",
    ),
    # The runner's own corner ribbon, its stylesheet, the invitation to add
    # an implementation to its matrix and the sponsor box belong to its public
    # site, not to these runs.
    (
        "index.html",
        '  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/github-fork-ribbon-css/0.2.3/gh-fork-ribbon.min.css" integrity="sha512-TktJbycEG5Van9KvrSHFUcYOKBroD7QCYkEe73HAutODCw9QTFcvF6fuxioYM1h6THNudK1GjVidazj6EslK4A==" crossorigin="anonymous" />\n',
        "",
    ),
    (
        "index.html",
        '  <a class="github-fork-ribbon" href="https://github.com/quic-interop/quic-interop-runner" data-ribbon="Fork me on GitHub" title="Fork me on GitHub">Fork me on GitHub</a>\n',
        "",
    ),
    (
        "index.html",
        '    <p>\n'
        '      It is straightforward to add <strong>your implementation</strong> to this automated testing effort; please <a href="https://github.com/quic-interop/quic-interop-runner/blob/master/README.md#building-a-quic-endpoint">see these simple instructions</a>.\n'
        '    </p>\n'
        '\n'
        '    <div class="sponsor alert alert-dark">\n'
        '      <p>\n'
        '        If you find the QUIC Interop Runner useful, please consider sponsoring this project.<br>\n'
        '        Keeping the QUIC Interop Runner running incurs monthly costs for storage and bandwidth, as well as regular maintenance work.\n'
        '      </p>\n'
        '\n'
        '      <a href="https://github.com/sponsors/marten-seemann" class="btn btn-light github-sponsor-btn" role="button" target="_blank">\n'
        '        <i class="fa fa-github"></i> Sponsor\n'
        '      </a>\n'
        '    </div>\n'
        '\n',
        "",
    ),
]
ABOUT = re.compile(
    r'(<h3 class="mt-5">About</h3>\s*<p>)(.*?)(</p>)', re.DOTALL
)
NOTICE = (
    "<!-- Changed from the QUIC Interop Runner's web pages (Apache-2.0, see"
    " LICENSE.md) by sakuya's verification/interop-runner/pages.py. -->\n"
)
STYLE = "\n/* sakuya's runs have no measurements. */\n#measurements-section { display: none; }\n"


def human(size):
    return f"{size / 1048576:.1f} MiB" if size >= 1048576 else f"{size} bytes"


def write_index(directory, entries, omitted):
    title = html.escape(directory.name)
    items = []
    for name, is_dir in entries:
        href = urllib.parse.quote(name) + ("/" if is_dir else "")
        label = html.escape(name) + ("/" if is_dir else "")
        items.append(f'<li><a href="{href}">{label}</a></li>')
    for name, size in omitted:
        items.append(
            f"<li>{html.escape(name)}: left out ({human(size)}); it is in the"
            " workflow run's artifact of logs</li>"
        )
    (directory / "index.html").write_text(
        "<!DOCTYPE html>\n<html lang=\"en\">\n<head><meta charset=\"utf-8\">"
        f"<title>{title}</title></head>\n<body>\n<h1>{title}</h1>\n"
        '<p><a href="../">..</a></p>\n<ul>\n' + "\n".join(items) + "\n</ul>\n"
        "</body>\n</html>\n"
    )


def copy_logs(src, dst, max_bytes):
    dst.mkdir(parents=True, exist_ok=True)
    entries, omitted = [], []
    for path in sorted(src.iterdir()):
        if path.is_symlink():
            continue
        if path.is_dir():
            copy_logs(path, dst / path.name, max_bytes)
            entries.append((path.name, True))
        elif path.is_file():
            size = path.stat().st_size
            if size > max_bytes or path.name == "index.html":
                omitted.append((path.name, size))
            else:
                shutil.copyfile(path, dst / path.name)
                entries.append((path.name, False))
    write_index(dst, entries, omitted)


def command_logs(args):
    src, dst = Path(args.src), Path(args.dst)
    if not src.is_dir():
        sys.exit(f"not a directory: {src}")
    for path in sorted(src.iterdir()):
        if path.is_dir() and not path.is_symlink():
            copy_logs(path, dst / path.name, args.max_bytes)


def about(repository, runner_commit):
    repository = repository.rstrip("/") if repository else "https://github.com/opengensokyonet/sakuya"
    workflow = f"{repository}/actions/workflows/interop-runner.yml"
    commit = f" at commit <code>{html.escape(runner_commit[:12])}</code>" if runner_commit else ""
    return (
        f'These are the runs of the <a href="{html.escape(workflow)}">Interop runner</a>'
        f' workflow of <a href="{html.escape(repository)}">sakuya</a>: the'
        ' <a href="https://github.com/quic-interop/quic-interop-runner">QUIC Interop Runner</a>'
        f"{commit} between sakuya and the other implementations in the matrix, daily and on demand,"
        " with sakuya's endpoint image built in the workflow. They are not the runner's"
        ' public results at <a href="https://interop.seemann.io/">interop.seemann.io</a>.'
        ' Earlier runs can be chosen with "Run" in the title bar; only the latest run links'
        " to its logs, without the files larger than 2 MiB. Each workflow run keeps its"
        " whole logs as artifacts for 14 days."
    )


def patched_web(web):
    files = {name: (web / name).read_text() for name in ("index.html", "script.js", "styles.css")}
    for name, old, new in PATCHES:
        count = files[name].count(old)
        if count != 1:
            sys.exit(f"{web / name}: expected one {old!r}, found {count}")
        files[name] = files[name].replace(old, new)
    return files


def command_site(args):
    web, out = Path(args.web), Path(args.out)
    with open(args.result) as f:
        result = json.load(f)
    run = result["log_dir"]
    if not RUN_NAME.match(run):
        sys.exit(f"not a run name: {run!r}")
    files = patched_web(web)
    text = about(args.repository, args.runner_commit)
    files["index.html"], count = ABOUT.subn(
        lambda m: m.group(1) + "\n      " + text + "\n    " + m.group(3),
        files["index.html"],
        count=1,
    )
    if count != 1:
        sys.exit(f"{web / 'index.html'}: found no About paragraph")
    files["index.html"] = files["index.html"].replace(
        "<!DOCTYPE html>\n", "<!DOCTYPE html>\n" + NOTICE, 1
    )
    files["styles.css"] += STYLE

    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)
    for name, text in files.items():
        (out / name).write_text(text)
    license_file = web.parent / "LICENSE.md"
    if license_file.is_file():
        shutil.copyfile(license_file, out / "LICENSE.md")

    runs = out / "logs" / "quic"
    run_dir = runs / run
    logs = Path(args.logs)
    if logs.is_dir():
        shutil.copytree(logs, run_dir)
    run_dir.mkdir(parents=True, exist_ok=True)
    write_index(
        run_dir,
        [(p.name, True) for p in sorted(run_dir.iterdir()) if p.is_dir()] + [("result.json", False)],
        [],
    )
    for directory in (run_dir, runs / "latest"):
        directory.mkdir(parents=True, exist_ok=True)
        with open(directory / "result.json", "w") as f:
            json.dump(result, f)
    with open(runs / "logs.json", "w") as f:
        json.dump([run], f)


def fetch_json(url):
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.load(response)


def command_history(args):
    runs = Path(args.site) / "logs" / "quic"
    with open(runs / "logs.json") as f:
        current = json.load(f)
    base = args.previous.rstrip("/") + "/logs/quic/"
    try:
        previous = fetch_json(base + "logs.json")
    except urllib.error.HTTPError as error:
        if error.code != 404:
            sys.exit(f"could not read {base}logs.json: {error}")
        print(f"no earlier runs: {base}logs.json is not there")
        return
    except (urllib.error.URLError, OSError, ValueError) as error:
        sys.exit(f"could not read {base}logs.json: {error}")
    if not isinstance(previous, list):
        sys.exit(f"{base}logs.json is not a list")
    names = [
        name for name in previous
        if isinstance(name, str) and RUN_NAME.match(name) and name not in current and name != "latest"
    ]
    room = args.keep - len(current)
    kept = []
    # The latest runs first, until there is no more room.
    for name in reversed(names):
        if len(kept) >= room:
            break
        url = base + urllib.parse.quote(name) + "/result.json"
        try:
            result = fetch_json(url)
        except urllib.error.HTTPError as error:
            if error.code != 404:
                sys.exit(f"could not read {url}: {error}")
            print(f"left out the run {name}: {url} is not there")
            continue
        except (urllib.error.URLError, OSError, ValueError) as error:
            sys.exit(f"could not read {url}: {error}")
        if not isinstance(result, dict) or not isinstance(result.get("run_url"), str):
            print(f"left out the run {name}: its result has no run_url")
            continue
        directory = runs / name
        directory.mkdir(parents=True, exist_ok=True)
        with open(directory / "result.json", "w") as f:
            json.dump(result, f)
        kept.append(name)
    kept.reverse()
    with open(runs / "logs.json", "w") as f:
        json.dump(kept + current, f)
    print(f"kept {len(kept)} earlier runs")


def main():
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    logs = commands.add_parser("logs")
    logs.add_argument("src")
    logs.add_argument("dst")
    logs.add_argument("--max-bytes", type=int, default=2 * 1048576)
    site = commands.add_parser("site")
    site.add_argument("--web", required=True)
    site.add_argument("--result", required=True)
    site.add_argument("--logs", required=True)
    site.add_argument("--out", required=True)
    site.add_argument("--repository")
    site.add_argument("--runner-commit")
    history = commands.add_parser("history")
    history.add_argument("--site", required=True)
    history.add_argument("--previous", required=True)
    history.add_argument("--keep", type=int, default=26)
    args = parser.parse_args()
    {"logs": command_logs, "site": command_site, "history": command_history}[args.command](args)


if __name__ == "__main__":
    main()
