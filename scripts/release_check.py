#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 the QSO Graph Trust contributors (see AUTHORS). Part of QSO Graph Trust; see LICENSE.
"""What .github/workflows/release.yml decides before it publishes, kept here so each decision has a
test (scripts/test_release_check.py) with the cases it must refuse.

    release_check.py version VERSION            VERSION is a release or a beta: X.Y.Z or X.Y.Z-beta.N
    release_check.py proving-run REPO TREE      the green pull request run of this repository's CI
                                                whose own commit holds exactly TREE; reads the runs
                                                from GitHub with gh, prints that commit
    release_check.py crate CRATE VERSION FILE   whether crates.io has CRATE VERSION: prints absent, or
                                                same if it is exactly FILE (a .crate cargo packaged),
                                                and fails if it holds anything else
    release_check.py tag REPO VERSION SHA       whether vVERSION is tagged: prints absent, or same if
                                                the tag is on SHA, and fails if it is anywhere else

A developer and CI tool only, never shipped; standard library and gh only.
"""

import hashlib
import json
import re
import subprocess
import sys
import urllib.error
import urllib.request

# Matched whole with fullmatch: `$` would also match before a trailing newline.
VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(-beta\.[1-9][0-9]{0,2})?")
USER_AGENT = "qso-graph-trust release (https://github.com/qso-graph/qso-graph-trust)"


def is_version(version):
    """A release, X.Y.Z, or a beta, X.Y.Z-beta.N with N from 1."""
    return VERSION.fullmatch(version) is not None


def proving_run(runs, repo, tree, tree_of):
    """The commit of the first run that proves TREE: this repository's CI, on a pull request from a
    branch of this repository (never a fork's), finished green, whose own commit holds exactly TREE.
    None if no run does. `tree_of` gives a commit's tree."""
    for run in runs:
        if run.get("event") != "pull_request" or run.get("conclusion") != "success":
            continue
        if run.get("path") != ".github/workflows/ci.yml":
            continue
        if (run.get("head_repository") or {}).get("full_name") != repo:
            continue
        head = run.get("head_sha")
        if head and tree_of(head) == tree:
            return head
    return None


def published(crate, version, local_sha256, checksum_of):
    """What crates.io holds for CRATE VERSION: "absent", or "same" if its checksum is the local
    package's. Anything else is a different package under that version, which is refused."""
    checksum = checksum_of(crate, version)
    if checksum is None:
        return "absent"
    if checksum == local_sha256:
        return "same"
    raise SystemExit(
        f"crates.io has {crate} {version}, and it is not this commit's package "
        f"(crates.io {checksum}, here {local_sha256})"
    )


def tag_state(refs, version, sha):
    """Where vVERSION points, from `git ls-remote` output: "absent", or "same" if on SHA. A tag on
    any other commit is refused: a release is finished where it started, never moved. An annotated
    tag is judged by the commit it peels to."""
    name = f"refs/tags/v{version}"
    target = None
    for line in refs.splitlines():
        if "\t" not in line:
            continue
        object_id, ref = line.split("\t", 1)
        if ref == name + "^{}":
            target = object_id
            break
        if ref == name:
            target = object_id
    if target is None:
        return "absent"
    if target == sha:
        return "same"
    raise SystemExit(f"v{version} is tagged on {target}, not {sha}")


def _gh(*args):
    return subprocess.run(["gh", *args], check=True, capture_output=True, text=True).stdout


def _tree_of(repo):
    return lambda sha: _gh("api", f"repos/{repo}/git/commits/{sha}", "--jq", ".tree.sha").strip()


def _checksum_of(crate, version):
    url = f"https://crates.io/api/v1/crates/{crate}/{version}"
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.load(response)["version"]["checksum"]
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return None
        raise SystemExit(f"crates.io could not be asked about {crate} {version}: HTTP {error.code}")


def main(argv):
    if len(argv) == 2 and argv[0] == "version":
        if not is_version(argv[1]):
            sys.exit(f"not a release or beta version: {argv[1]}")
        return
    if len(argv) == 3 and argv[0] == "proving-run":
        repo, tree = argv[1], argv[2]
        runs = json.loads(
            _gh("api", f"repos/{repo}/actions/workflows/ci.yml/runs?event=pull_request&status=success&per_page=100",
                "--jq", ".workflow_runs")
        )
        head = proving_run(runs, repo, tree, _tree_of(repo))
        if head is None:
            sys.exit(f"no green pull request run of this repository's CI checked exactly tree {tree}")
        print(head)
        return
    if len(argv) == 4 and argv[0] == "crate":
        crate, version, path = argv[1:]
        with open(path, "rb") as f:
            local = hashlib.sha256(f.read()).hexdigest()
        print(published(crate, version, local, _checksum_of))
        return
    if len(argv) == 4 and argv[0] == "tag":
        repo, version, sha = argv[1:]
        refs = subprocess.run(
            ["git", "ls-remote", f"https://github.com/{repo}.git", f"refs/tags/v{version}", f"refs/tags/v{version}^{{}}"],
            check=True, capture_output=True, text=True,
        ).stdout
        print(tag_state(refs, version, sha))
        return
    sys.exit(__doc__)


if __name__ == "__main__":
    main(sys.argv[1:])
