#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 the QSO Graph Trust contributors (see AUTHORS). Part of QSO Graph Trust; see LICENSE.
"""The release's decisions, each with the cases it must refuse. Run: python3 scripts/test_release_check.py"""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import release_check as rc  # noqa: E402

REPO = "qso-graph/qso-graph-trust"
TREES = {"good": "T", "other": "U", "fork": "T"}


def run(**over):
    base = {
        "event": "pull_request",
        "conclusion": "success",
        "path": ".github/workflows/ci.yml",
        "head_repository": {"full_name": REPO},
        "head_sha": "good",
    }
    base.update(over)
    return base


class Version(unittest.TestCase):
    def test_releases_and_betas(self):
        for v in ["0.1.0", "0.1.0-beta.1", "1.2.3-beta.12", "10.0.0"]:
            self.assertTrue(rc.is_version(v), v)

    def test_refused(self):
        for v in ["0.1", "v0.1.0", "0.1.0-beta.0", "0.1.0-beta", "0.1.0-rc.1", "0.1.0-beta.1 ", "0.1.0\n",
                  "0.1.0-beta.1;x", "01.0"]:
            self.assertFalse(rc.is_version(v), repr(v))


class ProvingRun(unittest.TestCase):
    def prove(self, runs, tree="T"):
        return rc.proving_run(runs, REPO, tree, TREES.get)

    def test_a_green_run_of_exactly_this_tree(self):
        self.assertEqual(self.prove([run()]), "good")

    def test_a_run_of_other_files(self):
        self.assertIsNone(self.prove([run(head_sha="other")]))

    def test_a_forks_run(self):
        self.assertIsNone(self.prove([run(head_sha="fork", head_repository={"full_name": "someone/qso-graph-trust"})]))
        self.assertIsNone(self.prove([run(head_repository=None)]))

    def test_a_run_that_did_not_pass(self):
        for conclusion in ["failure", "cancelled", "skipped", None]:
            self.assertIsNone(self.prove([run(conclusion=conclusion)]), conclusion)

    def test_another_workflow_or_event(self):
        self.assertIsNone(self.prove([run(path=".github/workflows/release.yml")]))
        self.assertIsNone(self.prove([run(event="push")]))
        self.assertIsNone(self.prove([run(event="workflow_dispatch")]))

    def test_the_first_proving_run_among_others(self):
        self.assertEqual(self.prove([run(head_sha="other"), run(conclusion="failure"), run()]), "good")


class Published(unittest.TestCase):
    def test_absent(self):
        self.assertEqual(rc.published("c", "0.1.0", "aa", lambda c, v: None), "absent")

    def test_the_same_package(self):
        self.assertEqual(rc.published("c", "0.1.0", "aa", lambda c, v: "aa"), "same")

    def test_a_different_package_under_the_version(self):
        with self.assertRaises(SystemExit):
            rc.published("c", "0.1.0", "aa", lambda c, v: "bb")



class FirstToken(unittest.TestCase):
    def test_while_a_crate_is_new(self):
        self.assertTrue(rc.first_token_allowed({"a": True, "b": True, "cli": False}))
        self.assertTrue(rc.first_token_allowed({"a": False}))

    def test_refused_once_every_crate_exists(self):
        self.assertFalse(rc.first_token_allowed({"a": True, "b": True, "cli": True}))


class Tag(unittest.TestCase):
    def test_absent(self):
        self.assertEqual(rc.tag_state("", "0.1.0", "abc"), "absent")
        self.assertEqual(rc.tag_state("abc\trefs/tags/v0.1.0-beta.1\n", "0.1.0", "abc"), "absent")

    def test_on_this_commit(self):
        self.assertEqual(rc.tag_state("abc\trefs/tags/v0.1.0\n", "0.1.0", "abc"), "same")

    def test_annotated_on_this_commit(self):
        refs = "tagobj\trefs/tags/v0.1.0\nabc\trefs/tags/v0.1.0^{}\n"
        self.assertEqual(rc.tag_state(refs, "0.1.0", "abc"), "same")

    def test_on_another_commit(self):
        with self.assertRaises(SystemExit):
            rc.tag_state("def\trefs/tags/v0.1.0\n", "0.1.0", "abc")
        with self.assertRaises(SystemExit):
            rc.tag_state("abc\trefs/tags/v0.1.0\ndef\trefs/tags/v0.1.0^{}\n", "0.1.0", "abc")


if __name__ == "__main__":
    unittest.main()
