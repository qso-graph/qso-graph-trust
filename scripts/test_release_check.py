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


class Source(unittest.TestCase):
    SHA = "a" * 40

    def args(self, **changes):
        values = dict(ref="refs/heads/main", event="workflow_dispatch", build_sha=self.SHA,
                      workflow_sha=self.SHA,
                      workflow_ref="qso-graph/qso-graph-trust/.github/workflows/release.yml@refs/heads/main",
                      actor="KI7MT", triggering_actor="KI7MT")
        values.update(changes)
        return list(values.values())

    def test_manual_main_release_at_exact_commit(self):
        self.assertTrue(rc.source_allowed(*self.args()))
        rc.main(["source", *self.args()])

    def test_other_branches_tags_and_pr_refs_are_refused(self):
        for ref in ["refs/heads/feature/0.1.0", "refs/heads/0.1.x", "refs/tags/v0.1.0",
                    "refs/pull/18/merge", "refs/pull/18/head", "main", "refs/heads/main\n", ""]:
            with self.subTest(ref=ref), self.assertRaises(SystemExit):
                rc.main(["source", *self.args(ref=ref)])

    def test_automatic_events_are_refused(self):
        for event in ["push", "pull_request", "pull_request_target", "schedule", "repository_dispatch", ""]:
            with self.subTest(event=event):
                self.assertFalse(rc.source_allowed(*self.args(event=event)))

    def test_other_main_workflows_and_other_operators_are_refused(self):
        for workflow in ["binaries.yml", "ci.yml"]:
            with self.subTest(workflow=workflow):
                ref=f"qso-graph/qso-graph-trust/.github/workflows/{workflow}@refs/heads/main"
                self.assertFalse(rc.source_allowed(*self.args(workflow_ref=ref)))
        self.assertFalse(rc.source_allowed(*self.args(workflow_ref="")))
        for actor in ["turing-qg[bot]", "someone", "KI7MT-other", ""]:
            with self.subTest(actor=actor):
                self.assertFalse(rc.source_allowed(*self.args(actor=actor)))
                self.assertFalse(rc.source_allowed(*self.args(triggering_actor=actor)))
        self.assertTrue(rc.source_allowed(*self.args(actor="ki7mt", triggering_actor="ki7mt")))

    def test_main_cannot_sign_a_different_or_ambiguous_commit(self):
        for build_sha, workflow_sha in [("b" * 40, self.SHA), ("main", self.SHA),
                                        ("", self.SHA), ("", ""), ("a" * 7, "a" * 7),
                                        (self.SHA + "\n", self.SHA + "\n")]:
            with self.subTest(build_sha=build_sha):
                self.assertFalse(rc.source_allowed(*self.args(build_sha=build_sha, workflow_sha=workflow_sha)))


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
