#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1]))
import backport


class BackportTest(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name)
        self.cwd = os.getcwd()
        os.chdir(self.root)
        self.git("init", "--quiet", "--initial-branch=main")
        self.git("config", "user.email", "test@example.com")
        self.git("config", "user.name", "Test User")
        self.commit("a.txt", "1\n2\n3\n4\n5\n", "Initial commit")
        self.old = self.commit("old.txt", "on\n", "Old (#1)")
        self.commit("old.txt", "off\n", "Revert old (#2)")
        self.git("branch", "release/7.x")
        self.commit("b.txt", "main only\n", "Diverge main")
        self.fix = self.commit("a.txt", "1\n2 fixed\n3\n4\n5\n", "Fix a (#10)")
        self.git("checkout", "--quiet", "release/7.x")
        self.commit("a.txt", "1\n2\n3\n4\n5 release\n", "Diverge release")
        self.base = self.git("rev-parse", "HEAD")

    def tearDown(self) -> None:
        os.chdir(self.cwd)
        self.directory.cleanup()

    def git(self, *args: str) -> str:
        return subprocess.run(
            ["git", *args], check=True, capture_output=True, text=True
        ).stdout.strip()

    def commit(self, path: str, content: str, message: str) -> str:
        Path(path).write_text(content, encoding="utf-8")
        self.git("add", path)
        self.git("commit", "--quiet", "-m", message)
        return self.git("rev-parse", "HEAD")

    def pick(self, commit: str) -> str:
        self.git("cherry-pick", "-x", commit)
        return self.git("rev-parse", "HEAD")

    def check(self) -> list[str]:
        return backport.check(self.base, self.git("rev-parse", "HEAD"), "main")

    def on_main(self, path: str, content: str, message: str) -> str:
        self.git("checkout", "--quiet", "main")
        commit = self.commit(path, content, message)
        self.git("checkout", "--quiet", "release/7.x")
        return commit

    def edited_pick(self, source: str, path: str, content: str) -> None:
        self.git("cherry-pick", "-x", "--no-commit", source)
        Path(path).write_text(content, encoding="utf-8")
        self.git("commit", "--quiet", "-a", "--no-edit")

    def test_clean_cherry_picks_then_fixups_pass(self) -> None:
        later = self.on_main("g.txt", "later\n", "Later fix (#12)")
        self.pick(self.fix)
        self.pick(later)
        self.commit("c.txt", "release only, adapted\n", "Adapt to 7.x")
        self.assertEqual(self.check(), [])

    def test_changed_cherry_pick_fails(self) -> None:
        for content in ["1\n2 fixed differently\n", "1\n2  fixed\n"]:
            with self.subTest(content=content):
                self.git("reset", "--quiet", "--hard", self.base)
                self.edited_pick(self.fix, "a.txt", content + "3\n4\n5 release\n")
                [error] = self.check()
                self.assertIn("differs from a clean cherry-pick", error)

    def test_cherry_pick_applied_elsewhere_fails(self) -> None:
        # Same lines changed at another place: equal zero-context patch IDs.
        add = self.on_main("dup.txt", "x\n1\n2\n3\nx\n", "Add dup (#20)")
        change = self.on_main("dup.txt", "y\n1\n2\n3\nx\n", "Change x (#21)")
        self.pick(add)
        self.edited_pick(change, "dup.txt", "x\n1\n2\n3\ny\n")
        [error] = self.check()
        self.assertIn("differs from a clean cherry-pick", error)

    def test_empty_and_renaming_cherry_picks_pass(self) -> None:
        self.git("checkout", "--quiet", "main")
        self.git("commit", "--quiet", "--allow-empty", "-m", "Empty (#15)")
        empty = self.git("rev-parse", "HEAD")
        self.git("mv", "a.txt", "d.txt")
        self.git("commit", "--quiet", "-m", "Rename (#16)")
        rename = self.git("rev-parse", "HEAD")
        self.git("checkout", "--quiet", "release/7.x")
        self.git("cherry-pick", "-x", "--allow-empty", empty)
        self.pick(rename)
        self.assertEqual(self.check(), [])

    def test_cherry_pick_after_fixup_passes(self) -> None:
        self.commit("c.txt", "prep\n", "Prep fixup")
        self.pick(self.fix)
        later = self.on_main("g.txt", "later\n", "Later fix (#12)")
        self.commit("c.txt", "middle\n", "Mid fixup")
        self.pick(later)
        self.assertEqual(self.check(), [])

    def test_update_branch_merge_commit_passes(self) -> None:
        self.pick(self.fix)
        self.git("checkout", "--quiet", "-b", "updated-base", self.base)
        self.commit("u.txt", "from base\n", "Base moved forward")
        self.base = self.git("rev-parse", "HEAD")
        self.git("checkout", "--quiet", "release/7.x")
        self.git("merge", "--quiet", "--no-edit", "updated-base")
        self.assertEqual(self.check(), [])
        self.commit("c.txt", "after update\n", "Follow-up fixup")
        self.assertEqual(self.check(), [])

    def test_merge_commit_with_cherry_pick_trailer_fails(self) -> None:
        self.pick(self.fix)
        self.git("checkout", "--quiet", "-b", "side", self.base)
        self.commit("d.txt", "side\n", "Side")
        self.git("checkout", "--quiet", "release/7.x")
        message = f"Merge side\n\n(cherry picked from commit {self.fix})"
        self.git("merge", "--quiet", "-m", message, "side")
        [error] = self.check()
        self.assertIn("single-parent", error)

    def test_malformed_cherry_pick_line_fails(self) -> None:
        sha = self.fix
        for trailer in [
            f"(cherry picked from commit {sha[:12]})",
            f"(cherry picked from commit {sha.upper()})",
            f"(cherry picked from {sha})",
            f"(cherry picked from commit {sha})\n(cherry picked from commit {sha})",
        ]:
            with self.subTest(trailer=trailer):
                self.git("reset", "--quiet", "--hard", self.base)
                self.git(
                    "commit", "--quiet", "--allow-empty", "-m", f"Fix\n\n{trailer}"
                )
                [error] = self.check()
                self.assertIn("malformed", error)

    def test_fixup_mentioning_cherry_pick_passes(self) -> None:
        self.pick(self.fix)
        for message in [
            f"Port #11\n\nManually cherry-picked from commit {self.fix}.",
            "Cherry-picked fixes need more tests on 7.x",
        ]:
            with self.subTest(message=message):
                self.git("commit", "--quiet", "--allow-empty", "-m", message)
                self.assertEqual(self.check(), [])

    def test_conflict_resolved_cherry_pick_fails(self) -> None:
        # Main deletes a file that release changed; keeping release's file
        # resolves the conflict with no change.
        self.commit("old.txt", "release\n", "Change old on release")
        self.base = self.git("rev-parse", "HEAD")
        self.git("checkout", "--quiet", "main")
        self.git("rm", "--quiet", "old.txt")
        self.git("commit", "--quiet", "-m", "Drop old (#17)")
        source = self.git("rev-parse", "HEAD")
        self.git("checkout", "--quiet", "release/7.x")
        message = f"Drop old (#17)\n\n(cherry picked from commit {source})"
        self.git("commit", "--quiet", "--allow-empty", "-m", message)
        [error] = self.check()
        self.assertIn("differs from a clean cherry-pick", error)

    def test_source_must_be_merged_to_main_since_branching(self) -> None:
        self.git("checkout", "--quiet", "-b", "feature", "main")
        unmerged = self.commit("e.txt", "unmerged\n", "Unmerged (#11)")
        self.git("checkout", "--quiet", "release/7.x")
        for source in [unmerged, self.old]:
            with self.subTest(source=source):
                self.git("reset", "--quiet", "--hard", self.base)
                message = f"Pick\n\n(cherry picked from commit {source})"
                self.git("commit", "--quiet", "--allow-empty", "-m", message)
                [error] = self.check()
                self.assertIn("is not a squash merge to main", error)

    def test_no_cherry_picks_passes(self) -> None:
        self.assertEqual(self.check(), [])
        self.commit("c.txt", "release only fix\n", "Release-only fix")
        self.assertEqual(self.check(), [])


if __name__ == "__main__":
    unittest.main()
