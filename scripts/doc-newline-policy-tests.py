#!/usr/bin/env python3
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import importlib.util
import sys
import unittest
from pathlib import Path

CHECKER_PATH = Path(__file__).with_name("doc-newline-check.py")
SPEC = importlib.util.spec_from_file_location("doc_newline_check", CHECKER_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"Could not load {CHECKER_PATH}")
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)


class DocumentationNewlineTests(unittest.TestCase):
    def test_suspicious_newlines(self) -> None:
        cases = {
            "plain prose": ("This sentence is\nwrapped.\n", False, [1]),
            "uppercase continuation": (
                "Use the official\nMicrosoft API.\n",
                False,
                [1],
            ),
            "aligned list continuation": (
                "- This sentence is\n  wrapped.\n",
                True,
                [1],
            ),
            "hanging list continuation": (
                "- This sentence is\n    wrapped.\n",
                False,
                [1],
            ),
            "abbreviation continuation": ("Use tools, e.g.\n`schema.py`.\n", True, [1]),
            "separate sentences": ("First sentence.\nSecond sentence.\n", False, []),
            "separate list items": ("- First item\n- Second item\n", True, []),
            "Markdown hard break": ("First line.  \nSecond line.\n", True, []),
            "YAML front matter": (
                "---\nname: example\ndescription: Example skill\n---\n",
                True,
                [],
            ),
            "HTML comment": ("<!-- prose split\nacross lines -->\n", True, []),
            "list in HTML comment": (
                "<!--\n- prose split\n  across lines\n-->\n",
                True,
                [],
            ),
            "Markdown fence": ("````\n```example\nprose-like code\n````\n", True, []),
            "list in Markdown fence": (
                "```markdown\n- prose split\n  across lines\n```\n",
                True,
                [],
            ),
            "list in YAML front matter": (
                "---\nitems:\n  - prose split\n    across lines\n---\n",
                True,
                [],
            ),
            "RST adornment": ("Heading\n~~~~~~~\nBody text.\n", False, []),
            "RST directive": (
                ".. note::\n\n   Deliberately wrapped\n   directive text.\n",
                False,
                [],
            ),
            "indented code in list": (
                "- Example::\n\n      command split\n      over lines\n",
                False,
                [],
            ),
        }

        for name, (text, markdown, expected) in cases.items():
            with self.subTest(name=name):
                self.assertEqual(
                    CHECKER.suspicious_newlines(text.splitlines(), markdown),
                    expected,
                )

    def test_format_lines(self) -> None:
        cases = {
            "paragraph": (
                "First sentence is\nwrapped. Second sentence.\n",
                False,
                ["First sentence is wrapped.", "Second sentence."],
            ),
            "hanging list": (
                "- First sentence is\n    wrapped. Second sentence.\n",
                False,
                ["- First sentence is wrapped.", "  Second sentence."],
            ),
            "abbreviation": (
                "Use tools, e.g.\n`schema.py`, here.\n",
                True,
                ["Use tools, e.g. `schema.py`, here."],
            ),
            "uppercase abbreviation": (
                "Use tools, E.g.\n`schema.py`, here.\n",
                True,
                ["Use tools, E.g. `schema.py`, here."],
            ),
        }

        for name, (text, markdown, expected) in cases.items():
            with self.subTest(name=name):
                formatted, fixes = CHECKER.format_lines(text.splitlines(), markdown)
                self.assertEqual(formatted, expected)
                self.assertGreater(fixes, 0)

                repeated, repeated_fixes = CHECKER.format_lines(formatted, markdown)
                self.assertEqual(repeated, formatted)
                self.assertEqual(repeated_fixes, 0)


if __name__ == "__main__":
    if sys.argv[1:] == ["-f"]:
        sys.argv.pop()
    unittest.main()
