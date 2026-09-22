# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import os
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from docutils import nodes
from sphinx.errors import SphinxError

import rustdoc


class RustdocTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        root = Path(self.directory.name)
        self.app = SimpleNamespace(
            srcdir=root / "version-checkout/doc",
            outdir=root / "site/release/8.x",
            doctreedir=root / "doctrees/release/8.x",
            builder=SimpleNamespace(
                format="html", get_target_uri=lambda name: name + ".html"
            ),
        )
        self.manifest = self.app.srcdir.parent / "src/rust/ccf-app/Cargo.toml"
        self.manifest.parent.mkdir(parents=True)
        self.manifest.touch()
        self.environment = patch.dict(os.environ, {}, clear=True)
        self.environment.start()
        self.addCleanup(self.environment.stop)

    def cargo_doc(self, command, **kwargs):
        self.assertEqual(
            command[:5], ["cargo", "doc", "--locked", "--lib", "--no-deps"]
        )
        self.assertEqual(
            command[command.index("--manifest-path") + 1], str(self.manifest)
        )
        self.assertEqual(kwargs["cwd"], self.manifest.parent)
        self.assertTrue(kwargs["check"])
        self.assertNotIn("CARGO_BUILD_TARGET", kwargs["env"])
        self.assertIn("-D warnings", kwargs["env"]["RUSTDOCFLAGS"])
        target = Path(command[command.index("--target-dir") + 1])
        self.assertEqual(target.parent, self.app.doctreedir)
        for filename in (
            "ccf_app/index.html",
            "static.files/style.css",
            "search-index.js",
            "src/ccf_app/lib.rs.html",
        ):
            path = target / "doc" / filename
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(filename, encoding="utf-8")

    def test_version_sources_and_complete_output(self):
        stale = self.app.outdir / "rust/ccf_app/removed.html"
        stale.parent.mkdir(parents=True)
        stale.touch()
        with (
            patch.dict(os.environ, {"CARGO_BUILD_TARGET": "unexpected-target"}),
            patch.object(rustdoc.subprocess, "run", side_effect=self.cargo_doc),
        ):
            rustdoc.build_rustdoc(self.app)
        self.assertFalse(stale.exists())
        for filename in (
            "ccf_app/index.html",
            "static.files/style.css",
            "search-index.js",
            "src/ccf_app/lib.rs.html",
        ):
            self.assertTrue((self.app.outdir / "rust" / filename).is_file())
        self.assertEqual(list(self.app.doctreedir.iterdir()), [])

    @patch.object(rustdoc.subprocess, "run")
    def test_old_version_without_sdk(self, run):
        self.manifest.unlink()
        rustdoc.build_rustdoc(self.app)
        run.assert_not_called()

    @patch.object(rustdoc.subprocess, "run")
    def test_explicit_local_skip(self, run):
        with patch.dict(os.environ, {"SKIP_RUSTDOC": "1"}):
            rustdoc.build_rustdoc(self.app)
        run.assert_not_called()

    @patch.object(rustdoc.subprocess, "run")
    def test_non_html_builder(self, run):
        self.app.builder.format = "latex"
        rustdoc.build_rustdoc(self.app)
        run.assert_not_called()

    def test_generation_failure_is_fatal(self):
        with patch.object(
            rustdoc.subprocess,
            "run",
            side_effect=subprocess.CalledProcessError(1, "cargo"),
        ):
            with self.assertRaises(subprocess.CalledProcessError):
                rustdoc.build_rustdoc(self.app)

    def test_encoded_flags_still_deny_warnings(self):
        for flags in ("", "--cfg\x1fdocs"):
            with self.subTest(flags=flags):
                with (
                    patch.dict(os.environ, {"CARGO_ENCODED_RUSTDOCFLAGS": flags}),
                    patch.object(
                        rustdoc.subprocess, "run", side_effect=self.cargo_doc
                    ) as run,
                ):
                    rustdoc.build_rustdoc(self.app)
                expected = flags + "\x1f-Dwarnings" if flags else "-Dwarnings"
                self.assertEqual(
                    run.call_args.kwargs["env"]["CARGO_ENCODED_RUSTDOCFLAGS"],
                    expected,
                )

    @patch.object(rustdoc.subprocess, "run")
    def test_missing_generated_output_is_fatal(self, run):
        with self.assertRaisesRegex(SphinxError, "did not generate"):
            rustdoc.build_rustdoc(self.app)

    def test_roles_link_within_the_current_version(self):
        page = self.app.outdir / "rust/ccf_app/struct.Registry.html"
        page.parent.mkdir(parents=True)
        page.write_text('<h2 id="method.read_only">Read only</h2>', encoding="utf-8")
        for docname, prefix in (
            ("index", ""),
            ("build_apps/rust_api", "../"),
            ("build_apps/kv/index", "../../"),
        ):
            with self.subTest(docname=docname):
                env = SimpleNamespace(app=self.app, docname=docname)
                inliner = SimpleNamespace(
                    document=SimpleNamespace(settings=SimpleNamespace(env=env))
                )
                nodes, messages = rustdoc.rustdoc_role(
                    "rustdoc",
                    "",
                    "Registry::read_only <struct.Registry.html#method.read_only>",
                    1,
                    inliner,
                )
                self.assertEqual(messages, [])
                self.assertEqual(nodes[0].astext(), "Registry::read_only")
                self.assertEqual(
                    nodes[0]["refuri"],
                    prefix + "rust/ccf_app/struct.Registry.html#method.read_only",
                )

    def test_missing_page_and_anchor_are_fatal(self):
        with self.assertRaisesRegex(SphinxError, "page does not exist"):
            rustdoc.check_target(self.app.outdir, "struct.Removed.html")
        page = self.app.outdir / "rust/ccf_app/index.html"
        page.parent.mkdir(parents=True)
        page.write_text("<h1>SDK</h1>", encoding="utf-8")
        with self.assertRaisesRegex(SphinxError, "anchor does not exist"):
            rustdoc.check_target(self.app.outdir, "index.html#missing")

    def test_cached_doctrees_are_checked(self):
        tree = nodes.section(
            "", nodes.reference("", "Removed", rustdoc_target="struct.Removed.html")
        )
        self.app.env = SimpleNamespace(
            found_docs={"build_apps/rust_api"},
            get_doctree=lambda docname: tree,
        )
        with self.assertRaisesRegex(SphinxError, "page does not exist"):
            rustdoc.check_links(self.app, None)
        with patch.dict(os.environ, {"SKIP_RUSTDOC": "1"}):
            rustdoc.check_links(self.app, None)


if __name__ == "__main__":
    unittest.main()
