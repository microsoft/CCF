# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""Publish the application SDK's rustdoc alongside each Sphinx HTML version."""

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
from html.parser import HTMLParser

from docutils import nodes
from sphinx.errors import SphinxError
from sphinx.util.nodes import split_explicit_title
from sphinx.util.osutil import relative_uri


def build_rustdoc(app):
    if app.builder.format != "html" or os.environ.get("SKIP_RUSTDOC"):
        return

    # Multiversion sources need not be in the checkout containing conf.py.
    manifest = Path(app.srcdir).resolve().parent / "src/rust/ccf-app/Cargo.toml"
    if not manifest.is_file():
        return

    env = os.environ.copy()
    env.pop("CARGO_BUILD_TARGET", None)
    env["RUSTDOCFLAGS"] = env.get("RUSTDOCFLAGS", "") + " -D warnings"
    if "CARGO_ENCODED_RUSTDOCFLAGS" in env:
        env["CARGO_ENCODED_RUSTDOCFLAGS"] = "\x1f".join(
            filter(None, [env["CARGO_ENCODED_RUSTDOCFLAGS"], "-Dwarnings"])
        )

    Path(app.doctreedir).mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="rustdoc-", dir=app.doctreedir) as target:
        subprocess.run(
            [
                "cargo",
                "doc",
                "--locked",
                "--lib",
                "--no-deps",
                "--manifest-path",
                str(manifest),
                "--target-dir",
                target,
            ],
            cwd=manifest.parent,
            env=env,
            check=True,
        )
        generated = Path(target) / "doc"
        if not (generated / "ccf_app/index.html").is_file():
            raise SphinxError("Cargo did not generate the ccf_app API reference")
        destination = Path(app.outdir) / "rust"
        if destination.exists():
            shutil.rmtree(destination)
        shutil.copytree(generated, destination)


class _Anchors(HTMLParser):
    def __init__(self):
        super().__init__()
        self.ids = set()

    def handle_starttag(self, tag, attrs):
        self.ids.update(value for name, value in attrs if name == "id")


def check_target(outdir, target):
    page, _, anchor = target.partition("#")
    path = Path(outdir) / "rust/ccf_app" / page
    if not path.is_file():
        raise SphinxError(f"Rust API page does not exist: {target}")
    if anchor:
        parser = _Anchors()
        parser.feed(path.read_text(encoding="utf-8"))
        if anchor not in parser.ids:
            raise SphinxError(f"Rust API anchor does not exist: {target}")


def rustdoc_role(name, rawtext, text, lineno, inliner, options=None, content=None):
    _, label, target = split_explicit_title(text)
    env = inliner.document.settings.env
    app = env.app
    page, separator, anchor = target.partition("#")
    refuri = (
        relative_uri(app.builder.get_target_uri(env.docname), f"rust/ccf_app/{page}")
        + separator
        + anchor
    )
    return [
        nodes.reference(
            rawtext,
            "",
            nodes.literal(label, label),
            refuri=refuri,
            rustdoc_target=target,
        )
    ], []


def check_links(app, exception):
    if (
        exception is not None
        or app.builder.format != "html"
        or os.environ.get("SKIP_RUSTDOC")
    ):
        return
    # Include cached doctrees so incremental builds also catch removed APIs.
    for docname in app.env.found_docs:
        for node in app.env.get_doctree(docname).findall(nodes.reference):
            if "rustdoc_target" in node:
                check_target(app.outdir, node["rustdoc_target"])


def setup(app):
    app.add_role("rustdoc", rustdoc_role)
    app.connect("builder-inited", build_rustdoc)
    app.connect("build-finished", check_links)
    return {"parallel_read_safe": True, "parallel_write_safe": True}
