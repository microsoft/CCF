# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import os
import sys
import shutil
import subprocess
import pathlib

from docutils import nodes

# Import local documentation helpers.
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import generate_config_rst


# -- Project information -----------------------------------------------------

project = "CCF"
copyright = "Microsoft"
author = "Microsoft"

extensions = [
    "sphinx.ext.mathjax",
    "sphinx.ext.viewcode",
    "breathe",
    "sphinx_pele",
    "sphinx.ext.autosectionlabel",
    "sphinx_copybutton",
    "sphinx.ext.autodoc",
    "sphinxcontrib.openapi",
    "sphinx_design",
    "sphinx.ext.extlinks",
    "sphinx_inline_tabs",
    "rustdoc",
]

autosectionlabel_prefix_document = True

# The name of the Pygments (syntax highlighting) style to use.
pygments_style = "default"
pygments_dark_style = "zenburn"

# Ignore main index file that has clickable images, JS/Doxygen output, and
# github anchors https://github.com/sphinx-doc/sphinx/issues/9016).
linkcheck_exclude_documents = [r"^index$"]
linkcheck_ignore = [
    r"https://github.com/.*#",
    r"../js/ccf-app.*",
    r"../doxygen/index.html",
    r"../trace-viewer/index.html",
    # The rustdoc role checks generated pages and anchors during HTML builds.
    r"(?:\.\./)*rust/ccf_app/.*",
    r"https://www.w3.org/Protocols/rfc2616/.*",
]


# -- Options for HTML output -------------------------------------------------

# The theme to use for HTML and HTML Help pages.  See the documentation for
# a list of builtin themes.
#
html_theme = "furo"

# Theme options are theme-specific and customize the look and feel of a theme
# further.  For a list of options available for each theme, see the
# documentation.
#
html_theme_options = {
    "source_repository": "https://github.com/microsoft/CCF/",
    "source_branch": "main",
    "source_directory": "doc/",
    "footer_icons": [
        {
            "name": "GitHub",
            "url": "https://github.com/microsoft/CCF",
            "html": """
                <svg stroke="currentColor" fill="currentColor" stroke-width="0" viewBox="0 0 16 16">
                  <path fill-rule="evenodd" d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0 0 16 8c0-4.42-3.58-8-8-8z"></path>
                </svg>
            """,
            "class": "",
        }
    ],
    # Dimmed slate dark mode, lighter than Furo's default near-black, so that
    # diagrams with transparent backgrounds read well in both modes
    "dark_css_variables": {
        "color-background-primary": "#1e232b",
        "color-background-secondary": "#252b34",
        "color-background-hover": "#2c333dff",
        "color-background-hover--transparent": "#2c333d00",
        "color-background-border": "#39414c",
        "color-background-item": "#4a5360",
        "color-foreground-muted": "#8f949b",
        "color-admonition-background": "#232932",
        "color-card-background": "#232932",
    },
}

# Add any paths that contain custom static files (such as style sheets) here,
# relative to this directory. They are copied after the builtin static files,
# so a file named "default.css" will overwrite the builtin "default.css".
html_static_path = ["_static"]

html_css_files = [
    "css/custom.css",
]

html_js_files = ["https://kit.fontawesome.com/c75a35380d.js"]


# -- Extension configuration -------------------------------------------------

# -- Breathe configuration

# Setup the breathe extension
breathe_projects = {"CCF": "../doxygen/xml"}
breathe_default_project = "CCF"

# -- Warnings filter

suppress_warnings = [
    "autosectionlabel", # https://stackoverflow.com/a/77577337
]

extlinks = {"ccf_repo": ("https://github.com/microsoft/CCF/tree/main/%s", "%s")}

# Theme options

html_favicon = "_static/favicon.ico"

# Configuration for sphinxcontrib-httpdomain, without which the following error happens
# ERROR: HTTP status code must be an integer (e.g. `200`) or start with an integer (e.g. `200 OK`);
# <#text: 'default'> is invalid
http_strict_mode = False

# Python autodoc options
autodoc_default_options = {
    "member-order": "bysource",
}


def typedoc_role(
    name: str, rawtext: str, text: str, lineno, inliner, options={}, content=[]
):
    """
    Supported syntaxes:
    :typedoc-package:`ccf-app`
    :typedoc-module:`ccf-app/global`
    :typedoc-function:`ccf-app/crypto#wrapKey`
    :typedoc-interface:`ccf-app/endpoints/Body`
    :typedoc-class:`ccf-app/kv/TypedKvMap`
    :typedoc-classmethod:`ccf-app/kv/TypedKvMap#delete`
    :typedoc-interfacemethod:`ccf-app/endpoints/Body#json`
    :typedoc-interface:`Body <ccf-app/endpoints/Body>`
    """
    # check for custom label
    if "<" in text:
        label, text = text.split(" <")
        text = text[:-1]
    else:
        label = text

    # extract hash if any, has to be appended after .html later on
    text_without_hash, *hash_name = text.split("#")
    url_hash = f"#{hash_name[0].lower()}" if hash_name else ""

    # translate role kind into typedoc subfolder
    # and add '()' for functions/methods
    kind_name = name.replace("typedoc-", "")
    is_kind_package = False
    if kind_name == "package":
        is_kind_package = True
    elif kind_name in ["module", "interface"]:
        kind_name += "s"
    elif kind_name == "class":
        kind_name += "es"
    elif kind_name == "function":
        kind_name = "modules"
        label += "()"
    elif kind_name == "classmethod":
        kind_name = "classes"
        label += "()"
    elif kind_name == "interfacemethod":
        kind_name = "interfaces"
        label += "()"
    else:
        raise ValueError(f"unknown typedoc kind: {kind_name}")

    # build typedoc url relative to doc root
    pkg_name, *element_path = text_without_hash.split("/")
    typedoc_path = f"js/{pkg_name}"
    if not is_kind_package:
        element_path = ".".join(element_path)
        typedoc_path += f"/{kind_name}/{element_path}.html{url_hash}"

    # Sphinx docnames are relative to the source root.
    docname = inliner.document.settings.env.docname
    levels = docname.count("/")
    refuri = "../" * levels + typedoc_path

    # build docutils node
    text_node = nodes.literal(label, label, classes=["xref"])
    ref_node = nodes.reference("", "", refuri=refuri)
    ref_node += text_node

    return [ref_node], []


def build_typedoc(app):
    if app.builder.format != "html":
        return

    js_pkg_dir = pathlib.Path(app.srcdir).parent / "js" / "ccf-app"
    js_docs_dir = pathlib.Path(app.outdir) / "js" / "ccf-app"
    subprocess.run(
        ["npm", "install", "--no-package-lock", "--no-audit", "--no-fund"],
        cwd=js_pkg_dir,
        check=True,
    )
    subprocess.run(
        ["npm", "run", "docs", "--", "--out", str(js_docs_dir)],
        cwd=js_pkg_dir,
        check=True,
    )


def setup(app):
    app.connect("builder-inited", build_typedoc)
    for kind in [
        "package",
        "module",
        "interface",
        "class",
        "function",
        "interfacemethod",
        "classmethod",
    ]:
        app.add_role(f"typedoc-{kind}", typedoc_role)

    doc_dir = pathlib.Path(app.srcdir)
    root_dir = doc_dir.parent
    out_dir = pathlib.Path(app.outdir)

    # doxygen
    breathe_projects["CCF"] = str(doc_dir / breathe_projects["CCF"])
    if not os.environ.get("SKIP_DOXYGEN"):
        subprocess.run(["doxygen"], cwd=root_dir, check=True)
        doxygen_html_src = root_dir / "doxygen/html"
        if doxygen_html_src.exists() and doxygen_html_src.is_dir():
            doxygen_html_dest = str(out_dir / "doxygen")
            subprocess.run(
                ["cp", "-r", str(doxygen_html_src), doxygen_html_dest], check=True
            )

    if not os.environ.get("SKIP_TRACE_VIEWER"):
        package_dir = root_dir / "lean" / "disaster-recovery"
        replayer_dir = package_dir / "replayer"
        subprocess.run(
            ["lake", "build", "disaster-recovery-replay"], cwd=package_dir, check=True
        )
        subprocess.run(
            [sys.executable, "viewer/build.py"], cwd=replayer_dir, check=True
        )
        viewer_dest = out_dir / "trace-viewer"
        shutil.rmtree(viewer_dest, ignore_errors=True)
        shutil.copytree(
            replayer_dir / "viewer",
            viewer_dest,
            ignore=shutil.ignore_patterns("*.py", ".gitignore"),
        )

    # configuration generator
    input_file_path = doc_dir / "host_config_schema/host_config.json"
    output_file_path = doc_dir / "operations/generated_config.rst"

    generate_config_rst.generate_configuration_docs(input_file_path, output_file_path)
