# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
# -*- coding: utf-8 -*-
#
# Configuration file for the Sphinx documentation builder.
#
# This file does only contain a selection of the most common options. For a
# full list see the documentation:
# http://www.sphinx-doc.org/en/master/config

# -- Path setup --------------------------------------------------------------

# If extensions (or modules to document with autodoc) are in another directory,
# add these directories to sys.path here. If the directory is relative to the
# documentation root, use os.path.abspath to make it absolute, like shown here.
#
import os
import sys
import subprocess
import pathlib
import re

from docutils import nodes

# To import generate_config_rst
sys.path.insert(0, os.path.abspath("."))

import generate_config_rst


# -- Project information -----------------------------------------------------

project = "CCF"
copyright = "2018, Microsoft Research"  # pylint: disable=redefined-builtin
author = "Microsoft Research"

# The short X.Y version
version = ""
# The full version, including alpha/beta/rc tags
release = ""


# -- General configuration ---------------------------------------------------

# If your documentation needs a minimal Sphinx version, state it here.
#
# needs_sphinx = '1.0'

# Add any Sphinx extension module names here, as strings. They can be
# extensions coming with Sphinx (named 'sphinx.ext.*') or your custom
# ones.
extensions = [
    "sphinx.ext.todo",
    "sphinx.ext.mathjax",
    "sphinx.ext.ifconfig",
    "sphinx.ext.viewcode",
    "breathe",
    "sphinxcontrib.mermaid",
    "sphinx.ext.autosectionlabel",
    "sphinx.ext.githubpages",
    "sphinx_multiversion",
    "sphinx_copybutton",
    "sphinx.ext.autodoc",
    "sphinxcontrib.openapi",
    "sphinx_panels",
    "sphinx.ext.extlinks",
]

autosectionlabel_prefix_document = True

# Add any paths that contain templates here, relative to this directory.
templates_path = ["_templates"]

# The suffix(es) of source filenames.
# You can specify multiple suffix as a list of string:
#
# source_suffix = ['.rst', '.md']
source_suffix = ".rst"

# The master toctree document.
master_doc = "index"

# The language for content autogenerated by Sphinx. Refer to documentation
# for a list of supported languages.
#
# This is also used if you do content translation via gettext catalogs.
# Usually you set "language" from the command line for these cases.
language = "en"

# List of patterns, relative to source directory, that match files and
# directories to ignore when looking for source files.
# This pattern also affects html_static_path and html_extra_path .
exclude_patterns = []

# The name of the Pygments (syntax highlighting) style to use.
pygments_style = "zenburn"


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
    "announcement": 'CCF 2.0 release candidate <a href="https://github.com/microsoft/CCF/releases/tag/ccf-2.0.0-rc0"> is now available </a>'
}

# Add any paths that contain custom static files (such as style sheets) here,
# relative to this directory. They are copied after the builtin static files,
# so a file named "default.css" will overwrite the builtin "default.css".
html_static_path = ["_static"]

# Custom sidebar templates, must be a dictionary that maps document names
# to template names.
#
# The default sidebars (for documents that don't match any pattern) are
# defined by theme itself.  Builtin themes are using these templates by
# default: ``['localtoc.html', 'relations.html', 'sourcelink.html',
# 'searchbox.html']``.
#
html_sidebars = {}

html_css_files = [
    "css/custom.css",
]

html_js_files = ["https://kit.fontawesome.com/c75a35380d.js"]


# -- Options for HTMLHelp output ---------------------------------------------

# Output file base name for HTML help builder.
htmlhelp_basename = "CCFdoc"


# -- Options for LaTeX output ------------------------------------------------

latex_elements = {
    # The paper size ('letterpaper' or 'a4paper').
    #
    # 'papersize': 'letterpaper',
    # The font size ('10pt', '11pt' or '12pt').
    #
    # 'pointsize': '10pt',
    # Additional stuff for the LaTeX preamble.
    #
    # 'preamble': '',
    # Latex figure (float) alignment
    #
    # 'figure_align': 'htbp',
}

# Grouping the document tree into LaTeX files. List of tuples
# (source start file, target name, title,
#  author, documentclass [howto, manual, or own class]).
latex_documents = [
    (master_doc, "CCF.tex", "CCF Documentation", "Microsoft Research", "manual")
]


# -- Options for manual page output ------------------------------------------

# One entry per manual page. List of tuples
# (source start file, name, description, authors, manual section).
man_pages = [(master_doc, "ccf", "CCF Documentation", [author], 1)]


# -- Options for Texinfo output ----------------------------------------------

# Grouping the document tree into Texinfo files. List of tuples
# (source start file, target name, title, author,
#  dir menu entry, description, category)
texinfo_documents = [
    (
        master_doc,
        "CCF",
        "CCF Documentation",
        author,
        "CCF",
        "One line description of project.",
        "Miscellaneous",
    )
]


# -- Extension configuration -------------------------------------------------

# -- Options for todo extension ----------------------------------------------

# If true, `todo` and `todoList` produce output, else they produce nothing.
todo_include_todos = True

# -- Breathe configuration

# Setup the breathe extension
breathe_projects = {"CCF": "../doxygen/xml"}
breathe_default_project = "CCF"

# Set up multiversion extension

whitelist_1_x = r"1\.\d+\.1\d+"  # from ccf-1.0.1x
whitelist_2_x = r"2([.\d+]+)(-rc.*|)"  # all 2.x but no -dev
whitelist_others = r"([3-9]|\d{2,}).*"  # all others
smv_tag_whitelist = rf"^ccf-({whitelist_1_x}|{whitelist_2_x}|{whitelist_others})$"

# Test versions regex match
assert not re.match(smv_tag_whitelist, "ccf-1.0.9")
assert re.match(smv_tag_whitelist, "ccf-1.0.10")
assert re.match(smv_tag_whitelist, "ccf-2.0.0-rc0")
assert not re.match(smv_tag_whitelist, "ccf-2.0.0-dev0")
assert re.match(smv_tag_whitelist, "ccf-2.0.0")
assert re.match(smv_tag_whitelist, "ccf-3.0.0")
assert re.match(smv_tag_whitelist, "ccf-3.0.0-dev0")
assert re.match(smv_tag_whitelist, "ccf-3.0.0-rc0")

smv_branch_whitelist = r"^main$"
smv_remote_whitelist = None
smv_outputdir_format = "{ref.name}"

# Intercept command line arguments passed by sphinx-multiversion to retrieve doc version.
# This is a little hacky with sphinx-multiversion 0.2.4 and the `SPHINX_MULTIVERSION_NAME`
# envvar should be used for further versions (release pending).
docs_version = "main"
for arg in sys.argv:
    if "smv_current_version=" in arg:
        docs_version = arg.split("=")[1]


# :ccf_repo: directive can be used to create a versioned link to GitHub repo
extlinks = {
    "ccf_repo": (
        f"https://github.com/microsoft/CCF/tree/{docs_version}/%s",
        "%s",
    )
}

# Theme options

html_logo = "_static/ccf.svg"
html_favicon = "_static/favicon.ico"

html_context = {
    "github_user": "Microsoft",
    "github_repo": "CCF",
    "github_version": "main",
    "doc_path": "doc/",
}

# Python autodoc options
autodoc_default_options = {
    "member-order": "bysource",
}

# sphinxcontrib.spelling options
spelling_show_suggestions = True
spelling_lang = "en_UK"
tokenizer_lang = "en_UK"
spelling_word_list_filename = ["spelling_wordlist.txt"]

# sphinxcontrib-mermaid options
mermaid_init_js = """mermaid.initialize({startOnLoad:true});

// Remove height from all mermaid diagrams
window.addEventListener(
  'load',
  function() {
    let nodes = document.querySelectorAll('.mermaid');
    for (let i = 0; i < nodes.length; i++) {
      const element = nodes[i];
      const svg = element.firstChild;
      svg.removeAttribute('height');
    }
  },
  false
);"""


def typedoc_role(
    name: str, rawtext: str, text: str, lineno, inliner, options={}, content=[]
):
    """
    Supported syntaxes:
    :typedoc:package:`ccf-app`
    :typedoc:module:`ccf-app/global`
    :typedoc:function:`ccf-app/crypto#wrapKey`
    :typedoc:interface:`ccf-app/endpoints/Body`
    :typedoc:class:`ccf-app/kv/TypedKvMap`
    :typedoc:classmethod:`ccf-app/kv/TypedKvMap#delete`
    :typedoc:interfacemethod:`ccf-app/endpoints/Body#json`
    :typedoc:interface:`Body <ccf-app/endpoints/Body>`
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
    kind_name = name.replace("typedoc:", "")
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

    # construct final url relative to current page
    source = inliner.document.attributes["source"]
    rel_source = source.split("/doc/", 1)[1]
    levels = rel_source.count("/")
    refuri = "../" * levels + typedoc_path

    # build docutils node
    text_node = nodes.literal(label, label, classes=["xref"])
    ref_node = nodes.reference("", "", refuri=refuri)
    ref_node += text_node

    return [ref_node], []


def config_inited(app, config):
    # anything that needs to access app.config goes here

    doc_dir = pathlib.Path(app.srcdir)
    outdir = pathlib.Path(app.outdir)

    js_pkg_dir = doc_dir / ".." / "js" / "ccf-app"
    js_docs_dir = outdir / "js" / "ccf-app"
    if js_pkg_dir.exists():
        # make versions.json from sphinx-multiversion available
        if app.config.smv_metadata_path:
            os.environ["SMV_METADATA_PATH"] = app.config.smv_metadata_path
            os.environ["SMV_CURRENT_VERSION"] = app.config.smv_current_version
        subprocess.run(
            ["sed", "-i", "s/\^4.2.3/4.2.4/g", "package.json"],
            cwd=js_pkg_dir,
            check=True,
        )
        subprocess.run(
            ["sed", "-i", 's/"\^14\.14\.35"/"14\.17\.27"/g', "package.json"],
            cwd=js_pkg_dir,
            check=True,
        )
        subprocess.run(
            ["npm", "install", "--save-exact", "colors@1.4.0"],
            cwd=js_pkg_dir,
            check=True,
        )
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
        # allow to link to typedoc pages
        for kind in [
            "package",
            "module",
            "interface",
            "class",
            "function",
            "interfacemethod",
            "classmethod",
        ]:
            app.add_role(f"typedoc:{kind}", typedoc_role)


def setup(app):
    if not os.environ.get("SKIP_JS"):
        app.connect("config-inited", config_inited)

    doc_dir = pathlib.Path(app.srcdir)  # CCF/doc/
    root_dir = os.path.abspath(doc_dir / "..")  # CCF/

    # import ccf python package to generate docs for this version
    python_path = os.path.abspath(doc_dir / "../python")
    sys.path.insert(0, python_path)

    # doxygen
    breathe_projects["CCF"] = str(doc_dir / breathe_projects["CCF"])
    if not os.environ.get("SKIP_DOXYGEN"):
        subprocess.run(["doxygen"], cwd=root_dir, check=True)

    # configuration generator
    input_file_path = doc_dir / "host_config_schema/cchost_config.json"
    output_file_path = doc_dir / "operations/generated_config.rst"

    if os.path.exists(input_file_path):
        generate_config_rst.generate_configuration_docs(
            input_file_path, output_file_path
        )
