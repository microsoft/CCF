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

sys.path.insert(0, os.path.abspath("../python"))


# -- Project information -----------------------------------------------------

project = u"CCF"
copyright = u"2018, Microsoft Research"  # pylint: disable=redefined-builtin
author = u"Microsoft Research"

# The short X.Y version
version = u""
# The full version, including alpha/beta/rc tags
release = u""


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
    "sphinxcontrib.spelling",
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
language = None

# List of patterns, relative to source directory, that match files and
# directories to ignore when looking for source files.
# This pattern also affects html_static_path and html_extra_path .
exclude_patterns = []

# The name of the Pygments (syntax highlighting) style to use.
pygments_style = "solarizeddark"


# -- Options for HTML output -------------------------------------------------

# The theme to use for HTML and HTML Help pages.  See the documentation for
# a list of builtin themes.
#
html_theme = "pydata_sphinx_theme"

# Theme options are theme-specific and customize the look and feel of a theme
# further.  For a list of options available for each theme, see the
# documentation.
#
# html_theme_options = {}

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
html_sidebars = {
    "**": ["sidebar-search-bs.html", "sidebar-nav-bs.html"],
}


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
    (master_doc, "CCF.tex", u"CCF Documentation", u"Microsoft Research", "manual")
]


# -- Options for manual page output ------------------------------------------

# One entry per manual page. List of tuples
# (source start file, name, description, authors, manual section).
man_pages = [(master_doc, "ccf", u"CCF Documentation", [author], 1)]


# -- Options for Texinfo output ----------------------------------------------

# Grouping the document tree into Texinfo files. List of tuples
# (source start file, target name, title, author,
#  dir menu entry, description, category)
texinfo_documents = [
    (
        master_doc,
        "CCF",
        u"CCF Documentation",
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

smv_tag_whitelist = r"^ccf-.*$"
smv_branch_whitelist = r"^master$"
smv_remote_whitelist = None
smv_outputdir_format = "{ref.name}"

# PyData theme options

html_logo = "_static/ccf.svg"
html_favicon = "_static/favicon.ico"

html_theme_options = {
    "github_url": "https://github.com/Microsoft/CCF",
    "use_edit_page_button": True,
}

html_context = {
    "github_user": "Microsoft",
    "github_repo": "CCF",
    "github_version": "master",
    "doc_path": "doc/",
}

# Python autodoc options
autodoc_default_options = {
    "member-order": "bysource",
}

# sphinxcontrib.spelling options
spelling_show_suggestions = True
spelling_lang='en_UK'
tokenizer_lang='en_UK'
spelling_word_list_filename=["spelling_wordlist.txt"]


def setup(self):
    import subprocess
    import pathlib

    srcdir = pathlib.Path(self.srcdir)

    breathe_projects["CCF"] = str(srcdir / breathe_projects["CCF"])
    subprocess.run(["doxygen"], cwd=srcdir / "..", check=True)
