# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import docutils.nodes
import docutils.parsers.rst
import docutils.utils
import docutils.frontend
from docutils.parsers.rst.directives import register_directive
from docutils.parsers.rst import Directive


class StubDirective(Directive):
    has_content = True

    def run(self):
        return []


class TablesVisitor(docutils.nodes.NodeVisitor):
    prefix = None
    tables = []

    def visit_section(self, node):
        (name,) = node.attributes["names"]
        if name.startswith("public:"):
            self.prefix = name
        else:
            if self.prefix:
                self.tables.append(f"{self.prefix}{name}")

    def unknown_visit(self, node) -> None:
        pass


def parse(text):
    for t in ("enum", "struct"):
        register_directive(f"doxygen{t}", StubDirective)
    parser = docutils.parsers.rst.Parser()
    components = (docutils.parsers.rst.Parser,)
    settings = docutils.frontend.OptionParser(
        components=components
    ).get_default_values()
    document = docutils.utils.new_document("<rst-doc>", settings=settings)
    parser.parse(text, document)
    return document


def extract_table_names(doc):
    v = TablesVisitor(doc)
    doc.walk(v)
    return v.tables
