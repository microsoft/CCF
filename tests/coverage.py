# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import xml.etree.ElementTree as et
import json
import xml.dom.minidom as minidom


def pretty_print(tree_root):
    tree_string = et.tostring(tree_root, "utf-8")
    final_string = tree_string
    reparsed = minidom.parseString(final_string)
    return reparsed.toprettyxml(indent="\t")


with open("coverage.json", "r") as file:
    data = json.load(file)["data"][0]

    line_rate = str(data["totals"]["lines"]["percent"] / 100.0)
    lines_covered = str(data["totals"]["lines"]["covered"])
    lines_valid = str(data["totals"]["lines"]["count"])
    branch_rate = str(data["totals"]["functions"]["percent"] / 100.0)
    branch_covered = str(data["totals"]["functions"]["covered"])
    branch_valid = str(data["totals"]["functions"]["count"])
    coverage = et.Element(
        "coverage",
        attrib={
            "line-rate": line_rate,
            "lines-covered": lines_covered,
            "lines-valid": lines_valid,
            "branches-covered": branch_covered,
            "branches-valid": branch_valid,
            "branch-rate": branch_rate,
            "version": "1.0",
            "timestamp": "0000001",
        },
    )
    packages = et.SubElement(coverage, "packages")
    package = et.SubElement(packages, "package")
    classes = et.SubElement(package, "classes")

    files = data["files"]
    for file in files:
        filename = file["filename"]
        line_rate = str(file["summary"]["lines"]["percent"] / 100.0)
        lines_covered = str(file["summary"]["lines"]["covered"])
        lines_valid = str(file["summary"]["lines"]["count"])
        branch_rate = str(file["summary"]["functions"]["percent"] / 100.0)
        branch_covered = str(file["summary"]["functions"]["covered"])
        branch_valid = str(file["summary"]["functions"]["count"])
        et.SubElement(
            classes,
            "class",
            name=filename,
            attrib={
                "filename": filename,
                "line-rate": line_rate,
                "lines-covered": lines_covered,
                "lines-valid": lines_valid,
                "branch-rate": branch_rate,
                "branches-covered": branch_covered,
                "branches-valid": branch_valid,
            },
        )

    tree = pretty_print(coverage)
    with open("coverage.xml", "w") as xml_file:
        xml_file.write(tree)
