# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import glob
import shutil

"""
copies the css into the html files
"""

style_file = "coverage/style.css"
index_html = "coverage/index.html"

with open(index_html, "a") as index_file:
    index_file.write("<p>")
    index_file.write("<div class='centered'>")
    index_file.write(
        "<table><tr><td class='column-entry-bold'>Coverage Per Unit Test</td></tr>"
    )

    for cov_dir in glob.glob("coverage/cov_*", recursive=False):
        index_file.write(
            "<tr class='light-row'><td><pre><a href='"
            + cov_dir
            + "/index.html'>"
            + cov_dir
            + "</a></pre></td></tr>"
        )
    index_file.write("</table>")
    index_file.write("</div>")
    index_file.write("</p>")

with open(style_file) as style:
    css = style.read()
    for filename in glob.iglob("coverage/**/*.html", recursive=True):
        with open(filename, "a") as html:
            html.write('<style type="text/css">')
            html.write(css)
            html.write("</style>")
