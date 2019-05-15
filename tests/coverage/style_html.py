# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import argparse
import glob

"""
copies the css into the html files
"""

style_file = "coverage/style.css"

with open(style_file) as style:
    css = style.read()
    for filename in glob.iglob("coverage/**/*.html", recursive=True):
        with open(filename, "a") as html:
            html.write('<style type="text/css">')
            html.write(css)
            html.write("</style>")
