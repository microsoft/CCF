# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import argparse

"""
copies the css into the html file
"""

style_file = "coverage/style.css"
html_file = "coverage/index.html"


with open(html_file, "a") as html:
    with open(style_file) as style:
        html.write('<style type="text/css">')
        html.write(style.read())
        html.write("</style>")
