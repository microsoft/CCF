# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import argparse
import json
import os
import sys
import jinja2
from typing import Optional


def build_ballot_raw(proposal: dict):
    template_loader = jinja2.PackageLoader("ccf", "templates")
    template_env = jinja2.Environment(
        loader=template_loader, undefined=jinja2.StrictUndefined
    )

    ballot_template = template_env.get_template("ballots.json.jinja")
    ballot = ballot_template.render(proposal)

    return ballot


def build_ballot(proposal_path: str):
    with open(proposal_path, "r") as f:
        proposal = json.load(f)

    return build_ballot_raw(proposal)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("proposal", type=str, help="Path to proposal JSON file")
    args = parser.parse_args()
    ballot = build_ballot(args.proposal)
    print(ballot)
