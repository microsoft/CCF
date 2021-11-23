# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import argparse
import json
import os
import sys
import jinja2
from typing import Optional

from loguru import logger as LOG  # type: ignore


DEFAULT_BALLOT_OUTPUT = "{proposal_name}_vote_for.json"


def complete_ballot_output_path(
    proposal_name: str, ballot_output_path: Optional[str] = None, common_dir: str = "."
):
    if ballot_output_path is None:
        ballot_output_path = DEFAULT_BALLOT_OUTPUT.format(proposal_name=proposal_name)

    if not ballot_output_path.endswith(".json"):
        ballot_output_path += ".json"

    ballot_output_path = os.path.normpath(os.path.join(common_dir, ballot_output_path))

    return ballot_output_path


def build_ballot_raw(proposal: dict):
    LOG.trace(f"Generating ballot")

    template_loader = jinja2.PackageLoader("ccf", "templates")
    template_env = jinja2.Environment(
        loader=template_loader, undefined=jinja2.StrictUndefined
    )

    ballot_template = template_env.get_template("ballots.json.jinja")
    ballot = ballot_template.render(proposal)

    LOG.trace(f"Generated ballot:\n{ballot}")

    return ballot


def build_ballot(proposal_path: str):
    LOG.trace(f"Reading proposal from: {proposal_path}")
    with open(proposal_path, "r") as f:
        proposal = json.load(f)

    return build_ballot_raw(proposal)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("proposal", type=str, help="Path to proposal JSON file")
    parser.add_argument(
        "-bo",
        "--ballot-output-file",
        type=str,
        help=f"Path where ballot JSON object (request body for POST /gov/proposals/{{proposal_id}}/ballots) will be written. Default is {DEFAULT_BALLOT_OUTPUT}",
    )
    parser.add_argument("-v", "--verbose", action="store_true")

    args = parser.parse_args()

    LOG.remove()
    LOG.add(
        sys.stdout,
        format="<level>[{time:YYYY-MM-DD HH:mm:ss.SSS}] {level} | {message}</level>",
        level="TRACE" if args.verbose else "INFO",
    )

    ballot = build_ballot(args.proposal)

    ballot_path = complete_ballot_output_path(
        args.proposal.replace("_proposal", "").replace(".json", ""),
        ballot_output_path=args.ballot_output_file,
    )
    LOG.success(f"Writing ballot to {ballot_path}")
    with open(ballot_path, "w", encoding="utf-8") as f:
        f.write(ballot)
