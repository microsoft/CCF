# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import argparse
import json

from loguru import logger as LOG


def file_to_byte_array(f):
    return [ord(c) for c in f.read()]


def dump_proposal(f, proposal, dump_args):
    LOG.debug(f"Writing proposal to {f.name}")
    json.dump(proposal, f, **dump_args)


def new_member_proposal(member_cert_file, member_keyshare_encryptor_file):
    LOG.trace("Generating new member proposal")
    proposal_script_text = """
    tables, member_info = ...
    return Calls:call("new_member", member_info)
    """

    # Convert certs to byte array
    member_cert = file_to_byte_array(member_cert_file)
    member_keyshare_encryptor = file_to_byte_array(member_keyshare_encryptor_file)

    return {
        "parameter": {"cert": member_cert, "keyshare": member_keyshare_encryptor},
        "script": {"text": proposal_script_text},
    }


def new_user_proposal(usert_cert_file):
    LOG.trace("Generating new member proposal")
    proposal_script_text = """
    tables, user_cert = ...
    return Calls:call("new_user", user_cert)
    """

    user_cert = file_to_byte_array(usert_cert_file)
    return {"parameter": user_cert, "script": {"text": proposal_script_text}}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "-o", "--output-file", type=argparse.FileType("w"), default="proposal.json"
    )
    parser.add_argument("-p", "--pretty-print", action="store_true")

    subparsers = parser.add_subparsers(
        title="Possible proposals", dest="proposal_kind", required=True
    )

    new_member = subparsers.add_parser("new_member")
    new_member.add_argument(
        "-c", "--new-member-cert", type=argparse.FileType("r"), required=True
    )
    new_member.add_argument(
        "-ks",
        "--new-member-keyshare-encryptor",
        type=argparse.FileType("r"),
        required=True,
    )

    new_user = subparsers.add_parser("new_user")
    new_user.add_argument(
        "-c", "--new-user-cert", type=argparse.FileType("r"), required=True
    )

    args = parser.parse_args()

    if args.proposal_kind == "new_member":
        proposal = new_member_proposal(
            member_cert_file=args.new_member_cert,
            member_keyshare_encryptor_file=args.new_member_keyshare_encryptor,
        )
    elif args.proposal_kind == "new_user":
        proposal = new_user_proposal(usert_cert_file=args.new_user_cert)
    else:
        raise ValueError(f"Unsupported proposal '{args.proposal_kind}'")

    dump_args = {}
    if args.pretty_print:
        dump_args["indent"] = 2
    dump_proposal(args.output_file, proposal, dump_args)
