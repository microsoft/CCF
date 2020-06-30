# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import argparse
import json

from loguru import logger as LOG


def dump_proposal(output_path, proposal, dump_args):
    LOG.debug(f"Writing proposal to {output_path}")
    with open(output_path, "w") as f:
        json.dump(proposal, f, **dump_args)


def dump_vote(output_path, vote, dump_args):
    LOG.debug(f"Writing vote to {output_path}")
    with open(output_path, "w") as f:
        json.dump(vote, f, **dump_args)


def file_to_byte_array(f):
    return [ord(c) for c in f.read()]


def array_as_lua_literal(a):
    return str(a).replace("[", "{").replace("]", "}")


PROPOSAL_ID_PLACEHOLDER = "<replace with desired proposal_id>"


def script_to_vote_object(script):
    return {"ballot": {"text": script}, "id": PROPOSAL_ID_PLACEHOLDER}


def new_member_proposal(member_cert_file, member_keyshare_encryptor_file):
    LOG.trace("Generating new member proposal")

    # Convert certs to byte arrays
    member_cert = file_to_byte_array(member_cert_file)
    member_keyshare_encryptor = file_to_byte_array(member_keyshare_encryptor_file)

    # Script which proposes adding a new member
    proposal_script_text = """
    tables, member_info = ...
    return Calls:call("new_member", member_info)
    """

    # Proposal object (request body for /gov/propose) containing this member's info as parameter
    proposal = {
        "parameter": {"cert": member_cert, "keyshare": member_keyshare_encryptor},
        "script": {"text": proposal_script_text},
    }

    # Sample vote script which checks the expected member is being added, and no other actions are being taken
    verifying_vote_script = f"""
    tables, calls = ...
    if #calls ~= 1 then
      return false
    end

    call = calls[1]
    if call.func ~= "new_member" then
      return false
    end

    function equal_arrays(a, b)
      if #a ~= #b then
        return false
      else
        for k, v in ipairs(a) do
          if b[k] ~= v then
            return false
          end
        end
        return true
      end
    end

    expected_cert = {array_as_lua_literal(member_cert)}
    if not equal_arrays(call.args.cert, expected_cert) then
      return false
    end

    expected_keyshare = {array_as_lua_literal(member_keyshare_encryptor)}
    if not equal_arrays(call.args.keyshare, expected_keyshare) then
      return false
    end

    return true
    """

    # Vote object (request body for /gov/vote)
    verifying_vote = {
        "ballot": {"text": verifying_vote_script},
        "id": PROPOSAL_ID_PLACEHOLDER,
    }

    return proposal, verifying_vote


def new_user_proposal(usert_cert_file):
    LOG.trace("Generating new user proposal")

    user_cert = file_to_byte_array(usert_cert_file)

    proposal_script_text = """
    tables, user_cert = ...
    return Calls:call("new_user", user_cert)
    """

    proposal = {"parameter": user_cert, "script": {"text": proposal_script_text}}

    verifying_vote_script = f"""
    tables, calls = ...
    if #calls ~= 1 then
      return false
    end

    call = calls[1]
    if call.func ~= "new_member" then
      return false
    end

    if call.args ~= {user_cert} then
      return false
    end

    return true
    """

    verifying_vote = script_to_vote_object(verifying_vote_script)

    return proposal, verifying_vote


if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument("-po", "--proposal-output-file", type=str)
    parser.add_argument("-vo", "--vote-output-file", type=str)
    parser.add_argument("-pp", "--pretty-print", action="store_true")

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
        proposal, vote = new_member_proposal(
            member_cert_file=args.new_member_cert,
            member_keyshare_encryptor_file=args.new_member_keyshare_encryptor,
        )
    elif args.proposal_kind == "new_user":
        proposal, vote = new_user_proposal(usert_cert_file=args.new_user_cert)
    else:
        raise ValueError(f"Unsupported proposal '{args.proposal_kind}'")

    dump_args = {}
    if args.pretty_print:
        dump_args["indent"] = 2

    proposal_output_path = args.proposal_output_file or f"{args.proposal_kind}.json"
    dump_proposal(proposal_output_path, proposal, dump_args)

    vote_output_path = args.vote_output_file or f"vote_for_{args.proposal_kind}.json"
    dump_vote(vote_output_path, vote, dump_args)
