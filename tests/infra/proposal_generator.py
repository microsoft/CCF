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


def file_to_byte_array(path):
    with open(path, "r") as f:
        return [ord(c) for c in f.read()]


def list_as_lua_literal(l):
    return str(l).replace("[", "{").replace("]", "}")


TRIVIAL_YES_BALLOT = {"text": "return true"}
TRIVIAL_NO_BALLOT = {"text": "return false"}

LUA_FUNCTION_EQUAL_ARRAYS = """
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
"""


PROPOSAL_ID_PLACEHOLDER = "<replace with desired proposal_id>"


def script_to_vote_object(script):
    return {"ballot": {"text": script}, "id": PROPOSAL_ID_PLACEHOLDER}


def add_arg_checks(lines, arg, arg_name="args"):
    lines.append(f"if {arg_name} == nil then return false")
    if isinstance(arg, list):
        expected_name = arg_name.replace(".", "_")
        lines.append(f"{expected_name} = {list_as_lua_literal(arg)}")
        lines.append(
            f"if not equal_arrays({arg_name}, {expected_name}) then return false end"
        )
    elif isinstance(arg, dict):
        for k, v in arg.items():
            add_arg_checks(lines, v, arg_name=f"{arg_name}.{k}")
    else:
        lines.append(f"if not {arg_name} == {arg} then return false end")


def build_proposal(proposed_call, args=None):
    LOG.warning(f"Generating {proposed_call} proposal")

    proposal_script_lines = []
    if args is None:
        proposal_script_lines.append(f'return Calls:call("{proposed_call}")')
    else:
        proposal_script_lines.append("tables, args = ...")
        proposal_script_lines.append(f'return Calls:call("{proposed_call}", args)')

    proposal_script_text = "; ".join(proposal_script_lines)
    proposal = {
        "script": {"text": proposal_script_text},
    }
    if args is not None:
        proposal["parameter"] = args

    vote_lines = [
        "tables, calls = ...",
        "if not #calls == 1 then return false end",
        "call = calls[1]",
        f'if not call.func == "{proposed_call}" then return false end',
        LUA_FUNCTION_EQUAL_ARRAYS,
    ]
    if args is not None:
        add_arg_checks(vote_lines, args)
    vote_lines.append("return true")
    vote_text = "; ".join(vote_lines)
    vote = {
        "ballot": {"text": vote_text},
        "id": PROPOSAL_ID_PLACEHOLDER,
    }

    LOG.warning(f"Made {proposed_call} proposal:\n{json.dumps(proposal, indent=2)}")
    LOG.warning(f"Accompanying vote:\n{json.dumps(vote, indent=2)}")

    return proposal, vote


def new_member_proposal(
    member_cert_path, member_keyshare_encryptor_path, proposer_vote_for=True
):
    LOG.warning("Generating new_member proposal")

    # Convert certs to byte arrays
    member_cert = file_to_byte_array(member_cert_path)
    member_keyshare_encryptor = file_to_byte_array(member_keyshare_encryptor_path)

    # Script which proposes adding a new member
    proposal_script_text = """
    tables, args = ...
    return Calls:call("new_member", args)
    """

    # Proposal object (request body for /gov/propose) containing this member's info as parameter
    proposal = {
        "parameter": {"cert": member_cert, "keyshare": member_keyshare_encryptor},
        "script": {"text": proposal_script_text},
        "ballot": TRIVIAL_YES_BALLOT if proposer_vote_for else TRIVIAL_NO_BALLOT,
    }

    # Sample vote script which checks the expected member is being added, and no other actions are being taken
    verifying_vote_text = f"""
    tables, calls = ...
    if #calls ~= 1 then
      return false
    end

    call = calls[1]
    if call.func ~= "new_member" then
      return false
    end

    {LUA_FUNCTION_EQUAL_ARRAYS}

    expected_cert = {list_as_lua_literal(member_cert)}
    if not equal_arrays(call.args.cert, expected_cert) then
      return false
    end

    expected_keyshare = {list_as_lua_literal(member_keyshare_encryptor)}
    if not equal_arrays(call.args.keyshare, expected_keyshare) then
      return false
    end

    return true
    """

    # Vote object (request body for /gov/vote)
    verifying_vote = {
        "ballot": {"text": verifying_vote_text},
        "id": PROPOSAL_ID_PLACEHOLDER,
    }

    LOG.warning(f"Made new member proposal:\n{json.dumps(proposal, indent=2)}")
    LOG.warning(f"Accompanying vote:\n{json.dumps(verifying_vote, indent=2)}")

    return proposal, verifying_vote


def retire_member_proposal(member_id):
    return build_proposal("retire_member", member_id)


def new_user_proposal(user_cert_path):
    user_cert = file_to_byte_array(user_cert_path)
    return build_proposal("new_user", user_cert)


def set_user_data_proposal(user_id, user_data):
    proposal_args = {"user_id": user_id, "user_data": user_data}
    return build_proposal("set_user_data", proposal_args)


def set_lua_app_proposal(app_script_path):
    with open(app_script_path) as f:
        app_script = f.read()
    return build_proposal("set_lua_app", app_script)


def set_js_app_proposal(app_script_path):
    with open(app_script_path) as f:
        app_script = f.read()
    return build_proposal("set_js_app", app_script)


def trust_node_proposal(node_id):
    return build_proposal("trust_node", node_id)


def retire_node_proposal(node_id):
    return build_proposal("retire_node", node_id)


def new_node_code_proposal(code_digest):
    if isinstance(code_digest):
        code_digest = list(bytearray.fromhex(code_digest))
    return build_proposal("new_node_code", code_digest)


def new_user_code_proposal(code_digest):
    if isinstance(code_digest):
        code_digest = list(bytearray.fromhex(code_digest))
    return build_proposal("new_user_code", code_digest)


def accept_recovery_proposal():
    return build_proposal("accept_recovery")


def open_network_proposal():
    return build_proposal("open_network")


def rekey_ledger_proposal():
    return build_proposal("rekey_ledger")


def update_recovery_shares_proposal():
    return build_proposal("update_recovery_shares")


def set_recovery_threshold_proposal(threshold):
    return build_proposal("set_recovery_threshold", threshold)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument("-po", "--proposal-output-file", type=str)
    parser.add_argument("-vo", "--vote-output-file", type=str)
    parser.add_argument("-pp", "--pretty-print", action="store_true")

    subparsers = parser.add_subparsers(
        title="Possible proposals", dest="proposal_kind", required=True
    )

    new_member = subparsers.add_parser("new_member")
    new_member.add_argument("-c", "--new-member-cert", required=True)
    new_member.add_argument(
        "-ks", "--new-member-keyshare-encryptor", required=True,
    )

    new_user = subparsers.add_parser("new_user")
    new_user.add_argument("-c", "--new-user-cert", required=True)

    args = parser.parse_args()

    if args.proposal_kind == "new_member":
        proposal, vote = new_member_proposal(
            member_cert_path=args.new_member_cert,
            member_keyshare_encryptor_path=args.new_member_keyshare_encryptor,
        )
    elif args.proposal_kind == "new_user":
        proposal, vote = new_user_proposal(user_cert_path=args.new_user_cert)
    else:
        raise ValueError(f"Unsupported proposal '{args.proposal_kind}'")

    dump_args = {}
    if args.pretty_print:
        dump_args["indent"] = 2

    proposal_output_path = args.proposal_output_file or f"{args.proposal_kind}.json"
    dump_proposal(proposal_output_path, proposal, dump_args)

    vote_output_path = args.vote_output_file or f"vote_for_{args.proposal_kind}.json"
    dump_vote(vote_output_path, vote, dump_args)
