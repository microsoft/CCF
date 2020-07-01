# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import argparse
import inspect
import json
import os

from loguru import logger as LOG


def dump_proposal(output_path, proposal, dump_args):
    LOG.info(f"Writing proposal to {output_path}")
    with open(output_path, "w") as f:
        json.dump(proposal, f, **dump_args)


def dump_vote(output_path, vote, dump_args):
    LOG.info(f"Writing vote to {output_path}")
    with open(output_path, "w") as f:
        json.dump(vote, f, **dump_args)


def file_to_byte_array(path):
    with open(path, "r") as f:
        return [ord(c) for c in f.read()]


def list_as_lua_literal(l):
    return str(l).translate(str.maketrans("[]", "{}"))


def script_to_vote_object(script):
    return {"ballot": {"text": script}, "id": PROPOSAL_ID_PLACEHOLDER}


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


def add_arg_construction(lines, arg, arg_name="args"):
    if isinstance(arg, list):
        lines.append(f"{arg_name} = {list_as_lua_literal(arg)}")
    elif isinstance(arg, dict):
        lines.append(f"{arg_name} = {{}}")
        for k, v in args.items():
            add_arg_construction(lines, v, arg_name=f"{arg_name}.{k}")
    elif isinstance(arg, str):
        lines.append(f'{arg_name} = "{arg}"')
    else:
        lines.append(f"{arg.name} = {arg}")


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
    elif isinstance(arg, str):
        lines.append(f'if not {arg_name} == "{arg}" then return false end')
    else:
        lines.append(f"if not {arg_name} == {arg} then return false end")


def build_proposal(proposed_call, args=None, inline_args=False):
    LOG.debug(f"Generating {proposed_call} proposal")

    proposal_script_lines = []
    if args is None:
        proposal_script_lines.append(f'return Calls:call("{proposed_call}")')
    else:
        if inline_args:
            add_arg_construction(proposal_script_lines, args)
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

    LOG.trace(f"Made {proposed_call} proposal:\n{json.dumps(proposal, indent=2)}")
    LOG.trace(f"Accompanying vote:\n{json.dumps(vote, indent=2)}")

    return proposal, vote


class Proposals:
    @staticmethod
    def new_member_proposal(member_cert_path, member_keyshare_encryptor_path):
        LOG.debug("Generating new_member proposal")

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

        LOG.trace(f"Made new member proposal:\n{json.dumps(proposal, indent=2)}")
        LOG.trace(f"Accompanying vote:\n{json.dumps(verifying_vote, indent=2)}")

        return proposal, verifying_vote

    @staticmethod
    def retire_member_proposal(member_id):
        return build_proposal("retire_member", member_id)

    @staticmethod
    def new_user_proposal(user_cert_path):
        user_cert = file_to_byte_array(user_cert_path)
        return build_proposal("new_user", user_cert)

    @staticmethod
    def set_user_data_proposal(user_id, user_data):
        proposal_args = {"user_id": user_id, "user_data": user_data}
        return build_proposal("set_user_data", proposal_args)

    @staticmethod
    def set_lua_app_proposal(app_script_path):
        with open(app_script_path) as f:
            app_script = f.read()
        return build_proposal("set_lua_app", app_script)

    @staticmethod
    def set_js_app_proposal(app_script_path):
        with open(app_script_path) as f:
            app_script = f.read()
        return build_proposal("set_js_app", app_script)

    @staticmethod
    def trust_node_proposal(node_id):
        return build_proposal("trust_node", node_id)

    @staticmethod
    def retire_node_proposal(node_id):
        return build_proposal("retire_node", node_id)

    @staticmethod
    def new_node_code_proposal(code_digest):
        if isinstance(code_digest):
            code_digest = list(bytearray.fromhex(code_digest))
        return build_proposal("new_node_code", code_digest)

    @staticmethod
    def new_user_code_proposal(code_digest):
        if isinstance(code_digest):
            code_digest = list(bytearray.fromhex(code_digest))
        return build_proposal("new_user_code", code_digest)

    @staticmethod
    def accept_recovery_proposal():
        return build_proposal("accept_recovery")

    @staticmethod
    def open_network_proposal():
        return build_proposal("open_network")

    @staticmethod
    def rekey_ledger_proposal():
        return build_proposal("rekey_ledger")

    @staticmethod
    def update_recovery_shares_proposal():
        return build_proposal("update_recovery_shares")

    @staticmethod
    def set_recovery_threshold_proposal(threshold):
        return build_proposal("set_recovery_threshold", threshold)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )

    default_proposal_output = "{proposal_type}.json"
    default_vote_output = "vote_for_{proposal_output}.json"

    parser.add_argument(
        "-po",
        "--proposal-output-file",
        type=str,
        help=f"Path where proposal json object (request body for /gov/propose) will be dumped. Default is {default_proposal_output}",
    )
    parser.add_argument(
        "-vo",
        "--vote-output-file",
        type=str,
        help=f"Path where vote json object (request body for /gov/vote) will be dumped. Default is {default_vote_output}",
    )
    parser.add_argument("-pp", "--pretty-print", action="store_true")

    # Auto-generate CLI args based on the inspected generator signatures
    proposal_generators = inspect.getmembers(Proposals, predicate=inspect.isfunction)
    subparsers = parser.add_subparsers(
        title="Possible proposals", dest="proposal_type", required=True
    )

    for func_name, func in proposal_generators:
        suffix = "_proposal"
        if not func_name.endswith(suffix):
            continue

        sub_func_name = func_name[: -len(suffix)]

        subparser = subparsers.add_parser(sub_func_name)
        arg_names = inspect.signature(func).parameters.keys()
        for arg_name in arg_names:
            subparser.add_argument(arg_name)
        subparser.set_defaults(func=func, func_arg_names=arg_names)

    args = parser.parse_args()

    proposal, vote = args.func(
        **{name: getattr(args, name) for name in args.func_arg_names}
    )

    dump_args = {}
    if args.pretty_print:
        dump_args["indent"] = 2

    proposal_output_path = args.proposal_output_file or default_proposal_output.format(
        proposal_type=args.proposal_type
    )
    dump_proposal(proposal_output_path, proposal, dump_args)

    vote_output_path = args.vote_output_file or default_vote_output.format(
        proposal_output=os.path.splitext(proposal_output_path)[0]
    )
    dump_vote(vote_output_path, vote, dump_args)
