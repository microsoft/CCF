# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import argparse
import collections
import inspect
import json
import os
import sys

from loguru import logger as LOG


def dump_to_file(output_path, obj, dump_args):
    with open(output_path, "w") as f:
        json.dump(obj, f, **dump_args)


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
    if isinstance(arg, str):
        lines.append(f'{arg_name} = "{arg}"')
    elif isinstance(arg, collections.abc.Sequence):
        lines.append(f"{arg_name} = {list_as_lua_literal(arg)}")
    elif isinstance(arg, collections.abc.Mapping):
        lines.append(f"{arg_name} = {{}}")
        for k, v in args.items():
            add_arg_construction(lines, v, arg_name=f"{arg_name}.{k}")
    else:
        lines.append(f"{arg_name} = {arg}")


def add_arg_checks(lines, arg, arg_name="args"):
    lines.append(f"if {arg_name} == nil then return false")
    if isinstance(arg, str):
        lines.append(f'if not {arg_name} == "{arg}" then return false end')
    elif isinstance(arg, collections.abc.Sequence):
        expected_name = arg_name.replace(".", "_")
        lines.append(f"{expected_name} = {list_as_lua_literal(arg)}")
        lines.append(
            f"if not equal_arrays({arg_name}, {expected_name}) then return false end"
        )
    elif isinstance(arg, collections.abc.Mapping):
        for k, v in arg.items():
            add_arg_checks(lines, v, arg_name=f"{arg_name}.{k}")
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
    if args is not None and not inline_args:
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


def cli_proposal(func):
    func.is_cli_proposal = True
    return func


@cli_proposal
def new_member(member_cert_path, member_enc_pubk_path):
    LOG.debug("Generating new_member proposal")

    # Convert certs to byte arrays
    member_cert = open(member_cert_path).read()
    member_keyshare_encryptor = open(member_enc_pubk_path).read()

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


@cli_proposal
def retire_member(member_id, **kwargs):
    return build_proposal("retire_member", member_id, **kwargs)


@cli_proposal
def new_user(user_cert_path, **kwargs):
    user_cert = open(user_cert_path).read()
    return build_proposal("new_user", user_cert, **kwargs)


@cli_proposal
def set_user_data(user_id, user_data, **kwargs):
    proposal_args = {"user_id": user_id, "user_data": user_data}
    return build_proposal("set_user_data", proposal_args, **kwargs)


@cli_proposal
def set_lua_app(app_script_path, **kwargs):
    with open(app_script_path) as f:
        app_script = f.read()
    return build_proposal("set_lua_app", app_script, **kwargs)


@cli_proposal
def set_js_app(app_script_path, **kwargs):
    with open(app_script_path) as f:
        app_script = f.read()
    return build_proposal("set_js_app", app_script, **kwargs)


@cli_proposal
def trust_node(node_id, **kwargs):
    return build_proposal("trust_node", node_id, **kwargs)


@cli_proposal
def retire_node(node_id, **kwargs):
    return build_proposal("retire_node", node_id, **kwargs)


@cli_proposal
def new_node_code(code_digest, **kwargs):
    if isinstance(code_digest, str):
        code_digest = list(bytearray.fromhex(code_digest))
    return build_proposal("new_node_code", code_digest, **kwargs)


@cli_proposal
def new_user_code(code_digest, **kwargs):
    if isinstance(code_digest, str):
        code_digest = list(bytearray.fromhex(code_digest))
    return build_proposal("new_user_code", code_digest, **kwargs)


@cli_proposal
def accept_recovery(**kwargs):
    return build_proposal("accept_recovery", **kwargs)


@cli_proposal
def open_network(**kwargs):
    return build_proposal("open_network", **kwargs)


@cli_proposal
def rekey_ledger(**kwargs):
    return build_proposal("rekey_ledger", **kwargs)


@cli_proposal
def update_recovery_shares(**kwargs):
    return build_proposal("update_recovery_shares", **kwargs)


@cli_proposal
def set_recovery_threshold(threshold, **kwargs):
    return build_proposal("set_recovery_threshold", threshold, **kwargs)


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
        help=f"Path where proposal JSON object (request body for /gov/propose) will be dumped. Default is {default_proposal_output}",
    )
    parser.add_argument(
        "-vo",
        "--vote-output-file",
        type=str,
        help=f"Path where vote JSON object (request body for /gov/vote) will be dumped. Default is {default_vote_output}",
    )
    parser.add_argument(
        "-pp",
        "--pretty-print",
        action="store_true",
        help="Pretty-print the JSON output",
    )
    parser.add_argument(
        "-i",
        "--inline-args",
        action="store_true",
        help="Create a fixed proposal script with the call arguments as literalsinside"
        "the script. When not inlined, the parameters are passed separately and could"
        "be replaced in the resulting object",
    )
    parser.add_argument("-v", "--verbose", action="store_true")

    # Auto-generate CLI args based on the inspected signatures of generator functions
    module = inspect.getmodule(inspect.currentframe())
    proposal_generators = inspect.getmembers(module, predicate=inspect.isfunction)
    subparsers = parser.add_subparsers(
        title="Possible proposals", dest="proposal_type", required=True
    )

    for func_name, func in proposal_generators:
        # Only generate for decorated functions
        try:
            getattr(func, "is_cli_proposal")
        except AttributeError:
            continue

        subparser = subparsers.add_parser(func_name)
        parameters = inspect.signature(func).parameters
        func_param_names = []
        for param_name, param in parameters.items():
            if param.kind == param.VAR_POSITIONAL or param.kind == param.VAR_KEYWORD:
                continue
            subparser.add_argument(param_name)
            func_param_names.append(param_name)
        subparser.set_defaults(func=func, param_names=func_param_names)

    args = parser.parse_args()

    LOG.remove()
    LOG.add(
        sys.stdout,
        format="<level>[{time:YYYY-MM-DD HH:mm:ss.SSS}] {level} | {message}</level>",
        level="TRACE" if args.verbose else "INFO",
    )

    proposal, vote = args.func(
        **{name: getattr(args, name) for name in args.param_names},
        inline_args=args.inline_args,
    )

    dump_args = {}
    if args.pretty_print:
        dump_args["indent"] = 2

    proposal_output_path = args.proposal_output_file or default_proposal_output.format(
        proposal_type=args.proposal_type
    )
    LOG.success(f"Writing proposal to {proposal_output_path}")
    dump_to_file(proposal_output_path, proposal, dump_args)

    vote_output_path = args.vote_output_file or default_vote_output.format(
        proposal_output=os.path.splitext(proposal_output_path)[0]
    )
    LOG.success(f"Writing vote to {vote_output_path}")
    dump_to_file(vote_output_path, vote, dump_args)
