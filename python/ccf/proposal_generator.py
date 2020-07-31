# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import argparse
import collections
import inspect
import json
import os
import sys
import functools
from typing import Union, Optional, Any

from cryptography import x509
import cryptography.hazmat.backends as crypto_backends
from loguru import logger as LOG  # type: ignore


def dump_to_file(output_path: str, obj: dict, dump_args: dict):
    with open(output_path, "w") as f:
        json.dump(obj, f, **dump_args)


def list_as_lua_literal(l):
    return str(l).translate(str.maketrans("[]", "{}"))


LUA_FUNCTION_EQUAL_ARRAYS = """function equal_arrays(a, b)
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
end"""

DEFAULT_PROPOSAL_OUTPUT = "{proposal_name}_proposal.json"
DEFAULT_VOTE_OUTPUT = "{proposal_name}_vote_for.json"


def complete_proposal_output_path(
    proposal_name: str,
    proposal_output_path: Optional[str] = None,
    common_dir: str = ".",
):
    if proposal_output_path is None:
        proposal_output_path = DEFAULT_PROPOSAL_OUTPUT.format(
            proposal_name=proposal_name
        )

    if not proposal_output_path.endswith(".json"):
        proposal_output_path += ".json"

    proposal_output_path = os.path.join(common_dir, proposal_output_path)

    return proposal_output_path


def complete_vote_output_path(
    proposal_name: str, vote_output_path: Optional[str] = None, common_dir: str = "."
):
    if vote_output_path is None:
        vote_output_path = DEFAULT_VOTE_OUTPUT.format(proposal_name=proposal_name)

    if not vote_output_path.endswith(".json"):
        vote_output_path += ".json"

    vote_output_path = os.path.join(common_dir, vote_output_path)

    return vote_output_path


def add_arg_construction(
    lines: list,
    arg: Union[str, collections.abc.Sequence, collections.abc.Mapping],
    arg_name: str = "args",
):
    if isinstance(arg, str):
        lines.append(f"{arg_name} = [====[{arg}]====]")
    elif isinstance(arg, collections.abc.Sequence):
        lines.append(f"{arg_name} = {list_as_lua_literal(arg)}")
    elif isinstance(arg, collections.abc.Mapping):
        lines.append(f"{arg_name} = {{}}")
        for k, v in args.items():
            add_arg_construction(lines, v, arg_name=f"{arg_name}.{k}")
    else:
        lines.append(f"{arg_name} = {arg}")


def add_arg_checks(
    lines: list,
    arg: Union[str, collections.abc.Sequence, collections.abc.Mapping],
    arg_name: str = "args",
    added_equal_arrays_fn: bool = False,
):
    lines.append(f"if {arg_name} == nil then return false end")
    if isinstance(arg, str):
        lines.append(f"if not {arg_name} == [====[{arg}]====] then return false end")
    elif isinstance(arg, collections.abc.Sequence):
        if not added_equal_arrays_fn:
            lines.extend(
                line.strip() for line in LUA_FUNCTION_EQUAL_ARRAYS.splitlines()
            )
            added_equal_arrays_fn = True
        expected_name = arg_name.replace(".", "_")
        lines.append(f"{expected_name} = {list_as_lua_literal(arg)}")
        lines.append(
            f"if not equal_arrays({arg_name}, {expected_name}) then return false end"
        )
    elif isinstance(arg, collections.abc.Mapping):
        for k, v in arg.items():
            add_arg_checks(
                lines,
                v,
                arg_name=f"{arg_name}.{k}",
                added_equal_arrays_fn=added_equal_arrays_fn,
            )
    else:
        lines.append(f"if not {arg_name} == {arg} then return false end")


def build_proposal(
    proposed_call: str,
    args: Optional[Any] = None,
    inline_args: bool = False,
    vote_against: bool = False,
):
    LOG.trace(f"Generating {proposed_call} proposal")

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
    if vote_against:
        proposal["ballot"] = {"text": "return false"}

    vote_lines = [
        "tables, calls = ...",
        "if not #calls == 1 then return false end",
        "call = calls[1]",
        f'if not call.func == "{proposed_call}" then return false end',
    ]
    if args is not None:
        vote_lines.append("args = call.args")
        add_arg_checks(vote_lines, args)
    vote_lines.append("return true")
    vote_text = "; ".join(vote_lines)
    vote = {"ballot": {"text": vote_text}}

    LOG.trace(f"Made {proposed_call} proposal:\n{json.dumps(proposal, indent=2)}")
    LOG.trace(f"Accompanying vote:\n{json.dumps(vote, indent=2)}")

    return proposal, vote


def cli_proposal(func):
    func.is_cli_proposal = True
    return func


@cli_proposal
def new_member(member_cert_path: str, member_enc_pubk_path: str, **kwargs):
    LOG.debug("Generating new_member proposal")

    # Read certs
    member_cert = open(member_cert_path).read()
    member_keyshare_encryptor = open(member_enc_pubk_path).read()

    # Script which proposes adding a new member
    proposal_script_text = """
    tables, args = ...
    return Calls:call("new_member", args)
    """

    # Proposal object (request body for POST /gov/proposals) containing this member's info as parameter
    proposal = {
        "parameter": {"cert": member_cert, "keyshare": member_keyshare_encryptor},
        "script": {"text": proposal_script_text},
    }

    vote_against = kwargs.pop("vote_against", False)

    if vote_against:
        proposal["ballot"] = {"text": "return false"}

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

    expected_cert = [====[{member_cert}]====]
    if not call.args.cert == expected_cert then
    return false
    end

    expected_keyshare = [====[{member_keyshare_encryptor}]====]
    if not call.args.keyshare == expected_keyshare then
    return false
    end

    return true
    """

    # Vote object (request body for POST /gov/proposals/{proposal_id}/votes)
    verifying_vote = {"ballot": {"text": verifying_vote_text}}

    LOG.trace(f"Made new member proposal:\n{json.dumps(proposal, indent=2)}")
    LOG.trace(f"Accompanying vote:\n{json.dumps(verifying_vote, indent=2)}")

    return proposal, verifying_vote


@cli_proposal
def retire_member(member_id: int, **kwargs):
    return build_proposal("retire_member", member_id, **kwargs)


@cli_proposal
def new_user(user_cert_path: str, **kwargs):
    user_cert = open(user_cert_path).read()
    return build_proposal("new_user", user_cert, **kwargs)


@cli_proposal
def remove_user(user_id: int, **kwargs):
    return build_proposal("remove_user", user_id, **kwargs)


@cli_proposal
def set_user_data(user_id: int, user_data: dict, **kwargs):
    proposal_args = {"user_id": user_id, "user_data": user_data}
    return build_proposal("set_user_data", proposal_args, **kwargs)


@cli_proposal
def set_lua_app(app_script_path: str, **kwargs):
    with open(app_script_path) as f:
        app_script = f.read()
    return build_proposal("set_lua_app", app_script, **kwargs)


@cli_proposal
def set_js_app(app_script_path: str, **kwargs):
    with open(app_script_path) as f:
        app_script = f.read()
    return build_proposal("set_js_app", app_script, **kwargs)


@cli_proposal
def set_module(module_name, module_path, **kwargs):
    if module_name.endswith(".js"):
        with open(module_path) as f:
            js = f.read()
        proposal_args = {"name": module_name, "module": {"js": js}}
    else:
        raise ValueError("module name must end with .js")
    return build_proposal("set_module", proposal_args, **kwargs)


@cli_proposal
def remove_module(module_name, **kwargs):
    return build_proposal("remove_module", module_name, **kwargs)


@cli_proposal
def trust_node(node_id: int, **kwargs):
    return build_proposal("trust_node", node_id, **kwargs)


@cli_proposal
def retire_node(node_id: int, **kwargs):
    return build_proposal("retire_node", node_id, **kwargs)


@cli_proposal
def new_node_code(code_digest: Union[str, list], **kwargs):
    if isinstance(code_digest, str):
        code_digest = list(bytearray.fromhex(code_digest))
    return build_proposal("new_node_code", code_digest, **kwargs)


@cli_proposal
def new_user_code(code_digest: Union[str, list], **kwargs):
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
def set_recovery_threshold(threshold: int, **kwargs):
    return build_proposal("set_recovery_threshold", threshold, **kwargs)

@cli_proposal
def update_root_ca_cert(cert_name, cert_path, skip_checks=False, **kwargs):
    with open(cert_path) as f:
        cert_pem = f.read()

    if not skip_checks:
        try:
            cert = x509.load_pem_x509_certificate(cert_pem.encode(), crypto_backends.default_backend())
        except Exception:
            raise ValueError("Cannot parse PEM certificate")
        
        # TODO remove one of the OID code paths, depending on which one OE chooses (OE#3312)
        try:
            oid_old = x509.ObjectIdentifier("1.2.840.113556.10.1.1")
            _ = cert.extensions.get_extension_for_oid(oid_old)
        except x509.ExtensionNotFound:
            try:
                oid_new = x509.ObjectIdentifier("1.2.840.113556.10.1.2")
                _ = cert.extensions.get_extension_for_oid(oid_new)
            except x509.ExtensionNotFound:
                raise ValueError("X.509 extension with SGX quote not found in certificate")
        
    args = {"name": cert_name, "cert": cert_pem}
    return build_proposal("update_root_ca_cert", args, **kwargs)


class ProposalGenerator:
    def __init__(self, common_dir: str = "."):
        self.common_dir = common_dir

        # Auto-generate methods wrapping inspected functions, dumping outputs to file
        def wrapper(func):
            @functools.wraps(func)
            def wrapper_func(
                *args,
                proposal_output_path_: Optional[str] = None,
                vote_output_path_: Optional[str] = None,
                **kwargs,
            ):
                proposal_output_path = complete_proposal_output_path(
                    func.__name__,
                    proposal_output_path=proposal_output_path_,
                    common_dir=self.common_dir,
                )

                vote_output_path = complete_vote_output_path(
                    func.__name__,
                    vote_output_path=vote_output_path_,
                    common_dir=self.common_dir,
                )

                proposal_object, vote_object = func(*args, **kwargs)
                dump_args = {"indent": 2}

                LOG.debug(f"Writing proposal to {proposal_output_path}")
                dump_to_file(proposal_output_path, proposal_object, dump_args)

                LOG.debug(f"Writing vote to {vote_output_path}")
                dump_to_file(vote_output_path, vote_object, dump_args)

                return f"@{proposal_output_path}", f"@{vote_output_path}"

            return wrapper_func

        module = inspect.getmodule(inspect.currentframe())
        proposal_generators = inspect.getmembers(module, predicate=inspect.isfunction)

        for func_name, func in proposal_generators:
            # Only wrap decorated functions
            if hasattr(func, "is_cli_proposal"):
                setattr(self, func_name, wrapper(func))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "-po",
        "--proposal-output-file",
        type=str,
        help=f"Path where proposal JSON object (request body for POST /gov/proposals) will be dumped. Default is {DEFAULT_PROPOSAL_OUTPUT}",
    )
    parser.add_argument(
        "-vo",
        "--vote-output-file",
        type=str,
        help=f"Path where vote JSON object (request body for POST /gov/proposals/{{proposal_id}}/votes) will be dumped. Default is {DEFAULT_VOTE_OUTPUT}",
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
        help="Create a fixed proposal script with the call arguments as literals inside "
        "the script. When not inlined, the parameters are passed separately and could "
        "be replaced in the resulting object",
    )
    parser.add_argument(
        "--vote-against",
        action="store_true",
        help="Include a negative initial vote when creating the proposal",
        default=False,
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
        if not hasattr(func, "is_cli_proposal"):
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
        vote_against=args.vote_against,
        inline_args=args.inline_args,
    )

    dump_args = {}
    if args.pretty_print:
        dump_args["indent"] = 2

    proposal_path = complete_proposal_output_path(
        args.proposal_type, proposal_output_path=args.proposal_output_file
    )
    LOG.success(f"Writing proposal to {proposal_path}")
    dump_to_file(proposal_path, proposal, dump_args)

    vote_path = complete_vote_output_path(
        args.proposal_type, vote_output_path=args.vote_output_file
    )
    LOG.success(f"Wrote vote to {vote_path}")
    dump_to_file(vote_path, vote, dump_args)
