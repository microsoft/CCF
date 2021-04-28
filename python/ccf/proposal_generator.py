# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import argparse
import inspect
import json
import glob
import os
import sys
import shutil
import tempfile
from typing import Optional, Any, List, Dict

from cryptography import x509
import cryptography.hazmat.backends as crypto_backends
from loguru import logger as LOG  # type: ignore


def dump_to_file(output_path: str, obj: dict, dump_args: dict):
    with open(output_path, "w") as f:
        json.dump(obj, f, **dump_args)


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


def build_proposal(
    proposed_call: str,
    args: Optional[Any] = None,
    inline_args: bool = False,
):
    LOG.trace(f"Generating {proposed_call} proposal")

    proposal: Dict[str, Any] = {}
    vote: Dict[str, Any] = {}

    action = {"name": proposed_call, "args": args}
    actions = [action]
    proposal = {"actions": actions}

    vote_lines = []
    vote_lines.append("export function vote (rawProposal, proposerId) {")
    vote_lines.append("  let proposal = JSON.parse(rawProposal);")
    vote_lines.append("  if (!('actions' in proposal)) { return false; };")
    vote_lines.append("  let actions = proposal['actions'];")
    vote_lines.append("  if (actions.length !== 1) { return false; };")
    vote_lines.append("  let action = actions[0];")
    vote_lines.append("  if (!('name' in action)) { return false; };")
    vote_lines.append(f"  if (action.name !== '{proposed_call}') {{ return false; }};")

    if args is not None:
        vote_lines.append("  if (!('args' in action)) { return false; };")
        vote_lines.append("  let args = action.args;")

        for name, body in args.items():
            vote_lines.append("  {")
            vote_lines.append(f"    if (!('{name}' in args)) {{ return false; }};")
            vote_lines.append(f"    let expected = {json.dumps(body)};")
            vote_lines.append(
                f"    if (JSON.stringify(args['{name}']) !== JSON.stringify(expected)) {{ return false; }};"
            )
            vote_lines.append("  }")

    vote_lines.append("  return true;")
    vote_lines.append("}")
    vote_text = "\n".join(vote_lines)
    vote = {"ballot": vote_text}

    LOG.trace(f"Made {proposed_call} proposal:\n{json.dumps(proposal, indent=2)}")
    LOG.trace(f"Accompanying vote:\n{json.dumps(vote, indent=2)}")

    return proposal, vote


def cli_proposal(func):
    func.is_cli_proposal = True
    return func


@cli_proposal
def set_member(
    member_cert_path: str,
    member_enc_pubk_path: str = None,
    member_data: Any = None,
    **kwargs,
):
    member_info = {"cert": open(member_cert_path).read()}
    if member_enc_pubk_path is not None:
        member_info["encryption_pub_key"] = open(member_enc_pubk_path).read()
    if member_data is not None:
        member_info["member_data"] = member_data

    return build_proposal("set_member", member_info, **kwargs)


@cli_proposal
def remove_member(member_id: str, **kwargs):
    args = {"member_id": member_id}
    return build_proposal("remove_member", args, **kwargs)


@cli_proposal
def set_member_data(member_id: str, member_data: Any, **kwargs):
    proposal_args = {"member_id": member_id, "member_data": member_data}
    return build_proposal("set_member_data", proposal_args, **kwargs)


@cli_proposal
def set_user(user_cert_path: str, user_data: Any = None, **kwargs):
    user_info = {"cert": open(user_cert_path).read()}
    if user_data is not None:
        user_info["user_data"] = user_data
    return build_proposal("set_user", user_info, **kwargs)


@cli_proposal
def remove_user(user_id: str, **kwargs):
    args = {"user_id": user_id}
    return build_proposal("remove_user", args, **kwargs)


@cli_proposal
def set_user_data(user_id: str, user_data: Any, **kwargs):
    proposal_args = {"user_id": user_id, "user_data": user_data}
    return build_proposal("set_user_data", proposal_args, **kwargs)


@cli_proposal
def set_constitution(constitution_paths: List[str], **kwargs):
    concatenated = "\n".join(open(path, "r").read() for path in constitution_paths)
    proposal_args = {"constitution": concatenated}
    return build_proposal("set_constitution", proposal_args, **kwargs)


@cli_proposal
def set_js_app(bundle_path: str, **kwargs):
    # read modules
    if os.path.isfile(bundle_path):
        tmp_dir = tempfile.TemporaryDirectory(prefix="ccf")
        shutil.unpack_archive(bundle_path, tmp_dir.name)
        bundle_path = tmp_dir.name
    modules_path = os.path.join(bundle_path, "src")
    modules = read_modules(modules_path)

    # read metadata
    metadata_path = os.path.join(bundle_path, "app.json")
    with open(metadata_path) as f:
        metadata = json.load(f)

    # sanity checks
    module_paths = set(module["name"] for module in modules)
    for url, methods in metadata["endpoints"].items():
        for method, endpoint in methods.items():
            module_path = endpoint["js_module"]
            if module_path not in module_paths:
                raise ValueError(
                    f"{method} {url}: module '{module_path}' not found in bundle"
                )

    proposal_args = {
        "bundle": {"metadata": metadata, "modules": modules},
    }

    return build_proposal("set_js_app", proposal_args, **kwargs)


@cli_proposal
def remove_js_app(**kwargs):
    return build_proposal("remove_js_app", **kwargs)


def read_modules(modules_path: str) -> List[dict]:
    modules = []
    for path in glob.glob(f"{modules_path}/**/*.js", recursive=True):
        if not os.path.isfile(path):
            continue
        rel_module_name = os.path.relpath(path, modules_path)
        rel_module_name = rel_module_name.replace("\\", "/")  # Windows support
        with open(path) as f:
            js = f.read()
            modules.append({"name": rel_module_name, "module": js})
    return modules


@cli_proposal
def transition_node_to_trusted(node_id: str, **kwargs):
    return build_proposal("transition_node_to_trusted", {"node_id": node_id}, **kwargs)


@cli_proposal
def remove_node(node_id: str, **kwargs):
    return build_proposal("remove_node", {"node_id": node_id}, **kwargs)


@cli_proposal
def add_node_code(code_id: str, **kwargs):
    return build_proposal("add_node_code", {"code_id": code_id}, **kwargs)


@cli_proposal
def remove_node_code(code_id: str, **kwargs):
    return build_proposal("remove_node_code", {"code_id": code_id}, **kwargs)


@cli_proposal
def transition_service_to_open(**kwargs):
    return build_proposal("transition_service_to_open", **kwargs)


@cli_proposal
def trigger_ledger_rekey(**kwargs):
    return build_proposal("trigger_ledger_rekey", **kwargs)


@cli_proposal
def trigger_recovery_shares_refresh(**kwargs):
    return build_proposal("trigger_recovery_shares_refresh", **kwargs)


@cli_proposal
def set_recovery_threshold(threshold: int, **kwargs):
    proposal_args = {"recovery_threshold": threshold}
    return build_proposal("set_recovery_threshold", proposal_args, **kwargs)


@cli_proposal
def set_ca_cert_bundle(cert_bundle_name, cert_bundle_path, skip_checks=False, **kwargs):
    with open(cert_bundle_path) as f:
        cert_bundle_pem = f.read()

    if not skip_checks:
        delim = "-----END CERTIFICATE-----"
        for cert_pem in cert_bundle_pem.split(delim):
            if not cert_pem.strip():
                continue
            cert_pem += delim
            try:
                x509.load_pem_x509_certificate(
                    cert_pem.encode(), crypto_backends.default_backend()
                )
            except Exception as exc:
                raise ValueError("Cannot parse PEM certificate") from exc

    args = {"name": cert_bundle_name, "cert_bundle": cert_bundle_pem}
    return build_proposal("set_ca_cert_bundle", args, **kwargs)


@cli_proposal
def remove_ca_cert_bundle(cert_bundle_name, **kwargs):
    args = {"name": cert_bundle_name}
    return build_proposal("remove_ca_cert_bundle", args, **kwargs)


@cli_proposal
def set_jwt_issuer(json_path: str, **kwargs):
    with open(json_path) as f:
        obj = json.load(f)
    args = {
        "issuer": obj["issuer"],
        "key_filter": obj.get("key_filter", "all"),
        "key_policy": obj.get("key_policy"),
        "ca_cert_bundle_name": obj.get("ca_cert_bundle_name"),
        "auto_refresh": obj.get("auto_refresh", False),
        "jwks": obj.get("jwks"),
    }
    return build_proposal("set_jwt_issuer", args, **kwargs)


@cli_proposal
def remove_jwt_issuer(issuer: str, **kwargs):
    args = {"issuer": issuer}
    return build_proposal("remove_jwt_issuer", args, **kwargs)


@cli_proposal
def set_jwt_public_signing_keys(issuer: str, jwks_path: str, **kwargs):
    with open(jwks_path) as f:
        jwks = json.load(f)
    if "keys" not in jwks:
        raise ValueError("not a JWKS document")
    args = {"issuer": issuer, "jwks": jwks}
    return build_proposal("set_jwt_public_signing_keys", args, **kwargs)


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
        help=f"Path where vote JSON object (request body for POST /gov/proposals/{{proposal_id}}/ballots) will be dumped. Default is {DEFAULT_VOTE_OUTPUT}",
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
            add_argument_extras = {}
            if param.kind == param.VAR_POSITIONAL or param.kind == param.VAR_KEYWORD:
                continue
            if param.annotation == param.empty:
                param_type = None
            elif param.annotation == dict or param.annotation == Any:
                param_type = json.loads
            elif param.annotation == List[str]:
                add_argument_extras["nargs"] = "+"
                param_type = str  # type: ignore
            else:
                param_type = param.annotation
            if param.default is None:
                add_argument_extras["nargs"] = "?"
                add_argument_extras["default"] = param.default  # type: ignore
            subparser.add_argument(param_name, type=param_type, **add_argument_extras)  # type: ignore
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
