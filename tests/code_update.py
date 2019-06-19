# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import e2e_args
import infra.ccf
import infra.proc
import json
import logging
import os
import subprocess
import time
from loguru import logger as LOG
from shutil import copyfile

OPCODE_PUSH_RBP = 0x55
OPCODE_RET = 0xC3
RET_BYTES = bytes([OPCODE_RET])


def patch_binary(so_path, function_name):
    procs = [
        ["nm", "-D", so_path],
        ["grep", f" {function_name}$"],
        ["cut", "-d", " ", "-f1"],
    ]

    result = infra.proc.ccall_with_pipe(procs)
    address = int(result, 0x10)

    with open(so_path, "r+b") as f:
        f.seek(address, 0)
        func_prologue = f.read(1)
        # make sure we know what we patch (the function prologue)
        if func_prologue[0] == OPCODE_PUSH_RBP:
            LOG.debug("Patching {} at 0x{:08x}".format(so_path, address))
            f.seek(address, 0)
            f.write(RET_BYTES)
        elif func_prologue[0] == OPCODE_RET:
            LOG.debug(
                "Not patching {} at 0x{:08x} - ELF already patched".format(
                    so_path, address
                )
            )
        else:
            # The function begins with an instruction which is
            # neither 'push rbp' nor 'ret', something is not right
            raise "Unexpected function prologue for {}".format(function_name)


def get_code_id(lib_path):
    oed = subprocess.run(
        [args.oesign, "dump", "-e", lib_path], capture_output=True, check=True
    )
    lines = [
        line
        for line in oed.stdout.decode().split(os.linesep)
        if line.startswith("mrenclave=")
    ]

    return lines[0].split("=")[1]


def create_new_code_version(primary):
    forwarded_args = {
        arg: getattr(args, arg) for arg in infra.ccf.Network.node_args_to_forward
    }

    copyfile(f"{args.package}.so", f"{args.patched_file_name}.so")
    patch_binary(f"{args.patched_file_name}.so", "stub_for_code_signing")

    # sign the patched binary
    oed = subprocess.run(
        [
            args.oesign,
            "sign",
            "-e",
            f"{args.patched_file_name}.so",
            "-c",
            args.oeconfpath,
            "-k",
            args.oesignkeypath,
        ],
        capture_output=True,
        check=True,
    )

    return get_code_id(f"{args.patched_file_name}.so.signed")


def add_new_code(primary, code_id):

    # first propose adding the new code id
    result = infra.proc.ccall(
        "./memberclient",
        "add_code",
        "--cert=member1_cert.pem",
        "--privk=member1_privk.pem",
        f"--host={primary.host}",
        f"--port={primary.tls_port}",
        "--ca=networkcert.pem",
        f"--new_code_id={code_id}",
    )

    # vote to accept the new code id
    result = infra.proc.ccall(
        "./memberclient",
        "vote",
        "--accept",
        "--cert=member1_cert.pem",
        "--privk=member1_privk.pem",
        "--host={}".format(primary.host),
        "--port={}".format(primary.tls_port),
        "--id=0",
        "--ca=networkcert.pem",
        "--sign",
    )
    j_result = json.loads(result.stdout)
    assert not j_result["result"]

    result = infra.proc.ccall(
        "./memberclient",
        "vote",
        "--accept",
        "--cert=member2_cert.pem",
        "--privk=member2_privk.pem",
        "--host={}".format(primary.host),
        "--port={}".format(primary.tls_port),
        "--id=0",
        "--ca=networkcert.pem",
        "--sign",
    )
    j_result = json.loads(result.stdout)
    assert j_result["result"]


def create_node_using_new_code(network, args, node_id):
    # add a node using unsupported code
    assert network.create_and_add_node(
        args.patched_file_name, args, node_id, False
    ) == (False, infra.jsonrpc.ErrorCode.CODE_ID_NOT_FOUND)


def run(args):
    hosts = ["localhost", "localhost"]

    with infra.ccf.network(
        hosts, args.build_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
    ) as network:
        primary, others = network.start_and_join(args)

        new_code_id = create_new_code_version(primary)
        LOG.debug(new_code_id)

        # add a node using unsupported code
        assert network.create_and_add_node(args.patched_file_name, args, 2, False) == (
            False,
            infra.jsonrpc.ErrorCode.CODE_ID_NOT_FOUND,
        )

        add_new_code(primary, new_code_id)

        # add a node using the same code id that failed earlier
        assert network.create_and_add_node(args.patched_file_name, args, 3, True)[0]

        # TODO: start replacing nodes


if __name__ == "__main__":

    def add(parser):
        parser.add_argument(
            "-p",
            "--package",
            help="The enclave package to load (e.g., libsimplebank)",
            default="libloggingenc",
        )
        parser.add_argument(
            "--oesign", help="Path to oesign binary", type=str, required=True
        )
        parser.add_argument(
            "--oeconfpath",
            help="Path to oe configuration file",
            type=str,
            required=True,
        )
        parser.add_argument(
            "--oesignkeypath", help="Path to oesign key", type=str, required=True
        )

    args = e2e_args.cli_args(add)
    args.package = args.app_script and "libluagenericenc" or "libloggingenc"
    args.patched_file_name = "{}_patched".format(args.package)
    run(args)
