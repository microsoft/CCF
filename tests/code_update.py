# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import e2e_args
import infra.ccf
import infra.proc
import json
import logging
import time
from shutil import copyfile

from loguru import logger as LOG

OPCODE_PUSH_RBP = 0x55
OPCODE_RET = 0xc3
RET_BYTES = bytes([OPCODE_RET])


def patch_binary(so_path, function_name):
    procs = [
            ["nm", "-D", so_path], 
            ["grep", " {}$".format(function_name)], 
            ["cut", "-d", " ", "-f1"]
        ]

    result = infra.proc.call_with_pipe(procs)
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
            LOG.debug("Not patching {} at 0x{:08x} - ELF already patched".format(so_path, address))
        else:
            # The function begins with an instruction which is
            # neither 'push rbp' nor 'ret', something is not right
            raise "Unexpected function prologue for {}".format(function_name)

def add_code(primary):
    forwarded_args = {
        arg: getattr(args, arg) for arg in infra.ccf.Network.node_args_to_forward
    }

    copyfile("../build/libloggingenc.so", "../build/libloggingenc_patched.so")
    patch_binary("../build/libloggingenc_patched.so", "stub_for_code_signing")
    # sign the patched binary



    result = infra.proc.ccall(
        "./memberclient",
        "add_code",
        "--cert=member1_cert.pem",
        "--privk=member1_privk.pem",
        "--host={}".format(primary.host),
        "--port={}".format(primary.tls_port),
        "--ca=networkcert.pem",
        "--new_code_path=quote1.bin",
    )
    # when proposal is added the proposal id and the result of running complete proposal are returned
    j_result = json.loads(result.stdout)
    assert not j_result["result"]["completed"]
    assert j_result["result"]["id"] == 0

def run(args):
    hosts = ["localhost", "localhost"]

    with infra.ccf.network(
        hosts, args.build_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
    ) as network:
        primary, others = network.start_and_join(args)

        add_code(primary)

        # # add a valid node
        # res = network.create_and_add_node("libloggingenc", args, 2)
        # assert res[0] == True
        # new_node = res[1]

        # with open("networkcert.pem", mode="rb") as file:
            # net_cert = list(file.read())

        # # add an invalid node
        # assert network.create_and_add_node("libluagenericenc", args, 3, False) == (
            # False,
            # infra.jsonrpc.ErrorCode.CODE_ID_NOT_FOUND,
        # )

        # with new_node.management_client(format="json") as c:
            # c.rpc(
                # "joinNetwork",
                # {
                    # "hostname": primary.host,
                    # "service": str(primary.tls_port),
                    # "network_cert": net_cert,
                # },
            # )
            # new_node.join_network()
            # network.wait_for_node_commit_sync()


if __name__ == "__main__":

    def add(parser):
        parser.add_argument(
            "-p",
            "--package",
            help="The enclave package to load (e.g., libsimplebank)",
            default="libloggingenc",
        )

    args = e2e_args.cli_args(add)
    args.package = args.app_script and "libluagenericenc" or "libloggingenc"
    run(args)
