# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import argparse
import os
import subprocess

OPCODE_MOV_EAX_DWORD = 0xB8
OPCODE_PUSH_RBP = 0x55
OPCODE_RET = 0xC3


def ccall_with_pipe(procs):
    cur_proc = subprocess.Popen(procs[0], shell=False, stdout=subprocess.PIPE)
    for p in procs[1:]:
        cur_proc = subprocess.Popen(
            p, shell=False, stdin=cur_proc.stdout, stdout=subprocess.PIPE
        )

    return (cur_proc.communicate()[0]).decode().strip()


def patch_binary(so_path, function_name):
    procs = [
        ["nm", "-D", so_path],
        ["grep", f" {function_name}$"],
        ["cut", "-d", " ", "-f1"],
    ]

    result = ccall_with_pipe(procs)
    address = int(result, 0x10)

    with open(so_path, "r+b") as f:
        f.seek(address, 0)
        func_prologue = f.read(1)
        # make sure we know what we patch (the function prologue)
        if (
            func_prologue[0] == OPCODE_PUSH_RBP
            or func_prologue[0] == OPCODE_MOV_EAX_DWORD
        ):
            print("Patching {} at 0x{:08x}".format(so_path, address))
            f.seek(address, 0)
            f.write(bytes([OPCODE_RET]))
        elif func_prologue[0] == OPCODE_RET:
            print(
                "Not patching {} at 0x{:08x} - ELF already patched".format(
                    so_path, address
                )
            )
        else:
            # The function begins with an instruction which is not
            # 'push rbp', 'mov eax,<DWORD>' or 'ret', something is not right
            raise ValueError(
                "Unexpected function prologue for {}".format(function_name)
            )


if __name__ == "__main__":

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-p",
        "--package",
        help="The enclave package to patch (e.g., liblogging.enclave.so)",
        required=True,
    )
    parser.add_argument(
        "-f",
        "--function",
        help="The name of the symbol to patch",
        default="stub_for_code_signing",
    )
    args = parser.parse_args()
    patch_binary(args.package, args.function)
