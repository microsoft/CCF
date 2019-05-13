# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import os
import sys
import time
import socket
from subprocess import check_call, Popen
from contextlib import contextmanager
from random import randrange as rr
from glob import glob


def rm(path):
    print(">> rm {}".format(path))
    try:
        os.remove(path)
    except OSError:
        pass


@contextmanager
def wd(path):
    cwd = os.getcwd()
    print(">> cd {}".format(path))
    os.chdir(path)
    try:
        yield
    except Exception:
        raise
    finally:
        os.chdir(cwd)


@contextmanager
def create_node(lib_path, node_id, quote_path, cert_path):
    cmd = [
        "./cchost",
        "--enclave-file={}".format(lib_path),
        "--quote-file={}".format(quote_path),
        "--node-cert-file={}".format(cert_path),
        "--raft-port=0",
        "--tls-port=0",
    ]
    print(">> {} &".format(" ".join(cmd)))
    proc = Popen(
        cmd,
        stdout=open("n{}.out".format(node_id), "wb"),
        stderr=open("n{}.err".format(node_id), "wb"),
    )
    try:
        yield proc
    except Exception:
        raise
    finally:
        print(">> kill {}".format(" ".join(cmd)))
        proc.terminate()
        proc.wait()


def verify_quote(lib_path, quote_path, quoted_path, should_fail=False):
    # As per OE 0.4.0, oe_verify_report() on the host leaks memory.
    # Turn ASAN leak check off for now until OE fixes it.
    asan_env_disable_leak = {"ASAN_OPTIONS": "detect_leaks=0"}
    cmd = [
        "./cchost",
        "--enclave-file={}".format(lib_path),
        "--start=verify",
        "--quote-file={}".format(quote_path),
        "--quoted-data={}".format(quoted_path),
    ]
    print(">> {} &".format(" ".join(cmd)))
    proc = Popen(
        cmd,
        stdout=open("verifier.out", "wb"),
        stderr=open("verifier.err", "wb"),
        env=asan_env_disable_leak,
    )
    try:
        proc.wait()
        failed = proc.returncode is not 0
    except Exception as e:
        print("ERROR")
        print(e)
        failed = True
    finally:
        if should_fail is not failed:
            raise RuntimeError("Quote verification did not behave as expected!")


def wait_for_file(path, max_waits=10):
    for _ in range(max_waits):
        if os.path.exists(path):
            break
        time.sleep(1)
    else:
        raise ValueError(path)


def run(build_directory, lib_path):
    with wd(build_directory):
        q0 = "q0.bin"
        p0 = "p0.pem"
        q1 = "q1.bin"
        p1 = "p1.pem"
        rm(q0)
        rm(p0)
        rm(q1)
        rm(p1)
        with create_node(lib_path, 0, q0, p0) as n0, create_node(
            lib_path, 1, q1, p1
        ) as n1:
            # Wait for quote files to be written, then kill these nodes
            wait_for_file(p0)
            wait_for_file(q0)
            wait_for_file(p1)
            wait_for_file(q1)

        verify_quote(lib_path, q0, p0)
        verify_quote(lib_path, q1, p1)
        verify_quote(lib_path, q0, p1, True)
        verify_quote(lib_path, q1, p0, True)
        print("Passed")


if __name__ == "__main__":
    build_directory = sys.argv[1]
    lib_path = sys.argv[2]
    run(build_directory, lib_path)
