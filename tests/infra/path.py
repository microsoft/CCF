# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import os
from contextlib import contextmanager
import logging

from loguru import logger as LOG


def mk(name, contents):
    LOG.info('echo "<{} bytes>" > {}'.format(len(contents), name))
    with open(name, "w") as dst:
        dst.write(contents)


def mk_new(name, contents):
    if not os.path.isfile(name):
        LOG.debug('Creating file at "{}" containing "{}"'.format(name, contents))
        mk(name, contents)


def build_lib_path(lib_name, enclave_type="debug"):
    if enclave_type == "virtual":
        return "./{}.virtual.so".format(lib_name)
    else:
        return "./{}.so.signed".format(lib_name)


def build_bin_path(bin_name, enclave_type=""):
    if enclave_type == "virtual":
        return "./{}.virtual".format(bin_name)
    else:
        return bin_name


def default_workspace():
    return os.path.join(os.getcwd(), "workspace")


def cert_bytes(cert_file_name):
    """
    Parses a pem certificate file into raw bytes and appends null character.
    """
    with open(cert_file_name, "rb") as pem:
        chars = []
        for c in pem.read():
            if c:
                chars.append(c)
            else:
                break
        # mbedtls demands null-terminated certs
        return chars + [0]


def quote_bytes(quote_file_name):
    """
    Parses a binary quote file into raw bytes.
    """
    with open(quote_file_name, "rb") as quote:
        chars = []
        for c in quote.read():
            chars.append(c)
        return chars


@contextmanager
def working_dir(path):
    cwd = os.getcwd()
    LOG.info("cd {}".format(path))
    os.chdir(path)
    try:
        yield
    except Exception:
        raise
    finally:
        os.chdir(cwd)
