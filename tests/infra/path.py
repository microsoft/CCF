# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import os
from contextlib import contextmanager
from shutil import copy2, rmtree
import hashlib

from loguru import logger as LOG


def mk(name, contents):
    LOG.info('echo "<{} bytes>" > {}'.format(len(contents), name))
    with open(name, "w", encoding="utf-8") as dst:
        dst.write(contents)


def mk_new(name, contents):
    if not os.path.isfile(name):
        LOG.debug('Creating file at "{}" containing "{}"'.format(name, contents))
        mk(name, contents)


def build_lib_path(
    lib_name, enclave_type=None, enclave_platform="sgx", library_dir="."
):
    if enclave_platform == "virtual":
        ext = ".virtual.so"
        mode = "Virtual mode"
    elif enclave_platform == "sgx":
        if enclave_type == "debug":
            ext = ".enclave.so.debuggable"
            mode = "Debuggable SGX enclave"
        elif enclave_type == "release":
            ext = ".enclave.so.signed"
            mode = "Release SGX enclave"
        else:
            raise ValueError(f"Invalid enclave_type {enclave_type} for SGX enclave")
    elif enclave_platform == "snp":
        ext = ".snp.so"
        mode = "SNP enclave"
    else:
        raise ValueError(f"Invalid enclave_platform passed {enclave_platform}")
    if os.path.isfile(lib_name):
        if ext not in lib_name:
            raise ValueError(f"{mode} requires {ext} enclave image")
        return lib_name
    else:
        # Make sure relative paths include current directory. Absolute paths will be unaffected
        return os.path.join(library_dir, os.path.normpath(f"{lib_name}{ext}"))


def build_bin_path(bin_name, binary_dir="."):
    return os.path.join(binary_dir, os.path.normpath(bin_name))


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
        # null-terminated certs, for compatibility
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


def create_dir(dir_path):
    # Remove directory if it already exists
    if os.path.isdir(dir_path):
        rmtree(dir_path)
    os.mkdir(dir_path)


def copy_dir(src_path, dst_path):
    copy2(src_path, dst_path)


def compute_file_checksum(file_name):
    h = hashlib.sha256()
    with open(file_name, "rb") as f:
        for b in iter(lambda: f.read(4096), b""):
            h.update(b)
    return h.hexdigest()


@contextmanager
def working_dir(path):
    cwd = os.getcwd()
    LOG.info("cd {}".format(path))
    os.chdir(path)
    try:
        yield
    finally:
        os.chdir(cwd)
