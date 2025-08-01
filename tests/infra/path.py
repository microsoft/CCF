# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import os
from contextlib import contextmanager
from shutil import copy2, rmtree
import hashlib
import infra.node
import infra.platform_detection
from packaging.version import Version  # type: ignore

from loguru import logger as LOG


def mk(name, contents):
    LOG.info('echo "<{} bytes>" > {}'.format(len(contents), name))
    with open(name, "w", encoding="utf-8") as dst:
        dst.write(contents)


def mk_new(name, contents):
    if not os.path.isfile(name):
        LOG.debug('Creating file at "{}" containing "{}"'.format(name, contents))
        mk(name, contents)


def build_lib_path(lib_name, library_dir=".", version=None):
    if not lib_name.startswith("lib"):
        lib_name = f"lib{lib_name}"

    if version is None or Version(infra.node.strip_version(version)).major >= 7:
        ext = ".so"
    else:
        if infra.platform_detection.is_virtual():
            ext = ".virtual.so"
        elif infra.platform_detection.is_snp():
            ext = ".snp.so"

    if infra.platform_detection.is_virtual():
        mode = "Virtual mode"
    elif infra.platform_detection.is_snp():
        mode = "SNP enclave"
    else:
        raise ValueError(
            f"Unexpected platform: {infra.platform_detection.get_platform()}"
        )

    if os.path.isfile(lib_name):
        if ext not in lib_name:
            raise ValueError(
                f"{mode} requires {ext} enclave image (could not find {lib_name})"
            )
        return lib_name
    else:
        # Make sure relative paths include current directory. Absolute paths will be unaffected
        return os.path.join(library_dir, os.path.normpath(f"{lib_name}{ext}"))


def build_bin_path(bin_name, binary_dir="."):
    return os.path.join(binary_dir, os.path.normpath(bin_name))


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
