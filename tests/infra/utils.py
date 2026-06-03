# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import infra.path
from hashlib import sha256
import infra.snp as snp
from infra.node import strip_version
from packaging.version import Version  # type: ignore
import os
import ccf
import ccf.ledger
import ccf.split_ledger
import infra.proc

from loguru import logger as LOG


FORCE_LEDGER_CHUNK_AFTER = 0x01


def get_measurement(enclave_type, enclave_platform, package, library_dir="."):
    if enclave_platform == "virtual":
        return "Insecure hard-coded virtual measurement v1"

    else:
        raise ValueError(f"Cannot get measurement on {enclave_platform}")


def get_host_data_and_security_policy(
    enclave_type, enclave_platform, package, library_dir="."
):
    lib_path = infra.path.build_lib_path(
        package, enclave_type, enclave_platform, library_dir
    )
    if enclave_platform == "snp":
        security_policy = snp.get_container_group_security_policy()
        host_data = sha256(security_policy.encode()).hexdigest()
        return host_data, security_policy
    elif enclave_platform == "virtual":
        hash = sha256(open(lib_path, "rb").read())
        return hash.hexdigest(), None
    else:
        raise ValueError(f"Cannot get security policy on {enclave_platform}")


def write_ledger_chunk(outdir, entries, end_seqno, complete):
    os.makedirs(outdir, exist_ok=True)
    selected_entries = [(s, raw) for s, raw in entries if s <= end_seqno]
    assert selected_entries, f"No entries selected up to {end_seqno}"

    ledger_file = ccf.split_ledger.create_new_ledger_file(outdir)
    if complete:
        final_seqno, final_raw_tx = selected_entries[-1]
        flagged_final_raw_tx = bytearray(final_raw_tx)
        flagged_final_raw_tx[
            ccf.ledger.TransactionHeader.VERSION_LENGTH
        ] |= FORCE_LEDGER_CHUNK_AFTER
        selected_entries[-1] = (final_seqno, bytes(flagged_final_raw_tx))

    entry_positions = []
    for _, raw_tx in selected_entries:
        entry_positions.append(ledger_file.tell())
        ledger_file.write(raw_tx)

    start_seqno = selected_entries[0][0]
    final_seqno = selected_entries[-1][0]
    final_file_name = ccf.split_ledger.make_final_ledger_file_name(
        start_seqno,
        final_seqno,
        is_complete=complete,
        is_committed=False,
    )
    ccf.split_ledger.close_ledger_file(
        ledger_file, entry_positions, final_file_name, complete_file=complete
    )
    LOG.info(
        f"Created recovery ledger variant {outdir}: {final_file_name} "
        f"complete={complete}"
    )
