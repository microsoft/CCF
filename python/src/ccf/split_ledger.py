# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import ccf.ledger
import sys
import argparse
import os
from typing import BinaryIO, List

from loguru import logger as LOG

DEFAULT_OUTPUT_DIR_NAME = "split_ledger"
TEMPORARY_LEDGER_FILE_NAME = "ledger.tmp"


def create_new_ledger_file(directory: str) -> BinaryIO:
    ledger_file_path = os.path.join(directory, TEMPORARY_LEDGER_FILE_NAME)
    if os.path.exists(ledger_file_path):
        raise ValueError(f"Ledger file {ledger_file_path} already exists")
    ledger_file = open(ledger_file_path, "wb")
    ledger_file.write(
        int.to_bytes(0, length=ccf.ledger.LEDGER_HEADER_SIZE, byteorder="little")
    )
    return ledger_file


def make_final_ledger_file_name(
    start_seqno: int,
    end_seqno: int,
    is_complete: bool,
    is_committed: bool,
) -> str:
    file_name = f"ledger_{start_seqno}"
    if is_complete:
        file_name += f"-{end_seqno}"
    if is_committed:
        assert is_complete, "All committed ledger files should be complete"
        file_name += ccf.ledger.COMMITTED_FILE_SUFFIX
    return file_name


def close_ledger_file(
    ledger_file, entry_positions: List[int], final_file_name: str, complete_file=True
):
    if complete_file:
        positions_offset = ledger_file.tell()
        for pos in entry_positions:
            ledger_file.write(int.to_bytes(pos, length=4, byteorder="little"))
        ledger_file.seek(0)
        ledger_file.write(
            int.to_bytes(
                positions_offset,
                length=ccf.ledger.LEDGER_HEADER_SIZE,
                byteorder="little",
            )
        )
    ledger_file.close()
    os.rename(
        ledger_file.name,
        os.path.join(os.path.dirname(ledger_file.name), final_file_name),
    )
    LOG.info(f"Wrote new ledger file: {final_file_name} (complete: {complete_file})")


def run(args_):
    parser = argparse.ArgumentParser(
        description="Split a CCF ledger file around an input sequenece number into two new files",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("path", help="Path to ledger file to split", type=str)
    parser.add_argument(
        "seqno",
        help="Transaction seqno at which the ledger file will be split (must be a signature transaction)",
        type=int,
    )
    parser.add_argument(
        "--output-dir",
        help="Output directory",
        type=str,
        default=DEFAULT_OUTPUT_DIR_NAME,
    )
    args = parser.parse_args(args_)

    if not os.path.exists(args.output_dir):
        os.mkdir(args.output_dir)

    ledger_file_input = ccf.ledger.LedgerChunk(args.path)
    is_input_file_complete = ledger_file_input.is_complete()
    is_input_file_committed = ledger_file_input.is_committed()
    LOG.info(
        f"Splitting ledger file {args.path} (complete: {is_input_file_complete}/committed: {is_input_file_committed}) at seqno {args.seqno}"
    )
    LOG.info(f"Output directory: {args.output_dir}")

    require_new_file = True
    found_target_seqno = False
    first_seqno = None
    is_target_seqno_signature = True
    next_signature_seqno = None

    for entry in ledger_file_input:
        public_entry = entry.get_public_domain()
        entry_seqno = public_entry.get_seqno()
        first_seqno = first_seqno or entry_seqno
        if require_new_file:
            ledger_file_output = create_new_ledger_file(args.output_dir)
            entry_positions = []
            require_new_file = False

        entry_positions.append(ledger_file_output.tell())
        ledger_file_output.write(entry.get_raw_tx())

        if (
            not is_target_seqno_signature
            and ccf.ledger.SIGNATURE_TX_TABLE_NAME in public_entry.get_tables()
        ):
            next_signature_seqno = entry_seqno
            break

        if entry_seqno == args.seqno:
            if ccf.ledger.SIGNATURE_TX_TABLE_NAME not in public_entry.get_tables():
                is_target_seqno_signature = False
                continue

            LOG.debug(f"Found target seqno {args.seqno}")
            found_target_seqno = True
            close_ledger_file(
                ledger_file_output,
                entry_positions,
                make_final_ledger_file_name(
                    first_seqno,
                    args.seqno,
                    is_complete=True,
                    is_committed=is_input_file_committed,
                ),
                complete_file=True,
            )
            require_new_file = True

    if next_signature_seqno is not None:
        os.remove(ledger_file_output.name)
        raise ValueError(
            f"Ledger entry at target seqno {args.seqno} must be a signature. Next signature is at seqno {next_signature_seqno}."
        )

    if not found_target_seqno:
        os.remove(ledger_file_output.name)
        raise ValueError(
            f"Could not find seqno {args.seqno} in ledger file {args.path}"
        )

    # Only if entries were written to file
    if not require_new_file:
        close_ledger_file(
            ledger_file_output,
            entry_positions,
            make_final_ledger_file_name(
                args.seqno + 1,
                entry_seqno,
                is_complete=is_input_file_complete,
                is_committed=is_input_file_committed,
            ),
            complete_file=is_input_file_complete,
        )
        return True

    # No split was performed since target seqno is already
    # last seqno in ledger file
    return False


def main():
    LOG.remove()
    LOG.add(
        sys.stdout,
        format="<level>{message}</level>",
    )

    run(sys.argv[1:])
