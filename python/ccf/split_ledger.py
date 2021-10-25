# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.


import ccf.ledger
import sys
import argparse
import os

from loguru import logger as LOG

DEFAULT_OUTPUT_FOLDER_NAME = "split_ledger"
TEMPORARY_LEDGER_FILE_NAME = "ledger_split.tmp"


def create_new_ledger_file(directory: str):
    ledger_file_name = os.path.join(directory, TEMPORARY_LEDGER_FILE_NAME)
    ledger_file = open(ledger_file_name, "wb")
    ledger_file.write(
        int.to_bytes(0, length=ccf.ledger.LEDGER_HEADER_SIZE, byteorder="little")
    )
    return ledger_file, ledger_file_name


def make_final_ledger_file_name(start_seqno, end_seqno, is_committed):
    return f'ledger_{start_seqno}-{end_seqno}{ccf.ledger.COMMITTED_FILE_SUFFIX if is_committed else ""}'


def run(args_):
    parser = argparse.ArgumentParser(description="Read CCF ledger or snapshot")
    parser.add_argument("path", help="Path to ledger file to split", type=str)
    parser.add_argument(
        "seqno",
        help="Transaction sequence number at which the ledger file will be split",
        type=int,
    )
    parser.add_argument(
        "--output-folder",
        help="Output folder",
        type=str,
        default=DEFAULT_OUTPUT_FOLDER_NAME,
    )
    args = parser.parse_args(args_)

    is_input_file_committed = ccf.ledger.is_ledger_chunk_committed(args.path)

    LOG.info(f"Output folder: {args.output_folder}")
    os.mkdir(args.output_folder)

    # TODO: What if chunk isn't committed?
    # TODO: If chunk isn't committed, should first chunk be completed and second no?

    ledger_file_input = ccf.ledger.LedgerChunk(args.path)
    is_input_file_complete = ledger_file_input.is_complete()
    is_input_file_committed = ledger_file_input.is_committed()
    LOG.info(
        f'Splitting ledger "{args.path}" [complete: {is_input_file_complete}/committed: {is_input_file_committed}] at seqno {args.seqno}'
    )

    create_new_file = True  # TODO: Rename
    found_target_seqno = False
    first_seqno = None

    for entry in ledger_file_input:
        if create_new_file:
            ledger_file_output, ledger_file_output_name = create_new_ledger_file(
                args.output_folder
            )
            entry_positions = []
            create_new_file = False

        public_entry = entry.get_public_domain()
        entry_seqno = public_entry.get_seqno()
        LOG.info(entry_seqno)

        first_seqno = first_seqno or entry_seqno

        entry_positions.append(ledger_file_output.tell())
        LOG.warning(f"Positions: {entry_positions}")
        ledger_file_output.write(entry.get_raw_tx())

        if entry_seqno == args.seqno:
            LOG.success(f"Found seqno {args.seqno}")
            if ccf.ledger.SIGNATURE_TX_TABLE_NAME not in public_entry.get_tables():
                raise ValueError(
                    f"Ledger entry at target {entry_seqno} is not a signature"
                )
            found_target_seqno = True
            LOG.warning(f"Positions: {entry_positions}")
            positions_offset = ledger_file_output.tell()
            for pos in entry_positions:
                ledger_file_output.write(
                    int.to_bytes(pos, length=4, byteorder="little")
                )
            ledger_file_output.seek(0)
            ledger_file_output.write(
                int.to_bytes(
                    positions_offset,
                    length=ccf.ledger.LEDGER_HEADER_SIZE,
                    byteorder="little",
                )
            )

            ledger_file_output.close()
            os.rename(
                ledger_file_output_name,
                os.path.join(
                    args.output_folder,
                    make_final_ledger_file_name(
                        first_seqno, args.seqno, is_input_file_committed
                    ),
                ),
            )
            create_new_file = True

    if not found_target_seqno:
        os.remove(ledger_file_output_name)
        raise ValueError(
            f"Could not find seqno {args.seqno} in ledger file {args.path}"
        )

    if not create_new_file:
        ledger_file_output.close()
        os.rename(
            ledger_file_output_name,
            os.path.join(
                args.output_folder,
                make_final_ledger_file_name(
                    args.seqno, entry_seqno, is_input_file_committed
                ),
            ),
        )


if __name__ == "__main__":

    LOG.remove()
    LOG.add(
        sys.stdout,
        format="<level>{message}</level>",
    )

    run(sys.argv[1:])
