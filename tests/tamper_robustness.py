# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import http
import infra.network
import infra.e2e_args
import infra.commit
import suite.test_requirements as reqs
from e2e_logging import get_all_entries
import os
import re
import random
import contextlib
import tempfile

from loguru import logger as LOG

TARGET_ID = 1


def get_node_root_dir(node):
    assert isinstance(node.remote.remote, infra.remote.LocalRemote), node.remote.remote
    assert os.path.isdir(node.remote.remote.root), node.remote.remote.root
    return node.remote.remote.root


def get_index_dir(node_root):
    return os.path.join(node_root, ".index")


def get_ledger_dir(node_root):
    for path in os.listdir(node_root):
        if ".ledger" in path:
            return os.path.join(node_root, path)
    raise RuntimeError(f"No ledger directory found within {node_root}")


def sorted_committed_files(ledger_dir):
    regex = re.compile("ledger_(\d+)-(\d+).committed")
    committed = []
    for file in os.listdir(ledger_dir):
        if m := regex.match(file):
            committed.append((int(m[1]), int(m[2]), file))
    committed.sort()
    return [os.path.join(ledger_dir, file) for _, _, file in committed]


def produce_tamperable_files(network, args):
    primary, _ = network.find_primary()

    with primary.client("user0") as c:
        node_root = get_node_root_dir(primary)

        desired_non_empty_dirs = [get_index_dir(node_root), get_ledger_dir(node_root)]

        def empty_dir(p):
            return len(os.listdir(p)) == 0

        loops = 0
        loop_limit = 10
        while any(empty_dir(p) for p in desired_non_empty_dirs):
            if loops > loop_limit:
                raise RuntimeError(
                    f"Failed to produce ledger and index after {loop_limit} loops"
                )
            loops += 1

            # Post several new entries, then fetch the latest historically
            num_entries = 500
            LOG.info(f"Posting {num_entries} new entries in loop #{loops}")
            for i in range(num_entries):
                r = c.post(
                    "/app/log/public",
                    {"id": TARGET_ID, "msg": f"Hello world: {loops}:{i}"},
                    log_capture=[],
                )
                assert r.status_code == http.HTTPStatus.OK, (
                    r.status_code,
                    r.body.text(),
                )

            infra.commit.wait_for_commit(c, seqno=r.seqno, view=r.view)

            get_all_entries(c, TARGET_ID, from_seqno=r.seqno, to_seqno=r.seqno)

        LOG.info("Populated interesting dirs:")
        for p in desired_non_empty_dirs:
            LOG.info(f"  {p} contains {len(os.listdir(p))} files")


@contextlib.contextmanager
def hide_file(src_path):
    with tempfile.TemporaryDirectory(dir=os.path.dirname(src_path)) as tmp_dir_name:
        dst_path = os.path.join(tmp_dir_name, os.path.basename(src_path))
        LOG.warning(f"Temporarily hiding file {src_path} => {dst_path}")
        os.rename(src_path, dst_path)
        yield
        os.rename(dst_path, src_path)


@reqs.description("Temporarily remove chunks from ledger")
def test_ledger_chunk_removal(network, args):
    primary, _ = network.find_primary()

    primary_dir = get_node_root_dir(primary)
    ledger_dir = get_ledger_dir(primary_dir)

    with primary.client("user0") as c:
        LOG.info("All entries can be retrieved initially")
        all_entries_before, _ = get_all_entries(c, TARGET_ID)

        committed_files = sorted_committed_files(ledger_dir)
        target_file = committed_files[-1]
        LOG.info(
            f"Historical audit times out while final committed ledger chunk {os.path.basename(target_file)} is unavailable"
        )
        with hide_file(target_file):
            try:
                get_all_entries(c, TARGET_ID, flush_on_timeout=False)
                raise RuntimeError(
                    "Historical audit unexpectedly succeeded despite missing file"
                )
            except TimeoutError:
                pass

        LOG.info("All entries can be retrieved once file is restored")
        all_entries_after, _ = get_all_entries(c, TARGET_ID)
        assert all_entries_before == all_entries_after

        for _ in range(5):
            target_file = random.choice(committed_files)
            LOG.info(
                f"Historical audit times out while {os.path.basename(target_file)} is unavailable"
            )
            with hide_file(target_file):
                try:
                    get_all_entries(c, TARGET_ID, flush_on_timeout=False)
                    raise RuntimeError(
                        "Historical audit unexpectedly succeeded despite missing file"
                    )
                except TimeoutError:
                    pass
            LOG.info("All entries can be retrieved once file is restored")
            all_entries_after, _ = get_all_entries(c, TARGET_ID)
            assert all_entries_before == all_entries_after


def run(args):
    with infra.network.network(
        args.nodes, args.binary_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
    ) as network:
        network.start_and_open(args)

        produce_tamperable_files(network, args)

        test_ledger_truncation(network, args)


if __name__ == "__main__":

    args = infra.e2e_args.cli_args()
    args.package = "samples/apps/logging/liblogging"

    args.nodes = infra.e2e_args.min_nodes(args, f=1)
    run(args)
