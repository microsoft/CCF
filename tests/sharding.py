# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import http
import infra.network
import infra.e2e_args
import suite.test_requirements as reqs
from infra.runner import ConcurrentRunner

from loguru import logger as LOG


@reqs.description("Test seal_current_shard governance proposal")
def test_seal_current_shard(network, args):
    primary, _ = network.find_nodes()

    LOG.info("Sealing the current shard via governance proposal")
    network.consortium.seal_current_shard(primary)

    LOG.info("Verifying shard table was updated")
    with primary.client("member0") as c:
        r = c.get("/gov/kv/public:ccf.gov.shards.info")
        if r.status_code == http.HTTPStatus.OK.value:
            LOG.info(f"Shards table contents: {r.body.json()}")

    return network


@reqs.description("Test set_shard_policy governance proposal")
def test_set_shard_policy(network, args):
    primary, _ = network.find_nodes()

    LOG.info("Setting shard policy via governance proposal")
    network.consortium.set_shard_policy(
        primary,
        auto_seal_after_seqno_count=5000,
        auto_seal_after_duration_s=3600,
        max_active_shard_memory_mb=512,
    )

    LOG.info("Verifying shard policy table was updated")
    with primary.client("member0") as c:
        r = c.get("/gov/kv/public:ccf.gov.shards.policy")
        if r.status_code == http.HTTPStatus.OK.value:
            LOG.info(f"Shard policy: {r.body.json()}")

    return network


@reqs.description("Test full shard lifecycle: create, seal, verify")
def test_shard_lifecycle(network, args):
    primary, _ = network.find_nodes()

    LOG.info("Step 1: Set shard policy")
    network.consortium.set_shard_policy(
        primary,
        auto_seal_after_seqno_count=10000,
    )

    LOG.info("Step 2: Issue some transactions")
    network.txs.issue(network, number_txs=10)

    LOG.info("Step 3: Seal the current shard")
    network.consortium.seal_current_shard(primary)

    LOG.info("Step 4: Issue more transactions on the new shard")
    network.txs.issue(network, number_txs=10)

    LOG.info("Step 5: Seal the second shard")
    network.consortium.seal_current_shard(primary)

    LOG.info("Step 6: Verify final state")
    with primary.client("member0") as c:
        r = c.get("/gov/kv/public:ccf.gov.shards.info")
        if r.status_code == http.HTTPStatus.OK.value:
            LOG.info(f"Final shards state: {r.body.json()}")

    return network


def run(args):
    with infra.network.network(
        args.nodes,
        args.binary_dir,
        args.debug_nodes,
        args.perf_nodes,
        pdb=args.pdb,
    ) as network:
        network.start_and_open(args)

        test_set_shard_policy(network, args)
        test_seal_current_shard(network, args)
        test_shard_lifecycle(network, args)


if __name__ == "__main__":
    cr = ConcurrentRunner()

    cr.add(
        "sharding",
        run,
        package="samples/apps/logging/logging",
        nodes=infra.e2e_args.min_nodes(cr.args, f=0),
        sharding_enabled=True,
    )

    cr.run()
