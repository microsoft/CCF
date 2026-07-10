# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import os
import shutil
import time
import http

import infra.e2e_args
import infra.network
import infra.node
import infra.crypto
import infra.logging_app as app
import suite.test_requirements as reqs
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from infra.runner import ConcurrentRunner
from loguru import logger as LOG

# Emitted by a joining node when it observes a topmost endorsement signed by a key
# that differs from its current (recovered) network identity - i.e. it read the
# service as OPEN with the stale pre-recovery endorsement before the recovery
# re-endorsement replicated.
STALE_IDENTITY_RETRY_LOG = (
    "differs from the expected current network identity public key"
)

# To make the joiner deterministically pass through the stale-identity window, the
# pre-recovery ledger is lengthened with these throwaway txns. The joiner starts
# from a snapshot taken before the service opened, so its byte-bound catch-up must
# replay this whole suffix; that keeps it in the [service-open, recovery-endorsement]
# window for several fetch_first poll intervals. They are issued repeatedly against
# a single key so the KV (and therefore snapshots) stay small and cheap.
PRE_RECOVERY_TXS = 250
PRE_RECOVERY_TX_MSG = "x" * (14 * 1024)


def recover(network, args):
    """Recover a service and return its new network and the old committed ledger."""
    network.save_service_identity(args)
    primary, _ = network.find_primary()
    current_ledger_dir, committed_ledger_dirs = primary.get_ledger()
    network.stop_all_nodes()

    recovered_network = infra.network.Network(
        args.nodes,
        args.binary_dir,
        args.debug_nodes,
        existing_network=network,
    )
    recovered_network.start_in_recovery(
        args,
        ledger_dir=current_ledger_dir,
        committed_ledger_dirs=committed_ledger_dirs,
    )
    recovered_network.recover(args)
    return recovered_network, committed_ledger_dirs


def preserve_oldest_committed_snapshot(network, dest_name):
    """Copy the oldest committed snapshot into a dedicated directory and return
    that directory."""
    primary, _ = network.find_primary()
    committed_snapshots_dir = network.get_committed_snapshots(primary)
    snapshots = sorted(
        os.listdir(committed_snapshots_dir),
        key=lambda name: infra.node.get_snapshot_seqnos(name)[0],
    )
    assert snapshots, "Expected at least one committed snapshot before recovery"
    oldest = snapshots[0]
    dest_dir = os.path.join(network.common_dir, dest_name)
    os.makedirs(dest_dir, exist_ok=True)
    shutil.copy(os.path.join(committed_snapshots_dir, oldest), dest_dir)
    LOG.info(f"Preserved pre-recovery snapshot {oldest} in {dest_dir}")
    return dest_dir


def get_trusted_keys_when_ready(node, timeout=60):
    """Poll the logging app's trusted_keys endpoint until the node's network
    identity subsystem has settled, returning the final response. The handler
    calls get_trusted_keys(), which raises (so the endpoint returns an error)
    until the endorsement chain has been fetched - that fetch is asynchronous and
    not awaited by trust_node."""
    deadline = time.time() + timeout
    while True:
        with node.client() as cli:
            r = cli.get("/log/public/trusted_keys")
        if r.status_code == http.HTTPStatus.OK or time.time() > deadline:
            return r
        time.sleep(0.2)


def join_from_snapshot(network, args, snapshots_dir, read_only_ledger_dirs=None):
    """Join and trust a node from a specific snapshot and optional ledger prefix."""
    new_node = network.create_node()
    network.join_node(
        new_node,
        args.package,
        args,
        from_snapshot=True,
        snapshots_dir=snapshots_dir,
        read_only_ledger_dirs=read_only_ledger_dirs,
        copy_ledger=False,
    )
    network.trust_node(new_node, args)
    return new_node


def verify_cross_recovery_identity_chain(node, minimum_key_count, description):
    """Functionally verify that `node` serves a network-identity trusted-key set
    spanning the expected recoveries. The logging app's trusted_keys endpoint returns the
    keys produced by the subsystem's get_trusted_keys(); those are only populated
    once the node has built the identity chain across each recovery boundary from
    its snapshot, and only after build_trusted_key_chain() has
    signature-verified every COSE endorsement in that chain. So a successful
    response containing the recovered identities is proof the cross-recovery chain
    was built and verified end to end."""
    with node.client() as cli:
        service_cert = cli.get("/node/network").body.json()["service_certificate"]
    cert = load_pem_x509_certificate(service_cert.encode("ascii"), default_backend())
    current_key_der = bytes(
        cert.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )

    r = get_trusted_keys_when_ready(node)
    assert r.status_code == http.HTTPStatus.OK, r
    jwks = r.body.json()
    assert "keys" in jwks, jwks
    trusted_keys_der = {
        bytes(infra.crypto.pub_key_der_from_jwk(key)) for key in jwks["keys"]
    }

    assert (
        current_key_der in trusted_keys_der
    ), "Joined node's trusted keys do not include the current service identity"
    assert len(trusted_keys_der) >= minimum_key_count, (
        f"Joined node's trusted keys do not span {description} "
        f"(only {len(trusted_keys_der)} key)"
    )
    LOG.success(
        f"Joined node serves {len(trusted_keys_der)} trusted keys spanning "
        f"{description}"
    )


@reqs.description(
    "A node joining from a pre-recovery snapshot catches up and serves a "
    "trusted-key set spanning the recovery"
)
def test_join_from_stale_pre_recovery_snapshot(network, args):
    # Capture a committed snapshot from before the recovery. A node started from
    # this snapshot sees the OLD (pre-recovery) service identity as current until
    # it replays the committed ledger suffix that includes the recovery.
    # Lengthen the pre-recovery ledger so a node joining from an early snapshot has
    # a long suffix to replay, and therefore spends several fetch_first poll
    # intervals catching up through the stale-identity window (see below). Issued
    # against a single key so the KV and snapshots stay small.
    LOG.info(f"Issuing {PRE_RECOVERY_TXS} txs to lengthen the pre-recovery ledger")
    app.LoggingTxs("user0").issue(
        network,
        number_txs=PRE_RECOVERY_TXS,
        msg=PRE_RECOVERY_TX_MSG,
        repeat=True,
        idx=1,
        wait_for_sync=True,
    )

    stale_snapshots_dir = preserve_oldest_committed_snapshot(
        network, "stale_pre_recovery_snapshot"
    )

    # Disaster-recover the service. Recovery mints a new network identity which
    # endorses the previous one, extending the identity endorsement chain and
    # changing the service identity that new nodes are handed when they join.
    recovered_network, _ = recover(network, args)
    LOG.success("Service recovered under a new network identity")

    # Add a new node that joins the recovered service from the STALE (pre-recovery)
    # snapshot and replicates the ledger suffix from the primary (copy_ledger=False,
    # the realistic production path: no ledger files are pre-copied). Because the
    # snapshot predates the recovery, the joiner initially sees the OLD service
    # identity as current and its network-identity bootstrap must walk the
    # endorsement chain across the recovery boundary before it can settle.
    new_node = join_from_snapshot(recovered_network, args, stale_snapshots_dir)
    LOG.success("New node joined from the stale pre-recovery snapshot and caught up")

    # Functional end-to-end check: the joined node must serve a trusted-key set
    # that spans the recovery. That is only possible once it has built the
    # identity chain across the recovery boundary from its pre-recovery snapshot;
    # had that regressed, bootstrap would fail and the endpoint would never
    # become ready.
    verify_cross_recovery_identity_chain(
        new_node,
        minimum_key_count=2,
        description="the recovery from its pre-recovery snapshot",
    )

    # Assert the joiner exercised the stale-identity retry path: with the
    # lengthened ledger above it observes the service OPEN with the stale
    # pre-recovery endorsement (whose endorsing key differs from its recovered
    # identity) while replicating the suffix, and retries until the recovery
    # re-endorsement arrives.
    out_path, _ = new_node.get_logs()
    assert out_path is not None, "joiner produced no output log"
    with open(out_path, encoding="utf-8") as f:
        hits = f.read().count(STALE_IDENTITY_RETRY_LOG)
    assert (
        hits > 0
    ), "joiner did not exercise the stale pre-recovery identity retry path"
    LOG.success(
        f"Joined node exercised the stale pre-recovery identity retry path ({hits} hits)"
    )

    return recovered_network


@reqs.description(
    "A node joining a twice-recovered service from an intermediate (first "
    "recovery) snapshot catches up and serves a trusted-key set spanning both "
    "recoveries"
)
def test_join_from_intermediate_recovery_snapshot(network, args):
    # Recovery 1 (I0 -> I1) writes a non-self endorsement for I0 signed by I1.
    intermediate_network, _ = recover(network, args)
    LOG.success("First recovery complete (I0 -> I1)")

    # Preserve a snapshot from the I1 epoch before the second recovery.
    intermediate_snapshot_dir = preserve_oldest_committed_snapshot(
        intermediate_network, "intermediate_i1_snapshot"
    )

    # Recovery 2 (I1 -> I2) returns the committed genesis..I1 ledger. Supplying
    # that ledger to the joiner pins its initial local view to I1 while still
    # allowing historical reads back to the genesis self-endorsement.
    final_network, intermediate_committed_ledger_dirs = recover(
        intermediate_network, args
    )
    LOG.success("Second recovery complete (I1 -> I2)")

    new_node = join_from_snapshot(
        final_network,
        args,
        intermediate_snapshot_dir,
        read_only_ledger_dirs=intermediate_committed_ledger_dirs,
    )
    LOG.success("New node joined from the intermediate snapshot and caught up")

    # I0 -> I1 -> I2 must produce all three trusted service identities. Without
    # the fix, the joiner instead aborts while its stale I1 chain is anchored to
    # the current I2 identity.
    verify_cross_recovery_identity_chain(
        new_node,
        minimum_key_count=3,
        description="both recoveries from its intermediate snapshot",
    )

    return final_network


def run_test(args, test):
    with infra.network.network(
        args.nodes,
        args.binary_dir,
        args.debug_nodes,
        pdb=args.pdb,
    ) as network:
        network.start_and_open(args)
        network = test(network, args)
        # Each test returns a recovered Network; stop it explicitly since the
        # context manager only stops the original Network instance it created.
        network.stop_all_nodes()


def run_stale_pre_recovery(args):
    run_test(args, test_join_from_stale_pre_recovery_snapshot)


def run_intermediate_recovery(args):
    run_test(args, test_join_from_intermediate_recovery_snapshot)


if __name__ == "__main__":

    def add(parser):
        parser.description = (
            "Verify nodes joining recovered services from stale snapshots catch "
            "up and build the complete network-identity chain."
        )

    cr = ConcurrentRunner(add)

    runner_args = {
        "package": "samples/apps/logging/logging",
        "nodes": infra.e2e_args.min_nodes(cr.args, f=1),
        "ledger_chunk_bytes": "12KB",
        "snapshot_tx_interval": 10,
        "sig_tx_interval": 1,
    }

    cr.add(
        "recovery_stale_snapshot_join",
        run_stale_pre_recovery,
        **runner_args,
    )
    cr.add(
        "recovery_intermediate_snapshot_join",
        run_intermediate_recovery,
        **runner_args,
    )

    cr.run()
