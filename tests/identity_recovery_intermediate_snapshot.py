# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
#
# Regression guard for the network-identity bootstrap fix (join-from-stale
# snapshot). It complements recovery_stale_snapshot_join_test by exercising the
# second, HARDER failure mode: an intermediate stale service view that, without
# the fix, aborts node startup with
#
#   Failed fetching network identity: Current service identity public key <A>
#   does not match the last endorsing key <B>
#
# (build_trusted_key_chain()'s final anchor check,
# src/node/rpc/network_identity_subsystem.h).
#
# Endorsement model (src/node/rpc/network_identity_chain_helpers.h and
# src/service/internal_tables_access.h::endorse_previous_identity):
#   * genesis identity I0 writes a self-endorsement e0;
#   * recovery 1 (I0 -> I1) writes e1 (endorsing_key = I1, endorses I0,
#     previous_version -> e0), so e1 is NON-self;
#   * recovery 2 (I1 -> I2) writes e2 (endorsing_key = I2, endorses I1).
#
# A node joining the final I2 service from an INTERMEDIATE (I1-epoch) snapshot
# settles its network-identity fetch while its KV still shows the I1 service as
# current. get_current_endorsement() returns e1 (non-self), so the subsystem
# walks e1 -> e0 and builds a chain whose newest endorsing key is I1 - but the
# node's attested identity (from the join response) is I2.
#
#   * WITHOUT the fix: build_trusted_key_chain()'s anchor check I2 == I1 throws
#     and fail_fetching() aborts startup, so the node never joins - this test
#     FAILS.
#   * WITH the fix: fetch_first() compares the topmost endorsement's signing key
#     against the current identity first, sees the mismatch, and reschedules
#     itself instead of settling. The joiner keeps retrying while it replicates
#     the recovery-2 suffix from the primary, then settles once its view reaches
#     I2 and serves a trusted-key set spanning both recoveries - this test PASSES.
#
# The joiner is given ONLY the committed ledger up to the first recovery
# (read_only_ledger_dirs from the I1 network). That deterministically forces the
# intermediate stale view - it has no local ledger for recovery 2, so it cannot
# advance past I1 before the first fetch - and also provides the genesis ledger
# needed to serve the historical read of e0 while walking the chain back.
import os
import shutil
import time
import http

import infra.e2e_args
import infra.network
import infra.node
import infra.crypto
import suite.test_requirements as reqs
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from infra.runner import ConcurrentRunner
from loguru import logger as LOG


def do_recovery(network, args):
    """Perform one full recovery cycle, returning (recovered_network,
    committed_ledger_dirs) where committed_ledger_dirs is the committed ledger of
    the service being recovered FROM (i.e. everything up to, but not including,
    this recovery's new epoch)."""
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


def preserve_committed_snapshot(network, dest_name):
    """Force and copy the earliest committed snapshot of the currently-running
    (recovered) network into a dedicated directory, returning that directory."""
    primary, _ = network.find_primary()
    committed_snapshots_dir = network.get_committed_snapshots(primary)
    snapshots = sorted(
        os.listdir(committed_snapshots_dir),
        key=lambda name: infra.node.get_snapshot_seqnos(name)[0],
    )
    assert snapshots, "Expected at least one committed snapshot in this epoch"
    chosen = snapshots[0]
    dest_dir = os.path.join(network.common_dir, dest_name)
    os.makedirs(dest_dir, exist_ok=True)
    shutil.copy(os.path.join(committed_snapshots_dir, chosen), dest_dir)
    LOG.info(f"Preserved intermediate-epoch snapshot {chosen} in {dest_dir}")
    return dest_dir


def get_trusted_keys_when_ready(node, timeout=60):
    """Poll the logging app's trusted_keys endpoint until the node's network
    identity subsystem has settled, returning the final response. The handler
    raises (so the endpoint returns an error) until the endorsement chain has
    been fetched; that fetch is asynchronous and not awaited by trust_node."""
    deadline = time.time() + timeout
    while True:
        with node.client() as cli:
            r = cli.get("/log/public/trusted_keys")
        if r.status_code == http.HTTPStatus.OK or time.time() > deadline:
            return r
        time.sleep(0.2)


def verify_cross_recovery_identity_chain(node):
    """Functionally verify that `node` serves a network-identity trusted-key set
    spanning BOTH recoveries. Those keys are only populated once the node has
    built and signature-verified the endorsement chain across the recovery
    boundaries from its intermediate snapshot. Without the fix the node aborts
    before this endpoint ever becomes ready."""
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
    # The chain spans two recoveries (I0 -> I1 -> I2), so it must expose at least
    # the current identity plus a prior one; in practice all three keys.
    assert len(trusted_keys_der) >= 2, (
        "Joined node's trusted keys do not span the recoveries "
        f"(only {len(trusted_keys_der)} key)"
    )
    LOG.success(
        f"Joined node serves {len(trusted_keys_der)} trusted keys spanning both "
        "recoveries, built from its intermediate snapshot"
    )


@reqs.description(
    "A node joining a twice-recovered service from an intermediate (first "
    "recovery) snapshot catches up and serves a trusted-key set spanning both "
    "recoveries"
)
def test_join_from_intermediate_recovery_snapshot(network, args):
    # --- Recovery 1: I0 -> I1 -------------------------------------------------
    net1, _ = do_recovery(network, args)
    LOG.success("First recovery complete (I0 -> I1)")

    # Capture an I1-epoch committed snapshot (taken after e1 was written) BEFORE
    # the second recovery, while the I1 network is still running.
    intermediate_snapshot_dir = preserve_committed_snapshot(
        net1, "intermediate_i1_snapshot"
    )

    # --- Recovery 2: I1 -> I2 -------------------------------------------------
    # do_recovery returns the committed ledger of the service being recovered
    # from, i.e. genesis..I1 - exactly the window the joiner is pinned to.
    net2, i1_committed_ledger_dirs = do_recovery(net1, args)
    LOG.success("Second recovery complete (I1 -> I2)")

    # --- Join a node to I2 from the I1-epoch snapshot, pinned to genesis..I1 ---
    # Without the fix, the joiner reads the stale I1 endorsement (e1) as current
    # and aborts on the anchor check, so join/trust below fails. With the fix it
    # retries until it has replicated past recovery 2 and then settles.
    new_node = net2.create_node()
    net2.join_node(
        new_node,
        args.package,
        args,
        from_snapshot=True,
        snapshots_dir=intermediate_snapshot_dir,
        read_only_ledger_dirs=i1_committed_ledger_dirs,
        copy_ledger=False,
    )
    net2.trust_node(new_node, args)
    LOG.success("New node joined from the intermediate snapshot and caught up")

    # Functional end-to-end check: the joined node must serve a trusted-key set
    # that spans both recoveries. That is only possible once it has built the
    # identity chain across the recovery boundaries from its intermediate
    # snapshot; had the fix regressed, bootstrap would abort and the endpoint
    # would never become ready.
    verify_cross_recovery_identity_chain(new_node)

    return net2


def run(args):
    with infra.network.network(
        args.nodes,
        args.binary_dir,
        args.debug_nodes,
        pdb=args.pdb,
    ) as network:
        network.start_and_open(args)
        network = test_join_from_intermediate_recovery_snapshot(network, args)
        # test_join_from_intermediate_recovery_snapshot returns the final
        # recovered Network; stop it explicitly here since the context manager
        # only stops the original Network instance it created.
        network.stop_all_nodes()


if __name__ == "__main__":

    def add(parser):
        parser.description = (
            "Reproduce a node joining a twice-recovered service from an "
            "intermediate (first-recovery) snapshot, and verify it catches up "
            "and serves a trusted-key set spanning both recoveries."
        )

    cr = ConcurrentRunner(add)

    cr.add(
        "recovery_intermediate_snapshot_join",
        run,
        package="samples/apps/logging/logging",
        nodes=infra.e2e_args.min_nodes(cr.args, f=1),
        ledger_chunk_bytes="12KB",
        snapshot_tx_interval=10,
        sig_tx_interval=1,
    )

    cr.run()
