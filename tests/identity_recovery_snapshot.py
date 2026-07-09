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
import suite.test_requirements as reqs
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from infra.runner import ConcurrentRunner
from loguru import logger as LOG

# Logged by the network identity subsystem (network_identity_subsystem.h) when a
# joining node detects a stale pre-recovery topmost endorsement and retries.
# Whether it appears is a startup race, so it is only surfaced best-effort here;
# network_identity_subsystem_test is the deterministic regression test for it.
STALE_IDENTITY_RETRY_LOG = "signed by a stale service identity"


def preserve_oldest_committed_snapshot(network, primary, dest_name):
    """Copy the oldest committed snapshot into a dedicated directory and return
    that directory."""
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


def verify_cross_recovery_identity_chain(node):
    """Functionally verify that `node` serves a network-identity trusted-key set
    spanning the recovery. The logging app's trusted_keys endpoint returns the
    keys produced by the subsystem's get_trusted_keys(); those are only populated
    once the node has built the identity chain across the recovery boundary from
    its pre-recovery snapshot, and only after build_trusted_key_chain() has
    signature-verified every COSE endorsement in that chain. So a successful
    response containing the recovered identity plus a prior identity is proof the
    cross-recovery chain was built and verified end to end."""
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
    # A chain that spans the recovery has at least two keys: the current
    # (recovered) identity and the pre-recovery identity it endorses.
    assert len(trusted_keys_der) >= 2, (
        "Joined node's trusted keys do not span the recovery "
        f"(only {len(trusted_keys_der)} key)"
    )
    LOG.success(
        f"Joined node serves {len(trusted_keys_der)} trusted keys spanning the "
        "recovery, built from its pre-recovery snapshot"
    )


@reqs.description(
    "A node joining from a pre-recovery snapshot catches up and serves a "
    "trusted-key set spanning the recovery"
)
def test_join_from_stale_pre_recovery_snapshot(network, args):
    # Capture a committed snapshot from before the recovery. A node started from
    # this snapshot sees the OLD (pre-recovery) service identity as current until
    # it replays the committed ledger suffix that includes the recovery.
    primary, _ = network.find_primary()
    stale_snapshots_dir = preserve_oldest_committed_snapshot(
        network, primary, "stale_pre_recovery_snapshot"
    )

    # Disaster-recover the service. Recovery mints a new network identity which
    # endorses the previous one, extending the identity endorsement chain and
    # changing the service identity that new nodes are handed when they join.
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
    LOG.success("Service recovered under a new network identity")

    # Add a new node that joins the recovered service from the STALE snapshot,
    # replaying the ledger suffix from the primary. copy_ledger=False keeps the
    # joining node's local store at the snapshot state initially (the realistic
    # production join path), so its bootstrap has to walk the identity chain
    # across the recovery boundary before it can settle.
    new_node = recovered_network.create_node()
    recovered_network.join_node(
        new_node,
        args.package,
        args,
        from_snapshot=True,
        snapshots_dir=stale_snapshots_dir,
        copy_ledger=False,
    )
    recovered_network.trust_node(new_node, args)
    LOG.success("New node joined from the stale pre-recovery snapshot and caught up")

    # Functional end-to-end check: the joined node must serve a trusted-key set
    # that spans the recovery. That is only possible once it has built the
    # identity chain across the recovery boundary from its pre-recovery snapshot;
    # had that regressed, bootstrap would fail and the endpoint would never
    # become ready.
    verify_cross_recovery_identity_chain(new_node)

    # Best-effort: surface it if the startup race lined up and the node also hit
    # the stale-identity retry path. Not asserted - that race cannot be forced via
    # the join API; network_identity_subsystem_test covers it deterministically.
    out_path, _ = new_node.get_logs()
    if out_path is not None:
        with open(out_path, encoding="utf-8") as f:
            if STALE_IDENTITY_RETRY_LOG in f.read():
                LOG.success(
                    "Joined node also exercised the stale pre-recovery identity "
                    "retry path"
                )

    return recovered_network


def run(args):
    with infra.network.network(
        args.nodes,
        args.binary_dir,
        args.debug_nodes,
        pdb=args.pdb,
    ) as network:
        network.start_and_open(args)
        network = test_join_from_stale_pre_recovery_snapshot(network, args)
        # test_join_from_stale_pre_recovery_snapshot returns a fresh recovered
        # Network; stop it explicitly here since the context manager only stops
        # the original Network instance it created.
        network.stop_all_nodes()


if __name__ == "__main__":

    def add(parser):
        parser.description = (
            "Reproduce a node joining a recovered service from a snapshot taken "
            "before the recovery, and verify it catches up once the recovery is "
            "replayed."
        )

    cr = ConcurrentRunner(add)

    cr.add(
        "recovery_stale_snapshot_join",
        run,
        package="samples/apps/logging/logging",
        nodes=infra.e2e_args.min_nodes(cr.args, f=1),
        ledger_chunk_bytes="50KB",
        snapshot_tx_interval=10,
    )

    cr.run()
