# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import infra.network
import infra.e2e_args
import infra.proc
import infra.logging_app as app
import infra.utils
import infra.github
import infra.jwt_issuer
import infra.crypto
import infra.node
import infra.platform_detection
import suite.test_requirements as reqs
import ccf.ledger
from ccf.tx_id import TxID
import time
import os
import json
import datetime
from e2e_logging import test_random_receipts
from governance import test_all_nodes_cert_renewal, test_service_cert_renewal
from distutils.dir_util import copy_tree
from cryptography import x509
from cryptography.hazmat.backends import default_backend

from loguru import logger as LOG

# Assumption:
# By default, this assumes that the local checkout is not a non-release branch (e.g. main)
# that is older than the latest release branch. This is to simplify the test, and assume
# that the latest release to test compatibility with is the latest available one.
# Use the CCF_LATEST_RELEASE_BRANCH_SUFFIX envvar below if this isn't the case.
ENV_VAR_LATEST_LTS_BRANCH_NAME = (
    "CCF_LATEST_RELEASE_BRANCH_SUFFIX"  # e.g. "release/1.x"
)

LOCAL_CHECKOUT_DIRECTORY = "."

# When a 2.x node joins a 1.x service, the node has to self-endorse
# its certificate, using a default value for the validity period
# hardcoded in CCF.
DEFAULT_NODE_CERTIFICATE_VALIDITY_DAYS = 365


def update_gov_authn(version):
    rv = None
    if not infra.node.version_after(version, "ccf-3.0.0"):
        rv = False
    if infra.node.version_after(version, "ccf-4.0.0-rc0"):
        rv = "COSE"
    LOG.info(f"Setting gov authn to {rv} because version is {version}")
    return rv


def issue_activity_on_live_service(network, args):
    log_capture = []
    network.txs.issue(
        network, number_txs=args.snapshot_tx_interval * 2, log_capture=log_capture
    )

    # At least one transaction that will require historical fetching
    network.txs.issue(network, number_txs=1, repeat=True)

    # At least one transaction that will require forwarding
    network.txs.issue(network, number_txs=1, on_backup=True)


def get_new_constitution_for_install(args, install_path):
    constitution_directory = os.path.join(
        install_path,
        (
            "../samples/constitutions/default"
            if install_path == LOCAL_CHECKOUT_DIRECTORY
            else "bin"
        ),
    )

    def replace_constitution_fragment(args, fragment_name):
        args.constitution[:] = [
            (
                os.path.join(constitution_directory, fragment_name)
                if os.path.basename(f) == fragment_name
                else f
            )
            for f in args.constitution
        ]

    # Note: Use resolve.js script from local checkout as only the trivial sandbox
    # version is included in installation
    replace_constitution_fragment(args, "actions.js")
    replace_constitution_fragment(args, "apply.js")
    replace_constitution_fragment(args, "validate.js")

    return args.constitution


def test_new_service(
    network,
    args,
    install_path,
    binary_dir,
    library_dir,
    version,
    expected_subject_name=None,
    test_jwt_cleanup=False,
):
    if infra.platform_detection.is_snp():
        LOG.info(
            "Skipping backwards compatibility test for AMD nodes until either we patch 2.x or we confirm that we don't need to do a live upgrade"
        )
        return

    LOG.info("Update constitution")
    primary, _ = network.find_primary()
    new_constitution = get_new_constitution_for_install(args, install_path)
    network.consortium.set_constitution(primary, new_constitution)

    all_nodes = network.get_joined_nodes()

    # Note: Changes to constitution between versions should be tested here

    LOG.info("Update JS app")
    js_app_directory = (
        "../samples/apps/logging/js"
        if install_path == LOCAL_CHECKOUT_DIRECTORY
        else os.path.join(install_path, "samples/logging/js")
    )
    network.consortium.set_js_app_from_dir(primary, js_app_directory)

    LOG.info("Add node to new service")

    valid_from = str(infra.crypto.datetime_to_X509time(datetime.datetime.utcnow()))

    kwargs = {}
    kwargs["reconfiguration_type"] = "OneTransaction"

    new_node = network.create_node(
        binary_dir=binary_dir,
        library_dir=library_dir,
        version=version,
    )
    network.join_node(new_node, args.package, args, **kwargs)
    network.trust_node(
        new_node,
        args,
        valid_from=valid_from,
    )
    new_node.verify_certificate_validity_period(
        expected_validity_period_days=DEFAULT_NODE_CERTIFICATE_VALIDITY_DAYS
    )
    all_nodes.append(new_node)

    test_all_nodes_cert_renewal(network, args, valid_from=valid_from)
    test_service_cert_renewal(network, args, valid_from=valid_from)

    if expected_subject_name:
        LOG.info(f"Confirming subject name == {expected_subject_name}")
        with primary.client() as c:
            r = c.get("/node/network")
            assert r.status_code == 200, r
            cert_pem = r.body.json()["service_certificate"]
            cert = x509.load_pem_x509_certificate(cert_pem.encode(), default_backend())
            assert cert.subject.rfc4514_string() == expected_subject_name, cert

    LOG.info("Apply transactions to new nodes only")
    issue_activity_on_live_service(network, args)
    test_random_receipts(network, args, lts=True, log_capture=[])
    # Setting from_seqno=1 as open ranges do not work with older ledgers
    # that did not record the now-deprecated "public:first_write_version" table
    network.txs.verify_range(log_capture=[], from_seqno=1)

    if test_jwt_cleanup:

        def get_fresh_public_state():
            with primary.client() as c:
                r = c.get("/node/commit")
                target_seqno = TxID.from_str(r.body.json()["transaction_id"]).seqno
            network.consortium.force_ledger_chunk(primary)
            for _ in range(10):
                ledger = ccf.ledger.Ledger(
                    primary.remote.ledger_paths(), committed_only=True
                )
                public_state, last_seqno = ledger.get_latest_public_state()
                if last_seqno >= target_seqno:
                    return public_state

                time.sleep(0.1)
            else:
                assert (
                    False
                ), f"Failed to up-to-date ledger state, seqno needed: {target_seqno}, last seqno: {last_seqno}"

        def table_has_entries(table_name, public_state):
            rows = public_state.get(table_name, None)
            return rows is not None and len(rows) > 0

        legacy_tables = [
            "public:ccf.gov.jwt.public_signing_keys",
            "public:ccf.gov.jwt.public_signing_keys_metadata",
            "public:ccf.gov.jwt.public_signing_key_issuer",
        ]
        new_table = "public:ccf.gov.jwt.public_signing_keys_metadata_v2"

        public_state = get_fresh_public_state()
        assert all(table_has_entries(table, public_state) for table in legacy_tables)
        assert table_has_entries(new_table, public_state)

        network.consortium.cleanup_legacy_jwt_records(
            primary, ensure_new_records_exist=True
        )

        public_state = get_fresh_public_state()
        assert all(
            not table_has_entries(table, public_state) for table in legacy_tables
        )

        # Cannot remove legacy if the current table is not populated but required to be
        network.consortium.remove_jwt_issuer(primary, network.jwt_issuer.issuer_url)
        public_state = get_fresh_public_state()
        assert not table_has_entries(new_table, public_state)
        try:
            network.consortium.cleanup_legacy_jwt_records(
                primary, ensure_new_records_exist=True
            )
        except infra.proposal.ProposalNotAccepted:
            pass

        # Although can remove it if not ensuring explicitly new records exist
        network.consortium.cleanup_legacy_jwt_records(
            primary, ensure_new_records_exist=False
        )


# Local build and install bin/ and lib/ directories differ
def get_bin_and_lib_dirs_for_install_path(install_path):
    return (
        [LOCAL_CHECKOUT_DIRECTORY] * 2
        if install_path == LOCAL_CHECKOUT_DIRECTORY
        else (os.path.join(install_path, "bin"), os.path.join(install_path, "lib"))
    )


def set_js_args(args, from_install_path, to_install_path=None):
    # Use from_version's app and constitution as new JS features may not be available
    # on older versions, but upgrade to the new constitution and JS app once the new network is ready
    js_app_directory = (
        "../samples/apps/logging/js"
        if from_install_path == LOCAL_CHECKOUT_DIRECTORY
        else "samples/logging/js"
    )
    args.js_app_bundle = os.path.join(from_install_path, js_app_directory)
    if to_install_path:
        args.new_js_app_bundle = os.path.join(
            to_install_path, "../samples/apps/logging/js"
        )

    get_new_constitution_for_install(args, from_install_path)


def run_code_upgrade_from(
    args,
    from_install_path,
    to_install_path,
    from_version=None,
    to_version=None,
    from_container_image=None,
):
    if infra.platform_detection.is_snp():
        LOG.info(
            "Skipping backwards compatibility test for AMD nodes until either we patch 2.x or we confirm that we don't need to do a live upgrade"
        )
        return

    from_binary_dir, from_library_dir = get_bin_and_lib_dirs_for_install_path(
        from_install_path
    )
    to_binary_dir, to_library_dir = get_bin_and_lib_dirs_for_install_path(
        to_install_path
    )

    set_js_args(args, from_install_path, to_install_path)

    service_subject_name = "CN=LTS custom service name"

    jwt_issuer = infra.jwt_issuer.JwtIssuer(
        "https://localhost", refresh_interval=args.jwt_key_refresh_interval_s
    )

    # pre 7.0.0 nodes may not always set the chunking flags in the ledger
    fv_skip_verify_chunking = infra.node.version_after("ccf-7.0.0", from_version)
    tv_skip_verify_chunking = infra.node.version_after("ccf-7.0.0", to_version)

    with jwt_issuer.start_openid_server():
        txs = app.LoggingTxs(jwt_issuer=jwt_issuer)
        with infra.network.network(
            args.nodes,
            binary_directory=from_binary_dir,
            library_directory=from_library_dir,
            pdb=args.pdb,
            txs=txs,
            jwt_issuer=jwt_issuer,
            version=from_version,
            skip_verify_chunking=fv_skip_verify_chunking or tv_skip_verify_chunking,
        ) as network:
            kwargs = {}
            if not infra.node.version_after(from_version, "ccf-4.0.0-rc1"):
                kwargs["reconfiguration_type"] = "OneTransaction"

            network.start_and_open(
                args,
                node_container_image=from_container_image,
                service_subject_name=service_subject_name,
                **kwargs,
            )

            old_nodes = network.get_joined_nodes()
            primary, _ = network.find_primary()

            LOG.info("Apply transactions to old service")
            issue_activity_on_live_service(network, args)

            LOG.info("Update constitution")
            new_constitution = get_new_constitution_for_install(args, to_install_path)
            network.consortium.set_constitution(primary, new_constitution)

            new_measurement = infra.utils.get_measurement(
                infra.platform_detection.get_platform(),
                args.package,
                library_dir=to_library_dir,
            )
            network.consortium.add_measurement(
                primary, infra.platform_detection.get_platform(), new_measurement
            )

            new_host_data = None
            try:
                new_host_data, new_security_policy = (
                    infra.utils.get_host_data_and_security_policy(
                        infra.platform_detection.get_platform(),
                        args.package,
                        library_dir=to_library_dir,
                        binary_dir=to_binary_dir,
                        version=to_version,
                    )
                )
                network.consortium.add_host_data(
                    primary,
                    infra.platform_detection.get_platform(),
                    new_host_data,
                    new_security_policy,
                )
            except ValueError as e:
                LOG.warning(f"Not setting host data/security policy for new nodes: {e}")

            # Note: alternate between joining from snapshot and replaying entire ledger
            new_nodes = []
            from_snapshot = True
            for _ in range(0, len(old_nodes)):
                new_node = network.create_node(
                    binary_dir=to_binary_dir,
                    library_dir=to_library_dir,
                    version=to_version,
                )
                network.join_node(
                    new_node, args.package, args, from_snapshot=from_snapshot
                )
                network.trust_node(
                    new_node,
                    args,
                    valid_from=str(  # Pre-2.0 nodes require X509 time format
                        infra.crypto.datetime_to_X509time(datetime.datetime.utcnow())
                    ),
                )
                # For 2.x nodes joining a 1.x service before the constitution is updated,
                # the node certificate validity period is set by the joining node itself
                # as [node startup time, node startup time + 365 days]
                new_node.verify_certificate_validity_period(
                    expected_validity_period_days=DEFAULT_NODE_CERTIFICATE_VALIDITY_DAYS,
                    ignore_proposal_valid_from=True,
                )
                from_snapshot = not from_snapshot
                new_nodes.append(new_node)

            # Verify that all nodes run the expected CCF version
            for node in network.get_joined_nodes():
                with node.client() as c:
                    r = c.get("/node/version")
                    expected_version = node.version or args.ccf_version
                    version = r.body.json()["ccf_version"]
                    assert (
                        version == expected_version
                    ), f"For node {node.local_node_id}, expect version {expected_version}, got {version}"

            # Verify that either custom service_subject_name was applied,
            # or that a default name is used
            primary, _ = network.find_primary()
            with primary.client() as c:
                r = c.get("/node/network")
                assert r.status_code == 200, r
                cert_pem = r.body.json()["service_certificate"]
                cert = x509.load_pem_x509_certificate(
                    cert_pem.encode(), default_backend()
                )
                version = primary.version or args.ccf_version
                if not infra.node.version_after(version, "ccf-5.0.0-dev14"):
                    service_subject_name = cert.subject.rfc4514_string()
                    LOG.info(
                        f"Custom subject name not supported on {version}, so falling back to default {service_subject_name}"
                    )
                else:
                    LOG.info(f"Custom subject name should be supported on {version}")
                    assert cert.subject.rfc4514_string() == service_subject_name, cert

            LOG.info("Apply transactions to hybrid network, with primary as old node")
            issue_activity_on_live_service(network, args)

            primary, _ = network.find_primary()

            old_measurement = infra.utils.get_measurement(
                infra.platform_detection.get_platform(),
                args.package,
                library_dir=from_library_dir,
            )
            if old_measurement != new_measurement:
                network.consortium.remove_measurement(
                    primary, infra.platform_detection.get_platform(), old_measurement
                )

            # If host_data was found for original nodes, check if it's different on new nodes, in which case old should be removed
            if new_host_data is not None:
                old_host_data, old_security_policy = (
                    infra.utils.get_host_data_and_security_policy(
                        infra.platform_detection.get_platform(),
                        args.package,
                        library_dir=from_library_dir,
                        binary_dir=from_binary_dir,
                        version=from_version,
                    )
                )

                if old_host_data != new_host_data:
                    network.consortium.remove_host_data(
                        primary, infra.platform_detection.get_platform(), old_host_data
                    )

            for index, node in enumerate(old_nodes):
                network.retire_node(primary, node)
                if primary == node:
                    primary, _ = network.wait_for_new_primary(primary)
                    # Submit tx and wait for commit after node retirement. See
                    # https://github.com/microsoft/CCF/issues/1713 for more detail.
                    network.txs.issue(network, number_txs=1, repeat=True)
                    # This block is here to test the transition period from a network that
                    # does not support custom claims to one that does. It can be removed after
                    # the transition is complete.
                    #
                    # The new build, being unreleased, doesn't have a version at all
                    if not primary.major_version:
                        LOG.info("Upgrade to new JS app")
                        # Upgrade to a version of the app containing an endpoint that
                        # registers custom claims
                        network.consortium.set_js_app_from_dir(
                            primary, args.new_js_app_bundle
                        )
                        LOG.info("Run transaction with additional claim")
                        # With wait_for_sync, the client checks that all nodes, including
                        # the minority of old ones, have acked the transaction
                        msg_idx = network.txs.idx + 1
                        txid = network.txs.issue(
                            network, number_txs=1, record_claim=True, wait_for_sync=True
                        )
                        assert len(network.txs.pub[msg_idx]) == 1
                        claims = network.txs.pub[msg_idx][-1]["msg"]

                        LOG.info(
                            "Check receipts are fine, including transaction with claims"
                        )
                        test_random_receipts(
                            network,
                            args,
                            lts=True,
                            additional_seqnos={txid.seqno: claims.encode()},
                            log_capture=[],
                        )
                        # Also check receipts on an old node
                        if index + 1 < len(old_nodes):
                            next_node = old_nodes[index + 1]
                            test_random_receipts(
                                network,
                                args,
                                lts=True,
                                additional_seqnos={txid.seqno: None},
                                node=next_node,
                                log_capture=[],
                            )
                node.stop()

            LOG.info("Service is now made of new nodes only")
            primary, _ = network.find_nodes()

            # Rollover JWKS so that new primary must read historical CA bundle table
            # and retrieve new keys via auto refresh
            jwt_issuer.refresh_keys()
            jwt_issuer.wait_for_refresh(network, args)

            test_new_service(
                network,
                args,
                to_install_path,
                to_binary_dir,
                to_library_dir,
                to_version,
                expected_subject_name=service_subject_name,
            )
            network.get_latest_ledger_public_state()


@reqs.description("Run live compatibility with latest LTS")
def run_live_compatibility_with_latest(
    args,
    repo,
    local_branch,
    this_release_branch_only=False,
    lts_install_path=None,
    lts_container_image=None,
):
    """
    Tests that a service from the latest LTS can be safely upgraded to the version of
    the local checkout.
    """
    if lts_install_path is None:
        lts_version, lts_install_path = repo.install_latest_lts_for_branch(
            os.getenv(ENV_VAR_LATEST_LTS_BRANCH_NAME, local_branch),
            this_release_branch_only,
            platform=infra.platform_detection.get_platform(),
        )
    else:
        lts_version = infra.github.get_version_from_install(lts_install_path)

    if lts_version is None:
        LOG.warning(
            f"Latest LTS not found for {local_branch} branch (this_release_branch_only: {this_release_branch_only})"
        )
        return None

    LOG.info(f"From LTS {lts_version} to local {local_branch} branch")
    if not args.dry_run:
        run_code_upgrade_from(
            args,
            from_install_path=lts_install_path,
            to_install_path=LOCAL_CHECKOUT_DIRECTORY,
            from_version=lts_version,
            to_version=None,
            from_container_image=lts_container_image,
        )
    return lts_version


@reqs.description("Run ledger compatibility since first LTS")
def run_ledger_compatibility_since_first(
    args, local_branch, use_snapshot, test_jwt_cleanup
):
    """
    Tests that a service from the very first LTS can be recovered
    to the next LTS, and so forth, until the version of the local checkout.

    The recovery process uses snapshot is `use_snapshot` is True. Otherwise, the
    entire historical ledger is used.
    """

    LOG.info("Use snapshot: {}", use_snapshot)
    repo = infra.github.Repository()
    lts_releases = repo.get_supported_lts_releases(local_branch)

    LOG.info(f"LTS releases: {[r[1] for r in lts_releases.items()]}")

    lts_versions = []

    # Add an empty entry to release to indicate local checkout
    # Note: dicts are ordered from Python3.7
    lts_releases[None] = None

    # These variables are the previous service's info
    ledger_dir = None
    committed_ledger_dirs = None
    snapshots_dir = None
    previous_version = None

    jwt_issuer = infra.jwt_issuer.JwtIssuer(
        "https://localhost", refresh_interval=args.jwt_key_refresh_interval_s
    )
    with jwt_issuer.start_openid_server():
        txs = app.LoggingTxs(jwt_issuer=jwt_issuer)
        for idx, (_, lts_release) in enumerate(lts_releases.items()):
            if lts_release:
                version, install_path = repo.install_release(
                    lts_release,
                    platform=infra.platform_detection.get_platform(),
                )
                lts_versions.append(version)
                set_js_args(args, install_path)
            else:
                version = args.ccf_version
                install_path = LOCAL_CHECKOUT_DIRECTORY
                get_new_constitution_for_install(args, install_path)

            binary_dir, library_dir = get_bin_and_lib_dirs_for_install_path(
                install_path
            )

            if not args.dry_run:
                network_args = {
                    "hosts": args.nodes,
                    "binary_dir": binary_dir,
                    "library_dir": library_dir,
                    "txs": txs,
                    "jwt_issuer": jwt_issuer,
                    "version": version,
                }
                kwargs = {}
                if not infra.node.version_after(version, "ccf-4.0.0-rc1"):
                    kwargs["reconfiguration_type"] = "OneTransaction"

                if idx == 0:
                    LOG.info(
                        f"Recovering end-of-life service from files (version: {version})"
                    )
                    # First, recover end-of-life services from files
                    expected_recovery_count = len(
                        infra.github.END_OF_LIFE_MAJOR_VERSIONS
                    )
                    service_dir = os.path.join(
                        os.path.dirname(os.path.realpath(__file__)),
                        "testdata",
                        "eol_service",
                    )
                    new_common = infra.network.get_common_folder_name(
                        args.workspace, args.label
                    )
                    copy_tree(os.path.join(service_dir, "common"), new_common)

                    new_ledger = os.path.join(new_common, "ledger")
                    copy_tree(os.path.join(service_dir, "ledger"), new_ledger)

                    if use_snapshot:
                        new_snapshots = os.path.join(new_common, "snapshots")
                        copy_tree(os.path.join(service_dir, "snapshots"), new_snapshots)

                    network = infra.network.Network(**network_args)

                    args.previous_service_identity_file = os.path.join(
                        service_dir, "common", "service_cert.pem"
                    )

                    network.start_in_recovery(
                        args,
                        committed_ledger_dirs=[new_ledger],
                        snapshots_dir=new_snapshots if use_snapshot else None,
                        common_dir=new_common,
                        **kwargs,
                    )

                    network.recover(
                        args, expected_recovery_count=expected_recovery_count
                    )

                    primary, _ = network.find_primary()
                    jwt_issuer.register(network)
                else:
                    LOG.info(f"Recovering service (new version: {version})")
                    network = infra.network.Network(
                        **network_args, existing_network=network
                    )

                    network.start_in_recovery(
                        args,
                        ledger_dir,
                        committed_ledger_dirs,
                        snapshots_dir=snapshots_dir,
                        set_authenticate_session=update_gov_authn(version),
                        **kwargs,
                    )
                    # Recovery count is not stored in pre-2.0.3 ledgers
                    network.recover(
                        args,
                        expected_recovery_count=(
                            1
                            if not infra.node.version_after(
                                previous_version, "ccf-2.0.3"
                            )
                            else None
                        ),
                    )

                nodes = network.get_joined_nodes()
                primary, _ = network.find_primary()

                # Verify that all nodes run the expected CCF version
                for node in nodes:
                    with node.client() as c:
                        r = c.get("/node/version")
                        expected_version = node.version or args.ccf_version
                        version = r.body.json()["ccf_version"]
                        assert (
                            r.body.json()["ccf_version"] == expected_version
                        ), f"Node version is not {expected_version}"
                    node.verify_certificate_validity_period()

                # Rollover JWKS so that new primary must read historical CA bundle table
                # and retrieve new keys via auto refresh
                jwt_issuer.refresh_keys()
                primary, _ = network.find_nodes()
                jwt_issuer.wait_for_refresh(network, args)

                issue_activity_on_live_service(network, args)

                if idx > 0:
                    test_new_service(
                        network,
                        args,
                        install_path,
                        binary_dir,
                        library_dir,
                        version,
                        test_jwt_cleanup=test_jwt_cleanup,
                    )

                snapshots_dir = (
                    network.get_committed_snapshots(primary) if use_snapshot else None
                )

                network.save_service_identity(args)

                def recovery_is_over_boundary(boundary_version):
                    ccf_prev = infra.node.CCFVersion(previous_version)
                    ccf_boundary = infra.node.CCFVersion(boundary_version)
                    ccf_version = infra.node.CCFVersion(version)
                    return ccf_prev < ccf_boundary and ccf_boundary <= ccf_version

                stop_verify_kwargs = {}
                # We accept ledger chunk file differences during upgrades
                # from 1.x to 2.x post rc7 ledger. This is necessary because
                # the ledger files may not be chunked at the same interval
                # between those versions (see https://github.com/microsoft/ccf/issues/3613;
                # 1.x ledgers do not contain the header flags to synchronize ledger chunks).
                if recovery_is_over_boundary("ccf-2.0.0-rc7"):
                    stop_verify_kwargs |= {
                        "skip_verification": True,
                        "accept_ledger_diff": True,
                        "skip_verify_chunking": True,
                    }
                # Pre 7 networks may not have all of the relevant chunk flags in old portions of the ledger
                # Hence if 7 nodes join without a snapshot, and hence replay the ledger from the start of time,
                # They will not chunk these files and hence have different chunking to the original ledger
                if recovery_is_over_boundary("ccf-7.0.0-dev1"):
                    stop_verify_kwargs |= {
                        "accept_ledger_diff": True,  # due to no snapshot causing replay
                        "skip_verify_chunking": True,
                    }
                if test_jwt_cleanup:
                    stop_verify_kwargs |= {"skip_verification": True}

                LOG.info(
                    "Stopping network recovering from version {} to {}".format(
                        previous_version, version
                    )
                )
                network.stop_all_nodes(**stop_verify_kwargs)

                ledger_dir, committed_ledger_dirs = primary.get_ledger()

                # Check that ledger and snapshots can be parsed
                ccf.ledger.Ledger(committed_ledger_dirs).get_latest_public_state()
                if snapshots_dir:
                    for s in os.listdir(snapshots_dir):
                        with ccf.ledger.Snapshot(
                            os.path.join(snapshots_dir, s)
                        ) as snapshot:
                            snapshot.get_public_domain()

                previous_version = version

    return lts_versions


if __name__ == "__main__":

    def add(parser):
        parser.add_argument("--check-ledger-compatibility", action="store_true")
        parser.add_argument(
            "--compatibility-report-file", type=str, default="compatibility_report.json"
        )
        # It is only possible to test compatibility with past releases since only the local infra
        # is able to spawn old nodes
        parser.add_argument(
            "--release-install-path",
            type=str,
            help='Absolute path to existing CCF release, e.g. "/opt/ccf"',
            default=None,
        )
        parser.add_argument("--dry-run", action="store_true")

    args = infra.e2e_args.cli_args(add)

    # JS generic is the only app included in CCF install
    args.package = "js_generic"
    args.nodes = infra.e2e_args.max_nodes(args, f=0)
    args.jwt_key_refresh_interval_s = 3
    args.sig_ms_interval = 1000  # Set to cchost default value

    # Hardcoded because host only accepts info log on release builds
    args.log_level = "info"

    repo = infra.github.Repository()
    local_branch = infra.github.GitEnv.local_branch()

    if args.dry_run:
        LOG.warning("Dry run: no compatibility check")

    compatibility_report = {}
    compatibility_report["version"] = args.ccf_version
    compatibility_report["live compatibility"] = {}
    if args.release_install_path:
        version = run_live_compatibility_with_latest(
            args,
            repo,
            local_branch,
            lts_install_path=args.release_install_path,
            lts_container_image=args.release_install_image,
        )
        compatibility_report["live compatibility"].update(
            {f"with release ({args.release_install_path})": version}
        )
    else:
        # Compatibility with previous LTS
        # (e.g. when releasing 2.0.1, check compatibility with existing 1.0.17)
        latest_lts_version = run_live_compatibility_with_latest(
            args, repo, local_branch, this_release_branch_only=False
        )
        compatibility_report["live compatibility"].update(
            {"with previous LTS": latest_lts_version}
        )

        # Compatibility with latest LTS on the same release branch
        # (e.g. when releasing 2.0.1, check compatibility with existing 2.0.0)
        latest_lts_version = run_live_compatibility_with_latest(
            args, repo, local_branch, this_release_branch_only=True
        )
        compatibility_report["live compatibility"].update(
            {"with same LTS": latest_lts_version}
        )

        if args.check_ledger_compatibility:
            compatibility_report["data compatibility"] = {}
            lts_versions = run_ledger_compatibility_since_first(
                args,
                local_branch,
                use_snapshot=False,
                test_jwt_cleanup=False,
            )
            compatibility_report["data compatibility"].update(
                {"with previous ledger": lts_versions}
            )
            lts_versions = run_ledger_compatibility_since_first(
                args,
                local_branch,
                use_snapshot=True,
                test_jwt_cleanup=True,
            )
            compatibility_report["data compatibility"].update(
                {"with previous snapshots": lts_versions}
            )

    if not args.dry_run:
        with open(args.compatibility_report_file, "w", encoding="utf-8") as f:
            json.dump(compatibility_report, f, indent=2)
            LOG.info(
                f"Compatibility report written to {args.compatibility_report_file}"
            )

    LOG.success(f"Compatibility report:\n {json.dumps(compatibility_report, indent=2)}")
