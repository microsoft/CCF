# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import infra.network
import infra.e2e_args
import infra.interfaces
import infra.net
from infra.runner import ConcurrentRunner
import http
import time

from loguru import logger as LOG


def test_redirects_with_default_config(network, args):
    paths = ("/app/log/private", "/app/log/public")
    msg = "Redirect test"

    def test_redirect_to_node(talk_to, redirect_to):
        interface = redirect_to.host.rpc_interfaces[
            infra.interfaces.PRIMARY_RPC_INTERFACE
        ]
        loc = f"https://{interface.public_host}:{interface.public_port}"

        with talk_to.client("user0") as c:
            for path in paths:
                r = c.post(path, {"id": 42, "msg": msg}, allow_redirects=False)
                assert r.status_code == http.HTTPStatus.TEMPORARY_REDIRECT.value
                assert "location" in r.headers
                assert r.headers["location"] == f"{loc}{path}", r.headers

    LOG.info("Redirect to original primary")
    primary, orig_backups = network.find_nodes()
    for backup in orig_backups:
        test_redirect_to_node(backup, primary)

    LOG.info("Redirect to subsequent primary")
    primary.stop()
    network.wait_for_new_primary(primary)
    new_primary, new_backups = network.find_nodes()
    for backup in new_backups:
        test_redirect_to_node(backup, new_primary)

    LOG.info("Subsequent primary no longer redirects")
    assert new_primary in orig_backups  # Check it WAS a backup
    with new_primary.client("user0") as c:
        for path in paths:
            r = c.post(path, {"id": 42, "msg": msg}, allow_redirects=False)
            assert r.status_code == http.HTTPStatus.OK.value

    LOG.info("Redirects fail when no primary available")
    new_primary.stop()
    backup = new_backups[0]
    start_time = time.time()
    timeout = network.observed_election_duration
    end_time = start_time + timeout
    while time.time() < end_time:
        with backup.client() as c:
            r = c.head("/node/primary", allow_redirects=False)
            if r.status_code == http.HTTPStatus.INTERNAL_SERVER_ERROR:
                break
        time.sleep(0.5)
    else:
        raise TimeoutError(f"Node failed to recognise primary death after {timeout}s")

    with backup.client("user0") as c:
        for path in paths:
            r = c.post(path, {"id": 42, "msg": msg}, allow_redirects=False)
            assert r.status_code == http.HTTPStatus.SERVICE_UNAVAILABLE.value
            assert r.body.json()["error"]["code"] == "PrimaryNotFound"


def test_redirects_with_static_name_config(network, args):
    hostname = "primary.my.ccf.service.example.test"

    paths = ("/app/log/private", "/app/log/public")
    msg = "Redirect test"

    new_node = network.create_node(
        infra.interfaces.HostSpec(
            rpc_interfaces={
                infra.interfaces.PRIMARY_RPC_INTERFACE: infra.interfaces.RPCInterface(
                    host=infra.net.expand_localhost(),
                    redirections=infra.interfaces.RedirectionConfig(
                        to_primary=infra.interfaces.StaticAddressResolver(hostname)
                    ),
                )
            }
        )
    )
    network.join_node(new_node, args.package, args)
    network.trust_node(new_node, args)

    with new_node.client("user0") as c:
        for path in paths:
            r = c.post(path, {"id": 42, "msg": msg}, allow_redirects=False)
            assert r.status_code == http.HTTPStatus.TEMPORARY_REDIRECT.value
            assert "location" in r.headers
            assert r.headers["location"] == f"https://{hostname}{path}", r.headers


def run_redirect_tests_default(args):
    with infra.network.network(
        args.nodes,
        args.binary_dir,
        args.debug_nodes,
        args.perf_nodes,
        pdb=args.pdb,
    ) as network:
        network.start_and_open(args)

        test_redirects_with_default_config(network, args)
        # ^ This test kills nodes, so be careful if you follow it!


def run_redirect_tests_static(args):
    with infra.network.network(
        args.nodes,
        args.binary_dir,
        args.debug_nodes,
        args.perf_nodes,
        pdb=args.pdb,
    ) as network:
        network.start_and_open(args)

        test_redirects_with_static_name_config(network, args)


if __name__ == "__main__":
    cr = ConcurrentRunner()

    cr.add(
        "redirects_default",
        run_redirect_tests_default,
        package="samples/apps/logging/liblogging",
        nodes=infra.e2e_args.min_nodes(cr.args, f=1),
    )

    cr.add(
        "redirects_static",
        run_redirect_tests_static,
        package="samples/apps/logging/liblogging",
        nodes=infra.e2e_args.min_nodes(cr.args, f=0),
    )

    cr.run()
