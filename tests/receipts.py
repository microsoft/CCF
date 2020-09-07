# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import infra.network
import infra.proc
import infra.net
import suite.test_requirements as reqs
import infra.e2e_args
import infra.checker

from loguru import logger as LOG


@reqs.description("Running transactions against logging app")
@reqs.supports_methods("receipt", "receipt/verify", "log/private")
@reqs.at_least_n_nodes(2)
def test(network, args):
    primary, _ = network.find_primary_and_any_backup()

    with primary.client() as mc:
        check_commit = infra.checker.Checker(mc)
        check = infra.checker.Checker()

        msg = "Hello world"

        LOG.info("Write/Read on primary")
        with primary.client("user0") as c:
            r = c.post("/app/log/private", {"id": 42, "msg": msg})
            check_commit(r, result=True)
            check(c.get("/app/log/private?id=42"), result={"msg": msg})
            for _ in range(10):
                c.post(
                    "/app/log/private",
                    {"id": 43, "msg": "Additional messages"},
                )
            check_commit(
                c.post("/app/log/private", {"id": 43, "msg": "A final message"}),
                result=True,
            )
            r = c.get(f"/app/receipt?commit={r.seqno}")
            check(
                c.post("/app/receipt/verify", {"receipt": r.body["receipt"]}),
                result={"valid": True},
            )
            invalid = r.body["receipt"]
            invalid[-3] += 1
            check(
                c.post("/app/receipt/verify", {"receipt": invalid}),
                result={"valid": False},
            )

    return network


def run(args):
    hosts = ["localhost"] * (4 if args.consensus == "pbft" else 2)

    with infra.network.network(
        hosts, args.binary_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
    ) as network:
        network.start_and_join(args)
        test(network, args)


if __name__ == "__main__":

    args = infra.e2e_args.cli_args()
    args.package = args.app_script or "liblogging"

    notify_server_host = "localhost"
    args.notify_server = (
        notify_server_host
        + ":"
        + str(infra.net.probably_free_local_port(notify_server_host))
    )
    run(args)
