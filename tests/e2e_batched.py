# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
from hashlib import md5
import itertools
import time

import infra.ccf
import infra.proc
import infra.jsonrpc
import infra.notification
import infra.net
import suite.test_requirements as reqs
import e2e_args

from loguru import logger as LOG

id_gen = itertools.count()


@reqs.lua_generic_app
def test(network, args, batch_size=100):
    LOG.info(f"Running batch submission of {batch_size} new entries")
    primary, _ = network.find_primary()

    with primary.user_client() as c:
        message_ids = [next(id_gen) for _ in range(batch_size)]
        messages = [
            {"id": i, "msg": f"A unique message: {md5(bytes(i)).hexdigest()}"}
            for i in message_ids
        ]

        pre_submit = time.time()
        submit_response = c.rpc("BATCH_submit", messages)
        post_submit = time.time()
        LOG.warning(
            f"Submitting {batch_size} new keys took {post_submit - pre_submit}s"
        )
        assert submit_response.result == len(messages)

        fetch_response = c.rpc("BATCH_fetch", message_ids)
        assert fetch_response.result is not None
        assert len(fetch_response.result) == len(message_ids)
        for n, m in enumerate(messages):
            fetched = fetch_response.result[n]
            assert m["id"] == fetched["id"]
            assert m["msg"] == fetched["msg"].decode()

    return network


def run(args):
    hosts = ["localhost", "localhost", "localhost"]

    with infra.ccf.network(
        hosts, args.build_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
    ) as network:
        network.start_and_join(args)

        network = test(network, args, batch_size=1)
        network = test(network, args, batch_size=5)
        network = test(network, args, batch_size=10)
        network = test(network, args, batch_size=100)
        network = test(network, args, batch_size=1000)

        bs = 10000
        try:
            while bs <= 100000:
                for _ in range(3):
                    network = test(network, args, batch_size=bs)
                bs += 10000
        except Exception as e:
            LOG.error("Looks like something broke")
            LOG.error(e)
            LOG.error("Press Ctrl+C to shutdown the network")

            try:
                while True:
                    time.sleep(60)

            except KeyboardInterrupt:
                LOG.info("Stopping all CCF nodes...")


if __name__ == "__main__":
    args = e2e_args.cli_args()
    args.package = "libluagenericenc"
    args.enforce_reqs = True

    run(args)
