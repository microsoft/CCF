# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

"""
Regression test for a compaction conflict raised by a JavaScript endpoint.

A transaction reads at a version fixed when it first touches the KV. If the
service commits and compacts past that version before the transaction first
accesses a given map, the KV raises CompactedVersionConflict for that map. The
framework is expected to re-execute the transaction, so the caller never
observes the conflict.

The conflict is produced deterministically here by holding a JS transaction
open, in a spin loop, while a second client writes to the map that the JS
endpoint has not yet touched.
"""

import threading
import time
from http import HTTPStatus

import infra.network
from loguru import logger as LOG

MODULE_NAME = "compaction.js"
CONFLICT_MAP = "compaction_records"

# Long enough for the concurrent writes to commit and be compacted while the
# endpoint is still executing, and short enough that two attempts each stay
# within the default JS execution time limit.
SPIN_MS = 2000

# Enough writes to move the map's history well past the spinning transaction's
# read version.
CONCURRENT_WRITES = 50

# Covers two executions of the spinning endpoint, since the framework
# re-executes it after the conflict.
SLOW_REQUEST_TIMEOUT_S = 30

MODULE = f"""
export function slow_write(request) {{
  // This transaction's read version is already fixed, by the module lookup
  // the framework performs before calling this function.
  const deadline = Date.now() + {SPIN_MS};
  while (Date.now() < deadline) {{}}

  // First access to this map in this transaction. By now the concurrent
  // writers have moved its history past the read version.
  ccf.kv["{CONFLICT_MAP}"].set(ccf.strToBuf("slow"), ccf.strToBuf("slow"));

  return {{ statusCode: 204 }};
}}

export function fast_write(request) {{
  ccf.kv["{CONFLICT_MAP}"].set(
    ccf.strToBuf(request.params.key), ccf.strToBuf("fast"));

  return {{ statusCode: 204 }};
}}
"""


def endpoint(js_function):
    return {
        "post": {
            "js_module": MODULE_NAME,
            "js_function": js_function,
            "forwarding_required": "never",
            "redirection_strategy": "none",
            "authn_policies": ["no_auth"],
            "mode": "readwrite",
            "openapi": {},
        }
    }


def make_bundle():
    return {
        "metadata": {
            "endpoints": {
                "/slow_write": endpoint("slow_write"),
                "/fast_write/{key}": endpoint("fast_write"),
            }
        },
        "modules": [{"name": MODULE_NAME, "module": MODULE}],
    }


def test_compaction_conflict_is_retried(network, args):
    primary, _ = network.find_primary()
    network.consortium.set_js_app_from_bundle(primary, make_bundle())

    # Create the map before the spinning transaction fixes its read version.
    # A map created after that version is not visible to the transaction,
    # which then makes its own copy, whose history begins at version 0 and so
    # can never be compacted out of reach. Without this the workload below
    # runs without ever producing a conflict.
    with primary.client() as c:
        r = c.post(f"/app/fast_write/{CONFLICT_MAP}_init")
        assert r.status_code == HTTPStatus.NO_CONTENT, r.status_code
    network.wait_for_all_nodes_to_commit(primary=primary)

    slow_response = {}

    def slow_write():
        with primary.client() as c:
            slow_response["r"] = c.post(
                "/app/slow_write", timeout=SLOW_REQUEST_TIMEOUT_S
            )

    LOG.info("Starting slow write, which holds a transaction open while spinning")
    slow = threading.Thread(target=slow_write)
    slow.start()

    # Let the slow endpoint fix its read version before advancing past it.
    time.sleep(SPIN_MS / 1000 / 4)

    LOG.info("Writing concurrently, to compact the map past that read version")
    with primary.client() as c:
        for i in range(CONCURRENT_WRITES):
            r = c.post(f"/app/fast_write/{i}")
            assert r.status_code == HTTPStatus.NO_CONTENT, r.status_code
    network.wait_for_all_nodes_to_commit(primary=primary)

    slow.join()

    r = slow_response["r"]
    assert r.status_code == HTTPStatus.NO_CONTENT, (
        f"Expected the conflict to be re-executed transparently, got "
        f"{r.status_code}: {r.body.text()}"
    )

    return network


def run(args):
    with infra.network.network(
        args.nodes, args.binary_dir, args.debug_nodes, pdb=args.pdb
    ) as network:
        network.start_and_open(args)
        test_compaction_conflict_is_retried(network, args)
