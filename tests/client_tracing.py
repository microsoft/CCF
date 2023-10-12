# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import json

import infra.network


class ClientTracing:
    processes = {}
    index = 0
    steps = []

    def __init__(self, client) -> None:
        self.client = client
        if client.hostname not in ClientTracing.processes:
            ClientTracing.processes[client.hostname] = len(ClientTracing.processes)
        self.process = ClientTracing.processes[client.hostname]

    def write(self, key, value):
        ClientTracing.index += 1
        trace = {
            "type": "invoke",
            "f": "txn",
            "value": [["w", key, value]],
            "process": self.process,
            "index": ClientTracing.index,
        }
        ClientTracing.steps.append(trace)
        r = self.client.put(f"/records/{key}", f"{value}")
        assert r.status_code == 204, r.status_code
        ClientTracing.index += 1
        trace = {
            "type": "ok",
            "f": "txn",
            "value": [["w", key, value]],
            "process": self.process,
            "index": ClientTracing.index,
        }
        ClientTracing.steps.append(trace)

    def read(self, key):
        ClientTracing.index += 1
        trace = {
            "type": "invoke",
            "f": "txn",
            "value": [["r", key, None]],
            "process": self.process,
            "index": ClientTracing.index,
        }
        ClientTracing.steps.append(trace)
        r = self.client.get(f"/records/{key}")
        value = int(r.body.text())
        assert r.status_code == 200, r.status_code
        ClientTracing.index += 1
        trace = {
            "type": "ok",
            "f": "txn",
            "value": [["r", key, value]],
            "process": self.process,
            "index": ClientTracing.index,
        }
        ClientTracing.steps.append(trace)


def run_rw_register_trace(args):
    with infra.network.network(
        args.nodes, args.binary_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
    ) as network:
        network.start_and_open(args)

        primary, _ = network.find_primary()
        with primary.client("user0") as c:
            cw = ClientTracing(c)
            cw.write("x", 2)
            cw.read("x")
            cw.read("x")

        with open("trace.json", "w") as f:
            f.write(json.dumps(ClientTracing.steps))


if __name__ == "__main__":
    args = infra.e2e_args.cli_args()
    args.nodes = infra.e2e_args.min_nodes(args, f=0)

    run_rw_register_trace(args)
