# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
"""Check the Fluentd exporter across startup, fan-out and tag-filter cases.

1. No exporter configured: transactions commit as usual.
2. Invalid exporter configuration: the node rejects it at startup.
3. Exporter configured but the collector refuses connections: transactions
   still commit.
4. Both delivery policies export traces to independent, healthy collectors.
5. Exporter configured against a real Fluentd (only with --fluentd PATH): the
   collector receives well-formed CCF consensus protocol events, and the node
   keeps committing after the collector is killed.
6. Literal prefix whitelists include or exclude events at the node, verified
   with a local Forward collector without requiring Fluentd.
"""

import copy
import json
import pathlib
import socket
import subprocess
import time

import infra.e2e_args
import infra.fluentd
import infra.network


def exercise(args, name, endpoints, while_running=None):
    args = copy.deepcopy(args)
    args.label += "_" + name
    args.observability = {"fluentd": endpoints} if endpoints is not None else None
    with infra.network.network(
        infra.e2e_args.nodes(args, 1), args.binary_dir, args.debug_nodes, pdb=args.pdb
    ) as network:
        network.start_and_open(args)
        primary, _ = network.find_primary()
        with primary.client("user0") as client:
            response = client.post("/app/log/private", {"id": 1, "msg": name})
            assert response.status_code == 200
            client.wait_for_commit(response)
            if while_running:
                while_running()
                response = client.post("/app/log/private", {"id": 2, "msg": "outage"})
                assert response.status_code == 200
                client.wait_for_commit(response)
        return json.loads(
            (pathlib.Path(network.common_dir) / "0.config.json").read_text()
        )


def run(args):
    baseline = exercise(args, "disabled", None)
    invalid_path = pathlib.Path(f"{args.label}_invalid.json")
    try:
        for endpoints, valid in (
            ([{"host": "127.0.0.1", "port": "0"}], False),
            ([{"host": "127.0.0.1", "port": "24224", "queue_capacity": 0}], False),
            ([{"host": "127.0.0.1", "port": "24224", "queue_capacity": -1}], False),
            (
                [{"host": "127.0.0.1", "port": "24224", "queue_capacity": 1048577}],
                True,
            ),
        ):
            baseline["observability"] = {"fluentd": endpoints}
            invalid_path.write_text(json.dumps(baseline), encoding="utf-8")
            result = subprocess.run(
                [
                    str(pathlib.Path(args.binary_dir) / args.package),
                    "--config",
                    str(invalid_path),
                    "--check",
                ],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            assert (result.returncode == 0) == valid, result.stdout + result.stderr
            if valid:
                continue
            output = result.stdout + result.stderr
            assert any(
                text in output
                for text in ("Fluentd", "Trace queue capacity", "queue_capacity")
            ), output
        for workers, valid in ((65533, True), (65534, False), (2**64 - 1, False)):
            baseline["worker_threads"] = workers
            invalid_path.write_text(json.dumps(baseline), encoding="utf-8")
            result = subprocess.run(
                [
                    str(pathlib.Path(args.binary_dir) / args.package),
                    "--config",
                    str(invalid_path),
                    "--check",
                ],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            assert (result.returncode == 0) == valid, result.stdout + result.stderr
            if not valid:
                assert "worker_threads" in result.stdout + result.stderr
    finally:
        invalid_path.unlink(missing_ok=True)
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
        endpoint = {"host": "127.0.0.1", "port": str(port)}
        # A bound, non-listening port reliably refuses connections.
        exercise(args, "outage", [endpoint])
    with infra.fluentd.Collector(1) as first, infra.fluentd.Collector(1) as second:
        exercise(
            args,
            "multiple",
            [
                {**first.endpoint, "delivery": "buffered-best-effort"},
                {**second.endpoint, "delivery": "unbuffered-non-blocking"},
            ],
        )
    assert first.records > 0
    assert second.records > 0
    assert first.processes == second.processes
    for delivery in ("buffered-best-effort", "unbuffered-non-blocking"):
        with (
            infra.fluentd.Collector(1) as broad,
            infra.fluentd.Collector(1) as exact,
            infra.fluentd.Collector(1) as excluded,
        ):
            exercise(
                args,
                f"filtered_fanout_{delivery}",
                [
                    {
                        **excluded.endpoint,
                        "delivery": delivery,
                        "tag_prefixes": ["ccf.sho", "ccf.kv"],
                    },
                    {
                        **broad.endpoint,
                        "delivery": delivery,
                        "tag_prefixes": ["ccf", "ccf.cft", "ccf"],
                    },
                    {
                        **exact.endpoint,
                        "delivery": delivery,
                        "tag_prefixes": ["ccf.kv", "ccf.cft", "ccf.sho"],
                    },
                ],
            )
        assert broad.records > 0
        assert exact.records > 0
        assert broad.tags == exact.tags == {"ccf.cft"}
        assert broad.processes == exact.processes
        assert excluded.records == 0
        assert excluded.bytes == 0
    for name, prefixes, matches in (
        ("omitted", None, True),
        ("empty", [], False),
        ("all", [""], True),
        ("all_last", ["ccf.sho", ""], True),
        ("ccf", ["ccf"], True),
        ("cft", ["ccf.cft"], True),
        ("partial", ["ccf.cf"], True),
        ("different", ["ccf.sho", "ccf.kv"], False),
        ("longer", ["ccf.cft.child"], False),
        ("case", ["CCF"], False),
        ("substring", ["cft"], False),
        ("wildcard", ["ccf.*"], False),
    ):
        with infra.fluentd.Collector(node_count=1) as collector:
            filtered_endpoint = dict(collector.endpoint)
            if prefixes is not None:
                filtered_endpoint["tag_prefixes"] = prefixes
            exercise(args, f"filter_{name}", [filtered_endpoint])
        if matches:
            assert collector.records > 0, name
            assert collector.tags == {"ccf.cft"}, (name, collector.tags)
        else:
            assert collector.records == 0, (name, collector.records)
            assert collector.bytes == 0, (name, collector.bytes)
    if not args.fluentd:
        print("Real Fluentd test not selected: pass --fluentd PATH")
        return

    config = pathlib.Path(f"{args.label}_fluentd.conf")
    output = pathlib.Path(f"{args.label}_fluentd_records.log")
    config.write_text(
        f"<source>\n@type forward\nbind 127.0.0.1\nport {port}\n</source>\n"
        "<match ccf.cft>\n@type stdout\n"
        "<format>\n@type json\n</format>\n</match>\n",
        encoding="utf-8",
    )
    with output.open("w", encoding="utf-8") as stream:
        process = subprocess.Popen(
            [args.fluentd, "--no-supervisor", "-c", str(config)],
            stdout=stream,
            stderr=subprocess.STDOUT,
        )
        try:
            deadline = time.monotonic() + 30
            while True:
                assert process.poll() is None, output.read_text()
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                        break
                except OSError:
                    assert time.monotonic() < deadline, output.read_text()
                    time.sleep(0.1)

            def stop_collector():
                process.terminate()
                process.wait(timeout=5)

            exercise(args, "enabled", [endpoint], stop_collector)
        finally:
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=5)
    records = []
    for line in output.read_text(encoding="utf-8").splitlines():
        if line.startswith("{"):
            records.append(json.loads(line))
    assert records, output.read_text()
    assert all({"h_ts", "process_id", "msg"} == set(record) for record in records)
    assert any(record["msg"]["function"] == "replicate" for record in records)
    assert all(record["msg"]["state"]["node_id"] for record in records)


if __name__ == "__main__":

    def add_args(parser):
        parser.add_argument("--fluentd", help="Path to real Fluentd executable")

    run(infra.e2e_args.cli_args(add=add_args))
