# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import os
import tempfile
import http
import time
import infra.network
import infra.path
import infra.proc
import infra.net
import infra.e2e_args
import suite.test_requirements as reqs


@reqs.description("Test host process launch")
def test_host_process_launch(network, args):
    primary, _ = network.find_nodes()

    with tempfile.TemporaryDirectory() as tmp_dir:
        script_path = os.path.join(os.path.dirname(__file__), "host_process.sh")
        out_path = os.path.join(tmp_dir, "test.out")

        first = "Hello world!\n"
        second = "Goodbye"
        expected_content = first + second

        body = {
            "args": [script_path, first, out_path],
            "input": second,
        }

        with primary.client("user0") as c:
            r = c.post("/app/launch", body=body)
            assert r.status_code == http.HTTPStatus.OK, r.status_code

        timeout = 1
        t0 = time.time()
        while time.time() - t0 < timeout:
            if os.path.exists(out_path):
                break
            time.sleep(0.1)
        assert os.path.exists(out_path), f"host process did not run within {timeout}s"
        with open(out_path, encoding="utf-8") as f:
            content = f.read()
        assert expected_content == content, content

    return network


@reqs.description("Test host process launch (many)")
def test_host_process_launch_many(network, args):
    primary, _ = network.find_nodes()

    with tempfile.TemporaryDirectory() as tmp_dir:
        script_path = os.path.join(os.path.dirname(__file__), "host_process.sh")
        count = 100

        with primary.client("user0") as c:
            r = c.post(
                "/app/launch_many",
                body={"program": script_path, "out_dir": tmp_dir, "count": count},
            )
            assert r.status_code == http.HTTPStatus.OK, r.status_code

        pending = set(range(count))
        timeout = 2
        t0 = time.time()
        while time.time() - t0 < timeout:
            for i in list(pending):
                if os.path.exists(os.path.join(tmp_dir, f"{i}")):
                    pending.remove(i)
            if not pending:
                break
            time.sleep(0.1)
        assert not pending, f"{len(pending)} pending host processes after {timeout}s"

    return network


def run(args):
    with infra.network.network(
        args.nodes, args.binary_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
    ) as network:
        network.start_and_open(args)
        network = test_host_process_launch(network, args)
        network = test_host_process_launch_many(network, args)


if __name__ == "__main__":

    args = infra.e2e_args.cli_args()
    args.package = "libjs_generic"
    args.nodes = infra.e2e_args.max_nodes(args, f=0)
    run(args)
