# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import tempfile
import http
import infra.network
import infra.path
import infra.proc
import infra.net
import infra.e2e_args
import suite.test_requirements as reqs

APP_SCRIPT = """
return {
  ["POST text"] = [[
    export default function(request)
    {
      if (request.headers['content-type'] !== 'text/plain')
        throw new Error('unexpected content-type: ' + request.headers['content-type']);
      const text = request.body.text();
      if (text !== 'text')
        throw new Error('unexpected body: ' + text);
      return { body: 'text' };
    }
  ]],
  ["POST json"] = [[
    export default function(request)
    {
      if (request.headers['content-type'] !== 'application/json')
        throw new Error('unexpected content type: ' + request.headers['content-type']);
      const obj = request.body.json();
      if (obj.foo !== 'bar')
        throw new Error('unexpected body: ' + obj);
      return { body: { foo: 'bar' } };
    }
  ]],
  ["POST binary"] = [[
    export default function(request)
    {
      if (request.headers['content-type'] !== 'application/octet-stream')
        throw new Error('unexpected content type: ' + request.headers['content-type']);
      const buf = request.body.arrayBuffer();
      if (buf.byteLength !== 42)
        throw new Error(`unexpected body size: ${buf.byteLength}`);
      return { body: new ArrayBuffer(42) };
    }
  ]],
  ["POST custom"] = [[
    export default function(request)
    {
      if (request.headers['content-type'] !== 'foo/bar')
        throw new Error('unexpected content type: ' + request.headers['content-type']);
      const text = request.body.text();
      if (text !== 'text')
        throw new Error('unexpected body: ' + text);
      return { body: 'text' };
    }
  ]]
}
"""


@reqs.description("Test content types")
def test_content_types(network, args):
    primary, _ = network.find_nodes()

    with tempfile.NamedTemporaryFile("w") as f:
        f.write(APP_SCRIPT)
        f.flush()
        network.consortium.set_js_app(remote_node=primary, app_script_path=f.name)

    with primary.client("user0") as c:
        r = c.post("/app/text", body="text")
        assert r.status_code == http.HTTPStatus.OK, r.status_code
        assert r.headers["content-type"] == "text/plain"
        assert r.body == "text"

        r = c.post("/app/json", body={"foo": "bar"})
        assert r.status_code == http.HTTPStatus.OK, r.status_code
        assert r.headers["content-type"] == "application/json"
        assert r.body == {"foo": "bar"}

        r = c.post("/app/binary", body=b"\x00" * 42)
        assert r.status_code == http.HTTPStatus.OK, r.status_code
        assert r.headers["content-type"] == "application/octet-stream"
        assert type(r.body) == bytes, type(r.body)
        assert r.body == b"\x00" * 42, r.body

        r = c.post("/app/custom", body="text", headers={"content-type": "foo/bar"})
        assert r.status_code == http.HTTPStatus.OK, r.status_code
        assert r.headers["content-type"] == "text/plain"
        assert r.body == "text"

    return network


def run(args):
    hosts = ["localhost"] * (3 if args.consensus == "pbft" else 2)

    with infra.network.network(
        hosts, args.binary_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
    ) as network:
        network.start_and_join(args)
        network = test_content_types(network, args)


if __name__ == "__main__":

    args = infra.e2e_args.cli_args()
    args.package = "libjs_generic"
    run(args)
