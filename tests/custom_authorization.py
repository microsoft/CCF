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

AUTH_VALUE = "Bearer 42"
APP_SCRIPT = f"""
return {{
  ["GET custom_auth"] = [[
    export default function(request)
    {{
      // Header names become lower-case
      const auth = request.headers['authorization'];
      return {{ body: auth === '{AUTH_VALUE}' };
    }}
  ]]
}}
"""


@reqs.description("Test custom authorization")
def test_custom_auth(network, args):
    primary, _ = network.find_nodes()

    with tempfile.NamedTemporaryFile("w") as f:
        f.write(APP_SCRIPT)
        f.flush()
        network.consortium.set_js_app(remote_node=primary, app_script_path=f.name)

    with primary.client("user0") as c:
        r = c.get(
            "/app/custom_auth", headers={"Authorization": AUTH_VALUE}, signed=False
        )
        assert r.status_code == http.HTTPStatus.OK, r.status_code
        assert r.body

    return network


def run(args):
    hosts = ["localhost"] * (3 if args.consensus == "bft" else 2)

    with infra.network.network(
        hosts, args.binary_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
    ) as network:
        network.start_and_join(args)
        network = test_custom_auth(network, args)


if __name__ == "__main__":

    args = infra.e2e_args.cli_args()
    args.package = "libjs_generic"
    run(args)
