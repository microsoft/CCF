# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
from http import HTTPStatus
import tempfile
import json
import base64
import infra.network
import infra.path
import infra.proc
import infra.net
import infra.e2e_args
import suite.test_requirements as reqs
import infra.jwt_issuer

from e2e_logging import test_multi_auth

from loguru import logger as LOG


@reqs.description("JWT authentication")
def test_jwt_auth(network, args):
    primary, _ = network.find_nodes()

    issuer = infra.jwt_issuer.JwtIssuer("https://example.issuer")

    jwt_kid = "my_key_id"

    LOG.info("Add JWT issuer with initial keys")
    with tempfile.NamedTemporaryFile(prefix="ccf", mode="w+") as metadata_fp:
        jwt_cert_der = infra.crypto.cert_pem_to_der(issuer.cert_pem)
        der_b64 = base64.b64encode(jwt_cert_der).decode("ascii")
        data = {
            "issuer": issuer.name,
            "jwks": {"keys": [{"kty": "RSA", "kid": jwt_kid, "x5c": [der_b64]}]},
        }
        json.dump(data, metadata_fp)
        metadata_fp.flush()
        network.consortium.set_jwt_issuer(primary, metadata_fp.name)

    LOG.info("Calling jwt endpoint after storing keys")
    with primary.client("user0") as c:
        r = c.get("/app/jwt", headers=infra.jwt_issuer.make_bearer_header("garbage"))
        assert r.status_code == HTTPStatus.UNAUTHORIZED, r.status_code

        jwt_mismatching_key_priv_pem, _ = infra.crypto.generate_rsa_keypair(2048)
        jwt = infra.crypto.create_jwt({}, jwt_mismatching_key_priv_pem, jwt_kid)
        r = c.get("/app/jwt", headers=infra.jwt_issuer.make_bearer_header(jwt))
        assert r.status_code == HTTPStatus.UNAUTHORIZED, r.status_code

        r = c.get(
            "/app/jwt",
            headers=infra.jwt_issuer.make_bearer_header(issuer.issue_jwt(jwt_kid)),
        )
        assert r.status_code == HTTPStatus.OK, r.status_code

    return network


@reqs.description("Roled-based access")
def test_role_based_access(network, args):
    primary, _ = network.find_nodes()

    users = network.users
    assert len(users) >= 3

    # Confirm that initially, no user can read or write from the secret, or modify roles
    for user in users:
        with primary.client(user.local_id) as c:
            r = c.get("/app/secret")
            assert r.status_code == 401, r.status_code

            r = c.post("/app/secret", {"new_secret": "I'm in charge"})
            assert r.status_code == 401, r.status_code

            r = c.post(
                "/app/roles",
                {"target_id": user.service_id, "target_role": "secret_reader"},
            )
            assert r.status_code == 401, r.status_code

    # Bootstrap with a member-governance operation to give first user special role, allowing them to set other users' roles
    network.consortium.set_user_data(
        primary, users[0].service_id, {"role": "role_master"}
    )

    readers = []
    writers = []

    # First user can now assign roles of itself and others
    with primary.client(users[0].local_id) as c:
        r = c.post(
            "/app/roles",
            {"target_id": users[0].service_id, "target_role": "secret_reader"},
        )
        assert r.status_code == 204, r.status_code
        readers.append(users[0])

        r = c.post(
            "/app/roles",
            {"target_id": users[1].service_id, "target_role": "role_master"},
        )
        assert r.status_code == 204, r.status_code

    # Second user can now assign roles, thanks to assignment from first user
    with primary.client(users[1].local_id) as c:
        r = c.post(
            "/app/roles",
            {"target_id": users[2].service_id, "target_role": "secret_reader"},
        )
        assert r.status_code == 204, r.status_code
        readers.append(users[2])

        r = c.post(
            "/app/roles",
            {"target_id": users[2].service_id, "target_role": "secret_writer"},
        )
        assert r.status_code == 204, r.status_code
        writers.append(users[2])

        r = c.post(
            "/app/roles",
            {"target_id": users[3].service_id, "target_role": "secret_reader"},
        )
        assert r.status_code == 204, r.status_code
        readers.append(users[3])

    # Those role assignments allow some users to read and write
    for user in users:
        with primary.client(user.local_id) as c:
            r = c.post(
                "/app/secret", {"new_secret": f"My favourite person is {user.local_id}"}
            )
            if user in writers:
                assert r.status_code == 204, r.status_code
            else:
                assert r.status_code == 401, r.status_code

            r = c.get("/app/secret")
            if user in readers:
                assert r.status_code == 200, r.status_code
            else:
                assert r.status_code == 401, r.status_code


def run(args):
    with infra.network.network(
        args.nodes, args.binary_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
    ) as network:
        network.start_and_join(args)
        network = test_jwt_auth(network, args)
        network = test_multi_auth(network, args)
        network = test_role_based_access(network, args)


if __name__ == "__main__":

    args = infra.e2e_args.cli_args()
    args.package = "libjs_generic"
    args.nodes = infra.e2e_args.max_nodes(args, f=0)
    args.initial_user_count = 4
    args.initial_member_count = 2
    run(args)
