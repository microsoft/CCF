# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import sys
import os
import grpc

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))

from loguru import logger as LOG
from argparse import ArgumentParser

from executors.wiki_cacher import WikiCacherExecutor
from executors.logging_app import LoggingExecutor
import infra.crypto

# pylint: disable=import-error
import executor_registration_pb2 as ExecutorRegistration

# pylint: disable=import-error
import executor_registration_pb2_grpc as RegistrationService


EXECUTORS = {
    "wiki_cacher": WikiCacherExecutor,
    "logging": LoggingExecutor,
}


def register_new_executor(
    node_public_rpc_address,
    common_dir,
    message=None,
    supported_endpoints=None,
):

    # Generate a new executor identity
    key_priv_pem, _ = infra.crypto.generate_ec_keypair()
    cert = infra.crypto.generate_cert(key_priv_pem)

    if message is None:
        # Create a default NewExecutor message
        message = ExecutorRegistration.NewExecutor()
        message.attestation.format = ExecutorRegistration.Attestation.AMD_SEV_SNP_V1
        message.attestation.quote = b"testquote"
        message.attestation.endorsements = b"testendorsement"
        message.supported_endpoints.add(method="GET", uri="/app/foo/bar")

        if supported_endpoints:
            for method, uri in supported_endpoints:
                message.supported_endpoints.add(method=method, uri=uri)

    message.cert = cert.encode()

    # Connect anonymously to register this executor
    anonymous_credentials = grpc.ssl_channel_credentials(
        open(os.path.join(common_dir, "service_cert.pem"), "rb").read()
    )

    with grpc.secure_channel(
        target=node_public_rpc_address,
        credentials=anonymous_credentials,
    ) as channel:
        stub = RegistrationService.ExecutorRegistrationStub(channel)
        r = stub.RegisterExecutor(message)
        assert r.details == "Executor registration is accepted."
        LOG.success(f"Registered new executor {r.executor_id}")

    # Create (and return) credentials that allow authentication as this new executor
    executor_credentials = grpc.ssl_channel_credentials(
        root_certificates=open(
            os.path.join(common_dir, "service_cert.pem"), "rb"
        ).read(),
        private_key=key_priv_pem.encode(),
        certificate_chain=cert.encode(),
    )

    return executor_credentials


if __name__ == "__main__":
    parser = ArgumentParser()
    parser.add_argument(
        "--executor",
        help="Executor to run",
    )
    parser.add_argument(
        "--node-public-rpc-address",
        help="Public RPC address of CCF node the executor is registered to",
    )
    parser.add_argument(
        "--network-common-dir",
        help="Path to common network directory",
    )
    parser.add_argument(
        "--supported-endpoints",
        help="Comma separated list of supported endpoints",
        type=lambda s: {tuple(e.split(":")) for e in s.split(",")},
    )
    args = parser.parse_args()

    LOG.info(f"Starting {args.executor} executor...")

    executor = EXECUTORS[args.executor](args.node_public_rpc_address)

    credentials = register_new_executor(
        args.node_public_rpc_address,
        args.network_common_dir,
        supported_endpoints=args.supported_endpoints,
    )

    executor.credentials = credentials

    executor.run_loop()
