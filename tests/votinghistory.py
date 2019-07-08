# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.
import e2e_args
import infra.ccf
import infra.proc
import infra.remote
import json
import ledger
import msgpack
from coincurve.context import GLOBAL_CONTEXT
from coincurve.ecdsa import deserialize_recoverable, recover
from coincurve.utils import bytes_to_int, sha256

import cryptography.x509
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend

# This function calls the native API and does not rely on the
# imported library's implementation. Though not being used by
# the current test, it might still be helpful to have this
# sequence of native calls for verification, in case the
# imported library's code changes.
def verify_recover_secp256k1_bc_native(
    signature, req, hasher=sha256, context=GLOBAL_CONTEXT
):
    # Compact
    native_rec_sig = ffi.new("secp256k1_ecdsa_recoverable_signature *")
    raw_sig, rec_id = signature[:64], bytes_to_int(signature[64:])
    lib.secp256k1_ecdsa_recoverable_signature_parse_compact(
        context.ctx, native_rec_sig, raw_sig, rec_id
    )

    # Recover public key
    native_public_key = ffi.new("secp256k1_pubkey *")
    msg_hash = hasher(req) if hasher is not None else req
    lib.secp256k1_ecdsa_recover(
        context.ctx, native_public_key, native_rec_sig, msg_hash
    )

    # Convert
    native_standard_sig = ffi.new("secp256k1_ecdsa_signature *")
    lib.secp256k1_ecdsa_recoverable_signature_convert(
        context.ctx, native_standard_sig, native_rec_sig
    )

    # Verify
    ret = lib.secp256k1_ecdsa_verify(
        context.ctx, native_standard_sig, msg_hash, native_public_key
    )


def verify_recover_secp256k1_bc(signature, req, hasher=sha256, context=GLOBAL_CONTEXT):
    msg_hash = hasher(req) if hasher is not None else req
    rec_sig = coincurve.ecdsa.deserialize_recoverable(signature)
    public_key = coincurve.PublicKey(coincurve.ecdsa.recover(req, rec_sig))
    n_sig = coincurve.ecdsa.recoverable_convert(rec_sig)

    if not lib.secp256k1_ecdsa_verify(
        context.ctx, n_sig, msg_hash, public_key.public_key
    ):
        raise RuntimeError("Failed to verify SECP256K1 bitcoin signature")


def verify_sig(raw_cert, sig, req):
    try:
        cert = cryptography.x509.load_der_x509_certificate(
            raw_cert, backend=default_backend()
        )
        pub_key = cert.public_key()
        hash_alg = ec.ECDSA(cert.signature_hash_algorithm)
        pub_key.verify(sig, req, hash_alg)
    except cryptography.exceptions.InvalidSignature as e:
        # we support a non-standard curve, which is also being
        # used for bitcoin.
        if curve_name != "secp256k1":
            raise e

        verify_recover_secp256k1_bc(sig, req)


def run(args):
    hosts = ["localhost", "localhost"]

    ledger_filename = None

    with infra.ccf.network(
        hosts, args.build_dir, args.debug_nodes, args.perf_nodes, pdb=args.pdb
    ) as network:
        primary, others = network.start_and_join(args)

        # propose to add a new member
        # proposal number 0
        infra.proc.ccall("./genesisgenerator", "cert", "--name=member4")
        result = infra.proc.ccall(
            "./memberclient",
            "add_member",
            "--cert=member1_cert.pem",
            "--privk=member1_privk.pem",
            "--host={}".format(primary.host),
            "--port={}".format(primary.tls_port),
            "--member_cert=member4_cert.pem",
            "--ca=networkcert.pem",
        )

        # when proposal is added the proposal id and the result of running complete proposal are returned
        j_result = json.loads(result.stdout)
        assert not j_result["result"]["completed"]
        assert j_result["result"]["id"] == 0

        # 2 out of 3 members vote to accept the new member so that that member can send its own proposals
        result = infra.proc.ccall(
            "./memberclient",
            "vote",
            "--accept",
            "--cert=member1_cert.pem",
            "--privk=member1_privk.pem",
            "--host={}".format(primary.host),
            "--port={}".format(primary.tls_port),
            "--id=0",
            "--ca=networkcert.pem",
        )
        j_result = json.loads(result.stdout)
        assert not j_result["result"]

        # this request should fail, as it is not signed
        result = infra.proc.ccall(
            "./memberclient",
            "vote",
            "--accept",
            "--cert=member2_cert.pem",
            "--privk=member2_privk.pem",
            "--host={}".format(primary.host),
            "--port={}".format(primary.tls_port),
            "--id=0",
            "--ca=networkcert.pem",
            "--force-unsigned",
        )
        j_result = json.loads(result.stdout)
        assert j_result["error"]["code"] == infra.jsonrpc.ErrorCode.RPC_NOT_SIGNED.value

        result = infra.proc.ccall(
            "./memberclient",
            "vote",
            "--accept",
            "--cert=member2_cert.pem",
            "--privk=member2_privk.pem",
            "--host={}".format(primary.host),
            "--port={}".format(primary.tls_port),
            "--id=0",
            "--ca=networkcert.pem",
        )
        j_result = json.loads(result.stdout)
        assert j_result["result"]

        ledger_filename = network.find_leader()[0].remote.ledger_path()

    l = ledger.Ledger(ledger_filename)

    # this maps a member_id to a cert object, and is updated when we iterate the transactions,
    # so that we always have the correct cert for a member on a given transaction
    members = {}
    verified_votes = 0
    for tr in l:
        tables = tr.get_public_domain().get_tables()
        members_table = tables["membercerts"]
        for cert, member_id in members_table.items():
            members[member_id] = cert

        if "votinghistory" in tables:
            votinghistory_table = tables["votinghistory"]
            for member_id, signed_request in votinghistory_table.items():
                # if the signed vote is stored - there has to be a member at this point
                assert member_id in members
                cert = members[member_id]
                sig = signed_request[0][0]
                req = signed_request[0][1]
                verify_sig(cert, sig, req)
                verified_votes += 1

    assert verified_votes >= 2


if __name__ == "__main__":

    args = e2e_args.cli_args()
    args.package = "libloggingenc"
    run(args)
