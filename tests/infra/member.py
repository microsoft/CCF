# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

from enum import Enum
import infra.proc
import infra.proposal
import infra.crypto
import ccf.clients
import http
import os
import base64
import json
from typing import NamedTuple, Optional

from loguru import logger as LOG


class NoRecoveryShareFound(Exception):
    def __init__(self, response):
        super(NoRecoveryShareFound, self).__init__()
        self.response = response


class MemberStatus(Enum):
    ACCEPTED = "Accepted"
    ACTIVE = "Active"
    RETIRED = "Retired"


class MemberInfo(NamedTuple):
    certificate_file: str
    encryption_pub_key_file: Optional[str]
    member_data_file: Optional[str]


class Member:
    def __init__(
        self,
        local_id,
        curve,
        common_dir,
        share_script,
        is_recovery_member=True,
        key_generator=None,
        member_data=None,
        authenticate_session=True,
    ):
        self.common_dir = common_dir
        self.local_id = local_id
        self.status_code = MemberStatus.ACCEPTED
        self.share_script = share_script
        self.member_data = member_data
        self.is_recovery_member = is_recovery_member
        self.authenticate_session = authenticate_session

        self.member_info = MemberInfo(
            f"{self.local_id}_cert.pem",
            f"{self.local_id}_enc_pubk.pem" if is_recovery_member else None,
            f"{self.local_id}_data.json" if member_data else None,
        )

        if key_generator is not None:
            key_generator_args = [
                "--name",
                self.local_id,
                "--curve",
                f"{curve.name}",
            ]

            if is_recovery_member:
                key_generator_args += [
                    "--gen-enc-key",
                ]

            infra.proc.ccall(
                key_generator,
                *key_generator_args,
                path=self.common_dir,
                log_output=False,
            ).check_returncode()
        else:
            # If no key generator is passed in, the identity of the member
            # should have been created in advance (e.g. by a previous network)
            assert os.path.isfile(
                os.path.join(self.common_dir, f"{self.local_id}_privk.pem")
            )
            assert os.path.isfile(
                os.path.join(self.common_dir, self.member_info.certificate_file)
            )

        if self.member_data is not None:
            with open(
                os.path.join(self.common_dir, self.member_info.member_data_file), "w"
            ) as md:
                json.dump(member_data, md)

        with open(
            os.path.join(self.common_dir, self.member_info.certificate_file)
        ) as c:
            self.service_id = infra.crypto.compute_cert_der_hash_hex_from_pem(c.read())

        LOG.info(f"Member {self.local_id} created: {self.service_id}")

    def auth(self, write=False):
        if self.authenticate_session:
            if write:
                return (self.local_id, self.local_id)
            else:
                return (self.local_id, None)
        else:
            return (None, self.local_id)

    def is_active(self):
        return self.status_code == MemberStatus.ACTIVE

    def set_active(self):
        # Use this with caution (i.e. only when the network is opening)
        self.status_code = MemberStatus.ACTIVE

    def propose(self, remote_node, proposal):
        with remote_node.client(*self.auth(write=True)) as mc:
            r = mc.post("/gov/proposals", proposal)
            if r.status_code != http.HTTPStatus.OK.value:
                raise infra.proposal.ProposalNotCreated(r)

            return infra.proposal.Proposal(
                proposer_id=self.local_id,
                proposal_id=r.body.json()["proposal_id"],
                state=infra.proposal.ProposalState(r.body.json()["state"]),
                view=r.view,
                seqno=r.seqno,
            )

    def vote(self, remote_node, proposal, ballot):
        with remote_node.client(*self.auth(write=True)) as mc:
            r = mc.post(f"/gov/proposals/{proposal.proposal_id}/votes", body=ballot)

        return r

    def withdraw(self, remote_node, proposal):
        with remote_node.client(*self.auth(write=True)) as c:
            r = c.post(f"/gov/proposals/{proposal.proposal_id}/withdraw")
            if r.status_code == http.HTTPStatus.OK.value:
                proposal.state = infra.proposal.ProposalState.WITHDRAWN
            return r

    def update_ack_state_digest(self, remote_node):
        with remote_node.client(*self.auth()) as mc:
            r = mc.post("/gov/ack/update_state_digest")
            assert (
                r.status_code == http.HTTPStatus.OK.value
            ), f"Error ack/update_state_digest: {r}"
            return r.body.json()

    def ack(self, remote_node):
        state_digest = self.update_ack_state_digest(remote_node)
        with remote_node.client(*self.auth(write=True)) as mc:
            r = mc.post("/gov/ack", body=state_digest)
            assert r.status_code == http.HTTPStatus.NO_CONTENT, f"Error ACK: {r}"
            self.status_code = MemberStatus.ACTIVE
            return r

    def get_and_decrypt_recovery_share(self, remote_node):
        if not self.is_recovery_member:
            raise ValueError(f"Member {self.local_id} does not have a recovery share")

        with remote_node.client(*self.auth()) as mc:
            r = mc.get("/gov/recovery_share")
            if r.status_code != http.HTTPStatus.OK.value:
                raise NoRecoveryShareFound(r)

            with open(
                os.path.join(self.common_dir, f"{self.local_id}_enc_privk.pem"),
                "r",
            ) as priv_enc_key:
                return infra.crypto.unwrap_key_rsa_oaep(
                    base64.b64decode(r.body.json()["encrypted_share"]),
                    priv_enc_key.read(),
                )

    def get_and_submit_recovery_share(self, remote_node):
        if not self.is_recovery_member:
            raise ValueError(f"Member {self.local_id} does not have a recovery share")

        res = infra.proc.ccall(
            self.share_script,
            f"https://{remote_node.pubhost}:{remote_node.pubport}",
            "--member-enc-privk",
            os.path.join(self.common_dir, f"{self.local_id}_enc_privk.pem"),
            "--cert",
            os.path.join(self.common_dir, f"{self.local_id}_cert.pem"),
            "--key",
            os.path.join(self.common_dir, f"{self.local_id}_privk.pem"),
            "--cacert",
            os.path.join(self.common_dir, "networkcert.pem"),
            log_output=True,
        )
        res.check_returncode()
        return ccf.clients.Response.from_raw(res.stdout)
