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


class NoRecoveryShareFound(Exception):
    def __init__(self, response):
        super(NoRecoveryShareFound, self).__init__()
        self.response = response


class MemberStatus(Enum):
    ACCEPTED = 0
    ACTIVE = 1
    RETIRED = 2


class Member:
    def __init__(
        self,
        member_id,
        curve,
        common_dir,
        share_script,
        key_generator=None,
        member_data=None,
    ):
        self.common_dir = common_dir
        self.member_id = member_id
        self.status_code = MemberStatus.ACCEPTED
        self.share_script = share_script
        self.member_data = member_data

        if key_generator is not None:
            # For now, all members are given an encryption key (for recovery)
            member = f"member{member_id}"
            infra.proc.ccall(
                key_generator,
                "--name",
                f"{member}",
                "--curve",
                f"{curve.name}",
                "--gen-enc-key",
                path=self.common_dir,
                log_output=False,
            ).check_returncode()
        else:
            # If no key generator is passed in, the identity of the member
            # should have been created in advance (e.g. by a previous network)
            assert os.path.isfile(
                os.path.join(self.common_dir, f"member{self.member_id}_privk.pem")
            )
            assert os.path.isfile(
                os.path.join(self.common_dir, f"member{self.member_id}_cert.pem")
            )
            assert os.path.isfile(
                os.path.join(self.common_dir, f"member{self.member_id}_enc_privk.pem")
            )

        if member_data is not None:
            with open(
                os.path.join(self.common_dir, f"member{self.member_id}_data.json"), "w"
            ) as md:
                json.dump(member_data, md)

    def is_active(self):
        return self.status_code == MemberStatus.ACTIVE

    def set_active(self):
        # Use this with caution (i.e. only when the network is opening)
        self.status_code = MemberStatus.ACTIVE

    def propose(
        self,
        remote_node,
        proposal,
        has_proposer_voted_for=True,
        wait_for_global_commit=True,
    ):
        with remote_node.client(f"member{self.member_id}") as mc:
            r = mc.post(
                "/gov/proposals",
                proposal,
                signed=True,
            )
            if wait_for_global_commit:
                ccf.commit.wait_for_commit(mc, r.seqno, r.view)
            if r.status_code != http.HTTPStatus.OK.value:
                raise infra.proposal.ProposalNotCreated(r)

            return infra.proposal.Proposal(
                proposer_id=self.member_id,
                proposal_id=r.body.json()["proposal_id"],
                state=infra.proposal.ProposalState(r.body.json()["state"]),
                has_proposer_voted_for=has_proposer_voted_for,
            )

    def vote(
        self,
        remote_node,
        proposal,
        accept=True,
        wait_for_global_commit=True,
    ):
        with remote_node.client(f"member{self.member_id}") as mc:
            r = mc.post(
                f"/gov/proposals/{proposal.proposal_id}/votes",
                body=proposal.vote_for,
                signed=True,
            )

        if r.status_code != 200:
            return r

        # If the proposal was accepted, wait for it to be globally committed
        # This is particularly useful for the open network proposal to wait
        # until the global hook on the SERVICE table is triggered
        if (
            r.body.json()["state"] == infra.proposal.ProposalState.Accepted.value
            and wait_for_global_commit
        ):
            with remote_node.client() as mc:
                # If we vote in a new node, which becomes part of quorum, the transaction
                # can only commit after it has successfully joined and caught up.
                # Given that the retry timer on join RPC is 4 seconds, anything less is very
                # likely to time out!
                ccf.commit.wait_for_commit(mc, r.seqno, r.view, timeout=6)

        return r

    def withdraw(self, remote_node, proposal):
        with remote_node.client(f"member{self.member_id}") as c:
            r = c.post(f"/gov/proposals/{proposal.proposal_id}/withdraw", signed=True)
            if r.status_code == http.HTTPStatus.OK.value:
                proposal.state = infra.proposal.ProposalState.Withdrawn
            return r

    def update_ack_state_digest(self, remote_node):
        with remote_node.client(f"member{self.member_id}") as mc:
            r = mc.post("/gov/ack/update_state_digest")
            assert r.status_code == 200, f"Error ack/update_state_digest: {r}"
            return bytearray(r.body.json()["state_digest"])

    def ack(self, remote_node):
        state_digest = self.update_ack_state_digest(remote_node)
        with remote_node.client(f"member{self.member_id}") as mc:
            r = mc.post(
                "/gov/ack", body={"state_digest": list(state_digest)}, signed=True
            )
            assert r.status_code == 200, f"Error ACK: {r}"
            self.status_code = MemberStatus.ACTIVE
            return r

    def get_and_decrypt_recovery_share(self, remote_node, defunct_network_enc_pubk):
        with remote_node.client(f"member{self.member_id}") as mc:
            r = mc.get("/gov/recovery_share")
            if r.status_code != http.HTTPStatus.OK.value:
                raise NoRecoveryShareFound(r)

            ctx = infra.crypto.CryptoBoxCtx(
                os.path.join(self.common_dir, f"member{self.member_id}_enc_privk.pem"),
                defunct_network_enc_pubk,
            )

            nonce_bytes = base64.b64decode(r.body.json()["nonce"])
            encrypted_share_bytes = base64.b64decode(
                r.body.json()["encrypted_recovery_share"]
            )
            return ctx.decrypt(encrypted_share_bytes, nonce_bytes)

    def get_and_submit_recovery_share(self, remote_node, defunct_network_enc_pubk):
        # For now, all members are given an encryption key (for recovery)
        res = infra.proc.ccall(
            self.share_script,
            "--rpc-address",
            f"{remote_node.host}:{remote_node.rpc_port}",
            "--member-enc-privk",
            os.path.join(self.common_dir, f"member{self.member_id}_enc_privk.pem"),
            "--network-enc-pubk",
            defunct_network_enc_pubk,
            "--cert",
            os.path.join(self.common_dir, f"member{self.member_id}_cert.pem"),
            "--key",
            os.path.join(self.common_dir, f"member{self.member_id}_privk.pem"),
            "--cacert",
            os.path.join(self.common_dir, "networkcert.pem"),
            log_output=True,
        )
        res.check_returncode()
        return ccf.clients.Response.from_raw(res.stdout)
