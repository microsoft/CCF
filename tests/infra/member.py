# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

from enum import Enum
import infra.proc
import infra.node
import infra.proposal
import infra.crypto
import http
import os
import base64


class NoRecoveryShareFound(Exception):
    def __init__(self, response):
        super(NoRecoveryShareFound, self).__init__()
        self.response = response


class MemberStatus(Enum):
    ACCEPTED = 0
    ACTIVE = 1
    RETIRED = 2


class Member:
    def __init__(self, member_id, curve, common_dir, share_script, key_generator=None):
        self.common_dir = common_dir
        self.member_id = member_id
        self.status = MemberStatus.ACCEPTED
        self.share_script = share_script

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

    def is_active(self):
        return self.status == MemberStatus.ACTIVE

    def set_active(self):
        # Use this with caution (i.e. only when the network is opening)
        self.status = MemberStatus.ACTIVE

    def propose(self, remote_node, proposal):
        with remote_node.client(f"member{self.member_id}") as mc:
            r = mc.rpc("/gov/propose", proposal, signed=True,)
            if r.status != http.HTTPStatus.OK.value:
                raise infra.proposal.ProposalNotCreated(r)

            return infra.proposal.Proposal(
                proposer_id=self.member_id,
                proposal_id=r.result["proposal_id"],
                state=infra.proposal.ProposalState(r.result["state"]),
                has_proposer_voted_for=True,
            )

    def vote(
        self,
        remote_node,
        proposal,
        accept=True,
        force_unsigned=False,
        wait_for_global_commit=True,
    ):
        ballot = """
        tables, changes = ...
        return true
        """
        with remote_node.client(f"member{self.member_id}") as mc:
            r = mc.rpc(
                "/gov/vote",
                {"ballot": {"text": ballot}, "id": proposal.proposal_id},
                signed=not force_unsigned,
            )

        if r.error is not None:
            return r

        # If the proposal was accepted, wait for it to be globally committed
        # This is particularly useful for the open network proposal to wait
        # until the global hook on the SERVICE table is triggered
        if (
            r.result["state"] == infra.proposal.ProposalState.Accepted.value
            and wait_for_global_commit
        ):
            with remote_node.client() as mc:
                # If we vote in a new node, which becomes part of quorum, the transaction
                # can only commit after it has successfully joined and caught up.
                # Given that the retry timer on join RPC is 4 seconds, anything less is very
                # likely to time out!
                infra.checker.wait_for_global_commit(
                    mc, r.seqno, r.view, True, timeout=6
                )

        return r

    def withdraw(self, remote_node, proposal):
        with remote_node.client(f"member{self.member_id}") as c:
            r = c.rpc("/gov/withdraw", {"id": proposal.proposal_id}, signed=True)
            if r.status == http.HTTPStatus.OK.value:
                proposal.state = infra.proposal.ProposalState.Withdrawn
            return r

    def update_ack_state_digest(self, remote_node):
        with remote_node.client(f"member{self.member_id}") as mc:
            r = mc.rpc("/gov/ack/update_state_digest")
            assert r.error is None, f"Error ack/update_state_digest: {r.error}"
            return bytearray(r.result["state_digest"])

    def ack(self, remote_node):
        state_digest = self.update_ack_state_digest(remote_node)
        with remote_node.client(f"member{self.member_id}") as mc:
            r = mc.rpc(
                "/gov/ack", params={"state_digest": list(state_digest)}, signed=True
            )
            assert r.error is None, f"Error ACK: {r.error}"
            self.status = MemberStatus.ACTIVE
            return r

    def get_and_decrypt_recovery_share(self, remote_node, defunct_network_enc_pubk):
        with remote_node.client(f"member{self.member_id}") as mc:
            r = mc.get("/gov/recovery_share")
            if r.status != http.HTTPStatus.OK.value:
                raise NoRecoveryShareFound(r)

            ctx = infra.crypto.CryptoBoxCtx(
                os.path.join(self.common_dir, f"member{self.member_id}_enc_privk.pem"),
                defunct_network_enc_pubk,
            )

            nonce_bytes = base64.b64decode(r.result["nonce"])
            encrypted_share_bytes = base64.b64decode(
                r.result["encrypted_recovery_share"]
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
        return infra.clients.Response.from_raw(res.stdout)
