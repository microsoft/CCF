# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

from enum import Enum
import infra.proc
import infra.node
import infra.proposal
import infra.crypto
import http
import os


from loguru import logger as LOG


class NoRecoveryShareFound(Exception):
    pass


class MemberStatus(Enum):
    ACCEPTED = 0
    ACTIVE = 1
    RETIRED = 2


class Member:
    def __init__(self, member_id, curve, key_generator, common_dir):
        self.key_generator = key_generator
        self.common_dir = common_dir
        self.member_id = member_id
        self.status = MemberStatus.ACCEPTED

        # For now, all members are given a recovery key share
        member = f"member{member_id}"
        infra.proc.ccall(
            self.key_generator,
            f"--name={member}",
            f"--curve={curve.name}",
            "--gen-key-share",
            path=self.common_dir,
            log_output=False,
        ).check_returncode()

    def is_active(self):
        return self.status == MemberStatus.ACTIVE

    def set_active(self):
        # Use this with caution (i.e. only when the network is opening)
        self.status = MemberStatus.ACTIVE

    def propose(self, remote_node, script=None, params=None, vote_for=True):
        with remote_node.member_client(self.member_id) as mc:
            r = mc.rpc(
                "propose",
                {
                    "parameter": params,
                    "script": {"text": script},
                    "ballot": {"text": ("return true" if vote_for else "return false")},
                },
                signed=True,
            )
            if r.status != http.HTTPStatus.OK.value:
                raise infra.proposal.ProposalNotCreated(r)

            return infra.proposal.Proposal(
                self.member_id, r.result["proposal_id"], vote_for
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
        with remote_node.member_client(member_id=self.member_id) as mc:
            r = mc.rpc(
                "vote",
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
            with remote_node.node_client() as mc:
                infra.checker.wait_for_global_commit(mc, r.commit, r.term, True)

        return r

    def withdraw(self, remote_node, proposal):
        with remote_node.member_client(member_id=self.member_id) as c:
            r = c.rpc("withdraw", {"id": proposal.proposal_id}, signed=True)
            if r.status == http.HTTPStatus.OK.value:
                proposal.state = infra.proposal.ProposalState.Withdrawn
            return r

    def update_ack_state_digest(self, remote_node):
        with remote_node.member_client(member_id=self.member_id) as mc:
            r = mc.rpc("updateAckStateDigest")
            assert r.error is None, f"Error updateAckStateDigest: {r.error}"
            return bytearray(r.result["state_digest"])

    def ack(self, remote_node):
        state_digest = self.update_ack_state_digest(remote_node)
        with remote_node.member_client(member_id=self.member_id) as mc:
            r = mc.rpc("ack", params={"state_digest": list(state_digest)}, signed=True)
            assert r.error is None, f"Error ACK: {r.error}"
            self.status = MemberStatus.ACTIVE

    def get_and_decrypt_recovery_share(self, remote_node):
        with remote_node.member_client(member_id=self.member_id) as mc:
            r = mc.rpc("getEncryptedRecoveryShare")

            if r.status != http.HTTPStatus.OK.value:
                raise NoRecoveryShareFound(r)

            # For now, members rely on a copy of the original network encryption
            # public key to decrypt their shares
            ctx = infra.crypto.CryptoBoxCtx(
                os.path.join(
                    self.common_dir, f"member{self.member_id}_kshare_priv.pem"
                ),
                os.path.join(self.common_dir, f"network_enc_pubk_orig.pem"),
            )

            nonce_bytes = bytes(r.result["nonce"])
            encrypted_share_bytes = bytes(r.result["encrypted_share"])
            return ctx.decrypt(encrypted_share_bytes, nonce_bytes)

    def submit_recovery_share(self, remote_node, decrypted_recovery_share):
        with remote_node.member_client(member_id=self.member_id) as mc:
            r = mc.rpc(
                "submitRecoveryShare", params={"share": list(decrypted_recovery_share)}
            )
            assert r.error is None, f"Error submitting recovery share: {r.error}"
            return r
