# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

from enum import Enum
import infra.proc
import infra.proposal
import infra.crypto
import infra.clients
import http
import os
import base64
import json

from loguru import logger as LOG


class MemberEndpointException(Exception):
    def __init__(self, response, *args, **kwargs):
        super(MemberEndpointException, self).__init__(*args, **kwargs)
        self.response = response


class NoRecoveryShareFound(MemberEndpointException):
    pass


class UnauthenticatedMember(MemberEndpointException):
    """Member is not known by the service"""


class AckException(MemberEndpointException):
    pass


class MemberStatus(Enum):
    ACCEPTED = "Accepted"
    ACTIVE = "Active"


class RecoveryRole(Enum):
    NonParticipant = "NonParticipant"
    Participant = "Participant"
    Owner = "Owner"


class MemberAPI:
    class v1_Base:
        def propose(self, member, remote_node, proposal):
            with remote_node.api_versioned_client(
                *member.auth(write=True),
                api_version=self.API_VERSION,
            ) as mc:
                r = mc.post("/gov/members/proposals:create", proposal)
                if r.status_code != http.HTTPStatus.OK.value:
                    raise infra.proposal.ProposalNotCreated(r)

                return infra.proposal.Proposal(
                    proposer_id=member.local_id,
                    proposal_id=r.body.json()["proposalId"],
                    state=infra.proposal.ProposalState(r.body.json()["proposalState"]),
                    view=r.view,
                    seqno=r.seqno,
                )

        def get_proposal_raw(self, remote_node, proposal_id):
            with remote_node.api_versioned_client(
                api_version=self.API_VERSION,
            ) as c:
                r = c.get(f"/gov/members/proposals/{proposal_id}")
                if r.status_code != http.HTTPStatus.OK.value:
                    raise MemberEndpointException(r)

                return r.body.json()

        def get_proposal(self, remote_node, proposal_id):
            body = self.get_proposal_raw(remote_node, proposal_id)
            return infra.proposal.Proposal(
                proposer_id=body["proposerId"],
                proposal_id=body["proposalId"],
                state=infra.proposal.ProposalState(body["proposalState"]),
            )

        def vote(self, member, remote_node, proposal, ballot):
            with remote_node.api_versioned_client(
                *member.auth(write=True),
                api_version=self.API_VERSION,
            ) as mc:
                r = mc.post(
                    f"/gov/members/proposals/{proposal.proposal_id}/ballots/{member.service_id}:submit",
                    body=ballot,
                )
                return r

        def withdraw(self, member, remote_node, proposal):
            with remote_node.api_versioned_client(
                *member.auth(write=True),
                api_version=self.API_VERSION,
            ) as mc:
                r = mc.post(f"/gov/members/proposals/{proposal.proposal_id}:withdraw")
                if (
                    r.status_code == http.HTTPStatus.OK.value
                    and r.body.json()["proposalState"] == "Withdrawn"
                ):
                    proposal.state = infra.proposal.ProposalState.WITHDRAWN
                return r

        def update_ack_state_digest(self, member, remote_node):
            with remote_node.api_versioned_client(
                *member.auth(write=True),
                api_version=self.API_VERSION,
            ) as mc:
                return mc.post(f"/gov/members/state-digests/{member.service_id}:update")

        def ack(self, member, remote_node, state_digest):
            with remote_node.api_versioned_client(
                *member.auth(write=True),
                api_version=self.API_VERSION,
            ) as mc:
                r = mc.post(
                    f"/gov/members/state-digests/{member.service_id}:ack",
                    body=state_digest,
                )
                if r.status_code == http.HTTPStatus.UNAUTHORIZED:
                    raise UnauthenticatedMember(
                        f"Failed to ack member {member.local_id}: {r.status_code}"
                    )
                assert r.status_code == http.HTTPStatus.NO_CONTENT, r
                member.status = MemberStatus.ACTIVE
                return r

        def get_recovery_share(self, member, remote_node):
            with remote_node.api_versioned_client(
                api_version=self.API_VERSION,
            ) as mc:
                r = mc.get(f"/gov/recovery/encrypted-shares/{member.service_id}")
                if r.status_code != http.HTTPStatus.OK.value:
                    raise NoRecoveryShareFound(r)
                return r.body.json()["encryptedShare"]

    class Preview_v1(v1_Base):
        API_VERSION = infra.clients.API_VERSION_PREVIEW_01

    class v1(v1_Base):
        API_VERSION = infra.clients.API_VERSION_01

    class Classic:
        API_VERSION = infra.clients.API_VERSION_CLASSIC

        def propose(self, member, remote_node, proposal):
            with remote_node.client(*member.auth(write=True)) as mc:
                r = mc.post("/gov/proposals", proposal)
                if r.status_code != http.HTTPStatus.OK.value:
                    raise infra.proposal.ProposalNotCreated(r)

                return infra.proposal.Proposal(
                    proposer_id=member.local_id,
                    proposal_id=r.body.json()["proposal_id"],
                    state=infra.proposal.ProposalState(r.body.json()["state"]),
                    view=r.view,
                    seqno=r.seqno,
                )

        def get_proposal_raw(self, remote_node, proposal_id):
            with remote_node.client() as c:
                r = c.get(f"/gov/proposals/{proposal_id}")
                if r.status_code != http.HTTPStatus.OK.value:
                    raise MemberEndpointException(r)

                return r.body.json()

        def get_proposal(self, remote_node, proposal_id):
            body = self.get_proposal_raw(remote_node, proposal_id)
            return infra.proposal.Proposal(
                proposer_id=body["proposer_id"],
                proposal_id=proposal_id,
                state=infra.proposal.ProposalState(body["state"]),
            )

        def vote(self, member, remote_node, proposal, ballot):
            with remote_node.client(*member.auth(write=True)) as mc:
                r = mc.post(
                    f"/gov/proposals/{proposal.proposal_id}/ballots",
                    body=ballot,
                )
                return r

        def withdraw(self, member, remote_node, proposal):
            with remote_node.client(*member.auth(write=True)) as c:
                r = c.post(f"/gov/proposals/{proposal.proposal_id}/withdraw")
                if (
                    r.status_code == http.HTTPStatus.OK.value
                    and r.body.json()["state"] == "Withdrawn"
                ):
                    proposal.state = infra.proposal.ProposalState.WITHDRAWN
                return r

        def update_ack_state_digest(self, member, remote_node):
            with remote_node.client(*member.auth()) as mc:
                return mc.post("/gov/ack/update_state_digest")

        def ack(self, member, remote_node, state_digest):
            with remote_node.client(*member.auth(write=True)) as mc:
                r = mc.post("/gov/ack", body=state_digest)
                if r.status_code == http.HTTPStatus.UNAUTHORIZED:
                    raise UnauthenticatedMember(
                        f"Failed to ack member {member.local_id}: {r.status_code}"
                    )
                assert r.status_code == http.HTTPStatus.NO_CONTENT, r
                member.status = MemberStatus.ACTIVE
                return r

        def get_recovery_share(self, member, remote_node):
            with remote_node.client() as mc:
                r = mc.get(f"/gov/encrypted_recovery_share/{member.service_id}")
                if r.status_code != http.HTTPStatus.OK.value:
                    raise NoRecoveryShareFound(r)
                return r.body.json()["encrypted_share"]

    # A special client used only for lts_compatibility tests. Attempts to use latest
    # API by default, but checks node version to fallback to a supported older API
    # where required
    class LtsCompat:
        def __init__(self):
            self._preview_v1 = MemberAPI.Preview_v1()
            self._classic = MemberAPI.Classic()

        def _by_node_version(self, remote_node):
            min_version = "4.0.0"
            if remote_node.version_after(min_version):
                return self._preview_v1
            else:
                return self._classic

        def propose(self, member, remote_node, proposal):
            return self._by_node_version(remote_node).propose(
                member, remote_node, proposal
            )

        def get_proposal_raw(self, remote_node, proposal_id):
            return self._by_node_version(remote_node).get_proposal_raw(
                remote_node, proposal_id
            )

        def get_proposal(self, remote_node, proposal_id):
            return self._by_node_version(remote_node).get_proposal(
                remote_node, proposal_id
            )

        def vote(self, member, remote_node, proposal, ballot):
            return self._by_node_version(remote_node).vote(
                member, remote_node, proposal, ballot
            )

        def withdraw(self, member, remote_node, proposal):
            return self._by_node_version(remote_node).withdraw(
                member, remote_node, proposal
            )

        def update_ack_state_digest(self, member, remote_node):
            return self._by_node_version(remote_node).update_ack_state_digest(
                member, remote_node
            )

        def ack(self, member, remote_node, state_digest):
            return self._by_node_version(remote_node).ack(
                member, remote_node, state_digest
            )

        def get_recovery_share(self, member, remote_node):
            return self._by_node_version(remote_node).get_recovery_share(
                member, remote_node
            )

        def api_version(self, remote_node):
            return self._by_node_version(remote_node).API_VERSION


class Member:
    def __init__(
        self,
        local_id,
        common_dir,
        share_script,
        recovery_role=RecoveryRole.Participant,
        key_generator=None,
        curve=None,
        member_data=None,
        authenticate_session=True,
        gov_api_impl=None,
    ):
        self.common_dir = common_dir
        self.local_id = local_id
        self.status = MemberStatus.ACCEPTED
        self.share_script = share_script
        self.member_data = member_data
        self.recovery_role = recovery_role
        self.is_retired = False
        self.authenticate_session = authenticate_session
        assert self.authenticate_session == "COSE", self.authenticate_session

        if "LTS_COMPAT_GOV_CLIENT" in os.environ:
            LOG.warning("Using custom LTS compatibility mode for member client!")
            gov_api_impl = MemberAPI.LtsCompat

        self.gov_api_impl_inst = gov_api_impl()

        self.member_info = {}
        self.member_info["certificate_file"] = f"{self.local_id}_cert.pem"
        self.member_info["encryption_public_key_file"] = (
            f"{self.local_id}_enc_pubk.pem"
            if recovery_role != RecoveryRole.NonParticipant
            else None
        )
        self.member_info["data_json_file"] = (
            f"{self.local_id}_data.json" if member_data else None
        )
        if recovery_role == RecoveryRole.Owner:
            self.member_info["recovery_role"] = "Owner"

        if key_generator is not None:
            assert curve is not None

            key_generator_args = [
                "--name",
                self.local_id,
                "--curve",
                f"{curve.name}",
            ]

            if recovery_role != RecoveryRole.NonParticipant:
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
                os.path.join(self.common_dir, self.member_info["certificate_file"])
            )

        if self.member_data is not None:
            with open(
                os.path.join(self.common_dir, self.member_info["data_json_file"]),
                "w",
                encoding="utf-8",
            ) as md:
                json.dump(member_data, md)

        with open(
            os.path.join(self.common_dir, self.member_info["certificate_file"]),
            encoding="utf-8",
        ) as c:
            self.cert = c.read()
            self.service_id = infra.crypto.compute_cert_der_hash_hex_from_pem(self.cert)

        LOG.info(f"Member {self.local_id} created: {self.service_id}")

    def auth(self, write=False):
        if self.authenticate_session == "COSE":
            return (None, None, self.local_id)
        if self.authenticate_session:
            if write:
                return (self.local_id, self.local_id)
            else:
                return (self.local_id, None)
        else:
            return (None, self.local_id)

    def is_active(self):
        return self.status == MemberStatus.ACTIVE and not self.is_retired

    def set_active(self):
        # Use this with caution (i.e. only when the network is opening)
        self.status = MemberStatus.ACTIVE

    def set_retired(self):
        # Members should be marked as retired once they have been removed
        # from the service
        self.is_retired = True

    def propose(self, remote_node, proposal):
        infra.clients.get_clock().advance()
        return self.gov_api_impl_inst.propose(self, remote_node, proposal)

    def get_proposal_raw(self, remote_node, proposal_id):
        return self.gov_api_impl_inst.get_proposal_raw(remote_node, proposal_id)

    def get_proposal(self, remote_node, proposal_id):
        return self.gov_api_impl_inst.get_proposal(remote_node, proposal_id)

    def vote(self, remote_node, proposal, ballot):
        return self.gov_api_impl_inst.vote(self, remote_node, proposal, ballot)

    def withdraw(self, remote_node, proposal):
        return self.gov_api_impl_inst.withdraw(self, remote_node, proposal)

    def update_ack_state_digest(self, remote_node):
        r = self.gov_api_impl_inst.update_ack_state_digest(self, remote_node)
        if r.status_code == http.HTTPStatus.UNAUTHORIZED:
            raise UnauthenticatedMember(
                f"Failed to ack member {self.local_id}: {r.status_code}"
            )
        if r.status_code != http.HTTPStatus.OK:
            raise AckException(r, f"Failed to ack member {self.local_id}")
        return r

    def ack(self, remote_node):
        return self.gov_api_impl_inst.ack(
            self, remote_node, self.update_ack_state_digest(remote_node).body.json()
        )

    def get_and_decrypt_recovery_share(self, remote_node):
        share = self.gov_api_impl_inst.get_recovery_share(self, remote_node)

        with open(
            os.path.join(self.common_dir, f"{self.local_id}_enc_privk.pem"),
            "r",
            encoding="utf-8",
        ) as priv_enc_key:
            return infra.crypto.unwrap_key_rsa_oaep(
                base64.b64decode(share),
                priv_enc_key.read(),
            )

    def get_and_submit_recovery_share(self, remote_node):
        if self.recovery_role == RecoveryRole.NonParticipant:
            raise ValueError(f"Member {self.local_id} does not have a recovery share")

        help_res = infra.proc.ccall(self.share_script, "--help", log_output=False)
        help_res.check_returncode()
        help_out = help_res.stdout.decode()
        supports_api_version = "--api-version" in help_out
        support_member_id_cert = "--member-id-cert" in help_out

        cmd = [
            self.share_script,
            f"https://{remote_node.get_public_rpc_host()}:{remote_node.get_public_rpc_port()}",
            "--member-enc-privk",
            os.path.join(self.common_dir, f"{self.local_id}_enc_privk.pem"),
        ]

        # Versions of the script that support --member-id arguments use COSE Sign1
        # to authenticate with the service.
        if support_member_id_cert:
            cmd += [
                "--member-id-privk",
                os.path.join(self.common_dir, f"{self.local_id}_privk.pem"),
                "--member-id-cert",
                os.path.join(self.common_dir, f"{self.local_id}_cert.pem"),
            ]

        if supports_api_version:
            api_version = (
                self.gov_api_impl_inst.API_VERSION
                if hasattr(self.gov_api_impl_inst, "API_VERSION")
                else self.gov_api_impl_inst.api_version(remote_node)
            )
            cmd += ["--api-version", api_version]

        # Versions of the script that do not support --member-id arguments use
        # client certificates (forward to curl) to authenticate with the service.
        if not support_member_id_cert:
            cmd += [
                "--key",
                os.path.join(self.common_dir, f"{self.local_id}_privk.pem"),
                "--cert",
                os.path.join(self.common_dir, f"{self.local_id}_cert.pem"),
            ]

        cmd += [
            "--cacert",
            os.path.join(self.common_dir, "service_cert.pem"),
        ]

        cmd += ["-L"]

        res = infra.proc.ccall(
            *cmd,
            log_output=True,
            env=os.environ,
        )
        res.check_returncode()
        return infra.clients.Response.from_raw(res.stdout)
