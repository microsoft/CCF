# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import os
import time
import http
import json
import random
import re
import infra.network
import infra.proc
import infra.checker
import infra.node
import infra.crypto
import infra.member
import ccf.proposal_generator
import ccf.ledger
from infra.proposal import ProposalState

from loguru import logger as LOG


class Consortium:
    def __init__(
        self,
        common_dir,
        key_generator,
        share_script,
        members_info=None,
        curve=None,
        remote_node=None,
        authenticate_session=True,
    ):
        self.common_dir = common_dir
        self.members = []
        self.key_generator = key_generator
        self.share_script = share_script
        self.members = []
        self.recovery_threshold = None
        self.authenticate_session = authenticate_session
        # If a list of member IDs is passed in, generate fresh member identities.
        # Otherwise, recover the state of the consortium from the common directory
        # and the state of the service
        if members_info is not None:
            self.recovery_threshold = 0
            for m_local_id, has_share, m_data in members_info:
                new_member = infra.member.Member(
                    f"member{m_local_id}",
                    curve,
                    common_dir,
                    share_script,
                    has_share,
                    key_generator,
                    m_data,
                    authenticate_session=authenticate_session,
                )
                if has_share:
                    self.recovery_threshold += 1
                self.members.append(new_member)
        else:
            for f in os.listdir(self.common_dir):
                if re.search("member(.*)_cert.pem", f) is not None:
                    local_id = f.split("_")[0]
                    new_member = infra.member.Member(
                        local_id,
                        curve,
                        self.common_dir,
                        share_script,
                        is_recovery_member=os.path.isfile(
                            os.path.join(self.common_dir, f"{local_id}_enc_privk.pem")
                        ),
                        authenticate_session=authenticate_session,
                    )
                    self.members.append(new_member)
                    LOG.info(
                        f"Successfully recovered member {local_id}: {new_member.service_id}"
                    )

            # Retrieve state of service directly from ledger
            latest_public_state, _ = remote_node.get_latest_ledger_public_state()
            self.recovery_threshold = json.loads(
                latest_public_state["public:ccf.gov.service.config"][
                    ccf.ledger.WELL_KNOWN_SINGLETON_TABLE_KEY
                ]
            )["recovery_threshold"]

            if not self.members:
                LOG.warning("No consortium member to recover")
                return

            for id_bytes, info_bytes in latest_public_state[
                "public:ccf.gov.members.info"
            ].items():
                member_id = id_bytes.decode()
                member_info = json.loads(info_bytes)

                status = member_info["status"]
                member = self.get_member_by_service_id(member_id)
                if member:
                    if (
                        infra.member.MemberStatus(status)
                        == infra.member.MemberStatus.ACTIVE
                    ):
                        member.set_active()
                else:
                    LOG.warning(
                        f"Keys and certificates for consortium member {member_id} do not exist locally"
                    )

    def set_authenticate_session(self, flag):
        self.authenticate_session = flag
        for member in self.members:
            member.authenticate_session = flag

    def make_proposal(self, proposal_name, *args, **kwargs):
        func = getattr(ccf.proposal_generator, proposal_name)
        proposal, vote = func(*args, **kwargs)

        proposal_output_path = os.path.join(
            self.common_dir, f"{proposal_name}_proposal.json"
        )
        vote_output_path = os.path.join(
            self.common_dir, f"{proposal_name}_vote_for.json"
        )

        dump_args = {"indent": 2}

        LOG.debug(f"Writing proposal to {proposal_output_path}")
        with open(proposal_output_path, "w") as f:
            json.dump(proposal, f, **dump_args)

        LOG.debug(f"Writing vote to {vote_output_path}")
        with open(vote_output_path, "w") as f:
            json.dump(vote, f, **dump_args)

        return f"@{proposal_output_path}", f"@{vote_output_path}"

    def activate(self, remote_node):
        for m in self.members:
            m.ack(remote_node)

    def generate_and_propose_new_member(
        self, remote_node, curve, recovery_member=True, member_data=None
    ):
        # The Member returned by this function is in state ACCEPTED. The new Member
        # should ACK to become active.
        new_member_local_id = f"member{len(self.members)}"
        new_member = infra.member.Member(
            new_member_local_id,
            curve,
            self.common_dir,
            self.share_script,
            is_recovery_member=recovery_member,
            key_generator=self.key_generator,
            authenticate_session=self.authenticate_session,
        )

        proposal_body, careful_vote = self.make_proposal(
            "new_member",
            os.path.join(self.common_dir, f"{new_member_local_id}_cert.pem"),
            os.path.join(self.common_dir, f"{new_member_local_id}_enc_pubk.pem")
            if recovery_member
            else None,
            member_data,
        )

        proposal = self.get_any_active_member().propose(remote_node, proposal_body)
        proposal.vote_for = careful_vote

        return (proposal, new_member, careful_vote)

    def generate_and_add_new_member(
        self, remote_node, curve, recovery_member=True, member_data=None
    ):
        proposal, new_member, careful_vote = self.generate_and_propose_new_member(
            remote_node, curve, recovery_member, member_data
        )
        self.vote_using_majority(remote_node, proposal, careful_vote)

        # If the member was successfully registered, add it to the
        # local list of consortium members
        self.members.append(new_member)
        return new_member

    def get_members_info(self):
        info = []
        for m in self.members:
            info += [m.member_info]
        return info

    def get_active_members(self):
        return [member for member in self.members if member.is_active()]

    def get_active_recovery_members(self):
        return [
            member
            for member in self.members
            if (member.is_active() and member.is_recovery_member)
        ]

    def get_active_non_recovery_members(self):
        return [
            member
            for member in self.members
            if (member.is_active() and not member.is_recovery_member)
        ]

    def get_any_active_member(self, recovery_member=None):
        if recovery_member is not None:
            if recovery_member == True:
                return random.choice(self.get_active_recovery_members())
            elif recovery_member == False:
                return random.choice(self.get_active_non_recovery_members())
        else:
            return random.choice(self.get_active_members())

    def get_member_by_local_id(self, local_id):
        return next(
            (member for member in self.members if member.local_id == local_id),
            None,
        )

    def get_member_by_service_id(self, service_id):
        return next(
            (member for member in self.members if member.service_id == service_id),
            None,
        )

    def vote_using_majority(
        self, remote_node, proposal, ballot, wait_for_global_commit=True, timeout=3
    ):
        response = None

        if proposal.state != ProposalState.ACCEPTED:
            active_members = self.get_active_members()
            majority_count = int(len(self.get_active_members()) / 2 + 1)

            for member in active_members:
                if proposal.votes_for >= majority_count:
                    break

                response = member.vote(remote_node, proposal, ballot)
                if response.status_code != http.HTTPStatus.OK.value:
                    raise infra.proposal.ProposalNotAccepted(proposal)
                proposal.state = infra.proposal.ProposalState(
                    response.body.json()["state"]
                )
                proposal.increment_votes_for()

        # Wait for proposal completion to be committed, even if no votes are issued
        if wait_for_global_commit:
            with remote_node.client() as c:
                if response is None:
                    if proposal.view is None or proposal.seqno is None:
                        raise RuntimeError(
                            "Don't know what to wait for - no target TxID"
                        )
                    seqno = proposal.seqno
                    view = proposal.view
                else:
                    seqno = response.seqno
                    view = response.view
                ccf.commit.wait_for_commit(c, seqno, view, timeout=timeout)

        if proposal.state == ProposalState.ACCEPTED:
            proposal.set_completed(seqno, view)
        else:
            LOG.error(
                json.dumps(
                    self.get_proposal(remote_node, proposal.proposal_id), indent=2
                )
            )
            raise infra.proposal.ProposalNotAccepted(proposal)

        return proposal

    def get_proposal(self, remote_node, proposal_id):
        member = self.get_any_active_member()
        with remote_node.client(*member.auth()) as c:
            r = c.get(f"/gov/proposals.js/{proposal_id}")
            assert r.status_code == http.HTTPStatus.OK.value
            return r.body.json()

    def retire_node(self, remote_node, node_to_retire):
        LOG.info(f"Retiring node {node_to_retire.local_id}")
        if os.getenv("JS_GOVERNANCE"):
            proposal_body, careful_vote = self.make_proposal(
                "remove_node", node_to_retire.node_id
            )
        else:
            proposal_body, careful_vote = self.make_proposal(
                "retire_node", node_to_retire.node_id
            )
        proposal = self.get_any_active_member().propose(remote_node, proposal_body)
        self.vote_using_majority(remote_node, proposal, careful_vote)

    def trust_node(self, remote_node, node_id, timeout=3):
        if not self._check_node_exists(
            remote_node, node_id, infra.node.NodeStatus.PENDING
        ):
            raise ValueError(f"Node {node_id} does not exist in state PENDING")

        if os.getenv("JS_GOVERNANCE"):
            proposal_body, careful_vote = self.make_proposal(
                "transition_node_to_trusted", node_id
            )
        else:
            proposal_body, careful_vote = self.make_proposal("trust_node", node_id)
        proposal = self.get_any_active_member().propose(remote_node, proposal_body)
        self.vote_using_majority(
            remote_node,
            proposal,
            careful_vote,
            wait_for_global_commit=True,
            timeout=timeout,
        )

        if not self._check_node_exists(
            remote_node, node_id, infra.node.NodeStatus.TRUSTED
        ):
            raise ValueError(f"Node {node_id} does not exist in state TRUSTED")

    def remove_member(self, remote_node, member_to_remove):
        LOG.info(f"Retiring member {member_to_remove.local_id}")
        proposal_body, careful_vote = self.make_proposal(
            "remove_member", member_to_remove.service_id
        )
        proposal = self.get_any_active_member().propose(remote_node, proposal_body)
        self.vote_using_majority(remote_node, proposal, careful_vote)
        member_to_remove.set_retired()

    def trigger_ledger_rekey(self, remote_node):
        proposal_body, careful_vote = self.make_proposal("rekey_ledger")
        proposal = self.get_any_active_member().propose(remote_node, proposal_body)
        return self.vote_using_majority(remote_node, proposal, careful_vote)

    def trigger_recovery_shares_refresh(self, remote_node):
        proposal_body, careful_vote = self.make_proposal("update_recovery_shares")
        proposal = self.get_any_active_member().propose(remote_node, proposal_body)
        return self.vote_using_majority(remote_node, proposal, careful_vote)

    def user_cert_path(self, user_id):
        return os.path.join(self.common_dir, f"{user_id}_cert.pem")

    def add_user(self, remote_node, user_id, user_data=None):
        proposal, careful_vote = self.make_proposal(
            "set_user",
            self.user_cert_path(user_id),
            user_data,
        )

        proposal = self.get_any_active_member().propose(remote_node, proposal)
        return self.vote_using_majority(remote_node, proposal, careful_vote)

    def add_users(self, remote_node, users):
        for u in users:
            self.add_user(remote_node, u)

    def remove_user(self, remote_node, user_id):
        proposal, careful_vote = self.make_proposal("remove_user", user_id)

        proposal = self.get_any_active_member().propose(remote_node, proposal)
        self.vote_using_majority(remote_node, proposal, careful_vote)

    def set_user_data(self, remote_node, user_id, user_data):
        proposal, careful_vote = self.make_proposal(
            "set_user_data",
            user_id,
            user_data,
        )
        proposal = self.get_any_active_member().propose(remote_node, proposal)
        self.vote_using_majority(remote_node, proposal, careful_vote)

    def set_member_data(self, remote_node, member_service_id, member_data):
        proposal, careful_vote = self.make_proposal(
            "set_member_data",
            member_service_id,
            member_data,
        )
        proposal = self.get_any_active_member().propose(remote_node, proposal)
        self.vote_using_majority(remote_node, proposal, careful_vote)

    def set_constitution(self, remote_node, constitution_paths):
        proposal_body, careful_vote = self.make_proposal(
            "set_constitution", constitution_paths
        )
        proposal = self.get_any_active_member().propose(remote_node, proposal_body)
        return self.vote_using_majority(remote_node, proposal, careful_vote)

    def set_js_app(self, remote_node, app_bundle_path):
        proposal_body, careful_vote = self.make_proposal("set_js_app", app_bundle_path)
        proposal = self.get_any_active_member().propose(remote_node, proposal_body)
        # Large apps take a long time to process - wait longer than normal for commit
        return self.vote_using_majority(remote_node, proposal, careful_vote, timeout=10)

    def remove_js_app(self, remote_node):
        proposal_body, careful_vote = ccf.proposal_generator.remove_js_app()
        proposal = self.get_any_active_member().propose(remote_node, proposal_body)
        return self.vote_using_majority(remote_node, proposal, careful_vote)

    def set_jwt_issuer(self, remote_node, json_path):
        proposal_body, careful_vote = self.make_proposal("set_jwt_issuer", json_path)
        proposal = self.get_any_active_member().propose(remote_node, proposal_body)
        return self.vote_using_majority(remote_node, proposal, careful_vote)

    def remove_jwt_issuer(self, remote_node, issuer):
        proposal_body, careful_vote = self.make_proposal("remove_jwt_issuer", issuer)
        proposal = self.get_any_active_member().propose(remote_node, proposal_body)
        return self.vote_using_majority(remote_node, proposal, careful_vote)

    def set_jwt_public_signing_keys(self, remote_node, issuer, jwks_path):
        proposal_body, careful_vote = self.make_proposal(
            "set_jwt_public_signing_keys", issuer, jwks_path
        )
        proposal = self.get_any_active_member().propose(remote_node, proposal_body)
        return self.vote_using_majority(remote_node, proposal, careful_vote)

    def set_ca_cert_bundle(
        self, remote_node, cert_name, cert_pem_path, skip_checks=False
    ):
        proposal_body, careful_vote = self.make_proposal(
            "set_ca_cert_bundle", cert_name, cert_pem_path, skip_checks=skip_checks
        )
        proposal = self.get_any_active_member().propose(remote_node, proposal_body)
        return self.vote_using_majority(remote_node, proposal, careful_vote)

    def remove_ca_cert_bundle(self, remote_node, cert_name):
        proposal_body, careful_vote = self.make_proposal(
            "remove_ca_cert_bundle", cert_name
        )
        proposal = self.get_any_active_member().propose(remote_node, proposal_body)
        return self.vote_using_majority(remote_node, proposal, careful_vote)

    def transition_service_to_open(self, remote_node):
        """
        Assuming a network in state OPENING, this functions creates a new
        proposal and make members vote to transition the network to state
        OPEN.
        """
        is_recovery = True
        with remote_node.client() as c:
            r = c.get("/node/state")
            if r.body.json()["state"] == infra.node.State.PART_OF_NETWORK.value:
                is_recovery = False

        proposal_body, careful_vote = self.make_proposal("transition_service_to_open")
        proposal = self.get_any_active_member().propose(remote_node, proposal_body)
        self.vote_using_majority(
            remote_node, proposal, careful_vote, wait_for_global_commit=True
        )
        # If the node was already in state "PartOfNetwork", the open network
        # proposal should open the service
        if not is_recovery:
            self.check_for_service(remote_node, infra.network.ServiceStatus.OPEN)

    def recover_with_shares(self, remote_node):
        submitted_shares_count = 0
        with remote_node.client() as nc:
            check_commit = infra.checker.Checker(nc)

            for m in self.get_active_recovery_members():
                r = m.get_and_submit_recovery_share(remote_node)
                submitted_shares_count += 1
                check_commit(r)

                if submitted_shares_count >= self.recovery_threshold:
                    assert "End of recovery procedure initiated" in r.body.text()
                    break
                else:
                    assert "End of recovery procedure initiated" not in r.body.text()

    def set_recovery_threshold(self, remote_node, recovery_threshold):
        proposal_body, careful_vote = self.make_proposal(
            "set_recovery_threshold", recovery_threshold
        )
        proposal = self.get_any_active_member().propose(remote_node, proposal_body)
        proposal.vote_for = careful_vote
        r = self.vote_using_majority(remote_node, proposal, careful_vote)
        if proposal.state == infra.proposal.ProposalState.ACCEPTED:
            self.recovery_threshold = recovery_threshold
        return r

    def add_new_code(self, remote_node, new_code_id):
        if os.getenv("JS_GOVERNANCE"):
            proposal_body, careful_vote = self.make_proposal(
                "add_node_code", new_code_id
            )
        else:
            proposal_body, careful_vote = self.make_proposal(
                "new_node_code", new_code_id
            )
        proposal = self.get_any_active_member().propose(remote_node, proposal_body)
        return self.vote_using_majority(remote_node, proposal, careful_vote)

    def retire_code(self, remote_node, code_id):
        if os.getenv("JS_GOVERNANCE"):
            proposal_body, careful_vote = self.make_proposal(
                "remove_node_code", code_id
            )
        else:
            proposal_body, careful_vote = self.make_proposal(
                "retire_node_code", code_id
            )
        proposal = self.get_any_active_member().propose(remote_node, proposal_body)
        return self.vote_using_majority(remote_node, proposal, careful_vote)

    def check_for_service(self, remote_node, status):
        """
        Check the certificate associated with current CCF service signing key has been recorded in
        the KV store with the appropriate status.
        """
        with remote_node.client() as c:
            r = c.get("/node/network")
            current_status = r.body.json()["service_status"]
            current_cert = r.body.json()["service_certificate"]

            expected_cert = open(
                os.path.join(self.common_dir, "networkcert.pem"), "rb"
            ).read()

            assert (
                current_cert == expected_cert[:-1].decode()
            ), "Current service certificate did not match with networkcert.pem"
            assert (
                current_status == status.value
            ), f"Service status {current_status} (expected {status.value})"

    def _check_node_exists(self, remote_node, node_id, node_status=None):
        with remote_node.client() as c:
            r = c.get(f"/node/network/nodes/{node_id}")

            if r.status_code != http.HTTPStatus.OK.value or (
                node_status and r.body.json()["status"] != node_status.value
            ):
                return False

        return True

    def wait_for_node_to_exist_in_store(
        self,
        remote_node,
        node_id,
        timeout,
        node_status=None,
    ):
        exists = False
        end_time = time.time() + timeout
        while time.time() < end_time:
            try:
                if self._check_node_exists(remote_node, node_id, node_status):
                    exists = True
                    break
            except TimeoutError:
                LOG.warning(f"Node {node_id} has not been recorded in the store yet")
            time.sleep(0.5)
        if not exists:
            raise TimeoutError(
                f"Node {node_id} has not yet been recorded in the store"
                + getattr(node_status, f" with status {node_status.value}", "")
            )

    def wait_for_all_nodes_to_be_trusted(self, remote_node, nodes, timeout=3):
        for n in nodes:
            self.wait_for_node_to_exist_in_store(
                remote_node, n.node_id, timeout, infra.node.NodeStatus.TRUSTED
            )
