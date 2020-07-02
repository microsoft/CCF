# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import array
import os
import time
import http
import random
import infra.ccf
import infra.proc
import infra.checker
import infra.node
import infra.crypto
import infra.member
from infra.proposal import ProposalState

from loguru import logger as LOG


class Consortium:
    def __init__(
        self,
        common_dir,
        key_generator,
        share_script,
        member_ids=None,
        curve=None,
        remote_node=None,
    ):
        self.common_dir = common_dir
        self.members = []
        self.key_generator = key_generator
        self.share_script = share_script
        self.members = []
        self.recovery_threshold = None
        # If a list of member IDs is passed in, generate fresh member identities.
        # Otherwise, recover the state of the consortium from the state of CCF.
        if member_ids is not None:
            for m_id in member_ids:
                new_member = infra.member.Member(
                    m_id, curve, common_dir, share_script, key_generator
                )
                self.members.append(new_member)
            self.recovery_threshold = len(self.members)
        else:
            with remote_node.client("member0") as mc:
                r = mc.rpc(
                    "gov/query",
                    {
                        "text": """tables = ...
                        non_retired_members = {}
                        tables["ccf.members"]:foreach(function(member_id, details)
                        if details["status"] ~= "RETIRED" then
                            table.insert(non_retired_members, {member_id, details["status"]})
                        end
                        end)
                        return non_retired_members
                        """
                    },
                )
                for m in r.result or []:
                    new_member = infra.member.Member(
                        m[0], curve, self.common_dir, share_script
                    )
                    if (
                        infra.member.MemberStatus[m[1]]
                        == infra.member.MemberStatus.ACTIVE
                    ):
                        new_member.set_active()
                    self.members.append(new_member)
                    LOG.info(f"Successfully recovered member {m[0]} with status {m[1]}")

                r = mc.rpc(
                    "gov/query",
                    {
                        "text": """tables = ...
                        return tables["ccf.config"]:get(0)
                        """
                    },
                )
                self.recovery_threshold = r.result["recovery_threshold"]

    def activate(self, remote_node):
        for m in self.members:
            m.ack(remote_node)

    def generate_and_propose_new_member(self, remote_node, curve):
        # The Member returned by this function is in state ACCEPTED. The new Member
        # should ACK to become active.
        new_member_id = len(self.members)
        new_member = infra.member.Member(
            new_member_id, curve, self.common_dir, self.share_script, self.key_generator
        )

        script = """
        tables, member_info = ...
        return Calls:call("new_member", member_info)
        """
        with open(
            os.path.join(self.common_dir, f"member{new_member_id}_cert.pem")
        ) as cert:
            new_member_cert_pem = [ord(c) for c in cert.read()]
        with open(
            os.path.join(self.common_dir, f"member{new_member_id}_enc_pubk.pem")
        ) as keyshare:
            new_member_keyshare = [ord(k) for k in keyshare.read()]

        return (
            self.get_any_active_member().propose(
                remote_node,
                script,
                {"cert": new_member_cert_pem, "keyshare": new_member_keyshare},
            ),
            new_member,
        )

    def generate_and_add_new_member(self, remote_node, curve):
        proposal, new_member = self.generate_and_propose_new_member(remote_node, curve)
        self.vote_using_majority(remote_node, proposal)

        # If the member was successfully registered, add it to the
        # local list of consortium members
        self.members.append(new_member)
        return new_member

    def get_members_info(self):
        members_certs = [f"member{m.member_id}_cert.pem" for m in self.members]
        members_enc_pub = [f"member{m.member_id}_enc_pubk.pem" for m in self.members]
        return list(zip(members_certs, members_enc_pub))

    def get_active_members(self):
        return [member for member in self.members if member.is_active()]

    def get_any_active_member(self):
        return random.choice(self.get_active_members())

    def get_member_by_id(self, member_id):
        return next(
            (member for member in self.members if member.member_id == member_id), None
        )

    def vote_using_majority(self, remote_node, proposal, wait_for_global_commit=True):
        # This function assumes that the proposal has just been proposed and
        # that at most, only the proposer has already voted for it when
        # proposing it
        majority_count = int(len(self.get_active_members()) / 2 + 1)

        for member in self.get_active_members():
            if proposal.votes_for >= majority_count:
                break

            # If the proposer has already voted for the proposal when it
            # was proposed, skip voting
            if (
                proposal.proposer_id == member.member_id
                and proposal.has_proposer_voted_for
            ):
                continue

            response = member.vote(
                remote_node,
                proposal,
                accept=True,
                force_unsigned=False,
                wait_for_global_commit=wait_for_global_commit,
            )
            assert response.status == http.HTTPStatus.OK.value
            proposal.state = infra.proposal.ProposalState(response.result["state"])
            proposal.increment_votes_for()

        if proposal.state is not ProposalState.Accepted:
            raise infra.proposal.ProposalNotAccepted(proposal)
        return proposal

    def get_proposals(self, remote_node):
        script = """
        tables = ...
        local proposals = {}
        tables["ccf.proposals"]:foreach( function(k, v)
            proposals[tostring(k)] = v;
        end )
        return proposals;
        """

        proposals = []
        with remote_node.client(f"member{self.get_any_active_member().member_id}") as c:
            r = c.rpc("gov/query", {"text": script})
            assert r.status == http.HTTPStatus.OK.value
            for proposal_id, attr in r.result.items():
                has_proposer_voted_for = False
                for vote in attr["votes"]:
                    if attr["proposer"] == vote[0]:
                        has_proposer_voted_for = True

                proposals.append(
                    infra.proposal.Proposal(
                        proposal_id=int(proposal_id),
                        proposer_id=int(attr["proposer"]),
                        state=infra.proposal.ProposalState(attr["state"]),
                        has_proposer_voted_for=has_proposer_voted_for,
                    )
                )
        return proposals

    def retire_node(self, remote_node, node_to_retire):
        script = """
        tables, node_id = ...
        return Calls:call("retire_node", node_id)
        """
        proposal = self.get_any_active_member().propose(
            remote_node, script, node_to_retire.node_id
        )
        self.vote_using_majority(remote_node, proposal)

        with remote_node.client(f"member{self.get_any_active_member().member_id}") as c:
            r = c.rpc("gov/read", {"table": "ccf.nodes", "key": node_to_retire.node_id})
            assert r.result["status"] == infra.node.NodeStatus.RETIRED.name

    def trust_node(self, remote_node, node_id):
        if not self._check_node_exists(
            remote_node, node_id, infra.node.NodeStatus.PENDING
        ):
            raise ValueError(f"Node {node_id} does not exist in state PENDING")

        script = """
        tables, node_id = ...
        return Calls:call("trust_node", node_id)
        """

        proposal = self.get_any_active_member().propose(remote_node, script, node_id)
        self.vote_using_majority(remote_node, proposal)

        if not self._check_node_exists(
            remote_node, node_id, infra.node.NodeStatus.TRUSTED
        ):
            raise ValueError(f"Node {node_id} does not exist in state TRUSTED")

    def retire_member(self, remote_node, member_to_retire):
        script = """
        tables, member_id = ...
        return Calls:call("retire_member", member_id)
        """
        proposal = self.get_any_active_member().propose(
            remote_node, script, member_to_retire.member_id
        )
        self.vote_using_majority(remote_node, proposal)
        member_to_retire.status = infra.member.MemberStatus.RETIRED

    def open_network(self, remote_node, pbft_open=False):
        """
        Assuming a network in state OPENING, this functions creates a new
        proposal and make members vote to transition the network to state
        OPEN.
        """
        script = """
        tables = ...
        return Calls:call("open_network")
        """
        proposal = self.get_any_active_member().propose(remote_node, script)
        self.vote_using_majority(
            remote_node, proposal, wait_for_global_commit=(not pbft_open)
        )
        self.check_for_service(remote_node, infra.ccf.ServiceStatus.OPEN, pbft_open)

    def rekey_ledger(self, remote_node):
        script = """
        tables = ...
        return Calls:call("rekey_ledger")
        """
        proposal = self.get_any_active_member().propose(remote_node, script)
        return self.vote_using_majority(remote_node, proposal)

    def update_recovery_shares(self, remote_node):
        script = """
        tables = ...
        return Calls:call("update_recovery_shares")
        """
        proposal = self.get_any_active_member().propose(remote_node, script)
        return self.vote_using_majority(remote_node, proposal)

    def add_users(self, remote_node, users):
        for u in users:
            user_cert = []
            with open(os.path.join(self.common_dir, f"user{u}_cert.pem")) as cert:
                user_cert = [ord(c) for c in cert.read()]

            script = """
            tables, user_cert = ...
            return Calls:call("new_user", user_cert)
            """
            proposal = self.get_any_active_member().propose(
                remote_node, script, user_cert
            )
            self.vote_using_majority(remote_node, proposal)

    def set_lua_app(self, remote_node, app_script):
        script = """
        tables, app = ...
        return Calls:call("set_lua_app", app)
        """
        with open(app_script) as app:
            new_lua_app = app.read()
        proposal = self.get_any_active_member().propose(
            remote_node, script, new_lua_app
        )
        return self.vote_using_majority(remote_node, proposal)

    def set_js_app(self, remote_node, app_script):
        script = """
        tables, app = ...
        return Calls:call("set_js_app", app)
        """
        with open(app_script) as app:
            new_js_app = app.read()
        proposal = self.get_any_active_member().propose(remote_node, script, new_js_app)
        return self.vote_using_majority(remote_node, proposal)

    def accept_recovery(self, remote_node):
        script = """
        tables = ...
        return Calls:call("accept_recovery")
        """
        proposal = self.get_any_active_member().propose(remote_node, script)
        return self.vote_using_majority(remote_node, proposal)

    def recover_with_shares(self, remote_node, defunct_network_enc_pubk):
        submitted_shares_count = 0
        with remote_node.client() as nc:
            check_commit = infra.checker.Checker(nc)

            for m in self.get_active_members():
                r = m.get_and_submit_recovery_share(
                    remote_node, defunct_network_enc_pubk
                )
                submitted_shares_count += 1
                check_commit(r)

                if submitted_shares_count >= self.recovery_threshold:
                    assert "End of recovery procedure initiated" in r.result
                    break
                else:
                    assert "End of recovery procedure initiated" not in r.result

    def set_recovery_threshold(self, remote_node, recovery_threshold):
        script = """
        tables, recovery_threshold = ...
        return Calls:call("set_recovery_threshold", recovery_threshold)
        """
        proposal = self.get_any_active_member().propose(
            remote_node, script, recovery_threshold
        )
        self.recovery_threshold = recovery_threshold
        return self.vote_using_majority(remote_node, proposal)

    def add_new_code(self, remote_node, new_code_id):
        script = """
        tables, code_digest = ...
        return Calls:call("new_node_code", code_digest)
        """
        code_digest = list(bytearray.fromhex(new_code_id))
        proposal = self.get_any_active_member().propose(
            remote_node, script, code_digest
        )
        return self.vote_using_majority(remote_node, proposal)

    def add_new_user_code(self, remote_node, new_code_id):
        script = """
        tables, code_digest = ...
        return Calls:call("new_user_code", code_digest)
        """
        code_digest = list(bytearray.fromhex(new_code_id))
        proposal = self.get_any_active_member().propose(
            remote_node, script, code_digest
        )
        return self.vote_using_majority(remote_node, proposal)

    def check_for_service(self, remote_node, status, pbft_open=False):
        """
        Check via the member frontend of the given node that the certificate
        associated with current CCF service signing key has been recorded in
        the KV store with the appropriate status.
        """
        # When opening the service in PBFT, the first transaction to be
        # completed when f = 1 takes a significant amount of time
        with remote_node.client(
            f"member{self.get_any_active_member().member_id}",
            request_timeout=(30 if pbft_open else 3),
        ) as c:
            r = c.rpc(
                "gov/query",
                {
                    "text": """tables = ...
                    service = tables["ccf.service"]:get(0)
                    if service == nil then
                        LOG_DEBUG("Service is nil")
                    else
                        LOG_DEBUG("Service version: ", tostring(service.version))
                        LOG_DEBUG("Service status: ", tostring(service.status))
                        cert_len = #service.cert
                        LOG_DEBUG("Service cert len: ", tostring(cert_len))
                        LOG_DEBUG("Service cert bytes: " ..
                            tostring(service.cert[math.ceil(cert_len / 4)]) .. " " ..
                            tostring(service.cert[math.ceil(cert_len / 3)]) .. " " ..
                            tostring(service.cert[math.ceil(cert_len / 2)])
                        )
                    end
                    return service
                    """
                },
            )
            current_status = r.result["status"]
            current_cert = array.array("B", r.result["cert"]).tobytes()

            expected_cert = open(
                os.path.join(self.common_dir, "networkcert.pem"), "rb"
            ).read()
            assert (
                current_cert == expected_cert
            ), "Current service certificate did not match with networkcert.pem"
            assert (
                current_status == status.name
            ), f"Service status {current_status} (expected {status.name})"

    def _check_node_exists(self, remote_node, node_id, node_status=None):
        with remote_node.client(f"member{self.get_any_active_member().member_id}") as c:
            r = c.rpc("gov/read", {"table": "ccf.nodes", "key": node_id})

            if r.error is not None or (
                node_status and r.result["status"] != node_status.name
            ):
                return False

        return True

    def wait_for_node_to_exist_in_store(
        self, remote_node, node_id, timeout, node_status=None,
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
                + getattr(node_status, f" with status {node_status.name}", "")
            )

    def wait_for_all_nodes_to_be_trusted(self, remote_node, nodes, timeout=3):
        for n in nodes:
            self.wait_for_node_to_exist_in_store(
                remote_node, n.node_id, timeout, infra.node.NodeStatus.TRUSTED
            )
