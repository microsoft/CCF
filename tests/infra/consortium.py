# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import os
import http
import json
import random
import infra.network
import infra.proc
import infra.checker
import infra.node
import infra.crypto
import infra.member
from infra.proposal import ProposalState
import shutil
import tempfile
import glob
import datetime
import infra.clients

from cryptography import x509
import cryptography.hazmat.backends as crypto_backends

from loguru import logger as LOG


def slurp_file(path):
    return open(path, encoding="utf-8").read()


def slurp_json(path):
    return json.load(open(path, encoding="utf-8"))


def read_modules(modules_path):
    modules = []
    for path in glob.glob(f"{modules_path}/**/*", recursive=True):
        if not os.path.isfile(path):
            continue
        rel_module_name = os.path.relpath(path, modules_path)
        rel_module_name = rel_module_name.replace("\\", "/")  # Windows support
        modules.append({"name": rel_module_name, "module": slurp_file(path)})
    return modules


class Consortium:
    def __init__(
        self,
        common_dir,
        key_generator,
        share_script,
        consensus,
        authenticate_session="COSE",
        gov_api_version=infra.member.MemberAPI.Preview_v1.API_VERSION,
    ):
        self.common_dir = common_dir
        self.members = []
        self.key_generator = key_generator
        self.share_script = share_script
        self.consensus = consensus
        self.recovery_threshold = 0
        self.authenticate_session = authenticate_session
        self.set_gov_api_version(gov_api_version)

    def add_member(self, member):
        self.members.append(member)

    def generate_new_member(self, curve, recovery_role, member_data):
        new_member_local_id = f"member{len(self.members)}"
        new_member = infra.member.Member(
            new_member_local_id,
            self.common_dir,
            self.share_script,
            recovery_role=recovery_role,
            key_generator=self.key_generator,
            curve=curve,
            member_data=member_data,
            authenticate_session=self.authenticate_session,
            gov_api_impl=self.gov_api_impl,
        )
        return new_member

    def generate_existing_member(self, local_id, recovery_role):
        new_member = infra.member.Member(
            local_id,
            self.common_dir,
            self.share_script,
            recovery_role=recovery_role,
            authenticate_session=self.authenticate_session,
            gov_api_impl=self.gov_api_impl,
        )
        return new_member

    def update_recovery_threshold_from_node(self, node):
        with node.client() as c:
            r = c.get("/node/service/configuration")
            assert r.status_code == 200
            self.recovery_threshold = r.body.json()["recovery_threshold"]

    def set_authenticate_session(self, flag):
        self.authenticate_session = flag
        for member in self.members:
            member.authenticate_session = flag

    def set_gov_api_version(self, version_s):
        for cls in (
            infra.member.MemberAPI.Preview_v1,
            infra.member.MemberAPI.v1,
        ):
            if version_s == cls.API_VERSION:
                self.gov_api_impl = cls
                break
        else:
            raise ValueError(f"Unsupported gov API version: {version_s}")

    def make_proposal(self, proposal_name, **kwargs):
        action = {
            "name": proposal_name,
        }
        if kwargs:
            args = {}
            for k, v in kwargs.items():
                if v is not None:
                    if isinstance(v, datetime.datetime):
                        args[k] = str(v)
                    else:
                        args[k] = v
            action["args"] = args

        proposal_body = {"actions": [action]}

        trivial_vote_for = (
            "export function vote (rawProposal, proposerId) { return true }"
        )
        ballot_body = {"ballot": trivial_vote_for}

        proposal_output_path = os.path.join(
            self.common_dir, f"{proposal_name}_proposal.json"
        )
        ballot_output_path = os.path.join(
            self.common_dir, f"{proposal_name}_vote_for.json"
        )

        LOG.debug(f"Writing proposal to {proposal_output_path}")
        with open(proposal_output_path, "w", encoding="utf-8") as f:
            json.dump(proposal_body, f, indent=2)

        LOG.debug(f"Writing ballot to {ballot_output_path}")
        with open(ballot_output_path, "w", encoding="utf-8") as f:
            json.dump(ballot_body, f, indent=2)

        return f"@{proposal_output_path}", f"@{ballot_output_path}"

    def activate(self, remote_node):
        for m in [m for m in self.members if not m.is_retired]:
            m.ack(remote_node)

    def generate_and_propose_new_member(
        self,
        remote_node,
        curve,
        recovery_role=infra.member.RecoveryRole.Participant,
        member_data=None,
    ):
        # The Member returned by this function is in state ACCEPTED. The new Member
        # should ACK to become active.
        new_member = self.generate_new_member(
            curve=curve,
            recovery_role=recovery_role,
            member_data=member_data,
        )

        proposal_body, careful_vote = self.make_proposal(
            "set_member",
            cert=slurp_file(
                os.path.join(self.common_dir, f"{new_member.local_id}_cert.pem")
            ),
            encryption_pub_key=(
                slurp_file(
                    os.path.join(self.common_dir, f"{new_member.local_id}_enc_pubk.pem")
                )
                if recovery_role != infra.member.RecoveryRole.NonParticipant
                else None
            ),
            member_data=member_data,
            recovery_role=(
                "Owner" if recovery_role == infra.member.RecoveryRole.Owner else None
            ),
        )

        proposal = self.get_any_active_member().propose(remote_node, proposal_body)
        proposal.vote_for = careful_vote

        return (proposal, new_member, careful_vote)

    def generate_and_add_new_member(
        self,
        remote_node,
        curve,
        recovery_role=infra.member.RecoveryRole.Participant,
        member_data=None,
    ):
        proposal, new_member, careful_vote = self.generate_and_propose_new_member(
            remote_node, curve, recovery_role, member_data
        )
        self.vote_using_majority(remote_node, proposal, careful_vote)

        # If the member was successfully registered, add it to the
        # local list of consortium members
        self.add_member(new_member)
        return new_member

    def get_members_info(self):
        info = []
        for m in self.members:
            info += [m.member_info]
        return info

    def get_active_members(self):
        return [member for member in self.members if member.is_active()]

    def get_active_recovery_participants(self):
        return [
            member
            for member in self.members
            if (
                member.is_active()
                and member.recovery_role == infra.member.RecoveryRole.Participant
            )
        ]

    def get_active_recovery_owners(self):
        return [
            member
            for member in self.members
            if (
                member.is_active()
                and member.recovery_role == infra.member.RecoveryRole.Owner
            )
        ]

    def get_active_non_recovery_members(self):
        return [
            member
            for member in self.members
            if (
                member.is_active()
                and member.recovery_role == infra.member.RecoveryRole.NonParticipant
            )
        ]

    def get_any_active_member(self, recovery_role=None):
        if recovery_role is not None:
            if recovery_role is infra.member.RecoveryRole.Owner:
                return random.choice(self.get_active_recovery_owners())
            elif recovery_role is infra.member.RecoveryRole.Participant:
                return random.choice(self.get_active_recovery_participants())
            else:
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
        self, remote_node, proposal, ballot, wait_for_commit=True, timeout=5
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
                    raise infra.proposal.ProposalNotAccepted(proposal, response)
                body = response.body.json()
                proposal_state = body.get("state", body.get("proposalState"))
                assert proposal_state, f"Could not find proposal state in {body}"
                proposal.state = infra.proposal.ProposalState(proposal_state)
                proposal.increment_votes_for(member.service_id)

        if response is None:
            if proposal.view is None or proposal.seqno is None:
                raise RuntimeError("Don't know what to wait for - no target TxID")
            seqno = proposal.seqno
            view = proposal.view
        else:
            seqno = response.seqno
            view = response.view

        # Wait for proposal completion to be committed, even if no votes are issued
        if wait_for_commit:
            with remote_node.client() as c:
                infra.commit.wait_for_commit(c, seqno, view, timeout=timeout)

        if proposal.state == ProposalState.ACCEPTED:
            proposal.set_completed(seqno, view)
        else:
            LOG.error(
                json.dumps(
                    self.get_proposal(remote_node, proposal.proposal_id), indent=2
                )
            )
            raise infra.proposal.ProposalNotAccepted(proposal, response)

        return proposal

    def get_proposal_raw(self, remote_node, proposal_id):
        return self.get_any_active_member().get_proposal_raw(remote_node, proposal_id)

    def get_proposal(self, remote_node, proposal_id):
        return self.get_any_active_member().get_proposal(remote_node, proposal_id)

    def retire_node(self, remote_node, node_to_retire, timeout=10):
        pending = False
        with remote_node.client(connection_timeout=timeout) as c:
            r = c.get(f"/node/network/nodes/{node_to_retire.node_id}")
            pending = r.body.json()["status"] == infra.node.State.PENDING.value
        LOG.info(f"Retiring node {node_to_retire.local_node_id}")
        proposal_body, careful_vote = self.make_proposal(
            "remove_node",
            node_id=node_to_retire.node_id,
        )
        proposal = self.get_any_active_member().propose(remote_node, proposal_body)
        self.vote_using_majority(remote_node, proposal, careful_vote)
        return pending

    def trust_nodes(
        self,
        remote_node,
        node_ids,
        valid_from,
        validity_period_days=None,
        **kwargs,
    ):
        proposal_body = {"actions": []}
        for node_id in node_ids:
            proposal_args = {"node_id": node_id, "valid_from": str(valid_from)}
            if validity_period_days is not None:
                proposal_args["validity_period_days"] = validity_period_days
            proposal_body["actions"].append(
                {"name": "transition_node_to_trusted", "args": proposal_args}
            )
        proposal = self.get_any_active_member().propose(remote_node, proposal_body)
        self.vote_using_majority(
            remote_node,
            proposal,
            {"ballot": "export function vote (proposal, proposer_id) { return true }"},
            **kwargs,
        )

    def replace_node(
        self,
        remote_node,
        node_to_retire,
        node_to_add,
        valid_from,
        validity_period_days=None,
        **kwargs,
    ):
        proposal_body = {"actions": []}
        trust_args = {"node_id": node_to_add.node_id, "valid_from": str(valid_from)}
        if validity_period_days is not None:
            trust_args["validity_period_days"] = validity_period_days
        proposal_body["actions"].append(
            {"name": "transition_node_to_trusted", "args": trust_args}
        )
        proposal_body["actions"].append(
            {"name": "remove_node", "args": {"node_id": node_to_retire.node_id}}
        )
        proposal = self.get_any_active_member().propose(remote_node, proposal_body)
        self.vote_using_majority(
            remote_node,
            proposal,
            {"ballot": "export function vote (proposal, proposer_id) { return true }"},
            **kwargs,
        )

    def trust_node(self, remote_node, node_id, *args, **kwargs):
        return self.trust_nodes(remote_node, [node_id], *args, **kwargs)

    def remove_member(self, remote_node, member_to_remove):
        LOG.info(f"Retiring member {member_to_remove.local_id}")
        proposal_body, careful_vote = self.make_proposal(
            "remove_member", member_id=member_to_remove.service_id
        )
        proposal = self.get_any_active_member().propose(remote_node, proposal_body)
        self.vote_using_majority(remote_node, proposal, careful_vote)
        member_to_remove.set_retired()

    def trigger_ledger_rekey(self, remote_node):
        proposal_body, careful_vote = self.make_proposal("trigger_ledger_rekey")
        proposal = self.get_any_active_member().propose(remote_node, proposal_body)
        return self.vote_using_majority(remote_node, proposal, careful_vote)

    def trigger_recovery_shares_refresh(self, remote_node):
        proposal_body, careful_vote = self.make_proposal(
            "trigger_recovery_shares_refresh"
        )
        proposal = self.get_any_active_member().propose(remote_node, proposal_body)
        return self.vote_using_majority(remote_node, proposal, careful_vote)

    def user_cert_path(self, user_id):
        return os.path.join(self.common_dir, f"{user_id}_cert.pem")

    def add_user(self, remote_node, user_id, user_data=None):
        proposal, careful_vote = self.make_proposal(
            "set_user",
            cert=slurp_file(self.user_cert_path(user_id)),
            user_data=user_data,
        )

        proposal = self.get_any_active_member().propose(remote_node, proposal)
        return self.vote_using_majority(remote_node, proposal, careful_vote)

    def get_service_identity(self):
        return slurp_file(os.path.join(self.common_dir, "service_cert.pem"))

    def add_users_and_transition_service_to_open(self, remote_node, users):
        proposal = {"actions": []}
        for user_id in users:
            cert = slurp_file(self.user_cert_path(user_id))
            proposal["actions"].append({"name": "set_user", "args": {"cert": cert}})

        args = {}
        if remote_node.version_after("ccf-2.0.0-rc3"):
            args = {"args": {"next_service_identity": self.get_service_identity()}}
        proposal["actions"].append({"name": "transition_service_to_open", **args})

        proposal = self.get_any_active_member().propose(remote_node, proposal)
        return self.vote_using_majority(
            remote_node,
            proposal,
            {"ballot": "export function vote (proposal, proposer_id) { return true }"},
        )

    def create_and_withdraw_large_proposal(self, remote_node, wait_for_commit=False):
        """
        This is useful to force a ledger chunk to be produced, which is desirable
        when trying to use ccf.ledger to read ledger entries.
        """
        proposal, _ = self.make_proposal(
            "set_user",
            cert=slurp_file(self.user_cert_path("user0")),
            user_data={"padding": "x" * 4096 * 5},
        )
        m = self.get_any_active_member()
        p = m.propose(remote_node, proposal)
        r = m.withdraw(remote_node, p)
        if wait_for_commit:
            with remote_node.client() as c:
                c.wait_for_commit(r)

    def add_users(self, remote_node, users):
        for u in users:
            self.add_user(remote_node, u)

    def remove_user(self, remote_node, user_id):
        proposal, careful_vote = self.make_proposal("remove_user", user_id=user_id)

        proposal = self.get_any_active_member().propose(remote_node, proposal)
        self.vote_using_majority(remote_node, proposal, careful_vote)

    def set_user_data(self, remote_node, user_id, user_data):
        proposal, careful_vote = self.make_proposal(
            "set_user_data",
            user_id=user_id,
            user_data=user_data,
        )
        proposal = self.get_any_active_member().propose(remote_node, proposal)
        self.vote_using_majority(remote_node, proposal, careful_vote)

    def set_member_data(self, remote_node, member_service_id, member_data):
        proposal, careful_vote = self.make_proposal(
            "set_member_data",
            member_id=member_service_id,
            member_data=member_data,
        )
        proposal = self.get_any_active_member().propose(remote_node, proposal)
        self.vote_using_majority(remote_node, proposal, careful_vote)

    def set_constitution(self, remote_node, constitution_paths):
        concatenated = "\n".join(slurp_file(path) for path in constitution_paths)
        proposal_body, careful_vote = self.make_proposal(
            "set_constitution", constitution=concatenated
        )
        proposal = self.get_any_active_member().propose(remote_node, proposal_body)
        return self.vote_using_majority(remote_node, proposal, careful_vote)

    def assert_service_identity(self, remote_node, service_cert_path):
        service_cert_pem = slurp_file(service_cert_path)
        proposal_body, careful_vote = self.make_proposal(
            "assert_service_identity", service_identity=service_cert_pem
        )
        proposal = self.get_any_active_member().propose(remote_node, proposal_body)
        return self.vote_using_majority(remote_node, proposal, careful_vote)

    def read_bundle_from_dir(self, bundle_path):
        if os.path.isfile(bundle_path):
            tmp_dir = tempfile.TemporaryDirectory(prefix="ccf")
            shutil.unpack_archive(bundle_path, tmp_dir.name)
            bundle_path = tmp_dir.name
        modules_path = os.path.join(bundle_path, "src")
        modules = read_modules(modules_path)

        # read metadata
        metadata_path = os.path.join(bundle_path, "app.json")
        with open(metadata_path, encoding="utf-8") as f:
            metadata = json.load(f)

        # sanity checks
        module_paths = set(module["name"] for module in modules)
        for url, methods in metadata["endpoints"].items():
            for method, endpoint in methods.items():
                module_path = endpoint["js_module"]
                if module_path not in module_paths:
                    raise ValueError(
                        f"{method} {url}: module '{module_path}' not found in bundle"
                    )

        return {"metadata": metadata, "modules": modules}

    def set_js_app_from_dir(
        self, remote_node, bundle_path, disable_bytecode_cache=False
    ):
        bundle = self.read_bundle_from_dir(bundle_path)
        return self.set_js_app_from_bundle(
            remote_node, bundle, disable_bytecode_cache=disable_bytecode_cache
        )

    def set_js_app_from_bundle(self, remote_node, bundle, disable_bytecode_cache=False):
        proposal_body, careful_vote = self.make_proposal(
            "set_js_app",
            bundle=bundle,
            disable_bytecode_cache=disable_bytecode_cache,
        )

        proposal = self.get_any_active_member().propose(remote_node, proposal_body)
        # Large apps take a long time to process - wait longer than normal for commit
        return self.vote_using_majority(remote_node, proposal, careful_vote, timeout=30)

    def set_js_runtime_options(
        self,
        remote_node,
        max_heap_bytes,
        max_stack_bytes,
        max_execution_time_ms,
        log_exception_details=False,
        return_exception_details=False,
        max_cached_interpreters=None,
    ):
        proposal_body, careful_vote = self.make_proposal(
            "set_js_runtime_options",
            max_heap_bytes=max_heap_bytes,
            max_stack_bytes=max_stack_bytes,
            max_execution_time_ms=max_execution_time_ms,
            log_exception_details=log_exception_details,
            return_exception_details=return_exception_details,
            max_cached_interpreters=max_cached_interpreters,
        )
        proposal = self.get_any_active_member().propose(remote_node, proposal_body)
        return self.vote_using_majority(remote_node, proposal, careful_vote)

    def remove_js_app(self, remote_node):
        proposal_body, careful_vote = self.make_proposal("remove_js_app")
        proposal = self.get_any_active_member().propose(remote_node, proposal_body)
        return self.vote_using_majority(remote_node, proposal, careful_vote)

    def refresh_js_app_bytecode_cache(self, remote_node):
        proposal_body, careful_vote = self.make_proposal(
            "refresh_js_app_bytecode_cache"
        )
        proposal = self.get_any_active_member().propose(remote_node, proposal_body)
        return self.vote_using_majority(remote_node, proposal, careful_vote)

    def set_jwt_issuer(self, remote_node, json_path):
        obj = slurp_json(json_path)
        args = {
            # Key filter is no longer used, but kept for compatibility with
            # lts_compatibility tests.
            "key_filter": "all",
            "issuer": obj["issuer"],
            "ca_cert_bundle_name": obj.get("ca_cert_bundle_name"),
            "auto_refresh": obj.get("auto_refresh", False),
            "jwks": obj.get("jwks"),
        }
        proposal_body, careful_vote = self.make_proposal("set_jwt_issuer", **args)
        proposal = self.get_any_active_member().propose(remote_node, proposal_body)
        return self.vote_using_majority(remote_node, proposal, careful_vote)

    def remove_jwt_issuer(self, remote_node, issuer):
        proposal_body, careful_vote = self.make_proposal(
            "remove_jwt_issuer", issuer=issuer
        )
        proposal = self.get_any_active_member().propose(remote_node, proposal_body)
        return self.vote_using_majority(remote_node, proposal, careful_vote)

    def set_jwt_public_signing_keys(self, remote_node, issuer, jwks_path):
        obj = slurp_json(jwks_path)
        proposal_body, careful_vote = self.make_proposal(
            "set_jwt_public_signing_keys", issuer=issuer, jwks=obj
        )
        proposal = self.get_any_active_member().propose(remote_node, proposal_body)
        return self.vote_using_majority(remote_node, proposal, careful_vote)

    def set_ca_cert_bundle(
        self, remote_node, cert_name, cert_bundle_path, skip_checks=False
    ):
        if not skip_checks:
            cert_bundle_pem = slurp_file(cert_bundle_path)
            delim = "-----END CERTIFICATE-----"
            for cert_pem in cert_bundle_pem.split(delim):
                if not cert_pem.strip():
                    continue
                cert_pem += delim
                try:
                    x509.load_pem_x509_certificate(
                        cert_pem.encode(), crypto_backends.default_backend()
                    )
                except Exception as exc:
                    raise ValueError("Cannot parse PEM certificate") from exc

        proposal_body, careful_vote = self.make_proposal(
            "set_ca_cert_bundle",
            name=cert_name,
            cert_bundle=slurp_file(cert_bundle_path),
        )
        proposal = self.get_any_active_member().propose(remote_node, proposal_body)
        return self.vote_using_majority(remote_node, proposal, careful_vote)

    def remove_ca_cert_bundle(self, remote_node, cert_name):
        proposal_body, careful_vote = self.make_proposal(
            "remove_ca_cert_bundle", name=cert_name
        )
        proposal = self.get_any_active_member().propose(remote_node, proposal_body)
        return self.vote_using_majority(remote_node, proposal, careful_vote)

    def transition_service_to_open(self, remote_node, previous_service_identity=None):
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

        args = {}
        if remote_node.version_after("ccf-2.0.0-rc3"):
            args = {
                "previous_service_identity": previous_service_identity,
                "next_service_identity": self.get_service_identity(),
            }

        proposal_body, careful_vote = self.make_proposal(
            "transition_service_to_open", **args
        )

        proposal = self.get_any_active_member().propose(remote_node, proposal_body)
        self.vote_using_majority(
            remote_node, proposal, careful_vote, wait_for_commit=True
        )
        # If the node was already in state "PartOfNetwork", the open network
        # proposal should open the service
        if not is_recovery:
            self.check_for_service(remote_node, infra.network.ServiceStatus.OPEN)

    def recover_with_shares(self, remote_node):
        submitted_shares_count = 0
        with remote_node.client() as nc:
            check_commit = infra.checker.Checker(nc)

            for m in self.get_active_recovery_participants():
                r = m.get_and_submit_recovery_share(remote_node)
                submitted_shares_count += 1
                check_commit(r)

                assert (
                    f"{submitted_shares_count}/{self.recovery_threshold}"
                    in r.body.text()
                )
                if submitted_shares_count >= self.recovery_threshold:
                    assert "End of recovery procedure initiated" in r.body.text()
                    break
                else:
                    assert "End of recovery procedure initiated" not in r.body.text()

    def recover_with_owner_share(self, remote_node):
        submitted_shares_count = 0
        with remote_node.client() as nc:
            check_commit = infra.checker.Checker(nc)

            m = self.get_any_active_member(
                recovery_role=infra.member.RecoveryRole.Owner
            )
            r = m.get_and_submit_recovery_share(remote_node)
            submitted_shares_count += 1
            check_commit(r)
            assert "Full recovery key successfully submitted" in r.body.text()
            assert "End of recovery procedure initiated" in r.body.text()

    def set_recovery_threshold(self, remote_node, recovery_threshold):
        proposal_body, careful_vote = self.make_proposal(
            "set_recovery_threshold", recovery_threshold=recovery_threshold
        )
        proposal = self.get_any_active_member().propose(remote_node, proposal_body)
        proposal.vote_for = careful_vote
        r = self.vote_using_majority(remote_node, proposal, careful_vote)
        if proposal.state == infra.proposal.ProposalState.ACCEPTED:
            self.recovery_threshold = recovery_threshold
        return r

    def add_measurement(self, remote_node, platform, measurement):
        if platform == "sgx":
            return self.add_new_code(remote_node, measurement)
        elif platform == "virtual":
            return self.add_virtual_measurement(remote_node, measurement)
        elif platform == "snp":
            return self.add_snp_measurement(remote_node, measurement)
        else:
            raise ValueError(f"Unsupported platform {platform}")

    def add_new_code(self, remote_node, new_code_id):
        proposal_body, careful_vote = self.make_proposal(
            "add_node_code", code_id=new_code_id
        )
        proposal = self.get_any_active_member().propose(remote_node, proposal_body)
        return self.vote_using_majority(remote_node, proposal, careful_vote)

    def add_virtual_measurement(self, remote_node, measurement):
        proposal_body, careful_vote = self.make_proposal(
            "add_virtual_measurement", measurement=measurement
        )
        proposal = self.get_any_active_member().propose(remote_node, proposal_body)
        return self.vote_using_majority(remote_node, proposal, careful_vote)

    def add_snp_measurement(self, remote_node, measurement):
        proposal_body, careful_vote = self.make_proposal(
            "add_snp_measurement", measurement=measurement
        )
        proposal = self.get_any_active_member().propose(remote_node, proposal_body)
        return self.vote_using_majority(remote_node, proposal, careful_vote)

    def add_snp_uvm_endorsement(self, remote_node, did, feed, svn):
        proposal_body, careful_vote = self.make_proposal(
            "add_snp_uvm_endorsement", did=did, feed=feed, svn=svn
        )
        proposal = self.get_any_active_member().propose(remote_node, proposal_body)
        return self.vote_using_majority(remote_node, proposal, careful_vote)

    def remove_measurement(self, remote_node, platform, measurement):
        if platform == "sgx":
            return self.retire_code(remote_node, measurement)
        elif platform == "virtual":
            return self.remove_virtual_measurement(remote_node, measurement)
        elif platform == "snp":
            return self.remove_snp_measurement(remote_node, measurement)
        else:
            raise ValueError(f"Unsupported platform {platform}")

    def retire_code(self, remote_node, code_id):
        proposal_body, careful_vote = self.make_proposal(
            "remove_node_code", code_id=code_id
        )
        proposal = self.get_any_active_member().propose(remote_node, proposal_body)
        return self.vote_using_majority(remote_node, proposal, careful_vote)

    def remove_virtual_measurement(self, remote_node, measurement):
        proposal_body, careful_vote = self.make_proposal(
            "remove_virtual_measurement", measurement=measurement
        )
        proposal = self.get_any_active_member().propose(remote_node, proposal_body)
        return self.vote_using_majority(remote_node, proposal, careful_vote)

    def remove_snp_measurement(self, remote_node, measurement):
        proposal_body, careful_vote = self.make_proposal(
            "remove_snp_measurement", measurement=measurement
        )
        proposal = self.get_any_active_member().propose(remote_node, proposal_body)
        return self.vote_using_majority(remote_node, proposal, careful_vote)

    def remove_snp_uvm_endorsement(self, remote_node, did, feed):
        proposal_body, careful_vote = self.make_proposal(
            "remove_snp_uvm_endorsement", did=did, feed=feed
        )
        proposal = self.get_any_active_member().propose(remote_node, proposal_body)
        return self.vote_using_majority(remote_node, proposal, careful_vote)

    def add_host_data(self, remote_node, platform, host_data_key, host_data_value=""):
        if platform == "virtual":
            return self.add_virtual_host_data(remote_node, host_data_key)
        elif platform == "snp":
            return self.add_snp_host_data(remote_node, host_data_key, host_data_value)
        else:
            raise ValueError(f"Unsupported platform {platform}")

    def add_virtual_host_data(
        self,
        remote_node,
        host_data_key,
    ):
        proposal_body, careful_vote = self.make_proposal(
            "add_virtual_host_data",
            host_data=host_data_key,
        )
        proposal = self.get_any_active_member().propose(remote_node, proposal_body)
        return self.vote_using_majority(remote_node, proposal, careful_vote)

    def add_snp_host_data(
        self,
        remote_node,
        new_host_data,
        new_security_policy,
    ):
        proposal_body, careful_vote = self.make_proposal(
            "add_snp_host_data",
            host_data=new_host_data,
            security_policy=new_security_policy,
        )
        proposal = self.get_any_active_member().propose(remote_node, proposal_body)
        return self.vote_using_majority(remote_node, proposal, careful_vote)

    def set_snp_minimum_tcb_version(self, remote_node, cpuid, new_tcb_version):
        proposal_body, careful_vote = self.make_proposal(
            "set_snp_minimum_tcb_version",
            cpuid=cpuid,
            tcb_version=new_tcb_version,
        )
        proposal = self.get_any_active_member().propose(remote_node, proposal_body)
        return self.vote_using_majority(remote_node, proposal, careful_vote)

    def set_snp_minimum_tcb_version_hex(self, remote_node, cpuid, new_tcb_version):
        proposal_body, careful_vote = self.make_proposal(
            "set_snp_minimum_tcb_version_hex",
            cpuid=cpuid,
            tcb_version=new_tcb_version,
        )
        proposal = self.get_any_active_member().propose(remote_node, proposal_body)
        return self.vote_using_majority(remote_node, proposal, careful_vote)

    def remove_host_data(self, remote_node, platform, host_data_key):
        if platform == "virtual":
            return self.remove_virtual_host_data(remote_node, host_data_key)
        elif platform == "snp":
            return self.remove_snp_host_data(remote_node, host_data_key)
        else:
            raise ValueError(f"Unsupported platform {platform}")

    def remove_virtual_host_data(self, remote_node, host_data):
        proposal_body, careful_vote = self.make_proposal(
            "remove_virtual_host_data",
            host_data=host_data,
        )
        proposal = self.get_any_active_member().propose(remote_node, proposal_body)
        return self.vote_using_majority(remote_node, proposal, careful_vote)

    def remove_snp_host_data(self, remote_node, host_data):
        proposal_body, careful_vote = self.make_proposal(
            "remove_snp_host_data",
            host_data=host_data,
        )
        proposal = self.get_any_active_member().propose(remote_node, proposal_body)
        return self.vote_using_majority(remote_node, proposal, careful_vote)

    def remove_snp_minimum_tcb_version(self, remote_node, cpuid):
        proposal_body, careful_vote = self.make_proposal(
            "remove_snp_minimum_tcb_version",
            cpuid=cpuid,
        )
        proposal = self.get_any_active_member().propose(remote_node, proposal_body)
        return self.vote_using_majority(remote_node, proposal, careful_vote)

    def set_node_data(self, remote_node, node_service_id, node_data):
        proposal, careful_vote = self.make_proposal(
            "set_node_data",
            node_id=node_service_id,
            node_data=node_data,
        )
        proposal = self.get_any_active_member().propose(remote_node, proposal)
        return self.vote_using_majority(remote_node, proposal, careful_vote)

    def set_node_certificate_validity(
        self, remote_node, node_to_renew, valid_from, validity_period_days
    ):
        proposal_body, careful_vote = self.make_proposal(
            "set_node_certificate_validity",
            node_id=node_to_renew.node_id,
            valid_from=valid_from,
            validity_period_days=validity_period_days,
        )
        proposal = self.get_any_active_member().propose(remote_node, proposal_body)
        return self.vote_using_majority(remote_node, proposal, careful_vote)

    def set_all_nodes_certificate_validity(
        self, remote_node, valid_from, validity_period_days
    ):
        proposal_body, careful_vote = self.make_proposal(
            "set_all_nodes_certificate_validity",
            valid_from=valid_from,
            validity_period_days=validity_period_days,
        )
        proposal = self.get_any_active_member().propose(remote_node, proposal_body)
        return self.vote_using_majority(remote_node, proposal, careful_vote)

    def set_service_certificate_validity(
        self, remote_node, valid_from, validity_period_days
    ):
        proposal_body, careful_vote = self.make_proposal(
            "set_service_certificate_validity",
            valid_from=valid_from,
            validity_period_days=validity_period_days,
        )
        proposal = self.get_any_active_member().propose(remote_node, proposal_body)
        return self.vote_using_majority(remote_node, proposal, careful_vote)

    def force_ledger_chunk(self, remote_node):
        # Submit a proposal to force a ledger chunk at the following signature
        proposal_body, careful_vote = self.make_proposal("trigger_ledger_chunk")
        proposal = self.get_any_active_member().propose(remote_node, proposal_body)
        return self.vote_using_majority(remote_node, proposal, careful_vote)

    def check_for_service(self, remote_node, status, recovery_count=None):
        """
        Check the certificate associated with current CCF service signing key has been recorded in
        the KV store with the appropriate status.
        """
        with remote_node.client() as c:
            r = c.get("/node/network").body.json()
            current_status = r["service_status"]
            current_cert = r["service_certificate"]
            if remote_node.version_after("ccf-2.0.3"):
                current_recovery_count = r["recovery_count"]
            else:
                assert "recovery_count" not in r

            expected_cert = slurp_file(
                os.path.join(self.common_dir, "service_cert.pem")
            )

            # Certs previously contained a terminating null byte. Strip it for comparison.
            current_cert = current_cert.strip("\x00")
            expected_cert = expected_cert.strip("\x00")

            assert (
                current_cert == expected_cert
            ), "Current service certificate did not match with service_cert.pem"
            assert (
                current_status == status.value
            ), f"Service status {current_status} (expected {status.value})"
            if remote_node.version_after("ccf-2.0.3"):
                assert (
                    recovery_count is None or current_recovery_count == recovery_count
                ), f"Current recovery count {current_recovery_count} is not expected {recovery_count}"
