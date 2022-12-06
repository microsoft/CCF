# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

from enum import Enum


class ProposalNotCreated(Exception):
    def __init__(self, response):
        super(ProposalNotCreated, self).__init__()
        self.response = response


class ProposalNotAccepted(Exception):
    def __init__(self, proposal, response):
        super(ProposalNotAccepted, self).__init__()
        self.proposal = proposal
        self.response = response


# Values defined in include/ccf/service/tables/proposals.h
class ProposalState(Enum):
    OPEN = "Open"
    ACCEPTED = "Accepted"
    WITHDRAWN = "Withdrawn"
    REJECTED = "Rejected"
    FAILED = "Failed"


class Proposal:
    def __init__(
        self,
        proposer_id,
        proposal_id,
        state,
        view=None,
        seqno=None,
    ):
        self.proposer_id = proposer_id
        self.proposal_id = proposal_id
        self.state = state

        self.voters = []
        self.view = view
        self.seqno = seqno

        self.completed_view = view if state == ProposalState.ACCEPTED else None
        self.completed_seqno = seqno if state == ProposalState.ACCEPTED else None

    def set_completed(self, seqno, view):
        self.completed_seqno = seqno
        self.completed_view = view

    def increment_votes_for(self, member_id):
        self.voters.append(member_id)

    @property
    def votes_for(self):
        return len(self.voters)
