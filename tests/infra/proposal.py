# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

from enum import Enum


class ProposalNotCreated(Exception):
    def __init__(self, response):
        super(ProposalNotCreated, self).__init__()
        self.response = response


class ProposalNotAccepted(Exception):
    def __init__(self, proposal):
        super(ProposalNotAccepted, self).__init__()
        self.proposal = proposal


# Values defined in node/proposals.h
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
        self.votes_for = 0
        self.view = view
        self.seqno = seqno

    def increment_votes_for(self):
        self.votes_for += 1
