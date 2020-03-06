# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

from enum import Enum

# Values defined in node/proposals.h
class ProposalState(Enum):
    Open = "OPEN"
    Accepted = "ACCEPTED"
    Withdrawn = "WITHDRAWN"
    Rejected = "REJECTED"
    Failed = "FAILED"
