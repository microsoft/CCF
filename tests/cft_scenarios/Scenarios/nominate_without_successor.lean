-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.
import CftDriver

open CftDriver

-- A single-node leader has no eligible peer to nominate. The request must leave
-- it leading normally without queueing a proposal.
initialize scenario "nominate_without_successor" do
  startNode 0
  replicate 2 [signature]
  assertDetail 0 "leadership_state" "Leader"

  nominateSuccessor 0
  assertDetail 0 "leadership_state" "Leader"

  loopUntilSync
