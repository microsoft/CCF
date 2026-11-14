-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.
import CftDriver

open CftDriver

-- A node which has no signed configuration ignores a nomination. The primary
-- adds node 2 and nominates it at once, before node 2 has any entry.
-- Found by `cft_model_driver --explore`, from `pre_vote_split`.
initialize scenario "nominate_new_node" do
  startNode 0
  swapNodes 2 [] [2]
  nominateSuccessor 0
  dispatchAll

  assertDetail 0 "leadership_state" "Leader"
  assertCommitIdx 0 0
  assertDetail 2 "leadership_state" "Follower"
  assertCommitIdx 2 0
