-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.
import CftDriver

open CftDriver

-- A primary which nominates a successor passes over a node which is being
-- removed. Nodes 1, 2 and 3 have acknowledged the same entries when the
-- primary orders the removal of node 3, so node 3 is the only one which is not
-- in the latest configuration. The primary proposes node 2, which is elected.
-- Found by `cft_model_driver --explore`, from `retire_backup_pre_vote`, then
-- written to elect the nominee.
initialize scenario "nominate_over_retiring_node" do
  startNode 0
  trustNodes 2 [1, 2, 3]
  replicate 2 [signature]
  dispatchAll
  periodicAll 10
  dispatchAll
  periodicAll 10
  dispatchAll
  -- Initial network state [0, 1, 2, 3], committed at 2.3

  -- The primary orders the removal of 3 at 2.4, which no other node receives
  swapNodes 2 [3] []
  assertDetail 0 "leadership_state" "Leader"

  -- The primary nominates 2, which campaigns in term 3
  nominateSuccessor 0
  dispatchSingle 0 2
  assertDetail 2 "leadership_state" "Candidate"
  assertDetail 3 "leadership_state" "Follower"

  -- 2 is elected with the votes of 0 and 1
  dispatchOne 2
  dispatchSingle 0 2
  dispatchSingle 1 2

  assertDetail 0 "leadership_state" "Follower"
  assertCommitIdx 0 3
  assertDetail 1 "leadership_state" "Follower"
  assertCommitIdx 1 3
  assertDetail 2 "leadership_state" "Leader"
  assertCommitIdx 2 3
  assertDetail 3 "leadership_state" "Follower"
  assertCommitIdx 3 3
