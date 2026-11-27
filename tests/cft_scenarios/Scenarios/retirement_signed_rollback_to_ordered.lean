-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.
import CftDriver

open CftDriver

-- Nothing is committed yet (commit_idx == 0), so a newly elected leader retains
-- unsigned entries after its last signature. Node 1 appends a reconfiguration
-- retiring node 2 at 3.4, replicates 3.4 to all peers, then appends a signature
-- at 3.5 and delivers it only to node 2 (putting node 2 in Signed phase with
-- retirement_idx = 4 and retirement_committable_idx = 5). Node 0 wins term 4
-- with quorum {0, 3, 4}, keeps 3.4, and appends an unsigned entry at 4.5.
-- Replicating 4.5 rolls node 2 back to 4: Signed downgrades to Ordered while
-- retirement_idx (4) is preserved rather than reverting to Active.
initialize scenario "retirement_signed_rollback_to_ordered" do
  startNode 0
  trustNodes 2 [1, 2, 3, 4]
  replicate 2 [signature]
  dispatchAll
  periodicOne 0 10
  dispatchOne 0
  assertLastTxid 1 "2.3"
  assertLastTxid 2 "2.3"
  assertLastTxid 3 "2.3"
  assertLastTxid 4 "2.3"
  -- Drop acknowledgements so commit_idx stays 0 on every node.
  dropPending 1
  dropPending 2
  dropPending 3
  dropPending 4
  assertCommitIdx 0 0

  -- Node 1 is elected in term 3 with votes from 0 and 3 (quorum of {0} and
  -- {0, 1, 2, 3, 4}).
  periodicOne 1 100
  assertDetail 1 "leadership_state" "PreVoteCandidate"
  dispatchSingle 1 0
  dispatchSingle 0 1
  dispatchSingle 1 3
  dispatchSingle 3 1
  assertDetail 1 "leadership_state" "Candidate"
  dispatchSingle 1 0
  dispatchSingle 0 1
  dispatchSingle 1 3
  dispatchSingle 3 1
  assertDetail 1 "leadership_state" "Leader"
  assertDetail 1 "current_view" 3
  assertCommitIdx 1 0
  dropPending 1

  -- Node 1 appends 3.4 retiring node 2 and delivers it to 0, 2, 3, 4.
  swapNodes 3 (retire := [2])
  periodicOne 1 10
  dispatchOne 1
  assertLastTxid 0 "3.4"
  assertLastTxid 2 "3.4"
  assertLastTxid 3 "3.4"
  assertLastTxid 4 "3.4"
  assertDetail 2 "membership_state" "Retired"
  assertDetail 2 "retirement_phase" "Ordered"
  dropPending 0
  dropPending 2
  dropPending 3
  dropPending 4

  -- Node 1 signs at 3.5 and delivers it only to node 2, putting node 2 in
  -- Signed phase while 0, 3, and 4 still have last_committable_idx = 3.
  replicate 3 [signature]
  periodicOne 1 10
  dropPendingTo 1 0
  dropPendingTo 1 3
  dropPendingTo 1 4
  dispatchSingle 1 2
  assertDetail 2 "membership_state" "Retired"
  assertDetail 2 "retirement_phase" "Signed"
  assertLastTxid 2 "3.5"
  assertCommitIdx 2 0
  dropPending 2

  -- Node 0 wins term 4 with votes from 3 and 4 (quorum of {0}, {0,1,2,3,4},
  -- and {0,1,3,4}) and retains 3.4 because commit_idx == 0.
  periodicOne 0 100
  assertDetail 0 "leadership_state" "PreVoteCandidate"
  dispatchSingle 0 3
  dispatchSingle 3 0
  dispatchSingle 0 4
  dispatchSingle 4 0
  assertDetail 0 "leadership_state" "Candidate"
  dispatchSingle 0 3
  dispatchSingle 3 0
  dispatchSingle 0 4
  dispatchSingle 4 0
  assertDetail 0 "leadership_state" "Leader"
  assertDetail 0 "current_view" 4
  assertLastTxid 0 "3.4"
  assertCommitIdx 0 0

  -- Drop node 0's pending election messages and initial heartbeat to node 2,
  -- then append an unsigned entry 4.5 on node 0 and deliver it to node 2.
  dropPendingTo 0 2
  replicate 4 ["w"]
  periodicOne 0 10
  dispatchSingle 0 2

  -- Replacing 3.5 with 4.5 rolls node 2 back to 4 (equal to retirement_idx):
  -- Signed downgrades to Ordered and node 2 stays Retired.
  assertLastTxid 2 "4.5"
  assertDetail 2 "membership_state" "Retired"
  assertDetail 2 "retirement_phase" "Ordered"
  assertConfig 2 4 [0, 1, 3, 4]

  -- A subsequent signature in term 4 moves node 2 back to Signed and commits.
  loopUntilSync
