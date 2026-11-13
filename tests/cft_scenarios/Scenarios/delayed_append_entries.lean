-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.
import CftDriver

open CftDriver

-- An AppendEntries from a deposed primary is delivered after that primary has rolled
-- back the entry which it carries. The follower receives the entry as it was sent.
initialize scenario "delayed_append_entries" do
  startNode 0
  replicate 2 [signature]
  assertCommitIdx 0 2

  trustNodes 2 [1, 2]
  replicate 2 [signature]

  dispatchAll
  periodicAll 10
  dispatchAll
  periodicAll 10
  dispatchAll
  assertCommitIdx 0 4
  assertStateSync
  -- Initial network state [0, 1, 2], all nodes in sync

  -- 0 sends 5 to 1 and 2. 1 never receives it, and 2 not yet
  replicate 2 ["hello"]
  periodicOne 0 10
  dropPendingTo 0 1

  -- 1 is elected with the vote of 0, and 2 hears nothing of it
  periodicOne 1 100
  assertDetail 1 "leadership_state" "PreVoteCandidate"
  dropPendingTo 1 2
  dispatchOne 1
  dispatchSingle 0 1
  assertDetail 1 "leadership_state" "Candidate"
  dropPendingTo 1 2
  dispatchOne 1
  assertDetail 0 "leadership_state" "Follower"
  dispatchSingle 0 1
  assertDetail 1 "leadership_state" "Leader"
  dropPendingTo 1 2

  -- 1 replicates another 5, and 6. 0 rolls back its own 5 to take them
  replicate 3 ["world", signature]
  dispatchSingle 1 0
  periodicOne 1 10
  dropPendingTo 1 2
  dispatchSingle 1 0
  assertLastTxid 0 "3.6"

  -- 2 is still in term 2, and now receives the 5 which 0 sent in that term
  assertDetail 2 "current_view" 2
  dispatchSingle 0 2
  assertLastTxid 2 "2.5"

  -- 1 brings 2 up to date, which rolls back that 5
  loopUntilSync
  assertLastTxid 2 "3.7"
