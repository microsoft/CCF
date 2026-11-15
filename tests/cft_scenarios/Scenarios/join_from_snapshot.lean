-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.
import CftDriver

open CftDriver

-- A node joins from a snapshot of the primary. It starts at the index which the
-- primary has committed, with the configuration of that index, and replicates
-- only what follows it.
initialize scenario "join_from_snapshot" do
  startNode 0
  replicate 2 ["a", signature]
  assertCommitIdx 0 3

  -- 2.4 is not committed, so the snapshot ends before it
  replicate 2 ["b"]
  trustNodeFromSnapshot 2 1
  assertLastTxid 1 "2.3"
  assertCommitIdx 1 3
  assertConfig 1 3 [0]
  assertDetail 1 "leadership_state" "Follower"

  -- 0 signs at 2.6, after the configuration which adds 1 at 2.5
  replicate 2 [signature]
  dispatchAll
  periodicAll 10
  dispatchAll
  periodicAll 10
  dispatchAll

  assertLastTxid 1 "2.6"
  assertConfig 1 5 [0, 1]
  assertDetail 0 "leadership_state" "Leader"
  assertCommitIdx 0 6
  assertDetail 1 "leadership_state" "Follower"
  assertCommitIdx 1 6
