-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.
import CftDriver

open CftDriver

-- A repro of the failing scenario where a follower rolls back its ledger by becoming a pre-vote-candidate and then back to a follower (#7618)
-- If this follower had previously acked an append-entries, then the leader's matchIdx for it would be higher than its truncated ledger.
-- This was fixed by no longer rolling back uncommittable entries (no signature) when becoming a follower.
initialize scenario "follower_rollback_match_index" do
  startNode 0
  replicate 2 [signature]
  assertCommitIdx 0 2

  swapNodes 2 (trust := [1, 2])
  replicate 2 [signature]

  loopUntilSync

  assertLastTxid 0 "2.5"
  replicate 2 ["tx1"]
  assertLastTxid 0 "2.6"

  -- advance matchIdx
  periodicOne 0 10
  dispatchSingle 0 2
  dispatchSingle 2 0

  -- Partition 2
  disconnectNode 2

  replicate 2 [signature]
  assertLastTxid 0 "2.7"

  periodicOne 0 10

  -- b2 time out
  periodicOne 2 100
  assertDetail 2 "leadership_state" "PreVoteCandidate"
  assertLastTxid 2 "2.6"

  dispatchAll

  -- Heal partition
  reconnectNode 2

  -- leader sends append entries [2.7,2.7) to b2
  -- b2 nacks but does not truncate
  periodicOne 0 10
  dispatchSingle 0 2
  dispatchSingle 2 0
  assertDetail 2 "leadership_state" "Follower"
  assertLastTxid 2 "2.6"

  loopUntilSync
