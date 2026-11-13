-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.
import CftDriver

open CftDriver

-- Keep the term-2 leader isolated while node 1 wins term 3. A write addressed to
-- the latest leader must select node 1 rather than the stale primary.
initialize scenario "replicate_on_latest_leader" do
  startNode 0
  emitSignature 2
  trustNodes 2 [1, 2]
  emitSignature 2
  dispatchAll
  periodicAll 10
  dispatchAll
  periodicAll 10
  dispatchAll
  assertStateSync

  dropPending 0
  dropPending 1
  dropPending 2
  periodicOne 1 100
  assertDetail 1 "leadership_state" "PreVoteCandidate"
  assertDetail 1 "current_view" 2
  dropPendingTo 1 0
  dispatchSingle 1 2
  dispatchSingle 2 1
  assertDetail 1 "leadership_state" "Candidate"
  assertDetail 1 "current_view" 3
  dropPendingTo 1 0
  dispatchSingle 1 2
  dispatchSingle 2 1
  assertDetail 0 "leadership_state" "Leader"
  assertDetail 1 "leadership_state" "Leader"
  assertDetail 0 "current_view" 2
  assertDetail 1 "current_view" 3

  replicate latest "latest leader write"
  assertLastTxid 0 "2.4"
  assertLastTxid 1 "3.5"
  loopUntilSync
