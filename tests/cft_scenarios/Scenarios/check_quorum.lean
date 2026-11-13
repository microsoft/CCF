-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.
import CftDriver

open CftDriver

initialize scenario "check_quorum" do
  startNode 0
  assertDetail 0 "leadership_state" "Leader"
  emitSignature 2

  assertDetail 0 "leadership_state" "Leader"
  assertCommitIdx 0 2

  trustNode 2 1
  emitSignature 2

  dispatchAll
  periodicAll 10
  dispatchAll
  assertCommitIdx 0 4

  trustNode 2 2
  emitSignature 2

  dispatchAll
  periodicAll 10
  dispatchAll
  assertCommitIdx 0 6

  trustNode 2 3
  emitSignature 2

  dispatchAll
  periodicAll 10
  dispatchAll
  assertCommitIdx 0 8

  dispatchAll
  periodicAll 10
  dispatchAll
  assertStateSync

  -- An initial entry is written and successfully replicated
  replicate 2 "helloworld"
  emitSignature 2

  periodicAll 10
  dispatchAll

  periodicAll 10
  dispatchAll

  stateAll
  assertStateSync

  -- Disconnect primary 0 from a minority of backups [1].
  -- Primary 0 should remain primary.

  disconnect 0 1

  -- 0 sends AE and receives ACKs from [2,3]
  periodicAll 10
  dispatchAll

  periodicOne 0 50
  dispatchAll

  -- 0 has now not received an ACK from 1 for longer than election timeout 100
  periodicOne 0 50
  dispatchAll

  stateAll
  assertDetail 0 "leadership_state" "Leader"
  assertDetail 1 "leadership_state" "Follower"
  assertDetail 2 "leadership_state" "Follower"
  assertDetail 3 "leadership_state" "Follower"

  -- Now disconnect primary 0 from another backup 1.
  -- Majority of backups [1,2] is disconnected and primary 0 should step down.

  disconnect 0 2

  assertDetail 0 "leadership_state" "Leader"

  periodicAll 10
  dispatchAll

  periodicOne 0 50
  dispatchAll

  assertDetail 0 "leadership_state" "Leader"

  -- 0 has now not received an ACK from [1,2] for longer than election timeout 100
  periodicOne 0 50

  -- Node 0 has stepped down as backup (check quorum)
  stateAll
  assertDetail 0 "leadership_state" "Follower"
  assertDetail 1 "leadership_state" "Follower"
  assertDetail 2 "leadership_state" "Follower"
  assertDetail 3 "leadership_state" "Follower"

  -- Eventually, the partition is lifted and a new leader is elected.
  -- In this case, we check that node 0 can be re-elected.

  reconnect 0 1
  reconnect 0 2
  dispatchAll

  periodicOne 0 100
  dispatchAll

  assertDetail 0 "leadership_state" "Leader"

  stateAll
