-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.
import CftDriver

open CftDriver

initialize scenario "suffix_collision_1" do
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
  periodicAll 10
  dispatchAll
  assertCommitIdx 0 6
  assertStateSync

  assertDetail 0 "leadership_state" "Leader"
  assertDetail 1 "leadership_state" "Follower"
  assertDetail 2 "leadership_state" "Follower"

  replicate 2 "hello world"
  emitSignature 2
  periodicAll 10
  dispatchAll

  replicate 2 "saluton mondo"
  emitSignature 2
  periodicAll 10
  dispatchAll

  periodicAll 10
  dispatchAll

  stateAll

  -- Node 0 is partitioned, and replicates another item
  disconnect 0 1
  disconnect 0 2

  replicate 2 "drop me 1"
  emitSignature 2
  periodicAll 10
  dispatchAll

  stateAll

  -- Node 1 calls an election, and wins
  periodicOne 1 110
  dispatchAll

  periodicAll 10
  dispatchAll -- This AppendEntries starts at a point that Node 1 would accept, but is dropped

  stateAll

  -- Node 1 replicates a new entry, resulting in the same seqno as Node 0
  replicate 3 "keep me 1"
  emitSignature 3
  periodicAll 10
  dispatchAll

  replicate 3 "keep me 2"
  emitSignature 3
  periodicAll 10
  dispatchAll

  stateAll

  -- Network heals
  connect 0 1
  connect 0 2

  -- Node 0 is brought up-to-date
  periodicAll 10
  dispatchAll

  periodicAll 10
  dispatchAll

  periodicAll 10
  dispatchAll

  stateAll
  assertStateSync
