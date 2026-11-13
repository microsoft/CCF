-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.
import CftDriver

open CftDriver

-- 5 initial nodes
initialize scenario "suffix_collision_3" do
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

  trustNode 2 4
  emitSignature 2

  dispatchAll
  periodicAll 10
  dispatchAll
  periodicAll 10
  dispatchAll
  assertCommitIdx 0 10
  assertStateSync

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

  -- All nodes are in-sync
  stateAll
  assertStateSync

  -- Nodes 0 and 1 are partitioned from the majority
  disconnect 0 2
  disconnect 0 3
  disconnect 0 4
  disconnect 1 2
  disconnect 1 3
  disconnect 1 4

  -- Node 2 becomes primary, with votes from 3 and 4
  periodicOne 2 110
  dispatchAll

  periodicAll 10
  dispatchAll

  -- Node 0 continues to produce a suffix in term 1
  replicate 2 "branch a 0"
  emitSignature 2

  replicate 2 "branch a 1"
  emitSignature 2

  replicate 2 "branch a 2"
  emitSignature 2

  -- Node 2 continues to produce a suffix in term 2
  replicate 3 "branch b 0"
  emitSignature 3

  replicate 3 "branch b 1"
  emitSignature 3

  replicate 3 "branch b 2"
  emitSignature 3

  replicate 3 "branch b 3"
  emitSignature 3

  -- AEs describing these suffices are produced, but lost in transit
  periodicAll 10
  dropPending 0
  dropPending 2
  dispatchAll

  -- Node 0 calls a new election, hears from node 4 just long enough to become primary in term 3
  periodicOne 0 110
  reconnect 0 4
  periodicOne 0 110
  dispatchAll
  periodicOne 0 110
  dispatchAll
  disconnect 0 4

  -- Node 2 calls a new election, hears from node 4 just long enough to become primary in term 4
  periodicOne 2 110
  reconnect 2 4
  periodicOne 2 110
  dispatchAll
  periodicOne 2 110
  dispatchAll
  disconnect 2 4

  -- Node 0 continues to produce a suffix in term 3
  replicate 4 "branch a 10"
  emitSignature 4

  replicate 4 "branch a 11"
  emitSignature 4

  replicate 4 "branch a 12"
  emitSignature 4

  -- Node 2 continues to produce a suffix in term 4
  replicate 5 "branch b 10"
  emitSignature 5

  replicate 5 "branch b 11"
  emitSignature 5

  replicate 5 "branch b 12"
  emitSignature 5

  -- AEs describing these suffices are produced, and delivered,
  -- but due to partition they cannot be committed
  stateAll

  periodicAll 10
  dispatchAll

  periodicAll 10
  dispatchAll

  -- Connection between 0 and 2 is restored
  reconnect 0 2

  -- Node 0 hears about 2's progress (and later term), rolls back,
  -- produces a probe NACK
  periodicOne 2 10
  dispatchOne 2

  -- Node 2 receives NACK from node 0
  dispatchOne 0

  -- Node 2 receives ACK from node 3
  -- It must not advance commit based on the NACK index from node 0!
  dispatchOne 3

  -- Debug print current state
  stateAll
