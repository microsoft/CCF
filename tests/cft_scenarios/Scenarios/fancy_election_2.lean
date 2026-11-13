-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.
import CftDriver

open CftDriver

-- This scenario re-creates figure 8 from the Raft paper
initialize scenario "fancy_election_2" do
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

  -- Node 0 appends a single entry, replicates it to all nodes
  replicate 2 "entry_1"
  emitSignature 2

  periodicAll 10
  dispatchAll

  -- Node 0 appends a second entry, which only reaches Node 1
  disconnectNode 0
  connect 0 1
  replicate 2 "entry_2"
  emitSignature 2

  periodicAll 10
  dispatchAll

  -- Node 4 becomes primary, appends a single entry which reaches nobody
  disconnectNode 0
  connect 4 3
  connect 4 2

  periodicOne 4 110
  dispatchAll

  replicate 3 "entry_3"
  emitSignature 3

  stateAll

  -- Node 0 returns, becomes primary again, manages to share second entry with additional node
  disconnectNode 4
  connect 0 1
  connect 0 2

  periodicAll 10
  dispatchAll

  periodicOne 0 110
  dispatchAll

  periodicAll 10
  dispatchAll -- NB: 1.2 is now present on a majority of nodes, and node 0 knows this

  -- Node 0 now loses connectivity, Node 4 wins election in a new term
  disconnectNode 0
  connect 4 3
  connect 4 2
  connect 4 1

  periodicAll 10
  dispatchAll

  periodicOne 4 110
  dispatchAll

  periodicAll 10
  dispatchAll -- NB: Nodes 1 and 2 have discarded their state, which a majority held
  stateAll

  periodicAll 10
  dispatchAll

  -- All nodes become connected - can they reach eventual agreement?
  connect 0 4

  periodicAll 10
  dispatchAll

  periodicAll 10
  dispatchAll

  periodicAll 10
  dispatchAll

  stateAll

  -- Not yet! We need node 4 to produce a new entry in its current term
  replicate 5 "entry_4"
  emitSignature 5

  periodicAll 10
  dispatchAll

  periodicAll 10
  dispatchAll

  stateAll
  assertStateSync
