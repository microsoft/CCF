-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.
import CftDriver

open CftDriver

initialize scenario "fancy_election_1" do
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

  -- Node 2 is initially partitioned
  disconnect 0 2
  disconnect 1 2

  dispatchAll
  periodicAll 10
  dispatchAll
  periodicAll 10
  dispatchAll
  assertCommitIdx 0 6
  assertCommitIdx 1 6

  assertDetail 0 "leadership_state" "Leader"
  assertDetail 1 "leadership_state" "Follower"

  replicate 2 "helloworld"
  emitSignature 2
  periodicAll 10
  dispatchAll

  -- Build an uncommitted suffix
  replicate 2 "salutonmondo"
  replicate 2 "hallo"
  replicate 2 "hullo"
  replicate 2 "ahoyhoy"
  emitSignature 2

  -- Dispatch AppendEntries containing this suffix, which will be received by Node 1, making
  -- it committed (known by a majority of nodes), though its commit status remains unknown
  periodicAll 10
  dispatchOne 0

  -- Receive ACKs from Node 1, allowing commit to advance on Node 0
  -- NB: This is not strictly necessary - the suffix is retained by Node 1 and election rules
  -- because it _could_ be committed. Here we show that Node 0 could hear this (and then advertise
  -- this commit point to clients), but even if that didn't happen the decision taken locally by
  -- Node 1 and the final result are the same
  dispatchOne 1

  stateAll

  -- Build a further suffix which is _not_ shared in time
  replicate 2 "z"
  replicate 2 "zz"
  replicate 2 "zzz"
  emitSignature 2

  stateAll

  -- Now the partition shifts - 0 is partitioned, but 1 and 2 can communicate
  disconnect 0 1
  connect 1 2

  -- Since 2 has been partitioned, it is likely to call an election (though it will lose)
  periodicOne 2 110
  dispatchAll

  -- Eventually, Node 1 (the only live/connected node who has the committed suffix), will call
  -- an election and win with a vote from Node 2
  periodicOne 1 110
  assertDetail 1 "leadership_state" "PreVoteCandidate"
  dispatchOne 1
  dispatchOne 2
  assertDetail 1 "leadership_state" "Candidate"
  dispatchOne 1
  dispatchOne 2

  -- Node 1 appends a new committable entry to confirm its primaryship
  replicate 3 "ConfirmCommit"
  emitSignature 3

  -- Node 1 sends an initial AppendEntries probe
  periodicOne 1 10
  dispatchOne 1

  -- Node 2 indicates it is behind
  dispatchOne 2

  -- Node 1 sends its committable suffix
  periodicAll 10
  dispatchOne 1

  -- Node 2 ACKs all of that, advancing commit on Node 1
  dispatchOne 2

  -- Node 1 sends Node 2 a heartbeat indicating the current commit index
  periodicAll 10
  dispatchOne 1

  stateAll

  -- Node 0 rejoins the network
  connect 0 1
  connect 0 2

  periodicAll 10
  dispatchAll

  periodicAll 10
  dispatchAll

  stateAll

  assertStateSync
