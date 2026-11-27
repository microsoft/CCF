-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.
import CftDriver

open CftDriver

-- A joining node has learned the primary's term from a probe AppendEntries,
-- but has not yet received any configuration. A ProposeRequestVote for its
-- current term must be ignored without becoming a candidate or advancing term.
initialize scenario "nominate_unconfigured_joiner" do
  startNode 0
  replicate 2 [signature]
  assertCommitIdx 0 2

  -- Add node 1: node 0 appends configuration 3 and queues an initial probe
  -- AppendEntries to node 1, while node 1 starts with no configurations.
  trustNode 2 1

  -- Deliver the probe so node 1 adopts term 2 and NACKs without receiving
  -- any entries or configuration.
  dispatchSingle 0 1
  assertDetail 1 "leadership_state" "Follower"
  assertDetail 1 "current_view" 2
  assertLastTxid 1 "0.0"

  -- Node 0 nominates node 1 before node 1 has received any configuration.
  nominateSuccessor 0
  dispatchSingle 0 1
  assertDetail 1 "leadership_state" "Follower"
  assertDetail 1 "current_view" 2
  assertPending 1 0 1

  -- Normal replication then brings node 1 up to date.
  dispatchAll
  loopUntilSync
