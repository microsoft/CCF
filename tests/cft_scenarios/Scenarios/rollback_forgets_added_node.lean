-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.
import CftDriver

open CftDriver

-- A node forgets the node which a configuration added, when it rolls that
-- configuration back. Node 0 replaces itself with node 2 in a configuration
-- which no signature follows. It hears nothing from node 2, and needs its vote
-- to be elected again. Once elected, it discards what follows its last
-- signature, and the configuration with it. No configuration of node 0 then
-- names node 2, so node 0 sends it nothing more.
initialize scenario "rollback_forgets_added_node" do
  startNode 0
  replicate 2 [signature]
  assertCommitIdx 0 2

  -- 0 retires and 2 joins at 2.3, which nothing signs
  swapNodes 2 [0] [2]
  assertDetail 0 "membership_state" "Retired"
  assertConfig 0 3 [2]

  -- 0 stands down for want of an acknowledgement, and calls an election
  periodicOne 0 100
  assertDetail 0 "leadership_state" "Follower"
  periodicOne 0 150
  assertDetail 0 "leadership_state" "PreVoteCandidate"

  -- 2 rejects the entries, which do not follow its empty ledger, and votes for 0
  dispatchAll
  assertDetail 0 "leadership_state" "Leader"
  assertDetail 0 "current_view" 3
  assertLastTxid 2 "0.0"

  -- 0 rolled back to 2.2: it is active again, and the configuration is gone
  assertLastTxid 0 "2.2"
  assertDetail 0 "membership_state" "Active"
  assertAbsentConfig 0 3

  -- 0 no longer knows 2, and sends it neither the signature nor a heartbeat
  replicate 3 [signature]
  assertCommitIdx 0 3
  periodicOne 0 10
  assertPending 0 2 0

  assertDetail 2 "leadership_state" "Follower"
  assertCommitIdx 2 0
