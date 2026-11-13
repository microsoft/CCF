-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.
import CftDriver

open CftDriver

private def assertPending (source target : NodeId) (count : Nat) : IO Unit := do
  let pending ← pendingMessages source target
  let link := s!"from {source.text} to {target.text}"
  unless pending.size == count do
    throw (IO.userError s!"Expected {count} messages {link}, got {pending}")

-- Messages on one link overtake one another, or are lost one at a time.
-- A follower ignores entries below its commit index, and a primary ignores an
-- acknowledgement below its match index.
initialize scenario "reordered_messages" do
  startNode 0
  replicate 2 [signature]
  assertCommitIdx 0 2

  trustNode 2 1
  replicate 2 [signature]

  dispatchAll
  periodicAll 10
  dispatchAll
  periodicAll 10
  dispatchAll
  assertCommitIdx 0 4
  assertCommitIdx 1 4
  -- Initial network state [0, 1], all nodes in sync

  -- 0 sends 5 and 6, then a heartbeat
  replicate 2 ["hello", signature]
  periodicOne 0 10
  periodicOne 0 10
  assertPending 0 1 2

  -- The heartbeat overtakes the entries, so 1 lacks its previous index
  dispatchNth 0 1 1
  assertLastTxid 1 "2.4"
  assertPending 0 1 1

  -- 0 learns where the ledger of 1 ends, and sends 5 and 6 again
  dispatchOne 1
  periodicOne 0 10
  assertPending 0 1 2

  -- 1 receives one copy, and 0 commits
  dispatchSingle 0 1
  dispatchOne 1
  assertCommitIdx 0 6

  -- 1 learns of the commit from a heartbeat, which overtakes the other copy
  periodicOne 0 10
  dispatchNth 0 1 1
  assertCommitIdx 1 6

  -- The other copy is now below the commit index of 1, which ignores it
  dispatchSingle 0 1
  assertPending 0 1 0
  assertPending 1 0 1
  dispatchOne 1

  -- 0 sends 7 and 8, then 9 and 10, and 1 acknowledges each
  replicate 2 ["world", signature]
  periodicOne 0 10
  replicate 2 ["again", signature]
  periodicOne 0 10
  dispatchOne 0
  assertLastTxid 1 "2.10"
  assertPending 1 0 2

  -- The later acknowledgement overtakes the earlier one, which 0 then ignores
  dispatchNth 1 0 1
  assertCommitIdx 0 10
  dispatchSingle 1 0
  assertCommitIdx 0 10

  -- 0 sends 11 and 12, then 13 and 14, and only the first message is lost
  replicate 2 ["more", signature]
  periodicOne 0 10
  replicate 2 ["last", signature]
  periodicOne 0 10
  dropNth 0 1 0
  dispatchOne 0
  assertLastTxid 1 "2.10"

  -- 0 learns where the ledger of 1 ends, and sends from there
  dispatchOne 1
  periodicOne 0 10
  dispatchOne 0
  dispatchOne 1
  assertCommitIdx 0 14
