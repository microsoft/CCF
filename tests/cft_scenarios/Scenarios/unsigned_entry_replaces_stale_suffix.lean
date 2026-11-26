-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.
import CftDriver

open CftDriver

private def assertPending (source target : NodeId) (count : Nat) : IO Unit := do
  let pending ← pendingMessages source target
  let link := s!"from {source.text} to {target.text}"
  unless pending.size == count do
    throw (IO.userError s!"Expected {count} messages {link}, got {pending}")

-- A follower replaces an entry of an earlier primary with a transaction of its
-- primary, and acknowledges it. Nothing is committed, so a node which is
-- elected keeps the transactions after its last signature. Node 1 holds 2.4,
-- then 3.5 and 3.6 of its own term, none of them signed, and node 0 is elected
-- in term 4 with 2.4 and 3.5. Its transaction 4.6 replaces 3.6 on node 1: term
-- 4 starts there, and not after 2.3, the last signature of node 1.
initialize scenario "unsigned_entry_replaces_stale_suffix" do
  startNode 0
  trustNode 2 1
  replicate 2 [signature, "x"]
  dispatchAll
  periodicOne 0 10
  dispatchOne 0
  assertLastTxid 1 "2.4"
  -- Initial network state [0, 1]. The acknowledgements of 1 are lost, so
  -- nothing is committed
  dropPending 1

  -- 1 is elected in term 3, and keeps 2.4, which is not signed
  periodicOne 1 100
  dispatchOne 1
  dispatchOne 0
  dispatchOne 1
  dispatchOne 0
  assertDetail 1 "leadership_state" "Leader"
  assertLastTxid 1 "2.4"
  dropPending 1

  -- 1 appends 3.5, which 0 receives, and 3.6, which it does not
  replicate 3 ["y"]
  periodicOne 1 10
  dispatchOne 1
  assertLastTxid 0 "3.5"
  assertView 0 (idx := 4) (view := 2)
  dropPending 0
  replicate 3 ["z"]
  assertLastTxid 1 "3.6"

  -- 0 is elected in term 4, and keeps 2.4 and 3.5
  periodicOne 0 100
  dispatchOne 0
  dispatchOne 1
  dispatchOne 0
  dispatchOne 1
  assertDetail 0 "leadership_state" "Leader"
  assertDetail 1 "leadership_state" "Follower"
  assertLastTxid 0 "3.5"

  -- The first heartbeat of 0 ends at 3.5. 1 acknowledges it, and keeps 3.6
  dispatchOne 0
  assertLastTxid 1 "3.6"
  dispatchOne 1

  -- 0 appends 4.6, which is not a signature. It replaces 3.6 on 1, which
  -- acknowledges it
  replicate 4 ["w"]
  periodicOne 0 10
  dispatchOne 0
  assertLastTxid 1 "4.6"
  assertView 1 (idx := 4) (view := 2)
  assertView 1 (idx := 5) (view := 3)
  assertPending 1 0 1
  dispatchOne 1

  -- 0 signs at 4.7, and commits
  replicate 4 [signature]
  periodicOne 0 10
  dispatchOne 0
  assertLastTxid 1 "4.7"
  dispatchOne 1
  periodicOne 0 10
  dispatchOne 0

  assertDetail 0 "leadership_state" "Leader"
  assertCommitIdx 0 7
  assertDetail 1 "leadership_state" "Follower"
  assertCommitIdx 1 7
