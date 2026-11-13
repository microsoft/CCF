-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.
import CftDriver

open CftDriver

-- Repro: partially matching append-entries #7999
-- The aim is to deliver an AppendEntries which is rooted in a backup's prefix, but which
-- otherwise match no-conflict.
--
-- Construction (no reconfiguration):
--   common prefix [1..4]@t2 ; node 2 holds a divergent suffix [5,6]@t3 ; node 1 leads t4
--   with its own block [5,6,7]@t4. Because node 1's t4 block starts at index 5, a t3 NACK
--   from node 2 backs node 1's sentIndex off to the term boundary (index 4). We:
--     1. make node 2 emit two t3 NACKs while still divergent (and retain them),
--     2. let node 2 ADOPT node 1's [5,6]@t4 (a modelled conflict+append),
--     3. deliver a retained t3 NACK to reset node 1's sentIndex to 4 again, keeping
--        node 1's match_idx for node 2 <= 4 by never delivering node 2's ACK,
--     4. let node 1 re-send prev=4 idx=7 covering [5,6,7]@t4 -> node 2 skips the matching
--        [5,6]@t4 and appends 7 == matching partial (prev=4 < last=6 < idx=7).
initialize scenario "matching_partial" do
  startNode 0
  assertDetail 0 "leadership_state" "Leader"
  replicate 2 [signature]
  trustNodes 2 [1, 2]
  replicate 2 [signature]
  dispatchAll
  periodicAll 10
  dispatchAll
  periodicAll 10
  dispatchAll
  assertStateSync

  -- Node 2 wins a term-3 election and creates a divergent suffix [5,6]@t3 it never shares.
  periodicOne 2 100
  dispatchAll
  assertDetail 2 "leadership_state" "Leader"
  replicate 3 ["divergent 5"]
  replicate 3 [signature]
  dropPending 2
  assertLastTxid 2 "3.6"

  -- Node 1 wins a term-4 election (node 0 gives the majority; node 2 rejects due to its longer log).
  periodicOne 1 100
  dispatchAll
  assertDetail 1 "leadership_state" "Leader"
  assertDetail 1 "current_view" 4

  -- Node 1 builds its own block [5,6]@t4.
  dropPending 1
  replicate 4 ["block 5"]
  replicate 4 [signature]

  -- Optimistically advance node 1's sentIndex for node 2 to 6, then DROP that AppendEntries
  -- so node 2 does not adopt yet and stays on its divergent [5,6]@t3.
  periodicOne 1 10
  dropPendingTo 1 2

  -- Two prev=6 heartbeats -> node 2 (still divergent) emits two t3 NACKs into its outbox.
  dropPending 2
  periodicOne 1 10
  periodicOne 1 10
  dispatchSingle 1 2
  dispatchSingle 1 2

  -- Deliver NACK #1: node 1 backs sentIndex off to the t4 block boundary (index 4).
  dispatchSingle 2 1

  -- Node 1 sends prev=4 idx=6 [5,6]@t4; node 2 rolls back its t3 [5,6] and ADOPTS t4 [5,6]
  -- (this conflict+append IS modelled). Node 2's ACK is left undelivered so match stays <= 4.
  periodicOne 1 10
  dispatchSingle 1 2
  assertLastTxid 2 "4.6"

  -- Node 1 extends its block with [7]@t4.
  replicate 4 [signature]

  -- Deliver the RETAINED NACK #2: node 1 again backs sentIndex off to 4 (match still <= 4).
  dispatchSingle 2 1

  -- Node 1 now sends prev=4 idx=7 covering [5,6,7]@t4. Node 2 already holds matching [5,6]@t4,
  -- so it SKIPS them and only appends 7 -> MATCHING PARTIAL (prev=4 < last=6 < idx=7).
  -- Previously this is the step which would fail to trace-validate
  periodicOne 1 10
  dispatchSingle 1 2
  assertLastTxid 2 "4.7"
