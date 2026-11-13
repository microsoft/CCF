-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.
import CftDriver

open CftDriver

-- A nomination from node 0 is delayed while node 2 wins a later election and
-- commits its own retirement. The old nomination must not restart an election.
initialize scenario "retired_committed_delayed_nomination" do
  startNode 0
  emitSignature 2
  trustNodes 2 [1, 2]
  emitSignature 2
  dispatchAll
  periodicAll 10
  dispatchAll
  periodicAll 10
  dispatchAll
  assertStateSync

  -- Give node 2 a strictly higher match index so nomination cannot choose node 1.
  emitSignature 2
  periodicOne 0 10
  dispatchSingle 0 2
  dispatchSingle 2 0
  assertCommitIdx 0 5
  assertLastTxid 2 "2.5"
  nominateSuccessor 0
  dispatchSingle 0 1
  dispatchSingle 1 0

  -- Leave the PRV queued while node 2 wins an election with node 1's votes.
  periodicOne 2 100
  assertDetail 2 "leadership_state" "PreVoteCandidate"
  dispatchSingle 2 1
  dispatchSingle 1 2
  assertDetail 2 "leadership_state" "Candidate"
  dispatchSingle 2 1
  dispatchSingle 1 2
  assertDetail 2 "leadership_state" "Leader"
  assertDetail 2 "current_view" 3
  -- Let node 0 process the election requests and heartbeat, but keep its PRV and
  -- subsequent responses queued. It learns term 3 before learning its retirement.
  dispatchSingle 2 0
  dispatchSingle 2 0
  dispatchSingle 2 0
  assertDetail 0 "leadership_state" "Follower"
  assertDetail 0 "current_view" 3
  dispatchSingle 2 1
  dispatchSingle 1 2

  -- Retire both primaries, leaving node 1 as the sole member of the new config.
  -- Node 0 learns it is retired without dispatching its delayed nomination.
  swapNodes 3 (retire := [0, 2])
  emitSignature 3
  periodicOne 2 10
  dispatchSingle 2 0
  dispatchSingle 2 1
  dispatchSingle 1 2
  assertCommitIdx 2 7
  assertDetail 2 "retirement_phase" "Completed"
  periodicOne 2 10
  dispatchSingle 2 0
  dispatchSingle 2 1
  dispatchSingle 1 2
  assertDetail 0 "membership_state" "Retired"
  assertDetail 0 "retirement_phase" "Completed"

  cleanupNodes 3 [0, 2]
  emitSignature 3
  periodicOne 2 10
  dispatchSingle 2 1
  dispatchSingle 1 2
  assertCommitIdx 2 9
  assertDetail 2 "retirement_phase" "RetiredCommitted"
  assertDetail 2 "leadership_state" "None"

  -- This is the original term-2 nomination, now reaching a retired-committed node.
  dispatchSingle 0 2
  assertCommitIdx 2 9
  assertDetail 2 "retirement_phase" "RetiredCommitted"
  assertDetail 2 "leadership_state" "None"
  assertDetail 2 "current_view" 3
  assertLastTxid 2 "3.9"

  -- Node 2's fresh nomination elects node 1, so the remaining network progresses.
  dispatchSingle 2 1
  assertDetail 1 "leadership_state" "Leader"
  assertDetail 1 "current_view" 4
  loopUntilSync
