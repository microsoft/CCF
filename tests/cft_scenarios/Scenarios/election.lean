-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.
import CftDriver

open CftDriver

initialize scenario "election" do
  startNode 0
  assertDetail 0 "leadership_state" "Leader"
  replicate 2 [signature]

  assertDetail 0 "leadership_state" "Leader"
  assertCommitIdx 0 2

  trustNode 2 1
  replicate 2 [signature]

  dispatchAll
  periodicAll 10
  dispatchAll
  assertCommitIdx 0 4

  trustNode 2 2
  replicate 2 [signature]

  dispatchAll
  periodicAll 10
  dispatchAll
  assertCommitIdx 0 6

  assertDetail 0 "leadership_state" "Leader"
  assertDetail 1 "leadership_state" "Follower"
  assertDetail 2 "leadership_state" "Follower"

  periodicOne 1 150
  dispatchAll
  dispatchAll
  assertDetail 1 "leadership_state" "Leader"
  assertDetail 0 "leadership_state" "Follower"
  assertDetail 2 "leadership_state" "Follower"
