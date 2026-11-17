module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import Consensus.TraceValidation.Proofs.Handlers.AppendEntries
public import Consensus.TraceValidation.Proofs.Handlers.AppendEntriesResponse
public import Consensus.TraceValidation.Proofs.Handlers.DropPendingTo
public import Consensus.TraceValidation.Proofs.Handlers.ForceBecomePrimary
public import Consensus.TraceValidation.Proofs.Handlers.InitAsBackup
public import Consensus.TraceValidation.Proofs.Handlers.Nomination
public import Consensus.TraceValidation.Proofs.Handlers.OutOfLockHook
public import Consensus.TraceValidation.Proofs.Handlers.ProposeRequestVote
public import Consensus.TraceValidation.Proofs.Handlers.Replicate
public import Consensus.TraceValidation.Proofs.Handlers.RequestPreVote
public import Consensus.TraceValidation.Proofs.Handlers.RequestPreVoteResponse
public import Consensus.TraceValidation.Proofs.Handlers.RequestVote
public import Consensus.TraceValidation.Proofs.Handlers.RequestVoteResponse
public import Consensus.TraceValidation.Proofs.Handlers.Tick

@[expose] public section

/-!
# Per-handler obligations: assembly (not reviewed)

Each obligation of `Obligations` is proved in its own file
`Consensus.TraceValidation.Proofs.Handlers.<Name>`, as
`theorem <name>Sound (env : Env) : <Name>Sound env`.
-/

namespace Consensus.TraceValidation.Proofs

/-- Every handler's obligation. -/
theorem obligations (env : Env) : Obligations env where
  appendEntries := appendEntriesSound env
  appendEntriesResponse := appendEntriesResponseSound env
  requestVote := requestVoteSound env
  requestPreVote := requestPreVoteSound env
  requestVoteResponse := requestVoteResponseSound env
  requestPreVoteResponse := requestPreVoteResponseSound env
  proposeRequestVote := proposeRequestVoteSound env
  tick := tickSound env
  replicate := replicateSound env
  nomination := nominationSound env
  initAsBackup := initAsBackupSound env
  outOfLockHook := outOfLockHookSound env
  forceBecomePrimary := forceBecomePrimarySound env
  dropPendingTo := dropPendingToSound env

end Consensus.TraceValidation.Proofs
