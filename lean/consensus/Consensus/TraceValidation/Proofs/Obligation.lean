module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import Consensus.TraceValidation.MTv.Invariant
public import Consensus.TraceValidation.MTv.Machine

@[expose] public section

/-!
# Per-handler obligations (not reviewed)

The refinement proof (`Consensus.TraceValidation.Proofs.Section`) reduces every lock hold to
one obligation about the `cft.h` handler the hold runs, `HoldSound`: run to completion from a
declared state `saved` satisfying the invariant, on any actions, the handler

* assuming the declared state at release satisfies `inv` (the machine rejects the trace
  at release otherwise), keeps the node id;
* if `saved` is not the pristine genesis primary (whose holds `genesisOk` restricts) and a
  clean state agrees with it and satisfies `UnnamedUnmatched`, the clean state is matched by
  the clean receive of the delivered message, if any, then admitted clean internal inputs,
  reaching a clean state that agrees with the released declared state and satisfies
  `UnnamedUnmatched`, with exactly the hold's sends, each satisfying `msgInv`.

`Obligations env` lists one obligation per handler, keyed by message type for deliveries.
Each is an independent proposition (`AppendEntriesSound` and so on), proved in its own file
under `Consensus.TraceValidation.Proofs.Handlers`, importing only this file and lemma
libraries.
-/

namespace Consensus.TraceValidation

open Consensus.Model.Node
open Consensus.TraceValidation.Exec (State)

/--
A clean primary `node` has match index 0 for every other node that no configuration in its
log names.

`agrees` (reviewed) relates match indexes only for the declared peers, so without this a
clean state related to a primary may hold a stale match index for a node outside its
configurations; when a configuration then adds that node, cft.h creates the peer with
`match_idx = 0` while the clean `appendEntry` keeps the stale value, and `ReplicateSound`
fails. It holds of every clean initial state (all match indexes are 0) and is kept by every
clean step: `becomePrimary` resets every match index, a primary's log only grows (so the
named nodes only grow), and a primary raises a match index only on a response from a peer,
which M_tv only accepts from a declared peer, whom the `peers` conjunct of `inv` puts in a
configuration of the log. A clean state that is not primary is unconstrained.

This is the weakest of the forms considered. Under `inv` (`peers`), the nodes outside the
declared peers and outside `removedNodes` are the unnamed nodes and possibly the node
itself, whose match index the clean model never reads, so this is implied by "a clean
primary has match index 0 outside its declared peers and `removedNodes`". Being about the
clean state alone, it needs no reasoning about peers erased at retirement.
-/
def UnnamedUnmatched (node : NodeID) (c : NodeState) : Prop :=
  c.role = .primary
  -> forall n,
      n ≠ node
      -> n ∉ configurationMembers (configurationHistory c.log)
      -> c.matchIndex n = 0

/--
`Rel env node c d`: the clean state `c` of `node` stands for the declared state `d`, which
satisfies the local invariant: `c` agrees with `d`, or, if `d` is the pristine genesis
primary (`pristine`), `c` is still the clean initial state; and `c` has no stale match
index for a node outside its configurations (`UnnamedUnmatched`).
-/
def Rel (env : Env) (node : NodeID) (c : NodeState) (d : State) : Prop :=
  d.nodeId = env.names.name node
  /\ env.names.id d.nodeId = node
  /\ inv env.names d = true
  /\ (pristine env d = false /\ agrees env.names c d = true
      \/ pristine env d = true /\ c = Consensus.Model.initialNodeState env.genesis node)
  /\ UnnamedUnmatched node c

/--
Admits an internal input given the other nodes' clean states: a node initializes only from
a prefix that some other node has committed (`Model.networkStep`'s guard).
-/
def admit (others : List (NodeID × NodeState)) (_node : NodeID) : Input -> Bool
  | .initAsBackup entries =>
      others.any
        fun (_, c) =>
          entries.length <= c.commitIndex && c.log.take entries.length == entries
  | _ => true

end Consensus.TraceValidation

namespace Consensus.TraceValidation.Proofs

open CCF.Sections (LocalRun Keyed)
open Consensus.Model.Node
open Consensus.TraceValidation.Exec (State Ctx Action)

/-- A hold's clean local actions: the receive of its message, if any, then internal inputs. -/
def cleanActions (env : Env) (recv : Option (NodeID × Message)) (inputs : List Input)
    : List Event :=
  (recv.map fun (source, message) => (protocol env).receive source message).toList
  ++ inputs.map (protocol env).internal

/-- The declared state at release of every hold but a joiner's: the handler's. -/
def plainFinish (_others : List (NodeID × Local)) (c : Ctx) : Except String State :=
  .ok c.vars

/-- The declared state at release of `init_as_backup`: the snapshot prefix from a donor. -/
def joinFinish (others : List (NodeID × Local)) (c : Ctx) : Except String State :=
  match snapshotOf c with
  | some (index, term) => fillSnapshot others index term c.vars
  | none => .ok c.vars

/--
The obligation of a hold of handler `h` on `node`, delivering `recv`, from the declared
state `saved`, released by `finish`.
-/
def HoldSound (env : Env) (node : NodeID) (recv : Option (NodeID × Message))
    (h : Exec.M Unit) (saved : State)
    (finish : List (NodeID × Local) -> Ctx -> Except String State)
    : Prop :=
  forall (actions : List Action) (c : Ctx) (vars : State) (others : List (NodeID × Local))
          (cleanOthers : List (NodeID × NodeState)),
    saved.nodeId = env.names.name node
    -> env.names.id saved.nodeId = node
    -> inv env.names saved = true
    -> (forall source message,
          recv = some (source, message)
          -> msgInv env.names ⟨source, node, message⟩ = true)
    -> Keyed (fun other local_ cleanOther => Rel env other cleanOther local_.vars) others
        cleanOthers
    -> Exec.run env saved actions true h = .ok c
    -> c.queue = []
    -> finish others c = .ok vars
    -> inv env.names vars = true
    -> vars.nodeId = saved.nodeId
        /\ forall clean,
            pristine env saved = false
            -> agrees env.names clean saved = true
            -> UnnamedUnmatched node clean
            -> exists (inputs : List Input) (clean' : NodeState),
                LocalRun (protocol env) node clean (cleanActions env recv inputs) clean'
                  c.outbox
                /\ agrees env.names clean' vars = true
                /\ UnnamedUnmatched node clean'
                /\ (forall input, input ∈ inputs -> admit cleanOthers node input = true)
                /\ forall envelope,
                    envelope ∈ c.outbox -> msgInv env.names envelope = true

/-! ## Deliveries, by message type -/

abbrev AppendEntriesSound (env : Env) : Prop :=
  forall node source request saved,
    HoldSound env node (some (source, .appendEntriesRequest request))
      (Exec.recvAppendEntries (env.names.name source) request) saved plainFinish

abbrev AppendEntriesResponseSound (env : Env) : Prop :=
  forall node source response saved,
    HoldSound env node (some (source, .appendEntriesResponse response))
      (Exec.recvAppendEntriesResponse (env.names.name source) response) saved plainFinish

abbrev RequestVoteSound (env : Env) : Prop :=
  forall node source request saved,
    HoldSound env node (some (source, .requestVoteRequest request))
      (Exec.recvRequestVote (env.names.name source) false request) saved plainFinish

abbrev RequestPreVoteSound (env : Env) : Prop :=
  forall node source request saved,
    HoldSound env node (some (source, .requestPreVoteRequest request))
      (Exec.recvRequestVote (env.names.name source) true request) saved plainFinish

abbrev RequestVoteResponseSound (env : Env) : Prop :=
  forall node source response saved,
    initialised saved = true
    -> HoldSound env node (some (source, .requestVoteResponse response))
        (Exec.recvRequestVoteResponse (env.names.name source) false response) saved
        plainFinish

abbrev RequestPreVoteResponseSound (env : Env) : Prop :=
  forall node source response saved,
    initialised saved = true
    -> HoldSound env node (some (source, .requestPreVoteResponse response))
        (Exec.recvRequestVoteResponse (env.names.name source) true response) saved
        plainFinish

abbrev ProposeRequestVoteSound (env : Env) : Prop :=
  forall node source term saved,
    initialised saved = true
    -> HoldSound env node (some (source, .proposeRequestVoteRequest term))
        (Exec.recvProposeRequestVote (env.names.name source) term) saved plainFinish

/-! ## Local heads -/

abbrev TickSound (env : Env) : Prop :=
  forall node saved, HoldSound env node none Exec.periodic saved plainFinish

abbrev ReplicateSound (env : Env) : Prop :=
  forall node saved, HoldSound env node none Exec.replicate saved plainFinish

abbrev NominationSound (env : Env) : Prop :=
  forall node saved, HoldSound env node none Exec.nominateSuccessor saved plainFinish

abbrev InitAsBackupSound (env : Env) : Prop :=
  forall node saved, HoldSound env node none Exec.initAsBackup saved joinFinish

/-- The snapshot's configuration hooks, outside the lock, before `init_as_backup`. -/
abbrev OutOfLockHookSound (env : Env) : Prop :=
  forall node saved,
    saved.leadership = .none
    -> saved.currentView = 0
    -> HoldSound env node none Exec.outOfLockHook saved plainFinish

/-- `force_become_primary`, untraced, opened by its `become_leader`. -/
abbrev ForceBecomePrimarySound (env : Env) : Prop :=
  forall node saved,
    saved.currentView = 0
    -> saved.leadership = .none
    -> pristine env saved = true
    -> HoldSound env node none Exec.forceBecomePrimary saved plainFinish

abbrev DropPendingToSound (env : Env) : Prop :=
  forall node saved, HoldSound env node none Exec.dropPendingTo saved plainFinish

/-- Every handler's obligation. -/
structure Obligations (env : Env) : Prop where
  appendEntries : AppendEntriesSound env
  appendEntriesResponse : AppendEntriesResponseSound env
  requestVote : RequestVoteSound env
  requestPreVote : RequestPreVoteSound env
  requestVoteResponse : RequestVoteResponseSound env
  requestPreVoteResponse : RequestPreVoteResponseSound env
  proposeRequestVote : ProposeRequestVoteSound env
  tick : TickSound env
  replicate : ReplicateSound env
  nomination : NominationSound env
  initAsBackup : InitAsBackupSound env
  outOfLockHook : OutOfLockHookSound env
  forceBecomePrimary : ForceBecomePrimarySound env
  dropPendingTo : DropPendingToSound env

end Consensus.TraceValidation.Proofs
