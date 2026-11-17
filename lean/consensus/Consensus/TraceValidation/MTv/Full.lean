module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import Consensus.TraceValidation.Input

@[expose] public section

/-!
# M_tv's working state (not reviewed)

The handlers (`Consensus.TraceValidation.MTv.Aft`) run on `State`: the reviewed declared
state (`Exec.Declared`) with the whole ledger instead of the entries the node holds. For a
node that joined from a snapshot, the entries up to `base` are a ghost: the machine fills
them at the `init_as_backup` release from a node that has committed them
(`fillSnapshot` in `MTv/Machine.lean`), so that the clean `initAsBackup` input
is admitted. `State.declared` projects them away; the machine checks that no hold's
outcome depends on them (`Machine.ghostFree`).

`abs` and `agrees` are the reviewed `Declared.abs` and `Declared.agrees` with the whole
ledger as the held entries; the proofs relate them (`Consensus.TraceValidation.Proofs.Suffix`).
-/

namespace Consensus.TraceValidation.Exec

/-- `Declared`, with the whole ledger. -/
structure State where
  nodeId : NodeId
  currentView : Nat := 0
  lastIdx : Nat := 0
  commitIdx : Nat := 0
  views : Array Nat := #[]
  committable : List Nat := []
  leadership : Leadership := .none
  retired : Bool := false
  retirementPhase : Option Phase := none
  retirementIdx : Option Nat := none
  retirementCommittableIdx : Option Nat := none
  retiredCommittedIdx : Option Nat := none
  votedFor : Option NodeId := none
  leaderId : Option NodeId := none
  votesForMe : List (Nat × List NodeId × Nat) := []
  isNewFollower : Bool := false
  ticking : Bool := false
  configurations : List Config := []
  allOtherNodes : List (NodeId × Peer) := []
  /-- The whole ledger: entry `i` is `ledger[i-1]`; up to `base`, a ghost. -/
  ledger : Array Entry := #[]
  rcEntries : List (Nat × List NodeId) := []
  base : Nat := 0
  baseView : Nat := 0
deriving DecidableEq, Inhabited

/-- The declared state: the ledger after `base`. -/
def State.declared (d : State) : Declared :=
  {
    nodeId := d.nodeId
    currentView := d.currentView
    lastIdx := d.lastIdx
    commitIdx := d.commitIdx
    views := d.views
    committable := d.committable
    leadership := d.leadership
    retired := d.retired
    retirementPhase := d.retirementPhase
    retirementIdx := d.retirementIdx
    retirementCommittableIdx := d.retirementCommittableIdx
    retiredCommittedIdx := d.retiredCommittedIdx
    votedFor := d.votedFor
    leaderId := d.leaderId
    votesForMe := d.votesForMe
    isNewFollower := d.isNewFollower
    ticking := d.ticking
    configurations := d.configurations
    allOtherNodes := d.allOtherNodes
    base := d.base
    baseView := d.baseView
    ledger := d.ledger.extract d.base d.ledger.size
    rcEntries := d.rcEntries
  }

/--
A declared state, with placeholders for the entries up to `base` it does not hold: view 0,
which no ledger entry has (`inv`'s `positive_terms`), and no signature or metadata.
-/
def Declared.expand (d : Declared) : State :=
  {
    nodeId := d.nodeId
    currentView := d.currentView
    lastIdx := d.lastIdx
    commitIdx := d.commitIdx
    views := d.views
    committable := d.committable
    leadership := d.leadership
    retired := d.retired
    retirementPhase := d.retirementPhase
    retirementIdx := d.retirementIdx
    retirementCommittableIdx := d.retirementCommittableIdx
    retiredCommittedIdx := d.retiredCommittedIdx
    votedFor := d.votedFor
    leaderId := d.leaderId
    votesForMe := d.votesForMe
    isNewFollower := d.isNewFollower
    ticking := d.ticking
    configurations := d.configurations
    allOtherNodes := d.allOtherNodes
    base := d.base
    baseView := d.baseView
    ledger := Array.replicate d.base { term := 0, sig := false } ++ d.ledger
    rcEntries := d.rcEntries
  }

end Consensus.TraceValidation.Exec

namespace Consensus.TraceValidation

open Consensus.Model.Node
open Consensus.TraceValidation.Exec (State)

/-- `Declared.abs`, with the whole ledger as the held entries. -/
def abs (names : Names) (d : State) : NodeState :=
  let peer (f : Exec.Peer -> Nat) (n : NodeID) : Nat :=
    match d.allOtherNodes.find? (fun (id, _) => names.id id == n) with
    | some (_, p) => f p
    | none => 0
  -- `votes_for_me` only counts the self-vote in configurations the node is in;
  -- a (pre-vote) candidate has always voted for itself.
  let votes := names.set (d.nodeId :: d.votesForMe.flatMap fun (_, vs, _) => vs)
  {
    role := absRole d.leadership
    currentTerm := d.currentView
    log := (d.ledger.toList.take d.lastIdx).map (absEntry names)
    commitIndex := d.commitIdx
    sentIndex := peer (·.sentIdx)
    matchIndex := peer (·.matchIdx)
    isNewFollower := d.isNewFollower
    votedFor := d.votedFor.map names.id
    primaryKnown := d.leaderId.isSome
    votesGranted := votes
    preVotesGranted := votes
    retiredCommittedIndex := d.retiredCommittedIdx
  }

/-- `Declared.trackedPeers`. -/
def trackedPeers (names : Names) (d : State) : List NodeID :=
  if d.leadership == .leader then d.allOtherNodes.map fun (id, _) => names.id id else []

/-- `Declared.agrees` on the whole ledger. -/
def agrees (names : Names) (c : NodeState) (d : State) : Bool :=
  let a := abs names d
  c.role == a.role
  && c.currentTerm == a.currentTerm
  && c.log == a.log
  && c.commitIndex == a.commitIndex
  && (trackedPeers names d).all
      (fun n => c.sentIndex n == a.sentIndex n && c.matchIndex n == a.matchIndex n)
  && c.isNewFollower == a.isNewFollower
  && c.votedFor == a.votedFor
  && c.primaryKnown == a.primaryKnown
  && (a.role != .candidate || c.votesGranted == a.votesGranted)
  && (a.role != .preVoteCandidate || c.preVotesGranted == a.preVotesGranted)
  && c.retiredCommittedIndex == a.retiredCommittedIndex

end Consensus.TraceValidation
