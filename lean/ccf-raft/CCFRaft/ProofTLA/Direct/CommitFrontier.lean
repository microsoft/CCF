module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import CCFRaft.ProofTLA.Direct.Effects
public import CCFRaft.ProofTLA.Direct.Framework
public import CCFRaft.ProofTLA.Ledger

@[expose] public section

set_option linter.unusedSectionVars false

/-!
# Commit frontiers

Every node's commit index lies within its log and, when positive, points to a
signature. The property is local: each local step preserves it, whatever the
message it handles.
-/

namespace CCFRaft.ProofTLA.Direct

open CCFRaft.ProofTLA.Config

open CCF
open Model.Node
open Ledger (
  isSignatureAt_of_prefix isSignatureAt_take_of_le
    signatureIndex_le_maxCommittableIndex maxCommittableIndexUpTo_le_length
    maxCommittableIndexUpToPositiveIsSignature
  )

variable [Initial]

/-- The commit index lies within the log and, when positive, is a signature. -/
def CommitFrontier (state : NodeState) : Prop :=
  state.commitIndex <= state.log.length
  /\ (0 < state.commitIndex -> isSignatureAt state.log state.commitIndex = true)

theorem CommitFrontier.of_log {state after : NodeState}
    (frontier : CommitFrontier state) (logEq : after.log = state.log)
    (commitEq : after.commitIndex = state.commitIndex)
    : CommitFrontier after := by
  unfold CommitFrontier at *
  rw [logEq, commitEq]
  exact frontier

theorem CommitFrontier.extend {state : NodeState}
    (frontier : CommitFrontier state) {log : List (Entry)}
    (extends_ : state.log <+: log)
    : CommitFrontier { state with log } := by
  refine ⟨frontier.1.trans extends_.length_le, fun positive => ?_⟩
  exact isSignatureAt_of_prefix extends_ (frontier.2 positive)

theorem CommitFrontier.keep {state : NodeState}
    (frontier : CommitFrontier state) {count : Nat} (within : state.commitIndex <= count)
    {suffix : List (Entry)}
    : CommitFrontier { state with log := state.log.take count ++ suffix } := by
  refine ⟨?_, fun positive => ?_⟩
  · simp only [List.length_append, List.length_take]
    have := frontier.1
    omega
  · exact isSignatureAt_of_prefix (List.prefix_append _ _)
      (isSignatureAt_take_of_le within (frontier.2 positive))

/-- A new commit frontier chosen from the latest covered signature. -/
theorem CommitFrontier.advance {state : NodeState}
    {log : List (Entry)} {bound : Nat}
    (extends_ : CommitFrontier { state with log })
    : CommitFrontier
        {
          state with
            log, commitIndex := max state.commitIndex (maxCommittableIndexUpTo log bound)
        } := by
  refine ⟨max_le extends_.1 (maxCommittableIndexUpTo_le_length log bound), fun positive => ?_⟩
  simp only at positive ⊢
  rcases Nat.le_total state.commitIndex (maxCommittableIndexUpTo log bound) with le | le
  · rw [max_eq_right le] at positive ⊢
    exact maxCommittableIndexUpToPositiveIsSignature positive
  · rw [max_eq_left le] at positive ⊢
    exact extends_.2 positive

theorem foldl_select_max (P : Nat -> Prop) [DecidablePred P] (values : List Nat)
    (init : Nat)
    : values.foldl (fun best index => if P index then max best index else best) init
        = init
      \/ P
          (values.foldl (fun best index => if P index then max best index else best)
            init) := by
  induction values generalizing init with
  | nil => exact Or.inl rfl
  | cons head tail ih =>
      simp only [List.foldl_cons]
      rcases ih (if P head then max init head else init) with same | holds
      · rw [same]
        by_cases chosen : P head
        · rcases Nat.le_total init head with le | le
          · right
            simp [chosen, max_eq_right le]
          · left
            simp [chosen, max_eq_left le]
        · simp [chosen]
      · exact Or.inr holds

theorem foldl_select_max_pos (P : Nat -> Prop) [DecidablePred P] (values : List Nat)
    (positive
      : 0 < values.foldl (fun best index => if P index then max best index else best) 0)
    : P
        (values.foldl (fun best index => if P index then max best index else best)
          0) := by
  rcases foldl_select_max P values 0 with zero | holds
  · rw [zero] at positive
    omega
  · exact holds

theorem highestCommittableIndex_signature (state : NodeState) (self : NodeID)
    (positive : 0 < highestCommittableIndex state self)
    : isSignatureAt state.log (highestCommittableIndex state self) = true := by
  unfold highestCommittableIndex at positive ⊢
  exact (foldl_select_max_pos _ _ positive).2.1

theorem signature_le_length {log : List (Entry)} {index : Nat}
    (signature : isSignatureAt log index = true)
    : index <= log.length := by
  obtain ⟨entry, found, _⟩ := Ledger.isSignatureAtTrue signature
  exact Ledger.entryAtSomeIndexBound found

theorem CommitFrontier.leaderAppendState {state : NodeState}
    (frontier : CommitFrontier state) (content : EntryContent)
    : CommitFrontier
        { state with log := state.log ++ [{ term := state.currentTerm, content }] } :=
  frontier.extend (List.prefix_append _ _)

section AppendEntries

variable {self : NodeID} {state : NodeState}
  {request : AppendEntriesRequest}

theorem CommitFrontier.fromLeader (frontier : CommitFrontier state)
    : CommitFrontier (handleAppendEntiresFromPrimary self state request).1 := by
  obtain ⟨retired, role, known, eq, _⟩ :=
    Ledger.handleAppendEntiresFromPrimary_eq self state request
  rw [eq]
  exact (CommitFrontier.advance
          (bound :=
            min request.primaryCommit (request.prevLogIndex + request.entries.length))
          (frontier.extend (List.prefix_append _ _))).of_log
    rfl rfl

theorem CommitFrontier.handleAppendEntriesRequest (frontier : CommitFrontier state)
    (caps : Caps) (source : NodeID)
    : Keeps CommitFrontier
        (Model.Node.handleAppendEntriesRequest caps self source state request) := by
  unfold Model.Node.handleAppendEntriesRequest
  have stepped : CommitFrontier (if request.term = state.currentTerm /\
      (state.role = .candidate \/ state.role = .preVoteCandidate) then
        Model.Node.becomeAwareOfNewTerm state request.term else state) := by
    split
    · exact frontier.of_log rfl rfl
    · exact frontier
  generalize (if request.term = state.currentTerm /\
      (state.role = .candidate \/ state.role = .preVoteCandidate) then
        Model.Node.becomeAwareOfNewTerm state request.term else state) = current
    at stepped
  refine Keeps.ite' (fun _ => by
    dsimp only
    split <;> exact Keeps.seq' fun _ => Keeps.pure' stepped) fun _ => ?_
  dsimp only
  refine Keeps.ite' (fun _ => Keeps.pure' (stepped.of_log rfl rfl)) fun notBefore => ?_
  have within : current.commitIndex <= request.prevLogIndex := by
    simp only [not_or] at notBefore
    omega
  generalize found : firstTermConflictIndex { current with primaryKnown := true } request
    = conflict
  refine Keeps.seq' fun _ => Keeps.pure' (CommitFrontier.fromLeader ?_)
  cases conflict with
  | none => exact stepped.of_log rfl rfl
  | some index =>
      have := Ledger.firstTermConflictIndex_gt found
      exact (stepped.keep (count := index - 1) (by omega) (suffix := [])).of_log (by simp)
        rfl

end AppendEntries

theorem CommitFrontier.advanced {state : NodeState} (self : NodeID)
    (frontier : CommitFrontier state) (caps : Caps)
    : Keeps CommitFrontier (Model.Node.advanceCommit caps state self) := by
  unfold Model.Node.advanceCommit
  refine Keeps.ite' (fun _ => Keeps.pure' frontier) fun ahead => ?_
  have signature := highestCommittableIndex_signature state self (by omega)
  have advanced : CommitFrontier
      (state.recordCommit self (highestCommittableIndex state self)) := by
    obtain ⟨retired, role, known, eq, _⟩ :=
      Ledger.recordCommit_eq self state (highestCommittableIndex state self)
    rw [eq]
    exact ⟨signature_le_length signature, fun _ => signature⟩
  dsimp only
  refine Keeps.ite'
    (fun _ =>
      Keeps.ite' (fun _ => Keeps.seq' fun _ => Keeps.pure' (advanced.of_log rfl rfl))
        fun _ => Keeps.pure' (advanced.of_log rfl rfl))
    fun _ => Keeps.pure' advanced

theorem CommitFrontier.withSent {state : NodeState}
    (frontier : CommitFrontier state) {sentIndex : NodeID -> Nat}
    : CommitFrontier { state with sentIndex } :=
  frontier.of_log rfl rfl

/-- The log a new leader keeps: its signed prefix, or everything at startup. -/
theorem CommitFrontier.promotedLog {state : NodeState} (frontier : CommitFrontier state)
    : CommitFrontier
        {
          state with
            log :=
              if state.commitIndex > 0 then
                state.log.take (lastCommittableIndex state)
              else
                state.log
        } := by
  split
  · have kept := frontier.keep (count := lastCommittableIndex state)
      (by unfold lastCommittableIndex; omega) (suffix := [])
    exact kept.of_log (by simp) rfl
  · exact frontier.of_log rfl rfl

section Handlers

variable (caps : Caps) (self : NodeID)

theorem CommitFrontier.appendEntry {state : NodeState}
    (frontier : CommitFrontier state) (content : EntryContent)
    : Keeps CommitFrontier (Model.Node.appendEntry caps self state content) := by
  unfold Model.Node.appendEntry
  simp only [pure_bind]
  repeat'
    first
    | exact Keeps.pure' ((frontier.leaderAppendState content).of_log rfl rfl)
    | refine Keeps.ite' (fun _ => ?_) fun _ => ?_
    | refine Keeps.seq' fun _ => ?_
    | split

theorem CommitFrontier.becomePrimary {state : NodeState} (frontier : CommitFrontier state)
    : Keeps CommitFrontier (Model.Node.becomePrimary caps self state) := by
  unfold Model.Node.becomePrimary
  refine Keeps.bind' (CommitFrontier.advanced self ?_ caps) fun _ kept =>
      Keeps.seq' fun _ => Keeps.pure' kept
  unfold Model.Node.primaryState
  exact frontier.promotedLog.of_log rfl rfl

theorem CommitFrontier.electIfQuorum {state : NodeState} (frontier : CommitFrontier state)
    : Keeps CommitFrontier (Model.Node.electIfQuorum caps self state) := by
  unfold Model.Node.electIfQuorum
  exact Keeps.ite' (fun _ => frontier.becomePrimary caps self) fun _ => Keeps.pure' frontier

theorem CommitFrontier.becomeCandidate {state : NodeState}
    (frontier : CommitFrontier state)
    : Keeps CommitFrontier (Model.Node.becomeCandidate caps state self) := by
  unfold Model.Node.becomeCandidate
  refine Keeps.bind' (CommitFrontier.electIfQuorum caps self ?_) fun _ kept =>
    Keeps.seq' fun _ => Keeps.pure' kept
  exact frontier.of_log rfl rfl

theorem CommitFrontier.becomePreVoteCandidate {state : NodeState}
    (frontier : CommitFrontier state)
    : Keeps CommitFrontier (Model.Node.becomePreVoteCandidate caps state self) := by
  unfold Model.Node.becomePreVoteCandidate
  refine Keeps.ite' (fun _ => CommitFrontier.becomeCandidate caps self ?_)
    fun _ => Keeps.seq' fun _ => Keeps.pure' ?_ <;> exact frontier.of_log rfl rfl

theorem CommitFrontier.act {state : NodeState}
    (frontier : CommitFrontier state) (input : Input)
    : Keeps CommitFrontier (Model.Node.act caps self state input) := by
  cases input with
  | append entries =>
      unfold Model.Node.act Model.Node.appendBatch
      exact Keeps.seq' fun _ => Keeps.bind'
        (Keeps.foldlM' (fun current content kept => kept.appendEntry caps self content)
          entries state frontier)
        fun _ kept => kept.advanced self caps
  | sendEntries destination endIndex =>
      unfold Model.Node.act Model.Node.sendEntries
      exact Keeps.seq' fun _ => Keeps.seq' fun _ => Keeps.pure' frontier.withSent
  | timeout kind =>
      cases kind with
      | election =>
          unfold Model.Node.act Model.Node.startElection
          exact Keeps.seq' fun _ => frontier.becomePreVoteCandidate caps self
      | checkQuorum =>
          unfold Model.Node.act Model.Node.checkQuorum
          exact Keeps.seq' fun _ => Keeps.pure' (frontier.of_log rfl rfl)
  | nominateSuccessor =>
      unfold Model.Node.act
      exact Keeps.seq' fun _ => Keeps.seq' fun _ =>
        Keeps.pure' (frontier.of_log rfl rfl)

theorem CommitFrontier.receive {state : NodeState}
    (frontier : CommitFrontier state) (source : NodeID) (message : Message)
    : Keeps CommitFrontier (Model.Node.receive caps self source state message) := by
  have observed : CommitFrontier (observeTerm state message) :=
    frontier.of_log (Concrete.observeTerm_log _ _) (Concrete.observeTerm_commitIndex _ _)
  unfold Model.Node.receive
  refine Keeps.ite' (fun _ => Keeps.pure' frontier) fun _ => ?_
  dsimp only
  generalize observeTerm state message = current at observed ⊢
  cases message with
  | appendEntriesRequest request => exact observed.handleAppendEntriesRequest caps source
  | appendEntriesResponse response =>
      unfold Model.Node.handleAppendEntriesResponse
      refine Keeps.ite' (fun _ => Keeps.pure' observed) fun _ => ?_
      refine Keeps.ite' (fun _ => ?_) fun _ => Keeps.pure' (observed.of_log rfl rfl)
      refine Keeps.ite' (fun _ => CommitFrontier.advanced self ?_ caps)
        fun _ => Keeps.pure' observed
      exact observed.of_log rfl rfl
  | requestVoteRequest request =>
      unfold Model.Node.handleRequestVoteRequest
      exact Keeps.seq' fun _ => Keeps.pure' (by split <;> exact observed.of_log rfl rfl)
  | requestVoteResponse response =>
      unfold Model.Node.handleRequestVoteResponse
      exact Keeps.ite' (fun _ => CommitFrontier.electIfQuorum caps self (observed.of_log rfl rfl))
        fun _ => Keeps.pure' observed
  | requestPreVoteRequest request =>
      unfold Model.Node.handleRequestPreVoteRequest
      exact Keeps.seq' fun _ => Keeps.pure' observed
  | requestPreVoteResponse response =>
      unfold Model.Node.handleRequestPreVoteResponse
      refine Keeps.ite' (fun _ => ?_) fun _ => Keeps.pure' observed
      dsimp only
      exact Keeps.ite' (fun _ => CommitFrontier.becomeCandidate caps self (observed.of_log rfl rfl))
        fun _ => Keeps.pure' (observed.of_log rfl rfl)
  | proposeRequestVoteRequest term =>
      unfold Model.Node.handleProposeRequestVoteRequest
      exact Keeps.ite' (fun _ => CommitFrontier.becomeCandidate caps self observed)
        fun _ => Keeps.pure' observed

end Handlers

theorem commitFrontier_invariant
    : Direct.NodeInvariant fun _ state => CommitFrontier state := by
  refine ⟨
    fun node =>
      ⟨Nat.zero_le _, fun positive => by simp [Model.initialNodeState] at positive⟩,
    ?_
  ⟩
  intro self state event after outputs frontier stepped
  cases event with
  | internal input =>
      simp only [Model.Node.step] at stepped
      exact frontier.act _ self _ _ _ _ stepped
  | receive source message =>
      simp only [Model.Node.step] at stepped
      exact frontier.receive _ self source message _ _ _ stepped

end CCFRaft.ProofTLA.Direct
