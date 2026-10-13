-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFRaft.Proofs.Direct.Framework
import CCFRaft.Properties
import CCFRaft.Proofs.Ledger

set_option autoImplicit false
set_option linter.unusedSectionVars false

/-!
# Commit frontiers

Every node's commit index lies within its log and, when positive, points to a
signature. The property is local: each local step preserves it, whatever the
message it handles.
-/

namespace CCFRaft.Proofs.Direct

open CCFRaft.Proofs.Config

open Shared
open Model.Local
open Ledger (
  isSignatureAt_of_prefix isSignatureAt_take_of_le
    signatureIndex_le_maxCommittableIndex maxCommittableIndexUpTo_le_length
    maxCommittableIndexUpToPositiveIsSignature
  )
open Ledger (refreshRetirementState_log refreshRetirementState_commitIndex)

variable {Node TxId : Type} [DecidableEq Node] [DecidableEq TxId] [InitialConfig Node]

/-- The commit index lies within the log and, when positive, is a signature. -/
def CommitFrontier (state : NodeState Node TxId) : Prop :=
  state.commitIndex <= state.log.length
  /\ (0 < state.commitIndex -> isSignatureAt state.log state.commitIndex = true)

theorem CommitFrontier.of_log {state after : NodeState Node TxId}
    (frontier : CommitFrontier state) (logEq : after.log = state.log)
    (commitEq : after.commitIndex = state.commitIndex)
    : CommitFrontier after := by
  unfold CommitFrontier at *
  rw [logEq, commitEq]
  exact frontier

theorem CommitFrontier.extend {state : NodeState Node TxId}
    (frontier : CommitFrontier state) {log : List (Entry Node TxId)}
    (extends_ : state.log <+: log)
    : CommitFrontier { state with log } := by
  refine ⟨frontier.1.trans extends_.length_le, fun positive => ?_⟩
  exact isSignatureAt_of_prefix extends_ (frontier.2 positive)

theorem CommitFrontier.keep {state : NodeState Node TxId}
    (frontier : CommitFrontier state) {count : Nat} (within : state.commitIndex <= count)
    {suffix : List (Entry Node TxId)}
    : CommitFrontier { state with log := state.log.take count ++ suffix } := by
  refine ⟨?_, fun positive => ?_⟩
  · simp only [List.length_append, List.length_take]
    have := frontier.1
    omega
  · exact isSignatureAt_of_prefix (List.prefix_append _ _)
      (isSignatureAt_take_of_le within (frontier.2 positive))

/-- A new commit frontier chosen from the latest covered signature. -/
theorem CommitFrontier.advance {state : NodeState Node TxId}
    {log : List (Entry Node TxId)} {bound : Nat}
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

theorem highestCommittableIndex_signature (state : NodeState Node TxId) (self : Node)
    (positive : 0 < highestCommittableIndex (inferInstance) state self)
    : isSignatureAt state.log (highestCommittableIndex (inferInstance) state self)
      = true := by
  unfold highestCommittableIndex at positive ⊢
  exact (foldl_select_max_pos _ _ positive).2.1

theorem signature_le_length {log : List (Entry Node TxId)} {index : Nat}
    (signature : isSignatureAt log index = true)
    : index <= log.length := by
  obtain ⟨entry, found, _⟩ := Ledger.isSignatureAtTrue signature
  exact Ledger.entryAtSomeIndexBound found

theorem CommitFrontier.leaderAppendState {state : NodeState Node TxId}
    (frontier : CommitFrontier state) (self : Node) (content : EntryContent Node TxId)
    : CommitFrontier
        (refreshRetirementState (inferInstance) self
          { state with log := state.log ++ [{ term := state.currentTerm, content }] }) :=
  (frontier.extend (List.prefix_append _ _)).of_log (refreshRetirementState_log _ _)
    (refreshRetirementState_commitIndex _ _)

section AppendEntries

variable {self : Node} {state : NodeState Node TxId}
  {request : AppendEntriesRequest Node TxId}

theorem CommitFrontier.fromLeader (frontier : CommitFrontier state)
    : CommitFrontier (appendEntriesFromLeader (inferInstance) self state request).1 := by
  have advanced := CommitFrontier.advance
    (bound := min request.leaderCommit (request.prevLogIndex + request.entries.length))
    (frontier.extend (List.prefix_append state.log
      (request.entries.drop (state.log.length - request.prevLogIndex))))
  unfold appendEntriesFromLeader committedFromLeader
  exact advanced.of_log (by simp) (by simp)

theorem CommitFrontier.handleAppendEntriesRequest (frontier : CommitFrontier state)
    : CommitFrontier
        (Model.Local.handleAppendEntriesRequest (inferInstance) self state
          request).1 := by
  unfold Model.Local.handleAppendEntriesRequest
  have stepped : CommitFrontier (if request.term = state.currentTerm /\
      (state.role = .candidate \/ state.role = .preVoteCandidate) then
        { state with role := .follower, isNewFollower := true } else state) := by
    split
    · exact frontier.of_log rfl rfl
    · exact frontier
  generalize (if request.term = state.currentTerm /\
      (state.role = .candidate \/ state.role = .preVoteCandidate) then
        { state with role := .follower, isNewFollower := true } else state) = current
    at stepped
  dsimp only
  split
  · exact stepped
  split
  · exact stepped.of_log rfl rfl
  rename_i _ notBefore
  have within : current.commitIndex <= request.prevLogIndex := by
    simp only [not_or] at notBefore
    omega
  split
  · have kept := stepped.keep within (suffix := [])
    exact CommitFrontier.fromLeader (kept.of_log (by simp) rfl)
  · exact CommitFrontier.fromLeader (stepped.of_log rfl rfl)

end AppendEntries

@[simp]
theorem run_pure (value : NodeState Node TxId)
    (outputs : Outputs Node (Message Node TxId) Notification)
    : StateT.run (pure value : NodeEffect Node TxId (NodeState Node TxId)) outputs
      = (value, outputs) :=
  rfl

theorem CommitFrontier.advanced {state : NodeState Node TxId} (self : Node)
    (advances : state.commitIndex < highestCommittableIndex (inferInstance) state self)
    : CommitFrontier (Model.Local.advanceCommit (inferInstance) state self) := by
  have signature := highestCommittableIndex_signature state self (by omega)
  have advanced : CommitFrontier
      (refreshRetirementState (inferInstance) self
        { state with commitIndex := highestCommittableIndex (inferInstance) state self }) :=
    ⟨by simpa using signature_le_length signature, fun _ => by simpa using signature⟩
  unfold Model.Local.advanceCommit
  dsimp only
  split
  · exact advanced.of_log rfl rfl
  · exact advanced

theorem CommitFrontier.withSent {state : NodeState Node TxId}
    (frontier : CommitFrontier state) {sentIndex : Node -> Nat}
    : CommitFrontier { state with sentIndex } :=
  frontier.of_log rfl rfl

theorem CommitFrontier.truncateToSignature {state : NodeState Node TxId}
    (frontier : CommitFrontier state)
    : state.commitIndex <= maxCommittableIndex state.log := by
  by_cases zero : state.commitIndex = 0
  · omega
  · exact signatureIndex_le_maxCommittableIndex (frontier.2 (Nat.pos_of_ne_zero zero))

/-- The log a new leader keeps: its signed prefix, or everything at startup. -/
theorem CommitFrontier.promotedLog {state : NodeState Node TxId}
    (frontier : CommitFrontier state)
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

theorem commitFrontier_invariant
    : Direct.NodeInvariant (Node := Node) (TxId := TxId)
        fun _ state => CommitFrontier state := by
  refine ⟨fun node => ⟨by simp [initialNodeState], by simp [initialNodeState]⟩, ?_⟩
  intro self state event after outputs frontier stepped
  cases event with
  | internal input =>
      cases input <;>
        simp only [Model.Local.step, Model.Local.act, Model.Local.leaderAppend] at stepped <;>
        simp [Capabilities.record] at stepped
      all_goals
        casesm* _ ∧ _
        subst after
      case initializeConfiguration =>
        constructor <;> simp [*]
      case changeConfiguration =>
        exact (frontier.leaderAppendState self _).of_log rfl rfl
      case becomeLeader =>
        exact frontier.promotedLog.of_log (by simp) (by simp)
      all_goals first
        | exact frontier.of_log rfl rfl
        | exact frontier.leaderAppendState _ _
        | exact CommitFrontier.advanced _ (by assumption)
  | receive source message =>
      have observed : CommitFrontier (observeTerm state message) :=
        frontier.of_log (Concrete.observeTerm_log _ _) (Concrete.observeTerm_commitIndex _ _)
      cases message <;>
        simp only [Model.Local.step, Model.Local.receive] at stepped
      case appendEntriesRequest request =>
        have handled := observed.handleAppendEntriesRequest (self := self) (request := request)
        have refreshed := handled.of_log (refreshRetirementState_log _ _)
          (refreshRetirementState_commitIndex _ _) (after := refreshRetirementState
            (inferInstance) self _)
        split at stepped <;> simp [Capabilities.record] at stepped <;>
          obtain ⟨rfl, -⟩ := stepped <;> exact refreshed
      all_goals
        (try split at stepped) <;> simp [Capabilities.record] at stepped <;>
          (try casesm* _ ∧ _) <;> subst after
      all_goals first
        | exact observed
        | exact observed.of_log rfl rfl
        | exact observed.of_log (Concrete.handleAppendEntriesResponse_log _ _ _).1
            (Concrete.handleAppendEntriesResponse_log _ _ _).2
        | exact observed.of_log (Concrete.handleRequestVoteRequest_log _ _ _).1
            (Concrete.handleRequestVoteRequest_log _ _ _).2
        | exact observed.of_log (Concrete.handleRequestVoteResponse_log _ _ _).1
            (Concrete.handleRequestVoteResponse_log _ _ _).2
        | exact observed.of_log (Concrete.handleRequestPreVoteResponse_log _ _ _).1
            (Concrete.handleRequestPreVoteResponse_log _ _ _).2

theorem committed_frontier_is_signature : Properties.CommittedFrontierIsSignature := by
  intro Node TxId _ _ config nodes trace state node nodeState ⟨valid, member, listed, positive⟩
  let _ : Model.Local.InitialConfig Node := config
  exact (commitFrontier_invariant.reachable (valid.reachable member) node nodeState listed).2
    positive

end CCFRaft.Proofs.Direct
