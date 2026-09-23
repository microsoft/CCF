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

open Shared
open Model.Local
open Ledger (
  isSignatureAt_of_prefix isSignatureAt_take_of_le
    signatureIndex_le_maxCommittableIndex maxCommittableIndexUpTo_le_length
    maxCommittableIndexUpToPositiveIsSignature
  )
open Ledger (refreshRetirementState_log refreshRetirementState_commitIndex)

variable {Node TxId : Type} [DecidableEq Node] [DecidableEq TxId] [Bootstrap Node]

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

theorem highestCommittableIndex_signature (state : NodeState Node TxId) (self : Node)
    (positive : 0 < highestCommittableIndex state self)
    : isSignatureAt state.log (highestCommittableIndex state self) = true := by
  unfold highestCommittableIndex at positive ⊢
  rcases foldl_select_max (fun index => index > state.commitIndex
      /\ isSignatureAt state.log index = true /\ termAt state.log index = state.currentTerm
      /\ hasMajorityAt state self index) (List.range (state.log.length + 1)) 0 with zero | holds
  · rw [zero] at positive
    omega
  · exact holds.2.1

theorem signature_le_length {log : List (Entry Node TxId)} {index : Nat}
    (signature : isSignatureAt log index = true)
    : index <= log.length := by
  obtain ⟨entry, found, _⟩ := Ledger.isSignatureAtTrue signature
  exact Ledger.entryAtSomeIndexBound found

theorem CommitFrontier.appendEntry {state : NodeState Node TxId}
    (frontier : CommitFrontier state) (self : Node) (content : EntryContent Node TxId)
    : CommitFrontier (appendEntry state self content) :=
  (frontier.extend (List.prefix_append _ _)).of_log (refreshRetirementState_log _ _)
    (refreshRetirementState_commitIndex _ _)

section AppendEntries

variable {self : Node} {state : NodeState Node TxId}
  {request : AppendEntriesRequest Node TxId}
  {result : NodeState Node TxId × AppendEntriesResponse}

theorem CommitFrontier.alreadyDone (frontier : CommitFrontier state)
    (done : appendEntriesAlreadyDone? state request = some result)
    : CommitFrontier result.1 := by
  unfold appendEntriesAlreadyDone? at done
  split at done
  · obtain rfl := (Option.some.inj done).symm
    exact CommitFrontier.advance (log := state.log) (frontier.of_log rfl rfl)
  · simp at done

theorem CommitFrontier.noConflict (frontier : CommitFrontier state)
    (within : state.commitIndex <= request.prevLogIndex)
    (appended : noConflictAppendEntriesRequest? self state request = some result)
    : CommitFrontier result.1 := by
  unfold noConflictAppendEntriesRequest? at appended
  split at appended
  · obtain rfl := (Option.some.inj appended).symm
    have kept := frontier.keep within (suffix := request.entries)
    apply (CommitFrontier.advance (bound :=
      min request.leaderCommit (request.prevLogIndex + request.entries.length)) kept).of_log
    · simp
    · simp [committedFromLeader]
  · simp at appended

theorem CommitFrontier.accept (frontier : CommitFrontier state)
    (accepted : acceptAppendEntriesRequest? self state request = some result)
    : CommitFrontier result.1 := by
  unfold acceptAppendEntriesRequest? at accepted
  split at accepted
  · rename_i guard
    have within : state.commitIndex <= request.prevLogIndex := guard.2.2.2
    split at accepted
    · rename_i done
      obtain rfl := Option.some.inj accepted
      exact frontier.alreadyDone done
    · split at accepted
      · rename_i appended
        obtain rfl := Option.some.inj accepted
        exact frontier.noConflict within appended
      · split at accepted
        · simp at accepted
        · rename_i truncated conflicted
          unfold conflictAppendEntriesRequest? at conflicted
          split at conflicted
          · obtain rfl := (Option.some.inj conflicted).symm
            have truncatedFrontier :
                CommitFrontier { state with
                  log := state.log.take request.prevLogIndex, isNewFollower := false } := by
              have kept := frontier.keep within (suffix := [])
              simpa using kept.of_log (after := { state with
                log := state.log.take request.prevLogIndex, isNewFollower := false })
                (by simp) rfl
            split at accepted
            · rename_i done
              obtain rfl := Option.some.inj accepted
              exact truncatedFrontier.alreadyDone done
            · exact truncatedFrontier.noConflict within accepted
          · simp at conflicted
  · simp at accepted

theorem CommitFrontier.handleAppendEntriesRequest (frontier : CommitFrontier state)
    (handled : handleAppendEntriesRequest? self state request = some result)
    : CommitFrontier result.1 := by
  unfold handleAppendEntriesRequest? at handled
  have stepped : CommitFrontier (if request.term = state.currentTerm /\
      (state.role = .candidate \/ state.role = .preVoteCandidate) then
        { state with role := .follower, isNewFollower := true } else state) := by
    split
    · exact frontier.of_log rfl rfl
    · exact frontier
  generalize (if request.term = state.currentTerm /\
      (state.role = .candidate \/ state.role = .preVoteCandidate) then
        { state with role := .follower, isNewFollower := true } else state) = current
    at handled stepped
  dsimp only at handled
  split at handled
  · rename_i rejected
    unfold rejectAppendEntriesRequest? at rejected
    split at rejected
    · obtain rfl := Option.some.inj handled
      obtain rfl := (Option.some.inj rejected).symm
      exact stepped
    · simp at rejected
  · exact stepped.accept handled

end AppendEntries

@[simp]
theorem run_pure (value : NodeState Node TxId)
    (outputs : Outputs Node (Message Node TxId) Notification)
    : StateT.run (pure value : NodeEffect Node TxId (NodeState Node TxId)) outputs
      = (value, outputs) :=
  rfl

@[simp]
theorem run_send (node target : Node) (message : Message Node TxId)
    (value : NodeState Node TxId)
    (outputs : Outputs Node (Message Node TxId) Notification)
    : StateT.run
        (StateT.bind ((Capabilities.record node : Host Node TxId).send message target)
            fun _ => pure value
          : NodeEffect Node TxId (NodeState Node TxId)) outputs
      = (
        value,
        { outputs with outgoing := outputs.outgoing ++ [⟨node, target, message⟩] }
      ) :=
  rfl

theorem CommitFrontier.advanced {state : NodeState Node TxId} (self : Node)
    (advances : state.commitIndex < highestCommittableIndex state self)
    : CommitFrontier (demoteRetiredCommitted (Model.Local.advanceCommit state self)) := by
  have signature := highestCommittableIndex_signature state self (by omega)
  have advanced : CommitFrontier (Model.Local.advanceCommit state self) := by
    unfold Model.Local.advanceCommit
    exact ⟨by simpa using signature_le_length signature, fun _ => by simpa using signature⟩
  unfold demoteRetiredCommitted
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

theorem CommitFrontier.promoted {state : NodeState Node TxId} (self : Node)
    (frontier : CommitFrontier state) {role : Role} {sentIndex matchIndex : Node -> Nat}
    : CommitFrontier
        (refreshRetirementState self
          {
            state with
              log := state.log.take (maxCommittableIndex state.log)
              role
              sentIndex
              matchIndex
          }) := by
  have kept := frontier.keep frontier.truncateToSignature (suffix := [])
  exact kept.of_log (by simp) (by simp)

theorem commitFrontier_invariant
    : Direct.NodeInvariant (Node := Node) (TxId := TxId)
        fun _ state => CommitFrontier state := by
  refine ⟨fun node => ⟨by simp [initialNodeState], by simp [initialNodeState]⟩, ?_⟩
  intro self state event execute frontier stepped
  cases event with
  | internal input =>
      simp only [Model.Local.step] at stepped
      cases input <;>
        simp only [Model.Local.act, guard, bind, Option.bind] at stepped <;>
        split at stepped <;> (try simp at stepped) <;>
        rename_i condition <;>
        have holds := Concrete.guard_holds condition <;>
        subst stepped <;>
        simp only [run_pure, run_send]
      all_goals first
        | exact frontier
        | exact frontier.appendEntry _ _
        | exact (frontier.appendEntry _ _).withSent
        | exact frontier.of_log rfl rfl
        | exact CommitFrontier.advanced _ holds.2.1
        | exact frontier.promoted _
        | exact ⟨by simp [holds.2.2.2.2.1], by simp [holds.2.2.2.2.1]⟩
  | receive source message =>
      simp only [Model.Local.step] at stepped
      have observed : CommitFrontier (observeTerm state message) :=
        frontier.of_log (Concrete.observeTerm_log _ _) (Concrete.observeTerm_commitIndex _ _)
      cases message with
      | appendEntriesRequest request =>
          simp only [Model.Local.receive] at stepped
          obtain ⟨⟨next, response⟩, handled, done⟩ := Option.bind_eq_some_iff.mp stepped
          obtain rfl := (Option.some.inj done).symm
          exact (observed.handleAppendEntriesRequest handled).of_log
            (refreshRetirementState_log _ _) (refreshRetirementState_commitIndex _ _)
      | appendEntriesResponse response =>
          simp only [Model.Local.receive] at stepped
          obtain rfl := (Option.some.inj stepped).symm
          have kept := Concrete.handleAppendEntriesResponse_log (observeTerm state
            (.appendEntriesResponse response)) source response
          exact observed.of_log kept.1 kept.2
      | requestVoteRequest request =>
          simp only [Model.Local.receive] at stepped
          obtain rfl := (Option.some.inj stepped).symm
          have kept := Concrete.handleRequestVoteRequest_log (observeTerm state
            (.requestVoteRequest request)) source request
          exact observed.of_log kept.1 kept.2
      | requestVoteResponse response =>
          simp only [Model.Local.receive] at stepped
          obtain rfl := (Option.some.inj stepped).symm
          have kept := Concrete.handleRequestVoteResponse_log (observeTerm state
            (.requestVoteResponse response)) source response
          exact observed.of_log kept.1 kept.2
      | requestPreVote request =>
          simp only [Model.Local.receive] at stepped
          obtain rfl := (Option.some.inj stepped).symm
          exact observed
      | requestPreVoteResponse response =>
          simp only [Model.Local.receive] at stepped
          obtain rfl := (Option.some.inj stepped).symm
          have kept := Concrete.handleRequestPreVoteResponse_log (observeTerm state
            (.requestPreVoteResponse response)) source response
          exact observed.of_log kept.1 kept.2
      | proposeVoteRequest term =>
          simp only [Model.Local.receive] at stepped
          obtain rfl := (Option.some.inj stepped).symm
          have kept := Concrete.handleProposeVoteRequest_log (observeTerm state
            (.proposeVoteRequest term)) self term
          exact observed.of_log kept.1 kept.2

theorem committed_frontier_is_signature : Properties.CommittedFrontierIsSignature := by
  intro Node TxId _ _ _ nodes trace state node nodeState ⟨valid, member, listed, positive⟩
  exact (commitFrontier_invariant.reachable (valid.reachable member) node nodeState listed).2
    positive

end CCFRaft.Proofs.Direct
