-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFRaft.Proofs.Direct.CommitFrontier
import CCFRaft.Properties

set_option autoImplicit false
set_option linter.unusedSectionVars false

/-!
# Append-only committed logs

A local step never lowers a node's commit index and never rewrites its log
below that index. Truncation happens only above the commit index: an accepted
AppendEntries request starts at or after it, and a new leader keeps its log up
to its latest signature, which the commit frontier does not pass.
-/

namespace CCFRaft.Proofs.Direct

open Shared Shared.MultiNodeTransitionSystem Refinement
open Model.Local
open Abstract.ModelProofs (refreshRetirementState_log refreshRetirementState_commitIndex)

variable {Node TxId : Type} [DecidableEq Node] [DecidableEq TxId] [Bootstrap Node]

/-- `after` keeps the committed prefix of `before` and commits no less. -/
def Extends (before after : NodeState Node TxId) : Prop :=
  before.commitIndex <= after.commitIndex
  /\ after.log.take before.commitIndex = before.log.take before.commitIndex

theorem Extends.refl (state : NodeState Node TxId) : Extends state state := ⟨le_rfl, rfl⟩

theorem Extends.trans {first second third : NodeState Node TxId}
    (left : Extends first second) (right : Extends second third)
    : Extends first third := by
  refine ⟨left.1.trans right.1, ?_⟩
  have taken := congrArg (List.take first.commitIndex) right.2
  simp only [List.take_take, Nat.min_eq_left left.1] at taken
  exact taken.trans left.2

theorem Extends.of_log {before after : NodeState Node TxId}
    (logEq : after.log = before.log) (commitEq : after.commitIndex = before.commitIndex)
    : Extends before after := by
  refine ⟨commitEq.ge, ?_⟩
  rw [logEq]

theorem Extends.committedLog {before after : NodeState Node TxId}
    (extended : Extends before after)
    : before.committedLog <+: after.committedLog := by
  unfold NodeState.committedLog
  rw [← extended.2]
  exact List.take_prefix_take_left extended.1

/-- Replacing the log above `count` keeps the prefix at and below the commit index. -/
theorem Extends.keep {state : NodeState Node TxId} {count : Nat}
    (bounded : state.commitIndex <= state.log.length)
    (within : state.commitIndex <= count) {suffix : List (Entry Node TxId)}
    {commitIndex : Nat} (grows : state.commitIndex <= commitIndex)
    : Extends state
        { state with log := state.log.take count ++ suffix, commitIndex } := by
  refine ⟨grows, ?_⟩
  simp only
  rw [List.take_append_of_le_length (by simp; omega), List.take_take, Nat.min_eq_left within]

theorem Extends.withSent {state : NodeState Node TxId} {sentIndex : Node -> Nat}
    : Extends state { state with sentIndex } :=
  Extends.of_log rfl rfl

theorem Extends.append {state : NodeState Node TxId} (frontier : CommitFrontier state)
    (entry : Entry Node TxId)
    : Extends state { state with log := state.log ++ [entry] } := by
  refine ⟨le_rfl, ?_⟩
  simp only
  rw [List.take_append_of_le_length frontier.1]

theorem Extends.appendEntry {state : NodeState Node TxId}
    (frontier : CommitFrontier state) (self : Node) (content : EntryContent Node TxId)
    : Extends state (appendEntry state self content) := by
  unfold Model.Local.appendEntry
  exact (Extends.append frontier _).trans
    (Extends.of_log (refreshRetirementState_log _ _) (refreshRetirementState_commitIndex _ _))

section AppendEntries

variable {self : Node} {state : NodeState Node TxId}
  {request : AppendEntriesRequest Node TxId}
  {result : NodeState Node TxId × AppendEntriesResponse}

theorem Extends.alreadyDone (done : appendEntriesAlreadyDone? state request = some result)
    : Extends state result.1 := by
  unfold appendEntriesAlreadyDone? at done
  split at done
  · obtain rfl := (Option.some.inj done).symm
    exact ⟨le_max_left _ _, rfl⟩
  · simp at done

theorem Extends.noConflict (bounded : state.commitIndex <= state.log.length)
    (within : state.commitIndex <= request.prevLogIndex)
    (appended : noConflictAppendEntriesRequest? self state request = some result)
    : Extends state result.1 := by
  unfold noConflictAppendEntriesRequest? at appended
  split at appended
  · obtain rfl := (Option.some.inj appended).symm
    have kept := Extends.keep (state := state) bounded within (suffix := request.entries)
      (commitIndex := committedFromLeader state request
        (state.log.take request.prevLogIndex ++ request.entries)) (le_max_left _ _)
    exact kept.trans (Extends.of_log (by simp) rfl)
  · simp at appended

theorem Extends.accept (bounded : state.commitIndex <= state.log.length)
    (accepted : acceptAppendEntriesRequest? self state request = some result)
    : Extends state result.1 := by
  unfold acceptAppendEntriesRequest? at accepted
  split at accepted
  · rename_i guard
    have within : state.commitIndex <= request.prevLogIndex := guard.2.2.2
    split at accepted
    · rename_i done
      obtain rfl := Option.some.inj accepted
      exact Extends.alreadyDone done
    · split at accepted
      · rename_i appended
        obtain rfl := Option.some.inj accepted
        exact Extends.noConflict bounded within appended
      · split at accepted
        · simp at accepted
        · rename_i truncated conflicted
          unfold conflictAppendEntriesRequest? at conflicted
          split at conflicted
          · obtain rfl := (Option.some.inj conflicted).symm
            have truncatedExtends : Extends state { state with
                log := state.log.take request.prevLogIndex, isNewFollower := false } := by
              have kept := Extends.keep (state := state) bounded within (suffix := [])
                (commitIndex := state.commitIndex) le_rfl
              exact kept.trans (Extends.of_log (by simp) rfl)
            split at accepted
            · rename_i done
              obtain rfl := Option.some.inj accepted
              exact truncatedExtends.trans (Extends.alreadyDone done)
            · exact truncatedExtends.trans (Extends.noConflict
                (by simp only [List.length_take]; omega) within accepted)
          · simp at conflicted
  · simp at accepted

theorem Extends.handleAppendEntriesRequest
    (bounded : state.commitIndex <= state.log.length)
    (handled : handleAppendEntriesRequest? self state request = some result)
    : Extends state result.1 := by
  unfold handleAppendEntriesRequest? at handled
  have stepped : Extends state (if request.term = state.currentTerm /\
      (state.role = .candidate \/ state.role = .preVoteCandidate) then
        { state with role := .follower, isNewFollower := true } else state) := by
    split
    · exact Extends.of_log rfl rfl
    · exact Extends.refl _
  have currentBounded : (if request.term = state.currentTerm /\
      (state.role = .candidate \/ state.role = .preVoteCandidate) then
        { state with role := .follower, isNewFollower := true } else state).commitIndex
        <= (if request.term = state.currentTerm /\
      (state.role = .candidate \/ state.role = .preVoteCandidate) then
        { state with role := .follower, isNewFollower := true } else state).log.length := by
    split <;> exact bounded
  generalize (if request.term = state.currentTerm /\
      (state.role = .candidate \/ state.role = .preVoteCandidate) then
        { state with role := .follower, isNewFollower := true } else state) = current
    at handled stepped currentBounded
  dsimp only at handled
  split at handled
  · rename_i rejected
    unfold rejectAppendEntriesRequest? at rejected
    split at rejected
    · obtain rfl := Option.some.inj handled
      obtain rfl := (Option.some.inj rejected).symm
      exact stepped
    · simp at rejected
  · exact stepped.trans (Extends.accept currentBounded handled)

end AppendEntries

theorem Extends.promoted {state : NodeState Node TxId} (self : Node)
    (frontier : CommitFrontier state) {role : Role} {sentIndex matchIndex : Node -> Nat}
    : Extends state
        (refreshRetirementState self
          {
            state with
              log := state.log.take (maxCommittableIndex state.log)
              role
              sentIndex
              matchIndex
          }) := by
  have kept := Extends.keep (state := state) frontier.1 frontier.truncateToSignature (suffix := [])
    (commitIndex := state.commitIndex) le_rfl
  exact kept.trans (Extends.of_log (by simp) (by simp))

theorem Extends.advanced {state : NodeState Node TxId} (self : Node)
    (advances : state.commitIndex < highestCommittableIndex state self)
    : Extends state (demoteRetiredCommitted (Model.Local.advanceCommit state self)) := by
  have advanced : Extends state (Model.Local.advanceCommit state self) := by
    unfold Model.Local.advanceCommit
    exact ⟨by simp; omega, by simp⟩
  unfold demoteRetiredCommitted
  split
  · exact advanced.trans (Extends.of_log rfl rfl)
  · exact advanced

theorem Extends.observeTerm (state : NodeState Node TxId) (message : Message Node TxId)
    : Extends state (Model.Local.observeTerm state message) :=
  Extends.of_log (Refinement.observeTerm_log _ _) (Refinement.observeTerm_commitIndex _ _)

/-- Every local step extends the acting node's committed log. -/
theorem extends_step {self : Node} {state : NodeState Node TxId}
    {event : Event Node TxId} {execute : NodeEffect Node TxId (NodeState Node TxId)}
    (frontier : CommitFrontier state)
    (stepped
      : Model.Local.step (Capabilities.record self) self state event = some execute)
    : Extends state (execute.run {}).1 := by
  cases event with
  | internal input =>
      simp only [Model.Local.step] at stepped
      cases input <;>
        simp only [Model.Local.act, guard, bind, Option.bind] at stepped <;>
        split at stepped <;> (try simp at stepped) <;>
        rename_i condition <;>
        have holds := Refinement.guard_holds condition <;>
        subst stepped <;>
        simp only [run_pure, run_send]
      all_goals first
        | exact Extends.refl _
        | exact Extends.of_log rfl rfl
        | exact Extends.appendEntry frontier _ _
        | exact (Extends.appendEntry frontier _ _).trans Extends.withSent
        | exact Extends.promoted _ frontier
        | exact ⟨by simp [holds.2.2.2.2.1], by simp [holds.2.2.2.2.1]⟩
        | exact Extends.advanced _ holds.2.1
  | receive source message =>
      simp only [Model.Local.step] at stepped
      have observed := Extends.observeTerm state message
      have bounded : (Model.Local.observeTerm state message).commitIndex
          <= (Model.Local.observeTerm state message).log.length := by
        rw [Refinement.observeTerm_log, Refinement.observeTerm_commitIndex]
        exact frontier.1
      cases message with
      | appendEntriesRequest request =>
          simp only [Model.Local.receive] at stepped
          obtain ⟨⟨next, response⟩, handled, done⟩ := Option.bind_eq_some_iff.mp stepped
          obtain rfl := (Option.some.inj done).symm
          exact (observed.trans (Extends.handleAppendEntriesRequest bounded handled)).trans
            (Extends.of_log (refreshRetirementState_log _ _)
              (refreshRetirementState_commitIndex _ _))
      | appendEntriesResponse response =>
          simp only [Model.Local.receive] at stepped
          obtain rfl := (Option.some.inj stepped).symm
          have kept := Refinement.handleAppendEntriesResponse_log
            (Model.Local.observeTerm state (.appendEntriesResponse response)) source response
          exact observed.trans (Extends.of_log kept.1 kept.2)
      | requestVoteRequest request =>
          simp only [Model.Local.receive] at stepped
          obtain rfl := (Option.some.inj stepped).symm
          have kept := Refinement.handleRequestVoteRequest_log
            (Model.Local.observeTerm state (.requestVoteRequest request)) source request
          exact observed.trans (Extends.of_log kept.1 kept.2)
      | requestVoteResponse response =>
          simp only [Model.Local.receive] at stepped
          obtain rfl := (Option.some.inj stepped).symm
          have kept := Refinement.handleRequestVoteResponse_log
            (Model.Local.observeTerm state (.requestVoteResponse response)) source response
          exact observed.trans (Extends.of_log kept.1 kept.2)
      | requestPreVote request =>
          simp only [Model.Local.receive] at stepped
          obtain rfl := (Option.some.inj stepped).symm
          exact observed
      | requestPreVoteResponse response =>
          simp only [Model.Local.receive] at stepped
          obtain rfl := (Option.some.inj stepped).symm
          have kept := Refinement.handleRequestPreVoteResponse_log
            (Model.Local.observeTerm state (.requestPreVoteResponse response)) source response
          exact observed.trans (Extends.of_log kept.1 kept.2)
      | proposeVoteRequest term =>
          simp only [Model.Local.receive] at stepped
          obtain rfl := (Option.some.inj stepped).symm
          have kept := Refinement.handleProposeVoteRequest_log
            (Model.Local.observeTerm state (.proposeVoteRequest term)) self term
          exact observed.trans (Extends.of_log kept.1 kept.2)

/-- A step keeps every other node's state and extends the actor's committed log. -/
theorem committed_log_append_only : Properties.CommittedLogAppendOnly := by
  intro Node TxId _ _ _ nodes trace step before after node beforeState afterState
    ⟨valid, first, second, beforeMember, afterMember⟩
  obtain ⟨action, stepped⟩ := valid.2 step before after first second
  have reachable := valid.reachable (List.mem_of_getElem? first)
  have distinct := keys_nodup reachable
  have frontiers := commitFrontier_invariant.reachable reachable
  have extended : forall {actor : Node} {old : NodeState Node TxId}
      {event : Event Node TxId} {execute : NodeEffect Node TxId (NodeState Node TxId)},
      nodeState before actor = some old ->
      Model.Local.step (Capabilities.record actor) actor old event = some execute ->
      (node, afterState) ∈ replaceNode before.nodes actor (execute.run {}).1 ->
      beforeState.committedLog <+: afterState.committedLog := by
    intro actor old event execute found acted member
    rcases mem_replaceNode member with ⟨rfl, rfl⟩ | ⟨_, listed⟩
    · have same : beforeState = old := Option.some.inj
        ((nodeState_of_mem distinct beforeMember).symm.trans found)
      subst same
      exact (extends_step (frontiers _ _ beforeMember) acted).committedLog
    · have same : afterState = beforeState := Option.some.inj
        ((nodeState_of_mem distinct listed).symm.trans (nodeState_of_mem distinct beforeMember))
      subst same
      exact List.prefix_refl _
  cases action with
  | «local» actor input =>
      obtain ⟨old, execute, found, acted, rfl⟩ := step_local stepped
      exact extended (event := .internal input) found acted afterMember
  | deliver envelope =>
      obtain ⟨_, old, execute, found, received, rfl⟩ := step_deliver stepped
      exact extended (event := .receive envelope.source envelope.payload) found received
        afterMember

end CCFRaft.Proofs.Direct
