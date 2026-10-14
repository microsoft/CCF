-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFRaft.Proofs.Direct.CommitFrontier
import CCFRaft.Properties

set_option linter.unusedSectionVars false

/-!
# Append-only committed logs

A local step never lowers a node's commit index and never rewrites its log
below that index. Truncation happens only above the commit index: an accepted
AppendEntries request starts at or after it, and a new leader keeps its log up
to its latest signature, which the commit frontier does not pass.
-/

namespace CCFRaft.Proofs.Direct

open CCFRaft.Proofs.Config

open Shared Shared.MultiNodeTransitionSystem Concrete
open Model.Local
open Ledger (refreshRetirementState_log refreshRetirementState_commitIndex)

variable {Node TxId : Type} [DecidableEq Node] [DecidableEq TxId] [InitialConfig Node]

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

theorem Extends.leaderAppendState {state : NodeState Node TxId}
    (frontier : CommitFrontier state) (self : Node) (content : EntryContent Node TxId)
    : Extends state
        (refreshRetirementState (inferInstance) self
          { state with log := state.log ++ [{ term := state.currentTerm, content }] }) :=
  (Extends.append frontier _).trans
    (Extends.of_log (refreshRetirementState_log _ _)
      (refreshRetirementState_commitIndex _ _))

section AppendEntries

variable {self : Node} {state : NodeState Node TxId}
  {request : AppendEntriesRequest Node TxId}

theorem Extends.fromLeader (bounded : state.commitIndex <= state.log.length)
    : Extends state (appendEntriesFromLeader (inferInstance) self state request).1 := by
  have kept := Extends.keep (state := state) (count := state.log.length) bounded bounded
    (suffix := request.entries.drop (state.log.length - request.prevLogIndex))
    (commitIndex := committedFromLeader state request
      (state.log ++ request.entries.drop (state.log.length - request.prevLogIndex)))
    (le_max_left _ _)
  unfold appendEntriesFromLeader
  exact kept.trans (Extends.of_log (by simp) (by simp))

theorem Extends.handleAppendEntriesRequest
    (bounded : state.commitIndex <= state.log.length)
    : Extends state
        (Model.Local.handleAppendEntriesRequest (inferInstance) self state
          request).1 := by
  unfold Model.Local.handleAppendEntriesRequest
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
    at stepped currentBounded
  dsimp only
  split
  · exact stepped
  split
  · exact stepped.trans (Extends.of_log rfl rfl)
  rename_i _ notBefore
  have within : current.commitIndex <= request.prevLogIndex := by
    simp only [not_or] at notBefore
    omega
  split
  · have kept := Extends.keep (state := current) currentBounded within (suffix := [])
      (commitIndex := current.commitIndex) le_rfl
    have truncated : Extends current { current with
        leaderKnown := true, log := current.log.take request.prevLogIndex,
        isNewFollower := false } := kept.trans (Extends.of_log (by simp) rfl)
    exact (stepped.trans truncated).trans
      (Extends.fromLeader (by simp only [List.length_take]; omega))
  · exact (stepped.trans (Extends.of_log rfl rfl)).trans
      (Extends.fromLeader (self := self) currentBounded)

end AppendEntries

theorem Extends.promotedLog {state : NodeState Node TxId}
    (frontier : CommitFrontier state)
    : Extends state
        {
          state with
            log :=
              if state.commitIndex > 0 then
                state.log.take (lastCommittableIndex state)
              else
                state.log
        } := by
  split
  · have kept := Extends.keep (state := state) (count := lastCommittableIndex state) frontier.1
      (by unfold lastCommittableIndex; omega) (suffix := []) (commitIndex := state.commitIndex)
      le_rfl
    exact kept.trans (Extends.of_log (by simp) rfl)
  · exact Extends.of_log rfl rfl

theorem Extends.advanced {state : NodeState Node TxId} (self : Node)
    (advances : state.commitIndex < highestCommittableIndex (inferInstance) state self)
    : Extends state (Model.Local.advanceCommit (inferInstance) state self) := by
  have advanced : Extends state
      (refreshRetirementState (inferInstance) self
        { state with commitIndex := highestCommittableIndex (inferInstance) state self }) :=
    ⟨by simp; omega, by simp⟩
  unfold Model.Local.advanceCommit
  dsimp only
  split
  · exact advanced.trans (Extends.of_log rfl rfl)
  · exact advanced

theorem Extends.observeTerm (state : NodeState Node TxId) (message : Message Node TxId)
    : Extends state (Model.Local.observeTerm state message) :=
  Extends.of_log (Concrete.observeTerm_log _ _) (Concrete.observeTerm_commitIndex _ _)

/-- Every local step extends the acting node's committed log. -/
theorem extends_step {self : Node} {state after : NodeState Node TxId}
    {event : Event Node TxId} {outputs : Outputs Node (Message Node TxId) Notification}
    (frontier : CommitFrontier state)
    (stepped
      : (Model.Local.step (inferInstance) (Capabilities.record self) self state event).run
          {}
        = some (after, outputs))
    : Extends state after := by
  cases event with
  | internal input =>
      cases input <;>
        simp only [Model.Local.step, Model.Local.act, Model.Local.leaderAppend] at stepped <;>
        simp [Capabilities.record] at stepped
      all_goals
        casesm* _ ∧ _
        subst after
      case initializeConfiguration =>
        exact ⟨le_rfl, by simp [*]⟩
      case changeConfiguration =>
        exact (Extends.leaderAppendState frontier self _).trans (Extends.of_log rfl rfl)
      case becomeLeader =>
        exact (Extends.promotedLog frontier).trans (Extends.of_log (by simp) (by simp))
      all_goals first
        | exact Extends.refl _
        | exact Extends.of_log rfl rfl
        | exact Extends.leaderAppendState frontier _ _
        | exact Extends.advanced _ (by assumption)
  | receive source message =>
      have observed := Extends.observeTerm state message
      have bounded : (Model.Local.observeTerm state message).commitIndex
          <= (Model.Local.observeTerm state message).log.length := by
        rw [Concrete.observeTerm_log, Concrete.observeTerm_commitIndex]
        exact frontier.1
      cases message <;>
        simp only [Model.Local.step, Model.Local.receive] at stepped
      case appendEntriesRequest request =>
        have handled := (observed.trans (Extends.handleAppendEntriesRequest (self := self)
          (request := request) bounded)).trans
          (Extends.of_log (refreshRetirementState_log _ _)
            (refreshRetirementState_commitIndex _ _) (after := refreshRetirementState
              (inferInstance) self _))
        split at stepped <;> simp [Capabilities.record] at stepped <;>
          obtain ⟨rfl, -⟩ := stepped <;> exact handled
      all_goals
        (try split at stepped) <;> simp [Capabilities.record] at stepped <;>
          (try casesm* _ ∧ _) <;> subst after
      all_goals first
        | exact observed
        | exact observed.trans (Extends.of_log rfl rfl)
        | exact observed.trans (Extends.of_log (Concrete.handleAppendEntriesResponse_log _ _ _).1
            (Concrete.handleAppendEntriesResponse_log _ _ _).2)
        | exact observed.trans (Extends.of_log (Concrete.handleRequestVoteRequest_log _ _ _).1
            (Concrete.handleRequestVoteRequest_log _ _ _).2)
        | exact observed.trans (Extends.of_log (Concrete.handleRequestVoteResponse_log _ _ _).1
            (Concrete.handleRequestVoteResponse_log _ _ _).2)
        | exact observed.trans (Extends.of_log (Concrete.handleRequestPreVoteResponse_log _ _ _).1
            (Concrete.handleRequestPreVoteResponse_log _ _ _).2)

/-- A step keeps every other node's state and extends the actor's committed log. -/
theorem committed_log_step {nodes : List Node} {before after : Model.State Node TxId}
    {action : Model.Action Node TxId}
    (reachable
      : (Model.transitionSystem (inferInstance) (TxId := TxId) nodes).Reachable before)
    (stepped
      : (Model.transitionSystem (inferInstance) nodes).step before action = some after)
    {node : Node} {beforeState afterState : NodeState Node TxId}
    (beforeMember : (node, beforeState) ∈ before.nodes)
    (afterMember : (node, afterState) ∈ after.nodes)
    : beforeState.committedLog <+: afterState.committedLog := by
  have distinct := keys_nodup reachable
  have frontiers := commitFrontier_invariant.reachable reachable
  have extended : forall {actor : Node} {old : NodeState Node TxId}
      {event : Event Node TxId} {new : NodeState Node TxId} {outputs},
      nodeState before actor = some old
      -> (Model.Local.step (inferInstance) (Capabilities.record actor) actor old event).run {}
        = some (new, outputs)
      -> (node, afterState) ∈ replaceNode before.nodes actor new
      -> beforeState.committedLog <+: afterState.committedLog := by
    intro actor old event new outputs found acted member
    rcases mem_replaceNode member with ⟨rfl, rfl⟩ | ⟨_, listed⟩
    · have same : beforeState = old :=
        Option.some.inj ((nodeState_of_mem distinct beforeMember).symm.trans found)
      subst same
      exact (extends_step (frontiers _ _ beforeMember) acted).committedLog
    · have same : afterState = beforeState :=
        Option.some.inj
          ((nodeState_of_mem distinct listed).symm.trans (nodeState_of_mem distinct beforeMember))
      subst same
      exact List.prefix_refl _
  cases action with
  | «local» actor input =>
      obtain ⟨old, new, outputs, found, acted, rfl⟩ := step_local stepped
      exact extended (event := .internal input) found acted afterMember
  | deliver envelope =>
      obtain ⟨_, old, new, outputs, found, received, rfl⟩ := step_deliver stepped
      exact extended (event := .receive envelope.source envelope.payload) found received afterMember

/-- A node present before a step is present after it. -/
theorem present_after_step {nodes : List Node} {before after : Model.State Node TxId}
    {action : Model.Action Node TxId}
    (stepped
      : (Model.transitionSystem (inferInstance) nodes).step before action = some after)
    {node : Node} {beforeState : NodeState Node TxId}
    (member : (node, beforeState) ∈ before.nodes)
    : exists afterState, (node, afterState) ∈ after.nodes := by
  have present : forall {actor : Node} {value : NodeState Node TxId},
      exists afterState, (node, afterState) ∈ replaceNode before.nodes actor value := by
    intro actor value
    by_cases same : node = actor
    · subst same
      exact ⟨value, List.mem_map.mpr ⟨_, member, by simp⟩⟩
    · exact ⟨beforeState, List.mem_map.mpr ⟨_, member, by simp [same]⟩⟩
  cases action with
  | «local» actor input =>
      obtain ⟨_, _, _, _, _, rfl⟩ := step_local stepped
      exact present
  | deliver envelope =>
      obtain ⟨_, _, _, _, _, _, rfl⟩ := step_deliver stepped
      exact present

/-- A node's committed log at one state of a trace is a prefix of the same node's
committed log at every later state. -/
theorem committed_log_later {nodes : List Node}
    {trace : Properties.GlobalTrace Node TxId}
    (valid : trace.Valid (Model.transitionSystem (inferInstance) nodes)) {index : Nat}
    {first : Model.State Node TxId} (atFirst : trace.states[index]? = some first)
    {node : Node} {firstState : NodeState Node TxId}
    (member : (node, firstState) ∈ first.nodes)
    : forall offset later,
        trace.states[index + offset]? = some later
        -> exists laterState,
            (node, laterState) ∈ later.nodes
            /\ firstState.committedLog <+: laterState.committedLog := by
  intro offset
  induction offset with
  | zero =>
      intro later atLater
      obtain rfl : first = later := Option.some.inj (atFirst.symm.trans atLater)
      exact ⟨firstState, member, List.prefix_refl _⟩
  | succ offset ih =>
      intro later atLater
      have bound : index + offset < trace.states.length := by
        obtain ⟨bound, _⟩ := List.getElem?_eq_some_iff.mp atLater
        omega
      have atMiddle := List.getElem?_eq_getElem bound
      obtain ⟨middleState, middleMember, prefixed⟩ := ih _ atMiddle
      obtain ⟨action, stepped⟩ := valid.2 (index + offset) _ later atMiddle
        (by simpa [Nat.add_assoc] using atLater)
      obtain ⟨laterState, laterMember⟩ := present_after_step stepped middleMember
      refine ⟨laterState, laterMember, prefixed.trans ?_⟩
      exact committed_log_step (valid.reachable (List.getElem_mem bound)) stepped
        middleMember laterMember

end CCFRaft.Proofs.Direct
