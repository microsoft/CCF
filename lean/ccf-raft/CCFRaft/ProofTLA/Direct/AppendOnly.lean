module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import CCFRaft.ProofTLA.Direct.CommitFrontier
public import CCF.Execution

@[expose] public section

set_option linter.unusedSectionVars false

/-!
# Append-only committed logs

A local step never lowers a node's commit index and keeps its committed log as a
prefix of the new log. Truncation happens only at or above the commit index: an
accepted AppendEntries request starts at or after it, and a new leader keeps its
log up to the larger of its commit index and latest signature. This needs no
invariant of the node state, so the one-step claim holds from any state whose
node identifiers are distinct.
-/

namespace CCFRaft.ProofTLA.Direct

open CCFRaft.ProofTLA.Config

open CCF CCF.MultiNodeTransitionSystem Concrete
open Model.Node

variable [Model.ModelConfig]

/-- `after` commits no less than `before` and its log extends the committed log
of `before`. No relation between `before`'s commit index and log is assumed. -/
def Extends (before after : NodeState) : Prop :=
  before.commitIndex <= after.commitIndex /\ before.committedLog <+: after.log

theorem Extends.committedLog {before after : NodeState} (extended : Extends before after)
    : before.committedLog <+: after.committedLog :=
  List.prefix_take_iff.mpr ⟨extended.2, (List.length_take_le _ _).trans extended.1⟩

theorem Extends.refl (state : NodeState) : Extends state state :=
  ⟨le_rfl, List.take_prefix _ _⟩

theorem Extends.trans {first second third : NodeState}
    (left : Extends first second) (right : Extends second third)
    : Extends first third :=
  ⟨left.1.trans right.1, left.committedLog.trans right.2⟩

/-- Keeping the log below `count`, at or above the commit index, and committing no
less extends the committed log. -/
theorem Extends.of_prefix {before after : NodeState} {count : Nat}
    (within : before.commitIndex <= count) (kept : before.log.take count <+: after.log)
    (grows : before.commitIndex <= after.commitIndex)
    : Extends before after := by
  refine ⟨grows, List.IsPrefix.trans ?_ kept⟩
  unfold NodeState.committedLog
  exact List.take_prefix_take_left within

theorem Extends.of_log {before after : NodeState}
    (logEq : after.log = before.log) (commitEq : after.commitIndex = before.commitIndex)
    : Extends before after :=
  ⟨commitEq.ge, logEq ▸ List.take_prefix _ _⟩

theorem Extends.append {state : NodeState} (entry : Entry)
    : Extends state { state with log := state.log ++ [entry] } :=
  ⟨le_rfl, (List.take_prefix _ _).trans (List.prefix_append _ _)⟩

section AppendEntries

variable {self : NodeID} {state : NodeState}
  {request : AppendEntriesRequest}

theorem Extends.fromLeader
    : Extends state (handleAppendEntiresFromPrimary self state request).1 := by
  obtain ⟨retired, role, known, eq, _⟩ :=
    Ledger.handleAppendEntiresFromPrimary_eq self state request
  rw [eq]
  exact ⟨le_max_left _ _, (List.take_prefix _ _).trans (List.prefix_append _ _)⟩

theorem Extends.handleAppendEntriesRequest (caps : Caps) (source : NodeID)
    : Keeps (Extends state)
        (Model.Node.handleAppendEntriesRequest caps self source state request) := by
  unfold Model.Node.handleAppendEntriesRequest
  have stepped : Extends state (if request.term = state.currentTerm /\
      (state.role = .candidate \/ state.role = .preVoteCandidate) then
        { state with role := .follower, isNewFollower := true } else state) := by
    split
    · exact Extends.of_log rfl rfl
    · exact Extends.refl _
  generalize (if request.term = state.currentTerm /\
      (state.role = .candidate \/ state.role = .preVoteCandidate) then
        { state with role := .follower, isNewFollower := true } else state) = current
    at stepped
  refine Keeps.ite' (fun _ => by
    dsimp only
    split <;> exact Keeps.seq' fun _ => Keeps.pure' stepped) fun _ => ?_
  dsimp only
  refine Keeps.ite' (fun _ => Keeps.pure' (stepped.trans (Extends.of_log rfl rfl)))
    fun notBefore => ?_
  have within : current.commitIndex <= request.prevLogIndex := by
    simp only [not_or] at notBefore
    omega
  generalize found : firstTermConflictIndex { current with primaryKnown := true } request
    = conflict
  refine Keeps.seq' fun _ => Keeps.pure' ?_
  cases conflict with
  | none =>
      exact (stepped.trans (Extends.of_log rfl rfl)).trans
        (Extends.fromLeader (self := self) (state := { current with primaryKnown := true }))
  | some index =>
      have := Ledger.firstTermConflictIndex_gt found
      have truncated : Extends current { current with
          primaryKnown := true, log := current.log.take (index - 1),
          isNewFollower := false } :=
        Extends.of_prefix (count := index - 1) (by omega) (List.prefix_refl _) le_rfl
      exact (stepped.trans truncated).trans Extends.fromLeader

end AppendEntries

section Handlers

variable (caps : Caps) (self : NodeID)

theorem Extends.advanced (state : NodeState)
    : Keeps (Extends state) (Model.Node.advanceCommit caps state self) := by
  unfold Model.Node.advanceCommit
  refine Keeps.ite' (fun _ => Keeps.pure' (Extends.refl _)) fun ahead => ?_
  have advanced : Extends state
      (state.recordCommit self (highestCommittableIndex state self)) := by
    obtain ⟨retired, role, known, eq, _⟩ :=
      Ledger.recordCommit_eq self state (highestCommittableIndex state self)
    rw [eq]
    exact ⟨by dsimp only; omega, List.take_prefix _ _⟩
  dsimp only
  exact Keeps.ite'
    (fun _ => Keeps.ite'
      (fun _ => Keeps.seq' fun _ => Keeps.pure' (advanced.trans (Extends.of_log rfl rfl)))
      fun _ => Keeps.pure' (advanced.trans (Extends.of_log rfl rfl)))
    fun _ => Keeps.pure' advanced

theorem Extends.appendEntry (state : NodeState) (content : EntryContent)
    : Keeps (Extends state) (Model.Node.appendEntry caps self state content) := by
  unfold Model.Node.appendEntry
  simp only [pure_bind]
  repeat'
    first
    | exact Keeps.pure' ((Extends.append _).trans (Extends.of_log rfl rfl))
    | refine Keeps.ite' (fun _ => ?_) fun _ => ?_
    | refine Keeps.seq' fun _ => ?_
    | split

theorem Extends.becomePrimary (state : NodeState)
    : Keeps (Extends state) (Model.Node.becomePrimary caps self state) := by
  unfold Model.Node.becomePrimary Model.Node.primaryState
  have promoted : Extends state
      {
        state with
          role := .primary
          log :=
            if state.commitIndex > 0 then state.log.take (lastCommittableIndex state)
            else state.log
          primaryKnown := true
          sentIndex := fun _ =>
            (if state.commitIndex > 0 then state.log.take (lastCommittableIndex state)
              else state.log).length
          matchIndex := fun _ => 0
      } := by
    split
    · exact Extends.of_prefix (by unfold lastCommittableIndex; omega) (List.prefix_refl _)
        le_rfl
    · exact Extends.of_log rfl rfl
  exact Keeps.bind' (Extends.advanced caps self _) fun _ kept =>
    Keeps.seq' fun _ => Keeps.pure' (promoted.trans kept)

theorem Extends.electIfQuorum (state : NodeState)
    : Keeps (Extends state) (Model.Node.electIfQuorum caps self state) := by
  unfold Model.Node.electIfQuorum
  exact Keeps.ite' (fun _ => Extends.becomePrimary caps self state)
    fun _ => Keeps.pure' (Extends.refl _)

theorem Extends.becomeCandidate (state : NodeState)
    : Keeps (Extends state) (Model.Node.becomeCandidate caps state self) := by
  unfold Model.Node.becomeCandidate
  exact Keeps.bind' (Extends.electIfQuorum caps self _) fun _ kept =>
    Keeps.seq' fun _ => Keeps.pure' ((Extends.of_log rfl rfl).trans kept)

theorem Extends.becomePreVoteCandidate (state : NodeState)
    : Keeps (Extends state) (Model.Node.becomePreVoteCandidate caps state self) := by
  unfold Model.Node.becomePreVoteCandidate
  refine Keeps.ite' (fun _ => ?_) fun _ => Keeps.seq' fun _ =>
    Keeps.pure' (Extends.of_log rfl rfl)
  exact (Extends.becomeCandidate caps self _).mono fun _ kept =>
    (Extends.of_log rfl rfl).trans kept

theorem Extends.act (state : NodeState) (input : Input)
    : Keeps (Extends state) (Model.Node.act caps self state input) := by
  cases input with
  | append entries =>
      unfold Model.Node.act Model.Node.appendBatch
      refine Keeps.seq' fun _ => ?_
      exact Keeps.bind'
        (Keeps.foldlM' (P := Extends state) (fun current content kept =>
          (Extends.appendEntry caps self current content).mono fun _ next =>
            kept.trans next) entries state (Extends.refl _))
        fun current kept => (Extends.advanced caps self current).mono fun _ next =>
          kept.trans next
  | sendEntries destination endIndex =>
      unfold Model.Node.act Model.Node.sendEntries
      exact Keeps.seq' fun _ => Keeps.seq' fun _ => Keeps.pure' (Extends.of_log rfl rfl)
  | timeout kind =>
      cases kind with
      | election =>
          unfold Model.Node.act Model.Node.startElection
          exact Keeps.seq' fun _ => Extends.becomePreVoteCandidate caps self state
      | checkQuorum =>
          unfold Model.Node.act Model.Node.checkQuorum
          exact Keeps.seq' fun _ => Keeps.pure' (Extends.of_log rfl rfl)
  | nominateSuccessor =>
      unfold Model.Node.act
      exact Keeps.seq' fun _ => Keeps.seq' fun _ =>
        Keeps.pure' (Extends.of_log rfl rfl)

theorem Extends.receive (state : NodeState) (source : NodeID) (message : Message)
    : Keeps (Extends state) (Model.Node.receive caps self source state message) := by
  have observedExtends : Extends state (observeTerm state message) :=
    Extends.of_log (Concrete.observeTerm_log _ _) (Concrete.observeTerm_commitIndex _ _)
  unfold Model.Node.receive
  dsimp only
  generalize observeTerm state message = current at observedExtends ⊢
  refine Keeps.mono (P := Extends current) ?_ fun _ next => observedExtends.trans next
  cases message with
  | appendEntriesRequest request =>
      exact Extends.handleAppendEntriesRequest caps source
  | appendEntriesResponse response =>
      unfold Model.Node.handleAppendEntriesResponse
      refine Keeps.ite' (fun _ => Keeps.pure' (Extends.refl _)) fun _ => ?_
      refine Keeps.ite' (fun _ => ?_) fun _ => Keeps.pure' (Extends.of_log rfl rfl)
      refine Keeps.ite' (fun _ => ?_) fun _ => Keeps.pure' (Extends.refl _)
      exact (Extends.advanced caps self _).mono fun _ next =>
        (Extends.of_log rfl rfl).trans next
  | requestVoteRequest request =>
      unfold Model.Node.handleRequestVoteRequest
      exact Keeps.seq' fun _ => Keeps.pure' (by split <;> exact Extends.of_log rfl rfl)
  | requestVoteResponse response =>
      unfold Model.Node.handleRequestVoteResponse
      refine Keeps.ite' (fun _ => ?_) fun _ => Keeps.pure' (Extends.refl _)
      exact (Extends.electIfQuorum caps self _).mono fun _ next =>
        (Extends.of_log rfl rfl).trans next
  | requestPreVote request =>
      unfold Model.Node.handleRequestPreVote
      exact Keeps.seq' fun _ => Keeps.pure' (Extends.refl _)
  | requestPreVoteResponse response =>
      unfold Model.Node.handleRequestPreVoteResponse
      refine Keeps.ite' (fun _ => ?_) fun _ => Keeps.pure' (Extends.refl _)
      dsimp only
      refine Keeps.ite' (fun _ => ?_) fun _ => Keeps.pure' (Extends.of_log rfl rfl)
      exact (Extends.becomeCandidate caps self _).mono fun _ next =>
        (Extends.of_log rfl rfl).trans next
  | proposeVoteRequest term =>
      unfold Model.Node.handleProposeVoteRequest
      exact Keeps.ite' (fun _ => Extends.becomeCandidate caps self current)
        fun _ => Keeps.pure' (Extends.refl _)

end Handlers

/-- From any state with distinct node identifiers, a step keeps every other node's
state and extends the actor's committed log. -/
theorem committed_log_step {nodes : List NodeID} {before after : Model.State}
    {action : Model.Action}
    (distinct : (before.nodes.map Prod.fst).Nodup)
    (stepped
      : (Model.transitionSystem (inferInstance) nodes).step before action = some after)
    {node : NodeID} {beforeState afterState : NodeState}
    (beforeMember : (node, beforeState) ∈ before.nodes)
    (afterMember : (node, afterState) ∈ after.nodes)
    : beforeState.committedLog <+: afterState.committedLog := by
  have extended : forall {actor : NodeID} {old : NodeState}
      {new : NodeState},
      nodeState before actor = some old
      -> Extends old new
      -> (node, afterState) ∈ replaceNode before.nodes actor new
      -> beforeState.committedLog <+: afterState.committedLog := by
    intro actor old new found grown member
    rcases mem_replaceNode member with ⟨rfl, rfl⟩ | ⟨_, listed⟩
    · have same : beforeState = old :=
        Option.some.inj ((nodeState_of_mem distinct beforeMember).symm.trans found)
      subst same
      exact grown.committedLog
    · have same : afterState = beforeState :=
        Option.some.inj
          ((nodeState_of_mem distinct listed).symm.trans (nodeState_of_mem distinct beforeMember))
      subst same
      exact List.prefix_refl _
  cases action with
  | «local» actor input =>
      obtain ⟨old, new, outputs, found, acted, rfl⟩ := step_local stepped
      exact extended found (Extends.act _ actor old input _ _ _ acted) afterMember
  | deliver envelope =>
      obtain ⟨_, old, new, outputs, found, received, rfl⟩ := step_deliver stepped
      exact extended found (Extends.receive _ _ old _ _ _ _ _ received) afterMember

end CCFRaft.ProofTLA.Direct
