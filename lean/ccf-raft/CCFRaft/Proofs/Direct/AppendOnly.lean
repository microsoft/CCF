module

public import CCFRaft.Proofs.Direct.CommitFrontier
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

namespace CCFRaft.Proofs.Direct

open CCFRaft.Proofs.Config

open CCF CCF.MultiNodeTransitionSystem Concrete
open Model.Node

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
  obtain ⟨retired, role, known, eq, -⟩ :=
    Ledger.handleAppendEntiresFromPrimary_eq self state request
  rw [eq]
  exact ⟨le_max_left _ _, (List.take_prefix _ _).trans (List.prefix_append _ _)⟩

theorem Extends.handleAppendEntriesRequest (caps : Caps) (source : NodeID)
    : Keeps (Extends state)
        (Model.Node.handleAppendEntriesRequest caps self source state request) := by
  unfold Model.Node.handleAppendEntriesRequest
  have stepped : Extends state (if request.term = state.currentTerm /\
      (state.role = .candidate \/ state.role = .preVoteCandidate) then
        becomeAwareOfNewTerm state request.term else state) := by
    split
    · exact Extends.of_log rfl rfl
    · exact Extends.refl _
  generalize (if request.term = state.currentTerm /\
      (state.role = .candidate \/ state.role = .preVoteCandidate) then
        becomeAwareOfNewTerm state request.term else state) = current
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
  split
  · exact Keeps.seq' fun _ => Keeps.pure'
      ((stepped.trans (Extends.of_log (after := { current with primaryKnown := true }) rfl
        rfl)).trans Extends.fromLeader)
  · rename_i index conflict
    have := Ledger.firstTermConflictIndex_ge conflict
    have truncated : Extends current {
        current with
          primaryKnown := true, log := current.log.take (index - 1), isNewFollower := false
      } :=
      Extends.of_prefix (count := index - 1) (by omega) (List.prefix_refl _) le_rfl
    exact Keeps.seq' fun _ => Keeps.pure' ((stepped.trans truncated).trans Extends.fromLeader)

end AppendEntries

section Handlers

variable (caps : Caps) (self : NodeID)

theorem Extends.advanced (state : NodeState)
    : Keeps (Extends state) (Model.Node.advanceCommit caps state self) := by
  unfold Model.Node.advanceCommit
  refine Keeps.ite' (fun _ => Keeps.pure' (Extends.refl _)) fun ahead => ?_
  have advanced : Extends state
      (state.recordCommit self (highestCommittableIndex state self)) :=
    ⟨by rw [Ledger.NodeState.recordCommit_commitIndex]; omega,
      by rw [Ledger.NodeState.recordCommit_log]; exact List.take_prefix _ _⟩
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
        (Keeps.foldlM' (P := Extends state) (fun current entry kept =>
          Keeps.bind' (Extends.appendEntry caps self current entry.content)
            fun appended next => Keeps.foldlM'
              (fun current (destination, endIndex) kept => by
                unfold Model.Node.sendEntries
                exact Keeps.seq' fun _ => Keeps.seq' fun _ => Keeps.pure' kept)
              entry.flushes appended (kept.trans next))
          entries state (Extends.refl _))
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
      exact (Keeps.nominateSuccessor caps self state).mono fun _ same =>
        same ▸ Extends.of_log rfl rfl

theorem Extends.receive (state : NodeState) (source : NodeID) (message : Message)
    : Keeps (Extends state) (Model.Node.receive caps self source state message) := by
  have observedExtends : Extends state (observeTerm state message) :=
    Extends.of_log (Concrete.observeTerm_log _ _) (Concrete.observeTerm_commitIndex _ _)
  unfold Model.Node.receive
  refine Keeps.ite' (fun _ => Keeps.pure' (Extends.refl _)) fun _ => ?_
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
  | requestPreVoteRequest request =>
      unfold Model.Node.handleRequestPreVoteRequest
      exact Keeps.seq' fun _ => Keeps.pure' (Extends.refl _)
  | requestPreVoteResponse response =>
      unfold Model.Node.handleRequestPreVoteResponse
      refine Keeps.ite' (fun _ => ?_) fun _ => Keeps.pure' (Extends.refl _)
      dsimp only
      refine Keeps.ite' (fun _ => ?_) fun _ => Keeps.pure' (Extends.of_log rfl rfl)
      exact (Extends.becomeCandidate caps self _).mono fun _ next =>
        (Extends.of_log rfl rfl).trans next
  | proposeRequestVoteRequest term =>
      unfold Model.Node.handleProposeRequestVoteRequest
      exact Keeps.ite' (fun _ => Extends.becomeCandidate caps self current)
        fun _ => Keeps.pure' (Extends.refl _)

end Handlers

/-- Every local step extends the acting node's committed log. -/
theorem extends_step {self : NodeID} {state after : NodeState}
    {event : Event} {outputs : Outputs NodeID (Message) Notification}
    (stepped
      : (Model.Node.step (Capabilities.record self) self state event).run {}
        = some (after, outputs))
    : Extends state after := by
  cases event with
  | internal input =>
      simp only [Model.Node.step] at stepped
      exact Extends.act _ self state _ _ _ _ stepped
  | receive source message =>
      simp only [Model.Node.step] at stepped
      exact Extends.receive _ self state source message _ _ _ stepped

section Global

variable [Config.InitialConfiguration]

/-- From any state with distinct node identifiers, a step keeps every other node's
state and extends the actor's committed log. -/
theorem committed_log_step {nodes : List NodeID} {before after : Model.State}
    {action : Model.Action}
    (distinct : (before.nodes.map Prod.fst).Nodup)
    (stepped
      : (Model.transitionSystem Config.INITIAL_CONFIGURATION nodes).step before action
        = some after)
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

/-- A node present before a step is present after it. -/
theorem present_after_step {nodes : List NodeID} {before after : Model.State}
    {action : Model.Action}
    (stepped
      : (Model.transitionSystem Config.INITIAL_CONFIGURATION nodes).step before action
        = some after)
    {node : NodeID} {beforeState : NodeState}
    (member : (node, beforeState) ∈ before.nodes)
    : exists afterState, (node, afterState) ∈ after.nodes := by
  have present : forall {actor : NodeID} {value : NodeState},
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
committed log at every later state of the trace. -/
theorem committed_log_later {nodes : List NodeID}
    {trace
      : CCF.Execution.Trace (Model.transitionSystem Config.INITIAL_CONFIGURATION nodes)}
    {index : Nat} {state : Model.State} (found : trace.stateAt index = some state)
    {node : NodeID} {firstState : NodeState} (member : (node, firstState) ∈ state.nodes)
    : forall offset later,
        trace.stateAt (index + offset) = some later
        -> exists laterState,
            (node, laterState) ∈ later.nodes
            /\ firstState.committedLog <+: laterState.committedLog := by
  intro offset
  induction offset with
  | zero =>
      intro later atLater
      rw [Nat.add_zero, found] at atLater
      cases atLater
      exact ⟨firstState, member, List.prefix_refl _⟩
  | succ offset ih =>
      intro later atLater
      rw [← Nat.add_assoc] at atLater
      cases atMiddle : trace.stateAt (index + offset) with
      | none => simp [trace.states.le_stable (Nat.le_succ _) atMiddle] at atLater
      | some middle =>
          obtain ⟨middleState, middleMember, prefixed⟩ := ih middle atMiddle
          obtain ⟨action, stepped⟩ := trace.step (index + offset) middle later atMiddle atLater
          obtain ⟨laterState, laterMember⟩ := present_after_step stepped middleMember
          refine ⟨laterState, laterMember, prefixed.trans ?_⟩
          exact committed_log_step (keys_nodup (trace.reachable (CCF.Execution.Trace.stateAt_mem atMiddle)))
            stepped middleMember laterMember

end Global

theorem single_node_committed_log_monotonic
    : forall (config : Finset NodeID) (nodes : List NodeID),
      forall (pre post : Model.State),
      forall (nodeId : NodeID) (nodePre nodePost : NodeState),
      forall (action : Model.Action),
        ((pre.nodes.map Prod.fst).Nodup
          /\ (Model.transitionSystem config nodes).step pre action = some post
          /\ (nodeId, nodePre) ∈ pre.nodes
          /\ (nodeId, nodePost) ∈ post.nodes)
        -> nodePre.committedLog <+: nodePost.committedLog := by
  intro config nodes pre post nodeId nodePre nodePost action
    ⟨distinct, stepped, preMember, postMember⟩
  let _ : Proofs.Config.InitialConfiguration := ⟨config⟩
  exact Proofs.Direct.committed_log_step distinct stepped preMember postMember

end CCFRaft.Proofs.Direct
