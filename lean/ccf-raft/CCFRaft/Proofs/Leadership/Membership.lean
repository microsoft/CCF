module

public import CCFRaft.Proofs.Replication.Step
public import CCFRaft.Proofs.CommitLiveness
public import CCFRaft.Proofs.Replication.Eligible

@[expose] public section

set_option linter.unusedSectionVars false

/-!
# The primary keeps its latest configuration

The last configuration in a log is active at every commit index, so a node of
the latest configuration of the primary's log, other than the primary, is one of
its replication peers. While the primary leads a term quiet among participants
it appends no configuration and accepts no AppendEntries, so a step keeps the
configuration history of its log.
-/

namespace CCFRaft.Proofs.Leadership

open CCF CCF.MultiNodeTransitionSystem
open Model.Node
open CCFRaft.Liveness
open CCFRaft.Proofs.Safety
open CCFRaft.Proofs.Replication
open CCFRaft.Proofs.Direct (Keeps)
open CCFRaft.Proofs.CommitLiveness (append_log advanceCommit_log)

/-! ## Configurations of a log -/

/-- Dropping all but the last committed configuration keeps the last configuration. -/
theorem latest_active (log : List Entry) (commitIndex : Nat)
    : latestConfigurationMembers (activeConfigurations log commitIndex)
      = latestConfigurationMembers (configurationHistory log) := by
  unfold activeConfigurations latestConfigurationMembers
  dsimp only
  rw [List.getLast?_drop]
  split
  · rename_i short
    have : configurationHistory log = [] := by
      have := List.length_filter_le
        (fun configuration => decide (configuration.index <= commitIndex))
        (configurationHistory log)
      exact List.eq_nil_of_length_eq_zero (by omega)
    rw [this]
    rfl
  · rfl

/-- A node of the latest configuration is an active member. -/
theorem latest_subset_active (state : NodeState)
    : latestConfigurationMembers (configurationHistory state.log)
      ⊆ state.activeMembers := by
  intro node member
  rw [← latest_active state.log state.commitIndex] at member
  unfold NodeState.activeMembers NodeState.activeConfigurations
  generalize activeConfigurations state.log state.commitIndex = configurations at member ⊢
  unfold latestConfigurationMembers at member
  cases last : configurations.getLast? with
  | none => simp [last] at member
  | some configuration =>
      rw [last] at member
      exact mem_configurationMembers_iff.mpr
        ⟨configuration, List.mem_of_getLast? last, member⟩

/-- A node of the latest configuration other than `self` is an eligible peer. -/
theorem eligible_of_latest {state : NodeState} {self node : NodeID}
    (member : node ∈ latestConfigurationMembers (configurationHistory state.log))
    (different : Not (node = self))
    : node ∈ eligiblePeers state self := by
  unfold eligiblePeers
  exact Finset.mem_erase.mpr
    ⟨different, Finset.mem_union_left _ (latest_subset_active state member)⟩

/-- Appending entries without a configuration keeps the configuration history. -/
theorem configurationHistory_append_none {log extra : List Entry}
    (none_ : forall entry, entry ∈ extra -> entry.content.metadata.configuration = none)
    : configurationHistory (log ++ extra) = configurationHistory log := by
  unfold configurationHistory
  rw [List.zipIdx_append, List.filterMap_append]
  refine (congrArg _ ?_).trans (List.append_nil _)
  apply List.filterMap_eq_nil_iff.mpr
  rintro ⟨entry, index⟩ member
  have : entry ∈ extra := List.fst_mem_of_mem_zipIdx member
  simp [none_ entry this]

/-! ## Handlers -/

section Handlers

variable (self : NodeID)

/-- Observing a message's term leaves a primary neither candidate nor pre-vote
candidate. -/
theorem observeTerm_role {state : NodeState} (primary : state.role = .primary)
    (message : Message)
    : Not ((observeTerm state message).role = .candidate)
      /\ Not ((observeTerm state message).role = .preVoteCandidate) := by
  unfold observeTerm updateTerm becomeAwareOfNewTerm
  split <;> (try split) <;> (try split) <;> simp_all

/-- A primary keeps its log on receipt of any message but an AppendEntries request
of its term or later. -/
theorem receive_log (state : NodeState) (source : NodeID) (message : Message)
    (primary : state.role = .primary)
    (request
      : forall request,
          message = .appendEntriesRequest request -> request.term < state.currentTerm)
    : Keeps (fun result => result.log = state.log)
        (Model.Node.receive (Capabilities.record self) self source state message) := by
  have roles := observeTerm_role primary message
  have observedLog := Concrete.observeTerm_log state message
  unfold Model.Node.receive
  refine Keeps.ite' (fun _ => Keeps.pure' rfl) fun _ => ?_
  dsimp only
  cases message with
  | appendEntriesRequest request' =>
      have lt := request request' rfl
      have observed : observeTerm state (.appendEntriesRequest request') = state :=
        updateTerm_of_le lt.le
      rw [observed]
      unfold handleAppendEntriesRequest
      have notSame : Not (request'.term = state.currentTerm) := Nat.ne_of_lt lt
      simp only [notSame, false_and, ite_false]
      refine Keeps.ite' (fun _ => ?_) fun no => absurd (Or.inl lt) no
      exact Keeps.ite' (fun _ => Keeps.seq' fun _ => Keeps.pure' rfl)
        fun _ => Keeps.seq' fun _ => Keeps.pure' rfl
  | appendEntriesResponse response =>
      generalize observeTerm state _ = current at observedLog ⊢
      unfold handleAppendEntriesResponse
      refine Keeps.ite' (fun _ => Keeps.pure' observedLog) fun _ => ?_
      refine Keeps.ite' (fun _ => ?_) fun _ => Keeps.pure' observedLog
      refine Keeps.ite' (fun _ => ?_) fun _ => Keeps.pure' observedLog
      exact (advanceCommit_log self _).mono fun _ kept => kept.1.trans observedLog
  | requestVoteRequest request' =>
      generalize observeTerm state _ = current at observedLog ⊢
      unfold handleRequestVoteRequest
      exact Keeps.seq' fun _ => Keeps.pure' (by split <;> exact observedLog)
  | requestVoteResponse response =>
      unfold handleRequestVoteResponse
      exact Keeps.ite' (fun candidate => absurd candidate.1 roles.1)
        fun _ => Keeps.pure' observedLog
  | requestPreVoteRequest request' =>
      unfold handleRequestPreVoteRequest
      exact Keeps.seq' fun _ => Keeps.pure' observedLog
  | requestPreVoteResponse response =>
      unfold handleRequestPreVoteResponse
      exact Keeps.ite' (fun preVote => absurd preVote.1 roles.2)
        fun _ => Keeps.pure' observedLog
  | proposeRequestVoteRequest term =>
      unfold handleProposeRequestVoteRequest
      refine Keeps.ite' (fun propose => ?_) fun _ => Keeps.pure' observedLog
      have role := propose.2.1
      simp only [observeTerm, primary] at role
      rcases role with role | role | role <;> cases role

/-- A primary keeps its log at every input but an append or an election
timeout. -/
theorem act_log (state : NodeState) (input : Input) (primary : state.role = .primary)
    (notAppend : forall contents, Not (input = .append contents))
    : Keeps (fun result => result.log = state.log)
        (Model.Node.act (Capabilities.record self) self state input) := by
  cases input with
  | append contents => exact absurd rfl (notAppend contents)
  | sendEntries destination batchEnds =>
      exact (Direct.Keeps.sendEntries _ self state destination batchEnds).mono
        fun _ ⟨_, eq⟩ => eq ▸ rfl
  | timeout kind =>
      cases kind with
      | election =>
          unfold Model.Node.act startElection
          refine Keeps.bind' Keeps.guard' fun _ can => ?_
          rcases can.1 with role | role | role <;> rw [role] at primary <;> cases primary
      | checkQuorum =>
          unfold Model.Node.act checkQuorum
          exact Keeps.seq' fun _ => Keeps.pure' rfl
  | nominateSuccessor =>
      exact (Direct.Keeps.nominateSuccessor _ self state).mono fun _ same => same ▸ rfl

end Handlers

/-! ## Steps -/

end CCFRaft.Proofs.Leadership
