module

public import CCFRaft.Model
public import CCF.Execution

import CCFRaft.Proofs.CommittedLogs
import CCFRaft.Proofs.Direct.CommitFrontier
import CCFRaft.Proofs.Election
import CCFRaft.Proofs.Witnesses

@[expose] public section

/-!
Safety theorems about the Raft model, each paired with a witness lemma
exhibiting a nontrivial execution relevant to that property.
-/

namespace CCFRaft.Properties

abbrev GlobalTrace := CCF.Execution.Trace Model.State

open Model.Node
open CCF.MultiNodeTransitionSystem (nodeState)
open Proofs.Witnesses

/-- Any two committed logs in a valid trace are prefix-comparable: those of
any two nodes, in any two states of the trace. -/
theorem committed_logs_prefix
    : forall (config : Finset NodeID),
      forall (nodes : List NodeID) (trace : GlobalTrace),
      forall (first second : Model.State),
      forall (left right : NodeID) (leftState rightState : NodeState),
        (trace.Valid (Model.transitionSystem config nodes)
          /\ first ∈ trace
          /\ second ∈ trace
          /\ (left, leftState) ∈ first.nodes
          /\ (right, rightState) ∈ second.nodes)
        -> leftState.committedLog <+: rightState.committedLog
            \/ rightState.committedLog <+: leftState.committedLog := by
  intro config nodes trace first second left right leftState rightState
    ⟨valid, firstMember, secondMember, leftMember, rightMember⟩
  let _ : Proofs.Config.InitialConfiguration := ⟨config⟩
  obtain ⟨firstIndex, firstFound⟩ := Stream'.Seq.mem_iff_exists_get?.mp firstMember
  obtain ⟨secondIndex, secondFound⟩ := Stream'.Seq.mem_iff_exists_get?.mp secondMember
  rcases Nat.le_total firstIndex secondIndex with ordered | ordered
  · exact Proofs.CommittedLogs.committed_logs_prefix_of_le valid ordered
      firstFound.symm secondFound.symm leftMember rightMember
  · exact (Proofs.CommittedLogs.committed_logs_prefix_of_le valid ordered
      secondFound.symm firstFound.symm rightMember leftMember).symm

/-- Witness: a valid trace has two states in which two distinct nodes have
nonempty committed logs. -/
lemma committed_logs_prefix_witness
    : exists (config : Finset NodeID),
    exists (nodes : List NodeID) (trace : GlobalTrace),
    exists (first second : Model.State),
    exists (left right : NodeID) (leftState rightState : NodeState),
      trace.Valid (Model.transitionSystem config nodes)
      /\ first ∈ trace
      /\ second ∈ trace
      /\ (left, leftState) ∈ first.nodes
      /\ (right, rightState) ∈ second.nodes
      /\ left ≠ right
      /\ leftState.committedLog ≠ []
      /\ rightState.committedLog ≠ [] := by
  have stemRun := commit_run
  exact ⟨
    {0, 1},
    [0, 1],
    lassoTrace commitSystem commitStart commitChoices commitCycle,
    commitPrimaryCommitted,
    commitFollowerCommitted,
    0,
    1,
    (nodeState commitPrimaryCommitted 0).get commit_primary_present,
    (nodeState commitFollowerCommitted 1).get commit_follower_present,
    lasso_valid (start_initial (by decide) (by decide)) stemRun commit_cycle
      (by simp [commitCycle]),
    lasso_mem stemRun (by decide) (eq_some_getD commit_primary_committed _),
    lasso_mem stemRun (by decide) (eq_some_getD commit_follower_committed _),
    member_of_nodeState _,
    member_of_nodeState _,
    by decide,
    by decide,
    by decide
  ⟩

/-- A successful network step from a state with unique node IDs preserves each
node's committed prefix. -/
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

/-- Witness: a successful step from a state with unique node IDs strictly extends
one node's nonempty committed log. -/
lemma single_node_committed_log_monotonic_witness
    : exists (config : Finset NodeID) (nodes : List NodeID),
    exists (pre post : Model.State),
    exists (nodeId : NodeID) (nodePre nodePost : NodeState),
    exists (action : Model.Action),
      (pre.nodes.map Prod.fst).Nodup
      /\ (Model.transitionSystem config nodes).step pre action = some post
      /\ (nodeId, nodePre) ∈ pre.nodes
      /\ (nodeId, nodePost) ∈ post.nodes
      /\ nodePre.committedLog ≠ []
      /\ nodePre.committedLog.length < nodePost.committedLog.length :=
  ⟨
    {0},
    [0],
    singleFinal,
    extendFinal,
    0,
    (nodeState singleFinal 0).get single_final_present,
    (nodeState extendFinal 0).get extend_final_present,
    extendAction,
    single_final_distinct,
    eq_some_getD extend_enabled _,
    member_of_nodeState _,
    member_of_nodeState _,
    extend_committed.1,
    extend_committed.2
  ⟩

/-- No two distinct nodes are primary in the same term. -/
theorem election_safety
    : forall (config : Finset NodeID),
      forall (nodes : List NodeID) (trace : GlobalTrace) (state : Model.State),
      forall (left right : NodeID) (leftState rightState : NodeState),
        (trace.Valid (Model.transitionSystem config nodes)
          /\ state ∈ trace
          /\ (left, leftState) ∈ state.nodes
          /\ (right, rightState) ∈ state.nodes
          /\ leftState.role = .primary
          /\ rightState.role = .primary
          /\ leftState.currentTerm = rightState.currentTerm)
        -> left = right := by
  intro config nodes trace state left right leftState rightState
    ⟨valid, member, leftMember, rightMember, leftLeader, rightLeader, sameTerm⟩
  let _ : Proofs.Config.InitialConfiguration := ⟨config⟩
  exact Proofs.Election.primary_eq_of_reachable (valid.reachable member)
    leftMember rightMember leftLeader rightLeader sameTerm

/-- Witness: a valid trace has a state in which two nodes are primaries. -/
lemma election_safety_witness
    : exists (config : Finset NodeID),
    exists
    (nodes : List NodeID) (trace : GlobalTrace) (state : Model.State),
    exists (left right : NodeID) (leftState rightState : NodeState),
      trace.Valid (Model.transitionSystem config nodes)
      /\ state ∈ trace
      /\ (left, leftState) ∈ state.nodes
      /\ (right, rightState) ∈ state.nodes
      /\ leftState.role = .primary
      /\ rightState.role = .primary
      /\ left ≠ right := by
  have lead := election_both_lead
  simp only [bothLead, Bool.and_eq_true, Option.any_eq_true, decide_eq_true_eq] at lead
  obtain ⟨⟨leftState, leftFound, leftPrimary⟩, ⟨rightState, rightFound, rightPrimary⟩⟩ := lead
  have stemRun := election_run
  exact ⟨
    {0, 1, 2},
    [0, 1, 2],
    lassoTrace electionSystem electionStart electionChoices electionCycle,
    electionFinal,
    0,
    1,
    leftState,
    rightState,
    lasso_valid (start_initial (by decide) (by decide)) stemRun election_cycle
      (by simp [electionCycle]),
    lasso_mem stemRun le_rfl (by rw [List.take_length]; exact stemRun),
    mem_of_nodeState leftFound,
    mem_of_nodeState rightFound,
    leftPrimary,
    rightPrimary,
    by decide
  ⟩

/-- Every positive commit index points to a signature entry. -/
theorem committed_frontier_is_signature
    : forall (config : Finset NodeID),
      forall (nodes : List NodeID) (trace : GlobalTrace) (state : Model.State),
      forall (node : NodeID) (nodeState : NodeState),
        (trace.Valid (Model.transitionSystem config nodes)
          /\ state ∈ trace
          /\ (node, nodeState) ∈ state.nodes
          /\ 0 < nodeState.commitIndex)
        -> isSignatureAt nodeState.log nodeState.commitIndex = true := by
  intro config nodes trace state node nodeState ⟨valid, member, listed, positive⟩
  let _ : Proofs.Config.InitialConfiguration := ⟨config⟩
  exact (Proofs.Direct.commitFrontier_invariant.reachable
          (valid.reachable member) node nodeState listed).2
    positive

/-- Witness: a valid trace has a state with a positive commit index. -/
lemma committed_frontier_is_signature_witness
    : exists (config : Finset NodeID),
    exists
    (nodes : List NodeID) (trace : GlobalTrace) (state : Model.State),
    exists (node : NodeID) (nodeState : NodeState),
      trace.Valid (Model.transitionSystem config nodes)
      /\ state ∈ trace
      /\ (node, nodeState) ∈ state.nodes
      /\ 0 < nodeState.commitIndex := by
  have stemRun := single_run
  exact ⟨
    {0},
    [0],
    lassoTrace singleSystem singleStart singleChoices singleCycle,
    singleFinal,
    0,
    (nodeState singleFinal 0).get single_final_present,
    lasso_valid (start_initial (by decide) (by decide)) stemRun single_cycle
      (by simp [singleCycle]),
    lasso_mem stemRun le_rfl (by rw [List.take_length]; exact stemRun),
    member_of_nodeState _,
    by decide
  ⟩

end CCFRaft.Properties
