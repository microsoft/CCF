module

public import Consensus.Proofs.GenericWitnesses

import all Init.Control.State

namespace Consensus.Proofs.Witnesses

open CCF.Execution
open Consensus.Model.Node
open GenericWitnesses

private theorem committed_trace (config : Consensus.Properties.ValidConfig)
    : exists (trace : Trace (Model.transitionSystem config (ids config))) (state
                                                                            : Model.State) (node
                                                                                            : NodeID) (nodeState
                                                                                                        : NodeState),
        state ∈ trace
        /\ (node, nodeState) ∈ state.nodes
        /\ 0 < nodeState.commitIndex
        /\ nodeState.committedLog ≠ [] := by
  obtain ⟨states, reachable, leading, _, _⟩ :=
    replicate_set config (config.val.erase (primary config)) (CCF.Finset.Subset.refl _)
  obtain ⟨trace, network, present⟩ := at_trace reachable
    (primary config) (primary_mem config) (by rw [leading]; rfl)
  refine ⟨trace, { nodes := table config states, network },
    primary config, states (primary config), present,
    table_member config states _ (primary_mem config), ?_, ?_⟩
  · rw [leading]
    simp [leader, full_commit config _ (primary_mem config)]
  · rw [leading]
    simp [leader, NodeState.committedLog, bootstrapLog,
      full_commit config _ (primary_mem config)]

private def singletonStart : Model.State :=
  { nodes := [(0, Model.initialNodeState {0} 0)] }

private def extensionPre : Model.State :=
  ((Model.transitionSystem {0} [0]).step singletonStart
    (.local 0 (.append [{ content := .signature }]))).getD
    singletonStart

private def extensionAction : Model.Action :=
  .local 0 (.append [{ content := .transaction 1 {} }, { content := .signature }])

private def extensionPost : Model.State :=
  ((Model.transitionSystem {0} [0]).step extensionPre extensionAction).getD extensionPre

private theorem extension_pre_present
    : (CCF.MultiNodeTransitionSystem.nodeState extensionPre 0).isSome := by
  decide +kernel

private theorem extension_post_present
    : (CCF.MultiNodeTransitionSystem.nodeState extensionPost 0).isSome := by
  decide +kernel

private theorem nodeState_member {state : Model.State} {node : NodeID} {value : NodeState}
    (found : CCF.MultiNodeTransitionSystem.nodeState state node = some value)
    : (node, value) ∈ state.nodes := by
  simp only [CCF.MultiNodeTransitionSystem.nodeState, Option.map_eq_some_iff] at found
  obtain ⟨⟨key, stored⟩, located, same⟩ := found
  simp only at same
  subst same
  have keyEq : key = node := by simpa using List.find?_some located
  subst keyEq
  exact List.mem_of_find?_eq_some located

public theorem committed_logs_prefix_witness
    : forall (config : Consensus.Properties.ValidConfig),
        exists
        (nodes : List NodeID) (trace : Trace (Model.transitionSystem config nodes)),
        exists (stateA stateB : Model.State),
        exists (left right : NodeID) (leftState rightState : NodeState),
          stateA ∈ trace
          /\ stateB ∈ trace
          /\ (left, leftState) ∈ stateA.nodes
          /\ (right, rightState) ∈ stateB.nodes
          /\ leftState.committedLog ≠ []
          /\ rightState.committedLog ≠ [] := by
  intro config
  obtain ⟨trace, state, node, nodeState, present, member, _, committed⟩ :=
    committed_trace config
  exact ⟨ids config, trace, state, state, node, node, nodeState, nodeState,
    present, present, member, member, committed, committed⟩

public theorem single_node_committed_log_monotonic_witness
    : forall (config : Consensus.Properties.ValidConfig),
        exists (nodes : List NodeID),
        exists (pre post : Model.State),
        exists (nodeId : NodeID) (nodePre nodePost : NodeState),
        exists (action : Model.Action),
          (pre.nodes.map Prod.fst).Nodup
          /\ (Model.transitionSystem config nodes).step pre action = some post
          /\ (nodeId, nodePre) ∈ pre.nodes
          /\ (nodeId, nodePost) ∈ post.nodes
          /\ nodePre.committedLog ≠ []
          /\ nodePre.committedLog.length < nodePost.committedLog.length := by
  intro config
  -- Initial membership affects initialization, not this append step.
  refine ⟨[0], extensionPre, extensionPost, 0,
    (CCF.MultiNodeTransitionSystem.nodeState extensionPre 0).get extension_pre_present,
    (CCF.MultiNodeTransitionSystem.nodeState extensionPost 0).get extension_post_present,
    extensionAction, ?_, ?_, ?_, ?_, ?_, ?_⟩
  · decide +kernel
  · have enabled : ((Model.transitionSystem {0} [0]).step extensionPre extensionAction).isSome := by
      decide +kernel
    change (Model.transitionSystem {0} [0]).step extensionPre extensionAction =
      some (((Model.transitionSystem {0} [0]).step extensionPre extensionAction).getD extensionPre)
    generalize (Model.transitionSystem {0} [0]).step extensionPre extensionAction = result at enabled ⊢
    cases result <;> simp_all
  · exact nodeState_member (Option.some_get extension_pre_present).symm
  · exact nodeState_member (Option.some_get extension_post_present).symm
  · decide +kernel
  · decide +kernel

public theorem election_safety_witness
    : forall (config : Consensus.Properties.ValidConfig),
        exists
        (nodes : List NodeID) (trace
                                : Trace (Model.transitionSystem config nodes)) (state
                                                                                : Model.State)
          ,
        exists (left right : NodeID) (leftState rightState : NodeState),
          state ∈ trace
          /\ (left, leftState) ∈ state.nodes
          /\ (right, rightState) ∈ state.nodes
          /\ leftState.role = .primary
          /\ rightState.role = .primary
          /\ leftState.currentTerm = rightState.currentTerm := by
  intro config
  obtain ⟨trace, network, present⟩ :=
    at_trace (at_initial config) (primary config) (primary_mem config)
      (by simp only [initial_primary])
  let state : Model.State := { nodes := table config (Model.initialNodeState config), network }
  have member := table_member config (Model.initialNodeState config) _ (primary_mem config)
  have leading : (Model.initialNodeState config (primary config)).role = .primary := by
    simp only [initial_primary]
  exact ⟨
    ids config,
    trace,
    state,
    primary config,
    primary config,
    Model.initialNodeState config (primary config),
    Model.initialNodeState config (primary config),
    present,
    member,
    member,
    leading,
    leading,
    rfl
  ⟩

/-- Every valid configuration reaches a state in which a node has committed. -/
public theorem deadlock_free_after_bootstrap_witness
    : forall (config : Consensus.Properties.ValidConfig),
        exists (nodes : List NodeID) (state : Model.State),
          (Model.transitionSystem config nodes).Reachable state
          /\ Consensus.Properties.Bootstrapped state := by
  intro config
  obtain ⟨trace, state, node, nodeState, present, member, positive, _⟩ :=
    committed_trace config
  exact ⟨ids config, state, trace.reachable present, node, nodeState, member, positive⟩

public theorem committed_frontier_is_signature_witness
    : forall (config : Consensus.Properties.ValidConfig),
        exists
        (nodes : List NodeID) (trace
                                : Trace (Model.transitionSystem config nodes)) (state
                                                                                : Model.State)
          ,
        exists (node : NodeID) (nodeState : NodeState),
          state ∈ trace
          /\ (node, nodeState) ∈ state.nodes
          /\ 0 < nodeState.commitIndex := by
  intro config
  obtain ⟨trace, state, node, nodeState, present, member, positive, _⟩ :=
    committed_trace config
  exact ⟨ids config, trace, state, node, nodeState, present, member, positive⟩

end Consensus.Proofs.Witnesses
