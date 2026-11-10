module

public import Consensus.Properties

@[expose] public section

namespace Consensus.Tests.Witnesses

open Model.Node

example (config : Properties.ValidConfig)
    : exists (nodes : List NodeID) (trace : Properties.GlobalTrace config nodes),
    exists (stateA stateB : Model.State),
    exists (left right : NodeID) (leftState rightState : NodeState),
      stateA ∈ trace
      /\ stateB ∈ trace
      /\ (left, leftState) ∈ stateA.nodes
      /\ (right, rightState) ∈ stateB.nodes
      /\ leftState.committedLog ≠ []
      /\ rightState.committedLog ≠ []
      /\ (leftState.committedLog <+: rightState.committedLog
          \/ rightState.committedLog <+: leftState.committedLog) := by
  obtain ⟨nodes, trace, stateA, stateB, left, right, leftState, rightState,
    inA, inB, leftPresent, rightPresent, leftCommitted, rightCommitted⟩ :=
    Properties.committed_logs_prefix_witness config
  exact ⟨nodes, trace, stateA, stateB, left, right, leftState, rightState,
    inA, inB, leftPresent, rightPresent, leftCommitted, rightCommitted,
    Properties.committed_logs_prefix config nodes trace stateA stateB left right leftState rightState
      ⟨inA, inB, leftPresent, rightPresent⟩⟩

example (config : Properties.ValidConfig)
    : exists (nodes : List NodeID) (pre post : Model.State),
    exists (node : NodeID) (nodePre nodePost : NodeState) (action : Model.Action),
      (pre.nodes.map Prod.fst).Nodup
      /\ (Model.transitionSystem config nodes).step pre action = some post
      /\ (node, nodePre) ∈ pre.nodes
      /\ (node, nodePost) ∈ post.nodes
      /\ nodePre.committedLog ≠ []
      /\ nodePre.committedLog.length < nodePost.committedLog.length
      /\ nodePre.committedLog <+: nodePost.committedLog := by
  obtain ⟨nodes, pre, post, node, nodePre, nodePost, action,
    unique, step, prePresent, postPresent, committed, grows⟩ :=
    Properties.single_node_committed_log_monotonic_witness config
  exact ⟨nodes, pre, post, node, nodePre, nodePost, action,
    unique, step, prePresent, postPresent, committed, grows,
    Properties.single_node_committed_log_monotonic config nodes pre post node nodePre nodePost action
      ⟨unique, step, prePresent, postPresent⟩⟩

example (config : Properties.ValidConfig)
    : exists
    (nodes : List NodeID) (trace : Properties.GlobalTrace config nodes) (state
                                                                          : Model.State),
    exists (left right : NodeID) (leftState rightState : NodeState),
      state ∈ trace
      /\ (left, leftState) ∈ state.nodes
      /\ (right, rightState) ∈ state.nodes
      /\ leftState.role = .primary
      /\ rightState.role = .primary
      /\ leftState.currentTerm = rightState.currentTerm
      /\ left = right := by
  obtain ⟨nodes, trace, state, left, right, leftState, rightState,
    present, leftPresent, rightPresent, leftPrimary, rightPrimary, sameTerm⟩ :=
    Properties.election_safety_witness config
  exact ⟨nodes, trace, state, left, right, leftState, rightState,
    present, leftPresent, rightPresent, leftPrimary, rightPrimary, sameTerm,
    Properties.election_safety config nodes trace state left right leftState rightState
      ⟨present, leftPresent, rightPresent, leftPrimary, rightPrimary, sameTerm⟩⟩

example (config : Properties.ValidConfig)
    : exists (nodes : List NodeID) (trace : Properties.GlobalTrace config nodes) (state
                                                                                  : Model.State) (node
                                                                                                  : NodeID) (nodeState
                                                                                                              : NodeState),
        state ∈ trace
        /\ (node, nodeState) ∈ state.nodes
        /\ 0 < nodeState.commitIndex
        /\ isSignatureAt nodeState.log nodeState.commitIndex = true := by
  obtain ⟨nodes, trace, state, node, nodeState, present, nodePresent, positive⟩ :=
    Properties.committed_frontier_is_signature_witness config
  exact ⟨nodes, trace, state, node, nodeState, present, nodePresent, positive,
    Properties.committed_frontier_is_signature config nodes trace state node nodeState
      ⟨present, nodePresent, positive⟩⟩

example : exists nodes, Nonempty (Properties.GlobalTrace {47} nodes) := by
  obtain ⟨nodes, trace, _⟩ :=
    Properties.committed_frontier_is_signature_witness ⟨{47}, by decide⟩
  exact ⟨nodes, ⟨trace⟩⟩

example : exists nodes, Nonempty (Properties.GlobalTrace {47} nodes) := by
  obtain ⟨nodes, trace, _⟩ :=
    Properties.committed_logs_prefix_witness ⟨{47}, by decide⟩
  exact ⟨nodes, ⟨trace⟩⟩

example : exists nodes, Nonempty (Properties.GlobalTrace {11} nodes) := by
  obtain ⟨nodes, trace, _⟩ :=
    Properties.election_safety_witness ⟨{11}, by decide⟩
  exact ⟨nodes, ⟨trace⟩⟩

example : exists nodes, Nonempty (Properties.GlobalTrace {11, 42} nodes) := by
  obtain ⟨nodes, trace, _⟩ :=
    Properties.election_safety_witness ⟨{11, 42}, by decide⟩
  exact ⟨nodes, ⟨trace⟩⟩

example
    : exists pre post : NodeState,
        pre.committedLog ≠ [] /\ pre.committedLog.length < post.committedLog.length := by
  obtain ⟨_, _, _, _, pre, post, _, _, _, _, _, committed, grows⟩ :=
    Properties.single_node_committed_log_monotonic_witness ⟨{17, 41, 99}, by decide⟩
  exact ⟨pre, post, committed, grows⟩

end Consensus.Tests.Witnesses
