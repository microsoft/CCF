module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import CCFRaft.Model
public import CCF.Execution

@[expose] public section

/-!
`NodeID` and `ReqID` are natural numbers.
Each claim quantifies every explicit `ModelConfig` value and every node list. Claims concern valid traces
or individual successful steps of `Model.transitionSystem`. Each has a `Witness`
claim exhibiting a nontrivial execution relevant to the property.
-/

namespace CCFRaft.Properties

abbrev GlobalTrace := CCF.Execution.Trace Model.State

open Model.Node
open Model (ModelConfig)

/-- Any two committed logs in a valid trace are prefix-comparable: those of
any two nodes, in any two states of the trace. -/
def CommittedLogsPrefix : Prop :=
  forall (config : ModelConfig),
  forall (nodes : List NodeID) (trace : GlobalTrace),
  forall (first second : Model.State),
  forall (left right : NodeID) (leftState rightState : NodeState),
    (trace.Valid (Model.transitionSystem config nodes)
      /\ first ∈ trace.states
      /\ second ∈ trace.states
      /\ (left, leftState) ∈ first.nodes
      /\ (right, rightState) ∈ second.nodes)
    -> leftState.committedLog <+: rightState.committedLog
        \/ rightState.committedLog <+: leftState.committedLog

/-- Witness: a valid trace has two states in which two distinct nodes have
nonempty committed logs. -/
def CommittedLogsPrefixWitness : Prop :=
  exists (config : ModelConfig),
  exists (nodes : List NodeID) (trace : GlobalTrace),
  exists (first second : Model.State),
  exists (left right : NodeID) (leftState rightState : NodeState),
    trace.Valid (Model.transitionSystem config nodes)
    /\ first ∈ trace.states
    /\ second ∈ trace.states
    /\ (left, leftState) ∈ first.nodes
    /\ (right, rightState) ∈ second.nodes
    /\ left ≠ right
    /\ leftState.committedLog ≠ []
    /\ rightState.committedLog ≠ []

/-- A successful network step from a state with unique node IDs preserves each
node's committed prefix. -/
def SingleNodeCommittedLogMonotonic : Prop :=
  forall (config : ModelConfig) (nodes : List NodeID),
  forall (pre post : Model.State),
  forall (nodeId : NodeID) (nodePre nodePost : NodeState),
  forall (action : Model.Action),
    ((pre.nodes.map Prod.fst).Nodup
      /\ (Model.transitionSystem config nodes).step pre action = some post
      /\ (nodeId, nodePre) ∈ pre.nodes
      /\ (nodeId, nodePost) ∈ post.nodes)
    -> nodePre.committedLog <+: nodePost.committedLog

/-- Witness: a successful step from a state with unique node IDs strictly extends
one node's nonempty committed log. -/
def SingleNodeCommittedLogMonotonicWitness : Prop :=
  exists (config : ModelConfig) (nodes : List NodeID),
  exists (pre post : Model.State),
  exists (nodeId : NodeID) (nodePre nodePost : NodeState),
  exists (action : Model.Action),
    (pre.nodes.map Prod.fst).Nodup
    /\ (Model.transitionSystem config nodes).step pre action = some post
    /\ (nodeId, nodePre) ∈ pre.nodes
    /\ (nodeId, nodePost) ∈ post.nodes
    /\ nodePre.committedLog ≠ []
    /\ nodePre.committedLog.length < nodePost.committedLog.length

/-- No two distinct nodes are primary in the same term. -/
def ElectionSafety : Prop :=
  forall (config : ModelConfig),
  forall (nodes : List NodeID) (trace : GlobalTrace) (state : Model.State),
  forall (left right : NodeID) (leftState rightState : NodeState),
    (trace.Valid (Model.transitionSystem config nodes)
      /\ state ∈ trace.states
      /\ (left, leftState) ∈ state.nodes
      /\ (right, rightState) ∈ state.nodes
      /\ leftState.role = .primary
      /\ rightState.role = .primary
      /\ leftState.currentTerm = rightState.currentTerm)
    -> left = right

/-- Witness: a valid trace has a state in which two nodes are primaries. -/
def ElectionSafetyWitness : Prop :=
  exists (config : ModelConfig),
  exists
  (nodes : List NodeID) (trace : GlobalTrace) (state : Model.State),
  exists (left right : NodeID) (leftState rightState : NodeState),
    trace.Valid (Model.transitionSystem config nodes)
    /\ state ∈ trace.states
    /\ (left, leftState) ∈ state.nodes
    /\ (right, rightState) ∈ state.nodes
    /\ leftState.role = .primary
    /\ rightState.role = .primary
    /\ left ≠ right

/-- Every positive commit index points to a signature entry. -/
def CommittedFrontierIsSignature : Prop :=
  forall (config : ModelConfig),
  forall (nodes : List NodeID) (trace : GlobalTrace) (state : Model.State),
  forall (node : NodeID) (nodeState : NodeState),
    (trace.Valid (Model.transitionSystem config nodes)
      /\ state ∈ trace.states
      /\ (node, nodeState) ∈ state.nodes
      /\ 0 < nodeState.commitIndex)
    -> isSignatureAt nodeState.log nodeState.commitIndex = true

/-- Witness: a valid trace has a state with a positive commit index. -/
def CommittedFrontierIsSignatureWitness : Prop :=
  exists (config : ModelConfig),
  exists
  (nodes : List NodeID) (trace : GlobalTrace) (state : Model.State),
  exists (node : NodeID) (nodeState : NodeState),
    trace.Valid (Model.transitionSystem config nodes)
    /\ state ∈ trace.states
    /\ (node, nodeState) ∈ state.nodes
    /\ 0 < nodeState.commitIndex

end CCFRaft.Properties
