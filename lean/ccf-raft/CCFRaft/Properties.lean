-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFRaft.Properties.Utils

set_option autoImplicit false

/-!
Each claim quantifies every node and transaction identifier type, every
`Bootstrap` instance, every node list, and every valid trace of
`Model.transitionSystem`. Each has a `Witness` claim: some valid trace
satisfies its premises.
-/

namespace CCFRaft.Properties

open Model.Local

/-- No two distinct nodes lead in the same term. -/
def ElectionSafety : Prop :=
  forall (Node TxId : Type) [DecidableEq Node] [DecidableEq TxId] [Bootstrap Node],
  forall (nodes : List Node) (trace : GlobalTrace Node TxId)
          (state : Model.State Node TxId),
  forall (left right : Node) (leftState rightState : NodeState Node TxId),
    (trace.Valid (Model.transitionSystem nodes)
      /\ state ∈ trace.states
      /\ (left, leftState) ∈ state.nodes
      /\ (right, rightState) ∈ state.nodes
      /\ leftState.role = .leader
      /\ rightState.role = .leader
      /\ leftState.currentTerm = rightState.currentTerm)
    -> left = right

/-- Witness: a valid trace has a state in which two nodes are leaders. -/
def ElectionSafetyWitness : Prop :=
  exists
  (Node TxId : Type) (_ : DecidableEq Node) (_ : DecidableEq TxId) (_ : Bootstrap Node),
  exists
  (nodes : List Node) (trace : GlobalTrace Node TxId) (state : Model.State Node TxId),
  exists (left right : Node) (leftState rightState : NodeState Node TxId),
    trace.Valid (Model.transitionSystem nodes)
    /\ state ∈ trace.states
    /\ (left, leftState) ∈ state.nodes
    /\ (right, rightState) ∈ state.nodes
    /\ leftState.role = .leader
    /\ rightState.role = .leader
    /\ left ≠ right

/-- Any two nodes' committed logs in one state are prefix-comparable. -/
def CommittedLogsPrefix : Prop :=
  forall (Node TxId : Type) [DecidableEq Node] [DecidableEq TxId] [Bootstrap Node],
  forall (nodes : List Node) (trace : GlobalTrace Node TxId)
          (state : Model.State Node TxId),
  forall (left right : Node) (leftState rightState : NodeState Node TxId),
    (trace.Valid (Model.transitionSystem nodes)
      /\ state ∈ trace.states
      /\ (left, leftState) ∈ state.nodes
      /\ (right, rightState) ∈ state.nodes)
    -> leftState.committedLog <+: rightState.committedLog
        \/ rightState.committedLog <+: leftState.committedLog

/-- Witness: a valid trace has a state in which two distinct nodes have
nonempty committed logs. -/
def CommittedLogsPrefixWitness : Prop :=
  exists
  (Node TxId : Type) (_ : DecidableEq Node) (_ : DecidableEq TxId) (_ : Bootstrap Node),
  exists
  (nodes : List Node) (trace : GlobalTrace Node TxId) (state : Model.State Node TxId),
  exists (left right : Node) (leftState rightState : NodeState Node TxId),
    trace.Valid (Model.transitionSystem nodes)
    /\ state ∈ trace.states
    /\ (left, leftState) ∈ state.nodes
    /\ (right, rightState) ∈ state.nodes
    /\ left ≠ right
    /\ leftState.committedLog ≠ []
    /\ rightState.committedLog ≠ []

/-- Every positive commit index points to a signature entry. -/
def CommittedFrontierIsSignature : Prop :=
  forall (Node TxId : Type) [DecidableEq Node] [DecidableEq TxId] [Bootstrap Node],
  forall (nodes : List Node) (trace : GlobalTrace Node TxId)
          (state : Model.State Node TxId),
  forall (node : Node) (nodeState : NodeState Node TxId),
    (trace.Valid (Model.transitionSystem nodes)
      /\ state ∈ trace.states
      /\ (node, nodeState) ∈ state.nodes
      /\ 0 < nodeState.commitIndex)
    -> isSignatureAt nodeState.log nodeState.commitIndex = true

/-- Witness: a valid trace has a state with a positive commit index. -/
def CommittedFrontierIsSignatureWitness : Prop :=
  exists
  (Node TxId : Type) (_ : DecidableEq Node) (_ : DecidableEq TxId) (_ : Bootstrap Node),
  exists
  (nodes : List Node) (trace : GlobalTrace Node TxId) (state : Model.State Node TxId),
  exists (node : Node) (nodeState : NodeState Node TxId),
    trace.Valid (Model.transitionSystem nodes)
    /\ state ∈ trace.states
    /\ (node, nodeState) ∈ state.nodes
    /\ 0 < nodeState.commitIndex

/-- Each step of a valid trace extends every node's committed log. This is
`CommittedLogAppendOnlyProp` in `tla/consensus/ccfraft.tla`. -/
def CommittedLogAppendOnly : Prop :=
  forall (Node TxId : Type) [DecidableEq Node] [DecidableEq TxId] [Bootstrap Node],
  forall (nodes : List Node) (trace : GlobalTrace Node TxId) (step : Nat),
  forall (before after : Model.State Node TxId),
  forall (node : Node) (beforeState afterState : NodeState Node TxId),
    (trace.Valid (Model.transitionSystem nodes)
      /\ trace.states[step]? = some before
      /\ trace.states[step + 1]? = some after
      /\ (node, beforeState) ∈ before.nodes
      /\ (node, afterState) ∈ after.nodes)
    -> beforeState.committedLog <+: afterState.committedLog

/-- Witness: a valid trace has a step that strictly extends a committed log. -/
def CommittedLogAppendOnlyWitness : Prop :=
  exists
  (Node TxId : Type) (_ : DecidableEq Node) (_ : DecidableEq TxId) (_ : Bootstrap Node),
  exists (nodes : List Node) (trace : GlobalTrace Node TxId) (step : Nat),
  exists (before after : Model.State Node TxId),
  exists (node : Node) (beforeState afterState : NodeState Node TxId),
    trace.Valid (Model.transitionSystem nodes)
    /\ trace.states[step]? = some before
    /\ trace.states[step + 1]? = some after
    /\ (node, beforeState) ∈ before.nodes
    /\ (node, afterState) ∈ after.nodes
    /\ beforeState.committedLog.length < afterState.committedLog.length

end CCFRaft.Properties
