module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import CCFRaft.Model
public import CCF.Execution
public import CCFRaft.ProofTLA.CommittedLogAppendOnlyProp
public import CCFRaft.ProofTLA.LogInv
public import CCFRaft.ProofTLA.Witnesses

@[expose] public section

/-!
Lean counterparts of `LogInv` and `CommittedLogAppendOnlyProp` in
`tla/consensus/ccfraft.tla`, stated in the style of `Properties.lean` and proved
in `CCFRaft/ProofTLA/`. Each has a `Witness` claim exhibiting a nontrivial valid
execution relevant to the property.

The statements match the TLA+ semantically, not syntactically. `Spec` is a
valid trace of `Model.transitionSystem`, without `Fairness`; `Servers` are the
nodes in a state; `Committed(i)` is `committedLog`; `IsPrefix` is `<+:`.
`[][A]_vars` becomes a claim about every step between consecutive states, whose
stuttering case holds trivially. The Lean model is not proved equivalent to the
TLA+ specification.
-/

namespace CCFRaft.PropertiesTLA

abbrev GlobalTrace (Node TxId : Type) := CCF.Execution.Trace (Model.State Node TxId)

open Model.Node

/-- `LogInv`: in every state, the committed logs of any two nodes are
prefix-comparable. -/
def LogInv : Prop :=
  forall (Node TxId : Type) [DecidableEq Node] [DecidableEq TxId] [Inhabited TxId]
          [LinearOrder Node],
  forall (config : InitialConfig Node),
  forall (nodes : List Node) (trace : GlobalTrace Node TxId)
          (state : Model.State Node TxId),
  forall (left right : Node) (leftState rightState : NodeState Node TxId),
    (trace.Valid (Model.transitionSystem config nodes)
      /\ state ∈ trace.states
      /\ (left, leftState) ∈ state.nodes
      /\ (right, rightState) ∈ state.nodes)
    -> leftState.committedLog <+: rightState.committedLog
        \/ rightState.committedLog <+: leftState.committedLog

/-- Witness: a valid trace has a state in which two distinct nodes have
nonempty committed logs. -/
def LogInvWitness : Prop :=
  exists (Node TxId : Type),
  exists (_ : DecidableEq Node) (_ : DecidableEq TxId),
  exists (_ : Inhabited TxId) (_ : LinearOrder Node),
  exists (config : InitialConfig Node),
  exists
  (nodes : List Node) (trace : GlobalTrace Node TxId) (state : Model.State Node TxId),
  exists (left right : Node) (leftState rightState : NodeState Node TxId),
    trace.Valid (Model.transitionSystem config nodes)
    /\ state ∈ trace.states
    /\ (left, leftState) ∈ state.nodes
    /\ (right, rightState) ∈ state.nodes
    /\ left ≠ right
    /\ leftState.committedLog ≠ []
    /\ rightState.committedLog ≠ []

/-- `CommittedLogAppendOnlyProp`: every step of a valid trace extends or keeps
each node's committed log. -/
def CommittedLogAppendOnlyProp : Prop :=
  forall (Node TxId : Type) [DecidableEq Node] [DecidableEq TxId] [Inhabited TxId]
          [LinearOrder Node],
  forall (config : InitialConfig Node),
  forall (nodes : List Node) (trace : GlobalTrace Node TxId) (index : Nat),
  forall (before after : Model.State Node TxId),
  forall (node : Node) (nodeBefore nodeAfter : NodeState Node TxId),
    (trace.Valid (Model.transitionSystem config nodes)
      /\ trace.states[index]? = some before
      /\ trace.states[index + 1]? = some after
      /\ (node, nodeBefore) ∈ before.nodes
      /\ (node, nodeAfter) ∈ after.nodes)
    -> nodeBefore.committedLog <+: nodeAfter.committedLog

/-- Witness: a step of a valid trace strictly extends a node's nonempty
committed log. -/
def CommittedLogAppendOnlyPropWitness : Prop :=
  exists (Node TxId : Type),
  exists (_ : DecidableEq Node) (_ : DecidableEq TxId),
  exists (_ : Inhabited TxId) (_ : LinearOrder Node),
  exists (config : InitialConfig Node),
  exists (nodes : List Node) (trace : GlobalTrace Node TxId) (index : Nat),
  exists (before after : Model.State Node TxId),
  exists (node : Node) (nodeBefore nodeAfter : NodeState Node TxId),
    trace.Valid (Model.transitionSystem config nodes)
    /\ trace.states[index]? = some before
    /\ trace.states[index + 1]? = some after
    /\ (node, nodeBefore) ∈ before.nodes
    /\ (node, nodeAfter) ∈ after.nodes
    /\ nodeBefore.committedLog ≠ []
    /\ nodeBefore.committedLog.length < nodeAfter.committedLog.length

/-- `THEOREM Spec => []LogInv` -/
theorem spec_logInv : LogInv :=
  fun _ _ _ _ _ _ config _ _ _ _ _ _ _ ⟨valid, member, leftMember, rightMember⟩ =>
    ProofTLA.logInv config valid member leftMember rightMember

theorem logInv_witness : LogInvWitness :=
  ProofTLA.Witnesses.logInv_witness

/-- `THEOREM Spec => CommittedLogAppendOnlyProp` -/
theorem spec_committedLogAppendOnlyProp : CommittedLogAppendOnlyProp :=
  fun _ _ _ _ _ _ config _ _ _ _ _ _ _ _
      ⟨valid, atBefore, atAfter, beforeMember, afterMember⟩ =>
    ProofTLA.committedLog_step config valid atBefore atAfter beforeMember afterMember

theorem committedLogAppendOnlyProp_witness : CommittedLogAppendOnlyPropWitness :=
  ProofTLA.Witnesses.committedLogAppendOnlyProp_witness

end CCFRaft.PropertiesTLA
