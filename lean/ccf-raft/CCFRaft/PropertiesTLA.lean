module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import CCFRaft.Model
public import CCFRaft.ProofTLA.CommittedLogAppendOnlyProp
public import CCFRaft.ProofTLA.LogInv
public import CCFRaft.ProofTLA.Witnesses

@[expose] public section

/-!
Lean counterparts of `LogInv` and `CommittedLogAppendOnlyProp` in
`tla/consensus/ccfraft.tla`, proved in `CCFRaft/ProofTLA/`. Each has a `Witness`
claim exhibiting a nontrivial reachable state or step relevant to the property.

The statements match the TLA+ semantically, not syntactically. For a safety
property, `Spec => []P` says `P` holds in every reachable state, and
`Spec => [][A]_vars` says `A` holds on every enabled step from a reachable state
(stuttering steps satisfy it trivially). `Fairness` is irrelevant to both.
Reachability is in `Model.transitionSystem`; `Servers` are the nodes in a state;
`Committed(i)` is `committedLog`; `IsPrefix` is `<+:`. The Lean model is not
proved equivalent to the TLA+ specification.
-/

namespace CCFRaft.PropertiesTLA

open Model.Node

/-- `LogInv`: in every reachable state, the committed logs of any two nodes are
prefix-comparable. -/
def LogInv : Prop :=
  forall (Node TxId : Type) [DecidableEq Node] [DecidableEq TxId] [Inhabited TxId]
          [LinearOrder Node],
  forall (config : InitialConfig Node),
  forall (nodes : List Node) (state : Model.State Node TxId),
  forall (left right : Node) (leftState rightState : NodeState Node TxId),
    ((Model.transitionSystem config nodes).Reachable state
      /\ (left, leftState) ∈ state.nodes
      /\ (right, rightState) ∈ state.nodes)
    -> leftState.committedLog <+: rightState.committedLog
        \/ rightState.committedLog <+: leftState.committedLog

/-- Witness: a reachable state in which two distinct nodes have nonempty
committed logs. -/
def LogInvWitness : Prop :=
  exists (Node TxId : Type),
  exists (_ : DecidableEq Node) (_ : DecidableEq TxId),
  exists (_ : Inhabited TxId) (_ : LinearOrder Node),
  exists (config : InitialConfig Node),
  exists (nodes : List Node) (state : Model.State Node TxId),
  exists (left right : Node) (leftState rightState : NodeState Node TxId),
    (Model.transitionSystem config nodes).Reachable state
    /\ (left, leftState) ∈ state.nodes
    /\ (right, rightState) ∈ state.nodes
    /\ left ≠ right
    /\ leftState.committedLog ≠ []
    /\ rightState.committedLog ≠ []

/-- `CommittedLogAppendOnlyProp`: every enabled step from a reachable state
extends or keeps each node's committed log. -/
def CommittedLogAppendOnlyProp : Prop :=
  forall (Node TxId : Type) [DecidableEq Node] [DecidableEq TxId] [Inhabited TxId]
          [LinearOrder Node],
  forall (config : InitialConfig Node),
  forall (nodes : List Node) (before after : Model.State Node TxId)
          (action : Model.Action Node TxId),
  forall (node : Node) (nodeBefore nodeAfter : NodeState Node TxId),
    ((Model.transitionSystem config nodes).Reachable before
      /\ (Model.transitionSystem config nodes).step before action = some after
      /\ (node, nodeBefore) ∈ before.nodes
      /\ (node, nodeAfter) ∈ after.nodes)
    -> nodeBefore.committedLog <+: nodeAfter.committedLog

/-- Witness: an enabled step from a reachable state strictly extends a node's
nonempty committed log. -/
def CommittedLogAppendOnlyPropWitness : Prop :=
  exists (Node TxId : Type),
  exists (_ : DecidableEq Node) (_ : DecidableEq TxId),
  exists (_ : Inhabited TxId) (_ : LinearOrder Node),
  exists (config : InitialConfig Node),
  exists
  (nodes : List Node) (before after : Model.State Node TxId) (action
                                                              : Model.Action Node TxId),
  exists (node : Node) (nodeBefore nodeAfter : NodeState Node TxId),
    (Model.transitionSystem config nodes).Reachable before
    /\ (Model.transitionSystem config nodes).step before action = some after
    /\ (node, nodeBefore) ∈ before.nodes
    /\ (node, nodeAfter) ∈ after.nodes
    /\ nodeBefore.committedLog ≠ []
    /\ nodeBefore.committedLog.length < nodeAfter.committedLog.length

/-- `THEOREM Spec => []LogInv` -/
theorem spec_logInv : LogInv :=
  fun _ _ _ _ _ _ config _ _ _ _ _ _ ⟨reachable, leftMember, rightMember⟩ =>
    ProofTLA.logInv config reachable leftMember rightMember

theorem logInv_witness : LogInvWitness :=
  ProofTLA.Witnesses.logInv_witness

/-- `THEOREM Spec => CommittedLogAppendOnlyProp` -/
theorem spec_committedLogAppendOnlyProp : CommittedLogAppendOnlyProp :=
  fun _ _ _ _ _ _ config _ _ _ _ _ _ _ ⟨reachable, stepped, beforeMember, afterMember⟩ =>
    ProofTLA.committedLog_step config reachable stepped beforeMember afterMember

theorem committedLogAppendOnlyProp_witness : CommittedLogAppendOnlyPropWitness :=
  ProofTLA.Witnesses.committedLogAppendOnlyProp_witness

end CCFRaft.PropertiesTLA
