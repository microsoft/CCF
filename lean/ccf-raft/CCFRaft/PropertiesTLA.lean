module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import CCFRaft.Model
public import CCF.Execution
public import CCFRaft.ProofTLA.AppendOnlyProp
public import CCFRaft.ProofTLA.LogInv

@[expose] public section

/-!
# TLA+ safety properties

Lean counterparts of `LogInv` and `CommittedLogAppendOnlyProp` in
`tla/consensus/ccfraft.tla`, and of `AppendOnlyProp` in `tla/consensus/abs.tla`
under ccfraft's `MappingToAbs` refinement mapping. Each theorem delegates to
`CCFRaft/ProofTLA/`. The Lean model is not proved equivalent to the TLA+
specification; these statements only read the TLA+ formulas in this model.

Reading the TLA+ in this model:

- `Spec`: a valid trace of `Model.transitionSystem config nodes`. `Fairness` is
  omitted; it does not constrain safety properties.
- `Servers`: the keys of `state.nodes`, which is `nodes` in every state of a
  valid trace, so inactive nodes are included.
- `log[i]`, `commitIndex[i]`: the fields of `i`'s entry in `state.nodes`.
- `IsPrefix`: `<+:`.
- `[]P`: `P` holds in every state of every valid trace (`Always`).
- `[][A]_v`: every step between consecutive states of a valid trace is an `A`
  step or leaves `v` unchanged (`AlwaysStep`, with the disjunction spelled out).

Finite traces suffice: these are safety properties, so a behaviour violates one
exactly when some finite prefix does.

`abs.tla`'s `AppendOnlyProp` is a property of the abstract specification. Read
through `MappingToAbs`, it says each node's committed terms only grow. It
follows from `CommittedLogAppendOnlyProp` by projecting entries to their terms,
but is weaker: it cannot see a committed entry replaced by one of the same term.
-/

namespace CCFRaft.PropertiesTLA

open Model.Node

variable {Node TxId : Type}

abbrev Trace (Node TxId : Type) := CCF.Execution.Trace (Model.State Node TxId)

/-- `[]P` over the states of a trace. -/
def Always (trace : Trace Node TxId) (P : Model.State Node TxId -> Prop) : Prop :=
  forall state, state ∈ trace.states -> P state

/-- `[]A` over the steps of a trace. -/
def AlwaysStep (trace : Trace Node TxId)
    (A : Model.State Node TxId -> Model.State Node TxId -> Prop)
    : Prop :=
  forall (k : Nat) (before after : Model.State Node TxId),
    trace.states[k]? = some before -> trace.states[k + 1]? = some after -> A before after

/-- ccfraft.tla `Committed(i)`: `log[i]` up to `commitIndex[i]`, over whole entries. -/
def Committed (s : NodeState Node TxId) : List (Entry Node TxId) :=
  s.log.take s.commitIndex

/-- ccfraft.tla `LogInv`. -/
def LogInv (state : Model.State Node TxId) : Prop :=
  forall (i j : Node) (si sj : NodeState Node TxId),
    (i, si) ∈ state.nodes
    -> (j, sj) ∈ state.nodes
    -> Committed si <+: Committed sj \/ Committed sj <+: Committed si

/-- ccfraft.tla `CommittedLogAppendOnlyProp`:
`[][\A i \in Servers : IsPrefix(Committed(i), Committed(i)')]_vars`. -/
def CommittedLogAppendOnlyStep (before after : Model.State Node TxId) : Prop :=
  (forall (i : Node) (si si' : NodeState Node TxId),
    (i, si) ∈ before.nodes -> (i, si') ∈ after.nodes -> Committed si <+: Committed si')
  \/ after = before

/-- ccfraft.tla `MappingToAbs`:
`cLogs <- [i \in Servers |-> [j \in 1..commitIndex[i] |-> log[i][j].term]]`. -/
def cLogs (state : Model.State Node TxId) : List (Node × List Nat) :=
  state.nodes.map fun entry => (entry.1, (Committed entry.2).map Entry.term)

/-- abs.tla `AppendOnlyProp`, under `MappingToAbs`:
`[][\A i \in Servers : IsPrefix(cLogs[i], cLogs'[i])]_cLogs`. -/
def AppendOnlyStep (before after : Model.State Node TxId) : Prop :=
  (forall (i : Node) (c c' : List Nat),
    (i, c) ∈ cLogs before -> (i, c') ∈ cLogs after -> c <+: c')
  \/ cLogs after = cLogs before

variable [DecidableEq Node] [DecidableEq TxId] [Inhabited TxId] [LinearOrder Node]

/-- `THEOREM Spec => []LogInv` -/
theorem spec_logInv (config : InitialConfig Node) (nodes : List Node)
    (trace : Trace Node TxId) (spec : trace.Valid (Model.transitionSystem config nodes))
    : Always trace LogInv :=
  fun _ member _ _ _ _ iMember jMember =>
    ProofTLA.logInv config spec member iMember jMember

/-- `THEOREM Spec => CommittedLogAppendOnlyProp` -/
theorem spec_committedLogAppendOnlyProp (config : InitialConfig Node) (nodes : List Node)
    (trace : Trace Node TxId) (spec : trace.Valid (Model.transitionSystem config nodes))
    : AlwaysStep trace CommittedLogAppendOnlyStep :=
  fun _ _ _ atBefore atAfter =>
    .inl fun _ _ _ => ProofTLA.committedLog_step config spec atBefore atAfter

/-- `Spec => MappingToAbs!AppendOnlyProp` -/
theorem spec_appendOnlyProp (config : InitialConfig Node) (nodes : List Node)
    (trace : Trace Node TxId) (spec : trace.Valid (Model.transitionSystem config nodes))
    : AlwaysStep trace AppendOnlyStep :=
  fun _ _ _ atBefore atAfter =>
    .inl
      fun _ _ _ =>
        ProofTLA.projected_committedLog_step Entry.term config spec atBefore atAfter

end CCFRaft.PropertiesTLA
