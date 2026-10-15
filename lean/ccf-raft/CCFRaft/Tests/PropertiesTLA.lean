module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import CCFRaft.PropertiesTLA

@[expose] public section

/-!
Checks that the `PropertiesTLA` statements read the TLA+ definitions as intended.
-/

namespace CCFRaft.Tests.PropertiesTLA

open Model.Node CCFRaft.PropertiesTLA ProofTLA

section Execution

variable {Node TxId : Type} [DecidableEq Node] [DecidableEq TxId] [Inhabited TxId]
  [LinearOrder Node]

example (s : NodeState Node TxId) : Committed s = s.committedLog := rfl

/-- `Servers`: every state of a valid trace holds each configured node exactly once. -/
theorem servers (config : InitialConfig Node) {nodes : List Node}
    {trace : PropertiesTLA.Trace Node TxId}
    (valid : trace.Valid (Model.transitionSystem config nodes))
    {state : Model.State Node TxId} (member : state ∈ trace.states)
    : state.nodes.map Prod.fst = nodes /\ nodes.Nodup := by
  let _ : InitialConfig Node := config
  refine ⟨?_, ?_⟩
  · have reachable := valid.reachable member
    clear member
    induction reachable with
    | initial initialized => exact initialized.2.1
    | @step before after action _ stepped ih =>
        cases action with
        | «local» actor input =>
            obtain ⟨_, _, _, _, _, rfl⟩ := Concrete.step_local stepped
            simpa [Concrete.replaceNode_keys] using ih
        | deliver envelope =>
            obtain ⟨_, _, _, _, _, _, rfl⟩ := Concrete.step_deliver stepped
            simpa [Concrete.replaceNode_keys] using ih
  · obtain ⟨initial, _, initialized⟩ := valid.1
    exact initialized.1

/-- `Committed(i)` is `SubSeq(log[i], 1, commitIndex[i])`: `take` never truncates
at the log's end, since the commit index lies within the log. -/
theorem committed_length (config : InitialConfig Node) {nodes : List Node}
    {trace : PropertiesTLA.Trace Node TxId}
    (valid : trace.Valid (Model.transitionSystem config nodes))
    {state : Model.State Node TxId} (member : state ∈ trace.states) {i : Node}
    {s : NodeState Node TxId} (listed : (i, s) ∈ state.nodes)
    : (Committed s).length = s.commitIndex := by
  let _ : InitialConfig Node := config
  have frontier := Direct.commitFrontier_invariant.reachable (valid.reachable member) i s listed
  simpa [Committed] using frontier.1

-- `[A]_v` admits stuttering steps.
example (s : Model.State Node TxId) : CommittedLogAppendOnlyStep s s := .inr rfl

example (s : Model.State Node TxId) : AppendOnlyStep s s := .inr rfl

end Execution

section Examples

private def logState (log : List (Entry Nat Nat)) (commitIndex : Nat)
    : NodeState Nat Nat where
  role := .none
  currentTerm := 0
  log := log
  commitIndex := commitIndex
  sentIndex := fun _ => 0
  matchIndex := fun _ => 0
  isNewFollower := false
  votedFor := none
  votesGranted := {}

private def oneNode (state : NodeState Nat Nat) : Model.State Nat Nat where
  nodes := [(0, state)]
  active := [0]

private def signed : Entry Nat Nat := { term := 1, content := .signature }

private def written : Entry Nat Nat := { term := 1, content := .transaction 7 {} }

-- `MappingToAbs` keeps only the terms of committed entries.
example : cLogs (oneNode (logState [signed, { signed with term := 2 }] 1)) = [(0, [1])] :=
  rfl

-- `Committed` compares whole entries.
example : Committed (logState [signed] 1) ≠ Committed (logState [written] 1) := by
  decide

-- Shrinking a committed log violates both step properties.
example
    : Not
        (AppendOnlyStep (oneNode (logState [signed] 1))
          (oneNode (logState [signed] 0))) := by
  simp [AppendOnlyStep, cLogs, Committed, oneNode, logState]

example
    : Not
        (CommittedLogAppendOnlyStep (oneNode (logState [signed] 1))
          (oneNode (logState [signed] 0))) := by
  simp [CommittedLogAppendOnlyStep, Committed, oneNode, logState]

-- Rewriting a committed entry's content with the same term is visible only to
-- `CommittedLogAppendOnlyProp`; the abstract log sees terms alone.
example
    : AppendOnlyStep (oneNode (logState [signed] 1)) (oneNode (logState [written] 1)) :=
  .inr rfl

example
    : Not
        (CommittedLogAppendOnlyStep (oneNode (logState [signed] 1))
          (oneNode (logState [written] 1))) := by
  simp [CommittedLogAppendOnlyStep, Committed, oneNode, logState, signed, written]

end Examples

end CCFRaft.Tests.PropertiesTLA
