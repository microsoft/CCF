module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import CCFRaft.Model
public import CCFRaft.ProofTLA.Config

import all Init.Control.State
import all Init.Data.List.Sort.Basic
import all Mathlib.Data.List.Sort

@[expose] public section

/-!
Concrete executions for the `PropertiesTLA` witnesses. The kernel evaluates
every step, so each witness is a real reachable state or step of the model.
Each witness restates its `PropertiesTLA` claim, which checks it against that
definition.
-/

namespace CCFRaft.ProofTLA.Witnesses

open CCF CCF.MultiNodeTransitionSystem
open CCFRaft.Model.Node (NodeState InitialConfig initialNodeState)

section Runs

variable {State Action : Type}

/-- The final state after choosing each action from the current state, when
every chosen action is enabled. -/
def run (system : TransitionSystem State Action) (start : State)
    : List (State -> Action) -> Option State
  | [] => some start
  | choose :: rest =>
      (system.step start (choose start)).bind fun next => run system next rest

theorem run_reachable {system : TransitionSystem State Action} {start final : State}
    {choices : List (State -> Action)} (reachable : system.Reachable start)
    (finished : run system start choices = some final)
    : system.Reachable final := by
  induction choices generalizing start with
  | nil =>
      simp only [run, Option.some.injEq] at finished
      subst finished
      exact reachable
  | cons choose rest ih =>
      simp only [run, Option.bind_eq_some_iff] at finished
      obtain ⟨next, stepped, rest⟩ := finished
      exact ih (.step reachable stepped) rest

end Runs

/-- Nodes are numbered; bootstrap membership and leader vary per witness. -/
@[reducible]
def bootstrapOf (configuration : Finset Nat) (leader : Nat)
    (member : leader ∈ configuration)
    : InitialConfig Nat where
  configuration
  leader
  leader_mem := member

/-- Every listed node in its initial state, all active, with an empty network. -/
def start [InitialConfig Nat] (nodes : List Nat) : CCFRaft.Model.State Nat Nat :=
  {
    nodes := nodes.map fun node => (node, initialNodeState (inferInstance) node),
    active := nodes
  }

theorem start_initial [InitialConfig Nat] {nodes : List Nat} (distinct : nodes.Nodup)
    : (CCFRaft.Model.transitionSystem (inferInstance) (TxId := Nat) nodes).init
        (start nodes) := by
  refine ⟨
    distinct,
    by simp [start, Function.comp_def],
    distinct,
    fun _ member => member,
    rfl,
    ?_
  ⟩
  intro entry member
  obtain ⟨node, _, rfl⟩ := List.mem_map.mp member
  rfl

/-- Deliver the oldest envelope in the network. -/
def deliverOldest (state : CCFRaft.Model.State Nat Nat) : CCFRaft.Model.Action Nat Nat :=
  match state.network with
  | envelope :: _ => .deliver envelope
  | [] => .local 0 (.timeout .election)

/-- Take `input` at `node` regardless of the current state. -/
def input (node : Nat) (input : CCFRaft.Model.Node.Input Nat Nat)
    : CCFRaft.Model.State Nat Nat -> CCFRaft.Model.Action Nat Nat :=
  fun _ => .local node input

theorem mem_of_nodeState {state : CCFRaft.Model.State Nat Nat} {node : Nat}
    {value : NodeState Nat Nat} (found : nodeState state node = some value)
    : (node, value) ∈ state.nodes := by
  simp only [nodeState, Option.map_eq_some_iff] at found
  obtain ⟨⟨key, stored⟩, located, same⟩ := found
  simp only at same
  subst same
  have keyEq : key = node := by simpa using List.find?_some located
  subst keyEq
  exact List.mem_of_find?_eq_some located

theorem member_of_nodeState {state : CCFRaft.Model.State Nat Nat} {node : Nat}
    (present : (nodeState state node).isSome)
    : (node, (nodeState state node).get present) ∈ state.nodes :=
  mem_of_nodeState (Option.some_get present).symm

/-- `Finset.sort` computed by insertion sort. The kernel cannot evaluate the
well-founded `List.mergeSort` behind `Finset.sort`, but it can evaluate this. -/
def insertionSorted {α : Type} [LinearOrder α] (s : Finset α) : List α :=
  Quot.liftOn s.val (List.insertionSort (· ≤ ·))
    fun _ _ perm =>
      ((List.perm_insertionSort _ _).trans
        (perm.trans (List.perm_insertionSort _ _).symm)).eq_of_pairwise'
        (List.pairwise_insertionSort _ _) (List.pairwise_insertionSort _ _)

theorem sort_eq_insertionSorted {α : Type} [LinearOrder α] (s : Finset α)
    : s.sort = insertionSorted s := by
  obtain ⟨⟨list⟩, _⟩ := s
  exact List.mergeSort_eq_insertionSort _ list

/-- Unfold a concrete run down to the model's broadcasts and replace each
`Finset.sort` with `insertionSorted`, so that `decide` can evaluate the run. -/
macro "sort_by_insertion" : tactic =>
  `(tactic| simp only [run, CCFRaft.Model.transitionSystem, MultiNodeTransitionSystem.lift,
    MultiNodeTransitionSystem.next, CCFRaft.Model.protocol, CCFRaft.Model.Node.step,
    CCFRaft.Model.Node.act, CCFRaft.Model.Node.receive,
    CCFRaft.Model.Node.startElection, CCFRaft.Model.Node.becomePreVoteCandidate,
    CCFRaft.Model.Node.becomeCandidate, CCFRaft.Model.Node.electIfQuorum,
    CCFRaft.Model.Node.becomeLeader, CCFRaft.Model.Node.broadcastToOthers,
    CCFRaft.Model.Node.advanceCommit, CCFRaft.Model.Node.nominateSuccessor,
    CCFRaft.Model.Node.findSuccessor, CCFRaft.Model.Node.appendBatch,
    CCFRaft.Model.Node.appendEntry,
    CCFRaft.Model.Node.handleAppendEntriesRequest,
    CCFRaft.Model.Node.handleAppendEntriesResponse,
    CCFRaft.Model.Node.handleRequestVoteResponse,
    CCFRaft.Model.Node.handleRequestPreVoteResponse,
    CCFRaft.Model.Node.handleProposeVoteRequest, sort_eq_insertionSorted])

section Commit

local instance : InitialConfig Nat := bootstrapOf {0, 1} 0 (by decide)

/-- Node 0 commits the bootstrap signature with node 1, then tells node 1. -/
def commitChoices : List (CCFRaft.Model.State Nat Nat -> CCFRaft.Model.Action Nat Nat) :=
  [
    input 0 (.append [.signature]),
    input 0 (.sendEntries 1 2),
    deliverOldest,
    deliverOldest,
    input 0 (.sendEntries 1 2),
    deliverOldest
  ]

def commitSystem := CCFRaft.Model.transitionSystem (inferInstance) (TxId := Nat) [0, 1]

theorem commit_finished : (run commitSystem (start [0, 1]) commitChoices).isSome := by
  decide

def commitFinal : CCFRaft.Model.State Nat Nat :=
  (run commitSystem (start [0, 1]) commitChoices).get commit_finished

theorem commit_present (node : Nat) (listed : node ∈ [0, 1])
    : (nodeState commitFinal node).isSome := by
  simp only [List.mem_cons, List.not_mem_nil, or_false] at listed
  rcases listed with rfl | rfl <;> decide

end Commit

section Single

local instance : InitialConfig Nat := bootstrapOf {0} 0 (by decide)

/-- A single bootstrap leader commits its first signature. -/
def singleChoices : List (CCFRaft.Model.State Nat Nat -> CCFRaft.Model.Action Nat Nat) :=
  [input 0 (.append [.signature])]

def singleSystem := CCFRaft.Model.transitionSystem (inferInstance) (TxId := Nat) [0]

theorem single_finished : (run singleSystem (start [0]) singleChoices).isSome := by
  decide

def singleFinal : CCFRaft.Model.State Nat Nat :=
  (run singleSystem (start [0]) singleChoices).get single_finished

theorem single_final_present : (nodeState singleFinal 0).isSome := by decide

/-- After committing the bootstrap signature, the leader commits a further
transaction and signature in one batch. -/
def extendAction : CCFRaft.Model.Action Nat Nat :=
  .local 0 (.append [.transaction 1 {}, .signature])

theorem extend_enabled : (singleSystem.step singleFinal extendAction).isSome := by
  unfold singleSystem singleFinal singleChoices extendAction
  sort_by_insertion
  decide

def extendFinal : CCFRaft.Model.State Nat Nat :=
  (singleSystem.step singleFinal extendAction).get extend_enabled

theorem extend_final_present : (nodeState extendFinal 0).isSome := by
  unfold extendFinal singleSystem singleFinal singleChoices extendAction
  sort_by_insertion
  decide

theorem extend_committed
    : ((nodeState singleFinal 0).get single_final_present).committedLog ≠ []
      /\ ((nodeState singleFinal 0).get single_final_present).committedLog.length
          < ((nodeState extendFinal 0).get extend_final_present).committedLog.length := by
  unfold extendFinal singleSystem singleFinal singleChoices extendAction
  sort_by_insertion
  decide

end Single

/-- `PropertiesTLA.LogInvWitness`: nodes 0 and 1 have both committed. -/
theorem logInv_witness
    : exists (Node TxId : Type),
    exists (_ : DecidableEq Node) (_ : DecidableEq TxId),
    exists (_ : Inhabited TxId) (_ : LinearOrder Node),
    exists (config : InitialConfig Node),
    exists (nodes : List Node) (state : CCFRaft.Model.State Node TxId),
    exists (left right : Node) (leftState rightState : NodeState Node TxId),
      (CCFRaft.Model.transitionSystem config nodes).Reachable state
      /\ (left, leftState) ∈ state.nodes
      /\ (right, rightState) ∈ state.nodes
      /\ left ≠ right
      /\ leftState.committedLog ≠ []
      /\ rightState.committedLog ≠ [] := by
  let _ : InitialConfig Nat := bootstrapOf {0, 1} 0 (by decide)
  exact ⟨
    Nat,
    Nat,
    inferInstance,
    inferInstance,
    inferInstance,
    inferInstance,
    bootstrapOf {0, 1} 0 (by decide),
    [0, 1],
    commitFinal,
    0,
    1,
    (nodeState commitFinal 0).get (commit_present 0 (by simp)),
    (nodeState commitFinal 1).get (commit_present 1 (by simp)),
    run_reachable (.initial (start_initial (by decide))) (Option.some_get _).symm,
    member_of_nodeState _,
    member_of_nodeState _,
    by decide,
    by decide,
    by decide
  ⟩

/-- `PropertiesTLA.CommittedLogAppendOnlyPropWitness`: a single leader's
nonempty committed log grows in one batch append. -/
theorem committedLogAppendOnlyProp_witness
    : exists (Node TxId : Type),
    exists (_ : DecidableEq Node) (_ : DecidableEq TxId),
    exists (_ : Inhabited TxId) (_ : LinearOrder Node),
    exists (config : InitialConfig Node),
    exists
    (nodes : List Node) (before after : CCFRaft.Model.State Node TxId) (action
                                                                        : CCFRaft.Model.Action
                                                                            Node TxId),
    exists (node : Node) (nodeBefore nodeAfter : NodeState Node TxId),
      (CCFRaft.Model.transitionSystem config nodes).Reachable before
      /\ (CCFRaft.Model.transitionSystem config nodes).step before action = some after
      /\ (node, nodeBefore) ∈ before.nodes
      /\ (node, nodeAfter) ∈ after.nodes
      /\ nodeBefore.committedLog ≠ []
      /\ nodeBefore.committedLog.length < nodeAfter.committedLog.length := by
  let _ : InitialConfig Nat := bootstrapOf {0} 0 (by decide)
  exact ⟨
    Nat,
    Nat,
    inferInstance,
    inferInstance,
    inferInstance,
    inferInstance,
    bootstrapOf {0} 0 (by decide),
    [0],
    singleFinal,
    extendFinal,
    extendAction,
    0,
    (nodeState singleFinal 0).get single_final_present,
    (nodeState extendFinal 0).get extend_final_present,
    run_reachable (.initial (start_initial (by decide)))
      (Option.some_get single_finished).symm,
    (Option.some_get extend_enabled).symm,
    member_of_nodeState _,
    member_of_nodeState _,
    extend_committed.1,
    extend_committed.2
  ⟩

end CCFRaft.ProofTLA.Witnesses
