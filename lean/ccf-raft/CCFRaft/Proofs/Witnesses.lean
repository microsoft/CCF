-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFRaft.Properties
import CCFRaft.Proofs.Concrete

set_option autoImplicit false

/-!
Concrete executions satisfying the premises of each property. The kernel
evaluates every step, so each witness is a real trace of the model.
-/

namespace CCFRaft.Proofs.Witnesses

open Shared Shared.Execution Shared.MultiNodeTransitionSystem
open CCFRaft.Model.Local (NodeState Bootstrap initialNodeState)

section Runs

variable {State Action : Type}

/-- The states visited by choosing each action from the current state. -/
def runTrace (system : TransitionSystem State Action) (start : State)
    : List (State -> Action) -> List State
  | [] => [start]
  | choose :: rest =>
      match system.step start (choose start) with
      | some next => start :: runTrace system next rest
      | none => [start]

/-- The final state of `runTrace`, when every chosen action is enabled. -/
def run (system : TransitionSystem State Action) (start : State)
    : List (State -> Action) -> Option State
  | [] => some start
  | choose :: rest =>
      (system.step start (choose start)).bind fun next => run system next rest

theorem runTrace_head (system : TransitionSystem State Action) (start : State)
    (choices : List (State -> Action))
    : (runTrace system start choices)[0]? = some start := by
  cases choices with
  | nil => rfl
  | cons choose rest =>
      simp only [runTrace]
      split <;> rfl

theorem runTrace_steps (system : TransitionSystem State Action) (start : State)
    (choices : List (State -> Action))
    : forall i before after,
        (runTrace system start choices)[i]? = some before
        -> (runTrace system start choices)[i + 1]? = some after
        -> exists action, system.step before action = some after := by
  induction choices generalizing start with
  | nil =>
      intro i before after _ second
      cases i <;> simp [runTrace] at second
  | cons choose rest ih =>
      intro i before after first second
      rcases stepped : system.step start (choose start) with _ | next
      · simp only [runTrace, stepped] at second
        cases i <;> simp at second
      · simp only [runTrace, stepped] at first second
        cases i with
        | zero =>
            have head := runTrace_head system next rest
            simp only [List.getElem?_cons_zero, Option.some.injEq] at first
            simp only [Nat.zero_add, List.getElem?_cons_succ, head, Option.some.injEq] at second
            subst first second
            exact ⟨choose start, stepped⟩
        | succ i =>
            exact ih next i before after (by simpa using first) (by simpa using second)

theorem runTrace_valid {system : TransitionSystem State Action} {start : State}
    (initialized : system.init start) (choices : List (State -> Action))
    : (⟨runTrace system start choices⟩ : Trace State).Valid system :=
  ⟨
    ⟨start, runTrace_head system start choices, initialized⟩,
    runTrace_steps system start choices
  ⟩

theorem run_mem {system : TransitionSystem State Action} {start final : State}
    {choices : List (State -> Action)} (finished : run system start choices = some final)
    : final ∈ runTrace system start choices := by
  induction choices generalizing start with
  | nil =>
      simp only [run, Option.some.injEq] at finished
      subst finished
      simp [runTrace]
  | cons choose rest ih =>
      simp only [run, Option.bind_eq_some_iff] at finished
      obtain ⟨next, stepped, rest⟩ := finished
      simp only [runTrace, stepped]
      exact List.mem_cons_of_mem _ (ih rest)

theorem runTrace_get {system : TransitionSystem State Action} {start final : State}
    {choices : List (State -> Action)} {index : Nat} (bounded : index <= choices.length)
    (finished : run system start (choices.take index) = some final)
    : (runTrace system start choices)[index]? = some final := by
  induction choices generalizing start index with
  | nil =>
      have zero : index = 0 := by simpa using bounded
      subst zero
      simp only [List.take_nil, run, Option.some.injEq] at finished
      subst finished
      rfl
  | cons choose rest ih =>
      cases index with
      | zero =>
          simp only [List.take_zero, run, Option.some.injEq] at finished
          subst finished
          exact runTrace_head system start _
      | succ index =>
          simp only [List.take_succ_cons, run, Option.bind_eq_some_iff] at finished
          obtain ⟨next, stepped, rest⟩ := finished
          simp only [runTrace, stepped, List.getElem?_cons_succ]
          exact ih (by simpa using bounded) rest

end Runs

/-- Nodes are numbered; bootstrap membership and leader vary per witness. -/
@[reducible]
def bootstrapOf (configuration : Finset Nat) (leader : Nat)
    (member : leader ∈ configuration)
    : Bootstrap Nat where
  configuration
  leader
  leader_mem := member

/-- Every listed node in its initial state, all active, with an empty network. -/
def start [Bootstrap Nat] (nodes : List Nat) : CCFRaft.Model.State Nat Nat :=
  { nodes := nodes.map fun node => (node, initialNodeState node), active := nodes }

theorem start_initial [Bootstrap Nat] {nodes : List Nat} (distinct : nodes.Nodup)
    : (CCFRaft.Model.transitionSystem (TxId := Nat) nodes).init (start nodes) := by
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
  | [] => .local 0 .timeout

/-- Take `input` at `node` regardless of the current state. -/
def input (node : Nat) (input : CCFRaft.Model.Local.Input Nat Nat)
    : CCFRaft.Model.State Nat Nat -> CCFRaft.Model.Action Nat Nat :=
  fun _ => .local node input

theorem member_of_nodeState {state : CCFRaft.Model.State Nat Nat} {node : Nat}
    (present : (nodeState state node).isSome)
    : (node, (nodeState state node).get present) ∈ state.nodes := by
  generalize fetched : (nodeState state node).get present = value
  have found : nodeState state node = some value := by
    rw [← fetched]
    exact (Option.some_get present).symm
  simp only [nodeState, Option.map_eq_some_iff] at found
  obtain ⟨⟨key, stored⟩, located, same⟩ := found
  simp only at same
  subst same
  have keyEq : key = node := by simpa using List.find?_some located
  subst keyEq
  exact List.mem_of_find?_eq_some located

section Election

local instance : Bootstrap Nat := bootstrapOf {0, 1, 2} 0 (by decide)

/-- Node 1 wins term 3 with node 2's vote while node 0 still leads term 2. -/
def electionChoices
    : List (CCFRaft.Model.State Nat Nat -> CCFRaft.Model.Action Nat Nat) :=
  [
    input 1 .timeout,
    input 1 (.requestVote 2),
    deliverOldest,
    deliverOldest,
    input 1 .becomeLeader
  ]

def electionSystem := CCFRaft.Model.transitionSystem (TxId := Nat) [0, 1, 2]

theorem election_finished
    : (run electionSystem (start [0, 1, 2]) electionChoices).isSome := by
  decide

def electionFinal : CCFRaft.Model.State Nat Nat :=
  (run electionSystem (start [0, 1, 2]) electionChoices).get election_finished

theorem election_present (node : Nat) (listed : node ∈ [0, 1, 2])
    : (nodeState electionFinal node).isSome := by
  simp only [List.mem_cons, List.not_mem_nil, or_false] at listed
  rcases listed with rfl | rfl | rfl <;> decide

end Election

theorem election_safety_witness : Properties.ElectionSafetyWitness := by
  let _ : Bootstrap Nat := bootstrapOf {0, 1, 2} 0 (by decide)
  refine ⟨
    Nat,
    Nat,
    inferInstance,
    inferInstance,
    bootstrapOf {0, 1, 2} 0 (by decide),
    [0, 1, 2],
    ⟨runTrace electionSystem (start [0, 1, 2]) electionChoices⟩,
    electionFinal,
    0,
    1,
    (nodeState electionFinal 0).get (election_present 0 (by simp)),
    (nodeState electionFinal 1).get (election_present 1 (by simp)),
    runTrace_valid (start_initial (by decide)) _,
    run_mem (Option.some_get _).symm,
    member_of_nodeState _,
    member_of_nodeState _,
    by decide,
    by decide,
    by decide
  ⟩

section Commit

local instance : Bootstrap Nat := bootstrapOf {0, 1} 0 (by decide)

/-- Node 0 commits the bootstrap signature with node 1, then tells node 1. -/
def commitChoices : List (CCFRaft.Model.State Nat Nat -> CCFRaft.Model.Action Nat Nat) :=
  [
    input 0 .initializeConfiguration,
    input 0 .signCommittableMessages,
    input 0 (.appendEntries 1 2),
    deliverOldest,
    deliverOldest,
    input 0 .advanceCommitIndex,
    input 0 (.appendEntries 1 2),
    deliverOldest
  ]

def commitSystem := CCFRaft.Model.transitionSystem (TxId := Nat) [0, 1]

theorem commit_finished : (run commitSystem (start [0, 1]) commitChoices).isSome := by
  decide

def commitFinal : CCFRaft.Model.State Nat Nat :=
  (run commitSystem (start [0, 1]) commitChoices).get commit_finished

theorem commit_present (node : Nat) (listed : node ∈ [0, 1])
    : (nodeState commitFinal node).isSome := by
  simp only [List.mem_cons, List.not_mem_nil, or_false] at listed
  rcases listed with rfl | rfl <;> decide

theorem commit_leader_committed
    : (run commitSystem (start [0, 1]) (commitChoices.take 6)).isSome := by
  decide

/-- The state after node 0 advances its commit index, before node 1 learns it. -/
def commitLeaderCommitted : CCFRaft.Model.State Nat Nat :=
  (run commitSystem (start [0, 1]) (commitChoices.take 6)).get commit_leader_committed

theorem commit_leader_present : (nodeState commitLeaderCommitted 0).isSome := by decide

end Commit

/-- Node 0 has committed in one state, and node 1 in a later one. -/
theorem committed_logs_prefix_witness : Properties.CommittedLogsPrefixWitness := by
  let _ : Bootstrap Nat := bootstrapOf {0, 1} 0 (by decide)
  refine ⟨
    Nat,
    Nat,
    inferInstance,
    inferInstance,
    bootstrapOf {0, 1} 0 (by decide),
    [0, 1],
    ⟨runTrace commitSystem (start [0, 1]) commitChoices⟩,
    commitLeaderCommitted,
    commitFinal,
    0,
    1,
    (nodeState commitLeaderCommitted 0).get commit_leader_present,
    (nodeState commitFinal 1).get (commit_present 1 (by simp)),
    runTrace_valid (start_initial (by decide)) _,
    List.mem_of_getElem? (runTrace_get (by decide) (Option.some_get _).symm),
    run_mem (Option.some_get _).symm,
    member_of_nodeState _,
    member_of_nodeState _,
    by decide,
    by decide,
    by decide
  ⟩

section Single

local instance : Bootstrap Nat := bootstrapOf {0} 0 (by decide)

/-- A single bootstrap leader commits its first signature. -/
def singleChoices : List (CCFRaft.Model.State Nat Nat -> CCFRaft.Model.Action Nat Nat) :=
  [
    input 0 .initializeConfiguration,
    input 0 .signCommittableMessages,
    input 0 .advanceCommitIndex
  ]

def singleSystem := CCFRaft.Model.transitionSystem (TxId := Nat) [0]

theorem single_finished : (run singleSystem (start [0]) singleChoices).isSome := by
  decide

def singleFinal : CCFRaft.Model.State Nat Nat :=
  (run singleSystem (start [0]) singleChoices).get single_finished

theorem single_final_present : (nodeState singleFinal 0).isSome := by decide

end Single

theorem committed_frontier_is_signature_witness
    : Properties.CommittedFrontierIsSignatureWitness := by
  let _ : Bootstrap Nat := bootstrapOf {0} 0 (by decide)
  exact ⟨
    Nat,
    Nat,
    inferInstance,
    inferInstance,
    bootstrapOf {0} 0 (by decide),
    [0],
    ⟨runTrace singleSystem (start [0]) singleChoices⟩,
    singleFinal,
    0,
    (nodeState singleFinal 0).get single_final_present,
    runTrace_valid (start_initial (by decide)) _,
    run_mem (Option.some_get _).symm,
    member_of_nodeState _,
    by decide
  ⟩

end CCFRaft.Proofs.Witnesses
