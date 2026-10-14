module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import CCFRaft.Properties
public import CCFRaft.Proofs.Concrete

import all Init.Control.State
import all Init.Data.List.Sort.Basic
import all Mathlib.Data.List.Sort

@[expose] public section

/-!
Concrete executions satisfying the premises of each property. The kernel
evaluates every step, so each witness is a real trace of the model.
-/

namespace CCFRaft.Proofs.Witnesses

open CCFRaft.Proofs.Config

open CCF CCF.Execution CCF.MultiNodeTransitionSystem
open CCFRaft.Model.Node (NodeState InitialConfig initialNodeState)

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

def deliverFrom (source target : Nat) (state : CCFRaft.Model.State Nat Nat)
    : CCFRaft.Model.Action Nat Nat :=
  match state.network.find?
          (fun envelope => envelope.source == source && envelope.target == target) with
  | some envelope => .deliver envelope
  | none => deliverOldest state

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
    CCFRaft.Model.Node.appendEntry, CCFRaft.Model.Node.applyTransactionEffect,
    CCFRaft.Model.Node.handleAppendEntriesRequest,
    CCFRaft.Model.Node.handleAppendEntriesResponse,
    CCFRaft.Model.Node.handleRequestVoteResponse,
    CCFRaft.Model.Node.handleRequestPreVoteResponse,
    CCFRaft.Model.Node.handleProposeVoteRequest, sort_eq_insertionSorted])

section Election

local instance : InitialConfig Nat := bootstrapOf {0, 1, 2} 0 (by decide)

/-- Node 1 wins term 3 with node 2's vote while node 0 still leads term 2. -/
def electionChoices
    : List (CCFRaft.Model.State Nat Nat -> CCFRaft.Model.Action Nat Nat) :=
  [input 1 (.timeout .election), deliverFrom 1 2, deliverFrom 2 1]

def electionSystem :=
  CCFRaft.Model.transitionSystem (inferInstance) (TxId := Nat) [0, 1, 2]

/-- Nodes 0 and 1 are both present and both lead. -/
def bothLead (state : CCFRaft.Model.State Nat Nat) : Bool :=
  ((nodeState state 0).any fun local_ => decide (local_.role = .leader))
  && ((nodeState state 1).any fun local_ => decide (local_.role = .leader))

theorem election_run
    : (run electionSystem (start [0, 1, 2]) electionChoices).any bothLead = true := by
  unfold electionSystem electionChoices
  sort_by_insertion
  decide

end Election

theorem election_safety_witness : Properties.ElectionSafetyWitness := by
  let _ : InitialConfig Nat := bootstrapOf {0, 1, 2} 0 (by decide)
  obtain ⟨final, finished, lead⟩ := (Option.any_eq_true _ _).mp election_run
  simp only [bothLead, Bool.and_eq_true, Option.any_eq_true, decide_eq_true_eq] at lead
  obtain ⟨⟨leftState, leftFound, leftLeader⟩, ⟨rightState, rightFound, rightLeader⟩⟩ := lead
  exact ⟨
    Nat,
    Nat,
    inferInstance,
    inferInstance,
    inferInstance,
    inferInstance,
    bootstrapOf {0, 1, 2} 0 (by decide),
    [0, 1, 2],
    ⟨runTrace electionSystem (start [0, 1, 2]) electionChoices⟩,
    final,
    0,
    1,
    leftState,
    rightState,
    runTrace_valid (start_initial (by decide)) _,
    run_mem finished,
    mem_of_nodeState leftFound,
    mem_of_nodeState rightFound,
    leftLeader,
    rightLeader,
    by decide
  ⟩

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

theorem commit_leader_committed
    : (run commitSystem (start [0, 1]) (commitChoices.take 4)).isSome := by
  decide

/-- The state after node 0 advances its commit index, before node 1 learns it. -/
def commitLeaderCommitted : CCFRaft.Model.State Nat Nat :=
  (run commitSystem (start [0, 1]) (commitChoices.take 4)).get commit_leader_committed

theorem commit_leader_present : (nodeState commitLeaderCommitted 0).isSome := by decide

end Commit

/-- Node 0 has committed in one state, and node 1 in a later one. -/
theorem committed_logs_prefix_witness : Properties.CommittedLogsPrefixWitness := by
  let _ : InitialConfig Nat := bootstrapOf {0, 1} 0 (by decide)
  refine ⟨
    Nat,
    Nat,
    inferInstance,
    inferInstance,
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

end Single

theorem committed_frontier_is_signature_witness
    : Properties.CommittedFrontierIsSignatureWitness := by
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
