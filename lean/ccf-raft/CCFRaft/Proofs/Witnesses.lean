module

public import CCFRaft.Model
public import CCFRaft.Proofs.Concrete
public import CCF.Execution

import all Init.Control.State
import all Init.Data.List.Sort.Basic
import all Mathlib.Data.List.Sort
meta import Lean.Elab.Tactic.Basic
meta import Lean.Meta.Tactic.AuxLemma

@[expose] public section

/-!
Concrete executions satisfying the premises of each property. Each trace runs a
finite stem of enabled actions and then repeats a nonempty cycle of enabled
actions that returns to the stem's final state, so it is a genuine infinite
execution without stuttering. The kernel evaluates every step.
-/

namespace CCFRaft.Proofs.Witnesses

open CCF CCF.Execution CCF.MultiNodeTransitionSystem
open CCFRaft.Model.Node
open CCFRaft.Model (initialNodeState)

section Runs

/-- The final state of choosing each action from the current state, when every
chosen action is enabled. -/
def run (system : TransitionSystem) (start : system.State)
    : List (system.State -> system.Action) -> Option system.State
  | [] => some start
  | choose :: rest =>
      (system.step start (choose start)).bind fun next => run system next rest

/-- Each prefix of a finished run finishes, and its next choice is enabled. -/
theorem run_take_step {system : TransitionSystem} {start final : system.State}
    {choices : List (system.State -> system.Action)}
    (finished : run system start choices = some final) {index : Nat}
    (bounded : index < choices.length)
    : exists before after,
        run system start (choices.take index) = some before
        /\ run system start (choices.take (index + 1)) = some after
        /\ system.step before (choices[index] before) = some after := by
  induction choices generalizing start index with
  | nil => simp at bounded
  | cons choose rest ih =>
      simp only [run, Option.bind_eq_some_iff] at finished
      obtain ⟨next, stepped, finished⟩ := finished
      cases index with
      | zero =>
          refine ⟨start, next, rfl, ?_, stepped⟩
          simp [run, stepped]
      | succ index =>
          obtain ⟨before, after, first, second, enabled⟩ :=
            ih finished (by simpa using bounded)
          exact ⟨
            before,
            after,
            by simpa [run, stepped] using first,
            by simpa [run, stepped] using second,
            by simpa using enabled
          ⟩

/--
The states of running `stem` from `start` and then repeating `cycle` forever.
The default `start` is never used when the runs finish.
-/
def lasso (system : TransitionSystem) (start : system.State)
    (stem cycle : List (system.State -> system.Action)) (index : Nat)
    : system.State :=
  if index < stem.length then
    (run system start (stem.take index)).getD start
  else
    (run system ((run system start stem).getD start)
      (cycle.take ((index - stem.length) % cycle.length))).getD
      start

/-- The lasso as an infinite trace. -/
def lassoStates (system : TransitionSystem) (start : system.State)
    (stem cycle : List (system.State -> system.Action))
    : Stream'.Seq system.State :=
  Stream'.Seq.ofStream (lasso system start stem cycle)

theorem lassoStates_get? {system : TransitionSystem} {start : system.State}
    {stem cycle : List (system.State -> system.Action)} (index : Nat)
    : (lassoStates system start stem cycle).get? index
      = some (lasso system start stem cycle index) :=
  rfl

/-- The action chosen at each position of a lasso. -/
def lassoAction (system : TransitionSystem) (start : system.State)
    (stem cycle : List (system.State -> system.Action)) (nonempty : cycle ≠ [])
    (index : Nat)
    : system.Action :=
  if inStem : index < stem.length then
    stem[index] (lasso system start stem cycle index)
  else
    (cycle[(index - stem.length) % cycle.length
      ]'(Nat.mod_lt _ (List.length_pos_iff.mpr nonempty)))
      (lasso system start stem cycle index)

/-- A finished stem followed by a nonempty cycle back to its final state records
the chosen action at every step of a valid infinite trace. -/
def lassoTrace {system : TransitionSystem} {start final : system.State}
    {stem cycle : List (system.State -> system.Action)} (initialized : system.init start)
    (stemRun : run system start stem = some final)
    (cycleRun : run system final cycle = some final) (nonempty : cycle ≠ [])
    : Trace system := by
  have positive : 0 < cycle.length := List.length_pos_iff.mpr nonempty
  have tail : forall index, stem.length <= index
      -> lasso system start stem cycle index
          = (run system final (cycle.take ((index - stem.length) % cycle.length))).getD
              start := by
    intro index le
    simp [lasso, Nat.not_lt.mpr le, stemRun]
  refine {
    states := lassoStates system start stem cycle
    actions := Stream'.Seq.ofStream (lassoAction system start stem cycle nonempty)
    valid_init := ⟨_, lassoStates_get? 0, ?_⟩
    valid_domains := fun _ => Iff.rfl
    valid_step := ?_
  }
  · show system.init (lasso system start stem cycle 0)
    by_cases empty : stem = []
    · subst empty
      simp only [run, Option.some.injEq] at stemRun
      subst stemRun
      simpa [tail 0 (Nat.zero_le _), run] using initialized
    · simpa [lasso, List.length_pos_iff.mpr empty, run] using initialized
  intro index before action atBefore chosen
  rw [lassoStates_get?, Option.some.injEq] at atBefore
  change some (lassoAction system start stem cycle nonempty index) = some action at chosen
  cases atBefore
  cases chosen
  show system.step (lasso system start stem cycle index)
      (lassoAction system start stem cycle nonempty index)
      = some (lasso system start stem cycle (index + 1))
  by_cases inStem : index < stem.length
  · obtain ⟨before, after, first, second, enabled⟩ := run_take_step stemRun inStem
    have now : lasso system start stem cycle index = before := by
      simp [lasso, inStem, first]
    have next : lasso system start stem cycle (index + 1) = after := by
      by_cases more : index + 1 < stem.length
      · simp [lasso, more, second]
      · have last : index + 1 = stem.length := by omega
        rw [tail _ (by omega), last, Nat.sub_self, Nat.zero_mod]
        rw [last, List.take_length, stemRun] at second
        simp only [Option.some.injEq] at second
        subst second
        simp [run]
    simpa [lassoAction, inStem, now, next] using enabled
  · have offset : (index + 1 - stem.length) % cycle.length
        = ((index - stem.length) % cycle.length + 1) % cycle.length := by
      rw [show index + 1 - stem.length = index - stem.length + 1 by omega, Nat.mod_add_mod]
    have within := Nat.mod_lt (index - stem.length) positive
    obtain ⟨before, after, first, second, enabled⟩ := run_take_step cycleRun within
    simp only [lassoAction, dite_eq_right inStem]
    rw [tail _ (by omega), tail _ (by omega), offset, first]
    by_cases more : (index - stem.length) % cycle.length + 1 < cycle.length
    · rw [Nat.mod_eq_of_lt more, second]
      exact enabled
    · have last : (index - stem.length) % cycle.length + 1 = cycle.length := by omega
      rw [last, Nat.mod_self, List.take_zero]
      rw [last, List.take_length, cycleRun] at second
      simp only [Option.some.injEq] at second
      subst second
      exact enabled

/-- Every state reached by a prefix of the stem occurs in the lasso. -/
theorem lasso_mem {system : TransitionSystem} {start final state : system.State}
    {stem cycle : List (system.State -> system.Action)}
    (stemRun : run system start stem = some final) {index : Nat}
    (bounded : index <= stem.length)
    (reached : run system start (stem.take index) = some state)
    : state ∈ lassoStates system start stem cycle := by
  apply Stream'.Seq.get?_mem (n := index)
  rw [lassoStates_get?, Option.some.injEq]
  by_cases inStem : index < stem.length
  · simp [lasso, inStem, reached]
  · have last : index = stem.length := by omega
    subst last
    rw [List.take_length, stemRun] at reached
    simp only [Option.some.injEq] at reached
    subst reached
    simp [lasso, stemRun, run]

/-- A present option is `some` of its value with any default. -/
theorem eq_some_getD {α : Type} {value : Option α} (present : value.isSome) (default : α)
    : value = some (value.getD default) := by
  cases value <;> simp_all

end Runs

/-- Every listed node in its initial state for `configuration`, with an empty network. -/
def start (configuration : Finset Nat) (nodes : List Nat) : CCFRaft.Model.State :=
  { nodes := nodes.map fun node => (node, initialNodeState configuration node) }

theorem start_initial {configuration : Finset Nat} {nodes : List Nat}
    (nonempty : configuration.Nonempty) (distinct : nodes.Nodup)
    : (CCFRaft.Model.transitionSystem configuration nodes).init
        (start configuration nodes) := by
  refine ⟨
    nonempty,
    by simp [start, Function.comp_def],
    by simpa [start, Function.comp_def],
    rfl,
    ?_
  ⟩
  intro entry member
  obtain ⟨node, _, rfl⟩ := List.mem_map.mp member
  rfl

/-- Deliver the oldest envelope in the network. -/
def deliverOldest (state : CCFRaft.Model.State) : CCFRaft.Model.Action :=
  match state.network with
  | envelope :: _ => .deliver envelope
  | [] => .local 0 (.timeout .election)

def deliverFrom (source target : Nat) (state : CCFRaft.Model.State)
    : CCFRaft.Model.Action :=
  match state.network.find?
          (fun envelope => envelope.source == source && envelope.target == target) with
  | some envelope => .deliver envelope
  | none => deliverOldest state

/-- Take `input` at `node` regardless of the current state. -/
def input (node : Nat) (input : CCFRaft.Model.Node.Input)
    : CCFRaft.Model.State -> CCFRaft.Model.Action :=
  fun _ => .local node input

theorem mem_of_nodeState {state : CCFRaft.Model.State} {node : Nat}
    {value : NodeState} (found : nodeState state node = some value)
    : (node, value) ∈ state.nodes := by
  simp only [nodeState, Option.map_eq_some_iff] at found
  obtain ⟨⟨key, stored⟩, located, same⟩ := found
  simp only at same
  subst same
  have keyEq : key = node := by simpa using List.find?_some located
  subst keyEq
  exact List.mem_of_find?_eq_some located

theorem member_of_nodeState {state : CCFRaft.Model.State} {node : Nat}
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
  `(tactic| simp (maxSteps := 10000000) only [run, CCFRaft.Model.transitionSystem, MultiNodeTransitionSystem.lift,
    MultiNodeTransitionSystem.next, CCFRaft.Model.protocol, CCFRaft.Model.Node.step,
    CCFRaft.Model.Node.act, CCFRaft.Model.Node.receive,
    CCFRaft.Model.Node.startElection, CCFRaft.Model.Node.becomePreVoteCandidate,
    CCFRaft.Model.Node.becomeCandidate, CCFRaft.Model.Node.electIfQuorum,
    CCFRaft.Model.Node.becomePrimary, CCFRaft.Model.Node.broadcastToOthers,
    CCFRaft.Model.Node.advanceCommit, CCFRaft.Model.Node.nominateSuccessor,
    CCFRaft.Model.Node.findSuccessor, CCFRaft.Model.Node.appendBatch,
    CCFRaft.Model.Node.appendEntry,
    CCFRaft.Model.Node.handleAppendEntriesRequest,
    CCFRaft.Model.Node.handleAppendEntriesResponse,
    CCFRaft.Model.Node.handleRequestVoteResponse,
    CCFRaft.Model.Node.handleRequestPreVoteResponse,
    CCFRaft.Model.Node.handleProposeRequestVoteRequest, sort_eq_insertionSorted])

open Lean Elab Tactic Meta in
/-- Close a closed goal `lhs = rhs` by asking only the kernel to check
`Eq.refl lhs`. Concrete states hold functions, so their equality is not
decidable, and the elaborator's definitional unfolding is far slower than the
kernel's on these runs. -/
elab "kernel_rfl" : tactic => closeMainGoalUsing `kernel_rfl fun target _ => do
  let some (type, lhs, _) := target.consumeMData.eq? | throwError "kernel_rfl: not an equality"
  let level <- getLevel type
  let name <- withOptions (Elab.async.set · false) do
    mkAuxLemma [] target (mkApp2 (mkConst ``Eq.refl [level]) type lhs)
  return mkConst name

section Election

abbrev electionSystem := CCFRaft.Model.transitionSystem {0, 1, 2} [0, 1, 2]

def electionStart := start {0, 1, 2} [0, 1, 2]

/-- Node 0 replicates its signed configuration to node 1. Node 1 then wins
pre-vote and term 3 with node 2's votes while node 0 still leads term 2. -/
def electionChoices : List (CCFRaft.Model.State -> CCFRaft.Model.Action) :=
  [
    input 0 (.append [{ content := .signature }]),
    input 0 (.sendEntries 1 2),
    deliverFrom 0 1,
    input 1 (.timeout .election),
    deliverFrom 1 2,
    deliverFrom 2 1,
    deliverFrom 1 2,
    deliverFrom 2 1
  ]

/-- Node 0 keeps nominating node 2, which ignores the stale-term proposal. -/
def electionCycle : List (CCFRaft.Model.State -> CCFRaft.Model.Action) :=
  [input 0 .nominateSuccessor, deliverFrom 0 2]

theorem election_finished
    : (run electionSystem electionStart electionChoices).isSome := by
  unfold electionSystem electionStart electionChoices
  sort_by_insertion
  decide +kernel

def electionFinal : CCFRaft.Model.State :=
  (run electionSystem electionStart electionChoices).getD electionStart

theorem election_run
    : run electionSystem electionStart electionChoices = some electionFinal :=
  eq_some_getD election_finished _

theorem election_cycle_finished
    : (run electionSystem electionFinal electionCycle).isSome := by
  unfold electionFinal electionSystem electionStart electionChoices electionCycle
  sort_by_insertion
  decide +kernel

theorem election_cycle_returns
    : (run electionSystem electionFinal electionCycle).getD electionStart
      = electionFinal := by
  unfold electionFinal electionSystem electionStart electionChoices electionCycle
  sort_by_insertion
  kernel_rfl

theorem election_cycle
    : run electionSystem electionFinal electionCycle = some electionFinal := by
  rw [eq_some_getD election_cycle_finished electionStart, election_cycle_returns]

/-- Nodes 0 and 1 are both present and both lead. -/
def bothLead (state : CCFRaft.Model.State) : Bool :=
  ((nodeState state 0).any fun local_ => decide (local_.role = .primary))
  && ((nodeState state 1).any fun local_ => decide (local_.role = .primary))

theorem election_both_lead : bothLead electionFinal = true := by
  unfold electionFinal electionSystem electionStart electionChoices
  sort_by_insertion
  decide +kernel

end Election

section Commit

abbrev commitSystem := CCFRaft.Model.transitionSystem {0, 1} [0, 1]

def commitStart := start {0, 1} [0, 1]

/--
Node 0 signs the bootstrap configuration and commits it with node 1 (after four
steps), then tells node 1 (after six). Node 0 then signs an unreplicated
transaction, so node 1's log is behind and its pre-vote requests are refused.
-/
def commitChoices : List (CCFRaft.Model.State -> CCFRaft.Model.Action) :=
  [
    input 0 (.append [{ content := .signature }]),
    input 0 (.sendEntries 1 2),
    deliverOldest,
    deliverOldest,
    input 0 (.sendEntries 1 2),
    deliverOldest,
    input 0 (.append [{ content := .transaction 1 {} }, { content := .signature }]),
    input 1 (.timeout .election),
    deliverFrom 1 0,
    deliverFrom 0 1
  ]

/-- Node 1 keeps asking for pre-votes and node 0 keeps refusing. -/
def commitCycle : List (CCFRaft.Model.State -> CCFRaft.Model.Action) :=
  [input 1 (.timeout .election), deliverFrom 1 0, deliverFrom 0 1]

theorem commit_finished : (run commitSystem commitStart commitChoices).isSome := by
  unfold commitSystem commitStart commitChoices
  sort_by_insertion
  decide +kernel

def commitFinal : CCFRaft.Model.State :=
  (run commitSystem commitStart commitChoices).getD commitStart

theorem commit_run : run commitSystem commitStart commitChoices = some commitFinal :=
  eq_some_getD commit_finished _

theorem commit_cycle_finished : (run commitSystem commitFinal commitCycle).isSome := by
  unfold commitFinal commitSystem commitStart commitChoices commitCycle
  sort_by_insertion
  decide +kernel

theorem commit_cycle_returns
    : (run commitSystem commitFinal commitCycle).getD commitStart = commitFinal := by
  unfold commitFinal commitSystem commitStart commitChoices commitCycle
  sort_by_insertion
  kernel_rfl

theorem commit_cycle : run commitSystem commitFinal commitCycle = some commitFinal := by
  rw [eq_some_getD commit_cycle_finished commitStart, commit_cycle_returns]

theorem commit_primary_committed
    : (run commitSystem commitStart (commitChoices.take 4)).isSome := by
  decide

/-- The state after node 0 advances its commit index, before node 1 learns it. -/
def commitPrimaryCommitted : CCFRaft.Model.State :=
  (run commitSystem commitStart (commitChoices.take 4)).getD commitStart

theorem commit_primary_present : (nodeState commitPrimaryCommitted 0).isSome := by decide

theorem commit_follower_committed
    : (run commitSystem commitStart (commitChoices.take 6)).isSome := by
  decide

/-- The state after node 1 learns the commit index. -/
def commitFollowerCommitted : CCFRaft.Model.State :=
  (run commitSystem commitStart (commitChoices.take 6)).getD commitStart

theorem commit_follower_present : (nodeState commitFollowerCommitted 1).isSome := by
  decide

end Commit

section Single

abbrev singleSystem := CCFRaft.Model.transitionSystem {0} [0]

def singleStart := start {0} [0]

/-- A single initial primary signs and so commits its bootstrap configuration. -/
def singleChoices : List (CCFRaft.Model.State -> CCFRaft.Model.Action) :=
  [input 0 (.append [{ content := .signature }])]

/-- With no peers, nominating a successor sends nothing and changes nothing. -/
def singleCycle : List (CCFRaft.Model.State -> CCFRaft.Model.Action) :=
  [input 0 .nominateSuccessor]

theorem single_finished : (run singleSystem singleStart singleChoices).isSome := by
  decide

def singleFinal : CCFRaft.Model.State :=
  (run singleSystem singleStart singleChoices).getD singleStart

theorem single_run : run singleSystem singleStart singleChoices = some singleFinal :=
  eq_some_getD single_finished _

theorem single_cycle : run singleSystem singleFinal singleCycle = some singleFinal := by
  kernel_rfl

theorem single_final_present : (nodeState singleFinal 0).isSome := by decide

/-- After committing the bootstrap signature, the primary commits a further
transaction and signature in one batch. -/
def extendAction : CCFRaft.Model.Action :=
  .local 0 (.append [{ content := .transaction 1 {} }, { content := .signature }])

theorem single_final_distinct : (singleFinal.nodes.map Prod.fst).Nodup := by
  unfold singleFinal singleSystem singleStart singleChoices
  sort_by_insertion
  decide

theorem extend_enabled : (singleSystem.step singleFinal extendAction).isSome := by
  unfold singleSystem singleFinal singleStart singleChoices extendAction
  sort_by_insertion
  decide

def extendFinal : CCFRaft.Model.State :=
  (singleSystem.step singleFinal extendAction).getD singleFinal

theorem extend_final_present : (nodeState extendFinal 0).isSome := by
  unfold extendFinal singleSystem singleFinal singleStart singleChoices extendAction
  sort_by_insertion
  decide

theorem extend_committed
    : ((nodeState singleFinal 0).get single_final_present).committedLog ≠ []
      /\ ((nodeState singleFinal 0).get single_final_present).committedLog.length
          < ((nodeState extendFinal 0).get extend_final_present).committedLog.length := by
  unfold extendFinal singleSystem singleFinal singleStart singleChoices extendAction
  sort_by_insertion
  decide

end Single

lemma committed_logs_prefix_witness
    : exists (config : Finset NodeID),
    exists
    (nodes : List NodeID) (trace
                            : CCF.Execution.Trace (Model.transitionSystem config nodes)),
    exists (stateA stateB : Model.State),
    exists (left right : NodeID) (leftState rightState : NodeState),
      stateA ∈ trace
      /\ stateB ∈ trace
      /\ (left, leftState) ∈ stateA.nodes
      /\ (right, rightState) ∈ stateB.nodes
      /\ left ≠ right
      /\ leftState.committedLog ≠ []
      /\ rightState.committedLog ≠ [] := by
  have stemRun := commit_run
  exact ⟨
    {0, 1},
    [0, 1],
    lassoTrace (start_initial (by decide) (by decide)) stemRun commit_cycle
      (by simp [commitCycle]),
    commitPrimaryCommitted,
    commitFollowerCommitted,
    0,
    1,
    (nodeState commitPrimaryCommitted 0).get commit_primary_present,
    (nodeState commitFollowerCommitted 1).get commit_follower_present,
    lasso_mem stemRun (by decide) (eq_some_getD commit_primary_committed _),
    lasso_mem stemRun (by decide) (eq_some_getD commit_follower_committed _),
    member_of_nodeState _,
    member_of_nodeState _,
    by decide,
    by decide,
    by decide
  ⟩

lemma single_node_committed_log_monotonic_witness
    : exists (config : Finset NodeID) (nodes : List NodeID),
    exists (pre post : Model.State),
    exists (nodeId : NodeID) (nodePre nodePost : NodeState),
    exists (action : Model.Action),
      (pre.nodes.map Prod.fst).Nodup
      /\ (Model.transitionSystem config nodes).step pre action = some post
      /\ (nodeId, nodePre) ∈ pre.nodes
      /\ (nodeId, nodePost) ∈ post.nodes
      /\ nodePre.committedLog ≠ []
      /\ nodePre.committedLog.length < nodePost.committedLog.length :=
  ⟨
    {0},
    [0],
    singleFinal,
    extendFinal,
    0,
    (nodeState singleFinal 0).get single_final_present,
    (nodeState extendFinal 0).get extend_final_present,
    extendAction,
    single_final_distinct,
    eq_some_getD extend_enabled _,
    member_of_nodeState _,
    member_of_nodeState _,
    extend_committed.1,
    extend_committed.2
  ⟩

lemma election_safety_witness
    : exists (config : Finset NodeID),
    exists
    (nodes : List NodeID) (trace
                            : CCF.Execution.Trace
                                (Model.transitionSystem config nodes)) (state
                                                                        : Model.State),
    exists (left right : NodeID) (leftState rightState : NodeState),
      state ∈ trace
      /\ (left, leftState) ∈ state.nodes
      /\ (right, rightState) ∈ state.nodes
      /\ leftState.role = .primary
      /\ rightState.role = .primary
      /\ left ≠ right := by
  have lead := election_both_lead
  simp only [bothLead, Bool.and_eq_true, Option.any_eq_true, decide_eq_true_eq] at lead
  obtain ⟨⟨leftState, leftFound, leftPrimary⟩, ⟨rightState, rightFound, rightPrimary⟩⟩ := lead
  have stemRun := election_run
  exact ⟨
    {0, 1, 2},
    [0, 1, 2],
    lassoTrace (start_initial (by decide) (by decide)) stemRun election_cycle
      (by simp [electionCycle]),
    electionFinal,
    0,
    1,
    leftState,
    rightState,
    lasso_mem stemRun le_rfl (by rw [List.take_length]; exact stemRun),
    mem_of_nodeState leftFound,
    mem_of_nodeState rightFound,
    leftPrimary,
    rightPrimary,
    by decide
  ⟩

lemma committed_frontier_is_signature_witness
    : exists (config : Finset NodeID),
    exists
    (nodes : List NodeID) (trace
                            : CCF.Execution.Trace
                                (Model.transitionSystem config nodes)) (state
                                                                        : Model.State),
    exists (node : NodeID) (nodeState : NodeState),
      state ∈ trace /\ (node, nodeState) ∈ state.nodes /\ 0 < nodeState.commitIndex := by
  have stemRun := single_run
  exact ⟨
    {0},
    [0],
    lassoTrace (start_initial (by decide) (by decide)) stemRun single_cycle
      (by simp [singleCycle]),
    singleFinal,
    0,
    (nodeState singleFinal 0).get single_final_present,
    lasso_mem stemRun le_rfl (by rw [List.take_length]; exact stemRun),
    member_of_nodeState _,
    by decide
  ⟩

end CCFRaft.Proofs.Witnesses
