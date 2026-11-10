module

public import Consensus.Model
public import CCF.Proofs.Execution

import all Init.Control.State

public meta import Lean.Elab.Tactic.ElabTerm

meta import Lean.Meta.Tactic.AuxLemma

namespace Consensus.Proofs.Config
end Consensus.Proofs.Config

namespace Consensus.Proofs.Concrete
end Consensus.Proofs.Concrete

namespace Consensus.Proofs.Witnesses

open CCF CCF.Execution CCF.MultiNodeTransitionSystem
open Consensus.Model.Node
open Consensus.Model (initialNodeState)
section Runs

/-- The final state of choosing each action from the current state, when every
chosen action is enabled. -/
public def run (system : TransitionSystem) (start : system.State)
    : List (system.State -> system.Action) -> Option system.State
  | [] => some start
  | choose :: rest =>
      (system.step start (choose start)).bind fun next => run system next rest

/-- Each prefix of a finished run finishes, and its next choice is enabled. -/
public theorem run_take_step {system : TransitionSystem} {start final : system.State}
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
public def lasso (system : TransitionSystem) (start : system.State)
    (stem cycle : List (system.State -> system.Action)) (index : Nat)
    : system.State :=
  if index < stem.length then
    (run system start (stem.take index)).getD start
  else
    (run system ((run system start stem).getD start)
      (cycle.take ((index - stem.length) % cycle.length))).getD
      start

/-- The action chosen at each position of a lasso. -/
public def lassoAction (system : TransitionSystem) (start : system.State)
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
public def lassoTrace {system : TransitionSystem} {start final : system.State}
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
  refine ⟨{
    init := lasso system start stem cycle 0
    steps := CCF.Seq.ofStream fun index =>
      (lassoAction system start stem cycle nonempty index,
        lasso system start stem cycle (index + 1))
  }, ?_, ?_⟩
  · show system.init (lasso system start stem cycle 0)
    by_cases empty : stem = []
    · subst empty
      simp only [run, Option.some.injEq] at stemRun
      subst stemRun
      simpa [tail 0 (Nat.zero_le _), run] using initialized
    · simpa [lasso, List.length_pos_iff.mpr empty, run] using initialized
  intro index before action atBefore chosen
  have atBefore : lasso system start stem cycle index = before := by
    cases index <;> exact Option.some.inj atBefore
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

end Runs
end Consensus.Proofs.Witnesses

namespace Consensus.Proofs.Witnesses

open CCF CCF.Execution CCF.MultiNodeTransitionSystem
open Consensus.Model.Node
open Consensus.Model (initialNodeState)

/-- Every listed node in its initial state for `configuration`, with an empty network. -/
public def start (configuration : Finset Nat) (nodes : List Nat)
    : Consensus.Model.State :=
  { nodes := nodes.map fun node => (node, initialNodeState configuration node) }

/-- Deliver the oldest envelope in the network. -/
public def deliverOldest (state : Consensus.Model.State) : Consensus.Model.Action :=
  match state.network with
  | envelope :: _ => .deliver envelope
  | [] => .local 0 (.timeout .election)

public def deliverFrom (source target : Nat) (state : Consensus.Model.State)
    : Consensus.Model.Action :=
  match state.network.find?
          (fun envelope => envelope.source == source && envelope.target == target) with
  | some envelope => .deliver envelope
  | none => deliverOldest state

/-- Take `input` at `node` regardless of the current state. -/
public def input (node : Nat) (input : Consensus.Model.Node.Input)
    : Consensus.Model.State -> Consensus.Model.Action :=
  fun _ => .local node input

/-- `run` over a bare step function. Unlike `run`, its step argument is not a
dependency of the other arguments' types, so tactics can rewrite inside it. -/
private def runWith {S A : Type} (step : S -> A -> Option S) (start : S)
    : List (S -> A) -> Option S
  | [] => some start
  | choose :: rest => (step start (choose start)).bind fun next => runWith step next rest

private theorem run_eq_runWith (system : TransitionSystem) (start : system.State)
    (choices : List (system.State -> system.Action))
    : run system start choices
      = runWith (fun state action => system.step state action) start choices := by
  induction choices generalizing start with
  | nil => rfl
  | cons choose rest ih => simp only [run, runWith, ih]

/-- Unfold the model's step function down to its broadcasts, so that the kernel
can evaluate the run. Each run becomes a `runWith` over a single copy of the
step function, rather than one copy per step, and `dsimp` unfolds it without
building proof terms. -/
macro "unfold_run" : tactic =>
  `(tactic| (simp only [run_eq_runWith]; dsimp only [Consensus.Model.transitionSystem, MultiNodeTransitionSystem.lift,
    MultiNodeTransitionSystem.next, Consensus.Model.protocol, Consensus.Model.Node.step,
    Consensus.Model.Node.act, Consensus.Model.Node.receive,
    Consensus.Model.Node.startElection, Consensus.Model.Node.becomePreVoteCandidate,
    Consensus.Model.Node.becomeCandidate, Consensus.Model.Node.electIfQuorum,
    Consensus.Model.Node.becomePrimary, Consensus.Model.Node.broadcastToOthers,
    Consensus.Model.Node.advanceCommit, Consensus.Model.Node.nominateSuccessor,
    Consensus.Model.Node.findSuccessor, Consensus.Model.Node.appendBatch,
    Consensus.Model.Node.appendEntry,
    Consensus.Model.Node.handleAppendEntriesRequest,
    Consensus.Model.Node.handleAppendEntriesResponse,
    Consensus.Model.Node.handleRequestVoteResponse,
    Consensus.Model.Node.handleRequestPreVoteResponse,
    Consensus.Model.Node.handleProposeRequestVoteRequest]))

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

end Consensus.Proofs.Witnesses

namespace Consensus.Proofs.Witnesses

open CCF CCF.Execution CCF.MultiNodeTransitionSystem
open Consensus.Model.Node
open Consensus.Model (initialNodeState)
section Election

public abbrev electionSystem := Consensus.Model.transitionSystem {0, 1, 2} [0, 1, 2]

public def electionStart := start {0, 1, 2} [0, 1, 2]

/-- Node 0 replicates its signed configuration to node 1. Node 1 then wins
pre-vote and term 3 with node 2's votes while node 0 still leads term 2. -/
public def electionChoices : List (Consensus.Model.State -> Consensus.Model.Action) :=
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
public def electionCycle : List (Consensus.Model.State -> Consensus.Model.Action) :=
  [input 0 .nominateSuccessor, deliverFrom 0 2]

public def electionFinal : Consensus.Model.State :=
  (run electionSystem electionStart electionChoices).getD electionStart

/-- Nodes 0 and 1 are both present and both lead. -/
public def bothLead (state : Consensus.Model.State) : Bool :=
  ((nodeState state 0).any fun local_ => decide (local_.role = .primary))
  && ((nodeState state 1).any fun local_ => decide (local_.role = .primary))

end Election
end Consensus.Proofs.Witnesses

namespace Consensus.Proofs.Witnesses

open CCF CCF.Execution CCF.MultiNodeTransitionSystem
open Consensus.Model.Node
open Consensus.Model (initialNodeState)
section Commit

public abbrev commitSystem := Consensus.Model.transitionSystem {0, 1} [0, 1]

public def commitStart := start {0, 1} [0, 1]

/--
Node 0 signs the bootstrap configuration and commits it with node 1 (after four
steps), then tells node 1 (after six). Node 0 then signs an unreplicated
transaction, so node 1's log is behind and its pre-vote requests are refused.
-/
public def commitChoices : List (Consensus.Model.State -> Consensus.Model.Action) :=
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
public def commitCycle : List (Consensus.Model.State -> Consensus.Model.Action) :=
  [input 1 (.timeout .election), deliverFrom 1 0, deliverFrom 0 1]

public def commitFinal : Consensus.Model.State :=
  (run commitSystem commitStart commitChoices).getD commitStart

/-- The state after node 0 advances its commit index, before node 1 learns it. -/
public def commitPrimaryCommitted : Consensus.Model.State :=
  (run commitSystem commitStart (commitChoices.take 4)).getD commitStart

/-- The state after node 1 learns the commit index. -/
public def commitFollowerCommitted : Consensus.Model.State :=
  (run commitSystem commitStart (commitChoices.take 6)).getD commitStart

end Commit
end Consensus.Proofs.Witnesses

namespace Consensus.Proofs.Witnesses

open CCF CCF.Execution CCF.MultiNodeTransitionSystem
open Consensus.Model.Node
open Consensus.Model (initialNodeState)
section Single

public abbrev singleSystem := Consensus.Model.transitionSystem {0} [0]

public def singleStart := start {0} [0]

/-- A single initial primary signs and so commits its bootstrap configuration. -/
public def singleChoices : List (Consensus.Model.State -> Consensus.Model.Action) :=
  [input 0 (.append [{ content := .signature }])]

/-- With no peers, nominating a successor sends nothing and changes nothing. -/
public def singleCycle : List (Consensus.Model.State -> Consensus.Model.Action) :=
  [input 0 .nominateSuccessor]

public def singleFinal : Consensus.Model.State :=
  (run singleSystem singleStart singleChoices).getD singleStart

/-- After committing the bootstrap signature, the primary commits a further
transaction and signature in one batch. -/
public def extendAction : Consensus.Model.Action :=
  .local 0 (.append [{ content := .transaction 1 {} }, { content := .signature }])

public def extendFinal : Consensus.Model.State :=
  (singleSystem.step singleFinal extendAction).getD singleFinal

end Single
end Consensus.Proofs.Witnesses

namespace Consensus.Proofs.Concrete

set_option linter.unusedSectionVars false
open Consensus.Proofs.Config
open CCF CCF.MultiNodeTransitionSystem
open Model.Node

private theorem mem_of_nodeState {concrete : Model.State} {node : NodeID}
    {state : NodeState} (found : nodeState concrete node = some state)
    : (node, state) ∈ concrete.nodes := by
  simp only [nodeState, Option.map_eq_some_iff] at found
  obtain ⟨⟨key, value⟩, located, rfl⟩ := found
  have same : key = node := by simpa using List.find?_some located
  subst same
  exact List.mem_of_find?_eq_some located

end Consensus.Proofs.Concrete

namespace Consensus.Proofs.Witnesses

open CCF CCF.Execution CCF.MultiNodeTransitionSystem
open Consensus.Model.Node
open Consensus.Model (initialNodeState)
section Runs

/-- Every state reached by a prefix of the stem occurs in the lasso. -/
public theorem lasso_mem {system : TransitionSystem} {start final state : system.State}
    {stem cycle : List (system.State -> system.Action)}
    (initialized : system.init start)
    (stemRun : run system start stem = some final)
    (cycleRun : run system final cycle = some final) (nonempty : cycle ≠ []) {index : Nat}
    (bounded : index <= stem.length)
    (reached : run system start (stem.take index) = some state)
    : state ∈ lassoTrace initialized stemRun cycleRun nonempty := by
  apply Trace.stateAt_mem (n := index)
  have position
      : (lassoTrace initialized stemRun cycleRun nonempty).stateAt index
          = some (lasso system start stem cycle index) := by
    cases index <;> rfl
  rw [position, Option.some.injEq]
  by_cases inStem : index < stem.length
  · simp [lasso, inStem, reached]
  · have last : index = stem.length := by omega
    subst last
    rw [List.take_length, stemRun] at reached
    simp only [Option.some.injEq] at reached
    subst reached
    simp [lasso, stemRun, run]

/-- A present option is `some` of its value with any default. -/
public theorem eq_some_getD {α : Type} {value : Option α} (present : value.isSome)
    (default : α)
    : value = some (value.getD default) := by
  cases value <;> simp_all

end Runs
end Consensus.Proofs.Witnesses

namespace Consensus.Proofs.Witnesses

open CCF CCF.Execution CCF.MultiNodeTransitionSystem
open Consensus.Model.Node
open Consensus.Model (initialNodeState)

public theorem start_initial {configuration : Finset Nat} {nodes : List Nat}
    (nonempty : configuration.Nonempty) (distinct : nodes.Nodup)
    : (Consensus.Model.transitionSystem configuration nodes).init
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

public theorem mem_of_nodeState {state : Consensus.Model.State} {node : Nat}
    {value : NodeState} (found : nodeState state node = some value)
    : (node, value) ∈ state.nodes := by
  simp only [nodeState, Option.map_eq_some_iff] at found
  obtain ⟨⟨key, stored⟩, located, same⟩ := found
  simp only at same
  subst same
  have keyEq : key = node := by simpa using List.find?_some located
  subst keyEq
  exact List.mem_of_find?_eq_some located

public theorem member_of_nodeState {state : Consensus.Model.State} {node : Nat}
    (present : (nodeState state node).isSome)
    : (node, (nodeState state node).get present) ∈ state.nodes :=
  mem_of_nodeState (Option.some_get present).symm

end Consensus.Proofs.Witnesses

namespace Consensus.Proofs.Witnesses

open CCF CCF.Execution CCF.MultiNodeTransitionSystem
open Consensus.Model.Node
open Consensus.Model (initialNodeState)
section Election

public theorem election_finished
    : (run electionSystem electionStart electionChoices).isSome := by
  unfold_run
  decide +kernel

public theorem election_run
    : run electionSystem electionStart electionChoices = some electionFinal :=
  eq_some_getD election_finished _

public theorem election_cycle_finished
    : (run electionSystem electionFinal electionCycle).isSome := by
  unfold electionFinal
  unfold_run
  decide +kernel

public theorem election_cycle_returns
    : (run electionSystem electionFinal electionCycle).getD electionStart
      = electionFinal := by
  unfold electionFinal
  unfold_run
  kernel_rfl

public theorem election_cycle
    : run electionSystem electionFinal electionCycle = some electionFinal := by
  rw [eq_some_getD election_cycle_finished electionStart, election_cycle_returns]

public theorem election_both_lead : bothLead electionFinal = true := by
  unfold electionFinal
  unfold_run
  decide +kernel

end Election
end Consensus.Proofs.Witnesses

namespace Consensus.Proofs.Witnesses

open CCF CCF.Execution CCF.MultiNodeTransitionSystem
open Consensus.Model.Node
open Consensus.Model (initialNodeState)
section Commit

public theorem commit_finished : (run commitSystem commitStart commitChoices).isSome := by
  unfold_run
  decide +kernel

public theorem commit_run
    : run commitSystem commitStart commitChoices = some commitFinal :=
  eq_some_getD commit_finished _

public theorem commit_cycle_finished
    : (run commitSystem commitFinal commitCycle).isSome := by
  unfold commitFinal
  unfold_run
  decide +kernel

public theorem commit_cycle_returns
    : (run commitSystem commitFinal commitCycle).getD commitStart = commitFinal := by
  unfold commitFinal
  unfold_run
  kernel_rfl

public theorem commit_cycle
    : run commitSystem commitFinal commitCycle = some commitFinal := by
  rw [eq_some_getD commit_cycle_finished commitStart, commit_cycle_returns]

public theorem commit_primary_committed
    : (run commitSystem commitStart (commitChoices.take 4)).isSome := by
  decide

public theorem commit_primary_present : (nodeState commitPrimaryCommitted 0).isSome := by
  decide

public theorem commit_follower_committed
    : (run commitSystem commitStart (commitChoices.take 6)).isSome := by
  decide

public theorem commit_follower_present
    : (nodeState commitFollowerCommitted 1).isSome := by
  decide

end Commit
end Consensus.Proofs.Witnesses

namespace Consensus.Proofs.Witnesses

open CCF CCF.Execution CCF.MultiNodeTransitionSystem
open Consensus.Model.Node
open Consensus.Model (initialNodeState)
section Single

public theorem single_finished : (run singleSystem singleStart singleChoices).isSome := by
  decide

public theorem single_run
    : run singleSystem singleStart singleChoices = some singleFinal :=
  eq_some_getD single_finished _

public theorem single_cycle
    : run singleSystem singleFinal singleCycle = some singleFinal := by
  kernel_rfl

public theorem single_final_present : (nodeState singleFinal 0).isSome := by decide

public theorem single_final_distinct : (singleFinal.nodes.map Prod.fst).Nodup := by
  decide +kernel

public theorem extend_enabled : (singleSystem.step singleFinal extendAction).isSome := by
  decide +kernel

public theorem extend_final_present : (nodeState extendFinal 0).isSome := by
  decide +kernel

public theorem extend_committed
    : ((nodeState singleFinal 0).get single_final_present).committedLog ≠ []
      /\ ((nodeState singleFinal 0).get single_final_present).committedLog.length
          < ((nodeState extendFinal 0).get extend_final_present).committedLog.length := by
  decide +kernel

end Single
end Consensus.Proofs.Witnesses

namespace Consensus.Proofs.Witnesses

open CCF CCF.Execution CCF.MultiNodeTransitionSystem
open Consensus.Model.Node
open Consensus.Model (initialNodeState)

public theorem committed_logs_prefix_witness
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
    lasso_mem (start_initial (by decide) (by decide)) stemRun commit_cycle
      (by simp [commitCycle]) (by decide) (eq_some_getD commit_primary_committed _),
    lasso_mem (start_initial (by decide) (by decide)) stemRun commit_cycle
      (by simp [commitCycle]) (by decide) (eq_some_getD commit_follower_committed _),
    member_of_nodeState _,
    member_of_nodeState _,
    by decide,
    by decide,
    by decide
  ⟩

public theorem single_node_committed_log_monotonic_witness
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

public theorem election_safety_witness
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
    lasso_mem
      (start_initial (by decide) (by decide))
      stemRun election_cycle
      (by simp [electionCycle])
      Nat.le.refl
      (by rw [List.take_length]; exact stemRun),
    mem_of_nodeState leftFound,
    mem_of_nodeState rightFound,
    leftPrimary,
    rightPrimary,
    by decide
  ⟩

public theorem committed_frontier_is_signature_witness
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
    lasso_mem
      (start_initial (by decide) (by decide))
      stemRun single_cycle
      (by simp [singleCycle])
      Nat.le.refl
      (by rw [List.take_length]; exact stemRun),
    member_of_nodeState _,
    by decide
  ⟩

end Consensus.Proofs.Witnesses
