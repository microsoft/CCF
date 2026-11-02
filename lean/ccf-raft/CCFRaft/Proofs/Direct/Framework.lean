module

public import CCFRaft.Proofs.Concrete

@[expose] public section

set_option linter.unusedSectionVars false

/-!
# Invariants of the network model

A step of `Model.transitionSystem` runs one node once: that node takes a new
state, the network loses the delivered envelope, if any, and gains the node's
sends. `NodeInvariant` lifts a predicate that every local step preserves to
every node of every reachable state.
-/

namespace CCFRaft.Proofs.Direct

open CCFRaft.Proofs.Config

open CCF CCF.MultiNodeTransitionSystem Concrete
open Model.Node
open Model (initialNodeState)

variable [Config.InitialConfiguration]

/-- A node-local predicate that holds initially and survives every local step. -/
structure NodeInvariant (P : NodeID -> NodeState -> Prop) : Prop where
  initial : forall node, P node (initialNodeState Config.INITIAL_CONFIGURATION node)
  step
    : forall node state event after outputs,
        P node state
        -> (Model.Node.step (Capabilities.record node) node state event).run {}
            = some (after, outputs)
        -> P node after

theorem NodeInvariant.reachable {P : NodeID -> NodeState -> Prop}
    (invariant : NodeInvariant P) {nodes : List NodeID} {state : Model.State}
    (reachable
      : (Model.transitionSystem Config.INITIAL_CONFIGURATION nodes).Reachable state)
    : forall node local_, (node, local_) ∈ state.nodes -> P node local_ := by
  induction reachable
    using @TransitionSystem.Reachable.rec
      (Model.transitionSystem Config.INITIAL_CONFIGURATION nodes) with
  | initial initialized =>
      intro node local_ member
      have initial : local_ = initialNodeState Config.INITIAL_CONFIGURATION node := initialized.2.2.2.2 (node, local_) member
      subst initial
      exact invariant.initial node
  | @step before after action _ stepped ih =>
      have preserved : forall {actor : NodeID} {old : NodeState}
          {event : Model.Node.Event} {new outputs},
          nodeState before actor = some old ->
          (Model.Node.step (Capabilities.record actor) actor old event).run {}
            = some (new, outputs) ->
          forall node local_,
            (node, local_) ∈ replaceNode before.nodes actor new ->
            P node local_ := by
        intro actor old event new outputs found acted node local_ member
        rcases mem_replaceNode member with ⟨rfl, rfl⟩ | ⟨_, listed⟩
        · exact invariant.step _ _ _ _ _ (ih _ _ (mem_of_nodeState found)) acted
        · exact ih _ _ listed
      cases action with
      | «local» actor input =>
          obtain ⟨old, new, outputs, found, acted, rfl⟩ := step_local stepped
          exact preserved (event := .internal input) found
            (by cases input <;> exact acted)
      | deliver envelope =>
          obtain ⟨_, old, new, outputs, found, received, rfl⟩ := step_deliver stepped
          exact preserved (event := .receive envelope.source envelope.payload) found received

theorem keys_nodup {nodes : List NodeID} {state : Model.State}
    (reachable
      : (Model.transitionSystem Config.INITIAL_CONFIGURATION nodes).Reachable state)
    : (state.nodes.map Prod.fst).Nodup := by
  induction reachable
    using @TransitionSystem.Reachable.rec
      (Model.transitionSystem Config.INITIAL_CONFIGURATION nodes) with
  | initial initialized => exact initialized.2.2.1
  | @step before after action _ stepped ih =>
      cases action with
      | «local» actor input =>
          obtain ⟨_, _, _, _, _, rfl⟩ := step_local stepped
          simpa [replaceNode_keys] using ih
      | deliver envelope =>
          obtain ⟨_, _, _, _, _, _, rfl⟩ := step_deliver stepped
          simpa [replaceNode_keys] using ih

theorem find_of_mem {entries : List (NodeID × NodeState)} {node : NodeID}
    {local_ : NodeState} (distinct : (entries.map Prod.fst).Nodup)
    (member : (node, local_) ∈ entries)
    : entries.find? (fun entry => entry.1 == node) = some (node, local_) := by
  induction entries with
  | nil => simp at member
  | cons head tail ih =>
      obtain ⟨key, value⟩ := head
      simp only [List.map_cons, List.nodup_cons] at distinct
      by_cases here : key = node
      · subst here
        rcases List.mem_cons.mp member with same | later
        · rw [same]
          simp
        · exact absurd (List.mem_map.mpr ⟨_, later, rfl⟩) distinct.1
      · rcases List.mem_cons.mp member with same | later
        · simp only [Prod.mk.injEq] at same
          exact absurd same.1.symm here
        · simp [here, ih distinct.2 later]

theorem nodeState_of_mem {state : Model.State} {node : NodeID}
    {local_ : NodeState} (distinct : (state.nodes.map Prod.fst).Nodup)
    (member : (node, local_) ∈ state.nodes)
    : nodeState state node = some local_ := by
  simp [nodeState, find_of_mem distinct member]

end CCFRaft.Proofs.Direct
