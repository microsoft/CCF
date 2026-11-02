module

public import CCFRaft.Proofs.Direct.Framework

@[expose] public section

set_option linter.unusedSectionVars false

/-!
# Executions as histories

An `Exec` lists the states of an execution, newest first. Safety invariants
are predicates on such a history: they may mention any earlier state, so
facts about past elections, votes and acknowledgements need no ghost state.
-/

namespace CCFRaft.Proofs.Safety

open CCFRaft.Proofs.Config

open CCF CCF.MultiNodeTransitionSystem Concrete Direct
open Model.Node

variable [Config.InitialConfiguration]

/-- An execution of the network of `nodes`, newest state first. -/
inductive Exec (nodes : List NodeID) : List Model.State -> Prop where
  | initial {state : Model.State}
    (initialized : (Model.transitionSystem Config.INITIAL_CONFIGURATION nodes).init state)
    : Exec nodes [state]
  | step {before after : Model.State} {history : List Model.State}
    {action : Model.Action}
    (prior : Exec nodes (before :: history))
    (stepped
      : (Model.transitionSystem Config.INITIAL_CONFIGURATION nodes).step before action
        = some after)
    : Exec nodes (after :: before :: history)

theorem exec_of_reachable {nodes : List NodeID} {state : Model.State}
    (reachable
      : (Model.transitionSystem Config.INITIAL_CONFIGURATION nodes).Reachable state)
    : exists history, Exec nodes (state :: history) := by
  induction reachable
    using @TransitionSystem.Reachable.rec
      (Model.transitionSystem Config.INITIAL_CONFIGURATION nodes) with
  | initial initialized => exact ⟨[], .initial initialized⟩
  | step _ stepped ih =>
      obtain ⟨history, prior⟩ := ih
      exact ⟨_, .step prior stepped⟩

theorem Exec.reachable {nodes : List NodeID} {state : Model.State}
    {history : List Model.State} (exec : Exec nodes (state :: history))
    : (Model.transitionSystem Config.INITIAL_CONFIGURATION nodes).Reachable state := by
  generalize equal : state :: history = states at exec
  induction exec generalizing state history with
  | initial initialized =>
      cases equal
      exact .initial initialized
  | step prior stepped ih =>
      cases equal
      exact .step (ih rfl) stepped

/-- Every nonempty suffix of an execution is an execution. -/
theorem Exec.suffix {nodes : List NodeID} {history : List Model.State}
    (exec : Exec nodes history) {earlier : List Model.State}
    (suffix : earlier <:+ history) (nonempty : Not (earlier = []))
    : Exec nodes earlier := by
  induction exec with
  | initial initialized =>
      rcases List.suffix_cons_iff.mp suffix with same | inner
      · rw [same]
        exact .initial initialized
      · exact absurd (List.eq_nil_of_suffix_nil inner) nonempty
  | step prior stepped ih =>
      rcases List.suffix_cons_iff.mp suffix with same | inner
      · rw [same]
        exact .step prior stepped
      · exact ih inner

theorem Exec.keys {nodes : List NodeID} {history : List Model.State}
    (exec : Exec nodes history) {state : Model.State} (member : state ∈ history)
    : (state.nodes.map Prod.fst).Nodup := by
  obtain ⟨front, back, split⟩ := List.append_of_mem member
  have tail : Exec nodes (state :: back) :=
    exec.suffix ⟨front, split.symm⟩ (by simp)
  exact keys_nodup tail.reachable

/-- One node step: the actor's local step, other nodes unchanged, the network
losing at most the delivered envelope and gaining the actor's sends. -/
structure LocalTransition (before after : Model.State) where
  actor : NodeID
  pre : NodeState
  post : NodeState
  event : Event
  outputs : Outputs NodeID (Message) Notification
  pending : List Model.Envelope
  found : nodeState before actor = some pre
  ran
    : (Model.Node.step (Capabilities.record actor) actor pre event).run {}
      = some (post, outputs)
  nodesEq : after.nodes = replaceNode before.nodes actor post
  networkEq : after.network = pending ++ outputs.outgoing
  pendingSub : forall envelope, envelope ∈ pending -> envelope ∈ before.network
  source
    : (exists input, event = .internal input /\ pending = before.network)
      \/ (exists envelope,
            envelope ∈ before.network
            /\ envelope.target = actor
            /\ event = .receive envelope.source envelope.payload
            /\ pending = removeOne envelope before.network)

theorem mem_removeOne {α : Type} [BEq α] {value item : α} {items : List α}
    (member : item ∈ removeOne value items)
    : item ∈ items := by
  induction items with
  | nil => simp [removeOne] at member
  | cons head tail ih =>
      simp only [removeOne] at member
      split at member
      · exact List.mem_cons_of_mem _ member
      · rcases List.mem_cons.mp member with rfl | later
        · exact List.mem_cons_self
        · exact List.mem_cons_of_mem _ (ih later)

theorem LocalTransition.ofStep {nodes : List NodeID} {before after : Model.State}
    {action : Model.Action}
    (stepped
      : (Model.transitionSystem Config.INITIAL_CONFIGURATION nodes).step before action
        = some after)
    : Nonempty (LocalTransition before after) := by
  cases action with
  | «local» actor input =>
      obtain ⟨pre, post, outputs, found, ran, rfl⟩ := step_local stepped
      exact ⟨{
              actor,
              pre,
              post,
              event := .internal input,
              outputs,
              pending := before.network
              found
              ran := by cases input <;> exact ran
              nodesEq := rfl
              networkEq := rfl
              pendingSub := fun _ member => member
              source := Or.inl ⟨input, rfl, rfl⟩
            }⟩
  | deliver envelope =>
      obtain ⟨queued, pre, post, outputs, found, ran, rfl⟩ := step_deliver stepped
      exact ⟨{
        actor := envelope.target, pre, post
        event := .receive envelope.source envelope.payload, outputs
        pending := removeOne envelope before.network
        found, ran
        nodesEq := rfl
        networkEq := rfl
        pendingSub := fun _ member => mem_removeOne member
        source := Or.inr ⟨envelope, queued, rfl, rfl, rfl⟩
      }⟩

theorem LocalTransition.mem_after {before after : Model.State}
    (transition : LocalTransition before after) {node : NodeID}
    {state : NodeState} (member : (node, state) ∈ after.nodes)
    : (node = transition.actor /\ state = transition.post)
      \/ (Not (node = transition.actor) /\ (node, state) ∈ before.nodes) := by
  rw [transition.nodesEq] at member
  exact mem_replaceNode member

theorem LocalTransition.pre_mem {before after : Model.State}
    (transition : LocalTransition before after)
    : (transition.actor, transition.pre) ∈ before.nodes :=
  mem_of_nodeState transition.found

theorem LocalTransition.post_mem {before after : Model.State}
    (transition : LocalTransition before after)
    : (transition.actor, transition.post) ∈ after.nodes := by
  rw [transition.nodesEq]
  simp only [replaceNode, List.mem_map]
  exact ⟨_, transition.pre_mem, by simp⟩

theorem LocalTransition.other_mem {before after : Model.State}
    (transition : LocalTransition before after) {node : NodeID}
    {state : NodeState} (member : (node, state) ∈ before.nodes)
    (different : Not (node = transition.actor))
    : (node, state) ∈ after.nodes := by
  rw [transition.nodesEq]
  simp only [replaceNode, List.mem_map]
  exact ⟨_, member, by simp [different]⟩

theorem LocalTransition.mem_network {before after : Model.State}
    (transition : LocalTransition before after) {envelope : Model.Envelope}
    (member : envelope ∈ after.network)
    : envelope ∈ before.network \/ envelope ∈ transition.outputs.outgoing := by
  rw [transition.networkEq] at member
  rcases List.mem_append.mp member with old | new
  · exact Or.inl (transition.pendingSub _ old)
  · exact Or.inr new

/-- Two entries of one reachable state for the same node agree. -/
theorem state_unique {state : Model.State}
    (distinct : (state.nodes.map Prod.fst).Nodup) {node : NodeID}
    {first second : NodeState} (left : (node, first) ∈ state.nodes)
    (right : (node, second) ∈ state.nodes)
    : first = second := by
  have := (nodeState_of_mem distinct left).symm.trans (nodeState_of_mem distinct right)
  exact Option.some.inj this

end CCFRaft.Proofs.Safety
