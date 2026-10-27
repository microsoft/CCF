module

public import CCFRaft.Proofs.Leadership.AnchorWindow
public import CCFRaft.Proofs.Replication.Commit

@[expose] public section

set_option linter.unusedSectionVars false

/-!
# The nodes of a reachable state

The system's nodes are the keys of every reachable state.
-/

namespace CCFRaft.Proofs.Leadership

open CCF CCF.MultiNodeTransitionSystem
open Model.Node
open CCFRaft.Liveness
open CCFRaft.Proofs.Replication
open CCFRaft.Proofs.Liveness (Admissible)
open HasProtocol (proto)
open HasTime (time)

section Keys

variable [Config.InitialConfiguration]

/-- The system's nodes are the keys of every reachable state. -/
theorem keys_eq {nodes : List NodeID} {state : Model.State}
    (reachable
      : (Model.transitionSystem Config.INITIAL_CONFIGURATION nodes).Reachable state)
    : state.nodes.map Prod.fst = nodes := by
  induction reachable
    using @TransitionSystem.Reachable.rec
      (Model.transitionSystem Config.INITIAL_CONFIGURATION nodes) with
  | initial initialized => exact initialized.2.1
  | @step before after action _ stepped ih =>
      cases action with
      | «local» actor input =>
          obtain ⟨_, _, _, _, _, rfl⟩ := Concrete.step_local stepped
          simpa [Concrete.replaceNode_keys] using ih
      | deliver envelope =>
          obtain ⟨_, _, _, _, _, _, rfl⟩ := Concrete.step_deliver stepped
          simpa [Concrete.replaceNode_keys] using ih

end Keys

end CCFRaft.Proofs.Leadership
