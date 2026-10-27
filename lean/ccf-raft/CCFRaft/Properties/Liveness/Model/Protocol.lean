module

public import CCFRaft.Properties.Liveness.Model.Trace
public import CCFRaft.Properties.Liveness.Model.World

@[expose] public section

namespace CCFRaft.Liveness

open Model.Node (NodeID)
open HasProtocol (proto)

/-- Lift `Model.transitionSystem config nodes` through the world's protocol projection.
Local actions and deliveries execute a step of that system; all other events stutter. -/
def protocolModel {W : Type} [HasProtocol W Model.State]
    (config : Finset NodeID) (nodes : List NodeID)
    : Model W Event where
  init world := (Model.transitionSystem config nodes).init (proto world)
  next step :=
    match step.action.action with
    | some action =>
        (Model.transitionSystem config nodes).step (proto step.before) action
        = some (proto step.after)
    | none => proto step.after = proto step.before

/-- Re-run the same recording callback used by the network to identify sends. -/
def outgoing (state : Model.State) (action : Model.Action)
    : Option (List Model.Envelope) := do
  let (node, event) :=
    match action with
    | .local node input => (node, Model.Node.Event.internal input)
    | .deliver envelope =>
        (envelope.target, Model.Node.Event.receive envelope.source envelope.payload)
  let before <- CCF.MultiNodeTransitionSystem.nodeState state node
  let (_, effects) <- (Model.Node.step (CCF.Capabilities.record node) node before
                        event).run
                        {}
  return effects.outgoing

end CCFRaft.Liveness
