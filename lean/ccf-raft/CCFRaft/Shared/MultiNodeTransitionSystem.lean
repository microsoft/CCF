import CCFRaft.Shared.TransitionSystem
import CCFRaft.Shared.Capabilities

namespace CCFRaft.Shared.MultiNodeTransitionSystem

/-!
Composes copies of one local protocol into a message-passing network. The
network is a multiset of envelopes; delivery picks any queued envelope, not
just the head. Each global step runs exactly one node once, with recording
capabilities, then appends that node's sends to the network. Notifications
are not stored: `LocalStep` and `Protocol.ValidStep` let properties talk
about them by re-running the local step.
-/

/-- Node states, the nodes allowed to act, and the messages in flight. -/
structure State (Node LocalState Message : Type) where
  nodes : List (Node × LocalState)
  active : List Node
  network : List (Envelope Node Message) := []
deriving Repr, BEq

/-- A node acts on its own (`local`) or receives one queued envelope (`deliver`). -/
inductive Action (Node Message Input : Type) where
  | local (node : Node) (input : Input)
  | deliver (envelope : Envelope Node Message)
deriving Repr, BEq

/-- What a local protocol must provide to be run by the network: initial
states, a step, and translations of deliveries and inputs into local actions. -/
structure Protocol (Node LocalState LocalAction Message Notification Input : Type) where
  init : Node -> LocalState -> Prop
  step
    : Capabilities Node Message Notification -> Node -> LocalState -> LocalAction
      -> Option (Effect Node Message Notification LocalState)
  receive : Node -> Message -> LocalAction
  internal : Input -> LocalAction

/-- A record of one node's step: what it saw, what it became, what it emitted. -/
structure LocalStep (Node LocalState LocalAction Message Notification : Type) where
  node : Node
  before : LocalState
  action : LocalAction
  after : LocalState
  effects : Outputs Node Message Notification

/-- `s` is a real step: running the protocol from `s.before` on `s.action` with
recording capabilities yields exactly `s.after` and `s.effects`. No reachability
or activity is required. -/
def Protocol.ValidStep
    (protocol : Protocol Node LocalState LocalAction Message Notification Input)
    (s : LocalStep Node LocalState LocalAction Message Notification)
    : Prop :=
  exists execute,
    protocol.step (Capabilities.record s.node) s.node s.before s.action = some execute
    /\ execute.run {} = (s.after, s.effects)

/-- The state of `node`, if it is in the node table. -/
def nodeState [BEq Node] (state : State Node LocalState Message) (node : Node)
    : Option LocalState :=
  (state.nodes.find? fun entry => entry.1 == node).map Prod.snd

/-- Removes the first occurrence only; duplicate envelopes are distinct deliveries. -/
def removeOne [BEq α] (value : α) : List α -> List α
  | [] => []
  | head :: tail =>
      if head == value then tail else head :: removeOne value tail

/-- One global step. `none` if the envelope is not queued, the node is not
active, the node is unknown, or the local step is disabled. -/
def next [BEq Node] [BEq Message]
    (protocol : Protocol Node LocalState LocalAction Message Notification Input)
    (state : State Node LocalState Message) (action : Action Node Message Input)
    : Option (State Node LocalState Message) := do
  let (node, event, pending) <- match action with
                                | .local node input =>
                                    pure (node, protocol.internal input, state.network)
                                | .deliver envelope => do
                                    guard (state.network.contains envelope)
                                    pure
                                      (
                                        envelope.target,
                                        protocol.receive envelope.source envelope.payload,
                                        removeOne envelope state.network
                                      )
  guard (state.active.contains node)
  let before <- nodeState state node
  let execute <- protocol.step (Capabilities.record node) node before event
  let (after, effects) := execute.run {}
  pure
    {
      state with
        nodes :=
          state.nodes.map fun entry => if entry.1 == node then (node, after) else entry
        network := pending ++ effects.outgoing
    }

/-- The network as a `TransitionSystem`. Initially every configured node has
an initial local state, the active nodes are a subset of them, and the
network is empty. -/
def lift [BEq Node] [BEq Message]
    (configured : List Node)
    (protocol : Protocol Node LocalState LocalAction Message Notification Input)
    : TransitionSystem (State Node LocalState Message) (Action Node Message Input) where
  init state :=
    configured.Nodup
    /\ state.nodes.map Prod.fst = configured
    /\ state.active.Nodup
    /\ (forall node, node ∈ state.active -> node ∈ configured)
    /\ state.network = []
    /\ (forall entry, entry ∈ state.nodes -> protocol.init entry.1 entry.2)
  step := next protocol

end CCFRaft.Shared.MultiNodeTransitionSystem
