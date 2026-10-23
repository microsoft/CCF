module

public import CCF.TransitionSystem
public import CCF.Capabilities

@[expose] public section

namespace CCF.MultiNodeTransitionSystem

/-!
Composes copies of one local protocol into a message-passing network. The
network is a multiset of envelopes; delivery picks any queued envelope, not
just the head. Each global step runs exactly one node once, with recording
capabilities, then appends that node's sends to the network. Notifications
are not stored: `LocalStep` and `Protocol.ValidStep` let properties talk
about them by re-running the local step.
-/

/-- Node states and the messages in flight. -/
structure State (Node LocalState Message : Type) where
  /-- The local state associated with each node. -/
  nodes : List (Node × LocalState)
  /-- Queued envelopes, including distinct copies of identical messages. -/
  network : List (Envelope Node Message) := []
deriving Repr, BEq

/-- A node acts on its own (`local`) or receives one queued envelope (`deliver`). -/
inductive Action (Node Message Input : Type) where
  /-- Run a node with an input not supplied by the network. -/
  | local (node : Node) (input : Input)
  /-- Deliver one occurrence of a queued message to its target. -/
  | deliver (envelope : Envelope Node Message)
deriving Repr, BEq

/-- What a local protocol must provide to be run by the network: initial
states, a step, and translations of deliveries and inputs into local actions. -/
structure Protocol (Node LocalState LocalAction Message Notification Input : Type) where
  /-- The initial-state predicate for a node. -/
  init : Node -> LocalState -> Prop
  /-- Runs a local action with the host's output callbacks, if enabled. -/
  step
    : Capabilities Node Message Notification -> Node -> LocalState -> LocalAction
      -> Effect Node Message Notification LocalState
  /-- Converts a delivered message and its sender into a local action. -/
  receive : Node -> Message -> LocalAction
  /-- Converts a node's internal input into a local action. -/
  internal : Input -> LocalAction

/-- A record of one node's step: what it saw, what it became, what it emitted. -/
structure LocalStep (Node LocalState LocalAction Message Notification : Type) where
  /-- The node taking this step. -/
  node : Node
  /-- Local state before executing the action. -/
  before : LocalState
  /-- The local action executed by the node. -/
  action : LocalAction
  /-- Local state produced by the action. -/
  after : LocalState
  /-- Messages and notifications emitted by the action. -/
  effects : Outputs Node Message Notification

/-- `s` is a real step: running the protocol from `s.before` on `s.action` with
recording capabilities yields exactly `s.after` and `s.effects`. No global
reachability is required. -/
def Protocol.ValidStep
    {Node LocalState LocalAction Message Notification Input : Type}
    (protocol : Protocol Node LocalState LocalAction Message Notification Input)
    (s : LocalStep Node LocalState LocalAction Message Notification)
    : Prop :=
  (protocol.step (Capabilities.record s.node) s.node s.before s.action).run {}
  = some (s.after, s.effects)

/-- The state of `node`, if it is in the node table. -/
def nodeState {Node LocalState Message : Type} [BEq Node]
    (state : State Node LocalState Message) (node : Node)
    : Option LocalState :=
  (state.nodes.find? fun entry => entry.1 == node).map Prod.snd

/-- Removes the first occurrence only; duplicate envelopes are distinct deliveries. -/
def removeOne {α : Type _} [BEq α] (value : α) : List α -> List α
  | [] => []
  | head :: tail =>
      if head == value then tail else head :: removeOne value tail

/-- One global step. `none` if the envelope is not queued, the node is unknown,
or the local step is disabled. The node table's keys are unchanged. -/
def next {Node Message LocalState LocalAction Notification Input : Type}
    [BEq Node] [BEq Message]
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
  let before <- nodeState state node
  let (after, effects) <- (protocol.step (Capabilities.record node) node before event).run
                            {}
  pure
    {
      state with
        nodes :=
          state.nodes.map fun entry => if entry.1 == node then (node, after) else entry
        network := pending ++ effects.outgoing
    }

/-- The network as a `TransitionSystem`. Initially node identities are distinct,
every node has an initial local state, and the network is empty. Protocols
choose which nodes must exist and which may act. -/
abbrev lift {Node Message LocalState LocalAction Notification Input : Type}
    [BEq Node] [BEq Message]
    (protocol : Protocol Node LocalState LocalAction Message Notification Input)
    : TransitionSystem where
  State := State Node LocalState Message
  Action := Action Node Message Input
  init state :=
    (state.nodes.map Prod.fst).Nodup
    /\ state.network = []
    /\ (forall entry, entry ∈ state.nodes -> protocol.init entry.1 entry.2)
  step := next protocol

end CCF.MultiNodeTransitionSystem
