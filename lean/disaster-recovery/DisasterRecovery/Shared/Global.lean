import DisasterRecovery.Shared.TransitionSystem
import DisasterRecovery.Shared.Capabilities

namespace DisasterRecovery.Shared.Global

structure Envelope (Node Message : Type) where
  source : Node
  target : Node
  payload : Message
deriving Repr, BEq, ReflBEq, LawfulBEq

structure State (Node LocalState Message : Type) where
  nodes : List (Node × LocalState)
  active : List Node
  network : List (Envelope Node Message) := []
deriving Repr, BEq

inductive Action (Node Message Input : Type) where
  | local (node : Node) (input : Input)
  | deliver (envelope : Envelope Node Message)
deriving Repr, BEq

structure Protocol (Node LocalState LocalAction Message Input : Type) where
  init : Node -> LocalState -> Prop
  step : {σ : Type} -> Capabilities σ Node Message ->
    Node -> LocalState -> LocalAction -> Option (ST σ LocalState)
  receive : Node -> Message -> LocalAction
  internal : Input -> LocalAction

def nodeState [BEq Node]
    (state : State Node LocalState Message) (node : Node) : Option LocalState :=
  (state.nodes.find? fun entry => entry.1 == node).map Prod.snd

def replaceNode [BEq Node]
    (node : Node) (next : LocalState) (nodes : List (Node × LocalState)) :
    List (Node × LocalState) :=
  nodes.map fun entry => if entry.1 == node then (node, next) else entry

def removeOne [BEq α] (value : α) : List α -> List α
  | [] => []
  | head :: tail =>
      if head == value then tail else head :: removeOne value tail

def runStep
    (protocol : Protocol Node LocalState LocalAction Message Input)
    (node : Node) (state : LocalState) (action : LocalAction) :
    Option (LocalState × List (Node × Message)) := runST fun σ => do
  let outgoing <- (ST.mkRef [] : ST σ (ST.Ref σ (List (Node × Message))))
  let host : Capabilities σ Node Message := {
    send := fun message target => outgoing.modify (· ++ [(target, message)])
  }
  match protocol.step host node state action with
  | none => return none
  | some execute =>
      let next <- execute
      return some (next, <- outgoing.get)

def runLocal [BEq Node]
    (protocol : Protocol Node LocalState LocalAction Message Input)
    (state : State Node LocalState Message) (node : Node) (action : LocalAction) :
    Option (State Node LocalState Message) := do
  guard (state.active.contains node)
  let before <- nodeState state node
  let (after, outgoing) <- runStep protocol node before action
  pure {
    state with
    nodes := replaceNode node after state.nodes
    network := state.network ++ outgoing.map fun (target, payload) =>
      { source := node, target, payload }
  }

def next [BEq Node] [BEq Message]
    (protocol : Protocol Node LocalState LocalAction Message Input)
    (state : State Node LocalState Message) :
    Action Node Message Input -> Option (State Node LocalState Message)
  | .local node input =>
      runLocal protocol state node (protocol.internal input)
  | .deliver envelope => do
      guard (state.network.contains envelope)
      runLocal protocol
        { state with network := removeOne envelope state.network }
        envelope.target (protocol.receive envelope.source envelope.payload)

def lift [BEq Node] [BEq Message]
    (configured : List Node)
    (protocol : Protocol Node LocalState LocalAction Message Input) :
    TransitionSystem (State Node LocalState Message) (Action Node Message Input) where
  init state :=
    configured.Nodup /\
      state.nodes.map Prod.fst = configured /\
      state.active.Nodup /\
      (forall node, node ∈ state.active -> node ∈ configured) /\
      state.network = [] /\
      (forall entry, entry ∈ state.nodes -> protocol.init entry.1 entry.2)
  step := next protocol

end DisasterRecovery.Shared.Global
