module

public import CCF.MultiNodeTransitionSystem
public import CCF.Execution
public import CCF.Observation

@[expose] public section

namespace CCF.Sections

/-!
Event-granular nodes with critical sections, and their refinement obligation
towards a `MultiNodeTransitionSystem.Protocol`.

A node machine takes one step per implementation event; a step is a partial function
of the node's local state, the delivered message (if any) and the event, and emits
nothing. The first event of a section takes the node's lock and may consume one queued
envelope. A silent `release` step runs the machine's `close` on the node's local state
and the other nodes' abstracted local states (which it may read, for example to find a
committed prefix to install), yielding the state after the section's untraced trailing
code and the section's sends in order; release then removes the consumed envelope from
the network and publishes the sends.

A clean state simulates an event-granular state when the networks agree and each
node's clean state is related, by the refinement's `rel`, to the node's state at lock
acquisition (`entry`), or to its current state when it holds no lock. `Refinement`
packages the local obligation: every complete section from an idle state corresponds to
clean local steps with the same sends, each admitted by `admit`. The lifting theorems are
in `CCF.Proofs.Sections` and `CCF.Proofs.SectionsObservation`.
-/

open MultiNodeTransitionSystem (nodeState removeOne)

/-- An event-granular node. -/
structure Machine (Node Message LocalState Event : Type) where
  /-- Initial local states. -/
  init : Node -> LocalState -> Prop
  /-- Whether no section is open in this state. -/
  idle : LocalState -> Bool
  /-- Events that take the lock: they may only occur outside a section. -/
  opens : Event -> Bool
  /-- One event, with the message (and its sender) it delivers, if any. -/
  step : Node -> LocalState -> Option (Node × Message) -> Event -> Option LocalState
  /--
  The section's untraced trailing code, and every send of the section, in order, given
  the other nodes' abstracted local states.
  -/
  close
    : List (Node × LocalState) -> Node -> LocalState
      -> Option (LocalState × List (Envelope Node Message))

/-- A node's machine state plus the bookkeeping of its open section. -/
structure Slot (Node Message LocalState : Type) where
  /-- The machine state after the latest event. -/
  current : LocalState
  /-- Ghost: the state at lock acquisition; `none` when the lock is free. -/
  entry : Option LocalState := none
  /-- The envelope consumed by the section's first event, still in the network. -/
  inbox : Option (Envelope Node Message) := none

/-- Global states reuse the network composition's node table and network. -/
abbrev State (Node Message LocalState : Type) :=
  MultiNodeTransitionSystem.State Node (Slot Node Message LocalState) Message

/-- A node consumes an event, an event delivers a queued envelope, or a node releases. -/
inductive Action (Node Message Event : Type) where
  /-- The node takes an event without receiving a message. -/
  | event (node : Node) (event : Event)
  /-- The envelope's target opens a section by receiving it. -/
  | deliver (envelope : Envelope Node Message) (event : Event)
  /-- The node ends its section and publishes its sends. -/
  | release (node : Node)

/-- Overwrite a node's table entry, like `MultiNodeTransitionSystem.next` does. -/
def setNode {Node LocalState Message : Type} [BEq Node]
    (state : MultiNodeTransitionSystem.State Node LocalState Message) (node : Node)
    (value : LocalState)
    : MultiNodeTransitionSystem.State Node LocalState Message :=
  {
    state with
      nodes :=
        state.nodes.map fun entry => if entry.1 == node then (node, value) else entry
  }

/-- The table without `node`. -/
def without {Node LocalState : Type} [BEq Node] (nodes : List (Node × LocalState))
    (node : Node)
    : List (Node × LocalState) :=
  nodes.filter fun entry => !(entry.1 == node)

/-- Two node tables with the same keys in the same order, related entrywise. -/
inductive Keyed {Node A B : Type} (related : Node -> A -> B -> Prop)
    : List (Node × A) -> List (Node × B) -> Prop where
  /-- Empty tables. -/
  | nil : Keyed related [] []
  /-- Related heads under one key, then related tails. -/
  | cons {node : Node} {left : A} {right : B} {lefts : List (Node × A)}
    {rights : List (Node × B)} (holds : related node left right)
    (rest : Keyed related lefts rights)
    : Keyed related ((node, left) :: lefts) ((node, right) :: rights)

/-- A slot's abstracted local state: its state at lock acquisition while it holds the lock. -/
def Slot.base {Node Message LocalState : Type} (slot : Slot Node Message LocalState)
    : LocalState :=
  slot.entry.getD slot.current

/-- One global step of the event-granular network. -/
def next {Node Message LocalState Event : Type} [BEq Node] [BEq Message]
    (machine : Machine Node Message LocalState Event)
    (state : State Node Message LocalState)
    : Action Node Message Event -> Option (State Node Message LocalState)
  | .event node event => do
      let slot <- nodeState state node
      guard (!machine.opens event || slot.entry.isNone)
      let current <- machine.step node slot.current none event
      pure
        (setNode state node
          { slot with current, entry := slot.entry.orElse fun _ => some slot.current })
  | .deliver envelope event => do
      guard (state.network.contains envelope)
      let node := envelope.target
      let slot <- nodeState state node
      guard (slot.entry.isNone)
      let current <- machine.step node slot.current
                      (some (envelope.source, envelope.payload)) event
      pure
        (setNode state node
          { current, entry := some slot.current, inbox := some envelope })
  | .release node => do
      let slot <- nodeState state node
      guard (slot.entry.isSome)
      let (current, sends) <- machine.close
                                ((without state.nodes node).map
                                  fun entry => (entry.1, entry.2.base))
                                node slot.current
      guard (machine.idle current)
      let pending <- match slot.inbox with
                      | none => pure state.network
                      | some envelope => do
                          guard (state.network.contains envelope)
                          pure (removeOne envelope state.network)
      pure { setNode state node { current } with network := pending ++ sends }

/-- The event-granular network: distinct nodes, idle initial states, empty network. -/
abbrev lift {Node Message LocalState Event : Type} [BEq Node] [BEq Message]
    (machine : Machine Node Message LocalState Event)
    : TransitionSystem where
  State := State Node Message LocalState
  Action := Action Node Message Event
  init state :=
    (state.nodes.map Prod.fst).Nodup
    /\ state.network = []
    /\ (forall entry,
          entry ∈ state.nodes
          -> entry.2.entry = none
              /\ entry.2.inbox = none
              /\ machine.init entry.1 entry.2.current)
  step := next machine

/-- Non-delivering events of one node. -/
inductive Steps {Node Message LocalState Event : Type}
    (machine : Machine Node Message LocalState Event) (node : Node)
    : LocalState -> List Event -> LocalState -> Prop where
  /-- No events. -/
  | nil (state : LocalState) : Steps machine node state [] state
  /-- One event, then the rest. -/
  | cons {state middle finish : LocalState} {event : Event} {events : List Event}
    (step : machine.step node state none event = some middle)
    (rest : Steps machine node middle events finish)
    : Steps machine node state (event :: events) finish

/-- A section's events: a first event, possibly delivering `received`, then the rest. -/
def SectionRun {Node Message LocalState Event : Type}
    (machine : Machine Node Message LocalState Event) (node : Node)
    (start : LocalState) (received : Option (Node × Message)) (events : List Event)
    (finish : LocalState)
    : Prop :=
  exists (first : Event) (rest : List Event) (middle : LocalState),
    events = first :: rest
    /\ machine.step node start received first = some middle
    /\ Steps machine node middle rest finish

/-- Clean local steps of one node, accumulating its sends. -/
inductive LocalRun {Node LocalState LocalAction Message Notification Input : Type}
    (protocol
      : MultiNodeTransitionSystem.Protocol Node LocalState LocalAction Message
          Notification Input)
    (node : Node)
    : LocalState -> List LocalAction -> LocalState -> List (Envelope Node Message)
      -> Prop where
  /-- No steps. -/
  | nil (state : LocalState) : LocalRun protocol node state [] state []
  /-- One enabled local step, then the rest. -/
  | cons {state middle finish : LocalState} {action : LocalAction}
    {actions : List LocalAction} {effects : Outputs Node Message Notification}
    {sends : List (Envelope Node Message)}
    (step
      : (protocol.step (Capabilities.record node) node state action).run {}
        = some (middle, effects))
    (rest : LocalRun protocol node middle actions finish sends)
    : LocalRun protocol node state (action :: actions) finish (effects.outgoing ++ sends)

/--
The clean network where an internal input of a node is enabled only if `admit` accepts
it given the other nodes' states. Specifications that guard internal inputs on global
state (for example, joining from a committed prefix) are reached from this one.
-/
def guardedNext {Node Message CleanState LocalAction Notification Input : Type}
    [BEq Node] [BEq Message]
    (protocol
      : MultiNodeTransitionSystem.Protocol Node CleanState LocalAction Message
          Notification Input)
    (admit : List (Node × CleanState) -> Node -> Input -> Bool)
    (state : MultiNodeTransitionSystem.State Node CleanState Message)
    : MultiNodeTransitionSystem.Action Node Message Input
      -> Option (MultiNodeTransitionSystem.State Node CleanState Message)
  | .local node input =>
      if admit (without state.nodes node) node input then
        MultiNodeTransitionSystem.next protocol state (.local node input)
      else
        none
  | .deliver envelope => MultiNodeTransitionSystem.next protocol state (.deliver envelope)

/-- `MultiNodeTransitionSystem.lift` with `guardedNext` steps. -/
abbrev guarded {Node Message CleanState LocalAction Notification Input : Type}
    [BEq Node] [BEq Message]
    (protocol
      : MultiNodeTransitionSystem.Protocol Node CleanState LocalAction Message
          Notification Input)
    (admit : List (Node × CleanState) -> Node -> Input -> Bool)
    : TransitionSystem :=
  { MultiNodeTransitionSystem.lift protocol with step := guardedNext protocol admit }

/--
The local obligation, relative to a relation `rel` between clean and machine local
states (which also carries any local invariant) and an invariant `msgInv` of messages in
flight. Initial machine states are idle and related to clean initial states. Every
complete section from an idle state related to `clean`, which received a message
satisfying `msgInv` (if any), closed given other nodes related to `cleanOthers`,
corresponds to: the clean receive of that message, if any, followed by admitted clean
internal inputs, from `clean` to a clean state related to the released state, with
exactly the section's sends; and every send satisfies `msgInv`.
-/
structure Refinement
    {Node Message LocalState Event CleanState LocalAction Notification Input : Type}
    (machine : Machine Node Message LocalState Event)
    (protocol
      : MultiNodeTransitionSystem.Protocol Node CleanState LocalAction Message
          Notification Input)
    (admit : List (Node × CleanState) -> Node -> Input -> Bool) where
  /-- What every machine message in flight satisfies. -/
  msgInv : Envelope Node Message -> Prop
  /-- Relates a node's clean state to its machine state. -/
  rel : Node -> CleanState -> LocalState -> Prop
  /-- Initial states are idle and related to a clean initial state. -/
  init_sound
    : forall node state,
        machine.init node state
        -> machine.idle state = true
            /\ exists clean, protocol.init node clean /\ rel node clean state
  /-- Every complete section is an admitted clean local run with the same sends. -/
  section_sound
    : forall node start received events middle finish sends clean
              (others : List (Node × LocalState))
              (cleanOthers : List (Node × CleanState)),
        machine.idle start = true
        -> rel node clean start
        -> (forall source message,
              received = some (source, message) -> msgInv ⟨source, node, message⟩)
        -> SectionRun machine node start received events middle
        -> machine.close others node middle = some (finish, sends)
        -> machine.idle finish = true
        -> Keyed (fun other local_ cleanOther => rel other cleanOther local_) others
            cleanOthers
        -> exists (inputs : List Input) (clean' : CleanState),
            LocalRun protocol node clean
              ((received.map
                  fun (source, message) => protocol.receive source message).toList
                ++ inputs.map protocol.internal)
              clean' sends
            /\ rel node clean' finish
            /\ (forall input, input ∈ inputs -> admit cleanOthers node input = true)
            /\ forall envelope, envelope ∈ sends -> msgInv envelope

open ObservationRefinement (Observation)

/--
`Emits machine declare start actions finish observations`: the actions run from `start`
to `finish`, and every event action emits one observation carrying the acting node's
declared state after the event. Releases emit nothing.
-/
inductive Emits {Node Message LocalState Event Declared : Type} [BEq Node] [BEq Message]
    (machine : Machine Node Message LocalState Event) (declare : LocalState -> Declared)
    : State Node Message LocalState -> List (Action Node Message Event)
      -> State Node Message LocalState -> List (Observation Node Event Declared)
      -> Prop where
  /-- No actions. -/
  | nil (state : State Node Message LocalState) : Emits machine declare state [] state []
  /-- A node takes an event. -/
  | event {before middle after : State Node Message LocalState} {node : Node}
    {event : Event} {slot : Slot Node Message LocalState}
    {actions : List (Action Node Message Event)}
    {observations : List (Observation Node Event Declared)}
    (step : next machine before (.event node event) = some middle)
    (found : MultiNodeTransitionSystem.nodeState middle node = some slot)
    (rest : Emits machine declare middle actions after observations)
    : Emits machine declare before (.event node event :: actions) after
        (⟨node, event, declare slot.current⟩ :: observations)
  /-- A node receives an envelope with an event. -/
  | deliver {before middle after : State Node Message LocalState}
    {envelope : Envelope Node Message} {event : Event}
    {slot : Slot Node Message LocalState} {actions : List (Action Node Message Event)}
    {observations : List (Observation Node Event Declared)}
    (step : next machine before (.deliver envelope event) = some middle)
    (found : MultiNodeTransitionSystem.nodeState middle envelope.target = some slot)
    (rest : Emits machine declare middle actions after observations)
    : Emits machine declare before (.deliver envelope event :: actions) after
        (⟨envelope.target, event, declare slot.current⟩ :: observations)
  /-- A node releases its lock. -/
  | release {before middle after : State Node Message LocalState} {node : Node}
    {actions : List (Action Node Message Event)}
    {observations : List (Observation Node Event Declared)}
    (step : next machine before (.release node) = some middle)
    (rest : Emits machine declare middle actions after observations)
    : Emits machine declare before (.release node :: actions) after observations

/--
Some run of the network, from an initial state over exactly the nodes `keys`, emits
exactly `observations` and ends with every lock released.
-/
def Accepts {Node Message LocalState Event Declared : Type} [BEq Node] [BEq Message]
    (machine : Machine Node Message LocalState Event) (declare : LocalState -> Declared)
    (keys : List Node) (observations : List (Observation Node Event Declared))
    : Prop :=
  exists start actions finish,
    (lift machine).init start
    /\ start.nodes.map Prod.fst = keys
    /\ Emits machine declare start actions finish observations
    /\ forall entry, entry ∈ finish.nodes -> entry.2.entry = none

end CCF.Sections
