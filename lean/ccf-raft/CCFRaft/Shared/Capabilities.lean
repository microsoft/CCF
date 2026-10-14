import Std

namespace CCFRaft.Shared

variable {Node Message Notification : Type}

/-!
A node runs in `Effect`, which can only emit outputs through the `send` and
`notify` callbacks in `Capabilities`, or fail. Failure means the step is
disabled and discards any outputs. `Capabilities.record` collects outputs in
an `Outputs` record for the network to read.
-/

/-- A message in flight from `source` to `target`. -/
structure Envelope (Node Message : Type) where
  source : Node
  target : Node
  payload : Message
deriving Repr, BEq, ReflBEq, LawfulBEq

/-- Everything a local step emitted, in emission order per list. -/
structure Outputs (Node Message Notification : Type) where
  outgoing : List (Envelope Node Message) := []
  notifications : List Notification := []
deriving Repr, BEq

/-- A local computation that can append to `Outputs` or fail when disabled. -/
abbrev Effect (Node Message Notification : Type) :=
  StateT (Outputs Node Message Notification) Option

/-- The callbacks a host lends to a node for one step. Both return `Unit`. -/
structure Capabilities (Node Message Notification : Type) where
  send : Message -> Node -> Effect Node Message Notification Unit
  notify : Notification -> Effect Node Message Notification Unit

/-- The recording host: sends become envelopes from `source`, notifications are kept. -/
def Capabilities.record (source : Node) : Capabilities Node Message Notification where
  send message target :=
    modify
      fun outputs =>
        {
          outputs with
            outgoing := outputs.outgoing ++ [{ source, target, payload := message }]
        }
  notify notification :=
    modify
      fun outputs =>
        { outputs with notifications := outputs.notifications ++ [notification] }

end CCFRaft.Shared
