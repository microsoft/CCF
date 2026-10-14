import Std

namespace DisasterRecovery.Shared

/-!
A protocol node cannot see the network. It gets a `Capabilities` record with
two output-only callbacks, `send` and `notify`, and runs in the `Effect` monad,
which only accumulates those outputs. The host that runs the node decides what
the callbacks do. `Capabilities.record` is the canonical host: it appends each
send and notification to an `Outputs` record, which the network and the
property statements then read.
-/

/-- A message in flight from `source` to `target`. -/
structure Envelope (Node Message : Type) where
  /-- The node that emitted the message. -/
  source : Node
  /-- The node to which the message can be delivered. -/
  target : Node
  /-- The protocol-specific message content. -/
  payload : Message
deriving Repr, BEq, ReflBEq, LawfulBEq

/-- Everything a local step emitted, in emission order per list. -/
structure Outputs (Node Message Notification : Type) where
  /-- Messages emitted by the local computation, in send order. -/
  outgoing : List (Envelope Node Message) := []
  /-- Host notifications emitted by the local computation, in emission order. -/
  notifications : List Notification := []
deriving Repr, BEq

/-- A local computation that can only append to `Outputs`. -/
abbrev Effect (Node Message Notification : Type) :=
  StateM (Outputs Node Message Notification)

/-- The callbacks a host lends to a node for one step. Both return `Unit`. -/
structure Capabilities (Node Message Notification : Type) where
  /-- Appends a message addressed to the given node. -/
  send : Message -> Node -> Effect Node Message Notification Unit
  /-- Appends a host-visible protocol notification. -/
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

end DisasterRecovery.Shared
