module

public import CCFRaft.Model
public import Mathlib.Basic.Real.Basic

@[expose] public section

namespace CCFRaft.Liveness

open Model.Node

/-- A send occurrence, distinguished even when two envelopes have equal contents. -/
structure Packet where
  /-- Sequence number issued by the network ledger; identity, not content. -/
  id : Nat
  envelope : Model.Envelope
  /-- Absolute time in the sending step's before-state, when the step happens. -/
  sentAt : Real

/-- Packets are identified by their issued sequence number, not by content. -/
def Packet.sameIdentity (left right : Packet) : Bool :=
  left.id == right.id

/-- Environment events interleave with the unchanged local protocol and deliveries. -/
inductive Event where
  | local (node : NodeID) (input : Input)
  | deliver (packet : Packet)
  | drop (packet : Packet)
  | crash (node : NodeID)
  | idle

/-- The envelope received by this event. -/
def Event.delivered : Event -> Option Model.Envelope
  | .deliver packet => some packet.envelope
  | _ => none

/-- Erase environment-only events. -/
def Event.action : Event -> Option Model.Action
  | .local node input => some (.local node input)
  | .deliver packet => some (.deliver packet.envelope)
  | _ => none

/-- The node executing a protocol step, or the node being crashed. -/
def Event.actor : Event -> Option NodeID
  | .local node _ | .crash node => some node
  | .deliver packet => some packet.envelope.target
  | _ => none

/-- The packet consumed by a delivery or drop. -/
def Event.consumedPacket : Event -> Option Packet
  | .deliver packet | .drop packet => some packet
  | _ => none

end CCFRaft.Liveness
