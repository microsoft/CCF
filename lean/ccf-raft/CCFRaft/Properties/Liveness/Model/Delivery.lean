module

public import CCFRaft.Properties.Liveness.Model.Protocol

@[expose] public section

namespace CCFRaft.Liveness

open Model.Node (NodeID)
open HasProtocol (proto)
open HasTime (time)
open HasLive (live)
open HasNetwork (pending issued)

/-- The outstanding packets that remain after an event: all but the one it
consumes, erased by send identity, so equal envelopes remain distinct occurrences. -/
def Event.remaining (event : Event) (pending : List Packet) : List Packet :=
  match event.consumedPacket with
  | some packet => pending.eraseP packet.sameIdentity
  | none => pending

/-- Each channel is FIFO with loss: a delivered packet is the oldest outstanding
packet from its source to its target. Drops are unrestricted, so a packet can
overtake an earlier one only if the earlier one is lost.
This matches CCF's node-to-node channels: senders number messages in send order,
and `Channel::decrypt` in `src/node/channels.h` rejects any nonce that is not above
the last one received, so an overtaken message is dropped on arrival.
Needed: otherwise the primary can split a pass of `k` entries, appended in zero
time before the next signature, into single-entry AppendEntries that arrive in
reverse order. Every batch except the earliest arrives before the entry it extends
and is rejected, so a peer gains one entry per round trip. Commit latency then
grows with `k` even though the backlog at `start` is zero. -/
def Event.InOrder (event : Event) (pending : List Packet) : Prop :=
  match event with
  | .deliver packet =>
      forall other,
        other ∈ pending
        -> other.envelope.source = packet.envelope.source
        -> other.envelope.target = packet.envelope.target
        -> packet.id <= other.id
  | _ => True

/-- A step's outputs as packets, numbered on from `first`, all sent at `sentAt`. -/
def Packet.batch (emitted : List Model.Envelope) (first : Nat) (sentAt : Real)
    : List Packet :=
  (emitted.zipIdx first).map fun (envelope, id) => { id, envelope, sentAt }

/-- Constrain the packet ledger, without changing protocol, time or availability.
The ledger starts empty with no packets issued; consumption precedes registration
of this step's outputs, and delivery is in order on each channel (`Event.InOrder`).
Each output receives the next sequence number and the before-time of its sending step.
`Model.transitionSystem config nodes` checks that a protocol action producing outputs is
enabled. -/
def deliveryModel {W : Type} [HasProtocol W Model.State] [HasTime W] [HasNetwork W]
    (config : Finset NodeID) (nodes : List NodeID)
    : Model W Event where
  init world := pending world = [] /\ issued world = 0
  next step :=
    (match step.action.consumedPacket with
      | some packet => packet ∈ pending step.before
      | none => True)
    /\ step.action.InOrder (pending step.before)
    /\ exists emitted,
        (match step.action.action with
          | some action => do
              let _ <- (Model.transitionSystem config nodes).step (proto step.before)
                        action
              outgoing (proto step.before) action
          | none => some [])
          = some emitted
        /\ issued step.after = issued step.before + emitted.length
        /\ pending step.after
            = step.action.remaining (pending step.before)
              ++ Packet.batch emitted (issued step.before) (time step.before)

/-- A separate deadline constraint on outstanding packets to live targets.
The delay bound must be nonnegative, even when no packets are pending.
It permits loss: dropping a packet removes the obligation.
No deadline state or delivery bound is built into `deliveryModel`. -/
def boundedDelayModel {W : Type} [HasTime W] [HasLive W] [HasNetwork W] (maxDelay : Real)
    : Model W Event where
  init world :=
    0 <= maxDelay
    /\ forall packet,
        packet ∈ pending world
        -> packet.envelope.target ∈ live world
        -> time world <= packet.sentAt + maxDelay
  next step :=
    forall packet,
      packet ∈ pending step.after
      -> packet.envelope.target ∈ live step.after
      -> time step.after <= packet.sentAt + maxDelay

end CCFRaft.Liveness
