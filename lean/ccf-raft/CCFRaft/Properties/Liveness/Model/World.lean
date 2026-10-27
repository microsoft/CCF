module

public import CCFRaft.Properties.Liveness.Model.Event

@[expose] public section

namespace CCFRaft.Liveness

open Model.Node

/-- Access to the protocol state, without fixing the rest of the world. -/
class HasProtocol (W : Type) (S : outParam Type) where
  proto : W -> S

/-- An absolute real-valued clock. -/
class HasTime (W : Type) where
  time : W -> Real

/-- Crash-stop availability. -/
class HasLive (W : Type) where
  live : W -> Finset NodeID

/-- The network ledger: outstanding send occurrences, distinct even for equal
envelopes, and the number of packets issued so far. -/
class HasNetwork (W : Type) where
  pending : W -> List Packet
  issued : W -> Nat

end CCFRaft.Liveness
