module

public import CCFRaft.Properties.Liveness.Model.World

@[expose] public section

namespace CCFRaft.Liveness

open Model.Node

/-- One closed instantiation of the open world, for witnesses only.
Public statements quantify over any `W` with the required accessors. -/
structure World (S : Type) where
  /-- The protocol state. -/
  proto : S
  /-- The absolute clock. -/
  time : Real
  /-- The nodes that have not crashed. -/
  live : Finset NodeID
  /-- Outstanding send occurrences. -/
  pending : List Packet
  /-- The number of packets issued so far. -/
  issued : Nat

instance {S : Type} : HasProtocol (World S) S where
  proto := World.proto

instance {S : Type} : HasTime (World S) where
  time := World.time

instance {S : Type} : HasLive (World S) where
  live := World.live

instance {S : Type} : HasNetwork (World S) where
  pending := World.pending
  issued := World.issued

end CCFRaft.Liveness
