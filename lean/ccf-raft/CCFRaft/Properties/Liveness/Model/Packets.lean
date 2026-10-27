module

public import CCFRaft.Properties.Liveness.Model.Delivery

@[expose] public section

open CCF.Execution (Trace)

namespace CCFRaft.Liveness

open HasNetwork (pending)

variable {W : Type} [HasNetwork W]

/-- The packet first appears in the ledger after step `index`: it was sent there.
Identity is the ledger's sequence number, so this reads only the network state. -/
def SentAt (trace : Trace W Event) (index : Nat) (packet : Packet) : Prop :=
  exists step,
    trace.stepAt index = some step
    /\ packet ∈ pending step.after
    /\ Not (packet ∈ pending step.before)

end CCFRaft.Liveness
