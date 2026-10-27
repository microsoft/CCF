module

public import CCFRaft.Properties.Liveness.Model.Timing

@[expose] public section

namespace CCFRaft.Liveness

open Model.Node

open HasProtocol (proto)

variable {W : Type} [HasProtocol W Model.State]

/-- Request identity, independent of its log position or election term. -/
def HasRequest (log : List Entry) (request : ReqID) : Prop :=
  exists entry,
    entry ∈ log /\ exists metadata, entry.content = .transaction request metadata

end CCFRaft.Liveness
