module

public import DisasterRecovery.Model

@[expose] public section

namespace DisasterRecovery.Tests

/-- Initializes every configured node with no queued messages. -/
def initial (config : Model.Config) : Model.State :=
  {
    nodes :=
      config.protocol.expectedLocations.map
        fun node => (node, Model.Local.initialNode node)
  }

open Model.Local

/-- A snapshot expected after the indicated writes commit. -/
def written (s : NodeState) (ws : CCF.OCC.Writes Table Key Value) : NodeState :=
  {s with store := CCF.OCC.publish s.store (s.version + 1) ws, version := s.version + 1}

/-- The normal view and outputs a successful run leaves pending. -/
def staged (config : Model.Config) (s : NodeState) (e : Event) : NodeState :=
  let ran := (transaction config.protocol e).exec s.store
  {s with pending := s.pending ++ [⟨e,ran.normal,ran.outputs⟩]}

end DisasterRecovery.Tests
