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

end DisasterRecovery.Tests
