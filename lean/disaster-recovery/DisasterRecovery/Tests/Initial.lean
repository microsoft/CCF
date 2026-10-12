import DisasterRecovery.Model

namespace DisasterRecovery.Tests

/-- Initialize every configured node, with only the supplied locations active. -/
def initial (config : Model.Config) (active : List Model.Local.Location) : Model.State :=
  {
    nodes :=
      config.protocol.expectedLocations.map
        fun node => (node, Model.Local.initialNode node)
    active
  }

end DisasterRecovery.Tests
