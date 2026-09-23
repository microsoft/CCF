import DisasterRecovery.Model

namespace DisasterRecovery.Tests

def initial (config : Model.Config) (active : List Model.Local.Location) : Model.State := {
  nodes := config.protocol.expectedLocations.map fun node => (node, Model.Local.initialNode node)
  active
}

end DisasterRecovery.Tests
