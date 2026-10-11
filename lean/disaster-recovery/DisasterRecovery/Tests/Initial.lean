/-
Copyright (c) 2026 Microsoft Corporation. All rights reserved.
Licensed under the Apache 2.0 License.
Authors: Microsoft Corporation
-/
import DisasterRecovery.Model

/-! Initial network states used by the recovery regression tests. -/

namespace DisasterRecovery.Tests

def initial (config : Model.Config) (active : List Model.Local.Location) : Model.State :=
  {
    nodes :=
      config.protocol.expectedLocations.map
        fun node => (node, Model.Local.initialNode node)
    active
  }

end DisasterRecovery.Tests
