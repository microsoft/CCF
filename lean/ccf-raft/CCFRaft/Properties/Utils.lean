-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFRaft.Model
import CCFRaft.Shared.Execution

namespace CCFRaft.Properties

/-- The states of one execution of the network, initial state first. -/
abbrev GlobalTrace (Node TxId : Type) := Shared.Execution.Trace (Model.State Node TxId)

end CCFRaft.Properties
