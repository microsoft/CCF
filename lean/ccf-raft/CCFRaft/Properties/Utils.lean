module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import CCFRaft.Model
public import CCF.Execution

@[expose] public section

namespace CCFRaft.Properties

abbrev GlobalTrace (Node TxId : Type) := CCF.Execution.Trace (Model.State Node TxId)

end CCFRaft.Properties
