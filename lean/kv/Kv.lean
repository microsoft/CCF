-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import Kv.AxiomAudit
import Kv.Proofs.Model
import Kv.Proofs.Trace
import Kv.Proofs.Types
import Kv.Properties
import Kv.Protocol.Invariants
import Kv.Protocol.Model
import Kv.Protocol.Programs
import Kv.Protocol.Types
import Kv.Trace

run_cmd Kv.BuildAudit.auditLibrary
