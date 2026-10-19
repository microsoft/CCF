-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

-- The public interface erases theorem bodies; inspect their implementation metadata.
import all Kv.Proof
meta import CCF.Architecture

public import CCF.Architecture
public import Kv.Proof

@[expose] public section

namespace Kv.Tests.ProofCoverage

-- Every public claim needs an exported theorem, and a non-vacuity claim if it has premises.
run_cmd do
  for error in ← Lean.Elab.Command.liftTermElabM (CCF.Architecture.coverageErrors `Kv) do
    Lean.throwError error

end Kv.Tests.ProofCoverage
