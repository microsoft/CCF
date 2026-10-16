module

-- The public interface erases theorem bodies; inspect their implementation metadata.
import all DisasterRecovery.Proof
meta import CCF.Architecture

public import CCF.Architecture
public import DisasterRecovery.Proof

@[expose] public section

namespace DisasterRecovery.Tests.ProofCoverage

open Lean

-- Every public claim, including each non-vacuity claim, needs an exported theorem.
run_cmd do
  for error in CCF.Architecture.coverageErrors (← getEnv) `DisasterRecovery true do
    throwError error

end DisasterRecovery.Tests.ProofCoverage
