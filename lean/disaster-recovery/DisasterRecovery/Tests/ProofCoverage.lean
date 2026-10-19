module

-- The public interface erases theorem bodies; inspect their implementation metadata.
import all DisasterRecovery.Proof
meta import CCF.Architecture

public import CCF.Architecture
public import DisasterRecovery.Proof

@[expose] public section

namespace DisasterRecovery.Tests.ProofCoverage

-- Every public claim needs an exported theorem, and a non-vacuity claim if it has premises.
run_cmd do
  for error in ← Lean.Elab.Command.liftTermElabM (CCF.Architecture.coverageErrors `DisasterRecovery) do
    Lean.throwError error

end DisasterRecovery.Tests.ProofCoverage
