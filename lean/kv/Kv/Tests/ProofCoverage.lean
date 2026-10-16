module

-- The public interface erases theorem bodies; inspect their implementation metadata.
import all Kv.Proof
meta import CCF.Architecture

public import CCF.Architecture
public import Kv.Proof

@[expose] public section

namespace Kv.Tests.ProofCoverage

-- Every public claim needs an exported theorem. Non-vacuity witnesses are not yet required.
run_cmd do
  for error in CCF.Architecture.coverageErrors (← Lean.getEnv) `Kv false do
    Lean.throwError error

end Kv.Tests.ProofCoverage
