module

meta import CCF.Architecture

public import CCF.Architecture
public import Kv.Properties

@[expose] public section

namespace Kv.Tests.Architecture

/--
error: Unknown identifier `undeclaredType`

Note: It is not possible to treat `undeclaredType` as an implicitly bound variable here because the `autoImplicit` option is set to `false`.
-/
#guard_msgs in
example (value : undeclaredType) := value

run_cmd do
  let env ← Lean.getEnv
  for name in #[`Kv.Properties.Reachable, `Kv.Proofs.Types.normalRun_append] do
    if env.contains name then
      Lean.throwError "Removed model/property API must not be reintroduced: {name}"
  for name in env.header.moduleNames do
    if (`Kv.Protocol).isPrefixOf name || name == `Kv.Trace || name == `Kv.Proofs.Types then
      Lean.throwError "Removed module must not be reintroduced: {name}"
  for error in CCF.Architecture.layeringErrors env `Kv do
    Lean.throwError error

end Kv.Tests.Architecture
