-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

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
  for error in CCF.Architecture.layeringErrors (← Lean.getEnv) `Kv do
    Lean.throwError error

end Kv.Tests.Architecture
