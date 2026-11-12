-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import Generated.CcfShamir
public import Shamir.Model.Field

/-!
# The Shamir model

The executable model is `Generated.CcfShamir`, in the `ccf_shamir` namespace. It is not written by
hand: Aeneas extracts it from the production Rust core in `src/rust/shamir`, and CI checks that
the committed file is reproduced exactly. This extraction links the model to the implementation
in place of the trace validation used by the other CCF specifications.

This module assembles that model with the field its arithmetic is interpreted in.
-/

@[expose] public section

open Aeneas Aeneas.Std

namespace Shamir.Model

/-- A default share, so that shares can be read from a slice by index. -/
instance inhabitedShare : Inhabited ccf_shamir.Share :=
  ⟨⟨0#u32, Array.repeat 10#usize 0#u32⟩⟩

end Shamir.Model
