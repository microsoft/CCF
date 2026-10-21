/- Copyright (c) Microsoft Corporation. All rights reserved.
Licensed under the Apache 2.0 License. -/
module

public import Shamir.Properties
public import Shamir.Proofs.CSLib

@[expose] public section

namespace CCF.Shamir

theorem sharing_refines_cslib : Properties.SharingRefinement :=
  sharing_refinement

theorem recovery_refines_cslib : Properties.RecoveryRefinement :=
  recovery_refinement

end CCF.Shamir
