module

public section

namespace CCF

universe u

/-- A universal implication together with an applicable case.
The extra witness predicate strengthens only existence, never the implication. -/
structure WitnessedTheorem {Case : Type u}
    («requires» : Case -> Prop)

    («ensures» : Case -> Prop)

    (witness_satisfies : Case -> Prop := fun _ => True)
    : Prop where

  /-- The conclusion holds for every case satisfying the premises. -/
  proof : forall c, «requires» c -> «ensures» c

  /-- Some case satisfies the premises and the extra witness predicate. -/
  witness_proof : exists c, «requires» c /\ witness_satisfies c

end CCF
