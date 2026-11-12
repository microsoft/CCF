-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import Kv.Properties.Semantics
public import CCF.Execution

@[expose] public section

namespace Kv.Properties

open Kv.Model

/-- The selected attempt is neither destroyed nor recreated by this semantic input. -/
def AttemptAction (tid : Nat) : Action → Prop
  | .txCreate _ actual | .txEnd _ actual => actual ≠ tid
  | _ => True

/-- The selected store is neither created, destroyed, nor successfully rolled back. -/
def SegmentAction (w : State) (sid : Nat) : Action → Prop
  | .storeCreate actual _ | .storeEnd actual => actual ≠ sid
  | .rollback actual requested _ =>
      actual ≠ sid ∨ ∃ s, find w.stores actual = some s ∧ requested < s.global
  | _ => True

/-- Every actual step along these inputs respects the selected store's branch boundary. -/
def SegmentInputs (w : State) (sid : Nat) : List Action → Prop
  | [] => True
  | a :: rest =>
      SegmentAction w sid a
      ∧ ∀ next, transitionSystem.step w a = some next → SegmentInputs next sid rest

/-- The live attempt an actual semantic input applies to the selected store. -/
def appliedTransaction (w : State) (sid : Nat) : Action → List Tx
  | .apply actual tid =>
      if actual = sid then ((lookupTx w actual tid).map Prod.snd).toList else []
  | _ => []

/-- Execute semantic inputs and extract their actual pre-application attempts in order. -/
def applicationInputs (w : State) (sid : Nat) : List Action → Option (List Tx)
  | [] => some []
  | a :: rest => do
      let next ← transitionSystem.step w a
      let tail ← applicationInputs next sid rest
      return appliedTransaction w sid a ++ tail

end Kv.Properties
