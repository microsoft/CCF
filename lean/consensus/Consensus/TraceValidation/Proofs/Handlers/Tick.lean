module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import Consensus.TraceValidation.Proofs.Handlers.TickElect

@[expose] public section

/-!
# The `Tick` obligation (not reviewed)

`Exec.periodic` is sound: its hold is matched by zero clean inputs, by heartbeats
(`sendEntries`), by a CheckQuorum step-down (`timeout .checkQuorum`) or by an election
timeout (`timeout .election`), as `tick_tri` and `el_tri` show over the ghost clean run.
-/

namespace Consensus.TraceValidation.Proofs

open Consensus.Model.Node
open Consensus.TraceValidation.Exec
open Consensus.TraceValidation (Names abs agrees inv)

theorem Tick.agrees_abs (names : Names) (d : State)
    : agrees names (abs names d) d = true := by
  simp [agrees]

theorem tickSound (env : Env) : TickSound env := by
  intro node saved actions c vars others cleanOthers _ self invS _ _ ran _ finished invVars
  simp only [plainFinish, Except.ok.injEq] at finished
  subst finished
  have post := fun (clean0 : NodeState) (ag : agrees env.names clean0 saved = true) =>
    Life.Tri.run (Tick.tick_tri invS self ag fun _ _ _ => Tick.el_tri invS self ag)
      ⟨rfl, rfl⟩ ran
  refine ⟨(post _ (Tick.agrees_abs env.names saved)).1, fun clean _ ag unmatched => ?_⟩
  obtain ⟨inputs, clean', run, ad, sendsInv, ag', un⟩ := (post clean ag).2 invVars
  exact ⟨
    inputs,
    clean',
    by simpa [cleanActions] using run,
    ag',
    un unmatched,
    fun input mem => ad input mem cleanOthers,
    sendsInv
  ⟩

end Consensus.TraceValidation.Proofs
