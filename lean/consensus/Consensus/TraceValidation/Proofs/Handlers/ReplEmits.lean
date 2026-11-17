module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import Consensus.TraceValidation.Proofs.Obligation

import all Init.Control.State

@[expose] public section

/-!
# Clean effects that succeed with known sends (not reviewed)

`Emits x a sends`: the clean effect `x` succeeds from any outputs with result `a`, appending
exactly `sends` (and no notification). The `replicate` proof builds the clean `append` run
entry by entry with these rules.
-/

namespace Consensus.TraceValidation.Proofs.Repl

open Consensus.Model.Node

def Emits {α : Type} (x : NodeEffect α) (a : α)
    (sends : List (CCF.Envelope NodeID Message))
    : Prop :=
  forall out : CCF.Outputs NodeID Message Notification,
    x.run out = some (a, { out with outgoing := out.outgoing ++ sends })

variable {node : NodeID}

theorem emits_pure {α : Type} (a : α) : Emits (pure a : NodeEffect α) a [] := by
  intro out
  cases out
  simp [StateT.run, pure, StateT.pure]

theorem emits_bind {α β : Type} {x : NodeEffect α} {f : α -> NodeEffect β} {a : α} {b : β}
    {first later : List (CCF.Envelope NodeID Message)}
    (hx : Emits x a first) (hf : Emits (f a) b later)
    : Emits (x >>= f) b (first ++ later) := by
  intro out
  have := hx out
  simp only [StateT.run, bind, StateT.bind] at this ⊢
  rw [this]
  simp only [Option.bind]
  have := hf { out with outgoing := out.outgoing ++ first }
  simp only [StateT.run, List.append_assoc] at this
  exact this

theorem emits_send (message : Message) (target : NodeID)
    : Emits ((CCF.Capabilities.record node).send message target) ()
        [⟨node, target, message⟩] := by
  intro out
  rfl

theorem emits_guard {p : Prop} [Decidable p] (h : p)
    : Emits (guard p : NodeEffect Unit) () [] := by
  intro out
  cases out
  simp [guard, h, StateT.run, pure, StateT.pure]

theorem emits_congr {α : Type} {x : NodeEffect α} {a b : α}
    {first later : List (CCF.Envelope NodeID Message)}
    (h : Emits x a first) (same : a = b) (sends : first = later)
    : Emits x b later := by
  subst same sends
  exact h

theorem emits_run {α : Type} {x : NodeEffect α} {a : α}
    {sends : List (CCF.Envelope NodeID Message)}
    (h : Emits x a sends)
    : x.run {} = some (a, { outgoing := sends }) :=
  h {}

theorem emits_ite_guard_bind {β : Type} {c : Prop} [Decidable c] {p : Prop} [Decidable p]
    {k : Unit -> NodeEffect β} {b : β} {sends : List (CCF.Envelope NodeID Message)}
    (h : c -> p) (hk : Emits (k ()) b sends)
    : Emits (if c then (guard p : NodeEffect Unit) >>= k else k ()) b sends := by
  split
  · rename_i yes
    exact emits_congr (emits_bind (emits_guard (h yes)) hk) rfl (List.nil_append _)
  · exact hk

theorem emits_forIn_send (peers : List NodeID) (f : NodeID -> Message)
    : Emits
        (forIn peers PUnit.unit
            fun peer _ => do
              (CCF.Capabilities.record node).send (f peer) peer
              pure (ForInStep.yield PUnit.unit)
          : NodeEffect PUnit)
        PUnit.unit (peers.map fun peer => ⟨node, peer, f peer⟩) := by
  induction peers with
  | nil => exact emits_pure _
  | cons peer rest ih =>
      rw [List.forIn_cons]
      exact emits_congr
        (emits_bind
          (x := do
            (CCF.Capabilities.record node).send (f peer) peer;
            pure (ForInStep.yield PUnit.unit))
          (a := ForInStep.yield PUnit.unit)
          (emits_bind (f := fun _ => pure (ForInStep.yield PUnit.unit)) (emits_send _ _)
            (emits_pure _)) ih)
        rfl (by simp)

end Consensus.TraceValidation.Proofs.Repl
