module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import Consensus.TraceValidation.Proofs.Handlers.LifeHoare

import all Init.Control.State

@[expose] public section

/-!
# Clean runs alongside a hold (not reviewed; `Tick` obligation)

A hold's declared run is related to clean internal steps through a ghost predicate on the
declared state and outbox: `Acc env node clean0 R v o` says the outbox `o` is the sends of
clean internal steps from `clean0` that reach a clean state related to `v` by `R`. Hoare
triples (`Life.Tri`) over `Acc` carry the clean run through binds and loops; a send of
the hold extends it by one clean step (`Acc.extend`), given that step as `Emits`.
-/

namespace Consensus.TraceValidation.Proofs.Tick

open CCF (Envelope Outputs Capabilities)
open CCF.Sections (LocalRun)
open Consensus.Model.Node
open Consensus.TraceValidation.Exec

theorem localRun_snoc {Node LocalState LocalAction Message Notification Input : Type}
    {protocol
      : CCF.MultiNodeTransitionSystem.Protocol Node LocalState LocalAction Message
          Notification Input}
    {node : Node} {start finish last : LocalState} {actions : List LocalAction}
    {sends : List (Envelope Node Message)} {action : LocalAction}
    {effects : Outputs Node Message Notification}
    (run : LocalRun protocol node start actions finish sends)
    (step
      : (protocol.step (Capabilities.record node) node finish action).run {}
        = some (last, effects))
    : LocalRun protocol node start (actions ++ [action]) last
        (sends ++ effects.outgoing) := by
  induction run with
  | nil state =>
      have := LocalRun.cons step (LocalRun.nil (protocol := protocol) (node := node) last)
      simpa using this
  | cons first _ ih =>
      have := LocalRun.cons first (ih step)
      simpa [List.append_assoc] using this

/-! ## Clean effects that succeed with known sends -/

/-- `x` succeeds from any outputs with result `a`, appending exactly `sends`. -/
def Emits {α : Type} (x : NodeEffect α) (a : α) (sends : List (Envelope NodeID Message))
    : Prop :=
  forall out : Outputs NodeID Message Notification,
    x.run out = some (a, { out with outgoing := out.outgoing ++ sends })

theorem emits_pure {α : Type} (a : α) : Emits (pure a : NodeEffect α) a [] := by
  intro out
  cases out
  simp [StateT.run, pure, StateT.pure]

theorem emits_bind {α β : Type} {x : NodeEffect α} {f : α -> NodeEffect β} {a : α} {b : β}
    {first later : List (Envelope NodeID Message)}
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

theorem emits_send {node : NodeID} (message : Message) (target : NodeID)
    : Emits ((Capabilities.record node).send message target) ()
        [⟨node, target, message⟩] := by
  intro out
  rfl

theorem emits_guard {p : Prop} [Decidable p] (h : p)
    : Emits (guard p : NodeEffect Unit) () [] := by
  intro out
  cases out
  simp [guard, h, StateT.run, pure, StateT.pure]

theorem emits_congr {α : Type} {x : NodeEffect α} {a b : α}
    {first later : List (Envelope NodeID Message)}
    (h : Emits x a first) (same : a = b) (sends : first = later)
    : Emits x b later := by
  subst same sends
  exact h

theorem emits_run {α : Type} {x : NodeEffect α} {a : α}
    {sends : List (Envelope NodeID Message)}
    (h : Emits x a sends)
    : x.run {} = some (a, { outgoing := sends }) := by
  have := h {}
  simpa using this

theorem emits_forIn {node : NodeID} (peers : List NodeID) (f : NodeID -> Message)
    : Emits
        (forIn peers PUnit.unit
            fun peer _ => do
              (Capabilities.record node).send (f peer) peer
              pure (ForInStep.yield PUnit.unit)
          : NodeEffect PUnit)
        PUnit.unit (peers.map fun peer => ⟨node, peer, f peer⟩) := by
  induction peers with
  | nil => exact emits_pure _
  | cons peer rest ih =>
      rw [List.forIn_cons]
      refine emits_congr (emits_bind
        (x := do (Capabilities.record node).send (f peer) peer; pure (ForInStep.yield PUnit.unit))
        (a := ForInStep.yield PUnit.unit)
        (emits_bind (f := fun _ => pure (ForInStep.yield PUnit.unit)) (emits_send _ _)
          (emits_pure _)) ih) rfl ?_
      simp

/-! ## The ghost clean run -/

/-- Admitted whatever the other nodes' states: any internal input but `initAsBackup`. -/
def Admitted (node : NodeID) (input : Input) : Prop :=
  forall others, admit others node input = true

/--
The outbox `o` is the sends of admitted clean internal steps of `node` from `clean0`,
which reach a clean state related to the declared state `v` by `R`; every send satisfies
`msgInv`.
-/
def Acc (env : Env) (node : NodeID) (clean0 : NodeState) (R : NodeState -> State -> Prop)
    (v : State) (o : Outbox)
    : Prop :=
  exists (inputs : List Input) (clean : NodeState),
    LocalRun (protocol env) node clean0 (inputs.map (protocol env).internal) clean o
    /\ (forall input, input ∈ inputs -> Admitted node input)
    /\ (forall e, e ∈ o -> msgInv env.names e = true)
    /\ R clean v

variable {env : Env} {node : NodeID} {clean0 : NodeState}

theorem Acc.start {R : NodeState -> State -> Prop} {v : State} (r : R clean0 v)
    : Acc env node clean0 R v [] :=
  ⟨[], clean0, LocalRun.nil _, by simp, by simp, r⟩

theorem Acc.mono {R R' : NodeState -> State -> Prop} {v v' : State} {o : Outbox}
    (acc : Acc env node clean0 R v o) (h : forall clean, R clean v -> R' clean v')
    : Acc env node clean0 R' v' o := by
  obtain ⟨inputs, clean, run, ad, inv, r⟩ := acc
  exact ⟨inputs, clean, run, ad, inv, h _ r⟩

/-- One clean internal step that emits `sends` extends the ghost run. -/
theorem Acc.extend {R R' : NodeState -> State -> Prop} {v v' : State} {o : Outbox}
    {sends : Outbox} (acc : Acc env node clean0 R v o)
    (h
      : forall clean,
          R clean v
          -> exists (input : Input) (clean' : NodeState),
              Emits (act (Capabilities.record node) node clean input) clean' sends
              /\ Admitted node input
              /\ R' clean' v')
    (sendsInv : forall e, e ∈ sends -> msgInv env.names e = true)
    : Acc env node clean0 R' v' (o ++ sends) := by
  obtain ⟨inputs, clean, run, ad, inv, r⟩ := acc
  obtain ⟨input, clean', emits, admitted, r'⟩ := h clean r
  have step : ((protocol env).step (Capabilities.record node) node clean
      ((protocol env).internal input)).run {} = some (clean', { outgoing := sends }) :=
    emits_run emits
  refine ⟨inputs ++ [input], clean', ?_, ?_, ?_, r'⟩
  · have := localRun_snoc (effects := { outgoing := sends }) run step
    simpa using this
  · intro i mem
    rcases List.mem_append.mp mem with mem | mem
    · exact ad i mem
    · simp only [List.mem_singleton] at mem
      exact mem ▸ admitted
  · intro e mem
    rcases List.mem_append.mp mem with mem | mem
    · exact inv e mem
    · exact sendsInv e mem

theorem admitted_sendEntries (destination : NodeID) (endIndex : Nat)
    : Admitted node (.sendEntries destination endIndex) :=
  fun _ => rfl

theorem admitted_timeout (kind : TimeoutKind) : Admitted node (.timeout kind) :=
  fun _ => rfl

end Consensus.TraceValidation.Proofs.Tick
