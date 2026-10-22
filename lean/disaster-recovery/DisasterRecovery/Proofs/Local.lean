module

public import DisasterRecovery.Properties.Utils
public import Mathlib.Tactic

import all Init.Control.State

@[expose] public section

namespace DisasterRecovery.Proofs.Local

open CCF
open Model.Local

@[simp]
lemma effect_pure {S A : Type} (a : A) (s : S)
    : (pure a : StateT S Option A) s = some (a, s) :=
  rfl

@[simp]
lemma effect_bind {S A B : Type} (a : StateT S Option A)
    (f : A -> StateT S Option B) (s : S)
    : (a >>= f) s = (a s).bind (fun (a, s) => f a s) :=
  rfl

@[simp]
lemma effect_map {S A B : Type} (f : A -> B) (a : StateT S Option A) (s : S)
    : (f <$> a) s = (a s).map (fun (a, s) => (f a, s)) := by
  change (a s).bind (fun (a, s) => some (f a, s)) = _
  cases a s <;> rfl

@[simp]
lemma effect_modify {S : Type} (f : S -> S) (s : S)
    : (modify f : StateT S Option Unit) s = some ((), f s) :=
  rfl

@[simp]
lemma effect_lift {S A : Type} (a : Option A) (s : S)
    : (liftM a : StateT S Option A) s = a.map (fun a => (a, s)) := by
  cases a <;> rfl

private lemma effect_orElse_internal {S A : Type} (a : StateT S Option A)
    (b : Unit -> StateT S Option A) (s : S)
    : (StateT.orElse a b) s = (a s <|> b () s) :=
  rfl

@[simp]
lemma effect_orElse {S A : Type} (a : StateT S Option A)
    (b : Unit -> StateT S Option A) (s : S)
    : (StateT.orElse a b) s = (a s <|> b () s) :=
  effect_orElse_internal a b s

private lemma effect_failure_internal {S A : Type} (s : S)
    : (failure : StateT S Option A) s = none :=
  rfl

@[simp]
lemma effect_failure {S A : Type} (s : S) : (failure : StateT S Option A) s = none :=
  effect_failure_internal s

@[simp]
lemma effect_failure_explicit {S A : Type} (s : S)
    : (StateT.failure : StateT S Option A) s = none :=
  effect_failure_internal s

@[simp]
lemma effect_alternative {S A : Type} (a b : StateT S Option A) (s : S)
    : (a <|> b) s = (a s <|> b s) :=
  effect_orElse_internal a (fun _ => b) s

@[simp]
lemma effect_bind_explicit {S A B : Type} (a : StateT S Option A)
    (f : A -> StateT S Option B) (s : S)
    : StateT.bind a f s = (a s).bind (fun (a, s) => f a s) :=
  rfl

@[simp]
lemma effect_pure_explicit {S A : Type} (a : A) (s : S)
    : (StateT.pure a : StateT S Option A) s = some (a, s) :=
  rfl

lemma validStep_run {config : Model.Config}
    {s
      : MultiNodeTransitionSystem.LocalStep Location NodeState Event Message Notification}
    (valid : (Model.protocol config).ValidStep s)
    : exists recovered,
        Model.recoveredTxID config s.node = some recovered
        /\ (step (Capabilities.record s.node) config.protocol recovered s.before
              s.action).run
              {}
            = some (s.after, s.effects) := by
  simpa [MultiNodeTransitionSystem.Protocol.ValidStep, Model.protocol, StateT.run,
    Option.bind_eq_some_iff, Option.map_eq_some_iff]
    using valid

lemma gossip_freezes_after_choice
    : forall (config : Model.Config),
      forall localStep : Properties.LocalStep,
      forall (source : Model.Local.Location) (txid : Model.Local.TxID),
        ((Model.protocol config).ValidStep localStep
          /\ localStep.action = .receiveGossip source txid .accepted
          /\ localStep.before.chosen.isSome = true)
        -> localStep.after = localStep.before
            /\ .rejected "gossip-frozen" ∈ localStep.effects.notifications := by
  rintro config s source txid ⟨valid, action, chosen⟩
  obtain ⟨recovered, _, run⟩ := validStep_run valid
  have selected : s.before.chosen ≠ none := by
    cases h : s.before.chosen <;> simp_all
  simp [step, action, selected, rejected, Capabilities.record,
    ] at run
  obtain ⟨states, effects⟩ := run
  exact ⟨states.symm, by rw [← effects]; simp⟩

lemma rejected_gossip_stutters
    : forall (config : Model.Config),
      forall localStep : Properties.LocalStep,
      forall (source : Model.Local.Location) (txid : Model.Local.TxID),
        ((Model.protocol config).ValidStep localStep
          /\ localStep.action = .receiveGossip source txid .rejected)
        -> localStep.after = localStep.before
            /\ .rejected "quote-or-certificate" ∈ localStep.effects.notifications := by
  rintro config s source txid ⟨valid, action⟩
  obtain ⟨recovered, _, run⟩ := validStep_run valid
  simp [step, action, rejected, Capabilities.record,
    ] at run
  obtain ⟨states, effects⟩ := run
  exact ⟨states.symm, by rw [← effects]; simp⟩

lemma quorum_advance_opens (config : Config) (state : NodeState) (source : Location)
    (timeout : Bool) (phase : state.phase = .voting)
    (quorum : state.votes.length >= voteQuorum config)
    : exists next effects,
        (advance (Capabilities.record source) config state timeout).run {}
          = some (next, effects)
        /\ next.phase = .opening
        /\ next.openKind = some .quorum
        /\ .opening .quorum ∈ effects.notifications := by
  have nonempty : state.votes ≠ [] := by
    intro empty
    simp [empty, voteQuorum] at quorum
  simp [advance, phase, quorum, nonempty]
  cases timeout <;>
    simp [Capabilities.record, advanceTimeoutLane, advanceTimeoutState,
      ]

lemma quorum_step_opens
    : forall (config : Model.Config),
      forall localStep : Properties.LocalStep,
        ((Model.protocol config).ValidStep localStep
          /\ (localStep.action = .timeout
              \/ exists source, localStep.action = .receiveVote source .accepted)
          /\ localStep.before.phase = .voting
          /\ localStep.before.votes.length >= Model.Local.voteQuorum config.protocol)
        -> localStep.after.phase = .opening
            /\ localStep.after.openKind = some .quorum
            /\ .opening .quorum ∈ localStep.effects.notifications := by
  rintro config s ⟨valid, action, phase, quorum⟩
  obtain ⟨recovered, _, run⟩ := validStep_run valid
  rcases action with action | ⟨source, action⟩
  · obtain ⟨advanced, effects, adv, opening, kind, notification⟩ :=
      quorum_advance_opens config.protocol s.before s.node true phase quorum
    simp [step, action, adv] at run
    obtain ⟨rfl, rfl⟩ := run
    exact ⟨opening, kind, notification⟩
  · have quorum' : (insertVote source s.before.votes).length >= voteQuorum config.protocol := by
      have length : s.before.votes.length <= (insertVote source s.before.votes).length := by
        simp [insertVote]
        split <;> simp
      omega
    obtain ⟨advanced, effects, adv, opening, kind, notification⟩ :=
      quorum_advance_opens config.protocol
        { s.before with votes := insertVote source s.before.votes } s.node false phase quorum'
    rw [action] at run
    change (StateT.orElse
      (advance (Capabilities.record s.node) config.protocol
        { s.before with votes := insertVote source s.before.votes } false)
      (fun _ => rejected (Capabilities.record s.node) s.before "vote-advance")).run {}
      = some (s.after, s.effects) at run
    simp only [StateT.run] at adv run
    rw [effect_orElse, adv] at run
    change some (advanced, effects) = some (s.after, s.effects) at run
    obtain ⟨rfl, rfl⟩ := Prod.mk.inj (Option.some.inj run)
    exact ⟨opening, kind, notification⟩

lemma aligned_opening_timeout_completes
    : forall (config : Model.Config),
      forall localStep : Properties.LocalStep,
        ((Model.protocol config).ValidStep localStep
          /\ localStep.action = .timeout
          /\ localStep.before.phase = .opening
          /\ localStep.before.timeoutState = .opening)
        -> localStep.after = { localStep.before with phase := .open }
            /\ .completed ∈ localStep.effects.notifications := by
  rintro config s ⟨valid, action, phase, timeout⟩
  obtain ⟨recovered, _, run⟩ := validStep_run valid
  simp [step, action, advance, phase, timeout, validTimeout, Capabilities.record,
    ] at run
  obtain ⟨states, effects⟩ := run
  constructor
  · have states' : s.after = { s.before with phase := .open, timeoutState := .opening } := states.symm
    simpa [timeout] using states'
  · change ({ outgoing := [], notifications := [.completed] } :
      Outputs Location Message Notification) = s.effects at effects
    rw [← effects]
    change Notification.completed ∈ [Notification.completed]
    simp

end DisasterRecovery.Proofs.Local
