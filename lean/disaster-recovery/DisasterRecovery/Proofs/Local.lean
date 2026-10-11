/-
Copyright (c) 2026 Microsoft Corporation. All rights reserved.
Licensed under the Apache 2.0 License.
Authors: Microsoft Corporation
-/
import DisasterRecovery.Properties
import Mathlib.Tactic

/-! Local recovery properties and independence from host recording state. -/

namespace DisasterRecovery.Proofs.Local

open Shared
open Model.Local

lemma advance_result_independent
    (first second : Capabilities Location Message Notification)
    (config : Config) (state : NodeState) (timeout : Bool)
    (firstPending secondPending : Outputs Location Message Notification)
    : (advance first config state timeout).map
        (fun execute => (execute.run firstPending).1)
      = (advance second config state timeout).map
          (fun execute => (execute.run secondPending).1) := by
  simp only [advance, ge_iff_le, Bool.or_eq_true, decide_eq_true_eq, Bool.and_eq_true,
    List.isEmpty_iff, Bool.not_eq_eq_eq_not, Bool.not_true, decide_eq_false_iff_not, not_le,
    bind_pure_comp]
  repeat first | split | rfl

lemma step_result_independent
    (first second : Capabilities Location Message Notification)
    (config : Config) (recovered : TxID) (state : NodeState) (event : Event)
    (firstPending secondPending : Outputs Location Message Notification)
    : (step first config recovered state event).map
        (fun execute => (execute.run firstPending).1)
      = (step second config recovered state event).map
          (fun execute => (execute.run secondPending).1) := by
  cases event <;> try cases_type Validation
  all_goals simp only [step, bne_iff_ne, ne_eq, rejected, bind_pure_comp, Option.pure_def, advance,
    ge_iff_le, Bool.or_eq_true, decide_eq_true_eq, Bool.and_eq_true, List.isEmpty_iff,
    Bool.not_eq_eq_eq_not, Bool.not_true, decide_eq_false_iff_not, not_le, ite_not, Option.map_some,
    StateT.run_map, Option.some.injEq, Option.getD_some, guard, beq_iff_eq,
    List.isEmpty_eq_false_iff, Option.failure_eq_none, List.forIn_yield_eq_foldlM, id_map',
    Option.bind_eq_bind, List.filter_eq_nil_iff, Decidable.not_not, not_forall]
  all_goals repeat first | split | rfl

lemma step_enabled_independent
    (first second : Capabilities Location Message Notification)
    (config : Config) (recovered : TxID) (state : NodeState) (event : Event)
    : (step first config recovered state event).isSome
      = (step second config recovered state event).isSome := by
  simpa using congrArg Option.isSome
    (step_result_independent first second config recovered state event {} {})

lemma validStep_run {config : Model.Config}
    {s
      : MultiNodeTransitionSystem.LocalStep Location NodeState Event Message Notification}
    (valid : (Model.protocol config).ValidStep s)
    : exists recovered execute,
        Model.recoveredTxID config s.node = some recovered
        /\ step (Capabilities.record s.node) config.protocol recovered s.before s.action
            = some execute
        /\ execute.run {} = (s.after, s.effects) := by
  obtain ⟨execute, enabled, run⟩ := valid
  simp only [Model.protocol, Option.bind_eq_bind, Option.bind_eq_some_iff] at enabled
  obtain ⟨recovered, found, enabled⟩ := enabled
  exact ⟨recovered, execute, found, enabled, run⟩

lemma gossip_freezes_after_choice : Properties.GossipFreezesAfterChoice := by
  rintro config s source txid ⟨valid, action, chosen⟩
  obtain ⟨recovered, execute, _, enabled, run⟩ := validStep_run valid
  have selected : s.before.chosen ≠ none := by
    cases h : s.before.chosen <;> simp_all
  simp only [step, action, bne_iff_ne, ne_eq, selected, not_false_eq_true, ↓reduceIte,
    Option.pure_def, Option.some.injEq] at enabled
  subst execute
  change (s.before, { outgoing := [], notifications := [.rejected "gossip-frozen"] }) =
    (s.after, s.effects) at run
  obtain ⟨states, effects⟩ := Prod.mk.inj run
  exact ⟨states.symm, by rw [← effects]; simp⟩

lemma rejected_gossip_stutters : Properties.RejectedGossipStutters := by
  rintro config s source txid ⟨valid, action⟩
  obtain ⟨recovered, execute, _, enabled, run⟩ := validStep_run valid
  simp only [step, action, Option.pure_def, Option.some.injEq] at enabled
  subst execute
  change (s.before, { outgoing := [], notifications := [.rejected "quote-or-certificate"] }) =
    (s.after, s.effects) at run
  obtain ⟨states, effects⟩ := Prod.mk.inj run
  exact ⟨states.symm, by rw [← effects]; simp⟩

lemma quorum_advance_opens (config : Config) (state : NodeState) (source : Location)
    (timeout : Bool) (phase : state.phase = .voting)
    (quorum : state.votes.length >= voteQuorum config)
    : exists execute,
        advance (Capabilities.record source) config state timeout = some execute
        /\ (execute.run {}).1.phase = .opening
        /\ (execute.run {}).1.openKind = some .quorum
        /\ .opening .quorum ∈ (execute.run {}).2.notifications := by
  have nonempty : state.votes ≠ [] := by
    intro empty
    simp [empty, voteQuorum] at quorum
  simp only [advance, phase, ge_iff_le, quorum, decide_true, Bool.true_or, ↓reduceIte,
    Bool.and_eq_true, List.isEmpty_iff, nonempty, and_false, Bool.not_true, Bool.and_false,
    Bool.false_eq_true, bind_pure_comp, Option.some.injEq, exists_eq_left', StateT.run_map]
  cases timeout <;>
    simp only [advanceTimeoutLane, Bool.false_eq_true, ↓reduceIte, Capabilities.record,
      StateT.run_modify, List.nil_append, map_pure, advanceTimeoutState]
  all_goals exact ⟨rfl, rfl, List.mem_cons_self⟩

lemma quorum_step_opens : Properties.QuorumAdvanceOpens := by
  rintro config s ⟨valid, action, phase, quorum⟩
  obtain ⟨recovered, execute, _, enabled, run⟩ := validStep_run valid
  rcases action with action | ⟨source, action⟩
  · obtain ⟨advanced, adv, opening, kind, notification⟩ :=
      quorum_advance_opens config.protocol s.before s.node true phase quorum
    simp [step, action, adv] at enabled
    subst execute
    simpa [run] using And.intro opening (And.intro kind notification)
  · have quorum' : (insertVote source s.before.votes).length >= voteQuorum config.protocol := by
      have length : s.before.votes.length <= (insertVote source s.before.votes).length := by
        simp [insertVote]
        split <;> simp
      omega
    obtain ⟨advanced, adv, opening, kind, notification⟩ :=
      quorum_advance_opens config.protocol
        { s.before with votes := insertVote source s.before.votes } s.node false phase quorum'
    simp [step, action, adv] at enabled
    subst execute
    simpa [run] using And.intro opening (And.intro kind notification)

lemma aligned_opening_timeout_completes : Properties.AlignedOpeningTimeoutCompletes := by
  rintro config s ⟨valid, action, phase, timeout⟩
  obtain ⟨recovered, execute, _, enabled, run⟩ := validStep_run valid
  simp only [step, action, advance, phase, validTimeout, timeout, decide_true, Bool.and_self,
    ↓reduceIte, bind_pure_comp, Option.some.injEq] at enabled
  subst execute
  have states := congrArg Prod.fst run
  have effects := congrArg Prod.snd run
  constructor
  · have states' : s.after = { s.before with phase := .open, timeoutState := .opening } :=
      states.symm
    simpa [timeout] using states'
  · change ({ outgoing := [], notifications := [.completed] } :
      Outputs Location Message Notification) = s.effects at effects
    rw [← effects]
    change Notification.completed ∈ [Notification.completed]
    simp

end DisasterRecovery.Proofs.Local
