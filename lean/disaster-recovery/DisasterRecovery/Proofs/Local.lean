import DisasterRecovery.Properties
import Mathlib.Tactic

namespace DisasterRecovery.Proofs.Local

open Shared
open Model.Local

lemma advance_result_independent
    (first second : Capabilities Location Message Notification)
    (config : Config) (state : NodeState) (timeout : Bool)
    (firstPending secondPending : Outputs Location Message Notification) :
    (advance first config state timeout).map (fun execute => (execute.run firstPending).1) =
      (advance second config state timeout).map (fun execute => (execute.run secondPending).1) := by
  simp [advance]
  repeat first | split | rfl

lemma step_result_independent
    (first second : Capabilities Location Message Notification)
    (config : Config) (recovered : TxID) (state : NodeState) (event : Event)
    (firstPending secondPending : Outputs Location Message Notification) :
    (step first config recovered state event).map (fun execute => (execute.run firstPending).1) =
      (step second config recovered state event).map (fun execute => (execute.run secondPending).1) := by
  cases event <;> try cases_type Validation
  all_goals simp [step, advance, rejected, guard]
  all_goals repeat first | split | rfl

lemma step_enabled_independent
    (first second : Capabilities Location Message Notification)
    (config : Config) (recovered : TxID) (state : NodeState) (event : Event) :
    (step first config recovered state event).isSome =
      (step second config recovered state event).isSome := by
  simpa using congrArg Option.isSome
    (step_result_independent first second config recovered state event {} {})

lemma validStep_run {config : Model.Config}
    {s : MultiNodeTransitionSystem.LocalStep Location NodeState Event Message Notification}
    (valid : (Model.protocol config).ValidStep s) :
    exists recovered execute,
      Model.recoveredTxID config s.node = some recovered /\
      step (Capabilities.record s.node) config.protocol recovered s.before s.action = some execute /\
      execute.run {} = (s.after, s.effects) := by
  obtain ⟨execute, enabled, run⟩ := valid
  simp [Model.protocol, Option.bind_eq_some_iff] at enabled
  obtain ⟨recovered, found, enabled⟩ := enabled
  exact ⟨recovered, execute, found, enabled, run⟩

lemma gossip_freezes_after_choice : Properties.GossipFreezesAfterChoice := by
  intro config s source txid valid action chosen
  obtain ⟨recovered, execute, _, enabled, run⟩ := validStep_run valid
  have selected : s.before.chosen ≠ none := by
    cases h : s.before.chosen <;> simp_all
  simp [step, action, selected] at enabled
  subst execute
  change (s.before, { outgoing := [], notifications := [.rejected "gossip-frozen"] }) =
    (s.after, s.effects) at run
  obtain ⟨states, effects⟩ := Prod.mk.inj run
  exact ⟨states.symm, by rw [← effects]; simp⟩

lemma rejected_gossip_stutters : Properties.RejectedGossipStutters := by
  intro config s source txid valid action
  obtain ⟨recovered, execute, _, enabled, run⟩ := validStep_run valid
  simp [step, action] at enabled
  subst execute
  change (s.before, { outgoing := [], notifications := [.rejected "quote-or-certificate"] }) =
    (s.after, s.effects) at run
  obtain ⟨states, effects⟩ := Prod.mk.inj run
  exact ⟨states.symm, by rw [← effects]; simp⟩

lemma quorum_advance_opens (config : Config) (state : NodeState) (source : Location)
    (timeout : Bool) (phase : state.phase = .voting)
    (quorum : state.votes.length >= voteQuorum config) :
    exists execute,
      advance (Capabilities.record source) config state timeout = some execute /\
      (execute.run {}).1.phase = .opening /\
      (execute.run {}).1.openKind = some .quorum /\
      .opening .quorum ∈ (execute.run {}).2.notifications := by
  have nonempty : state.votes ≠ [] := by
    intro empty
    simp [empty, voteQuorum] at quorum
  simp [advance, phase, quorum, nonempty]
  cases timeout <;>
    simp [Capabilities.record, advanceTimeoutLane, advanceTimeoutState]
  all_goals exact ⟨rfl, rfl, List.mem_cons_self⟩

lemma quorum_step_opens : Properties.QuorumAdvanceOpens := by
  intro config s valid action phase quorum
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
  intro config s valid action phase timeout
  obtain ⟨recovered, execute, _, enabled, run⟩ := validStep_run valid
  simp [step, action, advance, phase, timeout, validTimeout] at enabled
  subst execute
  have states := congrArg Prod.fst run
  have effects := congrArg Prod.snd run
  constructor
  · have states' : s.after = { s.before with phase := .open, timeoutState := .opening } := states.symm
    simpa [timeout] using states'
  · change ({ outgoing := [], notifications := [.completed] } :
      Outputs Location Message Notification) = s.effects at effects
    rw [← effects]
    change Notification.completed ∈ [Notification.completed]
    simp

end DisasterRecovery.Proofs.Local
