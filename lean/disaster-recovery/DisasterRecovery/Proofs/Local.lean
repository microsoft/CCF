import DisasterRecovery.Model.Local
import Mathlib.Tactic.Lemma

namespace DisasterRecovery.Proofs.Local

open DisasterRecovery.Model.Local

lemma step_enabled_independent
    (first : Shared.Capabilities Location Message)
    (second : Shared.Capabilities Location Message)
    (config : Config) (recovered : TxID) (state : NodeState) (event : Event) :
    (step first config recovered state event).isSome =
      (step second config recovered state event).isSome := by
  cases event <;> try (simp [step]; done)
  cases phase : state.phase <;> simp [step, phase, guard]
  all_goals split <;> rfl

lemma step_result_independent (host : Shared.Capabilities Location Message)
    (config : Config) (recovered : TxID) (state : NodeState) (event : Event)
    (execute : Shared.Effect Location Message NodeState) (pending : List (Location × Message))
    (enabled : step host config recovered state event = some execute) :
    exists output, transition config state event = some output /\
      (execute.run pending).1 = output.state := by
  cases event with
  | retry =>
      refine ⟨{ state }, rfl, ?_⟩
      simp [step, guard] at enabled
      repeat first | split at enabled | contradiction | (cases enabled; rfl)
  | receiveGossip source txid validation
  | receiveVote source validation
  | receiveIAmOpen source validation
  | timeout =>
      simp [step, Option.bind_eq_some_iff] at enabled
      obtain ⟨output, trans, rfl⟩ := enabled
      exact ⟨output, trans, rfl⟩

lemma gossip_freezes_after_choice
    (config : Config) (state : NodeState) (source : Location) (txid : TxID)
    (chosen : state.chosen.isSome = true) :
    transition config state (.receiveGossip source txid .accepted) =
      some (rejected state "gossip-frozen") := by
  cases value : state.chosen <;> simp_all [transition]

lemma rejected_gossip_stutters
    (config : Config) (state : NodeState) (source : Location) (txid : TxID) :
    transition config state (.receiveGossip source txid .rejected) =
      some (rejected state "quote-or-certificate") := by
  rfl

lemma quorum_advance_opens
    (config : Config) (state : NodeState)
    (phase : state.phase = .voting)
    (quorum : state.votes.length >= voteQuorum config) :
    let output := (advance config state false).get!
    output.state.phase = .opening /\
      output.state.openKind = some .quorum /\
      output.effects = [.opening .quorum] := by
  simp [advance, phase, quorum, validTimeout, advanceTimeoutLane]

lemma aligned_opening_timeout_completes (config : Config) (state : NodeState) :
    let opening := { state with phase := .opening, timeoutState := .opening }
    transition config opening .timeout =
      some {
        state := { opening with phase := .open }
        effects := [.completed]
      } := by
  simp [transition, advance, validTimeout, advanceTimeoutLane, advanceTimeoutState]

end DisasterRecovery.Proofs.Local
