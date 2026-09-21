import DisasterRecovery.Model.Local
import Mathlib.Tactic.Lemma

namespace DisasterRecovery.Proofs.Local

open DisasterRecovery.Model.Local

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
