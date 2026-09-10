import DisasterRecovery.Protocol.Model
import Mathlib.Tactic.Lemma

/-!
Machine-checked proof implementations. Review the system-level statements in
`DisasterRecovery.Properties` and definitions in `DisasterRecovery.Protocol.Model`.
-/

namespace DisasterRecovery.Proofs.Model

open Protocol.Model

lemma valid_timeout_requires_alignment
    (state : NodeState)
    (h : validTimeout state true = true) :
    state.phase = state.timeoutState := by
  simpa [validTimeout] using h

lemma gossip_freezes_after_choice
    (config : Config)
    (state : NodeState)
    (source : Location)
    (txid : TxID)
    (h : state.chosen.isSome = true) :
    let output := step config state (.receiveGossip source txid .accepted)
    output.state = state /\ output.accepted = false := by
  cases chosen : state.chosen <;> simp_all [step, rejected]

lemma rejected_gossip_stutters
    (config : Config)
    (state : NodeState)
    (source : Location)
    (txid : TxID) :
    let output := step config state (.receiveGossip source txid .rejected)
    output.state = state /\ output.accepted = false := by
  simp [step, rejected]

lemma duplicate_vote_is_idempotent
    (source : Location)
    (votes : List Location)
    (h : votes.contains source = true) :
    insertVote source votes = votes := by
  unfold insertVote
  rw [h]
  simp

lemma opening_rejects_iamopen
    (config : Config)
    (state : NodeState)
    (source : Location) :
    let opening := { state with phase := .opening }
    let output := step config opening (.receiveIAmOpen source .accepted)
    output.state = opening /\ output.accepted = false := by
  simp [step, rejected]

lemma open_rejects_iamopen
    (config : Config)
    (state : NodeState)
    (source : Location) :
    let opened := { state with phase := .open }
    let output := step config opened (.receiveIAmOpen source .accepted)
    output.state = opened /\ output.accepted = false := by
  simp [step, rejected]

lemma aligned_voting_timeout_without_votes_stutters
    (config : Config)
    (state : NodeState) :
    let waiting := {
      state with
      phase := .voting
      timeoutState := .voting
      votes := []
    }
    step config waiting .timeout = { state := waiting } := by
  simp [step, advance, validTimeout, voteQuorum]

lemma aligned_opening_timeout_completes
    (config : Config)
    (state : NodeState) :
    let opening := {
      state with
      phase := .opening
      timeoutState := .opening
    }
    let output := step config opening .timeout
    output.state.phase = .open /\
      output.state.timeoutState = .opening /\
      output.effects = [.completed] := by
  simp [step, advance, validTimeout, advanceTimeoutLane, advanceTimeoutState]

lemma quorum_advance_opens
    (config : Config)
    (state : NodeState)
    (phase : state.phase = .voting)
    (quorum : state.votes.length >= voteQuorum config) :
    let output := (advance config state false).get!
    output.state.phase = .opening /\
      output.state.openKind = some .quorum /\
      output.effects = [.opening .quorum] := by
  simp [advance, phase, quorum, validTimeout, advanceTimeoutLane]

lemma aligned_empty_gossip_timeout_aborts
    (config : Config)
    (state : NodeState) :
    let waiting := {
      state with
      phase := .gossiping
      timeoutState := .gossiping
      gossips := []
    }
    let output := step config waiting .timeout
    output.state = waiting /\ output.accepted = false := by
  simp [step, advance, validTimeout, rejected, maximumGossip]

end DisasterRecovery.Proofs.Model