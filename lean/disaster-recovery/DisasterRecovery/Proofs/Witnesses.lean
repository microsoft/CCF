module

public import DisasterRecovery.Properties.Utils

import all Init.Control.State

@[expose] public section

namespace DisasterRecovery.Proofs.Witnesses

open CCF
open Model.Local

private lemma exists_recovered (config : Properties.ValidConfig)
    : exists node txid, Model.recoveredTxID config node = some txid := by
  cases recovered : config.val.recovered with
  | nil =>
      have valid := config.property.1
      simp [Config.isValid, ← config.property.2.2, recovered] at valid
  | cons entry rest =>
      obtain ⟨node, txid⟩ := entry
      exact ⟨node, txid, by simp [Model.recoveredTxID, recovered]⟩

lemma gossip_freezes_after_choice_witness
    : forall (config : Properties.ValidConfig),
        exists localStep : Properties.LocalStep,
        exists (source : Location) (txid : TxID),
          (Model.protocol config).ValidStep localStep
          /\ localStep.action = .receiveGossip source txid .accepted
          /\ localStep.before.chosen.isSome = true := by
  intro config
  obtain ⟨node, txid, recovered⟩ := exists_recovered config
  let before := { initialNode node with chosen := some node }
  refine ⟨{
    node, before
    action := .receiveGossip node txid .accepted
    after := before
    effects := { notifications := [.rejected "gossip-frozen"] }
  }, node, txid, ?_, rfl, rfl⟩
  simp [MultiNodeTransitionSystem.Protocol.ValidStep, Model.protocol, recovered,
    step, before, rejected, Capabilities.record]

lemma rejected_gossip_stutters_witness
    : forall (config : Properties.ValidConfig),
        exists localStep : Properties.LocalStep,
        exists (source : Location) (txid : TxID),
          (Model.protocol config).ValidStep localStep
          /\ localStep.action = .receiveGossip source txid .rejected := by
  intro config
  obtain ⟨node, txid, recovered⟩ := exists_recovered config
  refine ⟨{
    node
    before := initialNode node
    action := .receiveGossip node txid .rejected
    after := initialNode node
    effects := { notifications := [.rejected "quote-or-certificate"] }
  }, node, txid, ?_, rfl⟩
  simp [MultiNodeTransitionSystem.Protocol.ValidStep, Model.protocol, recovered,
    step, rejected, Capabilities.record]

lemma quorum_advance_opens_witness
    : forall (config : Properties.ValidConfig),
        exists localStep : Properties.LocalStep,
          (Model.protocol config).ValidStep localStep
          /\ (localStep.action = .timeout
              \/ exists source, localStep.action = .receiveVote source .accepted)
          /\ localStep.before.phase = .voting
          /\ localStep.before.votes.length >= voteQuorum config.val.protocol := by
  intro config
  obtain ⟨node, txid, recovered⟩ := exists_recovered config
  let before : NodeState := {
    location := node
    phase := .voting
    votes := List.replicate (voteQuorum config.val.protocol) node
  }
  refine ⟨
    {
      node,
      before
      action := .timeout
      after :=
        {
          before with
            phase := .opening
            openKind := some .quorum
            timeoutState := .voting
        }
      effects := { notifications := [.opening .quorum] }
    },
    ?_,
    Or.inl rfl,
    rfl,
    by simp [before]
  ⟩
  simp [MultiNodeTransitionSystem.Protocol.ValidStep, Model.protocol, recovered,
    step, advance, before, validTimeout, advanceTimeoutLane, advanceTimeoutState,
    Capabilities.record]

lemma aligned_opening_timeout_completes_witness
    : forall (config : Properties.ValidConfig),
        exists localStep : Properties.LocalStep,
          (Model.protocol config).ValidStep localStep
          /\ localStep.action = .timeout
          /\ localStep.before.phase = .opening
          /\ localStep.before.timeoutState = .opening := by
  intro config
  obtain ⟨node, txid, recovered⟩ := exists_recovered config
  let before : NodeState := {
    location := node, phase := .opening, timeoutState := .opening
  }
  refine ⟨{
    node, before
    action := .timeout
    after := { before with phase := .open }
    effects := { notifications := [.completed] }
  }, ?_, rfl, rfl, rfl⟩
  simp [MultiNodeTransitionSystem.Protocol.ValidStep, Model.protocol, recovered,
    step, advance, before, validTimeout, advanceTimeoutLane, advanceTimeoutState,
    Capabilities.record]

end DisasterRecovery.Proofs.Witnesses
