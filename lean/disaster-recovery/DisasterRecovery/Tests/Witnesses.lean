import DisasterRecovery.Proof

namespace DisasterRecovery.Tests.Witnesses

open Model.Local

example
    : exists (config : Model.Config) (trace : Properties.GlobalTrace) (step : Nat) (opener
                                                                                    : Location),
        trace.Valid (Model.transitionSystem config)
        /\ Properties.Trace.NotificationAt config trace step opener (.opening .quorum)
        /\ opener = opener := by
  obtain ⟨config, trace, step, opener, valid, notified⟩ := Proof.quorum_opener_unique_witness
  exact ⟨config, trace, step, opener, valid, notified,
    Proof.quorum_opener_unique config trace step step opener opener ⟨valid, notified, notified⟩⟩

example
    : exists (config : Model.Config) (opener : Location) (txid : TxID),
        Model.recoveredTxID config opener = some txid
        /\ Properties.UpToDateWithQuorum config txid := by
  obtain ⟨config, trace, openedState, opener, openerState, valid, opened, present, kind, own⟩ :=
    Proof.quorum_open_preserves_commit_witness
  obtain ⟨txid, recovered, upToDate⟩ :=
    Proof.quorum_open_preserves_commit config trace openedState opener openerState
      ⟨valid, opened, present, kind, own⟩
  exact ⟨config, opener, txid, recovered, upToDate⟩

example
    : exists (config : Model.Config) (opener : Location) (txid : TxID),
        Model.recoveredTxID config opener = some txid
        /\ Properties.UpToDateWithQuorum config txid := by
  obtain ⟨config, trace, gossipedState, openedState, opener, openerState,
    valid, gossiped, full, opened, present, kind⟩ := Proof.full_gossip_preserves_commit_witness
  obtain ⟨txid, recovered, upToDate⟩ :=
    Proof.full_gossip_preserves_commit config trace gossipedState openedState opener openerState
      ⟨valid, gossiped, full, opened, present, by simp [kind]⟩
  exact ⟨config, opener, txid, recovered, upToDate⟩

example
    : exists localStep : Properties.LocalStep,
        localStep.after = localStep.before
        /\ .rejected "gossip-frozen" ∈ localStep.effects.notifications := by
  obtain ⟨config, localStep, source, txid, valid, action, chosen⟩ :=
    Proof.gossip_freezes_after_choice_witness
  exact ⟨localStep,
    Proof.gossip_freezes_after_choice config localStep source txid ⟨valid, action, chosen⟩⟩

example
    : exists localStep : Properties.LocalStep,
        localStep.after = localStep.before
        /\ .rejected "quote-or-certificate" ∈ localStep.effects.notifications := by
  obtain ⟨config, localStep, source, txid, valid, action⟩ := Proof.rejected_gossip_stutters_witness
  exact ⟨localStep,
    Proof.rejected_gossip_stutters config localStep source txid ⟨valid, action⟩⟩

example
    : exists localStep : Properties.LocalStep,
        localStep.after.phase = .opening
        /\ localStep.after.openKind = some .quorum
        /\ .opening .quorum ∈ localStep.effects.notifications := by
  obtain ⟨config, localStep, valid, action, phase, quorum⟩ := Proof.quorum_advance_opens_witness
  exact ⟨localStep, Proof.quorum_advance_opens config localStep ⟨valid, action, phase, quorum⟩⟩

example
    : exists localStep : Properties.LocalStep,
        localStep.after = { localStep.before with phase := .open }
        /\ .completed ∈ localStep.effects.notifications := by
  obtain ⟨config, localStep, valid, action, phase, timeoutState⟩ :=
    Proof.aligned_opening_timeout_completes_witness
  exact ⟨localStep,
    Proof.aligned_opening_timeout_completes config localStep ⟨valid, action, phase, timeoutState⟩⟩

end DisasterRecovery.Tests.Witnesses
