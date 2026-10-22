module

public import DisasterRecovery.Properties

@[expose] public section

namespace DisasterRecovery.Tests.Witnesses

open Model.Local

example
    : exists (config : Model.Config) (trace : Properties.GlobalTrace) (step
                                                                        : Nat) (opener
                                                                                : Location),
        trace.Valid (Model.transitionSystem config)
        /\ Properties.Trace.NotificationAt config trace step opener (.opening .quorum)
        /\ opener = opener := by
  obtain ⟨config, trace, step, opener, valid, notified⟩ := Properties.quorum_opener_unique_witness
  exact ⟨config, trace, step, opener, valid, notified,
    Properties.quorum_opener_unique config trace step step opener opener ⟨valid, notified, notified⟩⟩

example
    : exists (config : Model.Config) (opener : Location) (txid : TxID),
        Model.recoveredTxID config opener = some txid
        /\ Properties.UpToDateWithQuorum config txid := by
  obtain ⟨config, trace, openedState, opener, openerState, valid, opened, present, kind, own⟩ :=
    Properties.quorum_open_preserves_commit_witness
  obtain ⟨txid, recovered, upToDate⟩ :=
    Properties.quorum_open_preserves_commit config trace openedState opener openerState
      ⟨valid, opened, present, kind, own⟩
  exact ⟨config, opener, txid, recovered, upToDate⟩

example
    : exists (config : Model.Config) (opener : Location) (txid : TxID),
        Model.recoveredTxID config opener = some txid
        /\ Properties.UpToDateWithQuorum config txid := by
  obtain ⟨config, trace, gossipedState, openedState, opener, openerState,
    valid, gossiped, full, opened, present, kind⟩ := Properties.full_gossip_preserves_commit_witness
  obtain ⟨txid, recovered, upToDate⟩ :=
    Properties.full_gossip_preserves_commit config trace gossipedState openedState opener openerState
      ⟨valid, gossiped, full, opened, present, by simp [kind]⟩
  exact ⟨config, opener, txid, recovered, upToDate⟩

example
    : exists localStep : Properties.LocalStep,
        localStep.after = localStep.before
        /\ .rejected "gossip-frozen" ∈ localStep.effects.notifications := by
  obtain ⟨config, localStep, source, txid, valid, action, chosen⟩ :=
    Properties.gossip_freezes_after_choice_witness
  exact ⟨localStep,
    Properties.gossip_freezes_after_choice config localStep source txid ⟨valid, action, chosen⟩⟩

example
    : exists localStep : Properties.LocalStep,
        localStep.after = localStep.before
        /\ .rejected "quote-or-certificate" ∈ localStep.effects.notifications := by
  obtain ⟨config, localStep, source, txid, valid, action⟩ := Properties.rejected_gossip_stutters_witness
  exact ⟨localStep,
    Properties.rejected_gossip_stutters config localStep source txid ⟨valid, action⟩⟩

example
    : exists localStep : Properties.LocalStep,
        localStep.after.phase = .opening
        /\ localStep.after.openKind = some .quorum
        /\ .opening .quorum ∈ localStep.effects.notifications := by
  obtain ⟨config, localStep, valid, action, phase, quorum⟩ := Properties.quorum_advance_opens_witness
  exact ⟨localStep, Properties.quorum_advance_opens config localStep ⟨valid, action, phase, quorum⟩⟩

example
    : exists localStep : Properties.LocalStep,
        localStep.after = { localStep.before with phase := .open }
        /\ .completed ∈ localStep.effects.notifications := by
  obtain ⟨config, localStep, valid, action, phase, timeoutState⟩ :=
    Properties.aligned_opening_timeout_completes_witness
  exact ⟨localStep,
    Properties.aligned_opening_timeout_completes config localStep ⟨valid, action, phase, timeoutState⟩⟩

end DisasterRecovery.Tests.Witnesses
