module

public import DisasterRecovery.Properties.Utils
public import CCF.Witnessed

import DisasterRecovery.Proofs.Local
import DisasterRecovery.Proofs.Safety
import DisasterRecovery.Proofs.Witnesses
import DisasterRecovery.Proofs.GlobalWitnesses

@[expose] public section

/-!
The witnessed claims of `DisasterRecovery/Properties.lean`, each assembled from its safety
theorem, which holds for every configuration, and its witness for every valid configuration.
`Properties.lean` restates each claim and refers to its proof here.
-/

namespace DisasterRecovery.Proofs.Claims

open Properties
open Model.Local

/-- The claim `quorum_opener_unique` of `Properties.lean`. -/
theorem quorum_opener_unique
    : forall (config : Model.Config),
        config.Valid
        -> witnessed% forall (trace : GlobalTrace config) (firstStep secondStep : Nat)
                              (firstOpener secondOpener : Location),
                        {
                          pre :=
                            Trace.NotificationAt config trace firstStep firstOpener
                              (.opening .quorum)
                            /\ Trace.NotificationAt config trace secondStep secondOpener
                                (.opening .quorum)
                          post := firstOpener = secondOpener
                        } :=
  fun config valid =>
    ⟨
      Proofs.Model.quorum_opener_unique config,
      let ⟨trace, step, opener, notified⟩ :=
        Proofs.GlobalWitnesses.quorum_opener_unique_witness ⟨config, valid⟩
      ⟨trace, step, step, opener, opener, notified, notified⟩
    ⟩

/-- The claim `quorum_open_preserves_commit` of `Properties.lean`. -/
theorem quorum_open_preserves_commit
    : forall (config : Model.Config),
        config.Valid
        -> witnessed% forall (trace : GlobalTrace config) (openedState : Model.State)
                              (opener : Location) (openerState : NodeState),
                        {
                          pre :=
                            openedState ∈ trace
                            /\ (opener, openerState) ∈ openedState.nodes
                            /\ openerState.openKind = some .quorum
                            /\ (forall voter,
                                  voter ∈ openerState.votes
                                  -> ReceivedOwnGossip trace voter)
                          post :=
                            exists openerTxID,
                              Model.recoveredTxID config opener = some openerTxID
                              /\ UpToDateWithQuorum config openerTxID
                        } :=
  fun config valid =>
    ⟨
      Proofs.Gossip.quorum_open_preserves_commit config,
      Proofs.GlobalWitnesses.quorum_open_preserves_commit_witness ⟨config, valid⟩
    ⟩

/-- The claim `gossip_freezes_after_choice` of `Properties.lean`. -/
theorem gossip_freezes_after_choice
    : forall (config : Model.Config),
        config.Valid
        -> witnessed% forall (localStep : LocalStep) (source : Location) (txid : TxID),
                        {
                          pre :=
                            (Model.protocol config).ValidStep localStep
                            /\ localStep.action = .receiveGossip source txid .accepted
                            /\ localStep.before.chosen.isSome = true
                          post :=
                            localStep.after = localStep.before
                            /\ .rejected "gossip-frozen" ∈ localStep.effects.notifications
                        } :=
  fun config valid =>
    ⟨
      Proofs.Local.gossip_freezes_after_choice config,
      Proofs.Witnesses.gossip_freezes_after_choice_witness ⟨config, valid⟩
    ⟩

/-- The claim `rejected_gossip_stutters` of `Properties.lean`. -/
theorem rejected_gossip_stutters
    : forall (config : Model.Config),
        config.Valid
        -> witnessed% forall (localStep : LocalStep) (source : Location) (txid : TxID),
                        {
                          pre :=
                            (Model.protocol config).ValidStep localStep
                            /\ localStep.action = .receiveGossip source txid .rejected
                          post :=
                            localStep.after = localStep.before
                            /\ .rejected "quote-or-certificate"
                                ∈ localStep.effects.notifications
                        } :=
  fun config valid =>
    ⟨
      Proofs.Local.rejected_gossip_stutters config,
      Proofs.Witnesses.rejected_gossip_stutters_witness ⟨config, valid⟩
    ⟩

/-- The claim `quorum_advance_opens` of `Properties.lean`. -/
theorem quorum_advance_opens
    : forall (config : Model.Config),
        config.Valid
        -> witnessed% forall (localStep : LocalStep),
                        {
                          pre :=
                            (Model.protocol config).ValidStep localStep
                            /\ (localStep.action = .timeout
                                \/ exists source,
                                    localStep.action = .receiveVote source .accepted)
                            /\ localStep.before.phase = .voting
                            /\ localStep.before.votes.length >= voteQuorum config.protocol
                          post :=
                            localStep.after.phase = .opening
                            /\ localStep.after.openKind = some .quorum
                            /\ .opening .quorum ∈ localStep.effects.notifications
                        } :=
  fun config valid =>
    ⟨
      Proofs.Local.quorum_step_opens config,
      Proofs.Witnesses.quorum_advance_opens_witness ⟨config, valid⟩
    ⟩

/-- The claim `aligned_opening_timeout_completes` of `Properties.lean`. -/
theorem aligned_opening_timeout_completes
    : forall (config : Model.Config),
        config.Valid
        -> witnessed% forall (localStep : LocalStep),
                        {
                          pre :=
                            (Model.protocol config).ValidStep localStep
                            /\ localStep.action = .timeout
                            /\ localStep.before.phase = .opening
                            /\ localStep.before.timeoutState = .opening
                          post :=
                            localStep.after = { localStep.before with phase := .open }
                            /\ .completed ∈ localStep.effects.notifications
                        } :=
  fun config valid =>
    ⟨
      Proofs.Local.aligned_opening_timeout_completes config,
      Proofs.Witnesses.aligned_opening_timeout_completes_witness ⟨config, valid⟩
    ⟩

end DisasterRecovery.Proofs.Claims
