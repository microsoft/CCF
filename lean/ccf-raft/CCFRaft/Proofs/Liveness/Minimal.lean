module

public import CCFRaft.Proofs.Liveness.MinimalFacts
public import CCFRaft.Proofs.Timed.Commit

@[expose] public section

/-!
# Commit liveness from a caught-up primary

`commit_of_stable` composes the timed commit theorem, with no backlog, with a
stable window from `start`; `commit_minimal` in `MinimalCommit` supplies the
window for `Properties.commit_liveness`. The primary is already primary and every
listed node has its term and log, so the timed theorem's start conditions hold
directly.
-/

open CCF.Execution (Trace)

namespace CCFRaft.Proofs.Liveness

open CCFRaft.Liveness
open Model.Node
open CCF.MultiNodeTransitionSystem (nodeState)
open HasProtocol (proto)

variable {W : Type} [HasProtocol W Model.State] [HasTime W] [HasLive W] [HasNetwork W]

/-- A stable window with settled reconfiguration, of length `commitDuration` with
no backlog, commits a request the primary holds at `start` to a caught-up
`participants` within it. -/
theorem commit_of_stable
    {config : Finset NodeID} {nodes : List NodeID} {bounds : Bounds} {maxDelay : Real}
    {trace : Trace W Liveness.Event} {start : Nat} {leader : NodeID} {term : Nat}
    {participants : Finset NodeID} {request : ReqID}
    (protocol : Satisfies trace (protocolModel config nodes))
    (timing : Satisfies trace timingModel)
    (crash : Satisfies trace crashModel)
    (delivery : Satisfies trace (deliveryModel config nodes))
    (bounded : Satisfies trace (boundedDelayModel maxDelay))
    (diverges : TimeDiverges trace)
    (heartbeat : HeartbeatScheduling trace (some bounds.heartbeatInterval))
    (signature : SignatureScheduling trace (some bounds.signatureInterval))
    (inTerm : InTermAt trace start term participants)
    (submitted : SubmittedAt trace start leader request)
    (backlog : BacklogTerms trace start leader participants 0)
    (stable
      : StableWindow trace start (Timed.commitDuration bounds maxDelay 0) leader term
          participants)
    (settled
      : Window.ReconfigurationSettled trace start (Timed.commitDuration bounds maxDelay 0)
          leader)
    : exists index,
        Within trace start (Timed.commitDuration bounds maxDelay 0) index
        /\ RequestCommitted trace leader request index :=
  Timed.commit_within_duration config nodes bounds maxDelay 0 W trace start leader term
    participants request
    ⟨
      protocol,
      timing,
      crash,
      delivery,
      bounded,
      diverges,
      bounded.init.1,
      heartbeat,
      signature,
      stable,
      settled,
      backlog,
      inTerm,
      submitted
    ⟩

end CCFRaft.Proofs.Liveness
