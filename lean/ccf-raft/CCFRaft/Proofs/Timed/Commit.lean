module

public import CCFRaft.Proofs.Timed.Sign
public import CCFRaft.Proofs.Timed.Quorum
public import CCFRaft.Proofs.Timed.Window

@[expose] public section

set_option linter.unusedSectionVars false

/-!
# Timed commit liveness

The window ends at a last recorded index; cut there, the primary is stable. A
signature covering the request appears within the signature interval, and two
acknowledgement bounds later a live quorum of participants has committed it.
-/

open CCF.Execution (Trace)

namespace CCFRaft.Proofs.Timed

open CCF CCF.MultiNodeTransitionSystem
open CCFRaft.Liveness
open Model.Node
open HasProtocol (proto)
open HasTime (time)
open HasLive (live)
open CCFRaft.Proofs.Liveness (Admissible)
open CCFRaft.Proofs.StablePrimary

/-- The window length: a signature interval, then two acknowledgement bounds. -/
noncomputable def commitDuration (bounds : Bounds) (maxDelay : Real) (backlog : Nat)
    : Real :=
  max bounds.signatureInterval 0
  + 2 * max (ackBound maxDelay (max bounds.heartbeatInterval 0) backlog) 0

theorem commitDuration_nonneg (bounds : Bounds) (maxDelay : Real) (backlog : Nat)
    : 0 <= commitDuration bounds maxDelay backlog := by
  unfold commitDuration
  have := le_max_right bounds.signatureInterval 0
  have := le_max_right (ackBound maxDelay (max bounds.heartbeatInterval 0) backlog) 0
  linarith

/-- The request's covering signature, committed, carries the request into the
committed prefix of every later log of the primary. -/
theorem committed_of_prefix {state after : NodeState} {signature : Nat} {request : ReqID}
    (prefix_ : state.log <+: after.log) (le : signature <= after.commitIndex)
    (has : HasRequest (state.log.take signature) request)
    : HasRequest after.committedLog request := by
  obtain ⟨entry, member, rest⟩ := has
  refine ⟨entry, ?_, rest⟩
  have small : (state.log.take signature) <+: after.committedLog := by
    unfold NodeState.committedLog
    have p1 : state.log.take signature <+: after.log.take signature :=
      (List.prefix_take_iff.mpr ⟨(List.take_prefix _ _).trans prefix_, by simp⟩)
    exact p1.trans (List.take_prefix_take_left le)
  exact small.subset member

/-- A request submitted to the primary of a stable window of length
`commitDuration`, with settled reconfiguration and participant logs at most
`backlog` terms behind (`BacklogTerms`), is committed within the window. -/
theorem commit_within_duration
    : forall (config : Finset NodeID) (nodes : List NodeID),
      forall (bounds : Liveness.Bounds) (maxDelay : Real) (backlog : Nat),
      forall (W : Type) [Liveness.HasProtocol W Model.State] [Liveness.HasTime W]
              [Liveness.HasLive W] [Liveness.HasNetwork W],
      forall (trace : CCF.Execution.Trace W Liveness.Event) (start : Nat),
      forall (leader : NodeID) (term : Nat) (participants : Finset NodeID)
              (request : ReqID),
        (Satisfies trace (Liveness.protocolModel config nodes)
          /\ Satisfies trace Liveness.timingModel
          /\ Satisfies trace Liveness.crashModel
          /\ Satisfies trace (Liveness.deliveryModel config nodes)
          /\ Satisfies trace (Liveness.boundedDelayModel maxDelay)
          /\ Liveness.TimeDiverges trace
          /\ 0 <= maxDelay
          /\ HeartbeatScheduling trace (some bounds.heartbeatInterval)
          /\ SignatureScheduling trace (some bounds.signatureInterval)
          /\ Liveness.StableWindow trace start (commitDuration bounds maxDelay backlog)
              leader term participants
          /\ Liveness.Window.ReconfigurationSettled trace start
              (commitDuration bounds maxDelay backlog) leader
          /\ Liveness.BacklogTerms trace start leader participants backlog
          /\ Liveness.InTermAt trace start term participants
          /\ Liveness.SubmittedAt trace start leader request)
        -> exists index,
            Liveness.Within trace start (commitDuration bounds maxDelay backlog) index
            /\ Liveness.RequestCommitted trace leader request index := by
  intro config nodes bounds maxDelay backlog W _ _ _ _ trace start leader term participants
    request
    ⟨protocol, timing, crash, delivery, bounded, diverges, delayNonneg, heartbeats,
      signing, window, settled, backlogs, inTerm, submitted⟩
  let _ : Proofs.Config.InitialConfiguration := ⟨config⟩
  have admissible
      : Admissible Proofs.Config.INITIAL_CONFIGURATION nodes trace :=
    ⟨protocol, timing, crash, delivery⟩
  have nonneg := commitDuration_nonneg bounds maxDelay backlog
  set duration := commitDuration bounds maxDelay backlog with durationEq
  have intervalNonneg : 0 <= max bounds.heartbeatInterval 0 := le_max_right _ _
  obtain ⟨first, firstFound⟩ : exists first, trace.stateAt start = some first := by
    rcases submitted with ⟨point, _, found, _⟩ | ⟨step, _, stepped, _⟩
    · exact ⟨point, found⟩
    · exact ⟨step.before, Trace.stateAt_of_stepAt stepped⟩
  obtain ⟨last, lastPoint, afterStart, lastFound, inside, beyond⟩ :=
    window_end timing diverges nonneg firstFound
  have stable :=
    stable_cut admissible window.stableLeader window.staysActive afterStart inside firstFound
  have fits : bounds.signatureInterval <= duration := by
    rw [durationEq]
    unfold commitDuration
    have := le_max_left bounds.signatureInterval 0
    have := le_max_right (ackBound maxDelay (max bounds.heartbeatInterval 0) backlog) 0
    linarith
  obtain ⟨signed, state, signature, startLe, signedLe, signedClock, signedFound, isSignature,
      signatureTerm, has⟩ :=
    signed_within admissible signing stable firstFound nonneg fits beyond submitted
  have cutAdmissible := Admissible.cut admissible last
  have within : forall index, nodeAt (cut trace last) index leader ≠ none
      -> start <= index -> Within trace start duration index := by
    intro index found le
    obtain ⟨state, found⟩ := Option.ne_none_iff_exists'.mp found
    exact inside index le (cut_nodeAt found).1
  obtain ⟨later, after, signedLater, laterLe, laterFound, committed⟩ :=
    quorum_commits cutAdmissible stable
      (fun index state le found => by
        obtain ⟨_, found'⟩ := cut_nodeAt found
        obtain ⟨point, pointFound, nodeFound⟩ := nodeAt_eq_some.mp found'
        exact settled index point state (within index (by simp [found]) le) pointFound
          nodeFound)
      (quorum := Inter.inter (live lastPoint) participants)
      (fun state found => by
        obtain ⟨_, found'⟩ := cut_nodeAt found
        obtain ⟨point, pointFound, nodeFound⟩ := nodeAt_eq_some.mp found'
        rw [lastFound, Option.some.injEq] at pointFound
        subst pointFound
        exact window.liveQuorum last _ state (inside last afterStart le_rfl) lastFound
          nodeFound)
      (fun peer member _ eligible =>
        env_of_window admissible bounded diverges heartbeats nonneg window firstFound afterStart
          lastFound inside beyond (Finset.mem_inter.mp member).2 (Finset.mem_inter.mp member).1
          (fun index state le le' found =>
            eligible index state le (by rw [cut_nodeAt_of_le le']; exact found)))
      (fun peer member _ index point le le' found =>
        participant_term admissible window.stableLeader inTerm (Finset.mem_inter.mp member).2
          (inside index le le') (stateAt_of_cut found).2)
      (backlog := backlog)
      (fun peer member _ other primary otherFound primaryFound => by
        rw [cut_nodeAt_of_le afterStart] at otherFound primaryFound
        obtain ⟨point, pointFound, primaryNode⟩ := nodeAt_eq_some.mp primaryFound
        obtain ⟨point', pointFound', otherNode⟩ := nodeAt_eq_some.mp otherFound
        rw [pointFound, Option.some.injEq] at pointFound'
        subst pointFound'
        have := backlogs point primary peer other pointFound primaryNode
          (Finset.mem_inter.mp member).2 otherNode
        rwa [agreedPrefix_eq] at this)
      delayNonneg intervalNonneg
      ⟨lastPoint, by rw [cut_stateAt_of_le le_rfl]; exact lastFound⟩ startLe signedLe signedFound isSignature signatureTerm
      (by
        rw [durationEq]
        unfold commitDuration
        have := le_max_left (ackBound maxDelay (max bounds.heartbeatInterval 0) backlog) 0
        linarith)
  have kept :=
    CommitLiveness.stable_log_prefix cutAdmissible stable startLe signedLater signedFound
      laterFound
  obtain ⟨_, laterFound'⟩ := cut_nodeAt laterFound
  obtain ⟨point, pointFound, nodeFound⟩ := nodeAt_eq_some.mp laterFound'
  exact ⟨later, inside later (Nat.le_trans startLe signedLater) laterLe,
    point, after, pointFound, nodeFound, committed_of_prefix kept committed has⟩

end CCFRaft.Proofs.Timed
