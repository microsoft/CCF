module

public import CCFRaft.Proofs.Timed.Acks
public import CCFRaft.Proofs.CommitLiveness

@[expose] public section

set_option linter.unusedSectionVars false

/-!
# A covering signature in time

Within the signature interval of the window's start, the primary's log holds a
signature of its term past the submitted request.
-/

open CCF.Execution (Trace)

namespace CCFRaft.Proofs.Timed

open CCF CCF.MultiNodeTransitionSystem
open CCFRaft.Liveness
open Model.Node
open HasProtocol (proto)
open HasTime (time)
open CCFRaft.Proofs.Liveness (Admissible)
open CCFRaft.Proofs.Replication
open CCFRaft.Proofs.Safety
open CCFRaft.Proofs.StablePrimary
open CCFRaft.Proofs.CommitLiveness

/-- A request in a log stays in any prefix, of a longer log, that covers it. -/
theorem hasRequest_take {old new : List Entry} {request : ReqID} (prefix_ : old <+: new)
    {signature : Nat} (covers : old.length <= signature) (has : HasRequest old request)
    : HasRequest (new.take signature) request := by
  obtain ⟨entry, member, rest⟩ := has
  refine ⟨entry, ?_, rest⟩
  have eq : old = (new.take signature).take old.length := by
    rw [List.take_take, Nat.min_eq_left covers]
    exact List.prefix_iff_eq_take.mp prefix_
  rw [eq] at member
  exact List.mem_of_mem_take member

variable {W : Type} [HasProtocol W Model.State] [HasTime W] [HasLive W] [HasNetwork W]
  [Proofs.Config.InitialConfiguration] {nodes : List NodeID}
  {trace : Trace W Liveness.Event}
  (admissible : Admissible Proofs.Config.INITIAL_CONFIGURATION nodes trace)

include admissible

/-- The request is in the primary's log at a recorded index of the window, at the
window's start time. -/
theorem request_recorded {start last : Nat} {leader : NodeID} {first : W}
    (firstFound : trace.stateAt start = some first) (startLe : start <= last)
    {duration : Real} (nonneg : 0 <= duration)
    (beyond
      : forall index point,
          last < index
          -> trace.stateAt index = some point
          -> time first + duration < time point)
    {request : ReqID} (submitted : SubmittedAt trace start leader request)
    : exists index point state,
        start <= index
        /\ index <= last
        /\ trace.stateAt index = some point
        /\ time point = time first
        /\ nodeState (proto point) leader = some state
        /\ HasRequest state.log request := by
  rcases submitted with ⟨point, state, found, nodeFound, has⟩ | ⟨step, entries, stepped, action,
      member⟩
  · rw [firstFound, Option.some.injEq] at found
    subst found
    exact ⟨start, first, state, le_rfl, startLe, firstFound, rfl, nodeFound, has⟩
  · have before := Trace.stateAt_of_stepAt stepped
    rw [firstFound, Option.some.injEq] at before
    have busy : Not (step.action = .idle) := by rw [action]; simp
    have still : time step.after = time first := by
      rw [(admissible.timing.next stepped).2 busy, before]
    have afterFound := Trace.stateAt_succ_of_stepAt stepped
    have lt : start < last := by
      by_contra ge
      have := beyond (start + 1) step.after (by omega) afterFound
      linarith
    obtain ⟨state, next, _, _, ran, found'⟩ :=
      local_step_found (admissible.reachable_before stepped)
        (admissible.step stepped (by rw [action]; rfl))
    obtain ⟨log, _⟩ := append_log leader state entries _ _ _ ran
    refine ⟨start + 1, step.after, next, by omega, by omega, afterFound, still, found',
      { term := state.currentTerm, content := .transaction request {} }, ?_, {}, rfl⟩
    rw [log]
    exact List.mem_append_right _ (List.mem_map.mpr ⟨_, member, rfl⟩)

/-- A submitted request is covered by a signature of the term within the
signature interval, at a recorded index of the window. -/
theorem signed_within {signatureInterval : Real}
    (signing : SignatureScheduling trace (some signatureInterval)) {start last : Nat}
    {leader : NodeID} {term : Nat}
    (stable : StableLeader (cut trace last) start leader term) {first : W}
    (firstFound : trace.stateAt start = some first) {duration : Real}
    (nonneg : 0 <= duration) (fits : signatureInterval <= duration)
    (beyond
      : forall index point,
          last < index
          -> trace.stateAt index = some point
          -> time first + duration < time point)
    {request : ReqID} (submitted : SubmittedAt trace start leader request)
    : exists signed state signature,
        start <= signed
        /\ signed <= last
        /\ clock (cut trace last) signed <= time first + max signatureInterval 0
        /\ nodeAt (cut trace last) signed leader = some state
        /\ isSignatureAt state.log signature = true
        /\ termAt state.log signature = term
        /\ HasRequest (state.log.take signature) request := by
  have startLe : start <= last := by
    obtain ⟨_, found⟩ := stable.1
    exact (stateAt_of_cut found).1
  have cutAdmissible := Admissible.cut admissible last
  obtain ⟨index, point, state, afterStart, indexLe, found, sameTime, nodeFound, has⟩ :=
    request_recorded admissible firstFound startLe nonneg beyond submitted
  have cutFound : (cut trace last).stateAt index = some point := by
    rw [cut_stateAt_of_le indexLe]; exact found
  have cutNode : nodeAt (cut trace last) index leader = some state := by
    rw [nodeAt_of_stateAt cutFound, nodeFound]
  have nonempty : Not (state.log = []) := by
    obtain ⟨entry, member, _⟩ := has
    exact List.ne_nil_of_mem member
  have maxRight := le_max_right signatureInterval 0
  have maxLeft := le_max_left signatureInterval 0
  by_cases due : SignatureDue point leader
  · obtain ⟨later, laterPoint, le, laterFound, deadline, outcome⟩ :=
      signing leader index point found due
    have deadline : time laterPoint <= time point + signatureInterval := deadline
    have laterLe : later <= last := by
      by_contra gt
      have := beyond later laterPoint (by omega) laterFound
      linarith
    have cutLater : (cut trace last).stateAt later = some laterPoint := by
      rw [cut_stateAt_of_le laterLe]; exact laterFound
    rcases outcome with notDue | ⟨step, stepped, signs⟩
    · obtain ⟨_, after, nodeFound', _⟩ := stable.leads (Nat.le_trans afterStart le) cutLater
      have laterNode : nodeAt (cut trace last) later leader = some after := by
        rw [nodeAt_of_stateAt cutLater, nodeFound']
      have kept := stable_log_prefix cutAdmissible stable afterStart le cutNode laterNode
      obtain ⟨signature, signatureTerm⟩ :=
        signed_of_not_due stable (Nat.le_trans afterStart le) cutLater nodeFound' notDue
          (fun empty => nonempty (List.eq_nil_of_prefix_nil (empty ▸ kept)))
      refine ⟨later, after, after.log.length, by omega, laterLe, ?_, laterNode, signature,
        signatureTerm, hasRequest_take kept kept.length_le has⟩
      rw [clock_eq cutLater]
      linarith
    · have before := Trace.stateAt_of_stepAt stepped
      rw [laterFound, Option.some.injEq] at before
      have busy : Not (step.action = .idle) := by
        obtain ⟨entries, action, _⟩ := signs
        rw [action]; simp
      have still : time step.after = time laterPoint := by
        rw [(admissible.timing.next stepped).2 busy, before]
      have afterFound := Trace.stateAt_succ_of_stepAt stepped
      have lt : later < last := by
        by_contra ge
        have := beyond (later + 1) step.after (by omega) afterFound
        linarith
      have cutStepped : (cut trace last).stepAt later = some step := by
        rw [cut_stepAt_of_lt lt]; exact stepped
      obtain ⟨previous, after, signature, previousFound, afterNode, past, isSignature,
          signatureTerm⟩ :=
        signs_step cutAdmissible cutStepped signs
      have grown :=
        (stable_log_prefix cutAdmissible stable afterStart le cutNode previousFound).length_le
      have kept :=
        stable_log_prefix cutAdmissible stable afterStart (by omega) cutNode afterNode
      refine ⟨later + 1, after, signature, by omega, by omega, ?_, afterNode, isSignature,
        signatureTerm.trans (stable.current (Nat.le_trans afterStart le) previousFound),
        hasRequest_take kept (by omega) has⟩
      rw [clock_eq (Trace.stateAt_succ_of_stepAt cutStepped)]
      linarith
  · obtain ⟨signature, signatureTerm⟩ :=
      signed_of_not_due stable afterStart cutFound nodeFound due nonempty
    refine ⟨index, state, state.log.length, afterStart, indexLe, ?_, cutNode, signature,
      signatureTerm, by rw [List.take_length]; exact has⟩
    rw [clock_eq cutFound]
    linarith

end CCFRaft.Proofs.Timed
