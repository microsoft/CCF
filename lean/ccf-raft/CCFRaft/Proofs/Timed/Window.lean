module

public import CCFRaft.Proofs.Timed.Cut
public import CCFRaft.Proofs.Leadership.Settles

@[expose] public section

set_option linter.unusedSectionVars false

/-!
# The window as a cut recording

A diverging clock ends every window at a last recorded index. Cut there, the
recording has the window's primary stable at every state from `start`, so the
untimed replication lemmas apply to it. Window premises are used only for the
primary and the participants.
-/

open CCF.Execution (Trace)

namespace CCFRaft.Proofs.Timed

open CCF CCF.MultiNodeTransitionSystem
open CCFRaft.Liveness
open Model.Node
open HasProtocol (proto)
open HasTime (time)
open HasLive (live)
open HasNetwork (pending)
open CCFRaft.Proofs.Liveness (Admissible)
open CCFRaft.Proofs.Leadership (quietAmong_leader)

variable {W : Type} [HasProtocol W Model.State] [HasTime W] [HasLive W] [HasNetwork W]

/-- A window that starts at a recorded state ends at a last recorded index inside
it; every later recorded state is past it. -/
theorem window_end {trace : Trace W Liveness.Event}
    (timing : Satisfies trace timingModel) (diverges : TimeDiverges trace) {start : Nat}
    {duration : Real} (nonneg : 0 <= duration) {first : W}
    (firstFound : trace.stateAt start = some first)
    : exists last point,
        start <= last
        /\ trace.stateAt last = some point
        /\ (forall index,
              start <= index -> index <= last -> Within trace start duration index)
        /\ forall index point,
            last < index
            -> trace.stateAt index = some point
            -> time first + duration < time point := by
  classical
  let Past (index : Nat) : Prop :=
    start <= index
    /\ exists point, trace.stateAt index = some point /\ time first + duration < time point
  have exists_past : exists index, Past index := by
    obtain ⟨far, farPoint, farFound, late⟩ := diverges (time first + duration + 1)
    refine ⟨far, ?_, farPoint, farFound, by linarith⟩
    by_contra before
    have := Proofs.Liveness.time_mono timing (Nat.le_of_not_le before) farFound
      firstFound
    linarith
  let past := Nat.find exists_past
  have pastSpec : Past past := Nat.find_spec exists_past
  have minimal : forall index, index < past -> Not (Past index) :=
    fun _ lt => Nat.find_min exists_past lt
  obtain ⟨afterStart, pastPoint, pastFound, pastLate⟩ := pastSpec
  have startLt : start < past := by
    rcases Nat.eq_or_lt_of_le afterStart with same | lt
    · rw [← same, firstFound, Option.some.injEq] at pastFound
      subst pastFound
      linarith
    · exact lt
  obtain ⟨point, found⟩ := Trace.stateAt_ge_stable (Nat.sub_le past 1) pastFound
  refine ⟨
    past - 1,
    point,
    by omega,
    found,
    fun index after le => ?_,
    fun index later lt found => ?_
  ⟩
  · refine ⟨after, fun first' point' firstFound' found' => ?_⟩
    rw [firstFound, Option.some.injEq] at firstFound'
    subst firstFound'
    by_contra late
    exact minimal index (by omega) ⟨after, point', found', lt_of_not_ge late⟩
  · have := Proofs.Liveness.time_mono timing (show past <= index by omega) pastFound
      found
    linarith

variable [Proofs.Config.InitialConfiguration] {nodes : List NodeID}
  {trace : Trace W Liveness.Event}
  (admissible : Admissible Proofs.Config.INITIAL_CONFIGURATION nodes trace)

include admissible

/-- Cut at a recorded index inside the window, the window's primary is stable from
`start` in the untimed sense. -/
theorem stable_cut {start last : Nat} {duration : Real} {leader : NodeID} {term : Nat}
    {participants : Finset NodeID}
    (stable : Window.StableLeader trace start duration leader term participants)
    (active : Window.StaysActive trace start duration leader) (afterStart : start <= last)
    (inside
      : forall index,
          start <= index -> index <= last -> Within trace start duration index)
    {first : W} (firstFound : trace.stateAt start = some first)
    : StableLeader (cut trace last) start leader term := by
  refine ⟨
    ⟨first, by rw [cut_stateAt_of_le afterStart]; exact firstFound⟩,
    fun index point le found => ?_
  ⟩
  obtain ⟨below, found⟩ := stateAt_of_cut found
  have within := inside index le below
  obtain ⟨state, nodeFound, primary, termEq⟩ :=
    quietAmong_leader admissible found (stable index point within found).1
  exact ⟨
    point,
    state,
    by rw [cut_stateAt_of_le below]; exact found,
    active.live index point within found,
    nodeFound,
    primary,
    termEq,
    active.notRetired index point state within found nodeFound
  ⟩

/-- A participant in the term at `start` stays in it, and present, throughout the
window. -/
theorem participant_term {start : Nat} {duration : Real} {leader : NodeID} {term : Nat}
    {participants : Finset NodeID}
    (stable : Window.StableLeader trace start duration leader term participants)
    (inTerm : InTermAt trace start term participants) {node : NodeID}
    (member : node ∈ participants) {index : Nat} {point : W}
    (within : Within trace start duration index)
    (found : trace.stateAt index = some point)
    : exists state,
        nodeState (proto point) node = some state /\ state.currentTerm = term := by
  obtain ⟨first, initial, firstFound, initialFound, initialTerm⟩ := inTerm node member
  obtain ⟨state, stateFound, grows⟩ :=
    Proofs.StablePrimary.term_mono admissible within.1
      (by rw [nodeAt_of_stateAt firstFound, initialFound]) found
  rw [nodeAt_of_stateAt found] at stateFound
  have upper := (stable index point within found).1.terms node state
    (Proofs.Concrete.mem_of_nodeState stateFound) member
  exact ⟨state, stateFound, by omega⟩

end CCFRaft.Proofs.Timed
