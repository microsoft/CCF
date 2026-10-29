module

public import CCFRaft.Proofs.Timed.Rounds
public import CCFRaft.Proofs.Timed.Change
public import CCFRaft.Proofs.Timed.Grow

@[expose] public section

set_option linter.unusedSectionVars false

/-!
# Each peer acknowledges

A live peer of the term acknowledges at least the primary's log at a given point
within a bounded time. More than a delay after that point, either the peer's log
changes, and the accepting pass chains to an acknowledgement, or it stays fixed
long enough for the probes to reach the agreement. The primary's log beyond the
start of the window is of its own term, so the terms of its log beyond the
agreement at the start bound the rounds left.
-/

open CCF.Execution (Trace)

namespace CCFRaft.Proofs.Timed

open CCF CCF.MultiNodeTransitionSystem
open CCFRaft.Liveness
open Model.Node
open HasProtocol (proto)
open CCFRaft.Proofs.Liveness (Admissible)
open CCFRaft.Proofs.Replication
open CCFRaft.Proofs.Safety
open CCFRaft.Proofs.StablePrimary
open CCFRaft.Proofs.CommitLiveness (stable_log_prefix)

section Restrict

variable {W : Type} [HasProtocol W Model.State] [HasLive W]
  {trace : Trace W Liveness.Event}

theorem cut_nodeAt {cutoff index : Nat} {node : NodeID} {state : NodeState}
    (found : nodeAt (cut trace cutoff) index node = some state)
    : index <= cutoff /\ nodeAt trace index node = some state := by
  obtain ⟨point, pointFound, nodeFound⟩ := nodeAt_eq_some.mp found
  obtain ⟨le, pointFound⟩ := stateAt_of_cut pointFound
  exact ⟨le, by rw [nodeAt_of_stateAt pointFound, nodeFound]⟩

/-- Stable leadership survives cutting the recording after its start. -/
theorem stable_restrict {start : Nat} {leader : NodeID} {term : Nat}
    (stable : StableLeader trace start leader term) {cutoff : Nat} (le : start <= cutoff)
    : StableLeader (cut trace cutoff) start leader term := by
  obtain ⟨⟨first, firstFound⟩, leads⟩ := stable
  refine ⟨
    ⟨first, by rw [cut_stateAt_of_le le]; exact firstFound⟩,
    fun index point after found => ?_
  ⟩
  obtain ⟨below, found⟩ := stateAt_of_cut found
  obtain ⟨point', state, found', rest⟩ := leads index point after found
  exact ⟨point', state, by rw [cut_stateAt_of_le below]; exact found', rest⟩

end Restrict

/-- The blocks above `agreed` are the distinct terms of the log beyond it. -/
theorem blocks_drop (log : List Entry) (agreed : Nat)
    : blocks log agreed log.length
      = ((log.drop agreed).map Entry.term).toFinset.card := by
  unfold blocks
  congr 1
  ext value
  simp only [Finset.mem_image, Finset.mem_Ioc, List.mem_toFinset, List.mem_map]
  constructor
  · rintro ⟨k, ⟨lo, hi⟩, rfl⟩
    refine ⟨log[k - 1], ?_, (termAt_eq (by omega) hi).symm⟩
    rw [List.mem_iff_getElem]
    exact ⟨k - 1 - agreed, by simp; omega, by simp only [List.getElem_drop]; congr 1; omega⟩
  · rintro ⟨entry, member, rfl⟩
    obtain ⟨i, lt, rfl⟩ := List.mem_iff_getElem.mp member
    simp only [List.length_drop] at lt
    refine ⟨agreed + i + 1, ⟨by omega, by omega⟩, ?_⟩
    rw [termAt_eq (by omega) (by omega), List.getElem_drop]
    congr 1

/-- Raising the agreement leaves no more blocks. -/
theorem blocks_anti {log : List Entry} {agreed agreed' index : Nat}
    (le : agreed <= agreed')
    : blocks log agreed' index <= blocks log agreed index :=
  Finset.card_le_card (Finset.image_subset_image (Finset.Ioc_subset_Ioc_left le))

/-- An extension of one term adds at most one block. -/
theorem blocks_append {log extension : List Entry} {agreed index t : Nat}
    (terms : forall entry, entry ∈ extension -> entry.term = t)
    (bound : index <= (log ++ extension).length)
    : blocks (log ++ extension) agreed index <= blocks log agreed log.length + 1 := by
  unfold blocks
  calc
    ((Finset.Ioc agreed index).image (termAt (log ++ extension))).card
        <= ((Finset.Ioc agreed log.length).image (termAt (log ++ extension))
            ∪ {t}).card := by
      apply Finset.card_le_card
      intro value member
      simp only [Finset.mem_image, Finset.mem_Ioc] at member
      obtain ⟨k, ⟨lo, hi⟩, rfl⟩ := member
      simp only [Finset.mem_union, Finset.mem_image, Finset.mem_Ioc, Finset.mem_singleton]
      by_cases inside : k <= log.length
      · exact Or.inl ⟨k, ⟨lo, inside⟩, rfl⟩
      · right
        rw [termAt_eq (by omega) (by omega), List.getElem_append_right (by omega)]
        exact terms _ (List.getElem_mem _)
    _ <= ((Finset.Ioc agreed log.length).image (termAt (log ++ extension))).card + 1 :=
      (Finset.card_union_le _ _).trans (by simp)
    _ = ((Finset.Ioc agreed log.length).image (termAt log)).card + 1 := by
      congr 2
      apply Finset.image_congr
      intro k member
      simp only [Finset.coe_Ioc, Set.mem_Ioc] at member
      rw [termAt_eq (by omega) (by simp; omega), termAt_eq (by omega) member.2,
        List.getElem_append_left]

/-- The time within which a peer acknowledges. -/
def ackBound (delay interval : Real) (backlog : Nat) : Real :=
  6 * delay + 4 * interval + ((2 * (backlog + 1) : Nat) : Real) * (2 * delay + interval)

variable {W : Type} [HasProtocol W Model.State] [HasTime W] [HasLive W] [HasNetwork W]
  [Proofs.Config.InitialConfiguration] {nodes : List NodeID}
  {trace : Trace W Liveness.Event}
  (admissible : Admissible Proofs.Config.INITIAL_CONFIGURATION nodes trace)
  {start last : Nat} {stop delay interval : Real} {leader : NodeID} {term : Nat}
  (stable : StableLeader trace start leader term)
  {peer : NodeID} (different : Not (peer = leader))
  (env : Env trace start last stop delay interval leader peer)
  (current
    : forall index point,
        start <= index
        -> index <= last
        -> trace.stateAt index = some point
        -> exists state,
            nodeState (proto point) peer = some state /\ state.currentTerm = term)
  (eligible
    : forall index state,
        start <= index
        -> nodeAt trace index leader = some state
        -> peer ∈ eligiblePeers state leader)
  (nonneg : 0 <= delay) (intervalNonneg : 0 <= interval)

include admissible stable different env current eligible nonneg intervalNonneg

/-- The peer acknowledges at least the primary's log at `base` within the bound. -/
theorem peer_acks {backlog : Nat}
    (backlogAt
      : forall other primary,
          nodeAt trace start peer = some other
          -> nodeAt trace start leader = some primary
          -> ((primary.log.drop (agree other.log primary.log)).map
                Entry.term).toFinset.card
              <= backlog)
    {base : Nat} (startLe : start <= base) (baseLe : base <= last)
    (timely : clock trace base + ackBound delay interval backlog <= stop)
    : exists later step reply acked,
        base < later
        /\ clock trace later <= clock trace base + ackBound delay interval backlog
        /\ trace.stepAt later = some step
        /\ step.action = .deliver reply
        /\ reply.envelope
            = {
              source := peer
              target := leader
              payload :=
                .appendEntriesResponse { term, success := true, lastLogIndex := acked }
            }
        /\ forall state,
            nodeAt trace base leader = some state -> state.log.length <= acked := by
  classical
  have boundEq : ackBound delay interval backlog
      = 6 * delay + 4 * interval + ((2 * (backlog + 1) : Nat) : Real) * (2 * delay + interval) :=
    rfl
  have countNonneg : (0 : Real) <= ((2 * (backlog + 1) : Nat) : Real) * (2 * delay + interval) := by
    positivity
  rw [boundEq] at timely ⊢
  set count := 2 * (backlog + 1) with countEq
  set beta := clock trace base with betaEq
  set Y := beta + 4 * delay + 4 * interval + (count : Real) * (2 * delay + interval) with YEq
  have startClock : clock trace start <= beta := env.mono start base startLe baseLe
  -- A point a delay after `base`, and a point a delay after that.
  obtain ⟨origin, originStep, -, originStart, originAfter, originBefore, originStepped, -⟩ :=
    env.passes (beta + delay) (by linarith) (by linarith)
  have originLt := env.ends _ _ originStepped
  obtain ⟨first, firstStep, -, firstStart, firstAfter, firstBefore, firstStepped, -⟩ :=
    env.passes (clock trace origin + delay)
      (by have := env.mono start origin originStart originLt.le; linarith) (by linarith)
  have firstLt := env.ends _ _ firstStepped
  have baseLt : base < origin := by
    by_contra early
    have := env.mono origin base (by omega) baseLe
    linarith
  have originLe : origin <= first := by
    by_contra early
    have := env.mono first origin (by omega) originLt.le
    linarith
  -- Cut where the clock first passes `Y`.
  have existsCut : exists index, Y < clock trace index \/ last <= index := ⟨last, Or.inr le_rfl⟩
  have cutoffLe : Nat.find existsCut <= last := Nat.find_min' existsCut (Or.inr le_rfl)
  have below : forall index, index < Nat.find existsCut -> clock trace index <= Y := by
    intro index lt
    have := Nat.find_min existsCut lt
    simp only [not_or, not_lt] at this
    exact this.1
  have beyond : Nat.find existsCut < last -> Y < clock trace (Nat.find existsCut) := by
    intro lt
    rcases Nat.find_spec existsCut with spec | spec
    · exact spec
    · omega
  set cutoff := Nat.find existsCut with cutoffEq
  have firstLtCut : first < cutoff := by
    by_contra late
    have lt : cutoff < last := by omega
    have := beyond lt
    have := env.mono cutoff first (by omega) firstLt.le
    linarith
  by_cases changes
    : exists index step pre post,
        origin <= index
        /\ index < cutoff
        /\ trace.stepAt index = some step
        /\ nodeState (proto step.before) peer = some pre
        /\ nodeState (proto step.after) peer = some post
        /\ Not (post.log = pre.log)
  · -- The log changes: the accepting pass chains to an acknowledgement.
    obtain ⟨index, step, pre, post, originLe', ltCut, stepped, preFound, postFound, changed⟩ :=
      changes
    have := env.mono origin index originLe' (by omega)
    have := below index ltCut
    obtain ⟨later, step', reply, acked, lt, clockLe, stepped', event, envelope, covers⟩ :=
      change_acks admissible stable different env current eligible nonneg startLe baseLe stepped
        preFound postFound changed (by linarith) (by linarith)
    exact ⟨later, step', reply, acked, by omega, by linarith, stepped', event, envelope, covers⟩
  · -- The log stays fixed until the cut: probe it there.
    have originFound := Trace.stateAt_of_stepAt originStepped
    obtain ⟨other, otherFound, otherTerm⟩ :=
      current origin _ originStart originLt.le originFound
    have otherAt : nodeAt trace origin peer = some other := by
      rw [nodeAt_before originStepped, otherFound]
    obtain ⟨primary, primaryFound⟩ := stable.found originStart originFound
    have fixed
        : forall index point,
            origin <= index
            -> index <= cutoff
            -> trace.stateAt index = some point
            -> exists state,
                nodeState (proto point) peer = some state
                /\ state.currentTerm = term
                /\ state.log = other.log := by
      intro index point originLe'
      induction index, originLe' using Nat.le_induction generalizing point with
      | base =>
          intro _ found
          rw [originFound, Option.some.injEq] at found
          subst found
          exact ⟨other, otherFound, otherTerm, rfl⟩
      | succ index originLe' ih =>
          intro le found
          obtain ⟨step, stepped, after⟩ := Trace.stateAt_succ_eq_some.mp found
          subst after
          obtain ⟨pre, preFound, preTerm, preLog⟩ :=
            ih step.before (by omega) (Trace.stateAt_of_stepAt stepped)
          obtain ⟨post, postFound, postTerm⟩ :=
            current (index + 1) step.after (by omega) (by omega) found
          refine ⟨post, postFound, postTerm, ?_⟩
          by_contra changed
          exact changes ⟨index, step, pre, post, originLe', by omega, stepped, preFound, postFound,
            by rw [preLog]; exact changed⟩
    have stable' := stable_restrict stable (show start <= cutoff by omega)
    have regime : Regime stable' peer other.log (agree other.log primary.log) origin := {
      afterStart := originStart
      recorded := ⟨_, by rw [cut_stateAt_of_le (by omega)]; exact originFound⟩
      state := fun index point le found => by
        obtain ⟨below, found⟩ := stateAt_of_cut found
        exact fixed index point le below found
      agreement := fun index state le found => by
        obtain ⟨below, found⟩ := cut_nodeAt found
        exact agree_stays admissible stable originStart le otherAt primaryFound found
      fresh := fun index step packet le stepped event => by
        obtain ⟨lt, stepped⟩ := stepAt_of_cut stepped
        obtain ⟨sent, sentLt, sentAt⟩ :=
          admissible.consumed_sent stepped (packet := packet) (by rw [event]; rfl)
        refine ⟨sent, ?_, sentLt, (cut_sentAt (by omega)).mpr sentAt⟩
        by_contra early
        have := env.prompt index step packet sent stepped event sentAt
        have := env.mono sent start (by omega) env.startLe
        have := env.mono origin index le (by omega)
        linarith
    }
    have env' := env.restrict (cutoff := cutoff) (bound := Y) (by omega) cutoffLe
      (by linarith) below beyond
    have eligible'
        : forall index state,
            start <= index
            -> nodeAt (cut trace cutoff) index leader = some state
            -> peer ∈ eligiblePeers state leader :=
      fun index state le found => eligible index state le (cut_nodeAt found).2
    -- The primary's log at the cut, and the rounds it leaves.
    obtain ⟨lastPoint, lastFound⟩ := env.lastFound
    obtain ⟨cutPoint, cutFound⟩ := Trace.stateAt_ge_stable cutoffLe lastFound
    obtain ⟨reference, referenceFound⟩ := stable.found (show start <= cutoff by omega) cutFound
    obtain ⟨startPoint, startFound⟩ := stable.1
    obtain ⟨initial, initialFound⟩ := stable.found le_rfl startFound
    obtain ⟨peerInitial, peerInitialFound, _⟩ :=
      current start startPoint le_rfl env.startLe startFound
    have peerInitialAt : nodeAt trace start peer = some peerInitial := by
      rw [nodeAt_of_stateAt startFound, peerInitialFound]
    obtain ⟨extension, extended, extensionTerms⟩ :=
      leader_grows admissible stable le_rfl (show start <= cutoff by omega) initialFound
        referenceFound
    have grown := agree_grows admissible stable different le_rfl originStart
      (fun middle point le le' found => current middle point le (by omega) found)
      peerInitialAt otherAt initialFound primaryFound
    have backlogged := backlogAt peerInitial initial peerInitialAt initialFound
    have roundsLe
        : forall position,
            position <= reference.log.length
            -> rounds other.log reference.log (agree other.log primary.log) position
              <= count := by
      intro position le
      have := rounds_le (follower := other.log) (log := reference.log)
        (agreed := agree other.log primary.log) position
      rw [extended] at le this ⊢
      have := blocks_append (agreed := agree other.log primary.log) extensionTerms le
      have := blocks_anti (log := initial.log) (index := initial.log.length) grown
      have := blocks_drop initial.log (agree peerInitial.log initial.log)
      omega
    have late : clock (cut trace cutoff) origin + delay < clock (cut trace cutoff) first := by
      rw [clock_cut (by omega), clock_cut (by omega)]
      exact firstAfter
    have timely' :
        clock (cut trace cutoff) first + 2 * interval + count * (2 * delay + interval)
          + 2 * delay <= Y := by
      rw [clock_cut (by omega)]
      linarith
    obtain ⟨acked, index, reply, firstLtAcked, ackedLength, ackedLt, clockIndex, sentAt,
        envelope⟩ :=
      regime_acks (Admissible.cut admissible cutoff) stable' different env' nonneg eligible'
        regime originLe firstLtCut.le late intervalNonneg
        (by rw [cut_nodeAt_of_le le_rfl]; exact referenceFound) roundsLe timely'
    have indexLt := (stepAt_of_cut (Exists.choose_spec sentAt).1).1
    have sentAt := (cut_sentAt indexLt).mp sentAt
    rw [clock_cut indexLt.le] at clockIndex
    obtain ⟨later, step, laterLt, stepped, event⟩ :=
      env.arrives index reply (by omega) sentAt
        (Or.inr ⟨by rw [envelope], by rw [envelope]⟩) (by linarith)
    have := env.prompt later step reply index stepped event sentAt
    refine ⟨later, step, reply, agree other.log primary.log, by omega, by linarith, stepped,
      event, envelope, fun state found => ?_⟩
    obtain ⟨ackedPoint, ackedFound⟩ := Trace.stateAt_ge_stable (show acked <= last by omega) lastFound
    obtain ⟨ackedState, ackedStateFound⟩ := stable.found (show start <= acked by omega) ackedFound
    have length := ackedLength ackedState (by rw [cut_nodeAt_of_le (by omega)]; exact ackedStateFound)
    have := (stable_log_prefix admissible stable startLe (show base <= acked by omega) found
      ackedStateFound).length_le
    omega

end CCFRaft.Proofs.Timed
