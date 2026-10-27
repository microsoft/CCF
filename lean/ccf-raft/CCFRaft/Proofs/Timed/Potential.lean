module

public import CCFRaft.Proofs.Replication.Retry

@[expose] public section

set_option linter.unusedSectionVars false

/-!
# Rounds left before a probe reaches the agreement

A rejected probe of the primary's log moves the primary's retry index down past
at least one term block of its log, or into the follower's log. Counting term
blocks above the agreed prefix twice, less one inside the follower's log, gives a
potential that every rejection strictly lowers and that vanishes only at the
agreement.
-/

namespace CCFRaft.Proofs.Timed

open CCFRaft.Model.Node
open CCFRaft.Proofs.Safety
open CCFRaft.Proofs.Replication

/-- The number of distinct terms of `log` at positions `(agreed, index]`. -/
def blocks (log : List Entry) (agreed index : Nat) : Nat :=
  ((Finset.Ioc agreed index).image (termAt log)).card

/-- Rounds a probe at `index` may still take: two per term block above the
agreement, one fewer inside the follower's log, and none at or below the agreement. -/
def rounds (follower log : List Entry) (agreed index : Nat) : Nat :=
  if index <= agreed then
    0
  else
    2 * blocks log agreed index - (if index <= follower.length then 1 else 0)

section Rounds

variable [CCFRaft.Proofs.Config.InitialConfiguration] {follower log : List Entry}
  {agreed : Nat}

theorem blocks_mono {low high : Nat} (le : low <= high)
    : blocks log agreed low <= blocks log agreed high :=
  Finset.card_le_card (Finset.image_subset_image (Finset.Ioc_subset_Ioc_right le))

theorem blocks_pos {index : Nat} (lt : agreed < index) : 0 < blocks log agreed index :=
  Finset.card_pos.mpr
    ⟨termAt log index, Finset.mem_image.mpr ⟨index, Finset.mem_Ioc.mpr ⟨lt, le_rfl⟩, rfl⟩⟩

/-- A lower position whose term is below a higher one's misses that term's block. -/
theorem blocks_lt (sorted : log.Pairwise fun first second => first.term <= second.term)
    {low high : Nat} (above : agreed < high) (lowLt : low < high)
    (bound : high <= log.length) (lower : termAt log low < termAt log high)
    : blocks log agreed low < blocks log agreed high := by
  refine Finset.card_lt_card
    ((Finset.ssubset_iff_of_subset
      (Finset.image_subset_image (Finset.Ioc_subset_Ioc_right lowLt.le))).mpr ?_)
  refine ⟨termAt log high, Finset.mem_image.mpr ⟨high, Finset.mem_Ioc.mpr ⟨above, le_rfl⟩, rfl⟩,
    fun member => ?_⟩
  obtain ⟨position, inside, same⟩ := Finset.mem_image.mp member
  have := termAt_mono sorted (Finset.mem_Ioc.mp inside).2 (lowLt.le.trans bound)
  omega

theorem rounds_mono {low high : Nat} (le : low <= high)
    : rounds follower log agreed low <= rounds follower log agreed high := by
  have := blocks_mono (log := log) (agreed := agreed) le
  unfold rounds
  by_cases lowIn : low <= agreed
  · simp [lowIn]
  · have := blocks_pos (log := log) (lt_of_not_ge lowIn)
    have highOut : Not (high <= agreed) := by omega
    by_cases lowF : low <= follower.length <;> by_cases highF : high <= follower.length <;>
      simp [lowIn, highOut, lowF, highF] <;> omega

theorem le_of_rounds_eq_zero {index : Nat} (zero : rounds follower log agreed index = 0)
    : index <= agreed := by
  by_contra above
  have := blocks_pos (log := log) (lt_of_not_ge above)
  unfold rounds at zero
  by_cases inF : index <= follower.length <;> simp [above, inF] at zero <;> omega

theorem rounds_le (index : Nat)
    : rounds follower log agreed index <= 2 * blocks log agreed index := by
  unfold rounds
  by_cases low : index <= agreed
  · simp [low]
  · simp only [low, ↓reduceIte]
    omega

/-- A lower position with a lower term needs fewer rounds. -/
theorem rounds_lt_of_term
    (sorted : log.Pairwise fun first second => first.term <= second.term) {low high : Nat}
    (above : agreed < high) (lowLt : low < high) (bound : high <= log.length)
    (lower : termAt log low < termAt log high)
    : rounds follower log agreed low < rounds follower log agreed high := by
  have positive := blocks_pos (log := log) above
  have highOut : Not (high <= agreed) := by omega
  unfold rounds
  by_cases lowIn : low <= agreed
  · by_cases highF : high <= follower.length <;> simp [lowIn, highOut, highF] <;> omega
  · have := blocks_lt (agreed := agreed) sorted above lowLt bound lower
    by_cases lowF : low <= follower.length <;> by_cases highF : high <= follower.length <;>
      simp [lowIn, highOut, lowF, highF] <;> omega

/-- Below the follower's log end a position needs fewer rounds than one past it,
up to the same blocks. -/
theorem rounds_lt_of_inside {low high : Nat} (above : agreed < high) (lowLt : low < high)
    (inside : low <= follower.length) (outside : follower.length < high)
    : rounds follower log agreed low < rounds follower log agreed high := by
  have positive := blocks_pos (log := log) above
  have := blocks_mono (log := log) (agreed := agreed) lowLt.le
  have highOut : Not (high <= agreed) := by omega
  have highF : Not (high <= follower.length) := by omega
  unfold rounds
  by_cases lowIn : low <= agreed
  · simp [lowIn, highOut, highF]
    omega
  · simp [lowIn, highOut, highF, inside]
    omega

theorem rounds_pos {index : Nat} (above : agreed < index)
    : 0 < rounds follower log agreed index := by
  rcases Nat.eq_zero_or_pos (rounds follower log agreed index) with zero | positive
  · exact absurd (le_of_rounds_eq_zero zero) (by omega)
  · exact positive

theorem rounds_of_le {index : Nat} (le : index <= agreed)
    : rounds follower log agreed index = 0 := by
  simp [rounds, le]

/-- A rejection of a probe at `prevLogIndex` from a follower of the primary's term
moves the primary's retry index to a position that needs fewer rounds. Positions
are compared against the primary's later log `log`; the retry is computed over
the primary's log `current` when the rejection arrives. -/
theorem retry_rounds {current : List Entry} {top : Nat} {w : NodeState}
    {r : AppendEntriesRequest}
    (logSorted : log.Pairwise fun first second => first.term <= second.term)
    (followerPositive
      : forall index, 0 < index -> index <= follower.length -> 0 < termAt follower index)
    (matching
      : forall index,
          0 < index
          -> index <= follower.length
          -> index <= log.length
          -> termAt follower index = termAt log index
          -> follower.take index = log.take index)
    (agreement : agree follower log = agreed) (sub : current <+: log)
    (wLog : w.log = follower) (wTerm : w.currentTerm = top) (rTerm : r.term = top)
    (bound : r.prevLogIndex <= current.length)
    (prevTerm : r.prevLogTerm = termAt log r.prevLogIndex)
    (mismatch : Not (termAt follower r.prevLogIndex = termAt log r.prevLogIndex))
    : rounds follower log agreed (retry current w r)
      < rounds follower log agreed r.prevLogIndex := by
  have above : agreed < r.prevLogIndex := by
    rw [← agreement, ← wLog]
    exact agree_lt_prev (by rw [wLog]; exact mismatch)
  have logBound : r.prevLogIndex <= log.length := bound.trans sub.length_le
  have transfer : forall index, index <= current.length -> termAt current index = termAt log index :=
    fun index le => (termAt_of_prefix sub le).symm
  have positive := rounds_pos (follower := follower) (log := log) above
  unfold retry nackResponse
  split
  · rename_i stale
    have zero : termAt follower r.prevLogIndex = 0 := by
      rcases stale with older | zero
      · omega
      · rwa [wLog] at zero
    have outside : follower.length < r.prevLogIndex := by
      by_contra inside
      have := followerPositive _ (by omega) (Nat.le_of_not_lt inside)
      omega
    have le := fhpm_le (log := current) (index := w.log.length) (term := w.currentTerm)
    rw [wLog] at le
    dsimp only
    rw [wLog]
    exact (rounds_mono (log := log) (le.trans (Nat.min_le_left _ _))).trans_lt
      (rounds_lt_of_inside above outside le_rfl outside)
  · rename_i current'
    simp only [not_or] at current'
    have inside : r.prevLogIndex <= follower.length := by
      by_contra outside
      exact current'.2 (by rw [wLog]; exact termAt_of_length_lt (Nat.lt_of_not_le outside))
    dsimp only
    rw [wLog, prevTerm]
    generalize highEq : findHighestPossibleMatch follower r.prevLogIndex
      (termAt log r.prevLogIndex) = high
    have highLe := fhpm_le (log := follower) (index := r.prevLogIndex)
      (term := termAt log r.prevLogIndex)
    rw [highEq] at highLe
    have retryLe := fhpm_le (log := current) (index := high) (term := termAt follower high)
    generalize retryEq : findHighestPossibleMatch current high (termAt follower high) = again
      at retryLe
    rcases fhpm_chosen (log := follower) (index := r.prevLogIndex)
        (term := termAt log r.prevLogIndex) with zero | ⟨highPos, highTerm⟩
    · rw [highEq] at zero
      subst zero
      have : again = 0 := by omega
      rw [this, rounds_of_le (Nat.zero_le _)]
      exact positive
    rw [highEq] at highPos highTerm
    have logHigh : termAt log high <= termAt log r.prevLogIndex :=
      termAt_mono logSorted (highLe.trans (Nat.min_le_left _ _)) logBound
    rcases Nat.lt_or_ge (termAt follower high) (termAt log r.prevLogIndex) with lower | equal
    · rcases fhpm_chosen (log := current) (index := high) (term := termAt follower high)
          with zero | ⟨_, againTerm⟩
      · rw [retryEq] at zero
        rw [zero, rounds_of_le (Nat.zero_le _)]
        exact positive
      rw [retryEq] at againTerm
      have againBound : again <= current.length := retryLe.trans (Nat.min_le_right _ _)
      rw [transfer again againBound] at againTerm
      have lt : again < r.prevLogIndex := by
        rcases Nat.eq_or_lt_of_le (retryLe.trans ((Nat.min_le_left _ _).trans
          (highLe.trans (Nat.min_le_left _ _)))) with same | lt
        · rw [same] at againTerm
          omega
        · exact lt
      exact rounds_lt_of_term logSorted above lt logBound (by omega)
    · have same : termAt follower high = termAt log r.prevLogIndex := by omega
      have highLt : high < r.prevLogIndex := by
        rcases Nat.eq_or_lt_of_le (highLe.trans (Nat.min_le_left _ _)) with eq | lt
        · rw [eq] at same
          exact absurd same mismatch
        · exact lt
      have highRounds : rounds follower log agreed high < rounds follower log agreed r.prevLogIndex := by
        rcases Nat.lt_or_ge (termAt log high) (termAt log r.prevLogIndex) with lower | top'
        · exact rounds_lt_of_term logSorted above highLt logBound lower
        · have agreeHigh : high <= agreed := by
            rw [← agreement]
            exact le_agree _ _ _ (highLe.trans (Nat.min_le_right _ _))
              (highLt.le.trans logBound)
              (matching high highPos (highLe.trans (Nat.min_le_right _ _))
                (highLt.le.trans logBound) (by omega))
          rw [rounds_of_le agreeHigh]
          exact positive
      exact (rounds_mono (retryLe.trans (Nat.min_le_left _ _))).trans_lt highRounds

end Rounds

end CCFRaft.Proofs.Timed
