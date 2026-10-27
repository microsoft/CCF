module

public import CCFRaft.Proofs.Replication.Basic
public import CCFRaft.Proofs.Safety.Flow
public import CCFRaft.Proofs.Safety.Records

@[expose] public section

/-!
# Where a rejection sends the primary's retry index

A follower with log `J` rejects a request whose previous entry is taken from the
primary's log `Λ`. The primary then retries from `findHighestPossibleMatch` over
its own log. That index never drops below the agreed prefix of `J` and `Λ`, and
always drops below the rejected request's previous index, clipped to `|J| + 1`.
-/

namespace CCFRaft.Proofs.Replication

open CCFRaft.Model.Node
open CCFRaft.Proofs.Safety

/-- The primary's retry index after a rejection from `w` of `r`. -/
def retry (log : List Entry) (w : NodeState) (r : AppendEntriesRequest) : Nat :=
  findHighestPossibleMatch log (nackResponse w r).lastLogIndex (nackResponse w r).term

section Retry

variable {log : List Entry} {w : NodeState} {r : AppendEntriesRequest}

theorem termAt_agree {xs ys : List Entry} {index : Nat} (le : index <= agree xs ys)
    : termAt xs index = termAt ys index := by
  rw [← termAt_take (log := xs) le, ← termAt_take (log := ys) le, take_agree]

/-- A mismatched previous entry lies beyond the agreed prefix. -/
theorem agree_lt_prev
    (mismatch : Not (termAt w.log r.prevLogIndex = termAt log r.prevLogIndex))
    : agree w.log log < r.prevLogIndex := by
  by_contra le
  exact mismatch (termAt_agree (Nat.le_of_not_lt le))

/-- A rejection never retreats into the agreed prefix. -/
theorem agree_le_retry [Config.InitialConfiguration]
    (sortedFollower : w.log.Pairwise fun first second => first.term <= second.term)
    (sortedLog : log.Pairwise fun first second => first.term <= second.term)
    (terms : forall index, termAt log index <= w.currentTerm)
    (bound : r.prevLogIndex <= log.length)
    (prevTerm : r.prevLogTerm = termAt log r.prevLogIndex)
    (mismatch : Not (termAt w.log r.prevLogIndex = termAt log r.prevLogIndex))
    : agree w.log log <= retry log w r := by
  rcases Nat.eq_zero_or_pos (agree w.log log) with zero | positive
  · rw [zero]
    exact Nat.zero_le _
  have left := agree_le_left w.log log
  have right := agree_le_right w.log log
  have same := termAt_agree (xs := w.log) (ys := log) (le_refl (agree w.log log))
  unfold retry nackResponse
  split
  · exact le_fhpm positive left right (terms _)
  · have lt := agree_lt_prev mismatch
    have high : agree w.log log
        <= findHighestPossibleMatch w.log r.prevLogIndex r.prevLogTerm := by
      refine le_fhpm positive lt.le left ?_
      rw [same, prevTerm]
      exact termAt_mono sortedLog lt.le bound
    refine le_fhpm positive high right ?_
    rw [← same]
    exact termAt_mono sortedFollower high (fhpm_le.trans (Nat.min_le_right _ _))

/-- A rejection retreats below the rejected request's previous index, clipped to
just past the follower's log. -/
theorem retry_lt
    (positiveFollower
      : forall index, 0 < index -> index <= w.log.length -> 0 < termAt w.log index)
    (current : Not (r.term < w.currentTerm))
    (prevTerm : r.prevLogTerm = termAt log r.prevLogIndex)
    (mismatch : Not (termAt w.log r.prevLogIndex = termAt log r.prevLogIndex))
    : retry log w r < min r.prevLogIndex (w.log.length + 1) := by
  have positive : 0 < r.prevLogIndex := by
    rcases Nat.eq_zero_or_pos r.prevLogIndex with zero | positive
    · exact absurd (by rw [zero, termAt_zero, termAt_zero]) mismatch
    · exact positive
  unfold retry nackResponse
  split
  · rename_i short
    have beyond : w.log.length < r.prevLogIndex := by
      by_contra within
      have := positiveFollower _ positive (Nat.le_of_not_lt within)
      omega
    dsimp only
    rw [Nat.min_eq_right (by omega)]
    have := fhpm_le (log := log) (index := w.log.length) (term := w.currentTerm)
    omega
  · rename_i long
    have within : r.prevLogIndex <= w.log.length := by
      by_contra beyond
      exact long (Or.inr (termAt_of_length_lt (Nat.lt_of_not_le beyond)))
    rw [Nat.min_eq_left (by omega)]
    rw [prevTerm]
    generalize chosen : findHighestPossibleMatch w.log r.prevLogIndex (termAt log r.prevLogIndex)
      = high
    have highLe : high <= r.prevLogIndex := chosen ▸ fhpm_le.trans (Nat.min_le_left _ _)
    have retryLe := fhpm_le (log := log) (index := high) (term := termAt w.log high)
    rcases Nat.eq_or_lt_of_le highLe with top | lt
    · subst top
      have below : termAt w.log r.prevLogIndex < termAt log r.prevLogIndex := by
        rcases (fhpm_chosen (log := w.log) (index := r.prevLogIndex)
            (term := termAt log r.prevLogIndex)) with zero | ⟨_, le⟩
        · omega
        · rw [chosen] at le
          omega
      rcases Nat.eq_or_lt_of_le (retryLe.trans (Nat.min_le_left _ _)) with same | lt
      · rcases (fhpm_chosen (log := log) (index := r.prevLogIndex)
            (term := termAt w.log r.prevLogIndex)) with zero | ⟨_, le⟩
        · omega
        · rw [same] at le
          omega
      · exact lt
    · exact (retryLe.trans (Nat.min_le_left _ _)).trans_lt lt

end Retry

end CCFRaft.Proofs.Replication
