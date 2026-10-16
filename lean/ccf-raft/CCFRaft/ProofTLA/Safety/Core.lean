module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import CCFRaft.ProofTLA.Safety.Local

@[expose] public section

set_option linter.unusedSectionVars false

/-!
# Elections see acknowledged parts

The core of completeness: a part acknowledged by a quorum at `term`, whose
quorum shares a voter with a later election, is in the elected log, provided
every leader log of a term in between contains it.
-/

namespace CCFRaft.ProofTLA.Safety

open CCF
open Model.Node
open CCFRaft.ProofTLA.Ledger

variable {Node TxId : Type} [DecidableEq Node] [DecidableEq TxId] [InitialConfig Node]
  [LinearOrder Node] [Inhabited TxId]

theorem suffix_of_cons_suffix {α : Type} {x y : α} {first second : List α}
    (suffix : x :: first <:+ y :: second)
    : first <:+ second := by
  rcases List.suffix_cons_iff.mp suffix with same | inner
  · rw [(List.cons.inj same).2]
  · exact (List.suffix_cons _ _).trans inner

/-- A state with a lower term than one at `a` was seen before `a`. -/
theorem seen_split {history : History Node TxId} (termMono : Everywhere TermMono history)
    {a : Model.State Node TxId} {rest : History Node TxId}
    (suffix : a :: rest <:+ history) {node : Node} {granted state : NodeState Node TxId}
    (mem : (node, granted) ∈ a.nodes) (seen : Seen history node state)
    (lt : state.currentTerm < granted.currentTerm)
    : Seen rest node state := by
  obtain ⟨earlier, earlierSuffix, now⟩ := seen.now
  have late : a :: rest <:+ earlier -> False := by
    intro within
    obtain ⟨_, _, rfl⟩ := now.nonempty
    have := termMono _ earlierSuffix (List.cons_ne_nil _ _) node state granted now
      ⟨a, within.subset List.mem_cons_self, mem⟩
    omega
  rcases suffix_comparable earlierSuffix suffix with inner | outer
  · rcases List.suffix_cons_iff.mp inner with same | inner
    · exact (late (same ▸ List.suffix_refl _)).elim
    · exact now.seen.mono inner
  · exact (late outer).elim

/-- Prefix of a list of known length. -/
theorem take_of_prefix_length {α : Type} {small large : List α} {n : Nat}
    (sub : small <+: large) (length : small.length = n)
    : small = large.take n := by
  rw [← length]
  exact List.prefix_iff_eq_take.mp sub

/--
A commit step at `term` and a later election whose logs agree up to both
commit indices: the committed part is in the elected log, provided `clean`:
every leader log of a term in `(term, later]` before the election contains it.
-/
theorem core {small large : History Node TxId} (within : small <:+ large)
    (termMono : Everywhere TermMono large) (canonMono : Everywhere CanonMono small)
    (sorted : Everywhere Sorted small) {current : Model.State Node TxId}
    {past : History Node TxId} {leader : Node} {state : NodeState Node TxId}
    {term base index : Nat} (commitSuffix : current :: past <:+ small)
    (step : CommitStep (current :: past) leader state term base index)
    {a b : Model.State Node TxId} {r : History Node TxId} {node : Node}
    {later commit : Nat} {log : List (Entry Node TxId)}
    (electSuffix : a :: b :: r <:+ large) (electInner : b :: r <:+ small)
    (elect : ElectStep a b r node later log commit)
    (persist : Everywhere Persist (b :: r)) (anchor : Everywhere Anchor (b :: r))
    (terms : Everywhere Terms (b :: r)) (lt : term < later) {k : Nat}
    (agree : state.log.take k = log.take k) (baseLe : base <= k) (commitLe : commit <= k)
    (clean
      : forall later' log',
          term < later'
          -> later' <= later
          -> Canon (b :: r) later' log'
          -> state.log.take index <+: log')
    : state.log.take index <+: log := by
  obtain ⟨⟨leaderNow, leaderTerm, leaderRole, leaderLed⟩, _, indexLe, signature, termAtIndex,
    ackers, ackQuorum, acked⟩ := step
  obtain ⟨candidate, _, candidateMem, _, candidateLog, _, frontier, termCase, _, _, _, _,
    voters, voteQuorum, granted⟩ := elect
  obtain ⟨voter, ackMem, voteMem⟩ :=
    quorums_intersect inferInstance agree baseLe commitLe ackQuorum voteQuorum
  obtain ⟨acker, ackerSeen, ackerTerm, ackerLog⟩ := acked voter ackMem
  obtain ⟨a', b', r', grantSuffix, granting, grantedState, grantingMem, grantedMem,
    grantingTerm, grantedTerm, _, upToDate⟩ := granted voter voteMem
  have innerB : b' :: r' <:+ b :: r := suffix_of_cons_suffix grantSuffix
  have ackerB : Seen (b' :: r') voter acker :=
    seen_split termMono (grantSuffix.trans electSuffix) grantedMem
      (ackerSeen.mono (commitSuffix.trans within)) (by omega)
  -- The committed part and its signature.
  have partLength : (state.log.take index).length = index := by
    rw [List.length_take, Nat.min_eq_left indexLe]
  have partSignature : isSignatureAt (state.log.take index) index = true :=
    isSignatureAt_take_of_le le_rfl signature
  have partTerm : termAt (state.log.take index) index = term := by
    rw [termAt_take le_rfl, termAtIndex]
  have ackerTake : acker.log.take index = state.log.take index :=
    (take_of_prefix_length ackerLog partLength).symm
  have ackerTerm' : termAt acker.log index = term := by
    rw [termAt_of_prefix ackerLog partLength.ge, partTerm]
  -- The granting state holds the part.
  have inGranting : state.log.take index <+: granting.log := by
    rcases persist _ innerB (List.cons_ne_nil _ _) voter granting acker index grantingMem ackerB
        (isSignatureAt_of_prefix ackerLog partSignature) with sub | bad
    · rw [ackerTake] at sub
      exact sub
    · obtain ⟨later', log', above, below, canon, missing⟩ := bad
      rw [ackerTake, ackerTerm'] at *
      exact absurd (clean later' log' above (by omega) (canon.mono innerB)) missing
  have grantingSorted := sorted _ (innerB.trans electInner) (List.cons_ne_nil _ _) voter granting
    grantingMem
  have grantingSignature : isSignatureAt granting.log index = true :=
    isSignatureAt_of_prefix inGranting partSignature
  have maxGe : index <= maxCommittableIndex granting.log :=
    signatureIndex_le_maxCommittableIndex grantingSignature
  have maxTermGe : term <= maxCommittableTerm granting.log := by
    have := termAt_mono grantingSorted maxGe (maxCommittableIndexBounded granting.log)
    rw [termAt_of_prefix inGranting partLength.ge, partTerm] at this
    exact this
  -- The election's last committable position.
  simp only [voteLogUpToDate, vals] at upToDate
  set j := max commit (maxCommittableIndex log) with jEq
  have two : 2 <= term := by
    have := leaderLed.two_le
    omega
  have jBound : j <= log.length := max_le frontier (maxCommittableIndexBounded log)
  have termGe : term <= termAt log j := by omega
  have jPos : 0 < j := by
    rcases Nat.eq_zero_or_pos j with zero | positive
    · rw [zero, termAt_zero] at termGe
      omega
    · exact positive
  obtain ⟨anchored, canon, anchoredLength, anchoredTake⟩ :=
    anchor _ (List.suffix_refl _) (List.cons_ne_nil _ _) node candidate j candidateMem jPos
      (candidateLog ▸ jBound)
  rw [candidateLog] at canon anchoredTake
  have viaAnchor : index <= j -> index <= anchored.length
      -> state.log.take index = anchored.take index
      -> state.log.take index <+: log := by
    intro le _ same
    have : log.take index = anchored.take index := by
      have := congrArg (List.take index) anchoredTake
      simp only [List.take_take, Nat.min_eq_left le] at this
      exact this
    rw [same, ← this]
    exact List.take_prefix _ _
  rcases Nat.lt_or_eq_of_le termGe with above | same
  · have bound : termAt log j <= later := by
      have := termAt_le_of_mem
        (terms _ (List.suffix_refl _) (List.cons_ne_nil _ _) node candidate candidateMem) j
      rw [candidateLog] at this
      rcases termCase with lt' | ⟨eq, _⟩ <;> omega
    have sub := clean _ anchored above bound canon
    rcases Nat.lt_or_ge j index with short | long
    · exfalso
      have leaderSorted := sorted _ commitSuffix (List.cons_ne_nil _ _) leader state leaderNow
      have partSorted := leaderSorted.sublist (List.take_sublist index state.log)
      have mono := termAt_mono partSorted short.le partLength.ge
      have atJ : termAt (state.log.take index) j = termAt log j := by
        rw [← termAt_of_prefix sub (by omega), ← termAt_take (n := j) le_rfl, ← anchoredTake,
          termAt_take le_rfl]
      rw [atJ, partTerm] at mono
      omega
    · exact viaAnchor long (by omega)
        (take_of_prefix_length sub partLength)
  · have indexLeJ : index <= j := by
      rcases upToDate with gt | ⟨_, ge⟩
      · omega
      · omega
    rw [← same] at canon
    have leaderCanon : Canon small term state.log :=
      ⟨current :: past, commitSuffix, leader, state,
        ⟨leaderNow, leaderTerm, leaderRole, leaderLed⟩, rfl⟩
    have comparable := canon_chain canonMono (canon.mono electInner) leaderCanon
    exact viaAnchor indexLeJ (by omega)
      (take_eq_take_of_comparable comparable (by omega) indexLe).symm

end CCFRaft.ProofTLA.Safety
