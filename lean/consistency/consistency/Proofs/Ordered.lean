module

public import consistency.Proofs.RealTime

@[expose] public section

namespace consistency.Proofs.Ordered

open Model Properties Observations LedgerIdentity Commitment

theorem nodup_erase (xs : List Response) : xs.eraseDups.Nodup := by
  cases xs with
  | nil => simp
  | cons head tail =>
      rw [List.eraseDups_cons]
      apply List.nodup_cons.mpr
      refine ⟨?_, nodup_erase (tail.filter fun value => !value == head)⟩
      simp [List.mem_eraseDups, List.mem_filter]
termination_by xs.length
decreasing_by
  have bound := List.length_filter_le (fun value => !value == head) tail
  simp only [List.length_cons]
  omega

theorem sorted_responses (history : List Event)
    : (committedRwResponses history).Pairwise
        (fun left right => ¬txIDStrictlyLessThan right.txid left.txid) := by
  have transitive : ∀ (a b c : Response),
      decide (¬txIDStrictlyLessThan b.txid a.txid) →
      decide (¬txIDStrictlyLessThan c.txid b.txid) →
      decide (¬txIDStrictlyLessThan c.txid a.txid) := by
    intro a b c first second
    have firstOrder := of_decide_eq_true first
    have secondOrder := of_decide_eq_true second
    apply decide_eq_true
    unfold txIDStrictlyLessThan at *
    omega
  have total : ∀ (a b : Response),
      decide (¬txIDStrictlyLessThan b.txid a.txid) ||
      decide (¬txIDStrictlyLessThan a.txid b.txid) := by
    intro a b
    simp only [Bool.or_eq_true]
    by_cases first : ¬txIDStrictlyLessThan b.txid a.txid
    · exact Or.inl (decide_eq_true first)
    right
    apply decide_eq_true
    unfold txIDStrictlyLessThan at *
    omega
  exact (List.pairwise_mergeSort transitive total _).imp (by
    intro left right related
    exact of_decide_eq_true related)

theorem adjacent (history : List Event) {pair : Response × Response}
    (listed
      : pair ∈ (committedRwResponses history).zip (committedRwResponses history).tail)
    : pair.1 ∈ committedRwResponses history
      ∧ pair.2 ∈ committedRwResponses history
      ∧ pair.1 ≠ pair.2
      ∧ ¬txIDStrictlyLessThan pair.2.txid pair.1.txid := by
  obtain ⟨index, lookup⟩ := List.mem_iff_getElem?.mp listed
  obtain ⟨first, tailLookup⟩ := List.getElem?_zip_eq_some.mp lookup
  have second : (committedRwResponses history)[index + 1]? = some pair.2 := by
    simpa using tailLookup
  obtain ⟨firstBound, firstValue⟩ := List.getElem?_eq_some_iff.mp first
  obtain ⟨secondBound, secondValue⟩ := List.getElem?_eq_some_iff.mp second
  have nodup : (committedRwResponses history).Nodup :=
    (List.mergeSort_perm _ _).nodup_iff.mpr (nodup_erase _)
  have distinct := nodup.rel_getElem_of_lt firstBound secondBound (by omega)
  have ordered := (sorted_responses history).rel_getElem_of_lt firstBound secondBound (by omega)
  exact ⟨
    List.mem_of_getElem? first,
    List.mem_of_getElem? second,
    by simpa [firstValue, secondValue] using distinct,
    by simpa [firstValue, secondValue] using ordered
  ⟩

theorem mem_ordered (history : List Event) {response : Response}
    (member : response ∈ committedRwResponses history)
    : ∃ indexed ∈ committedResponses history .rw, indexed.2 = response := by
  simpa only [committedRwResponses, List.mem_mergeSort, List.mem_eraseDups, List.mem_map]
    using member

theorem sequence_order {state : State}
    (reachable : transitionSystem.Reachable state) {left right : TxID}
    (first : left ∈ statusIDs state.history .committed)
    (second : right ∈ statusIDs state.history .committed)
    (different : left ≠ right) (ordered : ¬txIDStrictlyLessThan right left)
    : left.seqno < right.seqno := by
  by_contra notLater
  have views := ViewOrder.committed_views reachable second first (by omega)
  unfold txIDStrictlyLessThan at ordered
  have sameView : left.view = right.view := by omega
  have sameSeq : left.seqno = right.seqno := by omega
  exact different (congrArg₂ TxID.mk sameView sameSeq)

theorem through_entry {α : Type} {xs : List α} {index : Nat} {value : α}
    (found : at? xs index = some value)
    : xs.take index = xs.take (index - 1) ++ [value] := by
  have positive := (at_bounds found).1
  have lookup : xs[index - 1]? = some value := by
    simpa [at?, Nat.ne_of_gt positive] using found
  obtain ⟨bound, actual⟩ := List.getElem?_eq_some_iff.mp lookup
  have same := List.take_succ_eq_append_getElem bound
  simpa [show index - 1 + 1 = index by omega, actual] using same

theorem strict_observations {ledger : List Entry} {leftSeq rightSeq : Nat}
    {entry : Entry} {tx : TxContent} (rightAt : at? ledger rightSeq = some entry)
    (value : entry.tx = some tx) (bound : leftSeq < rightSeq)
    : writes (ledger.take leftSeq) <+: writes (ledger.take rightSeq)
      ∧ (writes (ledger.take leftSeq)).length < (writes (ledger.take rightSeq)).length
      ∧ (writes (ledger.take rightSeq)).getLast? = some tx := by
  have through : writes (ledger.take rightSeq) =
      writes (ledger.take (rightSeq - 1)) ++ [tx] := by
    rw [through_entry rightAt]
    simp [writes, List.filterMap_append, value]
  have before : writes (ledger.take leftSeq) <+: writes (ledger.take (rightSeq - 1)) :=
    (List.take_prefix_take_left (l := ledger) (by omega)).filterMap Entry.tx
  refine ⟨
    (List.take_prefix_take_left (l := ledger) (Nat.le_of_lt bound)).filterMap Entry.tx,
    ?_,
    ?_
  ⟩
  · have length := before.length_le
    rw [through, List.length_append, List.length_singleton]
    omega
  · simp [through]

theorem committed_rw_ordered_serializable
    : forall (trace : CCF.Execution.Trace State) (state : State),
        (trace.Valid transitionSystem /\ state ∈ trace)
        → ∀ pair ∈
            (committedRwResponses state.history).zip
              (committedRwResponses state.history).tail,
            pair.1.observed <+: pair.2.observed
            ∧ pair.1.observed.length < pair.2.observed.length
            ∧ pair.2.observed.getLast? = some pair.2.tx := by
  intro trace state ⟨valid, member⟩ pair listed
  have reachable := valid.reachable member
  obtain ⟨firstListed, secondListed, different, ordered⟩ := adjacent state.history listed
  obtain ⟨first, firstMember, firstPayload⟩ := mem_ordered state.history firstListed
  obtain ⟨second, secondMember, secondPayload⟩ := mem_ordered state.history secondListed
  have distinctIDs : first.2.txid ≠ second.2.txid := by
    intro same
    have firstResponse := (List.mem_filter.mp firstMember).1
    have secondResponse := (List.mem_filter.mp secondMember).1
    have tx := LedgerIdentity.unique_txs trace state ⟨valid, member⟩
      first firstResponse second secondResponse same
    have obs := LedgerIdentity.same_observations trace state ⟨valid, member⟩
      first (List.mem_filter.mp firstResponse).1
      second (List.mem_filter.mp secondResponse).1 same
    have firstKind := ((History.mem_responsesOf_iff _ _ _).mp firstResponse).1
    have secondKind := ((History.mem_responsesOf_iff _ _ _).mp secondResponse).1
    have equal : first.2 = second.2 := by
      change Response.mk first.2.kind first.2.tx first.2.observed first.2.txid =
        Response.mk second.2.kind second.2.tx second.2.observed second.2.txid
      rw [firstKind, secondKind, tx, obs, same]
    exact different (firstPayload.symm.trans (equal.trans secondPayload))
  have firstKnown : first.2.txid ∈ statusIDs state.history .committed := by
    simpa using (List.mem_filter.mp firstMember).2
  have secondKnown : second.2.txid ∈ statusIDs state.history .committed := by
    simpa using (List.mem_filter.mp secondMember).2
  have seqno :=
    sequence_order reachable firstKnown secondKnown distinctIDs
      (by simpa [firstPayload, secondPayload] using ordered)
  obtain ⟨firstLedger, firstFound, firstObs, _⟩ := committed_snapshot reachable firstMember
  obtain ⟨secondLedger, secondFound, secondObs, secondEntry, secondAt, secondTx⟩ :=
    committed_snapshot reachable secondMember
  rw [firstFound] at secondFound
  cases secondFound
  rw [← firstPayload, ← secondPayload, firstObs, secondObs]
  exact strict_observations secondAt secondTx seqno

end consistency.Proofs.Ordered
