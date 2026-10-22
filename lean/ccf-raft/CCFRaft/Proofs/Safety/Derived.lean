module

public import CCFRaft.Proofs.Safety.Defs

@[expose] public section

set_option linter.unusedSectionVars false

/-!
# Basic facts about history records

Every record is monotone in the history: a record of a suffix is a record of
the whole history.
-/

namespace CCFRaft.Proofs.Safety

open CCF
open Model.Node

variable [Config.InitialConfiguration]

section Mono

variable {history later : History}

theorem Seen.mono (suffix : history <:+ later) {node : NodeID} {state : NodeState}
    (seen : Seen history node state)
    : Seen later node state := by
  obtain ⟨current, member, mem⟩ := seen
  exact ⟨current, suffix.subset member, mem⟩

theorem Granted.mono (suffix : history <:+ later) {voter candidate : NodeID} {term : Nat}
    {request : RequestVoteRequest}
    (granted : Granted history voter candidate term request)
    : Granted later voter candidate term request := by
  obtain ⟨after, before, rest, inner, step⟩ := granted
  exact ⟨after, before, rest, inner.trans suffix, step⟩

theorem Elected.mono (suffix : history <:+ later) {node : NodeID} {term commit : Nat}
    {log : List Entry} (elected : Elected history node term log commit)
    : Elected later node term log commit := by
  obtain ⟨after, before, rest, inner, step⟩ := elected
  exact ⟨after, before, rest, inner.trans suffix, step⟩

theorem Led.mono (suffix : history <:+ later) {node : NodeID} {term : Nat}
    (led : Led history node term)
    : Led later node term := by
  rcases led with bootstrap | ⟨log, commit, elected⟩
  · exact Or.inl bootstrap
  · exact Or.inr ⟨log, commit, elected.mono suffix⟩

theorem Canon.mono (suffix : history <:+ later) {term : Nat}
    {log : List Entry} (canon : Canon history term log)
    : Canon later term log := by
  obtain ⟨earlier, inner, rest⟩ := canon
  exact ⟨earlier, inner.trans suffix, rest⟩

theorem Committed.append {term : Nat} {part : List Entry}
    (committed : Committed history term part) (front : History)
    : Committed (front ++ history) term part := by
  induction front with
  | nil => exact committed
  | cons _ _ ih => exact .past ih

theorem Committed.mono (suffix : history <:+ later) {term : Nat}
    {part : List Entry} (committed : Committed history term part)
    : Committed later term part := by
  obtain ⟨front, rfl⟩ := suffix
  exact committed.append front

theorem Backed.mono (suffix : history <:+ later) {log : List Entry}
    {commit term : Nat} (backed : Backed history log commit term)
    : Backed later log commit term := by
  rcases backed with zero | ⟨earlier, part, committed, le, within⟩
  · exact Or.inl zero
  · exact Or.inr ⟨earlier, part, committed.mono suffix, le, within⟩

theorem Backed.weaken {log : List Entry} {commit term term' : Nat}
    (backed : Backed history log commit term) (le : term <= term')
    : Backed history log commit term' := by
  rcases backed with zero | ⟨earlier, part, committed, le', within⟩
  · exact Or.inl zero
  · exact Or.inr ⟨earlier, part, committed, by omega, within⟩

theorem Acked.mono (suffix : history <:+ later) {voter : NodeID} {term index : Nat}
    (acked : Acked history voter term index)
    : Acked later voter term index := by
  obtain ⟨acker, log, seen, termEq, canon, bound, sub⟩ := acked
  exact ⟨acker, log, seen.mono suffix, termEq, canon.mono suffix, bound, sub⟩

theorem Bad.mono (suffix : history <:+ later) {part : List Entry}
    {term bound : Nat} (bad : Bad history part term bound)
    : Bad later part term bound := by
  obtain ⟨term', log, lt, le, canon, missing⟩ := bad
  exact ⟨term', log, lt, le, canon.mono suffix, missing⟩

end Mono

theorem Now.seen {history : History} {node : NodeID} {state : NodeState}
    (now : Now history node state)
    : Seen history node state := by
  cases history with
  | nil => exact absurd now id
  | cons current rest => exact ⟨current, List.mem_cons_self, now⟩

theorem Seen.cons {current : Model.State} {rest : History}
    {node : NodeID} {state : NodeState} (seen : Seen (current :: rest) node state)
    : (node, state) ∈ current.nodes \/ Seen rest node state := by
  obtain ⟨state', member, mem⟩ := seen
  rcases List.mem_cons.mp member with rfl | inner
  · exact Or.inl mem
  · exact Or.inr ⟨state', inner, mem⟩

/-- Two suffixes of one list are comparable. -/
theorem suffix_comparable {α : Type} {first second whole : List α}
    (left : first <:+ whole) (right : second <:+ whole)
    : first <:+ second \/ second <:+ first := by
  rcases le_total first.length second.length with le | le
  · exact Or.inl (List.suffix_of_suffix_length_le left right le)
  · exact Or.inr (List.suffix_of_suffix_length_le right left le)

end CCFRaft.Proofs.Safety
