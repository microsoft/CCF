module

public import Consensus.Model.Node
public import Mathlib.Order.Prod.Lex.Basic
public import Mathlib.Tactic.CongrExclamation

@[expose] public section

/-!
`rankBelow` is the lexicographic order that `findSuccessor` used through
Mathlib's `toLex` before the Mathlib dependency was removed.
-/

namespace MathlibEquivalence.Rank

open Consensus.Model.Node

theorem rankBelow_eq (a b : Nat × Nat × Nat)
    : rankBelow a b = decide (toLex (a.1, toLex a.2) < toLex (b.1, toLex b.2)) := by
  rw [rankBelow, Bool.eq_iff_iff, decide_eq_true_iff]
  simp [Prod.lexLt, Prod.Lex.toLex_lt_toLex]

/-- `findSuccessor` as it was defined with Mathlib's `toLex`. -/
def findSuccessorLex (state : NodeState) (self : NodeID) : Option NodeID :=
  let configurations := state.activeConfigurations
  let rank node :=
    toLex (state.matchIndex node, toLex (latestMembershipIndex configurations node, node))
  let peers := (eligiblePeers state self).sort
  peers.foldl
    (fun best candidate =>
      match best with
      | none => some candidate
      | some selected =>
          if rank selected < rank candidate then
            some candidate
          else
            best)
    none

theorem findSuccessor_eq_lex (state : NodeState) (self : NodeID)
    : findSuccessor state self = findSuccessorLex state self := by
  simp only [findSuccessor, findSuccessorLex, rankBelow_eq, decide_eq_true_eq]
  congr!

end MathlibEquivalence.Rank
