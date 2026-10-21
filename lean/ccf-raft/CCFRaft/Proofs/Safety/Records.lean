module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import CCFRaft.Proofs.Safety.Derived

@[expose] public section

set_option linter.unusedSectionVars false

/-!
# Consequences of the invariant clauses

Facts derived from invariant clauses holding at every suffix of a history:
leader logs of one term form a chain, logs agreeing on a term agree before it,
one vote per term, and committed parts are comparable.
-/

namespace CCFRaft.Proofs.Safety

open CCF
open Model.Node
open CCFRaft.Proofs.Ledger

variable [Config.InitialConfiguration]

/-! ## Clauses at every suffix -/

/-- `clause` holds at every nonempty suffix of `history`. -/
def Everywhere (clause : History -> Prop) (history : History) : Prop :=
  forall earlier, earlier <:+ history -> Not (earlier = []) -> clause earlier

section Everywhere

variable {clause : History -> Prop} {history : History}

theorem Everywhere.cons {current : Model.State}
    (old : Everywhere clause history) (now : clause (current :: history))
    : Everywhere clause (current :: history) := by
  intro earlier suffix nonempty
  rcases List.suffix_cons_iff.mp suffix with rfl | inner
  · exact now
  · exact old earlier inner nonempty

theorem Everywhere.suffix (all : Everywhere clause history) {earlier : History}
    (suffix : earlier <:+ history)
    : Everywhere clause earlier :=
  fun inner within nonempty => all inner (within.trans suffix) nonempty

theorem Everywhere.here {current : Model.State} {rest : History}
    (all : Everywhere clause (current :: rest))
    : clause (current :: rest) :=
  all _ (List.suffix_refl _) (List.cons_ne_nil _ _)

theorem Good.everywhere (good : Good history) (project : forall {h}, Inv h -> clause h)
    : Everywhere clause history :=
  fun earlier suffix nonempty => project (good earlier suffix nonempty)

end Everywhere

/-! ## States of an execution -/

section Exec

variable {nodes : List NodeID}

theorem Now.nonempty {history : History} {node : NodeID}
    {state : NodeState} (now : Now history node state)
    : exists current rest, history = current :: rest := by
  cases history with
  | nil => exact absurd now id
  | cons current rest => exact ⟨current, rest, rfl⟩

theorem now_unique {history : History} (exec : Exec nodes history) {node : NodeID}
    {first second : NodeState} (left : Now history node first)
    (right : Now history node second)
    : first = second := by
  obtain ⟨current, rest, rfl⟩ := left.nonempty
  exact state_unique (exec.keys List.mem_cons_self) left right

/-- A state seen in a history is the current state of one of its suffixes. -/
theorem Seen.now {history : History} {node : NodeID} {state : NodeState}
    (seen : Seen history node state)
    : exists earlier, earlier <:+ history /\ Now earlier node state := by
  obtain ⟨current, member, mem⟩ := seen
  obtain ⟨front, back, split⟩ := List.append_of_mem member
  exact ⟨current :: back, ⟨front, split.symm⟩, mem⟩

theorem Seen.frontier {history : History} (exec : Exec nodes history)
    {node : NodeID} {state : NodeState} (seen : Seen history node state)
    : Direct.CommitFrontier state := by
  obtain ⟨current, member, mem⟩ := seen
  obtain ⟨front, back, split⟩ := List.append_of_mem member
  have tail : Exec nodes (current :: back) := exec.suffix ⟨front, split.symm⟩ (by simp)
  exact Direct.commitFrontier_invariant.reachable tail.reachable node state mem

theorem Seen.commit_le {history : History} (exec : Exec nodes history)
    {node : NodeID} {state : NodeState} (seen : Seen history node state)
    : state.commitIndex <= state.log.length :=
  (seen.frontier exec).1

end Exec

/-! ## Terms and signatures -/

theorem termAt_mono {log : List Entry}
    (sorted : log.Pairwise fun first second => first.term <= second.term) {i j : Nat}
    (le : i <= j) (bound : j <= log.length)
    : termAt log i <= termAt log j := by
  rcases Nat.eq_zero_or_pos i with rfl | positive
  · rw [termAt_zero]
    exact Nat.zero_le _
  rw [termAt_eq positive (le.trans bound), termAt_eq (by omega) bound]
  rcases Nat.eq_or_lt_of_le le with rfl | lt
  · exact le_rfl
  · exact List.pairwise_iff_getElem.mp sorted _ _ _ _ (by omega)

theorem termAt_le_of_mem {log : List Entry} {bound : Nat}
    (terms : forall entry, entry ∈ log -> entry.term <= bound) (index : Nat)
    : termAt log index <= bound := by
  unfold termAt
  cases found : entryAt? log index with
  | none => exact Nat.zero_le _
  | some entry => exact terms entry (entryAt_mem found)

theorem signature_pos {log : List Entry} {index : Nat}
    (signature : isSignatureAt log index = true)
    : 0 < index := by
  rcases Nat.eq_zero_or_pos index with rfl | positive
  · simp [isSignatureAt, entryAt?] at signature
  · exact positive

theorem signature_bound {log : List Entry} {index : Nat}
    (signature : isSignatureAt log index = true)
    : index <= log.length := by
  obtain ⟨entry, found, _⟩ := isSignatureAtTrue signature
  exact entryAtSomeIndexBound found

/-- The winning prefix `log.take (maxCommittableIndex log)` contains every
prefix of `log` ending in a signature. -/
theorem prefix_committable {part log : List Entry} (sub : part <+: log)
    (signature : isSignatureAt part part.length = true)
    : part <+: log.take (maxCommittableIndex log) := by
  have le := signatureIndex_le_maxCommittableIndex (isSignatureAt_of_prefix sub signature)
  rw [List.prefix_iff_eq_take.mp sub]
  exact take_prefix_take log le

theorem take_signature {log : List Entry} {index : Nat}
    (signature : isSignatureAt log index = true)
    : isSignatureAt (log.take index) (log.take index).length = true := by
  rw [List.length_take, Nat.min_eq_left (signature_bound signature)]
  exact isSignatureAt_take_of_le le_rfl signature

/-! ## Leadership records -/

theorem Led.two_le {history : History} {node : NodeID} {term : Nat}
    (led : Led history node term)
    : 2 <= term := by
  rcases led with ⟨rfl, -⟩ | ⟨log, commit, after, before, rest, -, candidate, leader, -, -, -,
    -, -, -, -, -, -, three, -⟩
  · decide
  · omega

theorem Led.elected {history : History} {node : NodeID} {term : Nat}
    (led : Led history node term) (above : 2 < term)
    : exists log commit, Elected history node term log commit := by
  rcases led with ⟨rfl, -⟩ | elected
  · exact absurd above (by decide)
  · exact elected

/-- Logs of leaders of one term form a chain. -/
theorem canon_chain {history : History} (mono : Everywhere CanonMono history)
    {term : Nat} {first second : List Entry} (left : Canon history term first)
    (right : Canon history term second)
    : first <+: second \/ second <+: first := by
  obtain ⟨early, earlySuffix, earlyNode, earlyState,
    ⟨earlyNow, earlyTerm, earlyRole, earlyLed⟩, rfl⟩ := left
  obtain ⟨late, lateSuffix, lateNode, lateState,
    ⟨lateNow, lateTerm, lateRole, lateLed⟩, rfl⟩ := right
  have contains : forall {inner outer : History} {innerNode outerNode : NodeID}
      {innerState outerState : NodeState},
      inner <:+ outer -> outer <:+ history
      -> Now inner innerNode innerState -> innerState.currentTerm = term
      -> Not (innerState.role = .candidate) -> Led inner innerNode term
      -> Now outer outerNode outerState -> outerState.currentTerm = term
      -> Not (outerState.role = .candidate) -> Led outer outerNode term
      -> innerState.log <+: outerState.log := by
    intro inner outer innerNode outerNode innerState outerState within outerSuffix
      innerNow innerTerm innerRole innerLed outerNow outerTerm outerRole outerLed
    obtain ⟨current, rest, rfl⟩ := outerNow.nonempty
    have clause := mono _ outerSuffix (List.cons_ne_nil _ _)
    refine (clause outerNode outerState outerNow outerRole (outerTerm ▸ outerLed)).1 _ ?_
    rw [outerTerm]
    exact ⟨inner, within, innerNode, innerState, ⟨innerNow, innerTerm, innerRole, innerLed⟩,
      rfl⟩
  rcases suffix_comparable earlySuffix lateSuffix with within | within
  · exact Or.inl (contains within lateSuffix earlyNow earlyTerm earlyRole earlyLed lateNow
      lateTerm lateRole lateLed)
  · exact Or.inr (contains within earlySuffix lateNow lateTerm lateRole lateLed earlyNow
      earlyTerm earlyRole earlyLed)

/-- Two seen logs agreeing on the term at `index` agree up to `index`. -/
theorem log_matching {history : History} (anchor : Everywhere Anchor history)
    (mono : Everywhere CanonMono history) {node other : NodeID}
    {first second : NodeState} (left : Seen history node first)
    (right : Seen history other second) {index : Nat} (positive : 0 < index)
    (leftBound : index <= first.log.length) (rightBound : index <= second.log.length)
    (same : termAt first.log index = termAt second.log index)
    : first.log.take index = second.log.take index := by
  obtain ⟨leftHistory, leftSuffix, leftNow⟩ := left.now
  obtain ⟨rightHistory, rightSuffix, rightNow⟩ := right.now
  obtain ⟨_, _, rfl⟩ := leftNow.nonempty
  obtain ⟨_, _, rfl⟩ := rightNow.nonempty
  obtain ⟨leftLog, leftCanon, leftLength, leftTake⟩ :=
    anchor _ leftSuffix (List.cons_ne_nil _ _) node first index leftNow positive leftBound
  obtain ⟨rightLog, rightCanon, rightLength, rightTake⟩ :=
    anchor _ rightSuffix (List.cons_ne_nil _ _) other second index rightNow positive
      rightBound
  rw [same] at leftCanon
  rw [leftTake, rightTake]
  exact take_eq_take_of_comparable
    (canon_chain mono (leftCanon.mono leftSuffix) (rightCanon.mono rightSuffix))
    leftLength rightLength

/-! ## Votes -/

/-- A voter grants at most one candidate per term. -/
theorem vote_unique {nodes : List NodeID} {history : History}
    (exec : Exec nodes history) (record : Everywhere VoteRecord history)
    {voter first second : NodeID} {term : Nat}
    {firstRequest secondRequest : RequestVoteRequest}
    (left : Granted history voter first term firstRequest)
    (right : Granted history voter second term secondRequest)
    : first = second := by
  have ordered : forall {early late : NodeID} {earlyRequest lateRequest : RequestVoteRequest},
      Granted history voter early term earlyRequest
      -> Granted history voter late term lateRequest
      -> (forall a b r a' b' r', a :: b :: r <:+ history -> a' :: b' :: r' <:+ history
          -> GrantStep a b voter early term earlyRequest
          -> GrantStep a' b' voter late term lateRequest
          -> a :: b :: r <:+ a' :: b' :: r' -> early = late) := by
    intro early late _ _ _ _ a b r a' b' r' suffix suffix' step step' within
    obtain ⟨granting, granted, grantingMem, grantedMem, _, grantedTerm, grantedVote, _⟩ := step
    obtain ⟨granting', granted', grantingMem', grantedMem', grantingTerm', grantedTerm',
      grantedVote', _⟩ := step'
    rcases List.suffix_cons_iff.mp within with same | inner
    · cases same
      have := state_unique (exec.keys (suffix'.subset List.mem_cons_self)) grantedMem
        grantedMem'
      subst this
      rw [grantedVote] at grantedVote'
      exact Option.some.inj grantedVote'
    · have tail : b' :: r' <:+ history := (List.suffix_cons _ _).trans suffix'
      have seen : Seen (b' :: r') voter granted := ⟨a, inner.subset List.mem_cons_self, grantedMem⟩
      rcases record _ tail (List.cons_ne_nil _ _) voter granting' granted early grantingMem'
          seen grantedVote with lt | ⟨termEq, keep⟩
      · omega
      · have seen' : Seen (a' :: b' :: r') voter granting' :=
          ⟨b', List.mem_cons_of_mem _ List.mem_cons_self, grantingMem'⟩
        rcases record _ suffix' (List.cons_ne_nil _ _) voter granted' granting' early grantedMem'
            seen' keep with lt | ⟨_, final⟩
        · omega
        · rw [final] at grantedVote'
          exact Option.some.inj grantedVote'
  obtain ⟨a, b, r, suffix, step⟩ := left
  obtain ⟨a', b', r', suffix', step'⟩ := right
  rcases suffix_comparable suffix suffix' with within | within
  · exact ordered ⟨a, b, r, suffix, step⟩ ⟨a', b', r', suffix', step'⟩ a b r a' b' r' suffix
      suffix' step step' within
  · exact (ordered ⟨a', b', r', suffix', step'⟩ ⟨a, b, r, suffix, step⟩ a' b' r' a b r suffix'
      suffix step' step within).symm

/-! ## Committed parts -/

/-- The commit step behind a committed part, with its backing. -/
theorem Committed.shape {history : History} {term : Nat}
    {part : List Entry} (committed : Committed history term part)
    : exists current rest leader state base index,
        current :: rest <:+ history
        /\ CommitStep (current :: rest) leader state term base index
        /\ part = state.log.take index
        /\ (base = 0
            \/ exists earlier part',
                Committed rest earlier part'
                /\ earlier <= term
                /\ state.log.take base <+: part') := by
  induction committed with
  | fresh step => exact ⟨_, _, _, _, _, _, List.suffix_refl _, step, rfl, Or.inl rfl⟩
  | chained step backing le within =>
      exact ⟨_, _, _, _, _, _, List.suffix_refl _, step, rfl,
        Or.inr ⟨_, _, backing, le, within⟩⟩
  | past _ ih =>
      obtain ⟨current, rest, leader, state, base, index, suffix, step, eq, backing⟩ := ih
      exact ⟨current, rest, leader, state, base, index, suffix.trans (List.suffix_cons _ _),
        step, eq, backing⟩

theorem Committed.signature {history : History} {term : Nat}
    {part : List Entry} (committed : Committed history term part)
    : isSignatureAt part part.length = true
      /\ termAt part part.length = term
      /\ 2 <= term := by
  obtain ⟨_, _, _, state, _, index, _, ⟨⟨_, _, _, led⟩, _, _, signature, termEq, _⟩, rfl,
    _⟩ := committed.shape
  refine ⟨take_signature signature, ?_, led.two_le⟩
  rw [List.length_take, Nat.min_eq_left (signature_bound signature),
    termAt_take le_rfl, termEq]

/-- A part committed in a term is in every later leader log. -/
theorem committed_in_canon {history : History} (complete : Completeness history)
    (mono : Everywhere CanonMono history) {term later : Nat}
    {part log : List Entry} (committed : Committed history term part)
    (canon : Canon history later log) (lt : term < later)
    : part <+: log := by
  obtain ⟨earlier, suffix, node, state, ⟨now, termEq, role, led⟩, rfl⟩ := canon
  obtain ⟨signature, _, two⟩ := committed.signature
  obtain ⟨elected, commit, election⟩ := led.elected (by omega)
  have inLog := complete term part node later elected commit committed
    (election.mono suffix) lt
  obtain ⟨_, _, rfl⟩ := now.nonempty
  have clause := mono _ suffix (List.cons_ne_nil _ _)
  exact (prefix_committable inLog signature).trans
    ((clause node state now role (termEq ▸ led)).2 elected commit (termEq ▸ election))

/-- Committed parts are comparable. -/
theorem committed_comparable {history : History}
    (complete : Completeness history) (mono : Everywhere CanonMono history)
    {first second : Nat} {left right : List Entry}
    (leftCommitted : Committed history first left)
    (rightCommitted : Committed history second right)
    : left <+: right \/ right <+: left := by
  have inCanon : forall {term term' : Nat} {part part' : List Entry},
      Committed history term part -> Committed history term' part' -> term <= term'
      -> part <+: part' \/ part' <+: part := by
    intro term term' part part' committed committed' le
    obtain ⟨current, rest, leader, state, _, index, suffix, ⟨⟨now, termEq, role, led⟩, _⟩,
      rfl, _⟩ := committed'.shape
    have canon' : Canon history term' state.log :=
      ⟨_, suffix, leader, state, ⟨now, termEq, role, led⟩, rfl⟩
    rcases Nat.eq_or_lt_of_le le with rfl | lt
    · obtain ⟨current₀, rest₀, leader₀, state₀, _, index₀, suffix₀,
        ⟨⟨now₀, termEq₀, role₀, led₀⟩, _⟩, rfl, _⟩ := committed.shape
      have canon : Canon history term state₀.log :=
        ⟨_, suffix₀, leader₀, state₀, ⟨now₀, termEq₀, role₀, led₀⟩, rfl⟩
      rcases canon_chain mono canon canon' with sub | sub
      · exact comparable_of_prefix ((List.take_prefix _ _).trans sub) (List.take_prefix _ _)
      · exact comparable_of_prefix (List.take_prefix _ _) ((List.take_prefix _ _).trans sub)
    · exact comparable_of_prefix (committed_in_canon complete mono committed canon' lt)
        (List.take_prefix _ _)
  rcases le_total first second with le | le
  · exact inCanon leftCommitted rightCommitted le
  · exact (inCanon rightCommitted leftCommitted le).symm

end CCFRaft.Proofs.Safety
