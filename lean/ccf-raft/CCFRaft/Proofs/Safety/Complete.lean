module

public import CCFRaft.Proofs.Safety.Core

@[expose] public section

set_option linter.unusedSectionVars false

/-!
# Elections and committed parts after one step

Election safety, leader-log monotonicity, log anchoring and completeness for
the extended history.
-/

namespace CCFRaft.Proofs.Safety

open CCF
open Model.Node
open CCFRaft.Proofs.Ledger
open CCFRaft.Proofs.Config
open Model (BOOTSTRAP_TERM)

variable [Config.InitialConfiguration]

/--
Either the committed part is already in `log`, or the two logs agree on a
prefix covering both commit indices, as quorum intersection needs.
-/
theorem agree_or_contained {α : Type} {state log : List α} {base index commit : Nat}
    (baseLe : base <= index) (indexLe : index <= state.length)
    (frontier : commit <= log.length) (low : commit <= base -> state.take base <+: log)
    (high
      : base < commit
        -> exists part,
            log.take commit <+: part
            /\ (state.take index <+: part \/ part <+: state.take index))
    : state.take index <+: log
      \/ exists k, state.take k = log.take k /\ base <= k /\ commit <= k := by
  rcases le_or_gt commit base with le | lt
  · exact Or.inr ⟨base, take_of_prefix_length (low le) (by simp; omega), le_rfl, le⟩
  · obtain ⟨part, inPart, comparable⟩ := high lt
    have commitLength : (log.take commit).length = commit := by simp; omega
    have partLong : commit <= part.length := commitLength ▸ inPart.length_le
    have indexLength : (state.take index).length = index := by simp; omega
    rcases le_or_gt commit index with le | short
    · refine Or.inr ⟨commit, ?_, lt.le, le_rfl⟩
      calc
        state.take commit = (state.take index).take commit := by
          rw [List.take_take, Nat.min_eq_left le]
        _ = part.take commit := take_eq_take_of_comparable comparable (by omega) partLong
        _ = log.take commit := by
          rw [take_eq_of_prefix inPart (by omega), List.take_take, Nat.min_self]
    · left
      have sub : state.take index <+: part := by
        rcases comparable with sub | sub
        · exact sub
        · have := sub.length_le
          omega
      have : state.take index <+: log.take commit := by
        rcases List.prefix_or_prefix_of_prefix sub inPart with inner | outer
        · exact inner
        · have := outer.length_le
          omega
      exact this.trans (List.take_prefix _ _)

theorem termAt_append_right {front back : List Entry} {index : Nat}
    (above : front.length < index) (bound : index <= (front ++ back).length)
    : exists entry, entry ∈ back /\ termAt (front ++ back) index = entry.term := by
  rw [termAt_eq (by omega) bound, List.getElem_append_right (by omega)]
  exact ⟨_, List.getElem_mem _, rfl⟩

namespace Ctx

variable {nodes : List NodeID} {after before : Model.State}
  {rest : History} (c : Ctx nodes after before rest)

include c

theorem termMonos : Everywhere TermMono (after :: before :: rest) :=
  (c.all Inv.term_mono).cons c.term_mono

theorem sortedAll : Everywhere Sorted (after :: before :: rest) :=
  (c.all Inv.sorted).cons c.sorted

theorem rootedAll : Everywhere RootedLogs (after :: before :: rest) :=
  (c.all Inv.rooted).cons c.rooted

theorem votes : Everywhere VoteRecord (after :: before :: rest) :=
  (c.all Inv.vote_record).cons c.vote_record

/-! ## Parts committed before the step -/

theorem old_step_in_new {node : NodeID} {later commit : Nat} {log : List Entry}
    (elect : ElectStep after before rest node later log commit)
    {current : Model.State} {past : History}
    (suffix : current :: past <:+ before :: rest) {leader : NodeID}
    {state : NodeState} {term base index : Nat}
    (step : CommitStep (current :: past) leader state term base index)
    (committed : Committed (current :: past) term (state.log.take index))
    (lt : term < later) (low : commit <= base -> state.log.take base <+: log)
    : state.log.take index <+: log := by
  have ⟨_, _, _, _, _, _, frontier, _⟩ := elect
  have committedH := committed.mono suffix
  have high : base < commit
      -> exists part,
          log.take commit <+: part
          /\ (state.log.take index <+: part \/ part <+: state.log.take index) := by
    intro above
    rcases c.elect_backed after before rest node later log commit (List.suffix_refl _) elect with
      zero | ⟨_, part, committedE, _, inPart⟩
    · omega
    · exact ⟨part, inPart, committed_comparable c.inv.completeness c.monos committedH committedE⟩
  rcases agree_or_contained step.2.1 step.2.2.1 frontier low high with
    done | ⟨k, agree, baseLe, commitLe⟩
  · exact done
  · exact core c.suffix_tail c.termMonos c.monos (c.all Inv.sorted) (c.all Inv.rooted) suffix
      step
      (List.suffix_refl _) (List.suffix_refl _) elect (c.all Inv.persist) c.anchors
      (c.all Inv.terms) lt agree baseLe commitLe
      fun _ _ above _ canon => committed_in_canon c.inv.completeness c.monos committedH canon above

/-- A part committed before the step is in the log of a new election. -/
theorem old_in_new {node : NodeID} {later commit : Nat} {log : List Entry}
    (elect : ElectStep after before rest node later log commit)
    {history : History} {term : Nat} {part : List Entry}
    (committed : Committed history term part) (suffix : history <:+ before :: rest)
    (lt : term < later)
    : part <+: log := by
  induction committed with
  | fresh step =>
      exact c.old_step_in_new elect suffix step (Committed.fresh step) lt
        fun _ => by rw [List.take_zero]; exact List.nil_prefix
  | chained step backing le within ih =>
      exact c.old_step_in_new elect suffix step (Committed.chained step backing le within)
        lt fun _ => within.trans (ih ((List.suffix_cons _ _).trans suffix) (by omega))
  | past _ ih => exact ih ((List.suffix_cons _ _).trans suffix) lt

/-- A part committed before the step is in every later elected log. -/
theorem old_complete {term later commit : Nat} {node : NodeID}
    {part log : List Entry} (committed : Committed (before :: rest) term part)
    (elected : Elected (after :: before :: rest) node later log commit)
    (lt : term < later)
    : part <+: log := by
  rcases c.elected_after elected with old | step
  · exact c.inv.completeness term part node later log commit committed old lt
  · exact c.old_in_new step committed (List.suffix_refl _) lt

/-! ## Election safety -/

theorem new_old_unique {node other : NodeID} {term commit : Nat}
    {log : List Entry}
    (elect : ElectStep after before rest node term log commit)
    (led : Led (before :: rest) other term)
    : node = other := by
  have ⟨candidate, _, candidateMem, _, candidateLog, _, frontier, _, _, _, _, three, voters,
    quorum, granted⟩ := elect
  rcases led with ⟨rfl, _⟩ | ⟨log', commit', a, b, r, suffix, elect'⟩
  · simp [BOOTSTRAP_TERM] at three
  have ⟨candidate', _, candidateMem', _, candidateLog', _, frontier', _, _, _, _, _, voters',
    quorum', granted'⟩ := elect'
  have agreement : exists k, log.take k = log'.take k /\ commit <= k /\ commit' <= k := by
    rcases Nat.le_total commit' commit with le | le
    · refine ⟨commit, ?_, le_rfl, le⟩
      rcases c.elect_backed after before rest node term log commit (List.suffix_refl _) elect with
        zero | ⟨_, part, committed, below, inPart⟩
      · rw [zero, List.take_zero, List.take_zero]
      · have := c.inv.completeness _ part other term log' commit' committed
          ⟨a, b, r, suffix, elect'⟩ (by omega)
        exact take_of_prefix_length (inPart.trans this) (by simp; omega)
    · refine ⟨commit', ?_, le, le_rfl⟩
      rcases c.inv.elect_backed a b r other term log' commit' suffix elect' with
        zero | ⟨_, part, committed, below, inPart⟩
      · rw [zero, List.take_zero, List.take_zero]
      · have := c.old_in_new elect committed ((List.suffix_cons _ _).trans suffix) (by omega)
        exact (take_of_prefix_length (inPart.trans this) (by simp; omega)).symm
  obtain ⟨k, agree, le, le'⟩ := agreement
  obtain ⟨voter, mem, mem'⟩ := quorums_intersect GENESIS_configured
    (candidateLog ▸ c.inv.rooted node candidate candidateMem)
    (candidateLog' ▸ c.all Inv.rooted _ ((List.suffix_cons _ _).trans suffix)
      (List.cons_ne_nil _ _) other candidate' candidateMem')
    agree le le' quorum quorum'
  exact vote_unique c.exec c.votes (granted voter mem)
    ((granted' voter mem').mono (suffix.trans c.suffix_tail))

theorem election_safety : ElectionSafety (after :: before :: rest) := by
  intro node other term left right
  rcases c.led_after left with left | ⟨_, _, leftStep⟩ <;>
    rcases c.led_after right with right | ⟨_, _, rightStep⟩
  · exact c.inv.election_safety node other term left right
  · exact (c.new_old_unique rightStep left).symm
  · exact c.new_old_unique leftStep right
  · exact (c.electStep leftStep).1.trans (c.electStep rightStep).1.symm

/-! ## Leader logs -/

/-- A leader continuing in its term keeps its log. -/
theorem keep_log (sameTerm : c.post.currentTerm = c.pre.currentTerm)
    (role : Not (c.pre.role = .candidate))
    (led : Led (before :: rest) c.actor c.pre.currentTerm)
    : c.pre.log <+: c.post.log := by
  cases Summary.kind c.sum with
  | same log _ => rw [log]
  | append _ _ _ _ _ advance =>
      rw [(Advance.facts advance).1]
      exact List.prefix_append _ _
  | ack _ _ _ _ _ _ advance => rw [(Advance.facts advance).1]
  | accept source request eq accepted =>
      exfalso
      obtain ⟨earlier, _, suffix, canon, aeok, _⟩ := c.accept_shape eq accepted
      have : source = c.actor :=
        c.inv.election_safety source c.actor request.term (canon.2.2.2.mono suffix)
          (by rw [accepted.1, sameTerm]; exact led)
      exact aeok.1 this.symm
  | elect wins =>
      have ⟨_, _, _, termCase, termEq, _⟩ := c.electStep (c.wins_elect wins)
      rcases termCase with lt | ⟨_, candidate⟩
      · omega
      · exact (role candidate).elim

/-- Every leader log is nonempty: an elected log holds its quorum's configuration. -/
theorem leader_logs : LeaderLogs (after :: before :: rest) := by
  intro node state now role
  rcases c.now_after now with ⟨rfl, rfl⟩ | ⟨_, old⟩
  · rcases Summary.leader c.sum role with ⟨preRole, termEq⟩ | wins
    · have keep := c.keep_log termEq (by rw [preRole]; simp)
        (c.inv.leader_led c.actor c.pre c.pre_now preRole)
      have nonempty := c.inv.leader_logs c.actor c.pre c.pre_now preRole
      intro empty
      rw [empty] at keep
      exact nonempty (List.prefix_nil.mp keep)
    · obtain ⟨candidate, campaign, quorum, logEq, _⟩ := Wins.facts wins
      have ⟨_, candidateLog, _, _⟩ := campaign
      have nonempty := hasQuorum_nonempty quorum
      rw [logEq]
      simp only [primaryState, lastCommittableIndex]
      split
      · rw [candidateLog]
        simp only [ne_eq, List.take_eq_nil_iff, not_or]
        exact ⟨by omega, nonempty⟩
      · rwa [candidateLog]
  · exact c.inv.leader_logs node state old role

/-- An earlier leadership of the actor in its new term continues. -/
theorem old_led_actor (led : Led (before :: rest) c.actor c.post.currentTerm)
    : c.pre.currentTerm = c.post.currentTerm /\ Not (c.pre.role = .candidate) := by
  have le := c.term_le
  rcases c.inv.led_cur c.actor c.pre _ c.pre_now led with lt | ⟨eq, role⟩
  · omega
  · exact ⟨eq.symm, role⟩

theorem canon_mono : CanonMono (after :: before :: rest) := by
  have safety := c.election_safety
  intro node state now role led
  -- A leader log of the term recorded at the head is this state's log.
  have current : forall node' state', CanonNow (after :: before :: rest) node' state'
      state.currentTerm -> state'.log <+: state.log := by
    intro node' state' ⟨now', _, _, led'⟩
    have := safety node' node _ led' led
    subst this
    rw [now_unique c.exec now' now]
  rcases c.now_after now with ⟨rfl, rfl⟩ | ⟨different, old⟩
  · have fromOld : Led (before :: rest) c.actor c.post.currentTerm
        -> c.pre.log <+: c.post.log /\ CanonMono (before :: rest)
            /\ c.pre.currentTerm = c.post.currentTerm
            /\ Not (c.pre.role = .candidate) := by
      intro oldLed
      obtain ⟨eq, preRole⟩ := c.old_led_actor oldLed
      exact ⟨c.keep_log eq.symm preRole (eq ▸ oldLed), c.inv.canon_mono, eq, preRole⟩
    refine ⟨fun log canon => ?_, fun log commit elected => ?_⟩
    · rcases c.canon_after canon with canon | ⟨node', state', canonNow, rfl⟩
      · have oldLed : Led (before :: rest) c.actor c.post.currentTerm := by
          obtain ⟨earlier, suffix, node', state', ⟨_, _, _, led'⟩, _⟩ := canon
          have := safety node' c.actor _ ((led'.mono suffix).mono c.suffix_tail) led
          subst this
          exact led'.mono suffix
        obtain ⟨keep, mono, eq, preRole⟩ := fromOld oldLed
        rw [← eq] at canon oldLed
        exact ((mono c.actor c.pre c.pre_now preRole oldLed).1 _ canon).trans keep
      · exact current node' state' canonNow
    · rcases c.elected_after elected with old | step
      · obtain ⟨keep, mono, eq, preRole⟩ := fromOld (Or.inr ⟨log, commit, old⟩)
        rw [← eq] at old
        exact ((mono c.actor c.pre c.pre_now preRole (Or.inr ⟨log, commit, old⟩)).2 log commit
          old).trans keep
      · exact (c.electStep step).2.2.2.2.2.2.1
  · have oldLed := c.led_other different led
    refine ⟨fun log canon => ?_, fun log commit elected => ?_⟩
    · rcases c.canon_after canon with canon | ⟨node', state', canonNow, rfl⟩
      · exact (c.inv.canon_mono node state old role oldLed).1 log canon
      · exact current node' state' canonNow
    · rcases c.elected_after elected with old' | step
      · exact (c.inv.canon_mono node state old role oldLed).2 log commit old'
      · exact absurd (c.electStep step).1 different

theorem canonMonos : Everywhere CanonMono (after :: before :: rest) :=
  c.monos.cons c.canon_mono

/-! ## Log anchors -/

theorem anchor : Anchor (after :: before :: rest) := by
  intro node state index now positive bound
  rcases c.now_after now with ⟨rfl, rfl⟩ | ⟨_, old⟩
  · have viaPre : c.pre.log <+: c.post.log \/ c.post.log <+: c.pre.log
        -> index <= c.pre.log.length
        -> exists log,
            Canon (after :: before :: rest) (termAt c.post.log index) log
            /\ index <= log.length
            /\ c.post.log.take index = log.take index := by
      intro comparable within
      obtain ⟨log, canon, length, take⟩ :=
        c.inv.anchor c.actor c.pre index c.pre_now positive within
      have same := take_eq_take_of_comparable comparable within bound
      have termSame : termAt c.post.log index = termAt c.pre.log index := by
        rw [← termAt_take (n := index) le_rfl, ← same, termAt_take le_rfl]
      rw [termSame, ← same]
      exact ⟨log, canon.mono c.suffix_tail, length, take⟩
    rcases c.post_log with sub | ⟨entries, log, terms, leader, term, notCandidate⟩
        | ⟨earlier, source, sender, n, suffix, canon, _, log⟩
    · exact viaPre (Or.inr sub) (bound.trans sub.length_le)
    · rcases le_or_gt index c.pre.log.length with within | above
      · exact viaPre (Or.inl (log ▸ List.prefix_append _ _)) within
      · have termEq : termAt c.post.log index = c.post.currentTerm := by
          rw [log] at bound ⊢
          obtain ⟨entry, mem, eq⟩ := termAt_append_right above bound
          rw [eq, terms entry mem, term]
        refine ⟨c.post.log, ?_, bound, rfl⟩
        rw [termEq]
        refine ⟨after :: before :: rest, List.suffix_refl _, c.actor, c.post,
          ⟨c.post_now, rfl, notCandidate, ?_⟩, rfl⟩
        rw [term]
        exact (c.inv.leader_led c.actor c.pre c.pre_now leader).mono c.suffix_tail
    · rw [log] at bound ⊢
      have short : index <= n := by
        have := bound
        simp at this
        omega
      obtain ⟨_, _, rfl⟩ := canon.1.nonempty
      obtain ⟨anchored, anchoredCanon, length, take⟩ :=
        c.anchors _ suffix (List.cons_ne_nil _ _) source sender index canon.1 positive
          (bound.trans (by simp))
      refine ⟨anchored, ?_, length, ?_⟩
      · rw [termAt_take short]
        exact anchoredCanon.mono (suffix.trans c.suffix_tail)
      · rw [List.take_take, Nat.min_eq_left short, take]
  · obtain ⟨log, canon, length, take⟩ := c.inv.anchor node state index old positive bound
    exact ⟨log, canon.mono c.suffix_tail, length, take⟩

/-! ## Parts committed at the step -/

/-- A part committed at the step is in every later elected log. -/
theorem new_in_elected {leader : NodeID} {state : NodeState}
    {term base index : Nat}
    (step : CommitStep (after :: before :: rest) leader state term base index)
    (backing
      : base = 0
        \/ exists earlier part,
            Committed (before :: rest) earlier part
            /\ earlier <= term
            /\ state.log.take base <+: part)
    : forall later node log commit,
        Elected (after :: before :: rest) node later log commit
        -> term < later
        -> state.log.take index <+: log := by
  have safety := c.election_safety
  have canonMonos := c.canonMonos
  obtain ⟨⟨leaderNow, rfl, leaderRole, leaderLed⟩, baseLe, indexLe, signature, _⟩ := step
  have partSignature := take_signature signature
  have two : 2 <= state.currentTerm := leaderLed.two_le
  intro later
  induction later using Nat.strong_induction_on with
  | _ later ih =>
      intro node log commit elected lt
      obtain ⟨a, b, r, electSuffix, elect⟩ := elected
      have ⟨candidate, _, candidateMem, _, _, _, frontier, termCase, _⟩ := elect
      have electInner : b :: r <:+ after :: before :: rest :=
        (List.suffix_cons _ _).trans electSuffix
      have innerH : b :: r <:+ before :: rest := suffix_of_cons_suffix electSuffix
      -- Every leader log of a term in `(term, later]` before the election holds the part.
      have clean
          : forall later' log',
              state.currentTerm < later'
              -> later' <= later
              -> Canon (b :: r) later' log'
              -> state.log.take index <+: log' := by
        intro later' log' above below canon
        obtain ⟨earlier, earlierSuffix, node', state', ⟨now', term', role', led'⟩, rfl⟩ :=
          canon
        rcases Nat.lt_or_eq_of_le below with lower | rfl
        · obtain ⟨log'', commit'', elected''⟩ := led'.elected (by omega)
          have inLog := ih later' lower node' log'' commit''
            ((elected''.mono earlierSuffix).mono electInner) above
          obtain ⟨_, _, rfl⟩ := now'.nonempty
          have clause := c.monos _ (earlierSuffix.trans innerH) (List.cons_ne_nil _ _)
          exact (prefix_committable inLog partSignature).trans
            ((clause node' state' now' role' (term' ▸ led')).2 log'' commit'' (term' ▸ elected''))
        · exfalso
          have ledInner : Led (b :: r) node' later' := led'.mono earlierSuffix
          have := safety node' node later' (ledInner.mono electInner)
            (Or.inr ⟨log, commit, a, b, r, electSuffix, elect⟩)
          subst this
          rcases c.all Inv.led_cur _ innerH (List.cons_ne_nil _ _) node' candidate later'
              candidateMem ledInner with lt' | ⟨eq, notCandidate⟩
          · rcases termCase with lt'' | ⟨_, _⟩ <;> omega
          · rcases termCase with lt'' | ⟨_, isCandidate⟩
            · omega
            · exact notCandidate isCandidate
      have low : commit <= base -> state.log.take base <+: log := by
        intro _
        rcases backing with zero | ⟨_, part, committed, below, inPart⟩
        · rw [zero, List.take_zero]
          exact List.nil_prefix
        · exact inPart.trans (c.old_complete committed
            ⟨a, b, r, electSuffix, elect⟩ (by omega))
      have high
          : base < commit
            -> exists part,
                log.take commit <+: part
                /\ (state.log.take index <+: part \/ part <+: state.log.take index) := by
        intro above
        rcases c.elect_backed a b r node later log commit electSuffix elect with
          zero | ⟨earlier, part, committed, below, inPart⟩
        · omega
        refine ⟨part, inPart, ?_⟩
        obtain ⟨current', past', leader', state', _, index', suffix', ⟨⟨now', term', role', led'⟩,
          _⟩, rfl, _⟩ :=
          committed.shape
        have canon' : Canon (after :: before :: rest) earlier state'.log :=
          ⟨_, suffix'.trans electInner, leader', state', ⟨now', term', role', led'⟩, rfl⟩
        have leaderCanon : Canon (after :: before :: rest) state.currentTerm state.log :=
          ⟨_, List.suffix_refl _, leader, state, ⟨leaderNow, rfl, leaderRole, leaderLed⟩,
            rfl⟩
        rcases lt_trichotomy earlier state.currentTerm with lower | rfl | higher
        · obtain ⟨log'', commit'', elected''⟩ := leaderLed.elected (by
            have := (committed.signature).2.2
            omega)
          have inLog := c.old_complete (committed.mono innerH) elected'' lower
          have inLeader := (prefix_committable inLog (committed.signature).1).trans
            ((c.canon_mono leader state leaderNow leaderRole (leaderLed)).2 log''
              commit'' elected'')
          exact comparable_of_prefix (List.take_prefix _ _) inLeader
        · rcases canon_chain canonMonos leaderCanon canon' with sub | sub
          · exact comparable_of_prefix ((List.take_prefix _ _).trans sub)
              (List.take_prefix _ _)
          · exact comparable_of_prefix (List.take_prefix _ _)
              ((List.take_prefix _ _).trans sub)
        · have := clean earlier state'.log higher (by omega)
            ⟨_, suffix', leader', state', ⟨now', term', role', led'⟩, rfl⟩
          exact comparable_of_prefix this (List.take_prefix _ _)
      rcases agree_or_contained baseLe indexLe frontier low high with
        done | ⟨k, agree, baseLe', commitLe⟩
      · exact done
      · exact core (List.suffix_refl _) c.termMonos canonMonos c.sortedAll c.rootedAll
          (List.suffix_refl _)
          ⟨⟨leaderNow, rfl, leaderRole, leaderLed⟩, baseLe, indexLe, signature, ‹_›⟩
          electSuffix electInner elect ((c.all Inv.persist).suffix innerH)
          (c.anchors.suffix innerH) ((c.all Inv.terms).suffix innerH) lt agree baseLe'
          commitLe clean

theorem completeness : Completeness (after :: before :: rest) := by
  intro term part node later log commit committed elected lt
  cases committed with
  | fresh step =>
      exact c.new_in_elected step (Or.inl rfl) later node log commit elected lt
  | chained step backing le within =>
      exact c.new_in_elected step (Or.inr ⟨_, _, backing, le, within⟩) later node log commit
        elected lt
  | past old => exact c.old_complete old elected lt

end Ctx

end CCFRaft.Proofs.Safety
