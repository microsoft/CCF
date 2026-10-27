module

public import CCFRaft.Proofs.Safety.Commit

@[expose] public section

set_option linter.unusedSectionVars false

/-!
# Follower logs within a term

Two clauses beyond the safety invariant, for the liveness proofs. Within a term
that nobody has led yet, a node's log is fixed. A node that does not lead a
term keeps, for the rest of that term, any prefix of a leader log of the term
that it held during the term.
-/

namespace CCFRaft.Proofs.Safety

open CCF
open Model.Node

variable [Config.InitialConfiguration]

/-- A node's log is fixed within a term that nobody has led yet. -/
def LogStable (history : History) : Prop :=
  forall node state earlier,
    Now history node state
    -> Seen history node earlier
    -> earlier.currentTerm = state.currentTerm
    -> (forall leader, Not (Led history leader state.currentTerm))
    -> earlier.log = state.log

/-- A node that does not lead its term keeps any prefix of a leader log of that
term that it held earlier in the term. -/
def CanonKeep (history : History) : Prop :=
  forall node state earlier log index,
    Now history node state
    -> Seen history node earlier
    -> earlier.currentTerm = state.currentTerm
    -> Not (Led history node state.currentTerm)
    -> Canon history state.currentTerm log
    -> index <= log.length
    -> log.take index <+: earlier.log
    -> log.take index <+: state.log

structure Keep (history : History) : Prop where
  stable : LogStable history
  keep : CanonKeep history

namespace Ctx

variable {nodes : List NodeID} {after before : Model.State}
  {rest : History} (c : Ctx nodes after before rest)

include c

/-- Without leading its resulting term, the actor changes its log only by
accepting AppendEntries, copying a prefix of a leader log of that term. -/
theorem log_follow
    (notLed : Not (Led (after :: before :: rest) c.actor c.post.currentTerm))
    : c.post.log = c.pre.log
      \/ exists earlier sender n,
          earlier <:+ before :: rest
          /\ (exists source, CanonNow earlier source sender c.post.currentTerm)
          /\ n <= sender.log.length
          /\ c.post.log = sender.log.take n
          /\ Not (c.pre.log.take n = sender.log.take n) := by
  cases Summary.kind c.sum with
  | same log _ => exact Or.inl log
  | append _ _ leader _ _ advance =>
      obtain ⟨_, term, _⟩ := Advance.facts advance
      refine absurd ((c.inv.leader_led c.actor c.pre c.pre_now leader).mono c.suffix_tail) ?_
      rw [term] at notLed
      exact notLed
  | ack _ _ _ _ _ _ advance => exact Or.inl (Advance.facts advance).1
  | accept source request eq accepted =>
      obtain ⟨earlier, sender, suffix, canon, _, bound, _, same | ⟨fresh, differ⟩, _⟩ :=
        c.accept_shape eq accepted
      · exact Or.inl same
      · rw [accepted.1] at canon
        exact Or.inr ⟨earlier, sender, _, suffix, ⟨source, canon⟩, bound, fresh, differ⟩
  | elect wins =>
      exact absurd (Or.inr ⟨_, _, after, before, rest, List.suffix_refl _, c.wins_elect wins⟩)
        notLed

theorem stable_step (stable : LogStable (before :: rest))
    : LogStable (after :: before :: rest) := by
  intro node state earlier now seen termEq noLeader
  have noLeader' : forall leader, Not (Led (before :: rest) leader state.currentTerm) :=
    fun leader led => noLeader leader (led.mono c.suffix_tail)
  rcases c.now_after now with ⟨rfl, rfl⟩ | ⟨different, old⟩
  · rcases c.seen_after seen with oldSeen | ⟨_, rfl⟩
    · have preTerm : c.pre.currentTerm = c.post.currentTerm := by
        have := c.inv.term_mono c.actor c.pre earlier c.pre_now oldSeen
        have := c.term_le
        omega
      have kept := stable c.actor c.pre earlier c.pre_now oldSeen (termEq.trans preTerm.symm)
        (by rw [preTerm]; exact noLeader')
      rcases c.log_follow (noLeader c.actor) with same | ⟨_, _, _, suffix, ⟨source, canon⟩, _⟩
      · rw [kept, same]
      · exact absurd ((canon.2.2.2.mono suffix).mono c.suffix_tail) (noLeader source)
    · rfl
  · rcases c.seen_after seen with oldSeen | ⟨eq, _⟩
    · exact stable node state earlier old oldSeen termEq noLeader'
    · exact absurd eq different

/-- A leader log of the actor after the step, held by another node. -/
theorem keep_leader (stable : LogStable (before :: rest))
    (keep : CanonKeep (before :: rest)) {node : NodeID} {state earlier : NodeState}
    {index : Nat} (now : Now (before :: rest) node state)
    (seen : Seen (before :: rest) node earlier)
    (termEq : earlier.currentTerm = state.currentTerm)
    (notLed : Not (Led (before :: rest) node state.currentTerm))
    (leader : CanonNow (after :: before :: rest) c.actor c.post state.currentTerm)
    (bound : index <= c.post.log.length) (held : c.post.log.take index <+: earlier.log)
    : c.post.log.take index <+: state.log := by
  by_cases ledBefore : Led (before :: rest) c.actor state.currentTerm
  · obtain ⟨_, postTerm, _, _⟩ := leader
    have le := c.term_le
    have preTerm : c.pre.currentTerm = state.currentTerm := by
      rcases c.inv.led_cur c.actor c.pre _ c.pre_now ledBefore with _ | ⟨_, _⟩ <;> omega
    have preRole : Not (c.pre.role = .candidate) := by
      rcases c.inv.led_cur c.actor c.pre _ c.pre_now ledBefore with _ | ⟨_, role⟩
      · omega
      · exact role
    have preLed : Led (before :: rest) c.actor c.pre.currentTerm := by
      rw [preTerm]
      exact ledBefore
    have preCanon : Canon (before :: rest) state.currentTerm c.pre.log :=
      ⟨before :: rest, List.suffix_refl _, c.actor, c.pre,
        ⟨c.pre_now, preTerm, preRole, ledBefore⟩, rfl⟩
    have viaOld : forall {canonLog : List Entry},
        Canon (before :: rest) state.currentTerm canonLog
        -> index <= canonLog.length
        -> c.post.log.take index = canonLog.take index
        -> c.post.log.take index <+: state.log := by
      intro canonLog canonical canonBound same
      rw [same] at held ⊢
      exact keep node state earlier canonLog index now seen termEq notLed canonical canonBound
        held
    rcases c.post_log with sub | ⟨entries, postEq, terms, _, _, _⟩
        | ⟨inner, source, sender, n, suffix, senderNow, nBound, postEq⟩
    · exact viaOld preCanon (le_trans bound sub.length_le) (take_eq_of_prefix sub bound).symm
    · rcases le_or_gt index c.pre.log.length with within | beyond
      · exact viaOld preCanon within (by rw [postEq, List.take_append_of_le_length within])
      · exfalso
        have heldBound : index <= earlier.log.length := by
          have := held.length_le
          simp only [List.length_take] at this
          omega
        have termIs : termAt earlier.log index = state.currentTerm := by
          rw [termAt_of_prefix held (by simp; omega), termAt_take le_rfl,
            termAt_eq (by omega) bound]
          simp only [postEq]
          rw [List.getElem_append_right (by omega), terms _ (List.getElem_mem _), preTerm]
        obtain ⟨_, eSuffix, eNow⟩ := seen.now
        obtain ⟨_, _, rfl⟩ := eNow.nonempty
        obtain ⟨canonLog, canonical, canonBound, _⟩ :=
          c.anchors _ eSuffix (List.cons_ne_nil _ _) node earlier index eNow (by omega)
            heldBound
        rw [termIs] at canonical
        have sub := (c.inv.canon_mono c.actor c.pre c.pre_now preRole preLed).1 canonLog
          (by rw [preTerm]; exact canonical.mono eSuffix)
        have := sub.length_le
        omega
    · have senderCanon : Canon (before :: rest) state.currentTerm sender.log := by
        rw [← postTerm]
        exact ⟨inner, suffix, source, sender, senderNow, rfl⟩
      have nle : index <= n := by
        rw [postEq] at bound
        simp only [List.length_take] at bound
        omega
      exact viaOld senderCanon (nle.trans nBound)
        (by rw [postEq, List.take_take, Nat.min_eq_left nle])
  · have none : forall other, Not (Led (before :: rest) other state.currentTerm) := by
      intro other led
      have same := c.election_safety other c.actor _ (led.mono c.suffix_tail) leader.2.2.2
      rw [same] at led
      exact ledBefore led
    rw [← stable node state earlier now seen termEq none]
    exact held

theorem keep_step (stable : LogStable (before :: rest))
    (keep : CanonKeep (before :: rest))
    : CanonKeep (after :: before :: rest) := by
  intro node state earlier log index now seen termEq notLed canon bound held
  have notLed' : Not (Led (before :: rest) node state.currentTerm) :=
    fun led => notLed (led.mono c.suffix_tail)
  rcases c.now_after now with ⟨rfl, rfl⟩ | ⟨different, old⟩
  · rcases c.seen_after seen with oldSeen | ⟨_, rfl⟩
    swap
    · exact held
    have preTerm : c.pre.currentTerm = c.post.currentTerm := by
      have := c.inv.term_mono c.actor c.pre earlier c.pre_now oldSeen
      have := c.term_le
      omega
    have oldCanon : Canon (before :: rest) c.post.currentTerm log := by
      rcases c.canon_after canon with old | ⟨leader, leaderState, leaderNow, rfl⟩
      · exact old
      · rcases c.now_after leaderNow.1 with ⟨rfl, rfl⟩ | ⟨leaderDifferent, leaderOld⟩
        · exact absurd leaderNow.2.2.2 notLed
        · exact ⟨before :: rest, List.suffix_refl _, leader, leaderState,
            ⟨leaderOld, leaderNow.2.1, leaderNow.2.2.1,
              c.led_other leaderDifferent leaderNow.2.2.2⟩, rfl⟩
    have preHeld := keep c.actor c.pre earlier log index c.pre_now oldSeen
      (termEq.trans preTerm.symm) (by rw [preTerm]; exact notLed')
      (by rw [preTerm]; exact oldCanon) bound held
    rcases c.log_follow notLed with same
        | ⟨inner, sender, n, suffix, ⟨source, senderNow⟩, nBound, postEq, differ⟩
    · rw [same]
      exact preHeld
    · have senderCanon : Canon (before :: rest) c.post.currentTerm sender.log :=
        ⟨inner, suffix, source, sender, senderNow, rfl⟩
      have chain := canon_chain c.monos oldCanon senderCanon
      rcases le_or_gt index n with within | beyond
      · rw [postEq, take_eq_take_of_comparable chain bound (within.trans nBound)]
        exact take_prefix_take _ within
      · exfalso
        apply differ
        rw [← take_eq_take_of_comparable chain (by omega) nBound,
          take_eq_of_prefix preHeld (by simp; omega), List.take_take,
          Nat.min_eq_left beyond.le]
  · rcases c.seen_after seen with oldSeen | ⟨eq, _⟩
    swap
    · exact absurd eq different
    rcases c.canon_after canon with oldCanon | ⟨leader, leaderState, leaderNow, rfl⟩
    · exact keep node state earlier log index old oldSeen termEq notLed' oldCanon bound held
    · rcases c.now_after leaderNow.1 with ⟨rfl, rfl⟩ | ⟨leaderDifferent, leaderOld⟩
      · exact c.keep_leader stable keep old oldSeen termEq notLed' leaderNow bound held
      · exact keep node state earlier _ index old oldSeen termEq notLed'
          ⟨before :: rest, List.suffix_refl _, leader, leaderState,
            ⟨leaderOld, leaderNow.2.1, leaderNow.2.2.1,
              c.led_other leaderDifferent leaderNow.2.2.2⟩, rfl⟩ bound held

end Ctx

/-- Both clauses hold at every point of every execution. -/
theorem keep_of_exec {nodes : List NodeID} {history : History} (exec : Exec nodes history)
    : Keep history := by
  induction exec with
  | @initial current initialized =>
      have exec := Exec.initial (nodes := nodes) initialized
      have same : forall {node : NodeID} {state earlier : NodeState},
          Now [current] node state -> Seen [current] node earlier -> earlier = state := by
        intro node state earlier now seen
        rcases seen.cons with mem | old
        · exact now_unique exec mem now
        · obtain ⟨_, member, _⟩ := old
          cases member
      exact ⟨fun _ _ _ now seen _ _ => by rw [same now seen],
        fun _ _ _ _ _ now seen _ _ _ _ held => by rw [← same now seen]; exact held⟩
  | step prior stepped ih =>
      obtain ⟨transition⟩ := LocalTransition.ofStep stepped
      have c : Ctx nodes _ _ _ := ⟨.step prior stepped, transition, good_of_exec prior⟩
      exact ⟨c.stable_step ih.stable, c.keep_step ih.stable ih.keep⟩

/-- A primary's match index for a peer in its term is a prefix the peer holds. -/
theorem match_held {history : History} (inv : Inv history) (keep : Keep history)
    {leader peer : NodeID} {state peerState : NodeState}
    (leaderNow : Now history leader state) (primary : state.role = .primary)
    (different : Not (peer = leader)) (peerNow : Now history peer peerState)
    (termEq : peerState.currentTerm = state.currentTerm)
    : state.log.take (state.matchIndex peer) <+: peerState.log
      /\ state.matchIndex peer <= peerState.log.length := by
  rcases Nat.eq_zero_or_pos (state.matchIndex peer) with zero | pos
  · simp [zero]
  obtain ⟨acker, log, seen, ackerTerm, canon, bound, held⟩ :=
    inv.match_ack leader state peer leaderNow primary different pos
  have led := inv.leader_led leader state leaderNow primary
  have notLed : Not (Led history peer peerState.currentTerm) := fun peerLed =>
    different (inv.election_safety peer leader _ peerLed (by rw [termEq]; exact led))
  have kept := keep.keep peer peerState acker log _ peerNow seen
    (ackerTerm.trans termEq.symm) notLed (by rw [termEq]; exact canon) bound held
  have sub := (inv.canon_mono leader state leaderNow (by simp [primary]) led).1 log canon
  rw [take_eq_of_prefix sub bound]
  refine ⟨kept, ?_⟩
  have := kept.length_le
  simp only [List.length_take] at this
  omega

end CCFRaft.Proofs.Safety
