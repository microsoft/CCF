module

public import CCFRaft.Proofs.Safety.Complete
public import CCFRaft.Proofs.Safety.Init

@[expose] public section

set_option linter.unusedSectionVars false

/-!
# Commit indices, persistence and messages after one step

The remaining invariant clauses, the invariant of the extended history, and
the invariant of every execution.
-/

namespace CCFRaft.Proofs.Safety

open CCF
open Model.Node
open CCFRaft.Proofs.Ledger

variable [Config.InitialConfiguration]

theorem Backed.transfer {history : History} {log log' : List Entry}
    {commit term : Nat} (backed : Backed history log commit term)
    (agree : log'.take commit = log.take commit)
    : Backed history log' commit term := by
  rcases backed with zero | ⟨earlier, part, committed, le, within⟩
  · exact Or.inl zero
  · exact Or.inr ⟨earlier, part, committed, le, agree ▸ within⟩

theorem maxCommittableIndexUpTo_le (log : List Entry) (frontier : Nat)
    : maxCommittableIndexUpTo log frontier <= frontier := by
  have := maxCommittableIndexBounded (log.take frontier)
  simp only [List.length_take] at this
  unfold maxCommittableIndexUpTo
  omega

namespace Ctx

variable {nodes : List NodeID} {after before : Model.State}
  {rest : History} (c : Ctx nodes after before rest)

include c

/-! ## Leaders before the step -/

theorem pre_led (leader : c.pre.role = .primary)
    : Led (before :: rest) c.actor c.pre.currentTerm :=
  c.inv.leader_led c.actor c.pre c.pre_now leader

theorem post_led
    (origin
      : (c.pre.role = .primary /\ c.post.currentTerm = c.pre.currentTerm)
        \/ Wins c.actor c.pre c.event c.post)
    : Led (after :: before :: rest) c.actor c.post.currentTerm := by
  rcases origin with ⟨leader, termEq⟩ | wins
  · rw [termEq]
    exact (c.pre_led leader).mono c.suffix_tail
  · exact Or.inr ⟨_, _, after, before, rest, List.suffix_refl _, c.wins_elect wins⟩

/-- An acknowledgement of a leader's term holds a prefix of the leader's log. -/
theorem acked_pre (leader : c.pre.role = .primary) {voter : NodeID} {index : Nat}
    (acked : Acked (before :: rest) voter c.pre.currentTerm index)
    : exists acker,
        Seen (after :: before :: rest) voter acker
        /\ acker.currentTerm = c.pre.currentTerm
        /\ index <= c.pre.log.length
        /\ c.pre.log.take index <+: acker.log := by
  obtain ⟨acker, log, seen, termEq, canon, bound, sub⟩ := acked
  have notCandidate : Not (c.pre.role = .candidate) := by
    rw [leader]
    intro h
    cases h
  have inLog :=
    (c.inv.canon_mono c.actor c.pre c.pre_now notCandidate (c.pre_led leader)).1 log canon
  refine ⟨acker, seen.mono c.suffix_tail, termEq, bound.trans inLog.length_le, ?_⟩
  rw [take_eq_of_prefix inLog bound]
  exact sub

/-! ## Commit indices -/

/-- An advanced commit index is a commit step backed by the earlier one. -/
theorem advance_backed {middle : NodeState}
    (advance : Advance c.actor middle c.post)
    (old : Backed (before :: rest) c.post.log middle.commitIndex c.post.currentTerm)
    (led : Led (after :: before :: rest) c.actor c.post.currentTerm)
    (role : middle.role = .primary)
    (acks
      : forall voter,
          Not (voter = c.actor)
          -> 0 < middle.matchIndex voter
          -> exists acker,
              Seen (after :: before :: rest) voter acker
              /\ acker.currentTerm = c.post.currentTerm
              /\ c.post.log.take (middle.matchIndex voter) <+: acker.log)
    : Backed (after :: before :: rest) c.post.log c.post.commitIndex
        c.post.currentTerm := by
  rcases advance with ⟨same, _⟩ | ⟨log, term, _, _, _, _, lt, eq, postRole⟩
  · subst same
    exact old.mono c.suffix_tail
  have ahead : middle.commitIndex < highestCommittableIndex middle c.actor :=
    eq ▸ lt
  obtain ⟨bound, signature, termEq, quorum⟩ := highestCommittableIndex_spec middle c.actor ahead
  obtain ⟨voters, quorum, members⟩
      : exists voters,
          hasQuorum
            (middle.activeConfigurations.filter
              fun configuration =>
                configuration.index <= highestCommittableIndex middle c.actor)
            voters
          /\ forall voter, voter ∈ voters
              -> voter = c.actor
                  \/ middle.matchIndex voter >= highestCommittableIndex middle
                      c.actor :=
    ⟨_, quorum, fun _ mem => (Finset.mem_filter.mp mem).2⟩
  have notCandidate : Not (c.post.role = .candidate) := by
    rcases postRole with postRole | ⟨postRole, _⟩ <;> rw [postRole]
    · rw [role]
      intro h
      cases h
    · intro h
      cases h
  have step : CommitStep (after :: before :: rest) c.actor c.post c.post.currentTerm
      middle.commitIndex c.post.commitIndex := by
    refine ⟨⟨c.post_now, rfl, notCandidate, led⟩, lt.le, ?_, ?_, ?_, voters, ?_, ?_⟩
    · rw [log, eq]
      exact bound
    · rw [log, eq]
      exact signature
    · rw [log, eq, termEq, term]
    · rw [log, eq]
      exact quorum
    · intro voter mem
      by_cases self : voter = c.actor
      · subst self
        exact ⟨c.post, c.post_seen, rfl, List.take_prefix _ _⟩
      · have ge := (members voter mem).resolve_left self
        obtain ⟨acker, seen, ackerTerm, sub⟩ := acks voter self (by omega)
        exact ⟨acker, seen, ackerTerm, (take_prefix_take _ (by omega)).trans sub⟩
  have committed
      : Committed (after :: before :: rest) c.post.currentTerm
          (c.post.log.take c.post.commitIndex) := by
    rcases old with zero | ⟨earlier, part, backing, le, within⟩
    · rw [zero] at step
      exact .fresh step
    · exact .chained step backing le within
  exact Or.inr ⟨_, _, committed, le_rfl, List.prefix_refl _⟩

theorem pre_backed
    (agree : c.post.log.take c.pre.commitIndex = c.pre.log.take c.pre.commitIndex)
    : Backed (before :: rest) c.post.log c.pre.commitIndex c.post.currentTerm :=
  ((c.inv.commit_backed c.actor c.pre c.pre_now).weaken c.term_le).transfer agree

/-- A leader's acknowledged prefix, from its match index. -/
theorem match_pre (leader : c.pre.role = .primary) {voter : NodeID}
    (different : Not (voter = c.actor)) (positive : 0 < c.pre.matchIndex voter)
    : exists acker,
        Seen (after :: before :: rest) voter acker
        /\ acker.currentTerm = c.pre.currentTerm
        /\ c.pre.matchIndex voter <= c.pre.log.length
        /\ c.pre.log.take (c.pre.matchIndex voter) <+: acker.log :=
  c.acked_pre leader
    (c.inv.match_ack c.actor c.pre voter c.pre_now leader different positive)

theorem accept_backed {source : NodeID} {request : AppendEntriesRequest}
    (received : c.event = .receive source (.appendEntriesRequest request))
    (accepted : Accepted c.pre request c.post)
    : Backed (after :: before :: rest) c.post.log c.post.commitIndex
        c.post.currentTerm := by
  obtain ⟨earlier, sender, suffix, canon, aeok, batchBound, postTake, shape, prevAgree⟩ :=
    c.accept_shape received accepted
  obtain ⟨requestTerm, _, commitLe, _, _, _, commitEq⟩ := accepted
  rw [commitEq]
  rcases max_choice c.pre.commitIndex
      (maxCommittableIndexUpTo c.post.log
        (min request.primaryCommit (request.prevLogIndex + request.entries.length))) with
    choice | choice <;> rw [choice]
  · refine (c.pre_backed ?_).mono c.suffix_tail
    rcases shape with same | ⟨fresh, _⟩
    · rw [same]
    · rw [fresh]
      calc
        (sender.log.take (request.prevLogIndex + request.entries.length)).take
              c.pre.commitIndex
            = sender.log.take c.pre.commitIndex := by
          rw [List.take_take, Nat.min_eq_left (by omega)]
        _ = (sender.log.take request.prevLogIndex).take c.pre.commitIndex := by
          rw [List.take_take, Nat.min_eq_left commitLe]
        _ = (c.pre.log.take request.prevLogIndex).take c.pre.commitIndex := by
          rw [prevAgree]
        _ = c.pre.log.take c.pre.commitIndex := by
          rw [List.take_take, Nat.min_eq_left commitLe]
  · have kLe := maxCommittableIndexUpTo_le c.post.log
      (min request.primaryCommit (request.prevLogIndex + request.entries.length))
    have lcLe := aeok.2.2.2.2.2.1
    have senderTerm := canon.2.1
    obtain ⟨_, _, rfl⟩ := canon.1.nonempty
    rcases c.all Inv.commit_backed _ suffix (List.cons_ne_nil _ _) source sender canon.1 with
      zero | ⟨earlier', part, committed, le, within⟩
    · exact Or.inl (by omega)
    · refine Or.inr
        ⟨earlier', part, committed.mono (suffix.trans c.suffix_tail), by omega, ?_⟩
      generalize maxCommittableIndexUpTo c.post.log
        (min request.primaryCommit (request.prevLogIndex + request.entries.length)) = k at kLe ⊢
      have agree : c.post.log.take k = sender.log.take k := by
        calc
          c.post.log.take k
              = (c.post.log.take (request.prevLogIndex + request.entries.length)).take
                  k := by
            rw [List.take_take, Nat.min_eq_left (by omega)]
          _ = (sender.log.take (request.prevLogIndex + request.entries.length)).take
                k := by
            rw [postTake]
          _ = sender.log.take k := by rw [List.take_take, Nat.min_eq_left (by omega)]
      rw [agree]
      exact (take_prefix_take _ (by omega)).trans within

theorem commit_backed : CommitBacked (after :: before :: rest) := by
  intro node state now
  rcases c.now_after now with ⟨rfl, rfl⟩ | ⟨_, old⟩
  · cases Summary.kind c.sum with
    | same log commit =>
        rw [commit]
        exact (c.pre_backed (by rw [log])).mono c.suffix_tail
    | append entries sent leader _ _ advance =>
        have logEq : c.post.log = c.pre.log ++ entries := (Advance.facts advance).1
        have termEq : c.post.currentTerm = c.pre.currentTerm := (Advance.facts advance).2.1
        refine c.advance_backed advance (c.pre_backed ?_) ?_ leader ?_
        · rw [logEq]
          exact List.take_append_of_le_length c.frontier_pre
        · rw [termEq]
          exact (c.pre_led leader).mono c.suffix_tail
        · intro voter different positive
          obtain ⟨acker, seen, ackerTerm, bound, sub⟩ := c.match_pre leader different positive
          refine ⟨acker, seen, by rw [ackerTerm, termEq], ?_⟩
          dsimp only
          rw [logEq, List.take_append_of_le_length bound]
          exact sub
    | ack source response received leader success responseTerm advance =>
        have logEq : c.post.log = c.pre.log := (Advance.facts advance).1
        have termEq : c.post.currentTerm = c.pre.currentTerm := (Advance.facts advance).2.1
        refine c.advance_backed advance (c.pre_backed (by rw [logEq])) ?_ leader ?_
        · rw [termEq]
          exact (c.pre_led leader).mono c.suffix_tail
        · intro voter different positive
          dsimp only at positive ⊢
          rw [logEq, termEq]
          by_cases fromSource : voter = source
          · subst fromSource
            rw [Function.update_self] at positive ⊢
            rcases max_choice (c.pre.matchIndex voter) response.lastLogIndex with
              choice | choice <;> rw [choice] at positive ⊢
            · obtain ⟨acker, seen, ackerTerm, _, sub⟩ := c.match_pre leader different positive
              exact ⟨acker, seen, ackerTerm, sub⟩
            · obtain ⟨envelope, ok, sourceEq, _, payload⟩ := c.received_ok received
              simp only [MessageOK, payload] at ok
              have acked := ok success
              rw [sourceEq, responseTerm] at acked
              obtain ⟨acker, seen, ackerTerm, _, sub⟩ := c.acked_pre leader acked
              exact ⟨acker, seen, ackerTerm, sub⟩
          · rw [Function.update_of_ne fromSource] at positive ⊢
            obtain ⟨acker, seen, ackerTerm, _, sub⟩ := c.match_pre leader different positive
            exact ⟨acker, seen, ackerTerm, sub⟩
    | accept source request received accepted => exact c.accept_backed received accepted
    | elect wins =>
        have elect := c.wins_elect wins
        have winning := (c.electStep elect).2.2.2.2.2.2.1
        obtain ⟨candidate, ⟨_, candidateLog, candidateCommit, _⟩, _, advance⟩ := wins
        have committable : c.pre.commitIndex <= maxCommittableIndex c.pre.log := by
          rcases Nat.eq_zero_or_pos c.pre.commitIndex with zero | positive
          · omega
          · exact signatureIndex_le_maxCommittableIndex
              ((c.pre_seen.frontier c.prior).2 positive)
        have agree : c.post.log.take c.pre.commitIndex = c.pre.log.take c.pre.commitIndex := by
          have := c.frontier_pre
          rw [take_eq_of_prefix winning (by simp; omega), List.take_take,
            Nat.min_eq_left committable]
        refine c.advance_backed advance ?_ (Or.inr ⟨_, _, after, before, rest,
          List.suffix_refl _, elect⟩) rfl ?_
        · show Backed _ _ candidate.commitIndex _
          rw [candidateCommit]
          exact c.pre_backed agree
        · intro voter _ positive
          exact absurd positive (Nat.lt_irrefl 0)
  · exact (c.inv.commit_backed node state old).mono c.suffix_tail

/-! ## Persistence of signed prefixes -/

/-- A signed prefix of the follower's log survives an accepted request, unless
the sender's leader log of a later term lacks it. -/
theorem accept_persist {source : NodeID} {request : AppendEntriesRequest}
    (received : c.event = .receive source (.appendEntriesRequest request))
    (accepted : Accepted c.pre request c.post) {part : List Entry}
    (signature : isSignatureAt part part.length = true) (inPre : part <+: c.pre.log)
    : part <+: c.post.log
      \/ Bad (after :: before :: rest) part (termAt part part.length)
          c.post.currentTerm := by
  obtain ⟨earlier, sender, suffix, canon, _, batchBound, _, shape, _⟩ :=
    c.accept_shape received accepted
  rcases shape with same | ⟨fresh, differ⟩
  · left
    rw [same]
    exact inPre
  have requestTerm : request.term = c.post.currentTerm := accepted.1
  have senderCanon : Canon (before :: rest) c.post.currentTerm sender.log := by
    rw [← requestTerm]
    exact ⟨earlier, suffix, source, sender, canon, rfl⟩
  generalize request.prevLogIndex + request.entries.length = n at batchBound fresh differ
  -- A part agreeing with the sender beyond the batch end contradicts the truncation.
  have beyond : n < part.length -> Not (part.take n = sender.log.take n) := by
    intro long agree
    apply differ
    rw [← agree]
    exact take_eq_of_prefix inPre long.le
  by_cases inSender : part <+: sender.log
  · rcases le_or_gt part.length n with short | long
    · left
      have := take_prefix_take sender.log short
      rw [← List.prefix_iff_eq_take.mp inSender] at this
      rw [fresh]
      exact this
    · exact (beyond long (take_eq_of_prefix inSender long.le).symm).elim
  · have positive := signature_pos signature
    have termLe : termAt part part.length <= c.post.currentTerm :=
      (termAt_le_of_mem (fun entry mem => c.inv.terms c.actor c.pre c.pre_now entry
        (inPre.subset mem)) _).trans c.term_le
    rcases Nat.lt_or_ge (termAt part part.length) c.post.currentTerm with lower | upper
    · exact Or.inr ⟨c.post.currentTerm, sender.log, lower, le_rfl,
        senderCanon.mono c.suffix_tail, inSender⟩
    · exfalso
      obtain ⟨log, logCanon, length, take⟩ :=
        c.inv.anchor c.actor c.pre part.length c.pre_now positive inPre.length_le
      have partEq : c.pre.log.take part.length = part :=
        (List.prefix_iff_eq_take.mp inPre).symm
      have termEq : termAt c.pre.log part.length = c.post.currentTerm := by
        have := termAt_take (log := c.pre.log) (le_refl part.length)
        rw [partEq] at this
        omega
      rw [termEq] at logCanon
      have partLog : part = log.take part.length := partEq.symm.trans take
      have comparable := canon_chain c.monos logCanon senderCanon
      rcases le_or_gt part.length sender.log.length with fits | long
      · apply inSender
        rw [partLog, take_eq_take_of_comparable comparable length fits]
        exact List.take_prefix _ _
      · apply beyond (by omega)
        rw [partLog, List.take_take, Nat.min_eq_left (by omega)]
        exact take_eq_take_of_comparable comparable (by omega) batchBound

/-- A signed prefix of the actor's log survives the step, unless a leader log
of a later term lacks it. -/
theorem persist_pre {part : List Entry}
    (signature : isSignatureAt part part.length = true) (inPre : part <+: c.pre.log)
    : part <+: c.post.log
      \/ Bad (after :: before :: rest) part (termAt part part.length)
          c.post.currentTerm := by
  cases Summary.kind c.sum with
  | same log _ =>
      left
      rw [log]
      exact inPre
  | append _ _ _ _ _ advance =>
      left
      rw [(Advance.facts advance).1]
      exact inPre.trans (List.prefix_append _ _)
  | ack _ _ _ _ _ _ advance =>
      left
      rw [(Advance.facts advance).1]
      exact inPre
  | accept _ _ received accepted =>
      exact c.accept_persist received accepted signature inPre
  | elect wins =>
      left
      have winning : c.pre.log.take (maxCommittableIndex c.pre.log) <+: c.post.log :=
        (c.electStep (c.wins_elect wins)).2.2.2.2.2.2.1
      exact (prefix_committable inPre signature).trans winning

theorem persist : Persist (after :: before :: rest) := by
  intro node state earlier index now seen signature
  rcases c.now_after now with ⟨rfl, rfl⟩ | ⟨different, old⟩
  · rcases c.seen_after seen with oldSeen | ⟨_, rfl⟩
    · rcases c.inv.persist c.actor c.pre earlier index c.pre_now oldSeen signature with
        inPre | ⟨later, log, lt, le, canon, missing⟩
      · have termEq : termAt (earlier.log.take index) (earlier.log.take index).length
            = termAt earlier.log index := by
          rw [List.length_take, Nat.min_eq_left (signature_bound signature),
            termAt_take le_rfl]
        rw [← termEq]
        exact c.persist_pre (take_signature signature) inPre
      · exact Or.inr ⟨later, log, lt, le.trans c.term_le, canon.mono c.suffix_tail, missing⟩
    · exact Or.inl (List.take_prefix _ _)
  · rcases c.seen_after seen with oldSeen | ⟨same, _⟩
    · rcases c.inv.persist node state earlier index old oldSeen signature with sub | bad
      · exact Or.inl sub
      · exact Or.inr (bad.mono c.suffix_tail)
    · exact (different same).elim

/-! ## Match indices -/

theorem match_ack : MatchAck (after :: before :: rest) := by
  intro node state peer now leader different positive
  rcases c.now_after now with ⟨rfl, rfl⟩ | ⟨_, old⟩
  · rcases Summary.leader c.sum leader with ⟨preLeader, termEq⟩ | wins
    · rw [termEq]
      rcases Summary.matchIndex c.sum leader preLeader termEq peer with
        same | ⟨response, received, success, responseTerm, matchEq⟩
      · rw [same] at positive ⊢
        exact (c.inv.match_ack c.actor c.pre peer c.pre_now preLeader different
          positive).mono c.suffix_tail
      · rw [matchEq]
        obtain ⟨envelope, ok, sourceEq, _, payload⟩ := c.received_ok received
        simp only [MessageOK, payload] at ok
        have acked := ok success
        rw [sourceEq, responseTerm] at acked
        exact acked.mono c.suffix_tail
    · obtain ⟨_, _, _, _, _, _, zero, _⟩ := Wins.facts wins
      rw [zero] at positive
      exact absurd positive (Nat.lt_irrefl 0)
  · exact (c.inv.match_ack node state peer old leader different positive).mono c.suffix_tail

/-! ## Messages -/

/-- Vote requests recorded for a candidacy stay accurate while it lasts. -/
theorem rv_stable {node : NodeID} {term : Nat} {request : RequestVoteRequest}
    (seen : exists state, Seen (before :: rest) node state /\ state.currentTerm = term)
    (stable
      : forall state,
          Now (before :: rest) node state
          -> state.role = .candidate
          -> state.currentTerm = term
          -> makeRequestVoteRequest state = request)
    : forall state,
        Now (after :: before :: rest) node state
        -> state.role = .candidate
        -> state.currentTerm = term
        -> makeRequestVoteRequest state = request := by
  intro state now role termEq
  rcases c.now_after now with ⟨rfl, rfl⟩ | ⟨_, old⟩
  · obtain ⟨_, logEq, commitEq, ⟨_, freshTerm, _⟩ | ⟨preRole, sameTerm, _⟩⟩ :=
      Summary.candidate c.sum role
    · obtain ⟨earlier, earlierSeen, earlierTerm⟩ := seen
      have := c.inv.term_mono c.actor c.pre earlier c.pre_now earlierSeen
      omega
    · have preTerm : c.pre.currentTerm = term := by
        rw [← sameTerm]
        exact termEq
      have := stable c.pre c.pre_now preRole preTerm
      rw [makeRequestVoteRequest_eq] at this ⊢
      rw [logEq, commitEq, sameTerm]
      exact this
  · exact stable state old role termEq

theorem seen_term {node : NodeID} {term : Nat}
    (seen : exists state, Seen (before :: rest) node state /\ state.currentTerm = term)
    : exists state,
        Seen (after :: before :: rest) node state /\ state.currentTerm = term := by
  obtain ⟨state, seen, termEq⟩ := seen
  exact ⟨state, seen.mono c.suffix_tail, termEq⟩

theorem old_message {envelope : Model.Envelope} (ok : MessageOK (before :: rest) envelope)
    : MessageOK (after :: before :: rest) envelope := by
  cases h : envelope.payload with
  | appendEntriesRequest request =>
      simp only [MessageOK, h] at ok ⊢
      obtain ⟨earlier, suffix, rest'⟩ := ok
      exact ⟨earlier, suffix.trans c.suffix_tail, rest'⟩
  | appendEntriesResponse response =>
      simp only [MessageOK, h] at ok ⊢
      exact fun success => (ok success).mono c.suffix_tail
  | requestVoteRequest request =>
      simp only [MessageOK, h] at ok ⊢
      obtain ⟨seen, stable⟩ := ok
      exact ⟨c.seen_term seen, c.rv_stable seen stable⟩
  | requestVoteResponse response =>
      simp only [MessageOK, h] at ok ⊢
      intro granted
      obtain ⟨request, grantedBy, seen, stable⟩ := ok granted
      exact ⟨request, grantedBy.mono c.suffix_tail, c.seen_term seen, c.rv_stable seen stable⟩
  | requestPreVoteRequest _ => simp only [MessageOK, h]
  | requestPreVoteResponse _ => simp only [MessageOK, h]
  | proposeRequestVoteRequest _ => simp only [MessageOK, h]

theorem new_message {envelope : Model.Envelope} (new : envelope ∈ c.sent)
    : MessageOK (after :: before :: rest) envelope := by
  obtain ⟨sourceEq, ok⟩ := Summary.sends c.sum envelope new
  cases h : envelope.payload with
  | appendEntriesRequest request =>
      simp only [h] at ok
      simp only [MessageOK, h]
      rw [sourceEq]
      obtain ⟨aeok, notCandidate, origin⟩ := ok
      refine ⟨after :: before :: rest, List.suffix_refl _, c.post,
        ⟨c.post_now, aeok.2.1.symm, notCandidate, ?_⟩, aeok⟩
      rw [aeok.2.1]
      exact c.post_led origin
  | appendEntriesResponse response =>
      simp only [h] at ok
      simp only [MessageOK, h]
      intro success
      obtain ⟨source, request, received, accepted, responseTerm, lastEq⟩ := ok.2 success
      obtain ⟨earlier, sender, suffix, canon, _, batchBound, postTake, _, _⟩ :=
        c.accept_shape received accepted
      rw [sourceEq, responseTerm, lastEq]
      refine ⟨c.post, sender.log, c.post_seen, rfl,
        ⟨earlier, suffix.trans c.suffix_tail, source, sender, ?_, rfl⟩, batchBound, ?_⟩
      · rw [← accepted.1]
        exact canon
      · rw [← postTake]
        exact List.take_prefix _ _
  | requestVoteRequest request =>
      simp only [h] at ok
      simp only [MessageOK, h]
      rw [sourceEq]
      obtain ⟨termEq, _, stable⟩ := ok
      refine ⟨⟨c.post, c.post_seen, termEq.symm⟩, fun state now role _ => ?_⟩
      rw [c.now_post now] at role ⊢
      exact stable role
  | requestVoteResponse response =>
      simp only [h] at ok
      simp only [MessageOK, h]
      obtain ⟨termEq, grants⟩ := ok
      intro granted
      obtain ⟨request, received, requestTerm, upToDate, voted⟩ := grants granted
      obtain ⟨_, ok', sourceEq', _, payload'⟩ := c.received_ok received
      simp only [MessageOK, payload'] at ok'
      obtain ⟨seen, stable⟩ := ok'
      rw [sourceEq', requestTerm] at seen stable
      rw [termEq]
      refine ⟨request, ?_, c.seen_term seen, c.rv_stable seen stable⟩
      rw [sourceEq]
      exact ⟨after, before, rest, List.suffix_refl _, c.pre, c.post, c.tr.pre_mem,
        c.tr.post_mem, c.term_le, rfl, voted, upToDate⟩
  | requestPreVoteRequest _ => simp only [MessageOK, h]
  | requestPreVoteResponse _ => simp only [MessageOK, h]
  | proposeRequestVoteRequest _ => simp only [MessageOK, h]

theorem messages : Messages (after :: before :: rest) := by
  intro envelope pending
  rcases c.tr.mem_network pending with old | new
  · exact c.old_message (c.inv.messages envelope old)
  · exact c.new_message new

theorem message_terms : MessageTerms (after :: before :: rest) := by
  intro envelope pending bumping
  rcases c.tr.mem_network pending with old | new
  · exact c.inv.message_terms envelope old bumping
  · have two := c.post_two (Or.inr (List.ne_nil_of_mem new))
    obtain ⟨_, ok⟩ := Summary.sends c.sum envelope new
    cases h : envelope.payload with
    | appendEntriesRequest request =>
        simp only [h] at ok
        simp only [Message.term]
        have := ok.1.2.1
        omega
    | appendEntriesResponse _ =>
        rw [h] at bumping
        exact bumping.elim
    | requestVoteRequest request =>
        simp only [h] at ok
        simp only [Message.term]
        have := ok.1
        omega
    | requestVoteResponse response =>
        simp only [h] at ok
        simp only [Message.term]
        have := ok.1
        omega
    | requestPreVoteRequest request =>
        simp only [h, Message.term] at ok ⊢
        omega
    | requestPreVoteResponse response =>
        simp only [h, Message.term] at ok ⊢
        omega
    | proposeRequestVoteRequest _ =>
        rw [h] at bumping
        exact bumping.elim

/-! ## The invariant after the step -/

theorem inv_step : Inv (after :: before :: rest) :=
  {
    terms := c.terms
    sorted := c.sorted
    active := c.active
    term_mono := c.term_mono
    vote_record := c.vote_record
    led_cur := c.led_cur
    leader_led := c.leader_led
    candidate := c.candidate
    elect_backed := c.elect_backed
    election_safety := c.election_safety
    canon_mono := c.canon_mono
    anchor := c.anchor
    completeness := c.completeness
    commit_backed := c.commit_backed
    persist := c.persist
    match_ack := c.match_ack
    messages := c.messages
    message_terms := c.message_terms
    rooted := c.rooted
    leader_logs := c.leader_logs
  }

end Ctx

/-! ## Executions -/

/-- The invariant holds at every point of every execution. -/
theorem good_of_exec {nodes : List NodeID} {history : History} (exec : Exec nodes history)
    : Good history := by
  induction exec with
  | initial initialized =>
      intro earlier suffix nonempty
      rcases List.suffix_cons_iff.mp suffix with rfl | inner
      · exact inv_initial initialized
      · exact (nonempty (List.eq_nil_of_suffix_nil inner)).elim
  | step prior stepped ih =>
      obtain ⟨transition⟩ := LocalTransition.ofStep stepped
      have c : Ctx nodes _ _ _ := ⟨.step prior stepped, transition, ih⟩
      intro earlier suffix nonempty
      rcases List.suffix_cons_iff.mp suffix with rfl | inner
      · exact c.inv_step
      · exact ih earlier inner nonempty

/-- Every reachable state is the head of a history satisfying the invariant. -/
theorem inv_of_reachable {nodes : List NodeID} {state : Model.State}
    (reachable
      : (Model.transitionSystem Config.INITIAL_CONFIGURATION nodes).Reachable state)
    : exists history, Exec nodes (state :: history) /\ Inv (state :: history) := by
  obtain ⟨history, exec⟩ := exec_of_reachable reachable
  exact ⟨history, exec, good_of_exec exec _ (List.suffix_refl _) (List.cons_ne_nil _ _)⟩

/-- The committed logs of two nodes in one state are comparable. -/
theorem committed_logs_comparable {nodes : List NodeID} {history : History}
    (exec : Exec nodes history) {left right : NodeID}
    {leftState rightState : NodeState} (leftNow : Now history left leftState)
    (rightNow : Now history right rightState)
    : leftState.committedLog <+: rightState.committedLog
      \/ rightState.committedLog <+: leftState.committedLog := by
  have good := good_of_exec exec
  have nonempty : Not (history = []) := by
    rintro rfl
    exact leftNow
  have inv := good _ (List.suffix_refl _) nonempty
  unfold NodeState.committedLog
  rcases inv.commit_backed left leftState leftNow with zero | ⟨_, part, committed, _, within⟩
  · left
    rw [zero, List.take_zero]
    exact List.nil_prefix
  rcases inv.commit_backed right rightState rightNow with
    zero | ⟨_, part', committed', _, within'⟩
  · right
    rw [zero, List.take_zero]
    exact List.nil_prefix
  rcases committed_comparable inv.completeness (good.everywhere Inv.canon_mono) committed
      committed' with sub | sub
  · exact comparable_of_prefix (within.trans sub) within'
  · exact comparable_of_prefix within (within'.trans sub)

end CCFRaft.Proofs.Safety
