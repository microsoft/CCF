module

public import CCFRaft.Proofs.Safety.Step

@[expose] public section

set_option linter.unusedSectionVars false

/-!
# Local clauses after one step

The clauses about a single node's own states: log terms, log order, terms and
votes over time, leadership and candidacy records.
-/

namespace CCFRaft.Proofs.Safety

open CCF
open Model.Node
open CCFRaft.Proofs.Ledger

variable [Config.InitialConfiguration]

theorem Advance.facts {self : NodeID} {middle state : NodeState}
    (advance : Advance self middle state)
    : state.log = middle.log
      /\ state.currentTerm = middle.currentTerm
      /\ (state.role = middle.role \/ state.role = .none) := by
  rcases advance with ⟨rfl, _⟩ | ⟨log, term, _, _, _, _, _, _, role⟩
  · exact ⟨rfl, rfl, Or.inl rfl⟩
  · exact ⟨log, term, role.imp_right And.left⟩

theorem makeRequestVoteRequest_eq (state : NodeState)
    : makeRequestVoteRequest state = vals state.currentTerm state.log state.commitIndex :=
  rfl

/-- A candidate's own log is up to date for its vote request. -/
theorem vals_upToDate {state : NodeState} (term : Nat)
    (sorted : state.log.Pairwise fun first second => first.term <= second.term)
    (frontier : state.commitIndex <= state.log.length)
    : voteLogUpToDate state (vals term state.log state.commitIndex) := by
  have mono : maxCommittableTerm state.log
      <= termAt state.log (max state.commitIndex (maxCommittableIndex state.log)) :=
    termAt_mono sorted (le_max_right _ _)
      (max_le frontier (maxCommittableIndexBounded state.log))
  rcases Nat.lt_or_eq_of_le mono with lt | eq
  · exact Or.inl lt
  · exact Or.inr ⟨eq.symm, le_max_right _ _⟩

namespace Ctx

variable {nodes : List NodeID} {after before : Model.State}
  {rest : History} (c : Ctx nodes after before rest)

include c

theorem anchors : Everywhere Anchor (before :: rest) := c.all Inv.anchor

theorem monos : Everywhere CanonMono (before :: rest) := c.all Inv.canon_mono

theorem pre_sorted : c.pre.log.Pairwise fun first second => first.term <= second.term :=
  c.inv.sorted c.actor c.pre c.pre_now

/-! ## Accepted AppendEntries -/

/-- An accepted request copies its sender's log up to the end of the batch,
keeping the follower's suffix exactly when the follower already agreed. -/
theorem accept_shape {source : NodeID} {request : AppendEntriesRequest}
    (eq : c.event = .receive source (.appendEntriesRequest request))
    (accepted : Accepted c.pre request c.post)
    : exists earlier sender,
        earlier <:+ before :: rest
        /\ CanonNow earlier source sender request.term
        /\ AEOk source c.actor sender request
        /\ request.prevLogIndex + request.entries.length <= sender.log.length
        /\ c.post.log.take (request.prevLogIndex + request.entries.length)
            = sender.log.take (request.prevLogIndex + request.entries.length)
        /\ (c.post.log = c.pre.log
            \/ (c.post.log
                  = sender.log.take (request.prevLogIndex + request.entries.length)
                /\ Not
                    (c.pre.log.take (request.prevLogIndex + request.entries.length)
                      = sender.log.take (request.prevLogIndex + request.entries.length))))
        /\ c.pre.log.take request.prevLogIndex
            = sender.log.take request.prevLogIndex := by
  obtain ⟨envelope, ok, sourceEq, targetEq, payload⟩ := c.received_ok eq
  simp only [MessageOK, payload] at ok
  obtain ⟨earlier, suffix, sender, canon, aeok⟩ := ok
  rw [sourceEq] at canon aeok
  rw [targetEq] at aeok
  refine ⟨earlier, sender, suffix, canon, aeok, ?_⟩
  obtain ⟨_, _, prevBound, prevTerm, entries, _⟩ := aeok
  obtain ⟨_, _, _, followerBound, termEq, logEq, _⟩ := accepted
  have senderSeen : Seen (before :: rest) source sender := canon.1.seen.mono suffix
  have batchBound : request.prevLogIndex + request.entries.length <= sender.log.length := by
    have := entries.length_le
    simp at this
    omega
  have match' : forall j, 0 < j -> j <= c.pre.log.length -> j <= sender.log.length
      -> termAt c.pre.log j = termAt sender.log j -> c.pre.log.take j = sender.log.take j :=
    fun _ positive left right same =>
      log_matching c.anchors c.monos c.pre_seen senderSeen positive left right same
  have prevAgree : c.pre.log.take request.prevLogIndex = sender.log.take request.prevLogIndex := by
    rcases Nat.eq_zero_or_pos request.prevLogIndex with zero | positive
    · rw [zero, List.take_zero, List.take_zero]
    · exact match' _ positive followerBound prevBound (termEq.trans prevTerm)
  have shape := acceptLog_eq followerBound prevBound prevAgree entries match'
  rw [← logEq] at shape
  refine ⟨batchBound, ?_⟩
  split at shape
  · rename_i agree
    have same : c.post.log = c.pre.log := by
      rw [shape, ← agree, List.take_append_drop]
    rw [same]
    exact ⟨agree, Or.inl rfl, prevAgree⟩
  · rename_i differ
    rw [List.append_nil] at shape
    rw [shape, List.take_take, Nat.min_self]
    exact ⟨rfl, Or.inr ⟨rfl, differ⟩, prevAgree⟩

/-! ## The new log -/

/-- The log after a step: a prefix of the old log, the old log extended by the
leader, or a prefix of a leader log. -/
theorem post_log
    : c.post.log <+: c.pre.log
      \/ (exists entries,
            c.post.log = c.pre.log ++ entries
            /\ (forall entry, entry ∈ entries -> entry.term = c.pre.currentTerm)
            /\ c.pre.role = .primary
            /\ c.post.currentTerm = c.pre.currentTerm
            /\ Not (c.post.role = .candidate))
      \/ (exists earlier source sender n,
            earlier <:+ before :: rest
            /\ CanonNow earlier source sender c.post.currentTerm
            /\ n <= sender.log.length
            /\ c.post.log = sender.log.take n) := by
  cases Summary.kind c.sum with
  | same log _ =>
      rw [log]
      exact Or.inl (List.prefix_refl _)
  | append entries sent leader terms _ advance =>
      obtain ⟨log, term, role⟩ := Advance.facts advance
      refine Or.inr (Or.inl ⟨entries, log, terms, leader, term, ?_⟩)
      rcases role with role | role <;> rw [role] <;> simp [leader]
  | ack _ _ _ _ _ _ advance =>
      obtain ⟨log, _, _⟩ := Advance.facts advance
      rw [log]
      exact Or.inl (List.prefix_refl _)
  | accept source request eq accepted =>
      obtain ⟨earlier, sender, suffix, canon, _, bound, _, same | ⟨fresh, _⟩, _⟩ :=
        c.accept_shape eq accepted
      · rw [same]
        exact Or.inl (List.prefix_refl _)
      · rw [accepted.1] at canon
        exact Or.inr (Or.inr ⟨earlier, source, sender, _, suffix, canon, bound, fresh⟩)
  | elect wins =>
      obtain ⟨_, ⟨_, candidateLog, _⟩, _, log, _⟩ := Wins.facts wins
      rw [log, ← candidateLog]
      exact Or.inl (primaryState_log_prefix _)

/-- Every log stays empty or rooted at the bootstrap configuration. -/
theorem rooted : RootedLogs (after :: before :: rest) := by
  intro node state now
  rcases c.now_after now with ⟨rfl, rfl⟩ | ⟨_, old⟩
  · have preRooted := c.inv.rooted c.actor c.pre c.pre_now
    rcases c.post_log with sub | ⟨entries, log, _, leader, _, _⟩
        | ⟨earlier, source, sender, n, suffix, canon, _, log⟩
    · exact preRooted.prefix sub
    · rw [log]
      exact preRooted.append (c.inv.leader_logs c.actor c.pre c.pre_now leader) entries
    · rw [log]
      obtain ⟨_, _, rfl⟩ := canon.1.nonempty
      exact (c.all Inv.rooted _ suffix (List.cons_ne_nil _ _) source sender canon.1).take n
  · exact c.inv.rooted node state old

/-! ## Log terms and order -/

theorem terms : Terms (after :: before :: rest) := by
  intro node state now entry mem
  rcases c.now_after now with ⟨rfl, rfl⟩ | ⟨_, old⟩
  · have le := c.term_le
    have preTerms := c.inv.terms c.actor c.pre c.pre_now
    rcases c.post_log with sub | ⟨entries, log, terms, _, term, _⟩
        | ⟨earlier, source, sender, n, suffix, canon, _, log⟩
    · exact (preTerms entry (sub.subset mem)).trans le
    · rw [log] at mem
      rcases List.mem_append.mp mem with old | new
      · exact (preTerms entry old).trans le
      · rw [terms entry new]
        exact le
    · rw [log] at mem
      obtain ⟨_, _, rfl⟩ := canon.1.nonempty
      have := c.all Inv.terms _ suffix (List.cons_ne_nil _ _) source sender canon.1 entry
        (List.mem_of_mem_take mem)
      rw [canon.2.1] at this
      exact this
  · exact c.inv.terms node state old entry mem

theorem sorted : Sorted (after :: before :: rest) := by
  intro node state now
  rcases c.now_after now with ⟨rfl, rfl⟩ | ⟨_, old⟩
  · have preTerms := c.inv.terms c.actor c.pre c.pre_now
    rcases c.post_log with sub | ⟨entries, log, terms, _, _, _⟩
        | ⟨earlier, source, sender, n, suffix, canon, _, log⟩
    · exact c.pre_sorted.sublist sub.sublist
    · rw [log, List.pairwise_append]
      refine ⟨c.pre_sorted, ?_, ?_⟩
      · exact List.pairwise_of_forall_mem_list fun first firstMem second secondMem => by
          rw [terms first firstMem, terms second secondMem]
      · intro first firstMem second secondMem
        rw [terms second secondMem]
        exact preTerms first firstMem
    · rw [log]
      obtain ⟨_, _, rfl⟩ := canon.1.nonempty
      exact (c.all Inv.sorted _ suffix (List.cons_ne_nil _ _) source sender canon.1).sublist
        (List.take_sublist _ _)
  · exact c.inv.sorted node state old

theorem post_sorted : c.post.log.Pairwise fun first second => first.term <= second.term :=
  c.sorted c.actor c.post c.post_now

/-! ## Terms and votes over time -/

theorem active : Active (after :: before :: rest) := by
  intro node state now role
  rcases c.now_after now with ⟨rfl, rfl⟩ | ⟨_, old⟩
  · exact c.post_two (Or.inl role)
  · exact c.inv.active node state old role

theorem term_mono : TermMono (after :: before :: rest) := by
  intro node state earlier now seen
  rcases c.now_after now with ⟨rfl, rfl⟩ | ⟨different, old⟩
  · rcases c.seen_after seen with seen | ⟨_, rfl⟩
    · exact (c.inv.term_mono c.actor c.pre earlier c.pre_now seen).trans c.term_le
    · exact le_rfl
  · rcases c.seen_after seen with seen | ⟨same, _⟩
    · exact c.inv.term_mono node state earlier old seen
    · exact absurd same different

theorem vote_record : VoteRecord (after :: before :: rest) := by
  intro node state earlier candidate now seen voted
  rcases c.now_after now with ⟨rfl, rfl⟩ | ⟨different, old⟩
  · rcases c.seen_after seen with seen | ⟨_, rfl⟩
    · have le := c.term_le
      rcases c.inv.vote_record c.actor c.pre earlier candidate c.pre_now seen voted with
        lt | ⟨termEq, keep⟩
      · exact Or.inl (by omega)
      · rcases Nat.lt_or_eq_of_le le with lt | same
        · exact Or.inl (by omega)
        · exact Or.inr ⟨by omega, Summary.vote_keep c.sum same.symm candidate keep⟩
    · exact Or.inr ⟨rfl, voted⟩
  · rcases c.seen_after seen with seen | ⟨same, _⟩
    · exact c.inv.vote_record node state earlier candidate old seen voted
    · exact absurd same different

/-! ## Campaigns -/

/-- The actor's own vote in the step. -/
theorem self_granted {term : Nat} (le : c.pre.currentTerm <= term)
    (termEq : c.post.currentTerm = term) (voted : c.post.votedFor = some c.actor)
    : Granted (after :: before :: rest) c.actor c.actor term
        (vals term c.pre.log c.pre.commitIndex) :=
  ⟨
    after,
    before,
    rest,
    List.suffix_refl _,
    c.pre,
    c.post,
    c.tr.pre_mem,
    c.tr.post_mem,
    le,
    termEq,
    voted,
    vals_upToDate term c.pre_sorted c.frontier_pre
  ⟩

/-- Every vote counted by a campaign was granted for its vote request. -/
theorem campaign_votes {candidate : NodeState}
    (campaign : Campaign c.actor c.pre c.event candidate)
    (termEq : c.post.currentTerm = candidate.currentTerm)
    (votedEq : c.post.votedFor = candidate.votedFor)
    : forall voter,
        voter ∈ candidate.votesGranted
        -> Granted (after :: before :: rest) voter c.actor candidate.currentTerm
            (vals candidate.currentTerm c.pre.log c.pre.commitIndex) := by
  obtain ⟨_, _, _, ⟨_, freshTerm, freshVote, freshVotes, _⟩
    | ⟨preRole, sameTerm, _, more⟩⟩ := campaign
  · intro voter mem
    rw [freshVotes, Finset.mem_singleton] at mem
    subst mem
    exact c.self_granted (by omega) termEq (votedEq.trans freshVote)
  · intro voter mem
    rw [sameTerm]
    rcases more voter mem with old | ⟨response, eq, responseTerm, granted⟩
    · exact ((c.inv.candidate c.actor c.pre c.pre_now preRole).2.2.1 voter old).mono
        c.suffix_tail
    · obtain ⟨envelope, ok, sourceEq, targetEq, payload⟩ := c.received_ok eq
      simp only [MessageOK, payload] at ok
      obtain ⟨request, granted', _, forNow⟩ := ok granted
      rw [targetEq] at forNow
      rw [sourceEq, targetEq, responseTerm] at granted'
      have requestEq := forNow c.pre c.pre_now preRole responseTerm.symm
      rw [makeRequestVoteRequest_eq] at requestEq
      rw [← requestEq] at granted'
      exact granted'.mono c.suffix_tail

/-- A campaign's term is above the bootstrap term. -/
theorem campaign_three {candidate : NodeState}
    (campaign : Campaign c.actor c.pre c.event candidate)
    : 3 <= candidate.currentTerm
      /\ (c.pre.currentTerm < candidate.currentTerm
          \/ (c.pre.currentTerm = candidate.currentTerm /\ c.pre.role = .candidate)) := by
  obtain ⟨_, _, _, ⟨active, freshTerm, _⟩ | ⟨preRole, sameTerm, _⟩⟩ := campaign
  · have := c.pre_two active
    omega
  · have := (c.inv.candidate c.actor c.pre c.pre_now preRole).1
    exact ⟨by omega, Or.inr ⟨sameTerm.symm, preRole⟩⟩

/-- Winning an election records it in the extended history. -/
theorem wins_elect (wins : Wins c.actor c.pre c.event c.post)
    : ElectStep after before rest c.actor c.post.currentTerm c.pre.log
        c.pre.commitIndex := by
  obtain ⟨candidate, campaign, quorum, logEq, termEq, votedEq, _, role, _⟩ := Wins.facts wins
  have ⟨_, candidateLog, candidateCommit, _⟩ := campaign
  obtain ⟨three, termCase⟩ := c.campaign_three campaign
  refine ⟨
    c.pre,
    c.post,
    c.tr.pre_mem,
    c.tr.post_mem,
    rfl,
    rfl,
    c.frontier_pre,
    ?_,
    rfl,
    role,
    ?_,
    by omega,
    candidate.votesGranted,
    quorum,
    ?_
  ⟩
  · rw [termEq]
    exact termCase
  · rw [logEq]
    simp only [primaryState]
    split
    · rw [candidateLog]
      exact take_prefix_take _ (by
        simp only [lastCommittableIndex, candidateLog]
        exact le_max_right _ _)
    · rw [candidateLog]
      exact List.take_prefix _ _
  · intro voter mem
    rw [termEq]
    exact c.campaign_votes campaign termEq votedEq voter mem

/-! ## Leadership and candidacy -/

theorem led_cur : LedCur (after :: before :: rest) := by
  intro node state term now led
  rcases c.now_after now with ⟨rfl, rfl⟩ | ⟨different, old⟩
  · rcases c.led_after led with led | ⟨_, _, step⟩
    · have le := c.term_le
      rcases c.inv.led_cur c.actor c.pre term c.pre_now led with lt | ⟨termEq, role⟩
      · exact Or.inl (by omega)
      · rcases Nat.lt_or_eq_of_le le with lt | same
        · exact Or.inl (by omega)
        · refine Or.inr ⟨by omega, fun candidate => ?_⟩
          obtain ⟨_, _, _, ⟨_, fresh, _⟩ | ⟨preRole, _⟩⟩ := Summary.candidate c.sum candidate
          · omega
          · exact role preRole
    · obtain ⟨_, _, _, _, termEq, role, _⟩ := c.electStep step
      refine Or.inr ⟨termEq.symm, ?_⟩
      rcases role with role | role <;> rw [role] <;> simp
  · exact c.inv.led_cur node state term old (c.led_other different led)

theorem leader_led : LeaderLed (after :: before :: rest) := by
  intro node state now role
  rcases c.now_after now with ⟨rfl, rfl⟩ | ⟨_, old⟩
  · rcases Summary.leader c.sum role with ⟨preRole, termEq⟩ | wins
    · rw [termEq]
      exact (c.inv.leader_led c.actor c.pre c.pre_now preRole).mono c.suffix_tail
    · exact Or.inr ⟨_, _, after, before, rest, List.suffix_refl _, c.wins_elect wins⟩
  · exact (c.inv.leader_led node state old role).mono c.suffix_tail

theorem candidate : Candidate (after :: before :: rest) := by
  intro node state now role
  rcases c.now_after now with ⟨rfl, rfl⟩ | ⟨_, old⟩
  · have campaign := Summary.candidate c.sum role
    have ⟨_, logEq, commitEq, kind⟩ := campaign
    obtain ⟨three, _⟩ := c.campaign_three campaign
    refine ⟨three, ?_, ?_, ?_⟩
    · rcases kind with ⟨_, _, voted, _⟩ | ⟨preRole, _, voted, _⟩
      · exact voted
      · have own := (c.inv.candidate c.actor c.pre c.pre_now preRole).2.1
        rcases voted with voted | none
        · rw [voted, own]
        · rw [own] at none
          cases none
    · intro voter mem
      rw [logEq, commitEq]
      exact c.campaign_votes campaign rfl rfl voter mem
    · rw [logEq, commitEq]
      rcases kind with ⟨_, fresh, _⟩ | ⟨preRole, same, _⟩
      · have := c.inv.commit_backed c.actor c.pre c.pre_now
        rw [fresh, Nat.add_sub_cancel]
        exact this.mono c.suffix_tail
      · rw [same]
        exact (c.inv.candidate c.actor c.pre c.pre_now preRole).2.2.2.mono c.suffix_tail
  · obtain ⟨three, voted, votes, backed⟩ := c.inv.candidate node state old role
    exact ⟨three, voted, fun voter mem => (votes voter mem).mono c.suffix_tail,
      backed.mono c.suffix_tail⟩

theorem elect_backed : ElectBacked (after :: before :: rest) := by
  intro a b r node term log commit suffix step
  rcases List.suffix_cons_iff.mp suffix with same | inner
  · simp only [List.cons.injEq] at same
    obtain ⟨rfl, rfl, rfl⟩ := same
    obtain ⟨_, logEq, commitEq, termCase, _⟩ := c.electStep step
    rw [← logEq, ← commitEq]
    rcases termCase with lt | ⟨same, preRole⟩
    · exact (c.inv.commit_backed c.actor c.pre c.pre_now).weaken (by omega)
    · rw [← same]
      exact (c.inv.candidate c.actor c.pre c.pre_now preRole).2.2.2
  · exact c.inv.elect_backed a b r node term log commit inner step

end Ctx

end CCFRaft.Proofs.Safety
