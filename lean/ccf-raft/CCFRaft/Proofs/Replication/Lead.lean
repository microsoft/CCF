module

public import CCFRaft.Proofs.Safety.Flow
public import CCFRaft.Proofs.Replication.Basic

@[expose] public section

set_option linter.unusedSectionVars false

/-!
# The primary of a term in an execution history

Safety facts about other logs and queued requests, stated against the current
log of the primary of a term: requests of that term carry slices of it, follower
logs that agree on a term agree on the whole prefix, and commit and match
indices lie within the agreeing prefix.
-/

namespace CCFRaft.Proofs.Replication

open CCF CCF.MultiNodeTransitionSystem
open Model.Node
open CCFRaft.Proofs.Config
open CCFRaft.Proofs.Safety

variable [Config.InitialConfiguration]

/-! ## Logs of any node -/

section Logs

variable {history : History} (inv : Inv history) {node : NodeID} {state : NodeState}
  (now : Now history node state)

include inv now

theorem entry_le_term {entry : Entry} (member : entry ∈ state.log)
    : entry.term <= state.currentTerm :=
  inv.terms node state now entry member

theorem termAt_le_term (index : Nat) : termAt state.log index <= state.currentTerm := by
  rcases Nat.eq_zero_or_pos index with rfl | positive
  · rw [termAt_zero]
    exact Nat.zero_le _
  rcases Nat.lt_or_ge state.log.length index with beyond | bound
  · rw [termAt_of_length_lt beyond]
    exact Nat.zero_le _
  rw [termAt_eq positive bound]
  exact entry_le_term inv now (List.getElem_mem _)

/-- Every position of a log has a positive term, from the bootstrap entry. -/
theorem termAt_pos {index : Nat} (positive : 0 < index)
    (bound : index <= state.log.length)
    : 0 < termAt state.log index := by
  have first := termAt_mono (inv.sorted node state now) positive bound
  rcases inv.rooted node state now with empty | head
  · rw [empty] at bound
    simp at bound
    omega
  · have : termAt state.log 1 = GENESIS.term := by
      rw [← termAt_take (log := state.log) (le_refl 1), head]
      rfl
    rw [this] at first
    simp only [Model.BOOTSTRAP_TERM] at first
    omega

end Logs

/-- `leader` is the primary of `term` with `state` at the head of an execution. -/
structure Lead (nodes : List NodeID) (history : History) (leader : NodeID) (term : Nat)
    (state : NodeState)
    : Prop where
  exec : Exec nodes history
  now : Now history leader state
  primary : state.role = .primary
  term : state.currentTerm = term

namespace Lead

variable {nodes : List NodeID} {history : History} {leader : NodeID} {term : Nat}
  {state : NodeState} (lead : Lead nodes history leader term state)

include lead

theorem nonempty : Not (history = []) := by
  rintro rfl
  exact lead.now

theorem inv : Inv history :=
  good_of_exec lead.exec _ (List.suffix_refl _) lead.nonempty

theorem led : Led history leader term := by
  rw [← lead.term]
  exact lead.inv.leader_led leader state lead.now lead.primary

/-- Nobody else leads the term. -/
theorem unique {node : NodeID} (led : Led history node term) : node = leader :=
  lead.inv.election_safety node leader term led lead.led

theorem canonNow : CanonNow history leader state term :=
  ⟨lead.now, lead.term, by simp [lead.primary], lead.led⟩

theorem self_canon : Canon history term state.log :=
  ⟨history, List.suffix_refl _, leader, state, lead.canonNow, rfl⟩

/-- Every leader log of the term is a prefix of the current one. -/
theorem canon {log : List Entry} (canon : Canon history term log)
    : log <+: state.log := by
  have led : Led history leader state.currentTerm := by
    rw [lead.term]
    exact lead.led
  have := (lead.inv.canon_mono leader state lead.now (by simp [lead.primary]) led).1
  rw [lead.term] at this
  exact this log canon

theorem termAt_le (index : Nat) : termAt state.log index <= term :=
  lead.term ▸ termAt_le_term lead.inv lead.now index

theorem sorted : state.log.Pairwise fun first second => first.term <= second.term :=
  lead.inv.sorted leader state lead.now

/-- A queued AppendEntries request of the term is a slice of the primary's log. -/
theorem request {envelope : Model.Envelope} (pending : Pending history envelope)
    {request : AppendEntriesRequest}
    (payload : envelope.payload = .appendEntriesRequest request)
    (current : request.term = term)
    : envelope.source = leader
      /\ Not (envelope.target = leader)
      /\ request.prevLogIndex <= state.log.length
      /\ request.prevLogTerm = termAt state.log request.prevLogIndex
      /\ request.entries <+: state.log.drop request.prevLogIndex := by
  have ok := lead.inv.messages envelope pending
  unfold MessageOK at ok
  rw [payload] at ok
  obtain ⟨earlier, suffix, sender, canonNow, different, _, prevBound, prevTerm, entries, _⟩ := ok
  rw [current] at canonNow
  have source := lead.unique (canonNow.2.2.2.mono suffix)
  have sub : sender.log <+: state.log :=
    lead.canon ⟨earlier, suffix, envelope.source, sender, canonNow, rfl⟩
  refine ⟨
    source,
    by rw [← source]; exact different,
    prevBound.trans sub.length_le,
    ?_,
    ?_
  ⟩
  · rw [prevTerm, termAt_of_prefix sub prevBound]
  · obtain ⟨tail, eq⟩ := sub
    rw [← eq, List.drop_append_of_le_length prevBound]
    exact entries.trans (List.prefix_append _ _)

/-- A log agreeing with the primary's on the term at a position agrees up to it. -/
theorem matching {node : NodeID} {other : NodeState} (seen : Seen history node other)
    {index : Nat} (positive : 0 < index) (bound : index <= other.log.length)
    (leaderBound : index <= state.log.length)
    (same : termAt other.log index = termAt state.log index)
    : other.log.take index = state.log.take index :=
  log_matching ((good_of_exec lead.exec).everywhere Inv.anchor)
    ((good_of_exec lead.exec).everywhere Inv.canon_mono) seen lead.now.seen positive bound
    leaderBound same

/-- A node of the term or older commits only entries the primary has. -/
theorem commit_le {node : NodeID} {other : NodeState} (now : Now history node other)
    (le : other.currentTerm <= term)
    : other.commitIndex <= agree other.log state.log := by
  have bound := now.seen.commit_le lead.exec
  rcases lead.inv.commit_backed node other now with zero | ⟨earlier, part, committed,
      termLe, within⟩
  · rw [zero]
    exact Nat.zero_le _
  have inLeader : part <+: state.log := by
    rcases Nat.lt_or_ge earlier term with lt | ge
    · exact committed_in_canon lead.inv.completeness
        ((good_of_exec lead.exec).everywhere Inv.canon_mono) committed lead.self_canon lt
    · have : earlier = term := by omega
      subst this
      obtain ⟨current, rest, leader', state', _, index, suffix, commitStep, partEq, _⟩ :=
        committed.shape
      rw [partEq]
      exact (List.take_prefix _ _).trans
        (lead.canon ⟨current :: rest, suffix, leader', state', commitStep.1, rfl⟩)
  have sub := within.trans inLeader
  have length : (other.log.take other.commitIndex).length = other.commitIndex := by
    simp only [List.length_take]
    omega
  refine le_agree _ _ _ bound (by have := sub.length_le; omega) ?_
  rw [take_eq_of_prefix sub (le_of_eq length.symm), List.take_take, Nat.min_self]

/-- The primary's match index for a peer of its term is within their agreeing prefix. -/
theorem match_le {peer : NodeID} {other : NodeState} (different : Not (peer = leader))
    (now : Now history peer other) (termEq : other.currentTerm = term)
    : state.matchIndex peer <= agree other.log state.log := by
  obtain ⟨held, bound⟩ := match_held lead.inv (keep_of_exec lead.exec) lead.now lead.primary
    different now (termEq.trans lead.term.symm)
  have leaderBound : state.matchIndex peer <= state.log.length := by
    rcases Nat.eq_zero_or_pos (state.matchIndex peer) with zero | pos
    · omega
    obtain ⟨_, log, _, _, canon, within, _⟩ :=
      lead.inv.match_ack leader state peer lead.now lead.primary different pos
    rw [lead.term] at canon
    exact within.trans (lead.canon canon).length_le
  refine le_agree _ _ _ bound leaderBound ?_
  have length : (state.log.take (state.matchIndex peer)).length = state.matchIndex peer := by
    simp only [List.length_take]
    omega
  rw [take_eq_of_prefix held (le_of_eq length.symm), List.take_take, Nat.min_self]

/-- A settled node of the term holds a prefix of the primary's log. -/
theorem settled_prefix {node : NodeID} {other : NodeState} (now : Now history node other)
    (settled : Settled other) (termEq : other.currentTerm = term)
    : other.log <+: state.log := by
  rcases noJunk_of_exec lead.exec node other now settled with empty | ⟨log, canon, held⟩
  · rw [empty]
    exact List.nil_prefix
  · rw [termEq] at canon
    exact held.trans (lead.canon canon)

end Lead

end CCFRaft.Proofs.Replication
