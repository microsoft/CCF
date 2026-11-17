module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import Consensus.TraceValidation.Proofs.Handlers.VoteTally

@[expose] public section

/-!
# `become_candidate` against the clean `becomeCandidate` (not reviewed)

M_tv's `becomeCandidate` resets the vote records, increments the view, records the self-vote
and, if that alone is a quorum, calls `becomeLeader`; it then asks every other member of the
active configurations for a vote, in string order. The clean `becomeCandidate` grants itself
the vote, elects itself on a quorum, and broadcasts to the other active members in id
order. The orders agree because every member is in the strictly sorted name table
(`inv`'s `members_known` and `names_sorted`), where `names.id` is the position
(`others_eq`).
-/

namespace Consensus.TraceValidation.Proofs.Vote

open Consensus.Model.Node
open Consensus.TraceValidation.Exec
open Consensus.TraceValidation.Proofs.Ae (Hoare)
open Consensus.TraceValidation (Names)
open Consensus.TraceValidation.Proofs.ReplUpdateCommit (Named named_inj absConfig)

/-! ## The name table orders ids as their names -/

theorem pairwise_of_adjacent
    : forall {l : List String},
        (l.zip l.tail).all (fun (x, y) => decide (x < y)) = true -> l.Pairwise (· < ·)
  | [], _ => List.Pairwise.nil
  | [_], _ => List.pairwise_singleton _ _
  | a :: b :: rest, h => by
      simp only [List.tail_cons, List.zip_cons_cons, List.all_cons, Bool.and_eq_true,
        decide_eq_true_eq] at h
      have tail := pairwise_of_adjacent (l := b :: rest) (by simpa using h.2)
      refine List.Pairwise.cons (fun z mz => ?_) tail
      rcases List.mem_cons.mp mz with rfl | mz
      · exact h.1
      · exact String.lt_trans h.1 (List.rel_of_pairwise_cons tail mz)

theorem id_known {names : Names} {x : NodeId} (m : x ∈ names.known)
    : exists h : names.id x < names.known.size, names.known[names.id x] = x := by
  have hs : (names.known.findIdx? (· == x)).isSome = true := by
    rw [Array.findIdx?_isSome, Array.any_eq_true]
    obtain ⟨i, hi, e⟩ := Array.mem_iff_getElem.mp m
    exact ⟨i, hi, by simp [e]⟩
  obtain ⟨i, hi⟩ := Option.isSome_iff_exists.mp hs
  obtain ⟨h, e, -⟩ := Array.findIdx?_eq_some_iff_getElem.mp hi
  have hid : names.id x = i := by simp [Names.id, hi]
  subst hid
  exact ⟨h, by simpa using e⟩

theorem named_of_known {names : Names} {x : NodeId} (m : x ∈ names.known)
    : Named names x := by
  obtain ⟨h, e⟩ := id_known m
  show names.name (names.id x) = x
  simp only [Names.name, Array.getElem?_eq_getElem h, e, Option.getD_some]

theorem id_lt {names : Names} (sorted : names.known.toList.Pairwise (· < ·))
    {x y : NodeId} (mx : x ∈ names.known) (my : y ∈ names.known) (lt : x < y)
    : names.id x < names.id y := by
  obtain ⟨hx, ex⟩ := id_known mx
  obtain ⟨hy, ey⟩ := id_known my
  rcases Nat.lt_trichotomy (names.id x) (names.id y) with h | h | h
  · exact h
  · have : x = y := by rw [← ex, ← ey]; simp only [h]
    subst this
    exact absurd lt (String.lt_irrefl _)
  · have := List.pairwise_iff_getElem.mp sorted (names.id y) (names.id x)
      (by simpa using hy) (by simpa using hx) h
    simp only [Array.getElem_toList, ex, ey] at this
    exact absurd lt (String.lt_asymm this)

theorem pairwise_eraseDups {α : Type} [BEq α] [LawfulBEq α] {R : α -> α -> Prop}
    : forall (n : Nat) (l : List α),
        l.length <= n -> l.Pairwise R -> l.eraseDups.Pairwise fun a b => R a b /\ a ≠ b
  | _, [], _, _ => by simp [List.eraseDups]
  | 0, _ :: _, hl, _ => by simp at hl
  | n + 1, a :: as, hl, h => by
      rw [List.eraseDups_cons]
      have hp := List.pairwise_cons.mp h
      refine List.Pairwise.cons (fun b mb => ?_)
        (pairwise_eraseDups n _ ?_ (hp.2.filter _))
      · rw [List.mem_eraseDups, List.mem_filter] at mb
        refine ⟨hp.1 b mb.1, fun e => ?_⟩
        subst e
        simp at mb
      · have := List.length_filter_le (fun b => !b == a) as
        simp only [List.length_cons] at hl
        omega

/-- The other members of the active configurations, as M_tv lists them. -/
theorem mem_others {v : State} {x : NodeId}
    : x ∈ v.otherNodesInActiveConfigs
      <-> (exists c, c ∈ v.configurations /\ x ∈ c.nodes.map Prod.fst)
          /\ x ≠ v.nodeId := by
  unfold State.otherNodesInActiveConfigs
  rw [List.mem_eraseDups, (List.mergeSort_perm _ _).mem_iff, List.mem_filter, List.mem_flatMap]
  simp

theorem others_sorted {names : Names} {v : State}
    (sorted : names.known.toList.Pairwise (· < ·))
    (known : forall c, c ∈ v.configurations -> forall a, a ∈ c.nodes -> a.1 ∈ names.known)
    : (v.otherNodesInActiveConfigs.map names.id).Pairwise (· < ·) := by
  have sortedS := List.pairwise_mergeSort (le := fun a b : String => decide (a <= b))
    (fun a b c hab hbc => by simp only [decide_eq_true_eq] at *; exact String.le_trans hab hbc)
    (fun a b => by simpa using String.le_total a b)
    ((v.configurations.flatMap (·.nodes.map Prod.fst)).filter (· != v.nodeId))
  have strict := pairwise_eraseDups _ _ (Nat.le_refl _) sortedS
  have isKnown : forall x, x ∈ v.otherNodesInActiveConfigs -> x ∈ names.known := by
    intro x mx
    obtain ⟨⟨c, mc, mx⟩, -⟩ := mem_others.mp mx
    obtain ⟨a, ma, rfl⟩ := List.mem_map.mp mx
    exact known c mc a ma
  rw [List.pairwise_map]
  refine strict.imp_of_mem
    fun {a b} ma mb ⟨le, ne⟩ => id_lt sorted (isKnown a ma) (isKnown b mb) ?_
  simp only [decide_eq_true_eq] at le
  refine Classical.byContradiction fun nlt => ne ?_
  exact String.le_antisymm le (String.not_lt.mp nlt)

theorem mem_members {cs : List Configuration} {n : NodeID}
    : n ∈ configurationMembers cs <-> exists c, c ∈ cs /\ n ∈ c.nodes := by
  unfold configurationMembers
  suffices h : forall (acc : CCF.Finset NodeID),
      n ∈ cs.foldl (fun nodes configuration => nodes ∪ configuration.nodes) acc
        <-> n ∈ acc \/ exists c, c ∈ cs /\ n ∈ c.nodes by
    rw [h]
    simp [CCF.Finset.notMem_empty]
  induction cs with
  | nil => simp
  | cons head tail ih =>
      intro acc
      simp only [List.foldl_cons, ih, CCF.Finset.mem_union, List.mem_cons]
      constructor
      · rintro ((old | new) | ⟨c, member, present⟩)
        · exact Or.inl old
        · exact Or.inr ⟨head, Or.inl rfl, new⟩
        · exact Or.inr ⟨c, Or.inr member, present⟩
      · rintro (old | ⟨c, rfl | member, present⟩)
        · exact Or.inl (Or.inl old)
        · exact Or.inl (Or.inr present)
        · exact Or.inr ⟨c, member, present⟩

/-- M_tv's vote targets are the clean broadcast's, in the same order. -/
theorem others_eq {names : Names} {v : State} {D : List Config}
    (sorted : names.known.toList.Pairwise (· < ·))
    (known : forall c, c ∈ v.configurations -> forall a, a ∈ c.nodes -> a.1 ∈ names.known)
    (selfNamed : Named names v.nodeId)
    (nodesEq : D.map (·.nodes) = v.configurations.map (·.nodes))
    : v.otherNodesInActiveConfigs.map names.id
      = ((configurationMembers (D.map (absConfig names))).erase
          (names.id v.nodeId)).sort := by
  refine CCF.Finset.eq_of_sorted_of_mem_iff (others_sorted sorted known)
    (CCF.Finset.sorted _) fun n => ?_
  have members : forall ns, ns ∈ D.map (·.nodes) <-> ns ∈ v.configurations.map (·.nodes) := by
    rw [nodesEq]; exact fun _ => Iff.rfl
  rw [CCF.Finset.mem_sort, CCF.Finset.mem_erase, mem_members, List.mem_map]
  constructor
  · rintro ⟨y, my, rfl⟩
    obtain ⟨⟨c, mc, myc⟩, ne⟩ := mem_others.mp my
    obtain ⟨c', mc', nodes⟩ := List.mem_map.mp ((members c.nodes).mpr (List.mem_map_of_mem mc))
    obtain ⟨a, ma, rfl⟩ := List.mem_map.mp myc
    refine ⟨fun e => ne (named_inj (known c mc a ma |> named_of_known) selfNamed e), ?_⟩
    refine ⟨absConfig names c', List.mem_map_of_mem mc', ?_⟩
    simp only [absConfig, Names.set, CCF.Finset.mem_ofList, nodes]
    exact List.mem_map_of_mem (List.mem_map_of_mem ma)
  · rintro ⟨ne, _, mx, hn⟩
    obtain ⟨c', mc', rfl⟩ := List.mem_map.mp mx
    simp only [absConfig, Names.set, CCF.Finset.mem_ofList, List.mem_map] at hn
    obtain ⟨y, ⟨a, ma, rfl⟩, rfl⟩ := hn
    obtain ⟨c, mc, nodes⟩ :=
      List.mem_map.mp ((members c'.nodes).mp (List.mem_map_of_mem mc'))
    refine ⟨a.1, mem_others.mpr ⟨⟨c, mc, ?_⟩, fun e => ne (by rw [e])⟩, rfl⟩
    rw [nodes]
    exact List.mem_map_of_mem ma

/-! ## The self-vote -/

theorem tally_reset
    : forall cs : List Config,
        Tally cs (cs.map fun c => (c.idx, [], State.quorum c.nodes.length)) []
  | [] => ⟨rfl, fun _ _ mem => by simp at mem⟩
  | c :: cs => by
      obtain ⟨len, all⟩ := tally_reset cs
      refine ⟨by simp [len], fun r x mem => ?_⟩
      simp only [List.map_cons, List.zip_cons_cons, List.mem_cons, Prod.mk.injEq] at mem
      rcases mem with ⟨rfl, rfl⟩ | mem
      · simp
      · exact all r x mem

/-- A configuration in which the self-vote alone is a quorum has only the node itself. -/
theorem alone_of_quorum {cs : List Config} {votes : List VoteRec} {self : NodeId}
    (t : Tally cs votes [self])
    (q : (votes.all fun r => decide (r.2.1.length >= r.2.2)) = true)
    : forall c, c ∈ cs -> forall x, x ∈ c.nodes.map Prod.fst -> x = self := by
  intro c mc x mx
  obtain ⟨r, mem⟩ := exists_zip_right t.1 c mc
  obtain ⟨-, hq, nd, hm⟩ := t.2 r c mem
  have big := List.all_eq_true.mp q r (List.of_mem_zip mem).1
  simp only [decide_eq_true_eq, hq, State.quorum] at big
  have small : r.2.1.length <= 1 :=
    nd.length_le_of_subset (l₂ := [self]) fun y my => ((hm y).mp my).2
  obtain ⟨w, mw⟩ := List.exists_mem_of_length_pos (l := r.2.1) (by omega)
  have ws := (hm w).mp mw
  have len : (c.nodes.map Prod.fst).length <= 1 := by simp only [List.length_map]; omega
  have hw : w = self := List.mem_singleton.mp ws.2
  subst hw
  match h : c.nodes.map Prod.fst, len, mx, ws.1 with
  | [], _, mx, _ => simp at mx
  | [u], _, mx, mw => rw [List.mem_singleton.mp mx, List.mem_singleton.mp mw]

theorem others_nil {v : State}
    (alone
      : forall c,
          c ∈ v.configurations -> forall x, x ∈ c.nodes.map Prod.fst -> x = v.nodeId)
    : v.otherNodesInActiveConfigs = [] := by
  refine List.eq_nil_iff_forall_not_mem.mpr fun x mx => ?_
  obtain ⟨⟨c, mc, mx⟩, ne⟩ := mem_others.mp mx
  exact ne (alone c mc x mx)

theorem hoare_discard {env : Env} {α : Type} {x : M α} {P : State -> Outbox -> Prop}
    {Q : Unit -> State -> Outbox -> Prop} (h : Hoare env P x fun _ => Q ())
    : Hoare env P (Functor.discard x) Q := by
  have : Hoare env P ((fun _ => PUnit.unit) <$> x) Q := by
    rw [map_eq_pure_bind]
    exact Ae.Hoare.bind h fun _ => Ae.Hoare.pure _ fun _ _ p => p
  exact this

theorem hoare_discard_ex {env : Env} {α : Type} {x : M α} {P : State -> Outbox -> Prop}
    {Q : α -> State -> Outbox -> Prop} (h : Hoare env P x Q)
    : Hoare env P (Functor.discard x) fun _ v o => exists a, Q a v o :=
  hoare_discard (Ae.Hoare.post h fun a _ _ p => ⟨a, p⟩)

/-- The vote request a candidate in state `w` sends. -/
def rvMsg (w : State) : Message :=
  .requestVoteRequest
    {
      term := w.currentView,
      lastCommittableTerm := w.getTerm w.lastCommittable,
      lastCommittableIndex := w.lastCommittable
    }

theorem sendVotes_spec (env : Env) {w : State} {o1 : Outbox} (ids : List NodeId)
    : Hoare env (fun v o => v = w /\ o = o1)
        (forIn ids PUnit.unit
          fun id _ => do
            Exec.sendRequestVote false id
            pure (ForInStep.yield PUnit.unit))
        (fun _ v o =>
          v = w
          /\ o
              = o1
                ++ ids.map
                    fun id =>
                      CCF.Envelope.mk (env.names.id w.nodeId) (env.names.id id)
                        (rvMsg w)) := by
  let f : NodeId -> CCF.Envelope NodeID Message :=
    fun id => CCF.Envelope.mk (env.names.id w.nodeId) (env.names.id id) (rvMsg w)
  refine Ae.Hoare.pre
    (Ae.Hoare.forIn_list _ _ _ (fun pre _ v o => v = w /\ o = o1 ++ pre.map f)
      (fun _ v o => v = w /\ o = o1 ++ ids.map f) ?_ fun _ _ _ p => p)
    fun v o ⟨hv, ho⟩ => ⟨hv, by simp [ho]⟩
  intro pre id rest _ _
  refine Ae.Hoare.pin fun v4 o4 ⟨hv, ho⟩ => ?_
  subst v4 o4
  refine Ae.Hoare.bind (R := fun _ v o => v = w /\ o = o1 ++ (pre ++ [id]).map f) ?_
    fun _ => Ae.Hoare.pure _ fun _ _ p => p
  unfold Exec.sendRequestVote
  refine Ae.Hoare.getV_bind fun s => ?_
  refine Ae.Hoare.pin fun v2 o2 ⟨⟨h1, h2⟩, h3⟩ => ?_
  subst v2 o2 s
  dsimp only
  split
  · keep_step
    exact Ae.Hoare.bind (R := fun _ _ _ => False) (Ae.Hoare.fail _)
      fun _ => Ae.Hoare.false_pre fun _ _ h => h
  · keep_step
    keep_step
    keep_step
    exact Ae.Hoare.send _ _ fun v o ⟨hv, ho⟩ => ⟨hv, by subst hv ho; simp [f, rvMsg]⟩

/-! ## The candidate states -/

/-- The declared state after `becomeCandidate`'s reset and view increment. -/
def candState (d : State) : State :=
  {
    d with
      leadership := .candidate,
      leaderId := none,
      votedFor := some d.nodeId,
      votesForMe :=
        d.configurations.map fun c => (c.idx, [], State.quorum c.nodes.length),
      currentView := d.currentView + 1
  }

/-- The declared state after the self-vote. -/
def candVoted (d : State) : State :=
  { candState d with votesForMe := recorded d.nodeId (candState d) }

/-- The clean candidate before `electIfQuorum`. -/
def cleanCand (self : NodeID) (c : NodeState) : NodeState :=
  {
    c with
      role := .candidate
      currentTerm := c.currentTerm + 1
      votedFor := some self
      primaryKnown := false
      votesGranted := {self}
      preVotesGranted := ∅
  }

theorem emits_becomeCandidate {self : NodeID} {c s : NodeState}
    {first : List (CCF.Envelope NodeID Message)}
    (h
      : Emits (electIfQuorum (CCF.Capabilities.record self) self (cleanCand self c)) s
          first)
    : Emits (Model.Node.becomeCandidate (CCF.Capabilities.record self) c self) s
        (first
          ++ (((cleanCand self c).activeMembers.erase self).sort.map
                fun p =>
                  ⟨
                    self,
                    p,
                    .requestVoteRequest (makeRequestVoteRequest (cleanCand self c))
                  ⟩)) := by
  unfold Model.Node.becomeCandidate broadcastToOthers
  refine emits_congr (emits_bind h (emits_bind (emits_bind (emits_forIn _ _) (emits_pure _))
    (emits_pure _))) rfl ?_
  simp only [List.append_nil]
  rfl

/-- A node with a ledger has exactly the clean eligible peers (`inv`'s `peers` conjuncts). -/
theorem peers_of_inv {names : Names} {d : State} (h : inv names d = true)
    (L0 : 0 < d.lastIdx)
    : d.allOtherNodes.map (fun x => names.id x.1)
      = (eligiblePeers (abs names d) (names.id d.nodeId)).sort := by
  have p1 : (d.lastIdx == 0 || d.leadership == .none
      || d.allOtherNodes.map (fun (id, _) => names.id id)
        == (eligiblePeers (abs names d) (names.id d.nodeId)).sort) = true := by
    inv_conj h "peers"
  have p2 : (d.lastIdx == 0 || d.leadership != .none
      || d.allOtherNodes.map (fun (id, _) => names.id id)
        == (eligiblePeers (abs names d) (names.id d.nodeId)).sort) = true := by
    inv_conj h "peers_without_role"
  have L0' : d.lastIdx ≠ 0 := by omega
  simp only [Bool.or_eq_true, beq_iff_eq, bne_iff_ne, ne_eq, L0', false_or] at p1 p2
  by_cases r : d.leadership = .none
  · simpa [r] using p2
  · simpa [r] using p1

theorem leaderPre_cand {names : Names} {e : State} (h : inv names e = true)
    (L0 : 0 < e.lastIdx)
    : LeaderPre names (candVoted e) := by
  obtain ⟨s1, s2, s3, s4, s5, s6, -⟩ := inv_parts h
  have vle : e.views.all (· <= e.lastIdx + 1) = true := by inv_conj h "views_le_last"
  have ret : e.isRetiredCommitted
      = decide ((abs names e).isRetiredCommitted (names.id e.nodeId)) := by
    have hc : (e.isRetiredCommitted
        == decide ((abs names e).isRetiredCommitted (names.id e.nodeId))) = true := by
      inv_conj h "retired_committed"
    simpa using hc
  refine ⟨
    by simp [candVoted, candState],
    by simp only [candVoted, candState]; omega,
    fun x hx => ?_,
    s1,
    s2,
    s3,
    s4,
    s5,
    ret,
    Or.inr ?_
  ⟩
  · have := Array.all_eq_true_iff_forall_mem.mp vle x (by simpa [candVoted, candState] using hx)
    simpa [candVoted, candState] using this
  · rw [eligiblePeers_congr (a := abs names (candVoted e)) (b := abs names e) rfl rfl]
    exact peers_of_inv (d := e) h L0

/-- The name table is strictly sorted once the node knows a configuration. -/
theorem known_sorted {names : Names} {d : State} (h : inv names d = true)
    (ne : d.configurations ≠ [])
    : names.known.toList.Pairwise (· < ·) := by
  have hc : ((d.configurations.isEmpty && d.allOtherNodes.isEmpty)
      || (names.known.toList.zip names.known.toList.tail).all fun (x, y) => decide (x < y))
      = true := by
    inv_conj h "names_sorted"
  have : d.configurations.isEmpty = false := by simpa using ne
  rw [this, Bool.false_and, Bool.false_or] at hc
  exact pairwise_of_adjacent hc

theorem members_known {names : Names} {d : State} (h : inv names d = true)
    : forall c, c ∈ d.configurations -> forall a, a ∈ c.nodes -> a.1 ∈ names.known := by
  have hc : (d.configurations.flatMap (·.nodes.map Prod.fst)).all names.known.contains = true := by
    inv_conj h "members_known"
  intro c mc a ma
  have := List.all_eq_true.mp hc a.1
    (List.mem_flatMap.mpr ⟨c, mc, List.mem_map_of_mem ma⟩)
  simpa using this

theorem set_single {names : Names} (x : NodeId) : names.set [x] = {names.id x} :=
  CCF.Finset.ext fun a => by simp [Names.set, CCF.Finset.mem_singleton]

/-- The vote-request broadcast that ends `becomeCandidate`. -/
theorem votesTail (env : Env) {w : State} {o1 : Outbox}
    {Q : Unit -> State -> Outbox -> Prop}
    (q
      : Q () w
          (o1
            ++ w.otherNodesInActiveConfigs.map
                fun id =>
                  CCF.Envelope.mk (env.names.id w.nodeId) (env.names.id id) (rvMsg w)))
    : Hoare env (fun v o => v = w /\ o = o1)
        (do
          let l ← Exec.getV
          forIn l.otherNodesInActiveConfigs PUnit.unit
            fun id _ => do
              Exec.sendRequestVote false id
              pure (ForInStep.yield PUnit.unit)
          pure ()) Q := by
  refine Ae.Hoare.getV_bind fun s => ?_
  refine Ae.Hoare.pin fun v1 o2 ⟨⟨hv, ho⟩, hs⟩ => ?_
  subst s
  subst v1 o2
  refine Ae.Hoare.bind (sendVotes_spec env _) fun _ => Ae.Hoare.pure _ fun v o ⟨hv, ho⟩ => ?_
  subst v o
  exact q

/--
`becomeCandidate` from a node `e` with a ledger and an active configuration, whatever its vote
records: it ends as the clean `becomeCandidate` from any clean state with `e`'s term, log, commit
index, follower flag and retirement latch, having sent the same messages.
-/
theorem becomeCandidate_spec (env : Env) {c : NodeState} {e : State} {X : List VoteRec}
    {o0 : Outbox} (h : inv env.names e = true) (L0 : 0 < e.lastIdx)
    (ne : e.configurations ≠ [])
    (ht : c.currentTerm = e.currentView) (hl : c.log = (abs env.names e).log)
    (hc : c.commitIndex = e.commitIdx) (hnf : c.isNewFollower = e.isNewFollower)
    (hrc : c.retiredCommittedIndex = e.retiredCommittedIdx)
    (unmatched : UnnamedUnmatched (env.names.id e.nodeId) c)
    : Hoare env (fun v o => v = { e with votesForMe := X } /\ o = o0) Exec.becomeCandidate
        (fun _ v o =>
          exists sends,
            o = o0 ++ sends
            /\ v.nodeId = e.nodeId
            /\ (inv env.names v = true
                -> exists c',
                    Emits
                      (Model.Node.becomeCandidate
                        (CCF.Capabilities.record (env.names.id e.nodeId)) c
                        (env.names.id e.nodeId))
                      c' sends
                    /\ agrees env.names c' v = true
                    /\ UnnamedUnmatched (env.names.id e.nodeId) c'
                    /\ forall m, m ∈ sends -> msgInv env.names m = true)) := by
  have hy := ReplUpdateCommit.Hyps.ofInv h
  obtain ⟨D, hD, sh⟩ := hy.configs L0
  have sorted := hy.sorted L0
  have t3 : Tally e.configurations (recorded e.nodeId (candState e)) [e.nodeId] :=
    tally_record e.nodeId (tally_reset e.configurations) sorted
  have quorum : (!e.configurations.isEmpty
        && (recorded e.nodeId (candState e)).all fun r => decide (r.2.1.length >= r.2.2))
      = decide (hasQuorum (D.map (absConfig env.names)) {env.names.id e.nodeId}) := by
    rw [← set_single]
    exact quorum_tally t3 hy.membersNamed
      (fun w mw => by rw [List.mem_singleton.mp mw]; exact hy.selfNamed) hy.distinct
      (shifted_nodes sh)
  have votes : (abs env.names (candVoted e)).votesGranted = {env.names.id e.nodeId} := by
    rw [← set_single]
    show env.names.set (voters (candVoted e)) = _
    apply set_congr
    intro x
    have := mem_flat_tally (x := x) t3
    simp only [voters, candVoted, candState, List.mem_cons, List.not_mem_nil, or_false]
      at this ⊢
    rw [this]
    constructor
    · rintro (e | ⟨e, -⟩) <;> exact e
    · exact Or.inl
  have active : (cleanCand (env.names.id e.nodeId) c).activeConfigurations
      = D.map (absConfig env.names) := by
    show activeConfigurations c.log c.commitIndex = _
    rw [hl, hc]
    exact hD
  have ag3 : agrees env.names (cleanCand (env.names.id e.nodeId) c) (candVoted e) = true := by
    have tp : trackedPeers env.names (candVoted e) = [] := by
      simp [trackedPeers, candVoted, candState]
    have e2 : (abs env.names (candVoted e)).currentTerm = c.currentTerm + 1 := by
      show e.currentView + 1 = _
      rw [ht]
    have e3 : (abs env.names (candVoted e)).log = c.log := hl.symm
    have e4 : (abs env.names (candVoted e)).commitIndex = c.commitIndex := hc.symm
    have e6 : (abs env.names (candVoted e)).isNewFollower = c.isNewFollower := hnf.symm
    have e11 : (abs env.names (candVoted e)).retiredCommittedIndex = c.retiredCommittedIndex :=
      hrc.symm
    simp only [agrees, tp, List.all_nil, e2, e3, e4, e6, e11, votes]
    simp [cleanCand, abs, absRole, candVoted, candState]
  obtain ⟨-, s2, s3, -⟩ := inv_parts h
  have bounds := lastCommittable_bounds s2 s3
  have lci : lastCommittableIndex (cleanCand (env.names.id e.nodeId) c) = e.lastCommittable := by
    show max c.commitIndex (maxCommittableIndex c.log) = _
    rw [hc, hl, ← lastCommittable_eq h]
    exact Nat.max_eq_right bounds.1
  have msg : rvMsg (candVoted e)
      = .requestVoteRequest (makeRequestVoteRequest (cleanCand (env.names.id e.nodeId) c)) := by
    simp only [rvMsg, makeRequestVoteRequest, lastCommittableTerm, lci]
    show Message.requestVoteRequest
        { term := e.currentView + 1, lastCommittableTerm := e.getTerm e.lastCommittable,
          lastCommittableIndex := e.lastCommittable } = _
    rw [getTerm_eq h]
    simp only [cleanCand, ht, hl]
  have bcast : (candVoted e).otherNodesInActiveConfigs.map env.names.id
      = ((cleanCand (env.names.id e.nodeId) c).activeMembers.erase (env.names.id e.nodeId)).sort := by
    rw [others_eq (v := candVoted e) (known_sorted h ne) (members_known (d := e) h) hy.selfNamed
      (shifted_nodes sh)]
    show _ = ((configurationMembers (cleanCand _ c).activeConfigurations).erase _).sort
    rw [active]
    rfl
  have rvInv : forall id, id ∈ (candVoted e).otherNodesInActiveConfigs
      -> msgInv env.names
        ⟨env.names.id e.nodeId, env.names.id id, rvMsg (candVoted e)⟩ = true := by
    intro id mid
    obtain ⟨⟨x, mx, ma⟩, ne'⟩ := mem_others.mp mid
    obtain ⟨a, ma2, rfl⟩ := List.mem_map.mp ma
    have named := named_of_known (members_known h x mx a ma2)
    have neq : env.names.id e.nodeId ≠ env.names.id a.1 :=
      fun same => ne' (named_inj hy.selfNamed named same).symm
    have self := hy.selfNamed
    simp only [Named] at self
    simp [msgInv, rvMsg, self, neq]
  have um3 : UnnamedUnmatched (env.names.id e.nodeId) (cleanCand (env.names.id e.nodeId) c) :=
    unmatched_frame unmatched fun hp => absurd hp (by simp [cleanCand])
  have sendsEq : ((cleanCand (env.names.id e.nodeId) c).activeMembers.erase
        (env.names.id e.nodeId)).sort.map (fun p =>
          (⟨env.names.id e.nodeId, p, .requestVoteRequest
            (makeRequestVoteRequest (cleanCand (env.names.id e.nodeId) c))⟩
            : CCF.Envelope NodeID Message))
      = (candVoted e).otherNodesInActiveConfigs.map fun id =>
          CCF.Envelope.mk (env.names.id (candVoted e).nodeId) (env.names.id id) (rvMsg (candVoted e)) := by
    rw [← bcast, List.map_map, msg]
    rfl
  have stay : Not ((cleanCand (env.names.id e.nodeId) c).role = .candidate
        /\ hasQuorum (cleanCand (env.names.id e.nodeId) c).activeConfigurations
          (cleanCand (env.names.id e.nodeId) c).votesGranted
        /\ Not ((cleanCand (env.names.id e.nodeId) c).isRetiredCommitted (env.names.id e.nodeId)))
      -> Emits (Model.Node.becomeCandidate (CCF.Capabilities.record (env.names.id e.nodeId)) c
            (env.names.id e.nodeId)) (cleanCand (env.names.id e.nodeId) c)
          ((candVoted e).otherNodesInActiveConfigs.map fun id =>
            CCF.Envelope.mk (env.names.id (candVoted e).nodeId) (env.names.id id)
              (rvMsg (candVoted e))) := by
    intro no
    have := emits_becomeCandidate (first := [])
      (show Emits (electIfQuorum (CCF.Capabilities.record (env.names.id e.nodeId))
        (env.names.id e.nodeId) (cleanCand (env.names.id e.nodeId) c))
        (cleanCand (env.names.id e.nodeId) c) [] by
          unfold electIfQuorum
          simp only [no, ↓reduceIte]
          exact emits_pure _)
    rw [List.nil_append, sendsEq] at this
    exact this
  unfold Exec.becomeCandidate
  refine Ae.Hoare.getV_bind fun s => ?_
  refine Ae.Hoare.pin fun v1 o1 ⟨⟨hv, ho⟩, hs⟩ => ?_
  subst s
  subst v1 o1
  refine Ae.Hoare.ite (fun he => absurd (List.isEmpty_iff.mp he) ne) fun _ => ?_
  refine Ae.Hoare.bind
    (Ae.Hoare.setV _
      (Q :=
        fun _ v o =>
          v
            = {
              e with
                votesForMe := X
                leadership := .candidate
                leaderId := none
                votedFor := some e.nodeId
            }
          /\ o = o0) fun v o ⟨hv, ho⟩ => ⟨by subst hv; rfl, ho⟩)
    fun _ => ?_
  refine Ae.Hoare.bind
    (Ae.Hoare.setV _
      (Q := fun _ v o => v = { candState e with currentView := e.currentView } /\ o = o0)
      fun v o ⟨hv, ho⟩ => ⟨by subst hv; rfl, ho⟩)
    fun _ => ?_
  refine Ae.Hoare.bind
    (Ae.Hoare.setV _ (Q := fun _ v o => v = candState e /\ o = o0)
      fun v o ⟨hv, ho⟩ => ⟨by subst hv; rfl, ho⟩)
    fun _ => ?_
  keep_step
  refine Ae.Hoare.getV_bind fun s => ?_
  refine Ae.Hoare.pin fun v1 o1 ⟨⟨hv, ho⟩, hs⟩ => ?_
  subst s
  subst v1 o1
  refine Ae.Hoare.bind (recordVote_spec env (candState e).nodeId (candState e) o0)
    fun b => ?_
  refine Ae.Hoare.pin fun v1 o1 ⟨hb, hv, ho⟩ => ?_
  subst v1 o1 b
  dsimp only
  refine Ae.Hoare.ite (fun hq => ?_) fun hq => ?_
  · have qd : decide (hasQuorum (D.map (absConfig env.names)) {env.names.id e.nodeId}) = true := by
      rw [← quorum]; exact hq
    have q2 : ((recorded e.nodeId (candState e)).all fun r => decide (r.2.1.length >= r.2.2))
        = true := ((Bool.and_eq_true _ _).mp hq).2
    have alone := alone_of_quorum t3 q2
    have none3 : (candVoted e).otherNodesInActiveConfigs = [] := others_nil alone
    refine Ae.Hoare.bind (hoare_discard_ex
      (becomeLeader_spec (d := candVoted e) env (leaderPre_cand h L0) ag3))
      fun _ => Ae.Hoare.pin fun v1 o1 ⟨b, p⟩ => ?_
    rcases p with ⟨hr, -, hv, ho⟩ | ⟨hr, -, sends, ho, wn, -, -, sub, cl⟩
    · subst v1 o1
      refine votesTail env ⟨_, rfl, rfl, fun _ => ⟨_, stay fun ⟨_, _, n⟩ => n hr, ag3, um3,
        fun m mm => ?_⟩⟩
      obtain ⟨id, mid, rfl⟩ := List.mem_map.mp mm
      exact rvInv id mid
    · subst o1
      have none1 : v1.otherNodesInActiveConfigs = [] :=
        others_nil fun x mx y my => wn ▸ alone x (sub x mx) y my
      refine votesTail env ⟨sends, by rw [none1, List.map_nil, List.append_nil], wn,
        fun hinv => ?_⟩
      obtain ⟨em, ag, mi⟩ := cl hinv
      have elect := emits_becomeCandidate (first := sends)
        (show Emits (electIfQuorum (CCF.Capabilities.record (env.names.id e.nodeId))
          (env.names.id e.nodeId) (cleanCand (env.names.id e.nodeId) c))
          (primaryState (cleanCand (env.names.id e.nodeId) c)) sends by
            unfold electIfQuorum
            have yes : (cleanCand (env.names.id e.nodeId) c).role = .candidate
                /\ hasQuorum (cleanCand (env.names.id e.nodeId) c).activeConfigurations
                  (cleanCand (env.names.id e.nodeId) c).votesGranted
                /\ Not ((cleanCand (env.names.id e.nodeId) c).isRetiredCommitted
                  (env.names.id e.nodeId)) :=
              ⟨rfl, by rw [active]; exact of_decide_eq_true qd, hr⟩
            rw [ite_eq_left yes]
            exact em)
      rw [sendsEq, none3, List.map_nil, List.append_nil] at elect
      exact ⟨_, elect, ag, unmatched_primaryState _ _, mi⟩
  · have qd : Not (hasQuorum (D.map (absConfig env.names)) {env.names.id e.nodeId}) := by
      intro hq'
      exact hq (quorum.trans (decide_eq_true hq'))
    refine votesTail env ⟨_, rfl, rfl, fun _ => ⟨_, stay fun ⟨_, hq', _⟩ => qd ?_, ag3, um3,
      fun m mm => ?_⟩⟩
    · rw [active] at hq'; exact hq'
    · obtain ⟨id, mid, rfl⟩ := List.mem_map.mp mm
      exact rvInv id mid

end Consensus.TraceValidation.Proofs.Vote
