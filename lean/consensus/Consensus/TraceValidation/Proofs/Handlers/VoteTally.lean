module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import Consensus.TraceValidation.Proofs.Handlers.VoteBecomeLeader

@[expose] public section

/-!
# Vote tallies: `record_vote` against the clean votes granted (not reviewed)
-/

namespace Consensus.TraceValidation.Proofs.Vote

open Consensus.Model.Node
open Consensus.TraceValidation.Exec
open Consensus.TraceValidation.Proofs.Ae (Hoare)
open Consensus.TraceValidation (Names)
open Consensus.TraceValidation.Proofs.ReplUpdateCommit (Named named_inj absConfig)

/-- A vote record: configuration index, votes, quorum. -/
abbrev VoteRec := Nat × List NodeId × Nat

def addVote (from_ : NodeId) (vs : List NodeId) : List NodeId :=
  if vs.contains from_ then vs else vs ++ [from_]

/-- One iteration of `record_vote`'s loop. -/
def voteStep (from_ : NodeId) (votes : List VoteRec) (c : Config) : List VoteRec :=
  if c.nodes.any (·.1 == from_) then
    match votes.find? (·.1 == c.idx) with
    | some _ =>
        votes.map
          fun (i, vs, q) => if i == c.idx then (i, addVote from_ vs, q) else (i, vs, q)
    | none => (votes ++ [(c.idx, [from_], 0)]).mergeSort (fun a b => a.1 <= b.1)
  else
    votes

/-- The vote records after `record_vote from_`. -/
def recorded (from_ : NodeId) (v : State) : List VoteRec :=
  v.configurations.foldl (voteStep from_) v.votesForMe

theorem recordVote_spec (env : Env) (from_ : NodeId) (v0 : State) (o0 : Outbox)
    : Hoare env (fun v o => v = v0 /\ o = o0) (Exec.recordVote from_)
        (fun b v o =>
          b
            = (!v0.configurations.isEmpty
                && (recorded from_ v0).all fun (_, vs, q) => decide (vs.length >= q))
          /\ v = { v0 with votesForMe := recorded from_ v0 }
          /\ o = o0) := by
  unfold Exec.recordVote
  refine Ae.Hoare.getV_bind fun s => ?_
  refine Ae.Hoare.pin fun v1 o1 ⟨⟨hv, ho⟩, hs⟩ => ?_
  subst s
  subst v1 o1
  split
  · rename_i he
    refine Ae.Hoare.pure _ fun v o ⟨hv, ho⟩ => ⟨by simp [he], ?_, ho⟩
    have : recorded from_ v0 = v0.votesForMe := by
      simp only [List.isEmpty_iff] at he
      simp [recorded, he]
    rw [this, hv]
  · refine Ae.Hoare.bind (Ae.Hoare.pre (Ae.Hoare.forIn_list _ _ _
      (fun pre b v o => v = v0 /\ o = o0 /\ b = pre.foldl (voteStep from_) v0.votesForMe)
      (fun b v o => v = v0 /\ o = o0 /\ b = recorded from_ v0) ?_ fun _ _ _ p => p)
      fun v o ⟨hv, ho⟩ => ⟨hv, ho, rfl⟩) ?_
    · intro pre c rest b hl
      dsimp only
      split <;> rename_i hc <;> refine Ae.Hoare.pure _ fun v o ⟨hv, ho, hb⟩ => ⟨hv, ho, ?_⟩ <;>
        simp only [List.foldl_append, List.foldl_cons, List.foldl_nil, ← hb, voteStep, addVote,
          hc] <;> rfl
    · rename_i he
      intro b
      refine Ae.Hoare.bind (R := fun _ v o =>
          v = { v0 with votesForMe := recorded from_ v0 } /\ o = o0 /\ b = recorded from_ v0)
        (Ae.Hoare.setV _ fun v o ⟨hv, ho, hb⟩ => ⟨by rw [hv, hb], ho, hb⟩) fun _ => ?_
      exact Ae.Hoare.pure _ fun v o ⟨hv, ho, hb⟩ => ⟨by simp [he, hb], hv, ho⟩

/-- A record after the loop: its votes gain `from_` if a configuration at its index has it. -/
def addIf (from_ : NodeId) (cs : List Config) (r : VoteRec) : VoteRec :=
  if cs.any (fun c => c.idx == r.1 && c.nodes.any (·.1 == from_)) then
    (r.1, addVote from_ r.2.1, r.2.2)
  else
    r

theorem addVote_addVote (from_ : NodeId) (vs : List NodeId)
    : addVote from_ (addVote from_ vs) = addVote from_ vs := by
  unfold addVote
  split
  · simp_all
  · simp

theorem mem_addVote {from_ x : NodeId} {vs : List NodeId}
    : x ∈ addVote from_ vs <-> x = from_ \/ x ∈ vs := by
  unfold addVote
  split
  · rename_i h
    simp only [List.contains_iff_mem] at h
    constructor
    · exact Or.inr
    · rintro (rfl | h')
      · exact h
      · exact h'
  · simp [or_comm]

theorem nodup_addVote {from_ : NodeId} {vs : List NodeId} (h : vs.Nodup)
    : (addVote from_ vs).Nodup := by
  unfold addVote
  split
  · exact h
  · rename_i hc
    simp only [List.contains_iff_mem] at hc
    exact List.nodup_append.mpr ⟨h, List.nodup_cons.mpr ⟨List.not_mem_nil, List.nodup_nil⟩, fun a ha b hb => by
      simp only [List.mem_singleton] at hb
      subst hb
      exact fun e => hc (e ▸ ha)⟩

/-- With a record at the index of each configuration, the loop adds to records in place. -/
theorem foldl_voteStep (from_ : NodeId)
    : forall (cs : List Config) (votes : List VoteRec),
        (forall c, c ∈ cs -> exists r, r ∈ votes /\ r.1 = c.idx)
        -> cs.foldl (voteStep from_) votes = votes.map (addIf from_ cs)
  | [], votes, _ =>
      ((List.map_congr_left (l := votes) (f := addIf from_ []) (g := id)
        fun r _ => by simp [addIf]).trans (List.map_id _)).symm
  | c :: rest, votes, cover => by
      rw [List.foldl_cons]
      by_cases hc : c.nodes.any (·.1 == from_) = true
      · obtain ⟨r, hr, hi⟩ := cover c List.mem_cons_self
        have found : (votes.find? (·.1 == c.idx)).isSome := by
          rw [List.find?_isSome]
          exact ⟨r, hr, by simp [hi]⟩
        have step : voteStep from_ votes c
            = votes.map fun r => if r.1 == c.idx then (r.1, addVote from_ r.2.1, r.2.2) else r := by
          simp only [voteStep, hc, ite_true]
          obtain ⟨y, hy⟩ := Option.isSome_iff_exists.mp found
          rw [hy]
        rw [step, foldl_voteStep from_ rest _ fun c' mem => ?_, List.map_map]
        · apply List.map_congr_left
          intro r _
          show addIf from_ rest (if r.1 == c.idx then (r.1, addVote from_ r.2.1, r.2.2) else r)
            = addIf from_ (c :: rest) r
          by_cases e : r.1 = c.idx
          · have be : (r.1 == c.idx) = true := beq_iff_eq.mpr e
            simp only [be, ite_true]
            unfold addIf
            simp [e, hc, addVote_addVote]
          · have be : (r.1 == c.idx) = false := beq_false_of_ne e
            have be' : (c.idx == r.1) = false := beq_false_of_ne fun h => e h.symm
            simp only [be, Bool.false_eq_true, ite_false]
            unfold addIf
            simp only [List.any_cons, be', Bool.false_and, Bool.false_or]
        · obtain ⟨r', hr', hi'⟩ := cover c' (List.mem_cons_of_mem _ mem)
          refine ⟨_, List.mem_map_of_mem hr', ?_⟩
          split <;> exact hi'
      · have step : voteStep from_ votes c = votes := by simp [voteStep, hc]
        rw [step, foldl_voteStep from_ rest _ fun c' mem =>
          cover c' (List.mem_cons_of_mem _ mem)]
        apply List.map_congr_left
        intro r _
        rw [Bool.not_eq_true] at hc
        simp only [addIf, List.any_cons, hc, Bool.and_false, Bool.false_or]

/--
`votes` tallies the votes of `W` against the configurations `cs`: one record per
configuration, at its index with its quorum, whose duplicate-free votes are the members of the
configuration in `W`.
-/
def Tally (cs : List Config) (votes : List VoteRec) (W : List NodeId) : Prop :=
  votes.length = cs.length
  /\ forall r c,
      (r, c) ∈ votes.zip cs
      -> r.1 = c.idx
          /\ r.2.2 = State.quorum c.nodes.length
          /\ r.2.1.Nodup
          /\ forall x, x ∈ r.2.1 <-> x ∈ c.nodes.map Prod.fst /\ x ∈ W

theorem exists_zip_right {α β : Type}
    : forall {as : List α} {bs : List β},
        as.length = bs.length -> forall b, b ∈ bs -> exists a, (a, b) ∈ as.zip bs
  | [], [], _, _, h => absurd h List.not_mem_nil
  | a :: as, b' :: bs, hl, b, h => by
      rcases List.mem_cons.mp h with rfl | h
      · exact ⟨a, by simp⟩
      · obtain ⟨x, hx⟩ := exists_zip_right (as := as) (by simpa using hl) b h
        exact ⟨x, List.mem_cons_of_mem _ hx⟩

theorem idx_inj
    : forall {cs : List Config},
        cs.Pairwise (fun a b => a.idx < b.idx)
        -> forall {a b : Config}, a ∈ cs -> b ∈ cs -> a.idx = b.idx -> a = b
  | [], _, _, _, ha, _, _ => absurd ha List.not_mem_nil
  | x :: xs, sorted, a, b, ha, hb, e => by
      obtain ⟨lt, sorted⟩ := List.pairwise_cons.mp sorted
      rcases List.mem_cons.mp ha with ha' | ha' <;> rcases List.mem_cons.mp hb with hb' | hb'
      · rw [ha', hb']
      · have := lt b hb'; rw [ha'] at e; omega
      · have := lt a ha'; rw [hb'] at e; omega
      · exact idx_inj sorted ha' hb' e

theorem Tally.cover {cs : List Config} {votes : List VoteRec} {W : List NodeId}
    (t : Tally cs votes W)
    : forall c, c ∈ cs -> exists r, r ∈ votes /\ r.1 = c.idx := by
  intro c mem
  obtain ⟨r, hr⟩ := exists_zip_right t.1 c mem
  exact ⟨r, (List.of_mem_zip hr).1, (t.2 r c hr).1⟩

theorem mem_ids {c : Config} {x : NodeId}
    : c.nodes.any (·.1 == x) = true <-> x ∈ c.nodes.map Prod.fst := by
  simp

/-- `record_vote from_` tallies one more voter. -/
theorem tally_record {cs : List Config} {votes : List VoteRec} {W : List NodeId}
    (from_ : NodeId) (t : Tally cs votes W)
    (sorted : cs.Pairwise fun a b => a.idx < b.idx)
    : Tally cs (cs.foldl (voteStep from_) votes) (from_ :: W) := by
  rw [foldl_voteStep from_ cs votes t.cover]
  refine ⟨by rw [List.length_map, t.1], fun r' c mem => ?_⟩
  rw [List.zip_map_left, List.mem_map] at mem
  obtain ⟨⟨r, c'⟩, mem, e⟩ := mem
  simp only [Prod.map, id, Prod.mk.injEq] at e
  obtain ⟨rfl, rfl⟩ := e
  obtain ⟨hi, hq, nd, hm⟩ := t.2 r c' mem
  have hc : c' ∈ cs := (List.of_mem_zip mem).2
  have cond : cs.any (fun c => c.idx == r.1 && c.nodes.any (·.1 == from_))
      = c'.nodes.any (·.1 == from_) := by
    apply Bool.eq_iff_iff.mpr
    simp only [List.any_eq_true, Bool.and_eq_true, beq_iff_eq]
    constructor
    · rintro ⟨c, mem, ci, has⟩
      rw [idx_inj sorted mem hc (ci.trans hi)] at has
      exact has
    · exact fun has => ⟨c', hc, hi.symm, has⟩
  unfold addIf
  rw [cond]
  split
  · rename_i has
    rw [mem_ids] at has
    refine ⟨hi, hq, nodup_addVote nd, fun x => ?_⟩
    rw [mem_addVote, hm, List.mem_cons]
    constructor
    · rintro (rfl | ⟨a, b⟩)
      · exact ⟨has, Or.inl rfl⟩
      · exact ⟨a, Or.inr b⟩
    · rintro ⟨a, rfl | b⟩
      · exact Or.inl rfl
      · exact Or.inr ⟨a, b⟩
  · rename_i has
    rw [mem_ids] at has
    refine ⟨hi, hq, nd, fun x => ?_⟩
    rw [hm, List.mem_cons]
    constructor
    · rintro ⟨a, b⟩
      exact ⟨a, Or.inr b⟩
    · rintro ⟨a, rfl | b⟩
      · exact absurd a has
      · exact ⟨a, b⟩

theorem nodup_map_named {names : Names} {l : List NodeId}
    (named : forall a, a ∈ l -> Named names a) (nodup : l.Nodup)
    : (l.map names.id).Nodup := by
  unfold List.Nodup
  rw [List.pairwise_map]
  exact List.Pairwise.imp_of_mem (fun ma mb ne same => ne (named_inj (named _ ma) (named _ mb) same))
    nodup

/-- A record's quorum check is the clean majority of its configuration. -/
theorem majority_tally {names : Names} {c : Config} {vs W : List NodeId}
    (named : forall a, a ∈ c.nodes -> Named names a.1)
    (Wnamed : forall w, w ∈ W -> Named names w) (distinct : (c.nodes.map Prod.fst).Nodup)
    (nodup : vs.Nodup) (mem : forall x, x ∈ vs <-> x ∈ c.nodes.map Prod.fst /\ x ∈ W)
    : decide (vs.length >= State.quorum c.nodes.length)
      = decide (hasConfigurationMajority (names.set W) (absConfig names c)) := by
  have idsNamed : forall a, a ∈ c.nodes.map Prod.fst -> Named names a := by
    intro a ha
    obtain ⟨p, hp, rfl⟩ := List.mem_map.mp ha
    exact named p hp
  have nodes : (absConfig names c).nodes.card = c.nodes.length := by
    simp only [absConfig, Names.set]
    rw [CCF.Finset.card_ofList_of_nodup (nodup_map_named idsNamed distinct), List.length_map,
      List.length_map]
  have inter : (names.set W ∩ (absConfig names c).nodes).card = vs.length := by
    rw [← List.length_map (f := names.id)]
    apply CCF.Finset.length_eq_of_nodup_of_mem_iff
      (CCF.Finset.nodup_of_sorted (CCF.Finset.sorted _))
      (nodup_map_named (fun a ha => idsNamed a ((mem a).mp ha).1) nodup)
    intro n
    rw [← CCF.Finset.mem_def, CCF.Finset.mem_inter]
    simp only [absConfig, Names.set, CCF.Finset.mem_ofList, List.mem_map]
    constructor
    · rintro ⟨⟨w, hw, rfl⟩, ⟨i, hi, e⟩⟩
      have hi' : i ∈ c.nodes.map Prod.fst := List.mem_map.mpr hi
      obtain ⟨p, hp, rfl⟩ := hi
      have same := named_inj (named p hp) (Wnamed w hw) e
      exact ⟨w, (mem w).mpr ⟨same ▸ hi', hw⟩, rfl⟩
    · rintro ⟨v, hv, rfl⟩
      obtain ⟨hi, hw⟩ := (mem v).mp hv
      obtain ⟨p, hp, rfl⟩ := List.mem_map.mp hi
      exact ⟨⟨p.1, hw, rfl⟩, ⟨p.1, ⟨p, hp, rfl⟩, rfl⟩⟩
  apply Bool.eq_iff_iff.mpr
  simp only [decide_eq_true_eq]
  unfold hasConfigurationMajority State.quorum
  rw [nodes, inter]
  omega

theorem all_zip {α β : Type} {p : α -> Bool} {q : β -> Bool}
    : forall {as : List α} {bs : List β},
        as.length = bs.length
        -> (forall a b, (a, b) ∈ as.zip bs -> p a = q b)
        -> as.all p = bs.all q
  | [], [], _, _ => rfl
  | a :: as, b :: bs, hl, h => by
      simp only [List.all_cons]
      rw [h a b (by simp), all_zip (as := as) (by simpa using hl)
        fun x y m => h x y (List.mem_cons_of_mem _ m)]

theorem all_majority_congr {names : Names} (V : CCF.Finset NodeID)
    : forall {D E : List Config},
        D.map (·.nodes) = E.map (·.nodes)
        -> (D.map (absConfig names)).all (fun c => decide (hasConfigurationMajority V c))
            = (E.map (absConfig names)).all
                (fun c => decide (hasConfigurationMajority V c))
  | [], [], _ => rfl
  | x :: D, y :: E, h => by
      simp only [List.map_cons, List.cons.injEq] at h
      simp only [List.map_cons, List.all_cons]
      rw [all_majority_congr V h.2]
      simp only [absConfig, hasConfigurationMajority, h.1]
      rfl

theorem shifted_nodes {ci : Nat} {D E : List Config}
    (sh : ReplUpdateCommit.Shifted ci D E)
    : D.map (·.nodes) = E.map (·.nodes) := by
  rcases sh with rfl | ⟨x, y, rest, rfl, rfl, nodes, -⟩
  · rfl
  · simp [nodes]

/-- `record_vote`'s result is the clean quorum of the tallied voters. -/
theorem quorum_tally {names : Names} {cs D : List Config} {votes : List VoteRec}
    {W : List NodeId} (t : Tally cs votes W)
    (named : forall x, x ∈ cs -> forall a, a ∈ x.nodes -> Named names a.1)
    (Wnamed : forall w, w ∈ W -> Named names w)
    (distinct : forall x, x ∈ cs -> (x.nodes.map Prod.fst).Nodup)
    (nodesEq : D.map (·.nodes) = cs.map (·.nodes))
    : (!cs.isEmpty && votes.all fun r => decide (r.2.1.length >= r.2.2))
      = decide (hasQuorum (D.map (absConfig names)) (names.set W)) := by
  have all : (votes.all fun r => decide (r.2.1.length >= r.2.2))
      = (cs.map (absConfig names)).all
          (fun c => decide (hasConfigurationMajority (names.set W) c)) := by
    rw [List.all_map]
    apply all_zip t.1
    intro r c mem
    obtain ⟨-, hq, nd, hm⟩ := t.2 r c mem
    have hc := (List.of_mem_zip mem).2
    rw [hq]
    exact majority_tally (named c hc) Wnamed (distinct c hc) nd hm
  have len : D.length = cs.length := by
    rw [← List.length_map (f := (·.nodes)), nodesEq, List.length_map]
  apply Bool.eq_iff_iff.mpr
  rw [all, ← all_majority_congr _ nodesEq]
  simp only [Bool.and_eq_true, Bool.not_eq_true', List.isEmpty_eq_false_iff, decide_eq_true_eq,
    ne_eq]
  constructor
  · rintro ⟨ne, h⟩
    refine ⟨fun e => ne (List.eq_nil_of_length_eq_zero ?_), h⟩
    have := congrArg List.length e
    rw [List.length_map, len] at this
    exact this
  · rintro ⟨ne, h⟩
    exact ⟨fun e => ne (List.eq_nil_of_length_eq_zero (by rw [List.length_map, len, e]; rfl)), h⟩

/-- The voters a (pre-)candidate has tallied: itself and every recorded vote. -/
def voters (d : State) : List NodeId := d.nodeId :: d.votesForMe.flatMap (·.2.1)

/-- A (pre-)candidate's vote records tally its voters (`inv`'s `votes_for_me`). -/
theorem tally_of_inv {names : Names} {d : State} (h : inv names d = true)
    (cand : d.leadership = .candidate \/ d.leadership = .preVoteCandidate)
    : Tally d.configurations d.votesForMe (voters d) := by
  have hc : (!(d.leadership == .candidate || d.leadership == .preVoteCandidate)
      || (d.votesForMe.length == d.configurations.length
          && (d.votesForMe.zip d.configurations).all
              fun (r, c) =>
                let members := (c.nodes.map Prod.fst).filter (voters d).contains
                r.1 == c.idx
                && r.2.2 == State.quorum c.nodes.length
                && r.2.1.eraseDups == r.2.1
                && r.2.1.all members.contains
                && members.all r.2.1.contains)) = true := by
    inv_conj h "votes_for_me"
  have hl : (d.leadership == .candidate || d.leadership == .preVoteCandidate) = true := by
    rcases cand with e | e <;> simp [e]
  rw [hl] at hc
  simp only [Bool.not_true, Bool.false_or, Bool.and_eq_true, beq_iff_eq, List.all_eq_true]
    at hc
  refine ⟨hc.1, fun r c mem => ?_⟩
  obtain ⟨⟨⟨⟨hi, hq⟩, hd⟩, h1⟩, h2⟩ := hc.2 (r, c) mem
  refine ⟨
    hi,
    hq,
    ReplUpdateCommit.nodup_of_eraseDups_eq hd,
    fun x => ⟨fun m => ?_, fun m => ?_⟩
  ⟩
  · have := h1 x m
    simp only [List.contains_iff_mem, List.mem_filter] at this
    exact this
  · have := h2 x (by simp only [List.mem_filter, List.contains_iff_mem]; exact m)
    simpa using this

theorem mem_flat_tally {cs : List Config} {votes : List VoteRec} {W : List NodeId}
    (t : Tally cs votes W) {x : NodeId}
    : x ∈ votes.flatMap (·.2.1)
      <-> x ∈ W /\ exists c, c ∈ cs /\ x ∈ c.nodes.map Prod.fst := by
  rw [List.mem_flatMap]
  constructor
  · rintro ⟨r, mr, mx⟩
    obtain ⟨i, hi, rfl⟩ := List.getElem_of_mem mr
    have hc : i < cs.length := t.1 ▸ hi
    have mem : (votes[i], cs[i]) ∈ votes.zip cs := by
      rw [List.mem_iff_getElem]
      exact ⟨i, by simp only [List.length_zip]; omega, by simp⟩
    obtain ⟨-, -, -, hm⟩ := t.2 _ _ mem
    exact ⟨((hm x).mp mx).2, cs[i], List.getElem_mem hc, ((hm x).mp mx).1⟩
  · rintro ⟨w, c, mc, mx⟩
    obtain ⟨r, mem⟩ := exists_zip_right t.1 c mc
    exact ⟨r, (List.of_mem_zip mem).1, ((t.2 r c mem).2.2.2 x).mpr ⟨mx, w⟩⟩

theorem set_congr {names : Names} {l m : List NodeId} (h : forall x, x ∈ l <-> x ∈ m)
    : names.set l = names.set m := by
  apply CCF.Finset.ext
  intro a
  simp only [Names.set, CCF.Finset.mem_ofList, List.mem_map]
  exact ⟨fun ⟨x, hx, e⟩ => ⟨x, (h x).mp hx, e⟩, fun ⟨x, hx, e⟩ => ⟨x, (h x).mpr hx, e⟩⟩

/-- After `record_vote from_` by a voter in a configuration, the voters gained `from_`. -/
theorem voters_record {d : State} {from_ : NodeId}
    (t : Tally d.configurations d.votesForMe (voters d))
    (sorted : d.configurations.Pairwise fun a b => a.idx < b.idx)
    (member : exists c, c ∈ d.configurations /\ from_ ∈ c.nodes.map Prod.fst)
    : forall x,
        x ∈ voters { d with votesForMe := recorded from_ d }
        <-> x ∈ from_ :: voters d := by
  have t' := tally_record from_ t sorted
  intro x
  have old := fun x => (mem_flat_tally (x := x) t).mp
  have new := fun x => mem_flat_tally (x := x) t'
  simp only [voters, recorded, List.mem_cons] at old new ⊢
  rw [new]
  constructor
  · rintro (rfl | ⟨w, -⟩)
    · exact Or.inr (Or.inl rfl)
    · exact w
  · rintro (rfl | rfl | w)
    · exact Or.inr ⟨Or.inl rfl, member⟩
    · exact Or.inl rfl
    · exact Or.inr ⟨Or.inr (Or.inr w), (old x w).2⟩

theorem lookup_isSome {β : Type} {l : List (NodeId × β)} {k : NodeId}
    : (l.lookup k).isSome = true <-> exists p, p ∈ l /\ p.1 = k := by
  induction l with
  | nil => simp
  | cons p l ih =>
      obtain ⟨a, b⟩ := p
      simp only [List.lookup_cons]
      by_cases e : k = a
      · subst e
        simp
      · have : (k == a) = false := beq_false_of_ne e
        simp only [this, ih, List.mem_cons]
        constructor
        · rintro ⟨q, mq, eq⟩
          exact ⟨q, Or.inr mq, eq⟩
        · rintro ⟨q, rfl | mq, eq⟩
          · exact absurd eq.symm e
          · exact ⟨q, mq, eq⟩

/--
An initialised node knows a peer exactly when the clean node has it as an eligible peer
(`inv`'s `peers` conjuncts, and `empty_ledger_alone` for an empty ledger).
-/
theorem peer_iff_eligible {names : Names} {d : State} (h : inv names d = true)
    (init : initialised d = true) {source : NodeID}
    (hs : names.id (names.name source) = source)
    : (d.peer? (names.name source)).isSome = true
      <-> source ∈ eligiblePeers (abs names d) (names.id d.nodeId) := by
  unfold State.peer?
  rw [lookup_isSome]
  by_cases L0 : d.lastIdx = 0
  · have alone : (d.currentView == 0 && d.leadership == .none) || d.lastIdx != 0
        || d.allOtherNodes.isEmpty := by
      inv_conj h "empty_ledger_alone"
    have commit : d.commitIdx = 0 := by have := (inv_parts h).2.1; omega
    have empty := eligiblePeers_empty (s := abs names d) (by simp [abs, L0]) commit
      (names.id d.nodeId)
    unfold initialised at init
    simp only [bne_iff_ne, ne_eq, Bool.or_eq_true] at init
    simp only [Bool.or_eq_true, Bool.and_eq_true, beq_iff_eq, bne_iff_ne, ne_eq, L0,
      not_true_eq_false, or_false, List.isEmpty_iff] at alone
    have none : d.allOtherNodes = [] := by
      rcases alone with ⟨a, b⟩ | a
      · rcases init with i | i <;> contradiction
      · exact a
    rw [none, ← CCF.Finset.mem_sort, empty]
    simp
  · have eq : d.allOtherNodes.map (fun x => names.id x.1)
        = (eligiblePeers (abs names d) (names.id d.nodeId)).sort := by
      have p1 : (d.lastIdx == 0 || d.leadership == .none
          || d.allOtherNodes.map (fun (id, _) => names.id id)
            == (eligiblePeers (abs names d) (names.id d.nodeId)).sort) = true := by
        inv_conj h "peers"
      have p2 : (d.lastIdx == 0 || d.leadership != .none
          || d.allOtherNodes.map (fun (id, _) => names.id id)
            == (eligiblePeers (abs names d) (names.id d.nodeId)).sort) = true := by
        inv_conj h "peers_without_role"
      simp only [Bool.or_eq_true, beq_iff_eq, bne_iff_ne, ne_eq, L0, false_or] at p1 p2
      by_cases r : d.leadership = .none
      · simpa [r] using p2
      · simpa [r] using p1
    have named := (ReplUpdateCommit.Hyps.ofInv h).peersNamed
    rw [← CCF.Finset.mem_sort, ← eq, List.mem_map]
    constructor
    · rintro ⟨p, mp, e⟩
      exact ⟨p, mp, by rw [e, hs]⟩
    · rintro ⟨p, mp, e⟩
      refine ⟨p, mp, ?_⟩
      rw [← named p mp, e]

end Consensus.TraceValidation.Proofs.Vote
