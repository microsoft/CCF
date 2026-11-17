module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import Consensus.TraceValidation.Proofs.Handlers.ReplUpdateCommit
public import Consensus.TraceValidation.Proofs.Handlers.AeLemmas

@[expose] public section

/-!
# cft.h's successor is the clean `findSuccessor` (not reviewed)

M_tv's `find_successor` loop (`Exec.becomeRetired.findSuccessor`) walks the peers in order
and keeps the peer with the highest match index, breaking ties by the latest configuration
naming it and then by the later peer. The peers are the clean eligible peers in increasing
id order (`inv` conjunct `peers`), so "the later peer" is the clean tie-break by node id:

* `findSuccessor_spec`: the loop reads the state, changes nothing and returns `tvSuccessor`;
* `tvSuccessor_eq`: for a leader satisfying `inv` and a clean state that agrees with it,
  `tvSuccessor` mapped to clean ids is the clean `findSuccessor`.
-/

namespace Consensus.TraceValidation.Proofs.AeResp

open Consensus.Model.Node
open Consensus.TraceValidation (Names abs agrees trackedPeers inv invChecks)
open Consensus.TraceValidation.Exec (State Ctx Peer Config M)
open Consensus.TraceValidation.Proofs.ReplUpdateCommit (absConfig Named named_inj)

/-- The index of the last configuration of `cs` naming `node`, or 0. -/
def latestIn (cs : List Config) (node : Exec.NodeId) : Nat :=
  ((cs.reverse.find? (·.nodes.any (·.1 == node))).map (·.idx)).getD 0

/-- The index of the last declared configuration naming `node`, or 0. -/
abbrev latestOf (v : State) (node : Exec.NodeId) : Nat := latestIn v.configurations node

/-- One iteration of `find_successor`: the successor, its match index and its `latest`. -/
def tvStep (v : State) (acc : Option Exec.NodeId × Nat × Nat) (p : Exec.NodeId × Peer)
    : Option Exec.NodeId × Nat × Nat :=
  if p.2.matchIdx >= acc.2.1 then
    if (!(p.2.matchIdx == acc.2.1 && decide (latestOf v p.1 < acc.2.2))) = true then
      (some p.1, p.2.matchIdx, latestOf v p.1)
    else
      acc
  else
    acc

/-- What `find_successor` returns on `v`. -/
def tvSuccessor (v : State) : Option Exec.NodeId :=
  (v.allOtherNodes.foldl (tvStep v) (none, 0, 0)).1

/-! ## The monadic loop -/

theorem forIn_yield {α β : Type} (f : β -> α -> β) (body : α -> β -> M (ForInStep β))
    (hb : forall a b, body a b = pure (.yield (f b a)))
    : forall (l : List α) (init : β), forIn l init body = pure (l.foldl f init)
  | [], _ => rfl
  | a :: l, init => by
      rw [List.forIn_cons, hb, pure_bind, List.foldl_cons]
      exact forIn_yield f body hb l (f init a)

theorem getV_bind_run {α : Type} (f : State -> M α) (c : Ctx)
    : (Exec.getV >>= f).run c = (f c.vars).run c :=
  rfl

theorem findSuccessor_run (c : Ctx)
    : Exec.becomeRetired.findSuccessor.run c = .ok (tvSuccessor c.vars, c) := by
  unfold Exec.becomeRetired.findSuccessor
  rw [getV_bind_run]
  dsimp only
  rw [forIn_yield (tvStep c.vars)]
  · rfl
  · intro p acc
    obtain ⟨k, st⟩ := p
    obtain ⟨s, mm, rc⟩ := acc
    simp only [tvStep, latestOf, latestIn]
    split
    · split
      · rename_i h
        exact congrArg (fun z => pure (ForInStep.yield z))
          (ite_eq_left_of_eq_true _ _ (eq_true h)).symm
      · rename_i h
        exact congrArg (fun z => pure (ForInStep.yield z))
          (ite_eq_right_of_eq_false _ _ (eq_false h)).symm
    · rfl

theorem findSuccessor_spec {env : Consensus.TraceValidation.Env}
    : Spec env Exec.becomeRetired.findSuccessor
        fun v o a v' o' => a = tvSuccessor v /\ v' = v /\ o' = o := by
  intro c a c' envOk h
  rw [findSuccessor_run] at h
  cases h
  exact ⟨envOk, rfl, rfl, rfl⟩

/-- `find_successor` returns a peer. -/
theorem tvSuccessor_mem {v : State} {s : Exec.NodeId} (h : tvSuccessor v = some s)
    : exists p, p ∈ v.allOtherNodes /\ p.1 = s := by
  unfold tvSuccessor at h
  have general : forall (l : List (Exec.NodeId × Peer)) (acc : Option Exec.NodeId × Nat × Nat),
      (l.foldl (tvStep v) acc).1 = some s
      -> acc.1 = some s \/ exists p, p ∈ l /\ p.1 = s := by
    intro l
    induction l with
    | nil => intro acc h; exact Or.inl h
    | cons q l ih =>
        intro acc h
        rcases ih _ h with h | ⟨p, mem, ps⟩
        · simp only [tvStep] at h
          split at h
          · split at h
            · simp only [Option.some.injEq] at h
              exact Or.inr ⟨q, List.mem_cons_self, h⟩
            · exact Or.inl h
          · exact Or.inl h
        · exact Or.inr ⟨p, List.mem_cons_of_mem _ mem, ps⟩
  rcases general _ _ h with h | found
  · cases h
  · exact found

/-! ## Against the clean fold -/

/-- The clean step of `findSuccessor`'s fold, with rank `(m n, lat n, n)`. -/
abbrev cleanStep (m lat : NodeID -> Nat) (best : Option NodeID) (candidate : NodeID)
    : Option NodeID :=
  match best with
  | none => some candidate
  | some selected =>
      if rankBelow (m selected, lat selected, selected)
            (m candidate, lat candidate, candidate)
          = true then
        some candidate
      else
        best

theorem tvStep_some (v : State) (s : Exec.NodeId) (mm rc : Nat) (p : Exec.NodeId × Peer)
    : tvStep v (some s, mm, rc) p
      = if mm < p.2.matchIdx \/ (p.2.matchIdx = mm /\ Not (latestOf v p.1 < rc)) then
          (some p.1, p.2.matchIdx, latestOf v p.1)
        else
          (some s, mm, rc) := by
  unfold tvStep
  by_cases a : mm <= p.2.matchIdx <;> by_cases b : p.2.matchIdx = mm <;>
    by_cases c : latestOf v p.1 < rc <;> simp [a, b, c] <;> omega

theorem cleanStep_some (m lat : NodeID -> Nat) {s c : NodeID} (lt : s < c)
    : cleanStep m lat (some s) c
      = if m s < m c \/ (m c = m s /\ Not (lat c < lat s)) then some c else some s := by
  simp only [cleanStep, rankBelow, Prod.lexLt]
  by_cases a : m s < m c <;> by_cases b : m c = m s <;> by_cases d : lat c < lat s <;>
    by_cases e : lat s = lat c <;> simp [a, b, d, e, lt] <;> omega

theorem fold_sim (v : State) (id : Exec.NodeId -> NodeID) (m lat : NodeID -> Nat)
    (P : Exec.NodeId -> Prop)
    (cmp
      : forall a b,
          P a -> P b -> (latestOf v a < latestOf v b <-> lat (id a) < lat (id b)))
    : forall (l : List (Exec.NodeId × Peer)) (acc : Option Exec.NodeId × Nat × Nat)
              (best : Option NodeID),
        l.Pairwise (fun p q => id p.1 < id q.1)
        -> (forall p, p ∈ l -> P p.1 /\ m (id p.1) = p.2.matchIdx)
        -> acc.1.map id = best
        -> (acc.1 = none -> acc.2 = (0, 0))
        -> (forall s,
              acc.1 = some s
              -> P s
                  /\ acc.2.1 = m (id s)
                  /\ acc.2.2 = latestOf v s
                  /\ forall p, p ∈ l -> id s < id p.1)
        -> (l.foldl (tvStep v) acc).1.map id
            = (l.map fun p => id p.1).foldl (cleanStep m lat) best
  | [], _, _, _, _, same, _, _ => same
  | p :: l, acc, best, sorted, values, same, zero, cur => by
      rw [List.foldl_cons, List.map_cons, List.foldl_cons]
      obtain ⟨hp, hm⟩ := values p List.mem_cons_self
      have later : forall q, q ∈ l -> id p.1 < id q.1 :=
        fun _ mem => List.rel_of_pairwise_cons sorted mem
      have rest := fun acc best =>
        fold_sim v id m lat P cmp l acc best (List.Pairwise.of_cons sorted)
          (fun q mem => values q (List.mem_cons_of_mem _ mem))
      have chosen : forall acc', acc' = (some p.1, p.2.matchIdx, latestOf v p.1)
          -> (l.foldl (tvStep v) acc').1.map id
              = (l.map fun p => id p.1).foldl (cleanStep m lat) (some (id p.1)) := by
        intro acc' h
        subst h
        exact rest _ _ rfl (by simp) fun s hs => by
          cases hs
          exact ⟨hp, hm.symm, rfl, later⟩
      obtain ⟨o, mm, rc⟩ := acc
      cases o with
      | none =>
          obtain ⟨rfl, rfl⟩ := Prod.mk.inj (zero rfl)
          simp only [Option.map_none] at same
          subst same
          exact chosen _ (by simp [tvStep])
      | some s =>
          obtain ⟨hs, hmm, hrc, lt⟩ := cur s rfl
          simp only [Option.map_some] at same
          subst same
          simp only at hmm hrc
          subst hmm hrc
          have sp := lt p List.mem_cons_self
          rw [tvStep_some, cleanStep_some m lat sp, hm]
          simp only [cmp p.1 s hp hs]
          by_cases rep : m (id s) < p.2.matchIdx
              \/ (p.2.matchIdx = m (id s) /\ Not (lat (id p.1) < lat (id s)))
          · simp only [rep, ↓reduceIte]
            exact chosen _ rfl
          · simp only [rep, ↓reduceIte]
            exact rest _ _ rfl (by simp) fun s' hs' => by
              cases hs'
              exact ⟨hs, rfl, rfl, fun q mem => lt q (List.mem_cons_of_mem _ mem)⟩

/-! ## The ranks agree -/

theorem foldl_latest {Q : Config -> Bool} {P : Config -> Prop} [DecidablePred P]
    : forall (D : List Config) (acc : Nat),
        (forall x, x ∈ D -> (P x <-> Q x = true))
        -> D.Pairwise (fun a b => a.idx < b.idx)
        -> (forall x, x ∈ D -> acc <= x.idx)
        -> D.foldl (fun highest x => if P x then max highest x.idx else highest) acc
            = ((D.reverse.find? Q).map (·.idx)).getD acc
  | [], _, _, _, _ => rfl
  | x :: D, acc, same, sorted, low => by
      rw [List.foldl_cons, List.reverse_cons, List.find?_append]
      have later : forall y, y ∈ D -> x.idx <= y.idx :=
        fun _ mem => Nat.le_of_lt (List.rel_of_pairwise_cons sorted mem)
      have rest := fun acc low' =>
        foldl_latest D acc (fun y mem => same y (List.mem_cons_of_mem _ mem))
          (List.Pairwise.of_cons sorted) low'
      by_cases px : P x
      · have qx : Q x = true := (same x List.mem_cons_self).mp px
        simp only [px, ↓reduceIte, List.find?_cons, qx]
        rw [Nat.max_eq_right (low x List.mem_cons_self), rest x.idx later]
        cases D.reverse.find? Q <;> rfl
      · have qx : Q x = false := by
          cases hq : Q x
          · rfl
          · exact absurd ((same x List.mem_cons_self).mpr hq) px
        simp only [px, ↓reduceIte, List.find?_cons, qx]
        refine (rest acc fun y mem => low y (List.mem_cons_of_mem _ mem)).trans ?_
        cases D.reverse.find? Q <;> rfl

theorem mem_absConfig_iff {names : Names} {x : Config} {node : Exec.NodeId}
    (named : Named names node) (membersNamed : forall a, a ∈ x.nodes -> Named names a.1)
    : names.id node ∈ (absConfig names x).nodes
      <-> (x.nodes.any (·.1 == node)) = true := by
  simp only [absConfig, Names.set, CCF.Finset.mem_ofList, List.map_map, List.mem_map,
    List.any_eq_true, beq_iff_eq, Function.comp_apply]
  constructor
  · rintro ⟨a, mem, same⟩
    exact ⟨a, mem, named_inj (membersNamed a mem) named same⟩
  · rintro ⟨a, mem, rfl⟩
    exact ⟨a, mem, rfl⟩

theorem latest_eq {names : Names} {D : List Config} {node : Exec.NodeId}
    (named : Named names node)
    (membersNamed : forall x, x ∈ D -> forall a, a ∈ x.nodes -> Named names a.1)
    (sorted : D.Pairwise fun a b => a.idx < b.idx)
    : latestMembershipIndex (D.map (absConfig names)) (names.id node)
      = latestIn D node := by
  unfold latestMembershipIndex latestIn
  rw [List.foldl_map]
  exact foldl_latest (Q := fun x => x.nodes.any (·.1 == node)) _ 0
    (fun x mem => mem_absConfig_iff named (membersNamed x mem)) sorted
    (fun _ _ => Nat.zero_le _)

theorem latestIn_cons (x : Config) (rest : List Config) (node : Exec.NodeId)
    : latestIn (x :: rest) node
      = match rest.reverse.find? (·.nodes.any (·.1 == node)) with
        | some z => z.idx
        | none => if x.nodes.any (·.1 == node) then x.idx else 0 := by
  unfold latestIn
  rw [List.reverse_cons, List.find?_append]
  cases rest.reverse.find? (·.nodes.any (·.1 == node)) with
  | some z => rfl
  | none =>
      simp only [Option.none_or, List.find?_cons, List.find?_nil]
      split <;> simp [*]

/--
Shifting the first configuration to a later index at or below `ci`, the others being above
`ci`, keeps the order of the latest configurations naming two nodes.
-/
theorem latestIn_shifted {ci : Nat} {D E : List Config}
    (sh : ReplUpdateCommit.Shifted ci D E) (pos : forall x, x ∈ D -> 0 < x.idx)
    (above : forall x, x ∈ D.drop 1 -> ci < x.idx) (a b : Exec.NodeId)
    : latestIn E a < latestIn E b <-> latestIn D a < latestIn D b := by
  rcases sh with rfl | ⟨x, y, rest, rfl, rfl, nodes, xy, yc⟩
  · exact Iff.rfl
  · simp only [List.drop_succ_cons, List.drop_zero] at above
    have x0 := pos x List.mem_cons_self
    have found : forall n z, rest.reverse.find? (·.nodes.any (·.1 == n)) = some z -> ci < z.idx :=
      fun _ z h => above z (List.mem_reverse.mp (List.mem_of_find?_eq_some h))
    rw [latestIn_cons, latestIn_cons, latestIn_cons, latestIn_cons, nodes]
    cases ha : rest.reverse.find? (·.nodes.any (·.1 == a)) <;>
      cases hb : rest.reverse.find? (·.nodes.any (·.1 == b)) <;>
      simp only
    · split <;> split <;> omega
    · have := found b _ hb
      split <;> omega
    · have := found a _ ha
      split <;> omega

theorem find_sorted (names : Names)
    : forall (l : List (Exec.NodeId × Peer)),
        l.Pairwise (fun p q => names.id p.1 < names.id q.1)
        -> forall p,
            p ∈ l -> l.find? (fun (id, _) => names.id id == names.id p.1) = some p
  | [], _, _, mem => by cases mem
  | q :: l, sorted, p, mem => by
      rcases List.mem_cons.mp mem with rfl | mem
      · simp
      · have lt := List.rel_of_pairwise_cons sorted mem
        have ne : (names.id q.1 == names.id p.1) = false := by
          simp only [beq_eq_false_iff_ne]
          exact Nat.ne_of_lt lt
        rw [List.find?_cons]
        simp only [ne]
        exact find_sorted names l (List.Pairwise.of_cons sorted) p mem

theorem abs_matchIndex_of_sorted {names : Names} {v : State}
    (sorted : v.allOtherNodes.Pairwise (fun p q => names.id p.1 < names.id q.1)) {p}
    (mem : p ∈ v.allOtherNodes)
    : (abs names v).matchIndex (names.id p.1) = p.2.matchIdx := by
  simp only [abs]
  rw [find_sorted names _ sorted p mem]

theorem eligiblePeers_of_log_nil {st : NodeState} (empty : st.log = []) (self : NodeID)
    : (eligiblePeers st self).sort = [] := by
  unfold eligiblePeers NodeState.activeMembers NodeState.retirementCompletedNodes
    NodeState.activeConfigurations NodeState.committedLog
  rw [empty]
  simp only [List.take_nil, activeConfigurations, configurationHistory, List.zipIdx_nil,
    List.filterMap_nil, List.filter_nil, List.drop_nil]
  rfl

/-! ## The successor -/

/--
The successor on `w`, which has the peers of a leader `v` satisfying `inv` (with any match
indexes) and its configurations, is the clean successor of a state with `v`'s log and commit
index and `w`'s match indexes.
-/
theorem tvSuccessor_core {names : Names} {v w : State} {c : NodeState}
    (h : inv names v = true) (leader : v.leadership = .leader)
    (hlog : c.log = (abs names v).log)
    (hcommit : c.commitIndex = (abs names v).commitIndex)
    (keys : w.allOtherNodes.map Prod.fst = v.allOtherNodes.map Prod.fst)
    (configs : w.configurations = v.configurations)
    (matched
      : forall p, p ∈ w.allOtherNodes -> c.matchIndex (names.id p.1) = p.2.matchIdx)
    : (tvSuccessor w).map names.id = findSuccessor c (names.id v.nodeId) := by
  have hyps := ReplUpdateCommit.Hyps.ofInv h
  have step : tvStep w = tvStep v := by
    funext acc p
    simp only [tvStep, latestOf, configs]
  have keysId : w.allOtherNodes.map (fun p => names.id p.1)
      = v.allOtherNodes.map (fun p => names.id p.1) := by
    have := congrArg (List.map names.id) keys
    simp only [List.map_map] at this
    exact this
  by_cases L0 : v.lastIdx = 0
  · have alone : v.allOtherNodes = [] := by
      have e := ReplUpdateCommit.inv_conjunct h "empty_leader_alone"
      simp only [invChecks, List.lookup, String.reduceBEq, Option.getD_some] at e
      simpa [L0, leader] using e
    have aloneW : w.allOtherNodes = [] := by
      rw [alone] at keys
      exact List.map_eq_nil_iff.mp keys
    have nil : (eligiblePeers c (names.id v.nodeId)).sort = [] := by
      apply eligiblePeers_of_log_nil
      rw [hlog]
      simp [abs, L0]
    unfold tvSuccessor findSuccessor
    rw [aloneW, nil]
    rfl
  · have peersEq : v.allOtherNodes.map (fun p => names.id p.1)
        = (eligiblePeers (abs names v) (names.id v.nodeId)).sort := by
      have e := ReplUpdateCommit.inv_conjunct h "peers"
      simp only [invChecks, List.lookup, String.reduceBEq, Option.getD_some] at e
      simpa [L0, leader] using e
    have sorted : w.allOtherNodes.Pairwise (fun p q => names.id p.1 < names.id q.1) := by
      have := (eligiblePeers (abs names v) (names.id v.nodeId)).sorted
      rw [← CCF.Finset.sort, ← peersEq, ← keysId, List.pairwise_map] at this
      exact this
    have namedW : forall p, p ∈ w.allOtherNodes -> Named names p.1 := by
      intro p mem
      have : p.1 ∈ v.allOtherNodes.map Prod.fst := by
        rw [← keys]
        exact List.mem_map_of_mem mem
      obtain ⟨q, qm, e⟩ := List.mem_map.mp this
      exact e ▸ hyps.peersNamed q qm
    obtain ⟨D, hD, sh⟩ := hyps.configs (Nat.pos_of_ne_zero L0)
    have active : c.activeConfigurations = D.map (absConfig names) := by
      unfold NodeState.activeConfigurations
      rw [hlog, hcommit]
      exact hD
    have membersD : forall x, x ∈ D -> forall a, a ∈ x.nodes -> Named names a.1 := by
      intro x mem a am
      rcases sh with rfl | ⟨x', y, rest, rfl, hE, nodes, _⟩
      · exact hyps.membersNamed x mem a am
      · rcases List.mem_cons.mp mem with rfl | mem
        · exact hyps.membersNamed y (by rw [hE]; exact List.mem_cons_self) a (nodes ▸ am)
        · exact hyps.membersNamed x (by rw [hE]; exact List.mem_cons_of_mem _ mem) a am
    let P : Exec.NodeId -> Prop := fun a => exists p, p ∈ w.allOtherNodes /\ p.1 = a
    have cmp : forall a b, P a -> P b
        -> (latestOf v a < latestOf v b
            <-> latestMembershipIndex c.activeConfigurations (names.id a)
              < latestMembershipIndex c.activeConfigurations (names.id b)) := by
      rintro a b ⟨p, pm, rfl⟩ ⟨q, qm, rfl⟩
      rw [active, latest_eq (namedW p pm) membersD (ReplUpdateCommit.declared_sorted hD),
        latest_eq (namedW q qm) membersD (ReplUpdateCommit.declared_sorted hD)]
      exact latestIn_shifted sh (fun _ mem => ReplUpdateCommit.declared_pos hD mem)
        (ReplUpdateCommit.active_tail_above names _ hD) _ _
    have values : forall p, p ∈ w.allOtherNodes
        -> P p.1 /\ c.matchIndex (names.id p.1) = p.2.matchIdx :=
      fun p mem => ⟨⟨p, mem, rfl⟩, matched p mem⟩
    have key := fold_sim v names.id c.matchIndex (latestMembershipIndex c.activeConfigurations)
      P cmp w.allOtherNodes (none, 0, 0) none sorted values rfl (fun _ => rfl)
      (fun _ hs => by cases hs)
    unfold tvSuccessor
    rw [step, key]
    unfold findSuccessor
    rw [Ae.eligiblePeers_congr hlog hcommit, ← peersEq, keysId]
    rfl

theorem tvSuccessor_eq {names : Names} {v : State} {c : NodeState}
    (h : inv names v = true) (leader : v.leadership = .leader)
    (agreed : agrees names c v = true)
    : (tvSuccessor v).map names.id = findSuccessor c (names.id v.nodeId) := by
  simp only [agrees, Bool.and_eq_true, beq_iff_eq, and_assoc, List.all_eq_true] at agreed
  obtain ⟨_, _, hlog, hcommit, tracked, _⟩ := agreed
  simp only [trackedPeers, leader, beq_self_eq_true, ↓reduceIte, List.mem_map] at tracked
  refine tvSuccessor_core h leader hlog hcommit rfl rfl fun p mem => ?_
  have sorted : v.allOtherNodes.Pairwise (fun p q => names.id p.1 < names.id q.1) := by
    by_cases L0 : v.lastIdx = 0
    · have e := ReplUpdateCommit.inv_conjunct h "empty_leader_alone"
      simp only [invChecks, List.lookup, String.reduceBEq, Option.getD_some] at e
      have alone : v.allOtherNodes = [] := by simpa [L0, leader] using e
      rw [alone]
      exact List.Pairwise.nil
    · have e := ReplUpdateCommit.inv_conjunct h "peers"
      simp only [invChecks, List.lookup, String.reduceBEq, Option.getD_some] at e
      have peersEq : v.allOtherNodes.map (fun p => names.id p.1)
          = (eligiblePeers (abs names v) (names.id v.nodeId)).sort := by
        simpa [L0, leader] using e
      have := (eligiblePeers (abs names v) (names.id v.nodeId)).sorted
      rw [← CCF.Finset.sort, ← peersEq, List.pairwise_map] at this
      exact this
  rw [(tracked _ ⟨p, mem, rfl⟩).2]
  exact abs_matchIndex_of_sorted sorted mem

/-- The clean successor is an eligible peer, so it is not the node itself. -/
theorem findSuccessor_mem {st : NodeState} {self t : NodeID}
    (h : findSuccessor st self = some t)
    : t ∈ eligiblePeers st self := by
  unfold findSuccessor at h
  have general : forall (l : List NodeID) (best : Option NodeID),
      (l.foldl (cleanStep st.matchIndex (latestMembershipIndex st.activeConfigurations)) best)
          = some t
      -> best = some t \/ t ∈ l := by
    intro l
    induction l with
    | nil => intro best h; exact Or.inl h
    | cons x l ih =>
        intro best h
        rcases ih _ h with h | mem
        · cases best with
          | none =>
              simp only [cleanStep, Option.some.injEq] at h
              exact Or.inr (h ▸ List.mem_cons_self)
          | some s =>
              simp only [cleanStep] at h
              split at h
              · simp only [Option.some.injEq] at h
                exact Or.inr (h ▸ List.mem_cons_self)
              · exact Or.inl h
        · exact Or.inr (List.mem_cons_of_mem _ mem)
  rcases general _ none h with h | mem
  · cases h
  · exact CCF.Finset.mem_sort.mp mem

theorem findSuccessor_ne {st : NodeState} {self t : NodeID}
    (h : findSuccessor st self = some t)
    : t ≠ self := by
  have := findSuccessor_mem h
  unfold eligiblePeers at this
  exact (CCF.Finset.mem_erase.mp this).1
