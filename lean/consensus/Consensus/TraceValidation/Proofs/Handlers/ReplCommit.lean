module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import Consensus.TraceValidation.Proofs.Handlers.ReplEntry
public import Consensus.TraceValidation.Proofs.Handlers.AppendEntriesResponse

@[expose] public section

/-!
# After the batch: the commit (not reviewed; `Replicate` obligation)

The clean `appendBatch` ends with `advanceCommit`. With other nodes in the active
configurations before the batch, it cannot move (`hc_stuck`): the new entries are above every
peer's match index, and the commit index was already maximal. Without them, the declared
`update_commit` runs, and it chooses the clean `highestCommittableIndex` (`updateCommit_tri`).
-/

namespace Consensus.TraceValidation.Proofs.Repl

open Consensus.Model.Node
open CCF (Finset)

/-! ## The clean commit -/

variable {node : NodeID}

theorem emits_advance (st : NodeState) (primary : st.role = .primary)
    : Emits (advanceCommit (CCF.Capabilities.record node) st node)
        (if highestCommittableIndex st node <= st.commitIndex then
            st
          else
            st.recordCommit node (highestCommittableIndex st node))
        (if ¬ highestCommittableIndex st node <= st.commitIndex
            /\ (st.recordCommit node (highestCommittableIndex st node)).isRetiredCommitted
                node then
            AeResp.nomSends node st
          else
            []) := by
  unfold advanceCommit
  by_cases h : highestCommittableIndex st node <= st.commitIndex
  · simp only [h, ↓reduceIte, not_true_eq_false, false_and]
    exact emits_pure _
  · by_cases r :
      (st.recordCommit node (highestCommittableIndex st node)).isRetiredCommitted node
    · simp only [h, ↓reduceIte, primary, not_false_eq_true, true_and]
      rw [ite_eq_left_of_eq_true _ _ (eq_true r), ite_eq_left_of_eq_true _ _ (eq_true r)]
      refine emits_congr
        (emits_bind (a := st)
          (b := st.recordCommit node (highestCommittableIndex st node)) (later := []) ?_
          (emits_pure _))
        rfl (List.append_nil _)
      unfold nominateSuccessor
      refine emits_congr (emits_bind (emits_guard primary) ?_) rfl (List.nil_append _)
      unfold AeResp.nomSends
      cases findSuccessor st node with
      | none => exact emits_pure _
      | some t =>
          exact emits_congr (emits_bind (emits_send _ _) (emits_pure _)) rfl rfl
    · simp only [h, ↓reduceIte, not_false_eq_true, true_and]
      rw [ite_eq_right_of_eq_false _ _ (eq_false r), ite_eq_right_of_eq_false _ _ (eq_false r)]
      exact emits_pure _

/-! ## Folds that stay put -/

theorem foldl_ge {g : Nat -> Nat -> Nat} (mono : forall a x, a <= g a x)
    : forall (l : List Nat) (a : Nat), a <= l.foldl g a
  | [], _ => Nat.le_refl _
  | x :: l, a => Nat.le_trans (mono a x) (foldl_ge mono l (g a x))

theorem foldl_fixed {g : Nat -> Nat -> Nat} (mono : forall a x, a <= g a x)
    : forall (l : List Nat) (a : Nat), l.foldl g a <= a -> forall x, x ∈ l -> g a x = a
  | [], _, _, _, mem => absurd mem List.not_mem_nil
  | y :: l, a, h, x, mem => by
      have hy : g a y = a :=
        Nat.le_antisymm (Nat.le_trans (foldl_ge mono l (g a y)) h) (mono a y)
      rcases List.mem_cons.mp mem with rfl | mem
      · exact hy
      · simp only [List.foldl_cons, hy] at h
        exact foldl_fixed mono l a h x mem

theorem foldl_const {g : Nat -> Nat -> Nat}
    : forall (l : List Nat) (a : Nat), (forall x, x ∈ l -> g a x = a) -> l.foldl g a = a
  | [], _, _ => rfl
  | y :: l, a, h => by
      simp only [List.foldl_cons, h y List.mem_cons_self]
      exact foldl_const l a fun x mem => h x (List.mem_cons_of_mem _ mem)

theorem le_ite_self {p : Prop} [Decidable p] {a x : Nat} (h : p -> a <= x)
    : a <= if p then x else a := by
  by_cases c : p
  · simp only [c, ↓reduceIte]
    exact h c
  · simp only [c, ↓reduceIte, Nat.le_refl]

/-! ## The clean commit cannot move past a batch with other nodes -/

theorem history_append (L0 T : List Model.Node.Entry)
    : exists R,
        configurationHistory (L0 ++ T) = configurationHistory L0 ++ R
        /\ forall c, c ∈ R -> L0.length < c.index := by
  unfold configurationHistory
  rw [List.zipIdx_append, List.filterMap_append]
  refine ⟨_, rfl, fun c mem => ?_⟩
  obtain ⟨⟨e, i⟩, memZ, found⟩ := List.mem_filterMap.mp mem
  have := List.mem_zipIdx memZ
  cases h : e.content.metadata.configuration with
  | none => simp [h] at found
  | some nodes =>
      simp only [h, Option.map_some, Option.some.injEq] at found
      subst found
      simp only
      omega

theorem active_append {L0 : List Model.Node.Entry} (T : List Model.Node.Entry) {ci : Nat}
    (le : ci <= L0.length)
    : exists R,
        activeConfigurations (L0 ++ T) ci = activeConfigurations L0 ci ++ R
        /\ forall c, c ∈ R -> L0.length < c.index := by
  obtain ⟨R, hR, above⟩ := history_append L0 T
  refine ⟨R, ?_, above⟩
  unfold activeConfigurations
  dsimp only
  rw [hR, List.filter_append]
  have none : R.filter (fun c => decide (c.index <= ci)) = [] :=
    List.filter_eq_nil_iff.mpr fun c mem => by
      have := above c mem
      simp only [decide_eq_true_eq]
      omega
  rw [none, List.append_nil, List.drop_append_of_le_length]
  have := List.length_filter_le (fun c => decide (c.index <= ci)) (configurationHistory L0)
  omega

theorem entryAt_append {L0 : List Model.Node.Entry} (T : List Model.Node.Entry)
    {idx : Nat} (le : idx <= L0.length)
    : entryAt? (L0 ++ T) idx = entryAt? L0 idx := by
  unfold entryAt?
  split
  · rfl
  · rw [List.getElem?_append_left (by omega)]

/--
Appending entries to a primary whose commit index is maximal does not let it commit, when an
active configuration has another member and no other member has reached the old log's end.
-/
theorem hc_stuck {st st' : NodeState} {self : NodeID} {T : List Model.Node.Entry}
    (log : st'.log = st.log ++ T) (commit : st'.commitIndex = st.commitIndex)
    (term : st'.currentTerm = st.currentTerm) (match_ : st'.matchIndex = st.matchIndex)
    (hmax : highestCommittableIndex st self <= st.commitIndex)
    (ciLe : st.commitIndex <= st.log.length)
    {X : Configuration} (hX : X ∈ activeConfigurations st.log st.commitIndex)
    {m : NodeID} (hm : m ∈ X.nodes) (mne : m ≠ self)
    (low : forall n, n ∈ X.nodes -> n ≠ self -> st.matchIndex n <= st.log.length)
    : highestCommittableIndex st' self <= st'.commitIndex := by
  obtain ⟨R, hA, above⟩ := active_append T ciLe
  unfold highestCommittableIndex at hmax ⊢
  simp only [NodeState.activeMembers, NodeState.activeConfigurations, log, commit, term,
    match_] at hmax ⊢
  have hfix := foldl_fixed (fun a x => le_ite_self fun c => Nat.le_of_lt c.1) _ _ hmax
  refine Nat.le_of_eq (foldl_const _ _ fun idx mem => ?_)
  split
  · rename_i c
    exfalso
    obtain ⟨gt, sig, tm, q⟩ := c
    rw [hA, List.filter_append] at q
    have range := List.mem_range.mp mem
    have hXh : X ∈ configurationHistory st.log := by
      unfold activeConfigurations at hX
      exact List.mem_of_mem_drop hX
    have members : forall Y, Y ∈ activeConfigurations st.log st.commitIndex -> forall n,
        n ∈ Y.nodes -> n ∈ configurationMembers (activeConfigurations st.log st.commitIndex ++ R)
          /\ n ∈ configurationMembers (activeConfigurations st.log st.commitIndex) :=
      fun Y memY n member => ⟨ReplUpdateCommit.mem_configurationMembers
        (List.mem_append_left _ memY) member,
        ReplUpdateCommit.mem_configurationMembers memY member⟩
    by_cases le : idx <= st.log.length
    · have fx := hfix idx (List.mem_range.mpr (by omega))
      rw [(List.filter_eq_nil_iff (l := R)).mpr (fun c memR => by
        have := above c memR
        simp only [decide_eq_true_eq]
        omega), List.append_nil] at q
      split at fx
      · omega
      · rename_i nc
        refine nc ⟨gt, by simpa only [isSignatureAt, entryAt_append T le] using sig,
          by simpa only [termAt, entryAt_append T le] using tm, q.1,
          List.all_eq_true.mpr fun Y memY => decide_eq_true ?_⟩
        have maj := of_decide_eq_true (List.all_eq_true.mp q.2 Y memY)
        have memY' := (List.mem_filter.mp memY).1
        unfold hasConfigurationMajority at maj ⊢
        refine Nat.lt_of_lt_of_le maj (Nat.mul_le_mul_right _ (CCF.Finset.card_le_card ?_))
        intro n inS
        obtain ⟨inR, inY⟩ := CCF.Finset.mem_inter.mp inS
        obtain ⟨-, which⟩ := CCF.Finset.mem_filter.mp inR
        exact CCF.Finset.mem_inter.mpr ⟨CCF.Finset.mem_filter.mpr
          ⟨(members Y memY' n inY).2, which⟩, inY⟩
    · have XLe := history_index_le st.log X hXh
      have memF : X ∈ (activeConfigurations st.log st.commitIndex ++ R).filter
          fun c => decide (c.index <= idx) :=
        List.mem_filter.mpr ⟨List.mem_append_left _ hX, decide_eq_true (by omega)⟩
      rw [← List.filter_append] at q
      have maj := of_decide_eq_true (List.all_eq_true.mp q.2 X memF)
      unfold hasConfigurationMajority at maj
      generalize hs : (CCF.Finset.filter (fun n => n = self \/ st.matchIndex n >= idx)
        (configurationMembers (activeConfigurations st.log st.commitIndex ++ R)) ∩ X.nodes) = s
        at maj
      have only : forall n, n ∈ s -> n = self := by
        intro n inS
        rw [← hs] at inS
        obtain ⟨inR, inY⟩ := CCF.Finset.mem_inter.mp inS
        obtain ⟨-, which⟩ := CCF.Finset.mem_filter.mp inR
        refine Decidable.by_contra fun ne => ?_
        have := low n inY ne
        rcases which with e | ge
        · exact ne e
        · omega
      have one : s.card <= 1 := by
        have := CCF.Finset.card_le_card (s := s) (t := {self})
          fun n inS => CCF.Finset.mem_singleton.mpr (only n inS)
        exact this
      have disj : CCF.Finset.Disjoint s {m} := fun n inS inM =>
        mne ((CCF.Finset.mem_singleton.mp inM).symm.trans (only n inS) |>.symm.symm)
      have sub : s ∪ {m} ⊆ X.nodes := by
        intro n inU
        rcases CCF.Finset.mem_union.mp inU with inS | inM
        · rw [← hs] at inS
          exact (CCF.Finset.mem_inter.mp inS).2
        · rw [CCF.Finset.mem_singleton.mp inM]
          exact hm
      have := CCF.Finset.card_le_card sub
      rw [CCF.Finset.card_union_of_disjoint disj] at this
      have m1 : ({m} : Finset NodeID).card = 1 := rfl
      omega
  · rfl

/-! ## The clean batch run -/

section CleanRun

open CCF.Sections (LocalRun)
open Consensus.TraceValidation (Env protocol)

theorem emits_appendBatch {cl0 cl cl' : NodeState} {es : List AppendEntryInput}
    {o o2 : List (CCF.Envelope NodeID Message)} (prim : cl0.role = .primary)
    (notRC : ¬ cl0.isRetiredCommitted node) (ne : es ≠ [])
    (em : Emits (es.foldlM (entryStep node) cl0) cl o)
    (ha : Emits (advanceCommit (CCF.Capabilities.record node) cl node) cl' o2)
    : Emits (appendBatch (CCF.Capabilities.record node) node cl0 es) cl' (o ++ o2) := by
  unfold appendBatch
  exact emits_congr (emits_bind (emits_guard ⟨prim, notRC, ne⟩) (emits_bind em ha)) rfl
    (List.nil_append _)

theorem localRun_append (env : Env) {cl0 cl' : NodeState} {es : List AppendEntryInput}
    {o : List (CCF.Envelope NodeID Message)}
    (h : Emits (appendBatch (CCF.Capabilities.record node) node cl0 es) cl' o)
    : LocalRun (protocol env) node cl0 (cleanActions env none [.append es]) cl' o := by
  have := LocalRun.cons (protocol := protocol env) (node := node) (state := cl0)
    (action := (protocol env).internal (.append es)) (effects := { outgoing := o })
    (emits_run h) (LocalRun.nil cl')
  simpa [cleanActions] using this

end CleanRun

/-! ## The batch's commit, against the declared state -/

section Declared

open Consensus.TraceValidation (Names abs agrees trackedPeers inv UnnamedUnmatched)
open Consensus.TraceValidation.Exec
open ReplUpdateCommit (Named named_inj Hyps shifted_mem absConfig)
open AeResp (Agrees hc_of_agrees)

theorem eraseDups_eq_nil_iff {l : List NodeId} : l.eraseDups = [] <-> l = [] := by
  cases l with
  | nil => simp
  | cons x xs => simp [List.eraseDups_cons]

/-- No other node is in the active configurations iff every member is the node itself. -/
theorem others_empty_iff (v : State)
    : v.otherNodesInActiveConfigs.isEmpty = true
      <-> forall c, c ∈ v.configurations -> forall a, a ∈ c.nodes -> a.1 = v.nodeId := by
  unfold State.otherNodesInActiveConfigs
  rw [List.isEmpty_iff, eraseDups_eq_nil_iff, ← List.length_eq_zero_iff, List.length_mergeSort,
    List.length_eq_zero_iff, List.filter_eq_nil_iff]
  simp only [List.mem_flatMap, List.mem_map, bne_iff_ne, ne_eq, Decidable.not_not]
  constructor
  · intro h c mc a ma
    exact h a.1 ⟨c, mc, a, ma, rfl⟩
  · rintro h x ⟨c, mc, a, ma, rfl⟩
    exact h c mc a ma

variable {names : Names} {node : NodeID} {v0 : State} {cl0 : NodeState}

/-- The clean match index of a node of the starting active configurations is in the log. -/
theorem Start.matchLow (S : Start names node v0 cl0) {n : NodeID}
    (act : n ∈ cl0.activeMembers) (ne : n ≠ node)
    : cl0.matchIndex n <= v0.lastIdx := by
  have M := Mid.start S
  obtain ⟨k, memK, rfl⟩ := (M.eligible n).mp
    (CCF.Finset.mem_erase.mpr ⟨ne, CCF.Finset.mem_union.mpr (Or.inl act)⟩)
  obtain ⟨p, memP⟩ := mem_keys.mp memK
  obtain ⟨f, -, P⟩ := M.clean
  have bounds : (v0.leadership != .leader
      || v0.allOtherNodes.all fun (_, p) => p.sentIdx <= v0.lastIdx && p.matchIdx <= v0.lastIdx)
      = true := by
    inv_conj S.inv "peer_bounds"
  simp only [S.leader, bne_self_eq_false, Bool.false_or, List.all_eq_true,
    Bool.and_eq_true, decide_eq_true_eq] at bounds
  rw [(P.rel k p ((lookup_iff_mem P.nodup).mpr memP)).2.2]
  exact (bounds _ memP).2

/-- The clean commit before the batch is maximal (`commit_maximal`). -/
theorem Start.maximal (S : Start names node v0 cl0)
    : highestCommittableIndex cl0 node <= cl0.commitIndex := by
  have M0 := Mid.start S
  have e : (v0.leadership != .leader
      || decide (highestCommittableIndex (abs names v0) (names.id v0.nodeId)
        <= v0.commitIdx)) = true := by
    inv_conj S.inv "commit_maximal"
  simp only [S.leader, bne_self_eq_false, Bool.false_or, decide_eq_true_eq] at e
  rw [← S.self, hc_of_agrees (Agrees.of S.agrees) fun n el => ?_, S.commit]
  · exact e
  · rw [S.self] at el
    obtain ⟨k, memK, rfl⟩ := (M0.eligible n).mp el
    obtain ⟨p, memP⟩ := mem_keys.mp memK
    exact (tracked_iff S.leader).mpr ⟨k, p, memP, rfl⟩

/-- With other nodes before the batch, the clean commit after it does not move. -/
theorem Mid.stuck (S : Start names node v0 cl0) {cl : NodeState} {v : State}
    (M : Mid names node v0 cl0 cl v)
    (others : v0.otherNodesInActiveConfigs.isEmpty = false)
    : highestCommittableIndex cl node <= cl.commitIndex := by
  obtain ⟨c, mc, a, ma, ne⟩ : exists c, c ∈ v0.configurations /\ exists a, a ∈ c.nodes
      /\ a.1 ≠ v0.nodeId := by
    refine Decidable.by_contra fun h => ?_
    have := (others_empty_iff v0).mpr fun c mc a ma =>
      Decidable.by_contra fun e => h ⟨c, mc, a, ma, e⟩
    rw [this] at others
    cases others
  have M0 := Mid.start S
  have hy := M0.hy
  have L0 := M0.pos (List.ne_nil_of_mem mc)
  have len : cl0.log.length = v0.lastIdx := by
    rw [S.log]
    exact ReplUpdateCommit.abs_log_length hy.size
  obtain ⟨D, hD, sh⟩ := hy.configs L0
  obtain ⟨x', memD, nodes⟩ := shifted_mem sh mc
  have named : Named names a.1 := hy.membersNamed c mc a ma
  have hX : absConfig names x' ∈ activeConfigurations cl0.log cl0.commitIndex := by
    rw [S.log, S.commit, hD]
    exact List.mem_map_of_mem memD
  have inX : names.id a.1 ∈ (absConfig names x').nodes := by
    simp only [absConfig, nodes, Names.set, CCF.Finset.mem_ofList, List.mem_map]
    exact ⟨a.1, ⟨a, ma, rfl⟩, rfl⟩
  have mne : names.id a.1 ≠ node := fun e =>
    ne (named_inj named hy.selfNamed (e.trans (S.self).symm))
  have hmax := S.maximal
  obtain ⟨f, rfl, -⟩ := M.clean
  obtain ⟨T, hT⟩ := M.isPrefix
  refine hc_stuck (st := cl0) (T := T) hT.symm rfl rfl rfl hmax ?_ hX inX mne
    fun n mem nne => ?_
  · rw [len, S.commit]
    exact hy.commitLe
  · rw [len]
    exact S.matchLow (ReplUpdateCommit.mem_configurationMembers hX mem) nne

theorem Mid.cover (S : Start names node v0 cl0) {cl : NodeState} {v : State}
    (M : Mid names node v0 cl0 cl v)
    : AeResp.Cover v := by
  rintro id ⟨c, memC, a, ma, rfl⟩ ne
  rcases M.member S memC ma with e | k
  · exact absurd e ne
  · obtain ⟨q, memQ⟩ := mem_keys.mp k
    exact ⟨(a.1, q), memQ, rfl⟩

/-- Without other nodes before the batch, no pending record names a node `v` keeps. -/
theorem Mid.rcRetired {cl : NodeState} {v : State}
    (M : Mid names node v0 cl0 cl v) (alone : v0.otherNodesInActiveConfigs.isEmpty = true)
    (i : Nat)
    : AeResp.RcRetired v i := by
  intro e memE _ id memId ne mem
  obtain ⟨c, memC, a, ma, rfl⟩ := mem.suffix (AeResp.pop_suffix _ _)
  obtain ⟨new, hv, fresh⟩ := M.cfgNew
  rw [hv] at memC
  rcases List.mem_append.mp memC with old | memN
  · exact ne (((others_empty_iff v0).mp alone c old a ma).trans M.frame.nodeId.symm)
  · exact fresh c memN a ma (M.rcRemoved e memE a.1 memId)

end Declared

/-! ## `update_commit` after the batch -/

section Uc

open Consensus.TraceValidation (Env)
open Consensus.TraceValidation.Exec
open Consensus.TraceValidation.Proofs.Ae
open AeResp (RInv Cover RcRetired commit_spec hoare_assume hoare_curLoc_fail)

/-- What `update_commit` by a leader `v1` with outbox `o1` leaves. -/
def UcOut (env : Env) (v1 : State) (o1 : Outbox) (v : State) (o : Outbox) : Prop :=
  exists res,
    ReplUpdateCommit.updateCommitOf v1 0 none (v1.lastIdx + 2) = .ok res
    /\ ((res.getD v1.commitIdx <= v1.commitIdx /\ v = v1 /\ o = o1)
        \/ exists i,
            res = some i /\ v1.commitIdx < i /\ i <= v1.lastIdx /\ RInv env v1 i o1 v o)

theorem updateCommit_hoare (env : Env) {v1 : State} {o1 : Outbox}
    (lead : v1.leadership = .leader) (cover : Cover v1) (hrc : forall i, RcRetired v1 i)
    : Hoare env (fun v o => v = v1 /\ o = o1) Exec.updateCommit
        fun _ => UcOut env v1 o1 := by
  unfold Exec.updateCommit
  refine Hoare.getV_bind fun s => ?_
  refine hoare_assume (φ := s = v1) (fun _ _ p => p.2.symm.trans p.1.1) fun e => ?_
  subst s
  have l1 : (v1.leadership == .leader) = true := by simp [lead]
  simp only [l1, ↓reduceIte]
  refine Hoare.bind (Hoare.of_spec (ReplUpdateCommit.updateCommitGo_spec _ _ _)
    (Q := fun res v o => v = v1 /\ o = o1
      /\ ReplUpdateCommit.updateCommitOf v1 0 none (v1.lastIdx + 2) = .ok res)
    fun v o a v' o' p q => ?_) fun res => ?_
  · obtain ⟨⟨e, f⟩, -⟩ := p
    obtain ⟨q1, q2, q3⟩ := q
    rw [q1, q2, e, f]
    exact ⟨rfl, rfl, e ▸ q3⟩
  have out : forall (v : State) (o : Outbox), (v = v1 /\ o = o1
      /\ ReplUpdateCommit.updateCommitOf v1 0 none (v1.lastIdx + 2) = .ok res)
      -> res.getD v1.commitIdx <= v1.commitIdx -> UcOut env v1 o1 v o :=
    fun v o p le => ⟨res, p.2.2, Or.inl ⟨le, p.1, p.2.1⟩⟩
  cases res with
  | none => exact Hoare.pure _ fun v o p => out v o p (Nat.le_refl _)
  | some i =>
      simp only
      by_cases gt : i > v1.lastIdx
      · unfold Exec.commit
        refine Hoare.getV_bind fun s => ?_
        refine hoare_assume (φ := s = v1) (fun _ _ p => p.2.symm.trans p.1.1) fun e => ?_
        subst s
        simp only [gt, ↓reduceIte]
        exact hoare_curLoc_fail _
      by_cases le : i <= v1.commitIdx
      · unfold Exec.commit
        refine Hoare.getV_bind fun s => ?_
        refine hoare_assume (φ := s = v1) (fun _ _ p => p.2.symm.trans p.1.1) fun e => ?_
        subst s
        simp only [gt, le, ↓reduceIte]
        exact Hoare.pure _ fun v o p => out v o p.1 le
      refine hoare_assume (φ := ReplUpdateCommit.updateCommitOf v1 0 none (v1.lastIdx + 2)
          = .ok (some i)) (fun _ _ p => p.2.2) fun ran => ?_
      exact Hoare.post
        (Hoare.pre
          (commit_spec env (v1 := v1) (o0 := o1) lead (by omega) (by omega) cover (hrc i))
          fun v o p => ⟨p.1, p.2.1⟩)
        fun _ v o q => ⟨some i, ran, Or.inr ⟨i, rfl, by omega, by omega, q⟩⟩

end Uc

end Consensus.TraceValidation.Proofs.Repl
