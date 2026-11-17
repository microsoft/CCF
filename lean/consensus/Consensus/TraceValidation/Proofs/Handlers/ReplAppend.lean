module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import Consensus.TraceValidation.Proofs.Handlers.ReplPush

@[expose] public section

/-!
# Appending one entry: the declared side (not reviewed; `Replicate` obligation)

`replicate_entry` checks an entry (`Guards`), runs its hooks, which change only the fields
`Hooked` lists, and appends it. The peers its configuration adds are the nodes the clean
`appendEntry` adds, with the same heartbeats, so the ghost extends by one clean entry
(`push_ghost`).
-/

namespace Consensus.TraceValidation.Proofs.Repl

open Consensus.Model.Node
open Consensus.TraceValidation (Names abs absEntry msgInv)
open Consensus.TraceValidation.Exec
open ReplUpdateCommit (Named named_inj Hyps shifted_mem absConfig)
open CCF (Finset)

/-- The declared entry `replicate_entry` appends. -/
def entryOf (v : State) (sig : Bool) (config : Option Nodes) (retired : List NodeId)
    : Exec.Entry :=
  { term := v.currentView, sig, config, retired }

/-- The clean content of that entry. -/
def contentOf (names : Names) (v : State) (sig : Bool) (config : Option Nodes)
    (retired : List NodeId)
    : EntryContent :=
  (absEntry names (entryOf v sig config retired)).content

/-- The configuration the entry adds to the declared configurations. -/
def cfgsOf (v : State) (config : Option Nodes) : List Config :=
  (config.map
    fun nodes => ({ idx := v.lastIdx + 1, nodes, rid := v.lastIdx + 1 } : Config)).toList

/-- The nodes the entry's configuration adds as peers. -/
def newE (v : State) (config : Option Nodes) : List NodeId :=
  newOf v
    (((v.configurations ++ cfgsOf v config).flatMap (·.nodes.map Prod.fst)).mergeSort
        (· <= ·)
      |>.eraseDups)

/-- What `replicate_entry` checks of an entry before appending it. -/
structure Guards (names : Names) (v : State) (sig : Bool) (config : Option Nodes)
    (retired : List NodeId)
    : Prop where
  sigNonempty : sig = true -> v.lastIdx ≠ 0
  sigPlain : sig = true -> retired = [] /\ config = none
  rc
    : retired ≠ []
      -> names.set retired
          ⊆ (abs names v).retirementCompletedNodes
            \ retiredCommittedNodes (abs names v).log
  known
    : forall id,
        id ∈ (config.getD []).map Prod.fst ++ retired -> names.known.contains id = true
  sorted : (config.getD []).map Prod.fst ++ retired ≠ [] -> SortedNames names
  cfg
    : forall nodes,
        config = some nodes
        -> (nodes.map Prod.fst).Nodup
            /\ nodes ≠ []
            /\ names.set (nodes.map Prod.fst)
                ≠ latestConfigurationMembers (configurationHistory (abs names v).log)
            /\ forall a, a ∈ nodes -> names.id a.1 ∉ removedNodes (abs names v).log

/-- The retirement confirmations the entry adds to the declared ones. -/
def rcsOf (v : State) (retired : List NodeId) : List (Nat × List NodeId) :=
  if retired.isEmpty then [] else [(v.lastIdx + 1, retired)]

/-- The state after the hooks: only these fields have changed. -/
def Hooked (v1 : State) (K : List Nat) (cfgs : List Config) (R : List (Nat × List NodeId))
    (w : State)
    : Prop :=
  exists tk r ph ri rci ps,
    w
    = {
      v1 with
        committable := v1.committable ++ K,
        configurations := v1.configurations ++ cfgs,
        allOtherNodes := ps,
        rcEntries := v1.rcEntries ++ R,
        ticking := tk,
        retired := r,
        retirementPhase := ph,
        retirementIdx := ri,
        retirementCommittableIdx := rci
    }

/-- The state after the entry is appended and the view history extended. -/
def pushed (v1 w : State) (e : Exec.Entry) : State :=
  {
    w with
      lastIdx := v1.lastIdx + 1,
      ledger := w.ledger.push e
      views := w.views ++ Array.replicate (w.currentView - w.views.size) (v1.lastIdx + 1)
  }

variable {env : Env} {names : Names} {node : NodeID} {v0 : State} {cl0 : NodeState}

section
variable (S : Start names node v0 cl0) {cl1 : NodeState} {v1 : State}
  (M : Mid names node v0 cl0 cl1 v1)
include S M

theorem Mid.mem_newE {config : Option Nodes} {k : NodeId}
    : k ∈ newE v1 config
      <-> (exists nodes, config = some nodes /\ k ∈ nodes.map Prod.fst)
          /\ k ≠ v1.nodeId
          /\ v1.peer? k = none := by
  unfold newE
  rw [mem_newOf, (sortDedup_spec _).2, List.mem_flatMap]
  constructor
  · rintro ⟨⟨x, memX, memK⟩, ne, none⟩
    refine ⟨?_, ne, none⟩
    rcases List.mem_append.mp memX with memX | memX
    · obtain ⟨a, ma, rfl⟩ := List.mem_map.mp memK
      rcases M.member S memX ma with e | e
      · exact absurd e ne
      · have := peer_isSome_iff.mpr e
        rw [none] at this
        cases this
    · cases hc : config with
      | none => simp [cfgsOf, hc] at memX
      | some nodes =>
          simp only [cfgsOf, hc, Option.map_some, Option.toList_some, List.mem_singleton] at memX
          subst memX
          exact ⟨nodes, rfl, memK⟩
  · rintro ⟨⟨nodes, rfl, memK⟩, ne, none⟩
    exact ⟨⟨{ idx := v1.lastIdx + 1, nodes, rid := v1.lastIdx + 1 }, List.mem_append_right _ (by simp [cfgsOf]), memK⟩, ne, none⟩

theorem Mid.named_of_newE {config : Option Nodes} {k : NodeId} {sig : Bool}
    {retired : List NodeId} (G : Guards names v1 sig config retired)
    (mem : k ∈ newE v1 config)
    : names.known.contains k = true := by
  obtain ⟨⟨nodes, rfl, memK⟩, -, -⟩ := (M.mem_newE S).mp mem
  exact G.known k (List.mem_append_left _ (by simpa using memK))

theorem Mid.addedOf_iff {sig : Bool} {config : Option Nodes} {retired : List NodeId}
    (G : Guards names v1 sig config retired) {p : NodeID}
    : p ∈ addedOf cl1 node (contentOf names v1 sig config retired)
      <-> exists k, k ∈ newE v1 config /\ names.id k = p := by
  have self := M.self S
  have none : forall k, k ∉ newE v1 none := by
    intro k mem
    obtain ⟨⟨_, e, _⟩, -⟩ := (M.mem_newE S).mp mem
    cases e
  cases sig with
  | true =>
      obtain ⟨-, rfl⟩ := G.sigPlain rfl
      simp only [addedOf, contentOf, absEntry, entryOf, ite_true, EntryContent.metadata,
        CCF.Finset.notMem_empty, false_iff, not_exists, not_and]
      exact fun k mem => absurd mem (none k)
  | false =>
      cases config with
      | none =>
          simp only [addedOf, contentOf, absEntry, entryOf, Bool.false_eq_true, ite_false,
            EntryContent.metadata, Option.map_none, CCF.Finset.notMem_empty, false_iff, not_exists,
            not_and]
          exact fun k mem => absurd mem (none k)
      | some nodes =>
          simp only [addedOf, contentOf, absEntry, entryOf, Bool.false_eq_true, ite_false,
            EntryContent.metadata, Option.map_some, CCF.Finset.mem_erase, CCF.Finset.mem_sdiff,
            Names.set, CCF.Finset.mem_ofList, List.mem_map]
          constructor
          · rintro ⟨ne, ⟨k, memK, rfl⟩, notEl⟩
            refine ⟨
              k,
              (M.mem_newE S).mpr ⟨⟨nodes, rfl, List.mem_map.mpr memK⟩, ?_, ?_⟩,
              rfl
            ⟩
            · rintro rfl
              exact ne self
            · cases h : v1.peer? k with
              | none => rfl
              | some q =>
                  refine absurd ((M.eligible _).mpr ⟨k, ?_, rfl⟩) notEl
                  exact peer_isSome_iff.mp (by rw [h]; rfl)
          · rintro ⟨k, mem, rfl⟩
            have known := M.named_of_newE S G mem
            obtain ⟨⟨nodes', e, memK⟩, ne, none⟩ := (M.mem_newE S).mp mem
            cases e
            refine ⟨fun e => ne (named_inj (named_of_known known) M.hy.selfNamed
              (e.trans self.symm)), ⟨k, List.mem_map.mp memK, rfl⟩, fun el => ?_⟩
            obtain ⟨k', memK', e⟩ := (M.eligible _).mp el
            obtain ⟨q, memQ⟩ := mem_keys.mp memK'
            have := named_inj (M.hy.peersNamed _ memQ) (named_of_known known) e
            subst this
            have := peer_isSome_iff.mpr memK'
            rw [none] at this
            cases this

theorem Mid.addedOf_sort {sig : Bool} {config : Option Nodes} {retired : List NodeId}
    (G : Guards names v1 sig config retired)
    : (addedOf cl1 node (contentOf names v1 sig config retired)).sort
      = (newE v1 config).map names.id := by
  refine CCF.Finset.eq_of_sorted_of_mem_iff (addedOf _ _ _).sorted ?_ fun p => ?_
  · cases h : newE v1 config with
    | nil => exact List.Pairwise.nil
    | cons k rest =>
        have mem : k ∈ newE v1 config := by rw [h]; exact List.mem_cons_self
        obtain ⟨⟨nodes, hc, memK⟩, -, -⟩ := (M.mem_newE S).mp mem
        have sorted := G.sorted (by
          subst hc
          intro e
          rw [Option.getD_some, List.append_eq_nil_iff] at e
          rw [e.1] at memK
          cases memK)
        rw [← h]
        refine map_id_sorted sorted ?_ fun x m => M.named_of_newE S G m
        exact ((sortDedup_spec _).1).filter _
  · rw [CCF.Finset.mem_sort, M.addedOf_iff S G, List.mem_map]

end

theorem Mid.hb_eq {env : Env} {node : NodeID} {v0 : State} {cl0 : NodeState}
    (S : Start env.names node v0 cl0) {cl1 : NodeState} {v1 : State}
    (M : Mid env.names node v0 cl0 cl1 v1) (k : NodeId)
    : hbClean node cl1 (env.names.id k) = hb env v1 k := by
  unfold hbClean hb rangeRequest
  rw [M.self S, M.cleanTerm S, M.cleanCommit S, M.cleanLog,
    ReplUpdateCommit.abs_log_length M.hy.size, getTerm_vh (names := env.names) M.vh]
  simp

theorem Mid.msgInv_hb {env : Env} {node : NodeID} {v0 : State} {cl0 : NodeState}
    (S : Start env.names node v0 cl0) {cl1 : NodeState} {v1 : State}
    (M : Mid env.names node v0 cl0 cl1 v1) {k : NodeId} (named : Named env.names k)
    (ne : k ≠ v1.nodeId)
    : msgInv env.names (hb env v1 k) = true := by
  have := msgInv_range S M (to := k)
    (fun e => ne (named_inj named M.hy.selfNamed (e.symm.trans (M.self S).symm)))
    (Nat.le_refl _) (Nat.le_refl _) (Nat.le_refl _) fun i a b => absurd b (by omega)
  unfold hb
  rw [M.self S]
  exact this

/-! ## The appended declared state -/

theorem abs_log_push {u v : State} (e : Exec.Entry) (size : v.ledger.size = v.lastIdx)
    (hl : u.ledger = v.ledger.push e) (hL : u.lastIdx = v.lastIdx + 1)
    : (abs names u).log = (abs names v).log ++ [absEntry names e] := by
  show (u.ledger.toList.take u.lastIdx).map _
  = (v.ledger.toList.take v.lastIdx).map _ ++ _
  rw [hl, hL, Array.toList_push, List.take_of_length_le (by simp [size]),
    List.take_of_length_le (by simp [size]), List.map_append, List.map_singleton]

theorem signaturesIn_push {u v : State} (e : Exec.Entry)
    (size : v.ledger.size = v.lastIdx) (hl : u.ledger = v.ledger.push e) {c : Nat}
    (hc : c <= v.lastIdx)
    : signaturesIn u c (v.lastIdx + 1)
      = signaturesIn v c v.lastIdx ++ (if e.sig then [v.lastIdx + 1] else []) := by
  unfold signaturesIn
  rw [show v.lastIdx + 1 - c = (v.lastIdx - c) + 1 by omega, List.range'_concat,
    List.filter_append]
  congr 1
  · refine List.filter_congr fun i mem => ?_
    rw [List.mem_range'_1] at mem
    rw [hl, Array.getElem?_push_lt (by omega), Array.getElem?_eq_getElem (by omega)]
  · rw [hl, Nat.one_mul, show c + 1 + (v.lastIdx - c) = v.lastIdx + 1 by omega]
    cases h : e.sig <;> simp [Array.getElem?_push, size, h]

theorem viewAt_ext {u v : State} {n L : Nat}
    (hv : u.views = v.views ++ Array.replicate n (L + 1)) {i : Nat} (hi : i <= L)
    : u.viewAt i = v.viewAt i := by
  unfold State.viewAt
  rw [hv, Array.toList_append, List.filter_append, Array.toList_replicate, List.length_append]
  simp only [List.filter_replicate, show ¬ (L + 1 <= i) by omega, decide_false, Bool.false_eq_true,
    ite_false, List.length_nil, Nat.add_zero]

theorem viewAt_ext_last {u v : State} {n L : Nat}
    (hv : u.views = v.views ++ Array.replicate n (L + 1))
    (le : forall x, x ∈ v.views.toList -> x <= L + 1)
    : u.viewAt (L + 1) = v.views.size + n := by
  unfold State.viewAt
  rw [hv, Array.toList_append, List.filter_append, Array.toList_replicate, List.length_append,
    List.filter_eq_self.mpr fun x m => decide_eq_true (le x m)]
  simp

theorem latest_active {log : List Consensus.Model.Node.Entry} {c : Nat} {n : NodeID}
    (mem : n ∈ latestConfigurationMembers (configurationHistory log))
    : n ∈ configurationMembers (activeConfigurations log c) := by
  unfold latestConfigurationMembers at mem
  cases h : (configurationHistory log).getLast? with
  | none => simp [h, CCF.Finset.notMem_empty] at mem
  | some x =>
      simp only [h, Option.map_some, Option.getD_some] at mem
      refine Repl.mem_members_iff.mpr ⟨x, ?_, mem⟩
      unfold activeConfigurations
      dsimp only
      have len := List.length_filter_le (fun c' : Configuration => decide (c'.index <= c))
        (configurationHistory log)
      have pos : 0 < (configurationHistory log).length := by
        cases e : configurationHistory log with
        | nil => rw [e] at h; cases h
        | cons _ _ => simp
      apply List.mem_of_getLast? (l := (configurationHistory log).drop _)
      rw [List.getLast?_drop, h]
      simp only [show ¬ ((configurationHistory log).length
        <= ((configurationHistory log).filter fun c' => decide (c'.index <= c)).length - 1) by omega,
        ite_false]

theorem Start.viewPos (S : Start names node v0 cl0) : 0 < v0.currentView := by
  have invS := S.inv
  have vz : (v0.currentView != 0
      || (v0.lastIdx == 0 && v0.leadership != .leader && v0.leadership != .candidate)) = true := by
    inv_conj invS "view_zero"
  simp only [S.leader, bne_self_eq_false, Bool.and_false, Bool.false_and, Bool.or_false,
    bne_iff_ne, ne_eq] at vz
  omega

theorem shifted_append {c : Nat} {D E : List Config} (h : ReplUpdateCommit.Shifted c D E)
    (X : List Config)
    : ReplUpdateCommit.Shifted c (D ++ X) (E ++ X) := by
  rcases h with rfl | ⟨x, y, rest, rfl, rfl, n, i, j⟩
  · exact Or.inl rfl
  · exact Or.inr ⟨x, y, rest ++ X, rfl, rfl, n, i, j⟩

theorem cfgs_abs {v : State} {sig : Bool} {config : Option Nodes} {retired : List NodeId}
    (plain : sig = true -> config = none)
    : entryConfig (absEntry names (entryOf v sig config retired)) (v.lastIdx + 1)
      = (cfgsOf v config).map (absConfig names) := by
  cases sig with
  | true =>
      rw [plain rfl]
      simp [entryConfig, absEntry, entryOf, cfgsOf, EntryContent.metadata]
  | false =>
      cases config <;> simp [entryConfig, absEntry, entryOf, cfgsOf, EntryContent.metadata, absConfig]

section
variable (S : Start names node v0 cl0) {cl1 : NodeState} {v1 : State}
  (M : Mid names node v0 cl0 cl1 v1)
include S M

/-- The appended declared state satisfies `Hyps` and `ViewHyps`. -/
theorem Mid.push_hyps {sig : Bool} {config : Option Nodes} {retired : List NodeId}
    (G : Guards names v1 sig config retired) {R : List (Nat × List NodeId)} {w : State}
    (hw : Hooked v1 (if sig then [v1.lastIdx + 1] else []) (cfgsOf v1 config) R w)
    (named : forall p, p ∈ w.allOtherNodes -> Named names p.1)
    : Hyps names (pushed v1 w (entryOf v1 sig config retired))
      /\ ViewHyps (pushed v1 w (entryOf v1 sig config retired)) := by
  obtain ⟨tk, r, ph, ri, rci, ps, rfl⟩ := hw
  have hy := M.hy
  have vh := M.vh
  have cv : 0 < v1.currentView := M.frame.view ▸ S.viewPos
  generalize he : entryOf v1 sig config retired = e
  have eTerm : e.term = v1.currentView := by rw [← he]; rfl
  have eSig : e.sig = sig := by rw [← he]; rfl
  have hl : (pushed v1 { v1 with
      committable := v1.committable ++ (if sig then [v1.lastIdx + 1] else []),
      configurations := v1.configurations ++ cfgsOf v1 config, allOtherNodes := ps,
      rcEntries := v1.rcEntries ++ R, ticking := tk, retired := r, retirementPhase := ph, retirementIdx := ri,
      retirementCommittableIdx := rci } e).ledger = v1.ledger.push e := rfl
  generalize hP : pushed v1 { v1 with
      committable := v1.committable ++ (if sig then [v1.lastIdx + 1] else []),
      configurations := v1.configurations ++ cfgsOf v1 config, allOtherNodes := ps,
      rcEntries := v1.rcEntries ++ R, ticking := tk, retired := r, retirementPhase := ph, retirementIdx := ri,
      retirementCommittableIdx := rci } e = P at hl named
  have hL : P.lastIdx = v1.lastIdx + 1 := by rw [← hP]; rfl
  have hv : P.views = v1.views ++ Array.replicate (v1.currentView - v1.views.size)
      (v1.lastIdx + 1) := by rw [← hP]; rfl
  have hcv : P.currentView = v1.currentView := by rw [← hP]; rfl
  have hc : P.commitIdx = v1.commitIdx := by rw [← hP]; rfl
  have hcom : P.committable = v1.committable ++ (if sig then [v1.lastIdx + 1] else []) := by
    rw [← hP]; rfl
  have hcfg : P.configurations = v1.configurations ++ cfgsOf v1 config := by rw [← hP]; rfl
  have hid : P.nodeId = v1.nodeId := by rw [← hP]; rfl
  have hps : P.allOtherNodes = ps := by rw [← hP]; rfl
  have size : P.ledger.size = P.lastIdx := by rw [hl, hL, Array.size_push, hy.size]
  have leLast := vh.leLast
  have terms : forall i, 1 <= i -> i <= P.lastIdx
      -> P.ledger[i - 1]?.map (·.term) = some (P.viewAt i) := by
    intro i i1 iL
    rw [hL] at iL
    rcases Nat.lt_or_ge i (v1.lastIdx + 1) with lt | ge
    · rw [hl, Array.getElem?_push_lt (by rw [hy.size]; omega), ← Array.getElem?_eq_getElem,
        viewAt_ext hv (by omega)]
      exact hy.terms i i1 (by omega)
    · rw [show i = v1.lastIdx + 1 by omega, viewAt_ext_last hv leLast, hl, Nat.add_sub_cancel,
        Array.getElem?_push]
      simp only [hy.size, ite_true, Option.map_some, eTerm, Option.some.injEq]
      have := hy.viewsBounded
      omega
  have vsize : P.views.size <= P.currentView := by
    rw [hv, hcv, Array.size_append, Array.size_replicate]
    have := hy.viewsBounded
    omega
  have hlog : (abs names P).log = (abs names v1).log ++ [absEntry names e] :=
    abs_log_push e hy.size hl hL
  have len1 : (abs names v1).log.length = v1.lastIdx := ReplUpdateCommit.abs_log_length hy.size
  refine ⟨
    ⟨
      size,
      by rw [hc, hL]; have := hy.commitLe; omega,
      ?_,
      terms,
      vsize,
      ?_,
      ?_,
      ?_,
      ?_,
      ?_
    ⟩,
    ⟨size, ?_, ?_, ?_, terms, ?_⟩
  ⟩
  · rw [hcom, hc, hL, signaturesIn_push e hy.size hl hy.commitLe, ← hy.committable, eSig]
  · intro _
    rw [hlog, hc, active_snoc _ _ (by rw [len1]; exact hy.commitLe), len1, ← he,
      cfgs_abs fun s => (G.sigPlain s).2, hcfg]
    by_cases z : v1.lastIdx = 0
    · have nil : (abs names v1).log = [] := List.eq_nil_of_length_eq_zero (len1.trans z)
      rw [nil, M.unconf z]
      exact ⟨cfgsOf v1 config, by simp [activeConfigurations, configurationHistory], Or.inl rfl⟩
    · obtain ⟨D, hD, sh⟩ := hy.configs (Nat.pos_of_ne_zero z)
      exact ⟨D ++ cfgsOf v1 config, by rw [hD, List.map_append], shifted_append sh _⟩
  · rw [hid]; exact hy.selfNamed
  · rw [hps]; exact named
  · rw [hcfg]
    intro x mem a ma
    rcases List.mem_append.mp mem with mem | mem
    · exact hy.membersNamed x mem a ma
    · cases hcf : config with
      | none => simp [cfgsOf, hcf] at mem
      | some nodes =>
          simp only [cfgsOf, hcf, Option.map_some, Option.toList_some,
            List.mem_singleton] at mem
          subst mem
          exact named_of_known
            (G.known a.1
              (List.mem_append_left _
                (by
                  simp only [hcf, Option.getD_some, List.mem_map]
                  exact ⟨a, ma, rfl⟩)))
  · rw [hcfg]
    intro x mem
    rcases List.mem_append.mp mem with mem | mem
    · exact hy.distinct x mem
    · cases hcf : config with
      | none => simp [cfgsOf, hcf] at mem
      | some nodes =>
          simp only [cfgsOf, hcf, Option.map_some, Option.toList_some,
            List.mem_singleton] at mem
          subst mem
          exact (G.cfg nodes hcf).1
  · rw [hv, Array.toList_append, Array.toList_replicate, List.pairwise_append]
    refine ⟨vh.sorted, List.pairwise_replicate.mpr (Or.inr (Nat.le_refl _)), fun a ma b mb => ?_⟩
    rw [(List.eq_of_mem_replicate mb)]
    exact leLast a ma
  · intro x mem
    rw [hv, Array.toList_append, Array.toList_replicate, List.mem_append] at mem
    rcases mem with mem | mem
    · exact vh.positive x mem
    · rw [List.eq_of_mem_replicate mem]; omega
  · intro x mem
    rw [hL]
    rw [hv, Array.toList_append, Array.toList_replicate, List.mem_append] at mem
    rcases mem with mem | mem
    · have := leLast x mem; omega
    · rw [List.eq_of_mem_replicate mem]; omega
  · intro x mem
    rw [hl, Array.toList_push, List.mem_append, List.mem_singleton] at mem
    rcases mem with mem | rfl
    · exact vh.posTerms x mem
    · rw [eTerm]; exact cv

end

theorem Mid.entryOk (S : Start names node v0 cl0) {cl1 : NodeState} {v1 : State}
    (M : Mid names node v0 cl0 cl1 v1) {sig : Bool} {config : Option Nodes}
    {retired : List NodeId} (G : Guards names v1 sig config retired)
    : EntryOk cl1 (contentOf names v1 sig config retired) := by
  have hlog := M.cleanLog
  have hcomm : cl1.committedLog = (abs names v1).committedLog := by
    unfold NodeState.committedLog
    rw [hlog, M.cleanCommit S]
    rfl
  have rcn : cl1.retirementCompletedNodes = (abs names v1).retirementCompletedNodes := by
    unfold NodeState.retirementCompletedNodes
    rw [hcomm]
  refine ⟨fun h e => ?_, fun ne => ?_, fun nodes h => ?_⟩
  · cases sig with
    | false => simp [contentOf, absEntry, entryOf, EntryContent.isSignature] at h
    | true =>
        rw [hlog] at e
        have := congrArg List.length e
        rw [ReplUpdateCommit.abs_log_length M.hy.size] at this
        exact G.sigNonempty rfl this
  · cases sig with
    | true =>
        obtain ⟨a, mem⟩ := ne
        simp [contentOf, absEntry, entryOf, EntryContent.metadata] at mem
    | false =>
        simp only [contentOf, absEntry, entryOf, Bool.false_eq_true, ite_false,
          EntryContent.metadata] at ne ⊢
        rw [rcn, hlog]
        refine G.rc fun e => ?_
        obtain ⟨a, mem⟩ := ne
        rw [e] at mem
        simp [Names.set] at mem
  · cases sig with
    | true => simp [contentOf, absEntry, entryOf, EntryContent.metadata] at h
    | false =>
        cases config with
        | none => simp [contentOf, absEntry, entryOf, EntryContent.metadata] at h
        | some ns =>
            simp only [contentOf, absEntry, entryOf, Bool.false_eq_true, ite_false,
              EntryContent.metadata, Option.map_some, Option.some.injEq] at h
            subst h
            obtain ⟨-, ne, latest, back⟩ := G.cfg ns rfl
            refine ⟨?_, by rw [hlog]; exact latest, fun x mem => ?_⟩
            · obtain ⟨a, rest, rfl⟩ := List.exists_cons_of_ne_nil ne
              exact ⟨names.id a.1, by simp [Names.set]⟩
            · simp only [Names.set, CCF.Finset.mem_ofList, List.mem_map] at mem
              obtain ⟨_, ⟨a, ma, rfl⟩, rfl⟩ := mem
              rw [hlog]
              exact back a ma

theorem contentOf_cfg {v : State} {sig : Bool} {config : Option Nodes}
    {retired : List NodeId} (plain : sig = true -> config = none)
    : (contentOf names v sig config retired).metadata.configuration
      = config.map fun ns => names.set (ns.map Prod.fst) := by
  cases sig with
  | false => simp [contentOf, absEntry, entryOf, EntryContent.metadata]
  | true =>
      rw [plain rfl]
      simp [contentOf, absEntry, entryOf, EntryContent.metadata]

theorem removed_snoc (log : List Model.Node.Entry) (x : Model.Node.Entry)
    (h
      : forall ns,
          x.content.metadata.configuration = some ns
          -> forall n, n ∈ ns -> n ∉ removedNodes log)
    : forall n, n ∈ removedNodes log -> n ∈ removedNodes (log ++ [x]) := by
  intro n mem
  unfold removedNodes at mem ⊢
  dsimp only at mem ⊢
  rw [history_snoc]
  cases hc : x.content.metadata.configuration with
  | none => simpa [entryConfig, hc] using mem
  | some ns =>
      have notIn := h ns hc n
      simp only [entryConfig, hc, Option.map_some, Option.toList_some]
      obtain ⟨m1, -⟩ := CCF.Finset.mem_sdiff.mp mem
      refine CCF.Finset.mem_sdiff.mpr ⟨(members_append _ _).mpr (Or.inl m1), ?_⟩
      simp only [latestConfigurationMembers, List.getLast?_append, List.getLast?_singleton,
        Option.some_or, Option.map_some, Option.getD_some]
      exact fun m => notIn m mem

/-- The batch keeps the committed log, so the retirement-completed nodes. -/
theorem Mid.rcnEq (S : Start names node v0 cl0) {cl1 : NodeState} {v1 : State}
    (M : Mid names node v0 cl0 cl1 v1)
    : (abs names v1).retirementCompletedNodes
      = (abs names v0).retirementCompletedNodes := by
  have hy0 := (Mid.start S).hy
  have len0 := ReplUpdateCommit.abs_log_length (names := names) hy0.size
  have hc : (abs names v1).committedLog = (abs names v0).committedLog := by
    unfold NodeState.committedLog
    obtain ⟨t, ht⟩ := M.isPrefix
    rw [S.log] at ht
    show (abs names v1).log.take v1.commitIdx = (abs names v0).log.take v0.commitIdx
    rw [← ht, M.frame.commit, List.take_append_of_le_length (by rw [len0]; exact hy0.commitLe)]
  unfold NodeState.retirementCompletedNodes
  rw [hc]

/-- The nodes a hook confirms were removed before the batch. -/
theorem Mid.retiredRemoved (S : Start names node v0 cl0) {cl1 : NodeState} {v1 : State}
    (M : Mid names node v0 cl0 cl1 v1) {sig : Bool} {config : Option Nodes}
    {retired : List NodeId} (G : Guards names v1 sig config retired)
    : forall id, id ∈ retired -> names.id id ∈ removedNodes (abs names v0).log := by
  intro id mem
  have ne : retired ≠ [] := by rintro rfl; cases mem
  have h := G.rc ne (by simp only [Names.set, CCF.Finset.mem_ofList, List.mem_map]; exact ⟨id, mem, rfl⟩)
  rw [M.rcnEq S] at h
  have e : (v0.leadership != .leader
      || decide ((abs names v0).retirementCompletedNodes ⊆ removedNodes (abs names v0).log))
      = true := by
    inv_conj S.inv "retirement_completed_removed"
  simp only [S.leader, bne_self_eq_false, Bool.false_or, decide_eq_true_eq] at e
  exact e (CCF.Finset.mem_sdiff.mp h).1

/-- Appending the entry keeps the batch relation. -/
theorem Mid.push (S : Start names node v0 cl0) {cl1 : NodeState} {v1 : State}
    (M : Mid names node v0 cl0 cl1 v1) {sig : Bool} {config : Option Nodes}
    {retired : List NodeId} (G : Guards names v1 sig config retired) {w : State}
    (hw
      : Hooked v1 (if sig then [v1.lastIdx + 1] else []) (cfgsOf v1 config)
          (rcsOf v1 retired) w)
    (rcw : w.isRetiredCommitted = false)
    (added : Added v1 (newE v1 config) w.allOtherNodes)
    : Mid names node v0 cl0 (appended node cl1 (contentOf names v1 sig config retired))
        (pushed v1 w (entryOf v1 sig config retired)) := by
  obtain ⟨tk, r, ph, ri, rci, ps, rfl⟩ := hw
  have self := M.self S
  obtain ⟨f, hcl, PR⟩ := M.clean
  have namedK : forall k, k ∈ newE v1 config -> Named names k :=
    fun k m => named_of_known (M.named_of_newE S G m)
  have v1peerNamed : forall k p, v1.peer? k = some p -> Named names k := fun k p h =>
    M.hy.peersNamed (k, p) ((lookup_iff_mem PR.nodup).mp h)
  have named : forall p, p ∈ ps -> Named names p.1 := by
    intro ⟨k, q⟩ mem
    have h := (lookup_iff_mem added.1).mpr mem
    rw [added.2 k] at h
    split at h
    · exact namedK k ‹_›
    · exact v1peerNamed k q h
  obtain ⟨hy, vh⟩ := M.push_hyps S G ⟨tk, r, ph, ri, rci, ps, rfl⟩ named
  have hlog := abs_log_push (names := names) (u := pushed v1 { v1 with
      committable := v1.committable ++ (if sig then [v1.lastIdx + 1] else []),
      configurations := v1.configurations ++ cfgsOf v1 config, allOtherNodes := ps,
      rcEntries := v1.rcEntries ++ rcsOf v1 retired, ticking := tk, retired := r, retirementPhase := ph, retirementIdx := ri,
      retirementCommittableIdx := rci } (entryOf v1 sig config retired))
    (entryOf v1 sig config retired) M.hy.size rfl rfl
  have len1 := ReplUpdateCommit.abs_log_length (names := names) M.hy.size
  have commitLe : cl1.commitIndex <= cl1.log.length := by
    rw [M.cleanCommit S, M.cleanLog, len1]; exact M.hy.commitLe
  have keysIff : forall k, k ∈ ps.map Prod.fst
      <-> k ∈ newE v1 config \/ k ∈ v1.allOtherNodes.map Prod.fst := by
    intro k
    rw [← peer_isSome_iff (v := { v1 with allOtherNodes := ps }), ← peer_isSome_iff]
    show (ps.lookup k).isSome = true <-> _
    rw [added.2 k]
    by_cases m : k ∈ newE v1 config <;> simp [m]
  have cfg := contentOf_cfg (names := names) (v := v1) (retired := retired)
    fun s => (G.sigPlain s).2
  refine ⟨
    by frame_step M.frame,
    rcw,
    hy,
    vh,
    fun h => absurd h (Nat.succ_ne_zero _),
    ?_,
    ?_,
    ?_,
    ?_,
    ?_,
    ?_,
    ?_,
    ?_
  ⟩
  · intro x mem id hid
    change x ∈ (v1.ledger.push (entryOf v1 sig config retired)).toList at mem
    rw [Array.toList_push, List.mem_append, List.mem_singleton] at mem
    rcases mem with mem | rfl
    · exact M.ledgerNamed x mem id hid
    · exact named_of_known (G.known id hid)
  · subst hcl
    refine ⟨fun p => if p ∈ addedOf { cl0 with log := (abs names v1).log, sentIndex := f } node
      (contentOf names v1 sig config retired) then (abs names v1).log.length else f p, ?_,
      added.1, fun k p hp => ?_⟩
    · rw [hlog]
      have ht : cl0.currentTerm = v1.currentView := M.cleanTerm S
      unfold appended
      dsimp only
      rw [ht]
      rfl
    · change ps.lookup k = some p at hp
      rw [added.2 k] at hp
      split at hp
      · rename_i mem
        cases hp
        have inA := (M.addedOf_iff S G).mpr ⟨k, mem, rfl⟩
        refine ⟨by simp [inA, len1], Nat.le_succ _, ?_⟩
        obtain ⟨⟨nodes, hc, memK⟩, neK, noneK⟩ := (M.mem_newE S).mp mem
        have ne : names.id k ≠ node := fun e =>
          neK (named_inj (namedK k mem) M.hy.selfNamed (e.trans self.symm))
        refine S.um S.role (names.id k) ne fun inMem => ?_
        have h1 := members_prefix M.isPrefix inMem
        obtain ⟨-, -, -, back⟩ := G.cfg nodes hc
        obtain ⟨a, ma, rfl⟩ := List.mem_map.mp memK
        have lat : names.id a.1
            ∈ latestConfigurationMembers (configurationHistory (abs names v1).log) :=
          Classical.byContradiction fun nl => back a ma (CCF.Finset.mem_sdiff.mpr ⟨h1, nl⟩)
        have el : names.id a.1 ∈ eligiblePeers
            { cl0 with log := (abs names v1).log, sentIndex := f } node :=
          CCF.Finset.mem_erase.mpr ⟨ne, CCF.Finset.mem_union.mpr (Or.inl (latest_active lat))⟩
        obtain ⟨k', memk', e⟩ := (M.eligible _).mp el
        obtain ⟨q, memQ⟩ := mem_keys.mp memk'
        have := named_inj (M.hy.peersNamed _ memQ) (namedK _ mem) e
        subst this
        have := peer_isSome_iff.mpr memk'
        rw [noneK] at this
        cases this
      · rename_i notMem
        obtain ⟨h1, h2, h3⟩ := PR.rel k p hp
        have notIn : names.id k ∉ addedOf { cl0 with log := (abs names v1).log, sentIndex := f }
            node (contentOf names v1 sig config retired) := by
          intro inA
          obtain ⟨k', m', e⟩ := (M.addedOf_iff S G).mp inA
          have := named_inj (namedK k' m') (v1peerNamed k p hp) e
          subst this
          exact notMem m'
        simp only [notIn, ↓reduceIte]
        exact ⟨h1, Nat.le_succ_of_le h2, h3⟩
  · intro n
    rw [Ae.eligiblePeers_congr (a := appended node cl1 (contentOf names v1 sig config retired))
      (b := { cl1 with
      log := cl1.log ++ [{ term := cl1.currentTerm, content := contentOf names v1 sig config retired }] })
      rfl rfl, eligible_snoc _ commitLe node n, M.eligible n, cfg]
    constructor
    · rintro (⟨k, mk, rfl⟩ | ⟨ne, nodes, hc, mn⟩)
      · exact ⟨k, (keysIff k).mpr (Or.inr mk), rfl⟩
      · obtain ⟨ns, rfl, rfl⟩ := Option.map_eq_some_iff.mp hc
        simp only [Names.set, CCF.Finset.mem_ofList, List.mem_map] at mn
        obtain ⟨_, ⟨a, ma, rfl⟩, rfl⟩ := mn
        refine ⟨a.1, (keysIff _).mpr ?_, rfl⟩
        cases hp : v1.peer? a.1 with
        | some q => exact Or.inr (peer_isSome_iff.mp (by rw [hp]; rfl))
        | none =>
            refine Or.inl ((M.mem_newE S).mpr ⟨⟨ns, rfl, List.mem_map.mpr ⟨a, ma, rfl⟩⟩,
              fun e => ne ?_, hp⟩)
            rw [e, self]
    · rintro ⟨k, mk, rfl⟩
      rcases (keysIff k).mp mk with m | m
      · obtain ⟨⟨ns, hc, memK⟩, neK, -⟩ := (M.mem_newE S).mp m
        refine Or.inr ⟨fun e => neK (named_inj (namedK k m) M.hy.selfNamed (e.trans self.symm)),
          _, by rw [hc]; rfl, ?_⟩
        simp only [Names.set, CCF.Finset.mem_ofList, List.mem_map]
        exact ⟨k, List.mem_map.mp memK, rfl⟩
      · exact Or.inl ⟨k, m, rfl⟩
  · rw [hlog]
    exact M.isPrefix.trans (List.prefix_append _ _)
  · intro x mem id hid
    rcases List.mem_append.mp mem with mem | mem
    · exact M.rcRemoved x mem id hid
    · cases hr : retired.isEmpty with
      | true => simp [rcsOf, hr] at mem
      | false =>
          simp only [rcsOf, hr, Bool.false_eq_true, ite_false, List.mem_singleton] at mem
          subst mem
          exact M.retiredRemoved S G id hid
  · intro j x cj hx n mem
    rw [hlog] at hx
    rcases Nat.lt_or_ge j (abs names v1).log.length with lt | ge
    · rw [List.getElem?_append_left lt] at hx
      exact M.confRemoved j x cj hx n mem
    · rw [List.getElem?_append_right ge] at hx
      have z : j - (abs names v1).log.length = 0 := by
        have := (List.getElem?_eq_some_iff.mp hx).1
        simp only [List.length_singleton] at this
        omega
      simp only [z, List.getElem?_singleton, ↓reduceIte, Option.some.injEq] at hx
      subst hx
      cases sig with
      | true =>
          simp [absEntry, entryOf, EntryContent.metadata, CCF.Finset.notMem_empty] at mem
      | false =>
          simp only [absEntry, entryOf, Bool.false_eq_true, ite_false, EntryContent.metadata,
            Names.set, CCF.Finset.mem_ofList, List.mem_map] at mem
          obtain ⟨id, mid, rfl⟩ := mem
          exact M.retiredRemoved S G id mid
  · intro n mem
    rw [hlog]
    refine removed_snoc _ _ (fun ns hns m mn => ?_) n (M.removedMono n mem)
    change (contentOf names v1 sig config retired).metadata.configuration = some ns at hns
    rw [cfg] at hns
    obtain ⟨nodes, hc, rfl⟩ := Option.map_eq_some_iff.mp hns
    simp only [Names.set, CCF.Finset.mem_ofList, List.mem_map] at mn
    obtain ⟨_, ⟨a, ma, rfl⟩, rfl⟩ := mn
    exact (G.cfg nodes hc).2.2.2 a ma
  · obtain ⟨new, hn, hnew⟩ := M.cfgNew
    refine ⟨new ++ cfgsOf v1 config, ?_, fun c mc a ma => ?_⟩
    · show v1.configurations ++ cfgsOf v1 config = _
      rw [hn, List.append_assoc]
    · rcases List.mem_append.mp mc with mc | mc
      · exact hnew c mc a ma
      · rcases config with _ | nodes
        · simp [cfgsOf] at mc
        · simp only [cfgsOf, Option.map_some, Option.toList_some, List.mem_singleton] at mc
          subst mc
          exact fun r => (G.cfg nodes rfl).2.2.2 a ma (M.removedMono _ r)

/-- Appending the entry extends the ghost by one clean entry and the added peers' heartbeats. -/
theorem push_ghost {env : Env} {node : NodeID} {v0 : State} {cl0 : NodeState}
    (S : Start env.names node v0 cl0) {es : List AppendEntryInput} {v1 : State}
    {o1 : Outbox} (g : Ghost env node v0 cl0 es v1 o1) {sig : Bool}
    {config : Option Nodes} {retired : List NodeId}
    (G : Guards env.names v1 sig config retired) {w : State}
    (hw
      : Hooked v1 (if sig then [v1.lastIdx + 1] else []) (cfgsOf v1 config)
          (rcsOf v1 retired) w)
    (rcw : w.isRetiredCommitted = false)
    (added : Added v1 (newE v1 config) w.allOtherNodes)
    : Ghost env node v0 cl0
        (es
          ++ [({ content := contentOf env.names v1 sig config retired, flushes := [] }
              : AppendEntryInput)])
        (pushed v1 w (entryOf v1 sig config retired))
        (o1 ++ (newE v1 config).map (hb env v1)) := by
  obtain ⟨cl1, em, M, mi⟩ := g
  refine ⟨_, ?_, M.push S G hw rcw added, fun x mem => ?_⟩
  · rw [List.foldlM_append]
    refine emits_bind em ?_
    simp only [List.foldlM_cons, List.foldlM_nil, entryStep]
    refine emits_congr (emits_bind (emits_bind (emits_appendEntry (M.entryOk S G))
      (emits_pure _)) (emits_pure _)) rfl ?_
    simp only [List.append_nil, M.addedOf_sort S G, List.map_map]
    exact List.map_congr_left fun k _ => M.hb_eq S k
  · rcases List.mem_append.mp mem with mem | mem
    · exact mi x mem
    · obtain ⟨k, mk, rfl⟩ := List.mem_map.mp mem
      exact M.msgInv_hb S (named_of_known (M.named_of_newE S G mk)) ((M.mem_newE S).mp mk).2.1

end Consensus.TraceValidation.Proofs.Repl
