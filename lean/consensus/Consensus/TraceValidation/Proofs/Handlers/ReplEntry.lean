module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import Consensus.TraceValidation.Proofs.Handlers.ReplAppend

@[expose] public section

namespace Consensus.TraceValidation.Proofs.Repl

open Consensus.Model.Node
open Consensus.TraceValidation (Names abs absEntry msgInv)
open Consensus.TraceValidation.Exec
open Consensus.TraceValidation.Proofs.Life

variable {env : Env} {node : NodeID} {v0 : State} {cl0 : NodeState}

theorem retiredHooks_pres {I : State -> Outbox -> Prop} (index : Nat)
    : forall (fuel : Nat) (acc : List NodeId), Pres env I (retiredHooks index fuel acc)
  | 0, _ => by
    unfold retiredHooks
    repeat' pres_step
  | fuel + 1, acc => by
    unfold retiredHooks
    repeat' (first | exact retiredHooks_pres index fuel _ | pres_step)

theorem hooked_refl (v : State) : Hooked v [] [] [] v :=
  ⟨
    v.ticking,
    v.retired,
    v.retirementPhase,
    v.retirementIdx,
    v.retirementCommittableIdx,
    v.allOtherNodes,
    by simp
  ⟩

theorem tri_setV_eq {Y : State} {O : Outbox} {f : State -> State}
    : Tri env (fun v o => v = Y /\ o = O) (setV f) fun _ v o => v = f Y /\ o = O :=
  Tri.setV fun v o p => by rw [p.1, p.2]; exact ⟨rfl, rfl⟩

theorem becomeOrdered_tri {Y : State} {O : Outbox} {idx : Nat}
    : Tri env (fun v o => v = Y /\ o = O) (becomeRetired idx .ordered)
        fun _ v o =>
          v
            = {
              Y with
                retirementIdx := some idx,
                retired := true,
                retirementPhase := some Phase.ordered
            }
          /\ o = O := by
  unfold becomeRetired
  dsimp only
  refine Tri.getV_bind fun x => ?_
  refine Tri.ite (fun _ => ?_) (fun _ => ?_)
  · exact Tri.bind (Tri.keeps Spec.curLoc) fun _ => Tri.fail_bind _
  · exact Tri.bind (Tri.conseq tri_setV_eq (fun _ _ p => p.1) fun _ _ _ q => q)
      fun _ => Tri.conseq tri_setV_eq (fun _ _ p => p) fun _ _ _ q => q

theorem becomeSigned_tri {Y : State} {O : Outbox} {idx : Nat}
    : Tri env (fun v o => v = Y /\ o = O) (becomeRetired idx .signed)
        fun _ v o =>
          v
            = {
              Y with
                retirementCommittableIdx := some idx,
                retired := true,
                retirementPhase := some Phase.signed
            }
          /\ o = O := by
  unfold becomeRetired
  dsimp only
  exact Tri.bind tri_setV_eq fun _ => Tri.conseq tri_setV_eq (fun _ _ p => p) fun _ _ _ q => q

/-- What `add_configuration` leaves: possibly a retirement, then a new configuration. -/
def AddPost (env : Env) (X : State) (O : Outbox) (idx : Nat) (nodes : Nodes) (v : State)
    (o : Outbox)
    : Prop :=
  exists Y : State,
    (Y = X
      \/ Y
          = {
            X with
              retirementIdx := some idx,
              retired := true,
              retirementPhase := some Phase.ordered
          })
    /\ ((X.configurations.getLast?.map (fun c : Config => c.nodes) = some nodes
          /\ v = Y
          /\ o = O)
        \/ CarInv env
            {
              Y with
                configurations :=
                  X.configurations ++ [({ idx, nodes, rid := idx } : Config)]
            }
            O
            (((X.configurations ++ [({ idx, nodes, rid := idx } : Config)]).flatMap
                (·.nodes.map Prod.fst)).mergeSort
                (· <= ·)
              |>.eraseDups)
            v o)

theorem addConfiguration_tri {X : State} {O : Outbox} {idx : Nat}
    (lead : X.leadership = .leader) (vh : ViewHyps X) (rc : X.isRetiredCommitted = false)
    (nd : (X.allOtherNodes.map Prod.fst).Nodup)
    : Tri env (fun v o => v = X /\ o = O) (addConfiguration (some idx) none)
        fun nodes => AddPost env X O idx nodes := by
  unfold addConfiguration
  refine Tri.bind (Tri.keeps (Spec.trace _)) fun _ => ?_
  refine Tri.getV_bind fun v => ?_
  dsimp only
  refine Tri.bind (Tri.keeps (Spec.emitNat _ _)) fun _ => ?_
  simp only [pure_bind]
  refine Tri.bind (Tri.keeps (Spec.emitNat _ _)) fun _ => ?_
  refine Tri.bind (Tri.keeps (Spec.use _)) fun _ => ?_
  refine Tri.bind (Tri.keeps (Spec.liftE _)) fun nodes => ?_
  refine tri_fact (φ := v = X) (fun _ _ p => p.2.symm.trans p.1.1) fun e => ?_
  subst e
  have tail : forall Y : State, (Y = v \/ Y = { v with retirementIdx := some idx, retired := true, retirementPhase := some Phase.ordered })
      -> Tri env (fun w o => w = Y /\ o = O) (do
        let w ← getV
        if (w.configurations.isEmpty
            || some nodes != w.configurations.getLast?.map (·.nodes)) = true then
          do
            setV fun w => { w with configurations := w.configurations ++ [{ idx, nodes, rid := idx }] }
            createAndRemoveNodeState
            pure nodes
        else pure nodes) fun r => AddPost env v O idx r := by
    intro Y hY
    have cfgY : Y.configurations = v.configurations := by rcases hY with rfl | rfl <;> rfl
    refine Tri.getV_bind fun w => ?_
    refine tri_fact (φ := w = Y) (fun _ _ p => p.2.symm.trans p.1.1) fun e => ?_
    subst e
    refine Tri.ite (fun _ => ?_) (fun hn => ?_)
    · let W : State := { w with configurations := v.configurations ++ [{ idx, nodes, rid := idx }] }
      have rcW : W.isRetiredCommitted = false := by
        rcases hY with rfl | rfl
        · exact rc
        · rfl
      have hW : W.leadership = .leader := by rcases hY with rfl | rfl <;> exact lead
      have ndW : (W.allOtherNodes.map Prod.fst).Nodup := by rcases hY with rfl | rfl <;> exact nd
      have vhW : ViewHyps W := by
        rcases hY with rfl | rfl <;>
          exact ⟨vh.size, vh.sorted, vh.positive, vh.leLast, vh.terms, vh.posTerms⟩
      refine Tri.bind (Q := fun _ u o => u = W /\ o = O)
        (Tri.setV fun u o p => by rw [p.1.1, p.1.2, cfgY]; exact ⟨rfl, rfl⟩) fun _ => ?_
      refine Tri.bind (car_spec hW vhW rcW ndW) fun _ => ?_
      exact Tri.pure' (Q := fun r => AddPost env v O idx r) _ |>.conseq
        (fun u o p => ⟨w, hY, Or.inr p⟩) fun _ _ _ q => q
    · refine Tri.conseq (Tri.pure' (Q := fun r => AddPost env v O idx r) _)
        (fun u o p => ⟨w, hY, Or.inl ⟨?_, p.1.1, p.1.2⟩⟩) fun _ _ _ q => q
      rw [← cfgY]
      simp only [Bool.or_eq_true, bne_iff_ne, ne_eq, not_or, Decidable.not_not] at hn
      exact hn.2.symm
  split
  · rename_i last _
    refine Tri.ite (fun _ => ?_) (fun _ => ?_)
    · exact Tri.bind (Tri.conseq becomeOrdered_tri (fun _ _ p => p.1) fun _ _ _ q => q)
        fun _ => tail _ (Or.inr rfl)
    · exact Tri.conseq (tail _ (Or.inl rfl)) (fun _ _ p => p.1) fun _ _ _ q => q
  · exact Tri.conseq (tail _ (Or.inl rfl)) (fun _ _ p => p.1) fun _ _ _ q => q

theorem names_set_congr {names : Names} {l1 l2 : List NodeId}
    (h : forall x, x ∈ l1 <-> x ∈ l2)
    : names.set l1 = names.set l2 := by
  apply CCF.Finset.ext
  intro n
  simp only [Names.set, CCF.Finset.mem_ofList, List.mem_map, h]

theorem shifted_last {c : Nat} {D E : List Config} (sh : ReplUpdateCommit.Shifted c D E)
    : D.getLast?.map (fun x : Config => x.nodes)
      = E.getLast?.map (fun x : Config => x.nodes) := by
  rcases sh with rfl | ⟨x, y, rest, rfl, rfl, n, -⟩
  · rfl
  · cases rest with
    | nil => simp [n]
    | cons a r => simp [List.getLast?_cons_cons]

theorem active_last {log : List Consensus.Model.Node.Entry} {c : Nat} {x : Configuration}
    (h : (activeConfigurations log c).getLast? = some x)
    : (configurationHistory log).getLast? = some x := by
  unfold activeConfigurations at h
  dsimp only at h
  rw [List.getLast?_drop] at h
  split at h
  · cases h
  · exact h

/-- The node set of the last declared configuration is the clean latest configuration. -/
theorem Mid.latest_of_last {names : Names} {cl : NodeState} {v : State}
    (M : Mid names node v0 cl0 cl v) {nodes : Nodes}
    (hl : v.configurations.getLast?.map (fun c : Config => c.nodes) = some nodes)
    : names.set (nodes.map Prod.fst)
      = latestConfigurationMembers (configurationHistory (abs names v).log) := by
  have pos : 0 < v.lastIdx := by
    rcases Nat.eq_zero_or_pos v.lastIdx with h | h
    · rw [M.unconf h] at hl
      cases hl
    · exact h
  obtain ⟨D, hD, sh⟩ := M.hy.configs pos
  rw [← shifted_last sh, Option.map_eq_some_iff] at hl
  obtain ⟨d, hd, rfl⟩ := hl
  have h1 : (activeConfigurations (abs names v).log v.commitIdx).getLast?
      = some (ReplUpdateCommit.absConfig names d) := by
    rw [hD, List.getLast?_map, hd]
    rfl
  simp only [latestConfigurationMembers, active_last h1, Option.map_some, Option.getD_some,
    ReplUpdateCommit.absConfig]

theorem Mid.newE_none {names : Names} (S : Start names node v0 cl0) {cl1 : NodeState}
    {v1 : State} (M : Mid names node v0 cl0 cl1 v1)
    : newE v1 none = [] :=
  List.eq_nil_iff_forall_not_mem.mpr
    fun _ m => by
      obtain ⟨⟨_, h, _⟩, _⟩ := (M.mem_newE S).mp m
      cases h

theorem added_nil {v : State} (nd : (v.allOtherNodes.map Prod.fst).Nodup)
    : Added v [] v.allOtherNodes :=
  ⟨nd, fun k => by simp only [List.not_mem_nil, ↓reduceIte]; rfl⟩

theorem Hooked.signed {v1 w : State} {K : List Nat} {cfgs : List Config}
    {R : List (Nat × List NodeId)} (h : Hooked v1 K cfgs R w) (idx : Nat)
    : Hooked v1 K cfgs R
        {
          w with
            retirementCommittableIdx := some idx,
            retired := true,
            retirementPhase := some Phase.signed
        } := by
  obtain ⟨tk, r, ph, ri, rci, ps, rfl⟩ := h
  exact ⟨tk, true, some Phase.signed, ri, some idx, ps, rfl⟩

theorem Hooked.commit {v1 w : State} {cfgs : List Config} {R : List (Nat × List NodeId)}
    (h : Hooked v1 [] cfgs R w) (k : Nat)
    : Hooked v1 [k] cfgs R { w with committable := w.committable ++ [k] } := by
  obtain ⟨tk, r, ph, ri, rci, ps, rfl⟩ := h
  exact ⟨tk, r, ph, ri, rci, ps, by simp⟩

theorem Hooked.tick {v1 w : State} {K : List Nat} {cfgs : List Config}
    {R : List (Nat × List NodeId)} (h : Hooked v1 K cfgs R w)
    : Hooked v1 K cfgs R { w with ticking := true } := by
  obtain ⟨tk, r, ph, ri, rci, ps, rfl⟩ := h
  exact ⟨true, r, ph, ri, rci, ps, rfl⟩

/-- The state and outbox after an entry's hooks, before it is appended. -/
def Stage (env : Env) (u : State) (o1 : Outbox) (K : List Nat) (cfgs : List Config)
    (R : List (Nat × List NodeId)) (new : List NodeId) (v : State) (o : Outbox)
    : Prop :=
  Hooked u K cfgs R v
  /\ v.isRetiredCommitted = false
  /\ Added u new v.allOtherNodes
  /\ o = o1 ++ new.map (hb env u)

theorem tri_getV_pin {β : Type} {f : State -> M β} {X : State} {O : Outbox}
    {R : β -> State -> Outbox -> Prop} (h : Tri env (fun v o => v = X /\ o = O) (f X) R)
    : Tri env (fun v o => v = X /\ o = O) (getV >>= f) R :=
  Tri.getV_bind
    fun v =>
      tri_fact (φ := v = X) (fun _ _ p => p.2.symm.trans p.1.1)
        fun e => by
          subst e
          exact Tri.conseq h (fun _ _ p => p.1) fun _ _ _ q => q

theorem tri_names_bind {β : Type} {f : Names -> M β} {P : State -> Outbox -> Prop}
    {R : β -> State -> Outbox -> Prop} (h : Tri env P (f env.names) R)
    : Tri env P (Exec.names >>= f) R :=
  Tri.bind (Tri.ofSpec (Q := fun a w o => P w o /\ a = env.names) Spec.names
    fun _ _ _ _ _ p h => by obtain ⟨rfl, rfl, rfl⟩ := h; exact ⟨p, rfl⟩)
    fun a => tri_fact (φ := a = env.names) (fun _ _ q => q.2) fun e => by
      subst e
      exact Tri.conseq h (fun _ _ q => q.1) fun _ _ _ q => q

/-- Some batch prefix relates the state and outbox. -/
def Batch (env : Env) (node : NodeID) (v0 : State) (cl0 : NodeState) (v : State)
    (o : Outbox)
    : Prop :=
  exists es, Ghost env node v0 cl0 es v o

theorem entry_tri (S : Start env.names node v0 cl0)
    : Tri env (Batch env node v0 cl0) replicateEntry
        fun _ => FlushGhost env node v0 cl0 := by
  refine tri_pin fun u o1 ⟨es, g⟩ => ?_
  obtain ⟨vhU, rcU, ndU⟩ := g.base
  obtain ⟨cl1, -, M, -⟩ := id g
  unfold replicateEntry
  refine Tri.bind (Tri.keeps (Spec.trace _)) fun _ => ?_
  refine Tri.getV_bind fun v => ?_
  refine tri_fact (φ := v = u) (fun _ _ p => p.2.symm.trans p.1.1) fun e => ?_
  subst v
  refine Tri.conseq (P' := fun w o => w = u /\ o = o1) ?_ (fun _ _ p => p.1)
    fun _ _ _ q => q
  extract_lets index config0 jpV
  refine Tri.bind (Tri.keeps (Spec.inBool _)) fun sig => ?_
  extract_lets jp0
  -- The flush after the views check.
  have hV : forall X O, FlushGhost env node v0 cl0
      { X with views := X.views ++ Array.replicate (X.currentView - X.views.size) index } O
      -> Tri env (fun w o => w = X /\ o = O) (jpV ()) fun _ => FlushGhost env node v0 cl0 := by
    intro X O fg
    refine Tri.bind (Q := fun _ w o => FlushGhost env node v0 cl0 w o)
      (Tri.setV fun w o p => by rw [p.1, p.2]; exact fg) fun _ => ?_
    refine Tri.bind (Tri.keeps Spec.lookFn) fun l => ?_
    refine Tri.ite (fun _ => ?_) (fun _ => ?_)
    · refine Tri.bind (Tri.keeps (Spec.trace _)) fun _ => ?_
      refine Tri.bind (Tri.keeps (Spec.note _)) fun _ => ?_
      refine Tri.bind pres_otherNodesSorted fun ids => ?_
      refine Tri.bind (Tri.forIn_list fun id _ _ => ?_) fun _ =>
        Tri.pure' (Q := fun _ => FlushGhost env node v0 cl0) _ |>.conseq (fun _ _ p => p)
          fun _ _ _ q => q
      refine Tri.getV_bind fun x => ?_
      split
      · rename_i p hp
        refine Tri.bind (Tri.conseq (flushSend_tri S) (fun w o q => ⟨q.1, p, by rw [q.2]; exact hp,
          rfl, by obtain ⟨_, _, _, gq⟩ := q.1; exact gq.bound (by rw [q.2]; exact hp)⟩)
          fun _ _ _ q => q) fun _ => Tri.pure' (Q := fun _ => FlushGhost env node v0 cl0) _
      · exact Tri.pure' (Q := fun _ => FlushGhost env node v0 cl0) _ |>.conseq
          (fun _ _ p => p.1) fun _ _ _ q => q
    · exact Tri.pure' (Q := fun _ => FlushGhost env node v0 cl0) _ |>.conseq (fun _ _ p => p)
        fun _ _ _ q => q
  refine Tri.ite (fun _ => Tri.bind (Tri.keeps Spec.curLoc) fun _ => Tri.fail_bind _)
    (fun hs0 => ?_)
  refine Tri.bind (Tri.keeps Spec.Keeps.get) fun ctx => ?_
  refine Tri.bind (retiredHooks_pres index _ _) fun retired => ?_
  extract_lets jp2 jp1 jpR
  have h2 : (retired ≠ [] -> env.names.set retired
        ⊆ (abs env.names u).retirementCompletedNodes \ retiredCommittedNodes (abs env.names u).log)
      -> forall config : Option Nodes, (forall nodes, config = some nodes
        -> (nodes.map Prod.fst).Nodup /\ nodes ≠ []
          /\ env.names.set (nodes.map Prod.fst)
            ≠ latestConfigurationMembers (configurationHistory (abs env.names u).log)
          /\ forall a, a ∈ nodes -> env.names.id a.1 ∉ removedNodes (abs env.names u).log)
      -> Tri env (Stage env u o1 [] (cfgsOf u config) (rcsOf u retired) (newE u config)) (jp2 () config)
        fun _ => FlushGhost env node v0 cl0 := by
    intro hrc config hcfg
    refine tri_names_bind ?_
    extract_lets ids jpPush jp6 jpS jp4
    refine Tri.ite (fun hk => ?_) (fun _ => Tri.bind (Tri.keeps Spec.curLoc) fun _ => Tri.fail_bind _)
    refine Tri.ite (fun _ => Tri.bind (Tri.keeps Spec.curLoc) fun _ => Tri.fail_bind _) (fun hp => ?_)
    have G : Guards env.names u sig config retired := {
      sigNonempty := fun hs h0 => hs0 (by simp [hs, h0])
      sigPlain := fun hs => by subst hs; simpa using hp
      rc := hrc
      known := fun id m => by
        simp only [ids, Bool.or_eq_true, Bool.and_eq_true, List.isEmpty_iff, List.all_eq_true] at hk
        rcases hk with he | ⟨ha, -⟩
        · rw [he] at m
          cases m
        · exact ha id m
      sorted := fun ne => by
        simp only [ids, Bool.or_eq_true, Bool.and_eq_true, List.isEmpty_iff] at hk
        rcases hk with he | ⟨-, hs⟩
        · exact absurd he ne
        · exact hs
      cfg := hcfg }
    have hP : Tri env (Stage env u o1 (if sig then [u.lastIdx + 1] else []) (cfgsOf u config)
        (rcsOf u retired) (newE u config)) (jpPush ()) fun _ => FlushGhost env node v0 cl0 := by
      refine tri_pin fun w O ⟨hw, rcw, added, eo⟩ => ?_
      have pg := push_ghost S g G hw rcw added
      rw [← eo] at pg
      obtain ⟨tk, r, ph, ri, rci, ps, rfl⟩ := hw
      refine tri_getV_pin ?_
      extract_lets entry
      refine Tri.bind tri_setV_eq fun _ => ?_
      refine Tri.bind (Tri.keeps (Spec.note _)) fun _ => ?_
      refine Tri.getV_bind fun y => ?_
      refine Tri.ite (fun _ => Tri.bind (Tri.keeps Spec.curLoc) fun _ => Tri.fail_bind _) fun _ => ?_
      exact Tri.conseq (hV _ _ ⟨_, _, _, pg⟩) (fun _ _ p => p.1) fun _ _ _ q => q
    refine Tri.ite (fun hs => ?_) (fun hs => ?_)
    · obtain ⟨rfl, rfl⟩ := G.sigPlain hs
      subst hs
      rw [M.newE_none S] at hP ⊢
      have h6 : Tri env (Stage env u o1 [] (cfgsOf u none) (rcsOf u []) []) (jp6 ())
          fun _ => FlushGhost env node v0 cl0 := by
        refine Tri.bind (Q := fun _ => Stage env u o1 [index] (cfgsOf u none) (rcsOf u []) [])
          (Tri.setV fun w o ⟨hw, rcw, added, eo⟩ => ⟨hw.commit _, rcw, added, eo⟩) fun _ => ?_
        refine Tri.bind (Q := fun _ => Stage env u o1 [index] (cfgsOf u none) (rcsOf u []) []) ?_ fun r => ?_
        · unfold startTickingIfNecessary
          refine Tri.setV fun w o ⟨hw, rcw, added, eo⟩ => ?_
          split
          · exact ⟨hw.tick, rcw, added, eo⟩
          · exact ⟨hw, rcw, added, eo⟩
        · cases r
          exact Tri.conseq hP (fun _ _ p => p) fun _ _ _ q => q
      refine Tri.getV_bind fun x => ?_
      refine Tri.ite (fun _ => ?_) (fun _ => Tri.conseq h6 (fun _ _ p => p.1) fun _ _ _ q => q)
      refine tri_pin fun X O ⟨st, _⟩ => ?_
      refine Tri.bind becomeSigned_tri fun r => ?_
      cases r
      refine Tri.conseq h6 (fun w o ⟨e1, e2⟩ => ?_) fun _ _ _ q => q
      subst e1 e2
      obtain ⟨hw, rcw, added, eo⟩ := st
      exact ⟨hw.signed _, rfl, added, eo⟩
    · simp only [Bool.not_eq_true] at hs
      subst hs
      exact Tri.conseq hP (fun _ _ p => p) fun _ _ _ q => q
  have h1 : (retired ≠ [] -> env.names.set retired
        ⊆ (abs env.names u).retirementCompletedNodes \ retiredCommittedNodes (abs env.names u).log)
      -> Tri env (fun w o => w = { u with rcEntries := u.rcEntries ++ rcsOf u retired } /\ o = o1)
        (jp1 ())
        fun _ => FlushGhost env node v0 cl0 := by
    intro hrc
    refine Tri.bind (Tri.keeps Spec.lookFn) fun l => ?_
    refine Tri.ite (fun _ => ?_) (fun _ => ?_)
    · refine tri_pin fun X O ⟨eX, eO⟩ => ?_
      subst eX eO
      refine Tri.bind (addConfiguration_tri (X := { u with rcEntries := u.rcEntries ++ rcsOf u retired }) (M.leader S)
        ⟨vhU.size, vhU.sorted, vhU.positive, vhU.leLast, vhU.terms, vhU.posTerms⟩ rcU ndU)
        fun nodes => ?_
      extract_lets ids1 cfg1 jpC jp3
      refine Tri.ite (fun hd => ?_) (fun _ => Tri.bind (Tri.keeps Spec.curLoc) fun _ => Tri.fail_bind _)
      refine tri_names_bind ?_
      extract_lets
      refine Tri.ite (fun _ => Tri.bind (Tri.keeps Spec.curLoc) fun _ => Tri.fail_bind _) (fun hne => ?_)
      refine Tri.ite (fun _ => Tri.bind (Tri.keeps Spec.curLoc) fun _ => Tri.fail_bind _) (fun hlat => ?_)
      refine Tri.ite (fun hb => ?_) (fun _ => Tri.bind (Tri.keeps Spec.curLoc) fun _ => Tri.fail_bind _)
      have hset : env.names.set ids1 = env.names.set (nodes.map Prod.fst) :=
        names_set_congr (sortDedup_spec (nodes.map Prod.fst)).2
      have hcfg : forall ns, some nodes = some ns -> (ns.map Prod.fst).Nodup /\ ns ≠ []
          /\ env.names.set (ns.map Prod.fst)
            ≠ latestConfigurationMembers (configurationHistory (abs env.names u).log)
          /\ forall a, a ∈ ns -> env.names.id a.1 ∉ removedNodes (abs env.names u).log := by
        rintro _ ⟨⟩
        refine ⟨ReplUpdateCommit.nodup_of_eraseDups_eq (beq_iff_eq.mp hd), ?_,
          fun h => hlat (decide_eq_true (hset.trans h)), fun a ma hr => ?_⟩
        · rintro rfl
          exact hne (by simp [ids1])
        · exact List.filter_eq_nil_iff.mp (List.isEmpty_iff.mp hb) a.1
            (((sortDedup_spec _).2 _).mpr (List.mem_map_of_mem ma)) (decide_eq_true hr)
      refine Tri.conseq (h2 hrc (some nodes) hcfg) (fun w o ⟨Y, hY, post⟩ => ?_) fun _ _ _ q => q
      rcases post with ⟨hl, -, -⟩ | ⟨ps, rfl, added, rfl⟩
      · exact (hlat (decide_eq_true (hset.trans (M.latest_of_last hl)))).elim
      · rcases hY with rfl | rfl
        · exact ⟨⟨u.ticking, u.retired, u.retirementPhase, u.retirementIdx,
            u.retirementCommittableIdx, ps, by simp [cfgsOf, index]⟩, rcU, added, rfl⟩
        · exact ⟨⟨u.ticking, true, some Phase.ordered, some index,
            u.retirementCommittableIdx, ps, by simp [cfgsOf, index]⟩, rfl, added, rfl⟩
    · exact Tri.conseq (h2 hrc none fun _ h => by cases h)
        (fun w o ⟨eW, eO⟩ => ⟨⟨u.ticking, u.retired, u.retirementPhase, u.retirementIdx,
          u.retirementCommittableIdx, u.allOtherNodes, by rw [eW]; simp [cfgsOf]⟩,
          by rw [eW]; exact rcU, by rw [M.newE_none S, eW]; exact added_nil ndU,
          by rw [M.newE_none S, eO]; simp⟩) fun _ _ _ q => q
  refine Tri.ite (fun hne0 => ?_) (fun he => ?_)
  · refine tri_names_bind ?_
    extract_lets a
    refine Tri.ite (fun hrcd => ?_) (fun _ => Tri.bind (Tri.keeps Spec.curLoc) fun _ => Tri.fail_bind _)
    have ne : retired.isEmpty = false := by simpa using hne0
    refine Tri.bind (Q := fun _ w o => w = { u with rcEntries := u.rcEntries ++ rcsOf u retired }
        /\ o = o1)
      (Tri.setV fun w o p => ⟨by rw [p.1]; simp [rcsOf, ne, index], p.2⟩) fun r => ?_
    cases r
    exact h1 fun _ => of_decide_eq_true hrcd
  · have hr : retired = [] := by simpa using he
    exact Tri.conseq (h1 fun h => absurd hr h) (fun w o p => ⟨by rw [p.1, hr]; simp [rcsOf], p.2⟩)
      fun _ _ _ q => q

/-- Before the batch, or after some of its entries. -/
def Loop (env : Env) (node : NodeID) (v0 : State) (cl0 : NodeState) (v : State)
    (o : Outbox)
    : Prop :=
  (v = v0 /\ o = []) \/ FlushGhost env node v0 cl0 v o

theorem batch_start (S : Start env.names node v0 cl0) : Batch env node v0 cl0 v0 [] :=
  ⟨[], cl0, emits_pure _, Mid.start S, by simp⟩

theorem Loop.batch (S : Start env.names node v0 cl0) {v : State} {o : Outbox}
    (h : Loop env node v0 cl0 v o)
    : Batch env node v0 cl0 v o := by
  rcases h with ⟨rfl, rfl⟩ | ⟨es, c, fl, g⟩
  · exact batch_start S
  · exact ⟨_, g⟩

theorem entries_tri (S : Start env.names node v0 cl0)
    : forall n, Pres env (Loop env node v0 cl0) (replicateEntries n)
  | 0 => by
    unfold replicateEntries
    exact Tri.bind (Tri.keeps Spec.curLoc) fun _ => Tri.fail _
  | n + 1 => by
    unfold replicateEntries
    refine Tri.bind (Tri.keeps Spec.lookFn) fun _ => Tri.ite (fun _ => ?_) fun _ => Pres.pure _
    exact Tri.bind (Tri.conseq (entry_tri S) (fun _ _ p => p.batch S) fun _ _ _ q => Or.inr q)
      fun _ => entries_tri S n

end Consensus.TraceValidation.Proofs.Repl
