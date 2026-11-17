module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import Consensus.TraceValidation.Proofs.Handlers.AeExec

@[expose] public section

/-!
# The conflict scan of AppendEntries (not reviewed)

The scan walks the request's indexes from `prevLogIndex + 1`. Before the first conflict `K`
(`ConflictSpec`) it skips matching entries; at the conflict it rolls back to `K - 1`
(`hoare_rollback`) if the node is a new follower, else it stops silently (`silentOf`); from
there it queues every entry with its retirement record (`hoare_scan`). Executing the queue
and the finish then end with `Good` over the final ledger and the ACK (`hoare_apply`), from
`Good` at the cut (`good_cCut`) for the parameters `aePar`.
-/

namespace Consensus.TraceValidation.Proofs.Ae

open Consensus.Model.Node
open Consensus.TraceValidation.Exec

/-- The core after `rollback idx`. -/
def rbCore (c : Core) (idx : Nat) : Core :=
  {
    c with
      rcEntries := c.rcEntries.filter (·.1 <= idx)
      ledger := c.ledger.extract 0 idx
      lastIdx := idx
      views := c.views.filter (· <= idx)
      committable := c.committable.filter (· <= idx)
  }

theorem hoare_rollback {env : Env} (C : Core) (o0 : Outbox) (idx : Nat)
    (hci : C.commitIdx <= idx) (hnl : C.leadership ≠ .leader)
    : Hoare env (fun v o => core v = C /\ o = o0) (rollback idx)
        (fun _ v o => core v = rbCore C idx /\ o = o0) := by
  unfold rollback
  refine Hoare.getV_bind fun s => ?_
  refine Hoare.pin fun v0 o1 ⟨⟨hc, ho⟩, hv⟩ => ?_
  subst hv ho hc
  refine Hoare.ite (fun h => absurd h (by simp only [core] at hci; omega)) fun _ => ?_
  refine Hoare.bind (R := fun _ v o => core v = rbCore (core v0) idx /\ o = o1)
    (Hoare.setV _ fun v o ⟨hv, ho⟩ => ⟨?_, ho⟩) fun _ => ?_
  · subst hv
    simp only [core, rbCore]
    split <;> (try split) <;> simp_all
  · have hnl' : (rbCore (core v0) idx).leadership ≠ .leader := hnl
    exact (show Frame env _ by frame_tac) _ _ hnl'

/-- The retirement record the scan pushes for entry `i`. -/
def rc1 (i : Nat) (e : Exec.Entry) : List (Nat × List NodeId) :=
  if e.retired.isEmpty then [] else [(i, e.retired)]

/-- Entry `i` of the request, as the scan reads it. -/
def ent (payload : Array Exec.Entry) (P i : Nat) : Exec.Entry := payload[i - P - 1]?.get!

/-- The work list for entries `a ..= b`. -/
def items (payload : Array Exec.Entry) (P a b : Nat) : List (Nat × Exec.Entry × Bool) :=
  (List.range' a (b + 1 - a)).map fun i => (i, ent payload P i, true)

/-- The retirement records the scan pushes for entries `a ..= b`. -/
def rcOf (payload : Array Exec.Entry) (P a b : Nat) : List (Nat × List NodeId) :=
  (List.range' a (b + 1 - a)).flatMap fun i => rc1 i (ent payload P i)

def addRc (C : Core) (l : List (Nat × List NodeId)) : Core :=
  { C with rcEntries := C.rcEntries ++ l }

theorem range'_snoc (a b : Nat) (h : a <= b + 1)
    : List.range' a (b + 1 + 1 - a) = List.range' a (b + 1 - a) ++ [b + 1] := by
  rw [show b + 1 + 1 - a = (b + 1 - a) + 1 by omega, List.range'_concat]
  congr 2
  omega

theorem items_snoc (payload : Array Exec.Entry) (P a b : Nat) (h : a <= b + 1)
    : items payload P a (b + 1)
      = items payload P a b ++ [(b + 1, ent payload P (b + 1), true)] := by
  simp [items, range'_snoc a b h]

theorem rcOf_snoc (payload : Array Exec.Entry) (P a b : Nat) (h : a <= b + 1)
    : rcOf payload P a (b + 1)
      = rcOf payload P a b ++ rc1 (b + 1) (ent payload P (b + 1)) := by
  simp [rcOf, range'_snoc a b h]

theorem items_empty (payload : Array Exec.Entry) (P a b : Nat) (h : b < a)
    : items payload P a b = [] := by
  simp [items]; omega

theorem rcOf_empty (payload : Array Exec.Entry) (P a b : Nat) (h : b < a)
    : rcOf payload P a b = [] := by
  simp [rcOf]; omega

theorem hoare_push {env : Env} (C : Core) (o0 : Outbox) (i : Nat) (e : Exec.Entry)
    (toApply : Array (Nat × Exec.Entry × Bool)) (τ : Nat)
    : Hoare env (fun v o => core v = C /\ o = o0)
        (do
          if (!e.retired.isEmpty) = true then
            setV fun v => { v with rcEntries := v.rcEntries ++ [(i, e.retired)] }
          pure (ForInStep.yield (none, toApply.push (i, e, e.term == τ)))
          : M (ForInStep (Option Unit × Array (Nat × Exec.Entry × Bool))))
        (fun st v o =>
          st = .yield (none, toApply.push (i, e, e.term == τ))
          /\ core v = addRc C (rc1 i e)
          /\ o = o0) := by
  extract_lets jp
  refine Hoare.ite (fun h => Hoare.bind (Hoare.setV _ fun v o ⟨hv, ho⟩ => ⟨?_, ho⟩)
      fun _ => Hoare.pure _ fun _ _ h => ⟨rfl, h⟩)
    (fun h => Hoare.pure _ fun v o ⟨hv, ho⟩ => ⟨rfl, ?_, ho⟩)
  · subst hv
    simp only [Bool.not_eq_eq_eq_not, Bool.not_true] at h
    simp [core, addRc, rc1, h]
  · subst hv
    simp only [Bool.not_eq_eq_eq_not, Bool.not_true] at h
    simp [core, addRc, rc1, h]

/-- The last index the scan keeps: before the first conflict, else the whole log. -/
def cutOf (U : State) : Option Nat -> Nat
  | some k => k - 1
  | none => U.lastIdx

/-- The core the scan starts appending from. -/
def cCut (U : State) : Option Nat -> Core
  | some k => { rbCore (core U) (k - 1) with isNewFollower := false }
  | none => core U

/-- The scan finds a conflict but may not roll back. -/
def silentOf (U : State) (K : Option Nat) : Prop :=
  K.isSome = true /\ U.isNewFollower = false

/-- What the scan compares: the first conflict `K` with the request's term `τ`. -/
def ConflictSpec (U : State) (P n τ : Nat) : Option Nat -> Prop
  | some k =>
      P < k
      /\ k <= U.lastIdx
      /\ k <= P + n
      /\ U.viewAt k ≠ τ
      /\ forall j, P < j -> j < k -> U.viewAt j = τ
  | none => forall j, P < j -> j <= U.lastIdx -> j <= P + n -> U.viewAt j = τ

theorem cCut_lastIdx (U : State) (K : Option Nat) : (cCut U K).lastIdx = cutOf U K := by
  cases K <;> rfl

theorem hoare_scan {env : Env} (from_ : NodeId) (r : AppendEntriesRequest)
    (payload : Array Exec.Entry) (U : State) (K : Option Nat)
    (hsize : payload.size = r.entries.length)
    (hτ : forall j (h : j < payload.size), payload[j].term = aeTermOfIdx r)
    (hP : r.prevLogIndex <= U.lastIdx) (hci : U.commitIdx <= r.prevLogIndex)
    (hnl : U.leadership ≠ .leader)
    (hK : ConflictSpec U r.prevLogIndex r.entries.length (aeTermOfIdx r) K)
    : Hoare env (fun v o => v = U /\ o = [])
        (forIn [r.prevLogIndex + 1 : aeIdx r + 1] (none, #[]) (scanBody from_ r payload))
        (fun t v o =>
          o = []
          /\ (silentOf U K /\ t.fst = some () /\ v = U
              \/ Not (silentOf U K)
                  /\ t.fst = none
                  /\ t.snd.toList = items payload r.prevLogIndex (cutOf U K + 1) (aeIdx r)
                  /\ core v
                      = addRc (cCut U K)
                          (rcOf payload r.prevLogIndex (cutOf U K + 1) (aeIdx r)))) := by
  generalize hPd : r.prevLogIndex = P at *
  generalize hnd : r.entries.length = n at *
  have hA : aeIdx r = P + n := by rw [aeIdx, hPd, hnd]
  generalize hτd : aeTermOfIdx r = τ at *
  have hcut : P <= cutOf U K := by
    cases K with
    | none => exact hP
    | some k => simp only [cutOf]; have := hK.1; omega
  rw [Std.Legacy.Range.forIn_eq_forIn_range']
  simp only [Std.Legacy.Range.size, hA, show P + n + 1 - (P + 1) = n by omega,
    Nat.add_sub_cancel, Nat.div_one]
  refine Hoare.pre
    (Hoare.forIn_list _ _ _
      (fun pre b v o =>
        o = []
        /\ (P + pre.length <= cutOf U K /\ b = (none, #[]) /\ v = U
            \/ cutOf U K < P + pre.length
                /\ Not (silentOf U K)
                /\ b.fst = none
                /\ b.snd.toList = items payload P (cutOf U K + 1) (P + pre.length)
                /\ core v
                    = addRc (cCut U K) (rcOf payload P (cutOf U K + 1) (P + pre.length))))
      _ ?_ ?_)
    fun v o ⟨hv, ho⟩ => ⟨ho, Or.inl ⟨by simpa using hcut, rfl, hv⟩⟩
  · intro pre a rest b he
    have hlen : pre.length < n := by
      have := congrArg List.length he; simp at this; omega
    have ha : a = P + pre.length + 1 := by
      have h1 : (List.range' (P + 1) n)[pre.length]'(by simpa using hlen) = a := by
        simp only [he, List.getElem_append_right (Nat.le_refl _), Nat.sub_self,
          List.getElem_cons_zero]
      simp at h1; omega
    generalize hm : P + pre.length = m at ha
    subst ha
    have hL : P + (pre ++ [m + 1]).length = m + 1 := by simp; omega
    have hmn : m < P + n := by omega
    have hPm : P <= m := by omega
    have hE : payload[m + 1 - P - 1]? = some (ent payload P (m + 1)) := by
      have : m + 1 - P - 1 = pre.length := by omega
      simp [ent, this, hsize, hlen]
    have hT : (ent payload P (m + 1)).term = τ := by
      have : m + 1 - P - 1 = pre.length := by omega
      simp only [ent, this, getElem?_pos payload pre.length (by omega), Option.get!_some]
      exact hτ _ _
    refine Hoare.pin fun v0 o0 ⟨ho, h⟩ => ?_
    subst ho
    unfold scanBody
    extract_lets toApply entry? entry jp push
    have hE' : entry? = some (ent payload P (m + 1)) := by
      simp only [entry?, hPd]; exact hE
    have hentry : entry = ent payload P (m + 1) := by
      simp only [entry, hE', Option.get!_some]
    have hpush : forall C, Hoare env (fun v o => core v = C /\ o = []) (push ())
        (fun st v o => st = .yield (none, toApply.push (m + 1, ent payload P (m + 1), true))
          /\ core v = addRc C (rc1 (m + 1) (ent payload P (m + 1))) /\ o = []) := by
      intro C
      have hb : (entry.term == aeTermOfIdx r) = true := by rw [hentry, hT, hτd]; simp
      refine Hoare.post (hoare_push C [] (m + 1) entry toApply (aeTermOfIdx r)) ?_
      intro st v o ⟨h1, h2, h3⟩
      exact ⟨by rw [h1, hb, hentry], by rw [h2, hentry], h3⟩
    refine Hoare.ite (fun hn => absurd hn (by simp [hE'])) fun _ => ?_
    refine Hoare.getV_bind fun s => Hoare.pin fun v1 o1 ⟨⟨hv1, ho1⟩, hs⟩ => ?_
    subst ho1 s v1
    rcases h with ⟨hmc, rfl, hU⟩ | ⟨hmc, hns, hb1, hb2, hb3⟩
    · subst v0
      have hcl : cutOf U K <= U.lastIdx := by
        cases K with
        | none => exact Nat.le_refl _
        | some k => simp only [cutOf]; have := hK.2.1; omega
      refine Hoare.ite (fun hle => ?_) (fun hgt => ?_)
      · refine Hoare.ite (fun hc => ?_) (fun hc => ?_)
        · have hc' : U.viewAt (m + 1) ≠ τ := by
            rw [← hτd]; intro h; simp [h] at hc
          cases K with
          | none => exact absurd (hK (m + 1) (by omega) hle (by omega)) hc'
          | some k =>
              obtain ⟨hPk, hkl, hkn, hkne, hbef⟩ := hK
              simp only [cutOf] at hmc
              rcases Nat.lt_or_ge (m + 1) k with hlt | hge
              · exact absurd (hbef _ (by omega) hlt) hc'
              have hk : k = m + 1 := by omega
              subst hk
              refine Hoare.ite (fun hnf => ?_) (fun hnf => ?_)
              · refine Hoare.bind (Hoare.pre (hoare_rollback (core U) [] (m + 1 - 1)
                  (show U.commitIdx <= _ by omega) hnl) fun v o ⟨hv, ho⟩ => ⟨by rw [hv], ho⟩)
                  fun _ => ?_
                refine Hoare.bind
                  (R := fun _ v o => core v = cCut U (some (m + 1)) /\ o = [])
                  (Hoare.setV _ fun v o ⟨hv, ho⟩ => ⟨?_, ho⟩) fun _ => ?_
                · show _ = { rbCore (core U) (m + 1 - 1) with isNewFollower := false }
                  rw [← hv]; rfl
                refine Hoare.post (hpush _) fun st v o ⟨h1, h2, h3⟩ => ?_
                subst h1
                refine ⟨h3, Or.inr ⟨by simp only [cutOf]; omega, ?_, rfl, ?_, ?_⟩⟩
                · simp [silentOf, hnf]
                · simp only [hL, cutOf, Nat.add_sub_cancel, toApply, Array.toList_push]
                  rw [items_snoc _ _ _ _ (Nat.le_refl _), items_empty _ _ _ _ (by omega)]
                · simp only [hL, cutOf, Nat.add_sub_cancel, h2]
                  rw [rcOf_snoc _ _ _ _ (Nat.le_refl _), rcOf_empty _ _ _ _ (by omega)]; rfl
              · exact Hoare.pure _ fun v o ⟨hv, ho⟩ =>
                  ⟨ho, Or.inl ⟨⟨rfl, by simpa using hnf⟩, rfl, hv⟩⟩
        · refine Hoare.pure _ fun v o ⟨hv, ho⟩ => ⟨ho, Or.inl ⟨?_, rfl, hv⟩⟩
          have hc' : U.viewAt (m + 1) = τ := by
            simp only [bne_iff_ne, ne_eq, Decidable.not_not] at hc; rw [← hτd, hc]
          rw [hL]
          cases K with
          | none => exact hle
          | some k =>
              obtain ⟨hPk, hkl, hkn, hkne, hbef⟩ := hK
              simp only [cutOf] at hmc ⊢
              have : k ≠ m + 1 := fun h => hkne (h ▸ hc')
              omega
      · have hmc' : m = U.lastIdx := by omega
        cases K with
        | some k => have := hK.1; have := hK.2.1; simp only [cutOf] at hmc; omega
        | none =>
            refine Hoare.post
              (Hoare.pre (hpush (core U)) fun v o ⟨hv, ho⟩ => ⟨by rw [hv], ho⟩)
              fun st v o ⟨h1, h2, h3⟩ => ?_
            subst h1
            refine ⟨
              h3,
              Or.inr
                ⟨
                  by simp only [cutOf, hL]; omega,
                  fun h => by simp [silentOf] at h,
                  rfl,
                  ?_,
                  ?_
                ⟩
            ⟩
            · simp only [hL, cutOf, ← hmc', toApply, Array.toList_push]
              rw [items_snoc _ _ _ _ (Nat.le_refl _), items_empty _ _ _ _ (by omega)]
            · simp only [hL, cutOf, ← hmc', h2]
              rw [rcOf_snoc _ _ _ _ (Nat.le_refl _), rcOf_empty _ _ _ _ (by omega)]; rfl
    · have hvl : v0.lastIdx = cutOf U K := (congrArg Core.lastIdx hb3).trans (cCut_lastIdx U K)
      refine Hoare.ite (fun hle => absurd hle (by omega)) fun _ => ?_
      refine Hoare.post (Hoare.pre (hpush (core v0)) fun v o ⟨hv, ho⟩ => ⟨by rw [hv], ho⟩)
        fun st v o ⟨h1, h2, h3⟩ => ?_
      subst h1
      refine ⟨h3, Or.inr ⟨by rw [hL]; omega, hns, rfl, ?_, ?_⟩⟩
      · simp only [hL, toApply, Array.toList_push, hb2]
        rw [items_snoc _ _ _ _ (by omega)]
      · rw [hL, h2, hb3, rcOf_snoc _ _ _ _ (by omega)]
        simp [addRc]
  · intro b v o ⟨ho, h⟩
    simp only [List.length_range'] at h
    refine ⟨ho, ?_⟩
    rcases h with ⟨h1, rfl, rfl⟩ | ⟨h1, h2, h3, h4, h5⟩
    · cases K with
      | some k => have := hK.1; have := hK.2.2.1; simp only [cutOf] at h1; omega
      | none =>
          refine Or.inr ⟨fun h => by simp [silentOf] at h, rfl, ?_, ?_⟩
          · rw [items_empty _ _ _ _ (by omega)]
          · rw [rcOf_empty _ _ _ _ (by omega)]; simp [addRc, cCut]
    · exact Or.inr ⟨h2, h3, h4, h5⟩

theorem cutOf_le {U : State} {P n τ : Nat} {K : Option Nat} (hP : P <= U.lastIdx)
    (hK : ConflictSpec U P n τ K)
    : P <= cutOf U K /\ cutOf U K <= U.lastIdx := by
  cases K with
  | none => exact ⟨hP, Nat.le_refl _⟩
  | some k => have := hK.1; have := hK.2.1; simp only [cutOf]; omega

theorem good_addRc {p : Par} {C : Core} {l : List (Nat × List NodeId)} (g : Good p C)
    (h : forall x, x ∈ l -> p.c0 < x.1)
    : Good p (addRc C l) :=
  {
    g with
      rc :=
        fun x hx => by
          simp only [addRc, List.mem_append] at hx
          exact hx.elim (g.rc x) (h x)
  }

theorem rcOf_gt {payload : Array Exec.Entry} {P a b : Nat}
    : forall x, x ∈ rcOf payload P a b -> a <= x.1 := by
  intro x hx
  simp only [rcOf, List.mem_flatMap, List.mem_range'] at hx
  obtain ⟨i, ⟨j, _, rfl⟩, hx⟩ := hx
  simp only [rc1] at hx
  split at hx
  · simp at hx
  · simp only [List.mem_singleton] at hx; subst hx; simp

theorem hoare_apply {env : Env} (from_ : NodeId) (r : AppendEntriesRequest)
    (payload : Array Exec.Entry) (U : State) (K : Option Nat) (p : Par)
    (hsize : payload.size = r.entries.length)
    (hτ : forall j (h : j < payload.size), payload[j].term = aeTermOfIdx r)
    (hP : r.prevLogIndex <= U.lastIdx) (hci : U.commitIdx <= r.prevLogIndex)
    (hnl : U.leadership ≠ .leader)
    (hK : ConflictSpec U r.prevLogIndex r.entries.length (aeTermOfIdx r) K)
    (hsz : U.ledger.size = U.lastIdx)
    (hG : Good p (cCut U K))
    (hlx
      : p.lx
        = U.ledger.toList.take (cutOf U K)
          ++ payload.toList.drop (cutOf U K - r.prevLogIndex))
    (hc0 : p.c0 <= r.prevLogIndex)
    (hv1 : r.term <= p.view) (hv2 : aeTermOfIdx r <= p.view)
    (hlim : min r.primaryCommit (aeIdx r) = p.lim)
    : Hoare env (fun v o => v = U /\ o = []) (aeApply from_ r payload)
        (fun _ v o =>
          silentOf U K /\ v = U /\ o = []
          \/ Not (silentOf U K)
              /\ GN p p.lx.length (core v)
              /\ v.commitIdx = p.bd
              /\ o = ack env from_ r v) := by
  have ⟨hc1, hc2⟩ := cutOf_le hP hK
  unfold aeApply
  refine Hoare.bind (hoare_scan from_ r payload U K hsize hτ hP hci hnl hK) fun s => ?_
  refine Hoare.pin fun v o ⟨ho, h⟩ => ?_
  subst ho
  rcases h with ⟨hs, h1, hv⟩ | ⟨hs, h1, h2, h3⟩
  · rw [h1]
    exact Hoare.pure _ fun v' o' ⟨hv', ho'⟩ => Or.inl ⟨hs, hv'.trans hv, ho'⟩
  · rw [h1]
    simp only
    rw [← Array.forIn_toList, h2]
    have hW : Work p (cutOf U K) (items payload r.prevLogIndex (cutOf U K + 1) (aeIdx r)) := by
      intro k hk
      simp only [items, List.length_map, List.length_range'] at hk
      simp only [items, List.getElem_map, List.getElem_range']
      refine ⟨by omega, ?_, by simp, ?_⟩
      · rw [hlx, List.getElem?_append_right (by simp; omega)]
        simp only [List.length_take, Array.length_toList, List.getElem?_drop, ent]
        have : cutOf U K - r.prevLogIndex + (cutOf U K + k - min (cutOf U K) U.ledger.size)
            = cutOf U K + 1 + k - r.prevLogIndex - 1 := by omega
        rw [this, Array.getElem?_toList]
        have hlt : cutOf U K + 1 + k - r.prevLogIndex - 1 < payload.size := by
          simp only [aeIdx] at hk; omega
        simp [hlt]
      · simp only [ent]
        have hlt : cutOf U K + 1 + k - r.prevLogIndex - 1 < payload.size := by
          simp only [aeIdx] at hk; omega
        simp only [Nat.one_mul, getElem?_pos payload (cutOf U K + 1 + k - r.prevLogIndex - 1) hlt,
          Option.get!_some, hτ _ hlt]
        exact hv2
    refine Hoare.bind (Hoare.pre (gt_execLoop from_ r _ _ hW hv1 hlim []) fun v' o' ⟨hv', ho'⟩ =>
      ⟨⟨by rw [hv', h3]; exact good_addRc hG fun x hx => by have := rcOf_gt x hx; omega,
        by rw [hv', h3]; exact cCut_lastIdx U K⟩, ho'⟩) fun t => ?_
    refine Hoare.pin fun v1 o1 ⟨⟨ht, hg⟩, ho1⟩ => ?_
    subst ho1
    rw [ht]
    simp only
    have hlen : cutOf U K + (items payload r.prevLogIndex (cutOf U K + 1) (aeIdx r)).length
        = p.lx.length := by
      simp only [items, List.length_map, List.length_range', hlx, List.length_append,
        List.length_take, Array.length_toList, List.length_drop, hsize, aeIdx]
      omega
    rw [hlen] at hg
    exact Hoare.post (Hoare.pre (hoare_finish from_ r hv1 hv2 hlim) fun v' o' ⟨hv', ho'⟩ =>
      ⟨hv' ▸ hg, ho'⟩) fun _ v' o' h => Or.inr ⟨hs, h⟩

theorem sigsIn_trunc (ledger : Array Exec.Entry) {lo m hi : Nat} (h1 : lo <= m)
    (h2 : m <= hi)
    : (sigsIn ledger lo hi).filter (fun x => decide (x <= m))
      = sigsIn (ledger.extract 0 m) lo m := by
  unfold sigsIn
  rw [show hi - lo = (m - lo) + (hi - m) by omega, ← List.range'_append_1]
  simp only [List.filter_append, List.filter_filter]
  rw [(List.filter_eq_nil_iff (l := List.range' (lo + 1 + (m - lo)) (hi - m))).mpr ?_,
    List.append_nil]
  · apply List.filter_congr
    intro x hx
    simp only [List.mem_range'_1] at hx
    have : x - 1 < m := by omega
    simp only [Array.getElem?_extract, show x <= m by omega, decide_true, Bool.true_and,
      Nat.zero_add]
    by_cases hs : x - 1 < ledger.size
    · have : x - 1 < min m ledger.size := Nat.lt_min.mpr ⟨this, hs⟩
      simp [hs, this]
    · have : ¬ x - 1 < min m ledger.size := fun h => hs (Nat.lt_min.mp h).2
      simp [hs, this]
  · intro x hx
    simp only [List.mem_range'_1] at hx
    simp; omega

/-- The hold's parameters for the execute phase. -/
def aePar (names : Names) (from_ : NodeId) (r : AppendEntriesRequest)
    (payload : Array Exec.Entry) (U : State) (K : Option Nat)
    : Par where
  names := names
  nid := U.nodeId
  view := U.currentView
  vf := U.votedFor
  nf := (cCut U K).isNewFollower
  lt := U.leadership
  ldr := from_
  rciT := U.retiredCommittedIdx
  c0 := U.commitIdx
  lim := min r.primaryCommit (aeIdx r)
  lx :=
    U.ledger.toList.take (cutOf U K) ++ payload.toList.drop (cutOf U K - r.prevLogIndex)

theorem good_cCut (names : Names) (from_ : NodeId) (r : AppendEntriesRequest)
    (payload : Array Exec.Entry) (U : State) (K : Option Nat)
    (hP : r.prevLogIndex <= U.lastIdx) (hci : U.commitIdx <= r.prevLogIndex)
    (hnl : U.leadership ≠ .leader)
    (hK : ConflictSpec U r.prevLogIndex r.entries.length (aeTermOfIdx r) K)
    (hsz : U.ledger.size = U.lastIdx)
    (hcomm : U.committable = sigsIn U.ledger U.commitIdx U.lastIdx)
    (hviews : U.views.size <= U.currentView)
    (hrc : forall x, x ∈ U.rcEntries -> U.commitIdx < x.1)
    (hld : U.leaderId = some from_)
    : Good (aePar names from_ r payload U K) (cCut U K) := by
  have ⟨hc1, hc2⟩ := cutOf_le hP hK
  have hlx : (U.ledger.toList.take (cutOf U K)).length = cutOf U K := by simp; omega
  cases K with
  | none =>
      simp only [cutOf] at hlx hc1 hc2
      exact {
        nodeId := rfl,
        view := rfl,
        vf := rfl,
        nf := rfl,
        size := hsz
        ledger := by
          simp only [cCut, core, aePar, cutOf]
          rw [List.take_append_of_le_length (by omega), List.take_take, Nat.min_self,
            List.take_of_length_le (by simp; omega)]
        last := by simp [aePar, cutOf, core, cCut]; omega
        committable := hcomm
        c0 := Nat.le_refl _
        bd := Nat.le_max_left _ _
        ci := by simp only [cCut, core]; omega
        views := hviews
        rc := hrc
        lt := hnl
        d := Or.inl ⟨rfl, rfl, hld⟩
      }
  | some k =>
      obtain ⟨hPk, hkl, -⟩ := hK
      simp only [cutOf] at hlx hc1 hc2
      exact {
        nodeId := rfl,
        view := rfl,
        vf := rfl,
        nf := rfl
        size := by simp [cCut, rbCore, core]; omega
        ledger := by
          simp only [cCut, core, aePar, cutOf, rbCore]
          rw [List.take_append_of_le_length (by omega), List.take_take, Nat.min_self]
          simp [Array.toList_extract]
        last := by simp [aePar, cutOf, core, cCut, rbCore]; omega
        committable := by
          simp only [cCut, core, rbCore]
          rw [hcomm]
          exact sigsIn_trunc _ (by omega) (by omega)
        c0 := Nat.le_refl _
        bd := Nat.le_max_left _ _
        ci := by simp only [cCut, core, rbCore]; omega
        views := Nat.le_trans Array.size_filter_le hviews
        rc :=
          fun x hx => by
            simp only [cCut, core, rbCore, List.mem_filter] at hx
            exact hrc x hx.1
        lt := hnl
        d := Or.inl ⟨rfl, rfl, hld⟩
      }

end Consensus.TraceValidation.Proofs.Ae
