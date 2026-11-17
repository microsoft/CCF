module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import Consensus.TraceValidation.Proofs.Handlers.AeClean
public import Consensus.TraceValidation.Proofs.Handlers.AeFrame

@[expose] public section

/-!
# The commit path during AppendEntries (not reviewed)

`GInv` says a handler keeps a predicate of the core and sends nothing. `Good` is the declared
core during the execute phase of an AppendEntries hold: the ledger is a prefix of the final
ledger `lx`, the committable list is its signatures above the commit index, and the commit
index stays between the starting one `c0` and the clean bound `Par.bd`. Retirement through
`storeCompact` only latches an index above `c0` and steps down. `commit` moves the commit
index and keeps `Good`; `commitIfPossible` keeps `Good` and, once the whole ledger is in,
reaches `Par.bd`.
-/

namespace Consensus.TraceValidation.Proofs.Ae

open Consensus.Model.Node
open Consensus.TraceValidation.Exec

/-- `x` keeps `G` of the core and sends nothing. -/
def GInv {α : Type} (env : Env) (G : Core -> Prop) (x : M α) : Prop :=
  forall o0 : Outbox,
    Hoare env (fun v o => G (core v) /\ o = o0) x (fun _ v o => G (core v) /\ o = o0)

namespace GInv
variable {env : Env} {G : Core -> Prop}

theorem of_frame {α : Type} {x : M α} (nl : forall c, G c -> c.leadership ≠ .leader)
    (h : Frame env x)
    : GInv env G x := by
  intro o0
  refine Hoare.pin fun v0 _ ⟨g, ho⟩ => ?_
  subst ho
  refine Hoare.post
    (Hoare.pre (h (core v0) _ (nl _ g)) fun v o ⟨hv, ho⟩ => ⟨by rw [hv], ho⟩) ?_
  intro _ v o ⟨hc, ho⟩
  exact ⟨by rw [hc]; exact g, ho⟩

theorem bind {α β : Type} {x : M α} {f : α -> M β} (hx : GInv env G x)
    (hf : forall a, GInv env G (f a))
    : GInv env G (x >>= f) :=
  fun o0 => Hoare.bind (hx o0) fun a => hf a o0

theorem getV_bind {β : Type} {k : State -> M β}
    (hk : forall s, G (core s) -> GInv env G (k s))
    : GInv env G (Exec.getV >>= k) := by
  intro o0
  refine Hoare.getV_bind fun s => ?_
  refine Hoare.pin fun v0 o1 ⟨⟨g, ho1⟩, hv⟩ => ?_
  subst hv ho1
  exact Hoare.pre (hk v0 g o1) fun v o ⟨hv, ho⟩ => ⟨by rw [hv]; exact g, ho⟩

theorem ite {α : Type} {b : Prop} [Decidable b] {x y : M α} (hx : b -> GInv env G x)
    (hy : Not b -> GInv env G y)
    : GInv env G (if b then x else y) := by
  by_cases h : b
  · simpa [h] using hx h
  · simpa [h] using hy h

theorem pure {α : Type} (a : α) : GInv env G (Pure.pure a : M α) :=
  fun _ => Hoare.pure a fun _ _ p => p

theorem fail {α : Type} (m : String) : GInv env G (Exec.fail m : M α) :=
  fun _ => Hoare.fail m

theorem fail_bind {α β : Type} (m : String) (f : α -> M β)
    : GInv env G (Exec.fail m >>= f) :=
  fun _ =>
    Hoare.bind (R := fun _ _ _ => False) (Hoare.fail m)
      fun _ =>
        Hoare.false_pre fun _ _ h => h

theorem keeps {α : Type} {x : M α} (h : Spec.Keeps env x) : GInv env G x :=
  fun _ => Hoare.keeps h fun _ _ _ p => p

theorem setV {f : State -> State} (hf : forall v, G (core v) -> G (core (f v)))
    : GInv env G (Exec.setV f) :=
  fun _ => Hoare.setV f fun v _ ⟨g, ho⟩ => ⟨hf v g, ho⟩

theorem forIn_list {α β : Type} (l : List α) (init : β) {f : α -> β -> M (ForInStep β)}
    (hf : forall a b, a ∈ l -> GInv env G (f a b))
    : GInv env G (forIn l init f) := by
  induction l generalizing init with
  | nil => exact pure init
  | cons a rest ih =>
      rw [List.forIn_cons]
      refine bind (hf a init (List.mem_cons_self ..)) fun r => ?_
      cases r with
      | done b => exact pure b
      | yield b => exact ih b (fun a b m => hf a b (List.mem_cons_of_mem _ m))

theorem option {α β : Type} {o : Option α} {x : M β} {f : α -> M β} (hx : GInv env G x)
    (hf : forall a, o = some a -> GInv env G (f a))
    : GInv env G
        (match o with
          | none => x
          | some a => f a) := by
  cases o
  · exact hx
  · exact hf _ rfl

end GInv

/-- The fixed parameters of the AppendEntries execute phase. -/
structure Par where
  names : Names
  nid : NodeId
  view : Nat
  vf : Option NodeId
  nf : Bool
  lt : Leadership
  ldr : NodeId
  rciT : Option Nat
  c0 : Nat
  lim : Nat
  /-- The ledger at the end of the hold. -/
  lx : List Exec.Entry

/-- Signature indexes of a ledger in `(lo, hi]`, as `signaturesIn`. -/
def sigsIn (ledger : Array Exec.Entry) (lo hi : Nat) : List Nat :=
  (List.range' (lo + 1) (hi - lo)).filter fun i => ledger[i - 1]?.any (·.sig)

/-- The commit index the hold ends with. -/
def Par.bd (p : Par) : Nat :=
  max p.c0 (maxCommittableIndexUpTo (p.lx.map (absEntry p.names)) p.lim)

/-- The declared core during the execute phase. -/
structure Good (p : Par) (c : Core) : Prop where
  nodeId : c.nodeId = p.nid
  view : c.currentView = p.view
  vf : c.votedFor = p.vf
  nf : c.isNewFollower = p.nf
  size : c.ledger.size = c.lastIdx
  ledger : c.ledger.toList = p.lx.take c.lastIdx
  last : c.lastIdx <= p.lx.length
  committable : c.committable = sigsIn c.ledger c.commitIdx c.lastIdx
  c0 : p.c0 <= c.commitIdx
  bd : c.commitIdx <= p.bd
  ci : c.commitIdx <= c.lastIdx
  views : c.views.size <= p.view
  rc : forall x, x ∈ c.rcEntries -> p.c0 < x.1
  lt : p.lt ≠ .leader
  d
    : (c.retiredCommittedIdx = p.rciT /\ c.leadership = p.lt /\ c.leaderId = some p.ldr)
      \/ ((exists s, p.c0 < s /\ c.retiredCommittedIdx = some s)
          /\ c.leadership = .none
          /\ c.leaderId = none)

theorem Good.nl {p : Par} {c : Core} (g : Good p c) : c.leadership ≠ .leader := by
  rcases g.d with ⟨_, h, _⟩ | ⟨_, h, _⟩
  · rw [h]; exact g.lt
  · rw [h]; decide

/-- `Good` with a fixed last and commit index: what the commit path keeps. -/
def CG (p : Par) (n m : Nat) (c : Core) : Prop :=
  Good p c /\ c.lastIdx = n /\ c.commitIdx = m

theorem CG.nl {p : Par} {n m : Nat} : forall c, CG p n m c -> c.leadership ≠ .leader :=
  fun _ g => g.1.nl

theorem CG.retire {p : Par} {n m : Nat} {c : Core} (g : CG p n m c) {s : Nat}
    (hs : p.c0 < s)
    : CG p n m
        { c with retiredCommittedIdx := some s, leadership := .none, leaderId := none } :=
  ⟨{ g.1 with d := Or.inr ⟨⟨s, hs, rfl⟩, rfl, rfl⟩ }, g.2⟩

def stepDown (w : State) : State :=
  {
    w with
      leaderId := none
      leadership := .none
  }

/-- The effect of `becomeRetired _ .retiredCommitted` on a non-leader. -/
def retireRC (w : State) : State :=
  {
    w with
      leaderId := none
      leadership := .none
      retired := true
      retirementPhase := some .retiredCommitted
  }

theorem hoare_becomeRetired_rc {env : Env} (i : Nat) (Pre : State -> Outbox -> Prop)
    (hnl : forall v o, Pre v o -> v.leadership ≠ .leader)
    : Hoare env Pre (becomeRetired i .retiredCommitted)
        (fun _ v o => exists w, Pre w o /\ v = retireRC w) := by
  unfold becomeRetired becomeRetired.nominateSuccessorUnsafe
  refine Hoare.pin fun w o0 pw => ?_
  refine Hoare.bind (R := fun _ v o => v = w /\ o = o0) ?_ fun _ => ?_
  · refine Hoare.getV_bind fun s => ?_
    refine Hoare.pin fun v1 o1 ⟨⟨hv1, ho1⟩, hs⟩ => ?_
    subst hv1 ho1 hs
    have nl := hnl _ _ pw
    refine Hoare.ite (fun h => absurd (beq_iff_eq.mp h) nl) fun _ => ?_
    exact Hoare.pure _ fun _ _ p => p
  · refine Hoare.bind (Hoare.setV _ (Q := fun _ v o => v = stepDown w /\ o = o0) fun v o ⟨hv, ho⟩ => ⟨by rw [hv]; rfl, ho⟩) fun _ => ?_
    exact Hoare.setV _ fun v o ⟨hv, ho⟩ => ⟨w, ho ▸ pw, by rw [hv]; rfl⟩

theorem core_retireRC (w : State) (s : Nat)
    : core (retireRC { w with retiredCommittedIdx := some s })
      = {
        core w with
          retiredCommittedIdx := some s, leadership := .none, leaderId := none
      } :=
  rfl

theorem ginv_retire_self {env : Env} {p : Par} {n m : Nat} (seqno : Nat)
    (hs : p.c0 < seqno) {β : Type} (k : Unit -> M β)
    (hk : forall a, GInv env (CG p n m) (k a))
    : GInv env (CG p n m)
        (Exec.setV (fun v => { v with retiredCommittedIdx := some seqno })
          >>= fun _ =>
                becomeRetired seqno .retiredCommitted >>= k) := by
  intro o0
  refine Hoare.bind
    (R :=
      fun _ v o =>
        exists w,
          (CG p n m (core w) /\ o = o0)
          /\ v = { w with retiredCommittedIdx := some seqno })
    (Hoare.setV _ fun v o h => ⟨v, h, rfl⟩) fun _ => ?_
  refine Hoare.bind (hoare_becomeRetired_rc seqno _ ?_) fun a => ?_
  · rintro v o ⟨w, ⟨g, _⟩, rfl⟩
    exact g.1.nl
  · refine Hoare.pre (hk a o0) ?_
    rintro v o ⟨w', ⟨w, ⟨g, ho⟩, rfl⟩, rfl⟩
    exact ⟨by rw [core_retireRC]; exact g.retire hs, ho⟩

theorem ginv_setRetiredCommitted {env : Env} {p : Par} {n m : Nat} (seqno : Nat)
    (hs : p.c0 < seqno) (ids : List NodeId) (peers0 : List (NodeId × Peer))
    : GInv env (CG p n m) (setRetiredCommitted seqno ids peers0) := by
  unfold setRetiredCommitted
  refine GInv.bind (GInv.forIn_list _ _ fun id _ _ => ?_) fun _ => GInv.pure _
  refine GInv.getV_bind fun s g => ?_
  refine GInv.ite (fun _ => ?_) (fun _ => ?_)
  · dsimp only
    have nl : ¬ (s.leadership == .leader) = true := fun h => g.1.nl (beq_iff_eq.mp h)
    refine GInv.ite (fun _ => ?_) fun _ =>
      GInv.bind (GInv.keeps Spec.curLoc) fun _ => GInv.fail_bind _ _
    exact GInv.ite (fun h => absurd h nl) fun _ =>
      ginv_retire_self seqno hs _ fun _ => GInv.pure _
  · exact GInv.bind (GInv.setV fun _ h => h) fun _ => GInv.pure _

theorem ginv_storeCompact_go {env : Env} {p : Par} {n m : Nat} (idx : Nat)
    (peers0 : List (NodeId × Peer))
    : forall l : List (Nat × List NodeId),
        (forall x, x ∈ l -> p.c0 < x.1)
        -> GInv env (CG p n m) (storeCompact.go idx peers0 l) := by
  intro l
  induction l with
  | nil => intro _; exact GInv.pure _
  | cons x rest ih =>
      intro h
      obtain ⟨ver, ids⟩ := x
      rw [storeCompact.go]
      refine GInv.ite (fun _ => ?_) fun _ => GInv.pure _
      exact GInv.bind (ginv_setRetiredCommitted ver (h _ (List.mem_cons_self ..)) ids peers0)
        fun _ => ih fun y hy => h y (List.mem_cons_of_mem _ hy)

theorem ginv_storeCompact {env : Env} {p : Par} {n m : Nat} (idx : Nat)
    : GInv env (CG p n m) (storeCompact idx) := by
  unfold storeCompact
  refine GInv.getV_bind fun _ _ => GInv.getV_bind fun s g => ?_
  refine GInv.bind (ginv_storeCompact_go idx _ _ g.1.rc) fun _ => GInv.setV fun v h => ?_
  exact ⟨{ h.1 with rc := fun x hx => h.1.rc x (List.mem_filter.mp hx).1 }, h.2⟩

theorem sigsIn_filter (ledger : Array Exec.Entry) {m idx n : Nat} (h1 : m <= idx)
    (h2 : idx <= n)
    : (sigsIn ledger m n).filter (fun x => decide (x > idx)) = sigsIn ledger idx n := by
  unfold sigsIn
  have split : List.range' (m + 1) (n - m)
      = List.range' (m + 1) (idx - m) ++ List.range' (idx + 1) (n - idx) := by
    rw [show n - m = (idx - m) + (n - idx) by omega, ← List.range'_append_1,
      show m + 1 + (idx - m) = idx + 1 by omega]
  rw [split, List.filter_append, List.filter_append]
  have a : ((List.range' (m + 1) (idx - m)).filter fun i => ledger[i - 1]?.any (·.sig)).filter
      (fun x => decide (x > idx)) = [] := by
    rw [List.filter_eq_nil_iff]
    intro x hx
    have := (List.mem_filter.mp hx).1
    rw [List.mem_range'_1] at this
    simp only [decide_eq_true_eq]
    omega
  have b : ((List.range' (idx + 1) (n - idx)).filter fun i => ledger[i - 1]?.any (·.sig)).filter
      (fun x => decide (x > idx))
      = (List.range' (idx + 1) (n - idx)).filter fun i => ledger[i - 1]?.any (·.sig) := by
    rw [List.filter_eq_self]
    intro x hx
    have := (List.mem_filter.mp hx).1
    rw [List.mem_range'_1] at this
    simp only [decide_eq_true_eq]
    omega
  rw [a, b, List.nil_append]

/-- Decompose a handler into `GInv` rules for `CG`. -/
macro "ginv_tac" : tactic =>
  `(tactic| repeat' (first
    | with_reducible exact GInv.pure _
    | with_reducible exact GInv.fail _
    | with_reducible exact GInv.keeps (Spec.trace _)
    | with_reducible exact GInv.keeps (Spec.emitNat _ _)
    | with_reducible exact GInv.keeps (Spec.emitStr _ _)
    | with_reducible exact GInv.keeps Spec.curLoc
    | with_reducible exact ginv_storeCompact _
    | (refine GInv.of_frame CG.nl ?_; frame_ext)
    | (with_reducible apply GInv.getV_bind; intro _ _)
    | with_reducible apply GInv.bind
    | with_reducible apply GInv.ite
    | (refine GInv.setV fun _ h => h)
    | (with_reducible intro)
    | dsimp only
    | with_reducible split))

theorem hoare_commit {env : Env} {p : Par} {n m : Nat} (idx : Nat) (o0 : Outbox)
    (hm : m < idx) (hn : idx <= n) (hb : idx <= p.bd)
    : Hoare env (fun v o => CG p n m (core v) /\ o = o0) (commit idx)
        (fun _ v o => CG p n idx (core v) /\ o = o0) := by
  unfold commit
  refine Hoare.getV_bind fun s => ?_
  refine Hoare.pin fun v0 o1 ⟨⟨g, ho1⟩, hv⟩ => ?_
  subst hv ho1
  dsimp only
  have l : v0.lastIdx = n := g.2.1
  have c : v0.commitIdx = m := g.2.2
  refine Hoare.ite (fun h => ?_) fun _ => ?_
  · exfalso
    omega
  refine Hoare.ite (fun h => ?_) fun _ => ?_
  · exfalso
    omega
  refine Hoare.bind (Hoare.keeps (Spec.trace _) (Q := fun _ v o => v = v0 /\ o = o1)
    fun _ _ _ p => p) fun _ => ?_
  refine Hoare.bind (Hoare.keeps (Spec.emitNat _ _) (Q := fun _ v o => v = v0 /\ o = o1)
    fun _ _ _ p => p) fun _ => ?_
  refine Hoare.bind (Hoare.setV _ (Q := fun _ v o => CG p n idx (core v) /\ o = o1)
    fun v o ⟨hv, ho⟩ => ⟨?_, ho⟩) fun _ => ?_
  · subst hv
    have g1 := g.1
    refine ⟨{ g1 with
      committable := ?_
      c0 := Nat.le_trans g1.c0 (by simp only [core] at c ⊢; omega)
      bd := hb
      ci := by simp only [core] at l ⊢; omega }, l, rfl⟩
    have e := g1.committable
    simp only [core] at e l c ⊢
    rw [e, l, c]
    exact sigsIn_filter _ (Nat.le_of_lt hm) hn
  · refine (?_ : GInv env (CG p n idx) _) o1
    ginv_tac

theorem mem_sigsIn {ledger : Array Exec.Entry} {lo hi x : Nat}
    : x ∈ sigsIn ledger lo hi
      <-> lo < x /\ x <= hi /\ ledger[x - 1]?.any (·.sig) = true := by
  unfold sigsIn
  simp only [List.mem_filter, List.mem_range'_1]
  constructor
  · rintro ⟨⟨a, b⟩, c⟩
    exact ⟨by omega, by omega, c⟩
  · rintro ⟨a, b, c⟩
    exact ⟨⟨by omega, by omega⟩, c⟩

theorem sigsIn_sorted (ledger : Array Exec.Entry) (lo hi : Nat)
    : (sigsIn ledger lo hi).Pairwise (· < ·) :=
  (List.pairwise_lt_range' (s := lo + 1) (n := hi - lo)).filter _

theorem isSig_abs (names : Names) (lx : List Exec.Entry) {lim h : Nat} (h0 : 0 < h)
    (hl : h <= lim)
    : isSignatureAt ((lx.map (absEntry names)).take lim) h = lx[h - 1]?.any (·.sig) := by
  unfold isSignatureAt entryAt?
  simp only [Nat.pos_iff_ne_zero.mp h0, ite_false, List.getElem?_take,
    show h - 1 < lim by omega, ite_true, List.getElem?_map]
  cases lx[h - 1]? with
  | none => rfl
  | some e =>
      simp only [Option.map_some, Option.any_some]
      unfold absEntry
      cases e.sig <;> rfl

theorem Good.get {p : Par} {c : Core} (g : Good p c) {h : Nat} (hh : h <= c.lastIdx)
    (h0 : 0 < h)
    : c.ledger[h - 1]? = p.lx[h - 1]? := by
  rw [← Array.getElem?_toList, g.ledger, List.getElem?_take]
  simp only [show h - 1 < c.lastIdx by omega, ite_true]

theorem Good.sig_le_bd {p : Par} {c : Core} (g : Good p c) {h : Nat}
    (hm : h ∈ sigsIn c.ledger c.commitIdx c.lastIdx) (hl : h <= p.lim)
    : h <= p.bd := by
  obtain ⟨lo, hi, sig⟩ := mem_sigsIn.mp hm
  rw [g.get hi (by omega), ← isSig_abs p.names _ (by omega) hl] at sig
  have := le_mcI sig
  unfold Par.bd maxCommittableIndexUpTo
  omega

theorem viewAt_le_size' (v : State) (i : Nat) : v.viewAt i <= v.views.size := by
  unfold State.viewAt
  have := List.length_filter_le (fun x => decide (x <= i)) v.views.toList
  simpa using this

theorem getLast_max {l : List Nat} (sorted : l.Pairwise (· < ·)) {x : Nat}
    (last : l.getLast? = some x)
    : forall y, y ∈ l -> y <= x := by
  obtain ⟨ys, rfl⟩ := List.getLast?_eq_some_iff.mp last
  intro y mem
  rcases List.mem_append.mp mem with mem | mem
  · have := (List.pairwise_append.mp sorted).2.2 y mem x (List.mem_singleton_self _)
    omega
  · simp only [List.mem_singleton] at mem
    omega

theorem hoare_cip {env : Env} {p : Par} {n : Nat} (o0 : Outbox)
    : Hoare env (fun v o => Good p (core v) /\ v.lastIdx = n /\ o = o0)
        (commitIfPossible p.lim)
        (fun _ v o =>
          Good p (core v)
          /\ v.lastIdx = n
          /\ (n = p.lx.length -> v.commitIdx = p.bd)
          /\ o = o0) := by
  unfold commitIfPossible
  refine Hoare.getV_bind fun s => ?_
  refine Hoare.pin fun v0 o1 ⟨⟨g, l, ho1⟩, hv⟩ => ?_
  subst hv ho1
  -- The bound when the whole ledger is in: the top signature up to `lim` is committable.
  have top : n = p.lx.length -> p.bd <= v0.commitIdx \/ (v0.commitIdx < p.bd
      /\ p.bd ∈ (v0.committable.filter fun x => decide (x <= p.lim))) := by
    intro hn
    by_cases lt : p.bd <= v0.commitIdx
    · exact Or.inl lt
    · refine Or.inr ⟨by omega, ?_⟩
      have c0 := g.c0
      simp only [core] at c0
      have eq : p.bd = maxCommittableIndexUpTo (p.lx.map (absEntry p.names)) p.lim := by
        unfold Par.bd at lt ⊢
        omega
      rcases mcI_cases ((p.lx.map (absEntry p.names)).take p.lim) with z | sig
      · unfold maxCommittableIndexUpTo at eq
        omega
      · have b := mcIUpTo_le (p.lx.map (absEntry p.names)) p.lim
        unfold maxCommittableIndexUpTo at eq b
        rw [← eq] at sig b
        rw [List.length_map] at b
        rw [isSig_abs _ _ (by omega) b.1] at sig
        have cm := g.committable
        simp only [core] at cm l
        have gg := g.get (h := p.bd) (by simp only [core]; omega) (by omega)
        simp only [core] at gg
        rw [List.mem_filter, cm, mem_sigsIn, gg]
        exact ⟨⟨by omega, by omega, sig⟩, by simp only [decide_eq_true_eq]; omega⟩
  have cm : v0.committable = sigsIn v0.ledger v0.commitIdx v0.lastIdx := g.committable
  have bd : v0.commitIdx <= p.bd := g.bd
  have done : (n = p.lx.length -> v0.commitIdx = p.bd)
      -> Hoare env (fun v o => v = v0 /\ o = o1) (Pure.pure () : M Unit)
        (fun _ v o => Good p (core v) /\ v.lastIdx = n
          /\ (n = p.lx.length -> v.commitIdx = p.bd) /\ o = o1) :=
    fun h => Hoare.pure _ fun v o ⟨hv, ho⟩ => by
      subst hv ho
      exact ⟨g, l, h, rfl⟩
  have sorted : (v0.committable.filter fun x => decide (x <= p.lim)).Pairwise (· < ·) := by
    rw [cm]
    exact (sigsIn_sorted _ _ _).filter _
  refine Hoare.ite (fun _ => ?_) fun hg => done fun hn => ?_
  · split
    · rename_i h heq
      unfold State.highestCommittableLe at heq
      have mem : h ∈ v0.committable.filter fun x => decide (x <= p.lim) := by
        obtain ⟨ys, eq⟩ := List.getLast?_eq_some_iff.mp heq
        rw [eq]
        exact List.mem_append_right _ (List.mem_singleton_self _)
      have mem' := List.mem_filter.mp mem
      rw [cm] at mem'
      have hb := g.sig_le_bd mem'.1 (by simpa using mem'.2)
      obtain ⟨lo, hi, _⟩ := mem_sigsIn.mp mem'.1
      refine Hoare.pre (Hoare.post (hoare_commit h o1 lo (by omega) hb)
        fun _ v o ⟨cg, ho⟩ => ⟨cg.1, cg.2.1, fun hn => ?_, ho⟩) fun v o ⟨hv, ho⟩ => by
          subst hv ho
          exact ⟨⟨g, l, rfl⟩, rfl⟩
      have e : v.commitIdx = h := cg.2.2
      rw [e]
      rcases top hn with t | ⟨_, t⟩
      · omega
      · have := getLast_max sorted heq p.bd t
        omega
    · rename_i x hx
      refine done fun hn => ?_
      rcases top hn with t | ⟨_, t⟩
      · omega
      · exfalso
        unfold State.highestCommittableLe at hx
        obtain ⟨y, hy⟩ := Option.ne_none_iff_exists'.mp
          (mt List.getLast?_eq_none_iff.mp (List.ne_nil_of_mem t))
        exact hx y hy
  · rcases top hn with t | ⟨lt, t⟩
    · omega
    · exfalso
      apply hg
      have hl := (List.mem_filter.mp t).2
      simp only [decide_eq_true_eq] at hl
      simp only [Bool.and_eq_true, decide_eq_true_eq]
      refine ⟨by omega, ?_⟩
      have vw : v0.views.size <= p.view := g.views
      have cv : v0.currentView = p.view := g.view
      have := viewAt_le_size' v0 p.lim
      unfold State.getTerm
      split <;> omega

end Consensus.TraceValidation.Proofs.Ae
