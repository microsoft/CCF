module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import Consensus.TraceValidation.Proofs.Handlers.Nomination
public import Consensus.TraceValidation.Proofs.Handlers.AeRespClean
public import Consensus.TraceValidation.Proofs.Handlers.AeHoare

@[expose] public section

/-!
# A leader's `commit` (not reviewed)

`commit i` on a leader `v1` above its commit index sets the commit index and keeps the
node's term, ledger and votes (`Kept`). It either stays leader, sends nothing and keeps a
sub-collection of `v1`'s peers, or (when the node's own retirement commits) steps down
retired-committed, having nominated the successor that `find_successor` picks from `v1`'s
peers (`nominationSends`). M_tv checks that the successor cft.h picks after erasing the peers
retired-committed earlier in the same commit is that one.

A retired-committed peer erased by the commit is not re-created by
`create_and_remove_node_state`: `inv` (`rc_entries_retired`) puts it outside the
configurations the commit keeps.
-/

namespace Consensus.TraceValidation.Proofs.AeResp

open Consensus.Model.Node
open Consensus.TraceValidation (Names Env abs agrees trackedPeers inv invChecks)
open Consensus.TraceValidation.Exec (State Ctx Peer Config M)
open Consensus.TraceValidation.Proofs.Ae (Hoare)

/-! ## Configurations kept by a commit -/

theorem pop_suffix (i : Nat) : forall cs : List Config, Exec.commit.pop i cs <:+ cs
  | [] => by rw [Exec.commit.pop.eq_def]; exact List.suffix_refl _
  | [c] => by rw [Exec.commit.pop.eq_def]; exact List.suffix_refl _
  | c :: n :: rest => by
      rw [Exec.commit.pop.eq_1]
      split
      · exact List.suffix_refl _
      · exact (pop_suffix i (n :: rest)).trans (List.suffix_cons _ _)

theorem pop_pop {ver i : Nat} (le : ver <= i)
    : forall cs : List Config,
        Exec.commit.pop i (Exec.commit.pop ver cs) = Exec.commit.pop i cs
  | [] => by simp only [Exec.commit.pop.eq_def]
  | [c] => by simp only [Exec.commit.pop.eq_def]
  | c :: n :: rest => by
      by_cases h : ver < n.idx
      · simp only [Exec.commit.pop.eq_1 ver, h, ↓reduceIte]
      · have h' : ¬ i < n.idx := by omega
        simp only [Exec.commit.pop.eq_1 ver, h, Exec.commit.pop.eq_1 i, h', ↓reduceIte]
        exact pop_pop le (n :: rest)

/-- `id` is a member of a configuration of `cs`. -/
def MemIn (cs : List Config) (id : Exec.NodeId) : Prop :=
  exists c, c ∈ cs /\ exists a, a ∈ c.nodes /\ a.1 = id

theorem MemIn.suffix {cs ds : List Config} {id : Exec.NodeId} (h : cs <:+ ds)
    (m : MemIn cs id)
    : MemIn ds id := by
  obtain ⟨c, mem, rest⟩ := m
  exact ⟨c, h.subset mem, rest⟩

theorem MemIn.pop {ver i : Nat} (le : ver <= i) {cs : List Config} {id : Exec.NodeId}
    (m : MemIn (Exec.commit.pop i cs) id)
    : MemIn (Exec.commit.pop ver cs) id := by
  rw [← pop_pop le] at m
  exact m.suffix (pop_suffix _ _)

theorem memIn_of_any {cs : List Config} {id : Exec.NodeId}
    (h : (cs.any fun c => c.nodes.any fun a => a.1 == id) = true)
    : MemIn cs id := by
  simp only [List.any_eq_true, beq_iff_eq] at h
  obtain ⟨c, mem, a, ma, e⟩ := h
  exact ⟨c, mem, a, ma, e⟩

theorem memIn_active {cs : List Config} {id : Exec.NodeId}
    (h
      : id
        ∈ ((cs.flatMap fun x => x.nodes.map Prod.fst).mergeSort
            fun x1 x2 => decide (x1 <= x2)).eraseDups)
    : MemIn cs id := by
  rw [List.mem_eraseDups, List.mem_mergeSort, List.mem_flatMap] at h
  obtain ⟨c, mem, h⟩ := h
  obtain ⟨a, ma, e⟩ := List.mem_map.mp h
  exact ⟨c, mem, a, ma, e⟩

theorem lookup_isSome {l : List (Exec.NodeId × Peer)} {p : Exec.NodeId × Peer}
    (mem : p ∈ l)
    : (l.lookup p.1).isSome = true := by
  induction l with
  | nil => cases mem
  | cons q l ih =>
      rw [List.lookup_cons]
      split
      · rfl
      · rcases List.mem_cons.mp mem with rfl | mem
        · rename_i ne; simp at ne
        · exact ih mem

/-! ## The successor -/

theorem tvSuccessor_congr {v w : State} (h1 : v.allOtherNodes = w.allOtherNodes)
    (h2 : v.configurations = w.configurations)
    : tvSuccessor v = tvSuccessor w := by
  have : tvStep v = tvStep w := by
    funext acc p
    simp only [tvStep, latestOf, h2]
  simp only [tvSuccessor, this, h1]

theorem nominationSends_congr {names : Names} {v w : State} (lv : v.leadership = .leader)
    (lw : w.leadership = .leader) (hs : tvSuccessor v = tvSuccessor w)
    (hn : v.nodeId = w.nodeId) (ht : v.currentView = w.currentView)
    : nominationSends names v = nominationSends names w := by
  simp only [nominationSends, lv, lw, hs, hn, ht, ↓reduceIte]

/-! ## Hoare helpers -/

theorem hoare_assume {env : Env} {α : Type} {x : M α} {P : State -> Outbox -> Prop}
    {Q : α -> State -> Outbox -> Prop} {φ : Prop} (imp : forall v o, P v o -> φ)
    (h : φ -> Hoare env P x Q)
    : Hoare env P x Q :=
  fun c a c' e p r => h (imp _ _ p) c a c' e p r

theorem hoare_fail_bind {env : Env} {α β : Type} (m : String) {f : α -> M β}
    {P : State -> Outbox -> Prop} {Q : β -> State -> Outbox -> Prop}
    : Hoare env P (Exec.fail m >>= f) Q :=
  Hoare.bind (R := fun _ _ _ => False) (Hoare.fail m)
    fun _ => Hoare.false_pre fun _ _ h => h

theorem hoare_curLoc_fail {env : Env} {α β : Type} (m : String -> String) {f : α -> M β}
    {P : State -> Outbox -> Prop} {Q : β -> State -> Outbox -> Prop}
    : Hoare env P (Exec.curLoc >>= fun l => Exec.fail (m l) >>= f) Q :=
  Hoare.bind (Hoare.keeps Spec.curLoc fun _ _ _ h => h) fun _ => hoare_fail_bind _

/-! ## What a commit keeps -/

/-- The fields a commit keeps, and the commit index it sets. -/
def Kept (v1 : State) (i : Nat) (w : State) : Prop :=
  w.nodeId = v1.nodeId
  /\ w.currentView = v1.currentView
  /\ w.ledger = v1.ledger
  /\ w.lastIdx = v1.lastIdx
  /\ w.isNewFollower = v1.isNewFollower
  /\ w.votedFor = v1.votedFor
  /\ w.commitIdx = i

/--
Still leader: nothing sent, the peers among `v1`'s, keeping every peer of `v1` that is a
member of `cs`.
-/
def StillLeader (v1 : State) (cs : List Config) (o0 : Outbox) (w : State) (o : Outbox)
    : Prop :=
  w.leadership = .leader
  /\ w.leaderId = v1.leaderId
  /\ o = o0
  /\ (forall p, p ∈ w.allOtherNodes -> p ∈ v1.allOtherNodes)
  /\ (forall p, p ∈ v1.allOtherNodes -> MemIn cs p.1 -> p ∈ w.allOtherNodes)

/-- Stepped down retired-committed, having nominated `v1`'s successor. -/
def SteppedDown (names : Names) (v1 : State) (o0 : Outbox) (w : State) (o : Outbox)
    : Prop :=
  w.leadership = .none
  /\ w.leaderId = none
  /\ w.isRetiredCommitted = true
  /\ o = o0 ++ nominationSends names v1

/-- The invariant of the retired-committed records' processing. -/
def CInv (env : Env) (v1 : State) (i : Nat) (o0 : Outbox) (w : State) (o : Outbox)
    : Prop :=
  Kept v1 i w
  /\ w.configurations = v1.configurations
  /\ (StillLeader v1 (Exec.commit.pop i v1.configurations) o0 w o
      \/ SteppedDown env.names v1 o0 w o)

section
variable {env : Env} {v1 : State} {i : Nat} {o0 : Outbox}

theorem becomeRetiredRC_spec (seqno : Nat)
    : Spec env (Exec.becomeRetired seqno .retiredCommitted)
        fun v o _ v' o' =>
          v'
            = {
              v with
                leaderId := none,
                leadership := .none,
                retired := true,
                retirementPhase := some .retiredCommitted
            }
          /\ o' = o ++ nominationSends env.names v := by
  unfold Exec.becomeRetired
  exact Spec.weaken
    (Spec.bind nominateUnsafe_spec fun _ => Spec.bind (Spec.setV _) fun _ => Spec.setV _)
    fun _ _ _ _ _ ⟨_, _, _, ⟨e1, f1⟩, _, _, _, ⟨e2, f2⟩, e3, f3⟩ => by
      subst e1 f1 e2 f2 e3 f3
      exact ⟨rfl, rfl⟩

/-- The step down when the node's own retirement commits. -/
def rcTail (seqno : Nat) : M (ForInStep PUnit) := do
  Exec.setV fun v => { v with retiredCommittedIdx := some seqno }
  Exec.becomeRetired seqno Exec.Phase.retiredCommitted
  pure (ForInStep.yield PUnit.unit)

def rcState (seqno : Nat) (v : State) : State :=
  {
    v with
      retiredCommittedIdx := some seqno,
      leaderId := none,
      leadership := .none,
      retired := true,
      retirementPhase := some .retiredCommitted
  }

theorem rcTail_spec (seqno : Nat)
    : Spec env (rcTail seqno)
        fun v o r v' o' =>
          r = .yield PUnit.unit
          /\ v' = rcState seqno v
          /\ o'
              = o
                ++ nominationSends env.names
                    { v with retiredCommittedIdx := some seqno } :=
  Spec.weaken
    (Spec.bind (Spec.setV _)
      fun _ =>
        Spec.bind (becomeRetiredRC_spec seqno) fun _ => Spec.pure _)
    fun _ _ _ _ _ ⟨_, _, _, ⟨e1, f1⟩, _, _, _, ⟨e2, f2⟩, e3, e4, f3⟩ => by
      subst e1 f1 e2 f2 e3 e4 f3
      exact ⟨rfl, rfl, rfl⟩

/-- One `set_retired_committed` record that the commit covers. -/
theorem setRetiredCommitted_spec (env : Env) (lead : v1.leadership = .leader)
    (seqno : Nat) (ids : List Exec.NodeId)
    (hids
      : forall id,
          id ∈ ids -> id ≠ v1.nodeId -> ¬ MemIn (Exec.commit.pop i v1.configurations) id)
    : Hoare env (CInv env v1 i o0) (Exec.setRetiredCommitted seqno ids v1.allOtherNodes)
        fun _ => CInv env v1 i o0 := by
  unfold Exec.setRetiredCommitted
  refine Hoare.bind
    (Hoare.forIn_list ids PUnit.unit _ (fun _ _ => CInv env v1 i o0)
      (fun _ => CInv env v1 i o0) ?_ fun _ _ _ h => h)
    fun _ => Hoare.pure _ fun _ _ h => h
  intro pre a rest _ hl
  have mem : a ∈ ids := by simp [hl]
  refine Hoare.pin fun w o hw => ?_
  refine Hoare.getV_bind fun s => ?_
  refine hoare_assume (φ := w = s) (fun _ _ h => h.1.1 ▸ h.2) fun e => ?_
  subst e
  obtain ⟨kept, cfg, hw⟩ := hw
  by_cases self : a = w.nodeId
  · subst self
    simp only [beq_self_eq_true, ↓reduceIte]
    refine Hoare.ite (fun _ => ?_) (fun _ => hoare_curLoc_fail _)
    have done : forall o', o' = o0 ++ nominationSends env.names v1
        -> CInv env v1 i o0 (rcState seqno w) o' :=
      fun o' e => ⟨kept, cfg, Or.inr ⟨rfl, rfl, rfl, e⟩⟩
    refine Hoare.ite (fun hl => ?_) (fun hnl => ?_)
    · have hl : w.leadership = .leader := by simpa using hl
      obtain ⟨-, -, ho, -, -⟩ := hw.resolve_right fun d => by rw [d.1] at hl; cases hl
      let w' := { w with allOtherNodes := v1.allOtherNodes }
      refine Hoare.bind (R := fun a v o' => a = tvSuccessor w /\ v = w /\ o' = o)
        (Hoare.of_spec findSuccessor_spec fun _ _ _ _ _ p r => by
          obtain ⟨⟨rfl, rfl⟩, -⟩ := p; exact r) fun actual => ?_
      refine hoare_assume (fun _ _ p => p.1) fun ha => ?_
      refine Hoare.bind (R := fun _ v o' => v = w' /\ o' = o)
        (Hoare.setV _ fun v o' p => by obtain ⟨_, rfl, rfl⟩ := p; exact ⟨rfl, rfl⟩)
        fun _ => ?_
      refine Hoare.bind (R := fun b v o' => b = tvSuccessor w' /\ v = w' /\ o' = o)
        (Hoare.of_spec findSuccessor_spec fun _ _ _ _ _ p r => by
          obtain ⟨rfl, rfl⟩ := p; exact r) fun specified => ?_
      refine hoare_assume (fun _ _ p => p.1) fun hs => ?_
      refine Hoare.bind (R := fun _ v o' => v = w /\ o' = o)
        (Hoare.setV _ fun _ _ p => ⟨rfl, p.2.2⟩) fun _ => ?_
      refine Hoare.ite (fun he => ?_) (fun _ => hoare_curLoc_fail _)
      have he : actual = specified := by simpa using he
      refine Hoare.of_spec (rcTail_spec seqno) fun _ _ _ _ _ p q => ?_
      obtain ⟨rfl, rfl⟩ := p
      obtain ⟨rfl, rfl, rfl⟩ := q
      refine done _ ?_
      rw [ho]
      congr 1
      refine nominationSends_congr hl lead ?_ kept.1 kept.2.1
      exact (tvSuccessor_congr rfl rfl).trans
        (ha.symm.trans (he.trans (hs.trans (tvSuccessor_congr rfl cfg))))
    · have hnl : w.leadership ≠ .leader := by simpa using hnl
      obtain ⟨-, -, -, ho⟩ := hw.resolve_left fun st => hnl st.1
      refine Hoare.of_spec (rcTail_spec seqno) fun _ _ _ _ _ p q => ?_
      obtain ⟨⟨rfl, rfl⟩, -⟩ := p
      obtain ⟨rfl, rfl, rfl⟩ := q
      refine done _ ?_
      simp only [nominationSends, hnl, ↓reduceIte, List.append_nil, ho]
  · have ne : (a == w.nodeId) = false := by simpa using self
    simp only [ne, Bool.false_eq_true, ↓reduceIte]
    refine Hoare.bind (Hoare.setV _ fun v o' p => ?_) fun _ => Hoare.pure _ fun _ _ h => h
    obtain ⟨⟨rfl, rfl⟩, -⟩ := p
    refine ⟨kept, cfg, ?_⟩
    rcases hw with ⟨l, li, ho, sub, keep⟩ | down
    · refine Or.inl ⟨l, li, ho, fun p mp => sub p (List.mem_filter.mp mp).1, fun p mp m => ?_⟩
      refine List.mem_filter.mpr ⟨keep p mp m, ?_⟩
      have : p.1 ≠ a := fun e => hids a mem (kept.1 ▸ self) (e ▸ m)
      simpa using this
    · exact Or.inr down

/-- The covered records, in order. -/
theorem go_spec (env : Env) (lead : v1.leadership = .leader)
    : forall l : List (Nat × List Exec.NodeId),
        (forall e,
          e ∈ l
          -> e.1 <= i
          -> forall id,
              id ∈ e.2
              -> id ≠ v1.nodeId
              -> ¬ MemIn (Exec.commit.pop e.1 v1.configurations) id)
        -> Hoare env (CInv env v1 i o0) (Exec.storeCompact.go i v1.allOtherNodes l)
            fun _ => CInv env v1 i o0
  | [], _ => by
      rw [Exec.storeCompact.go.eq_def]
      exact Hoare.pure _ fun _ _ h => h
  | (ver, ids) :: rest, h => by
      rw [Exec.storeCompact.go.eq_def]
      dsimp only
      refine Hoare.ite (fun le => ?_) (fun _ => Hoare.pure _ fun _ _ h => h)
      exact Hoare.bind
        (setRetiredCommitted_spec env lead ver ids fun id m ne mi =>
          h _ List.mem_cons_self le id m ne (MemIn.pop le mi))
        fun _ => go_spec env lead rest fun e m => h e (List.mem_cons_of_mem _ m)

theorem storeCompact_spec (env : Env) (lead : v1.leadership = .leader)
    (hrc
      : forall e,
          e ∈ v1.rcEntries
          -> e.1 <= i
          -> forall id,
              id ∈ e.2
              -> id ≠ v1.nodeId
              -> ¬ MemIn (Exec.commit.pop e.1 v1.configurations) id)
    : Hoare env
        (fun v o =>
          CInv env v1 i o0 v o
          /\ v.allOtherNodes = v1.allOtherNodes
          /\ v.rcEntries = v1.rcEntries)
        (Exec.storeCompact i) fun _ => CInv env v1 i o0 := by
  unfold Exec.storeCompact
  refine Hoare.getV_bind fun s => ?_
  refine hoare_assume (φ := s.allOtherNodes = v1.allOtherNodes /\ s.rcEntries = v1.rcEntries)
    (fun _ _ p => p.2 ▸ p.1.2) fun ⟨hp, hr⟩ => ?_
  refine Hoare.getV_bind fun s' => ?_
  refine hoare_assume (φ := s' = s) (fun _ _ p => p.2.symm.trans p.1.2) fun e => ?_
  subst e
  rw [hp, hr]
  exact Hoare.bind (Hoare.pre (go_spec env lead _ hrc) fun _ _ p => p.1.1.1)
    fun _ => Hoare.setV _ fun _ _ h => h

/-- After the configurations are popped. -/
def RInv (env : Env) (v1 : State) (i : Nat) (o0 : Outbox) (w : State) (o : Outbox)
    : Prop :=
  Kept v1 i w
  /\ w.configurations = Exec.commit.pop i v1.configurations
  /\ (StillLeader v1 (Exec.commit.pop i v1.configurations) o0 w o
      \/ SteppedDown env.names v1 o0 w o)

/-- `id` of a configuration of `v1` other than the node is one of its peers. -/
def Cover (v1 : State) : Prop :=
  forall id,
    MemIn v1.configurations id
    -> id ≠ v1.nodeId
    -> exists p, p ∈ v1.allOtherNodes /\ p.1 = id

theorem createAndRemove_spec (env : Env) (cover : Cover v1)
    : Hoare env (RInv env v1 i o0) Exec.createAndRemoveNodeState
        fun _ => RInv env v1 i o0 := by
  unfold Exec.createAndRemoveNodeState
  refine Hoare.getV_bind fun s => ?_
  refine hoare_assume
    (φ := s.configurations = Exec.commit.pop i v1.configurations /\ s.nodeId = v1.nodeId)
    (fun _ _ p => p.2 ▸ ⟨p.1.2.1, p.1.1.1⟩) fun ⟨hc, hn⟩ => ?_
  refine Hoare.bind
    (Hoare.pre
      (Hoare.forIn_list _ PUnit.unit _ (fun _ _ => RInv env v1 i o0)
        (fun _ => RInv env v1 i o0) ?_ fun _ _ _ h => h)
      fun _ _ p => p.1)
    fun _ => Hoare.pure _ fun _ _ h => h
  intro pre a rest _ hl
  have mi : MemIn (Exec.commit.pop i v1.configurations) a := by
    rw [← hc]
    exact memIn_active (by rw [hl]; simp)
  refine Hoare.pin fun w o hw => ?_
  have same : forall v o', (v = w /\ o' = o) -> RInv env v1 i o0 v o' := by
    rintro _ _ ⟨rfl, rfl⟩
    exact hw
  refine Hoare.ite (fun _ => Hoare.pure _ same) fun ne => ?_
  have ne : a ≠ v1.nodeId := by
    rw [← hn]
    simpa using ne
  refine Hoare.getV_bind fun t => ?_
  refine hoare_assume (φ := t = w) (fun _ _ p => p.2.symm.trans p.1.1) fun e => ?_
  subst e
  refine Hoare.ite (fun hnone => ?_) fun _ => Hoare.pure _ fun _ _ p => same _ _ p.1
  have down : SteppedDown env.names v1 o0 t o := hw.2.2.resolve_left fun st => by
    obtain ⟨p, mp, e⟩ := cover a (mi.suffix (pop_suffix _ _)) ne
    have := lookup_isSome (st.2.2.2.2 p mp (e ▸ mi))
    rw [e] at this
    simp only [State.peer?, Option.isNone_iff_eq_none] at hnone
    rw [hnone] at this
    cases this
  refine Hoare.bind
    (R :=
      fun _ v o' => v = t.setPeer a { sentIdx := t.lastIdx + 1, matchIdx := 0 } /\ o' = o)
    (Hoare.setV _ fun _ _ p => by obtain ⟨⟨rfl, rfl⟩, -⟩ := p; exact ⟨rfl, rfl⟩)
    fun _ => ?_
  have post : forall v o', (v = t.setPeer a { sentIdx := t.lastIdx + 1, matchIdx := 0 }
      /\ o' = o) -> RInv env v1 i o0 v o' := by
    rintro _ _ ⟨rfl, rfl⟩
    exact ⟨hw.1, hw.2.1, Or.inr down⟩
  refine Hoare.ite (fun hl => ?_) fun _ => Hoare.pure _ post
  rw [down.1] at hl
  cases hl

theorem commitTail_spec (env : Env) (lead : v1.leadership = .leader) (cover : Cover v1)
    (hrc
      : forall e,
          e ∈ v1.rcEntries
          -> e.1 <= i
          -> forall id,
              id ∈ e.2
              -> id ≠ v1.nodeId
              -> ¬ MemIn (Exec.commit.pop e.1 v1.configurations) id)
    : Hoare env
        (fun v o =>
          CInv env v1 i o0 v o
          /\ v.allOtherNodes = v1.allOtherNodes
          /\ v.rcEntries = v1.rcEntries)
        (do
          Exec.storeCompact i
          let l ← Exec.getV
          if (List.length (Exec.commit.pop i l.configurations) != l.configurations.length)
              = true then do
            Exec.setV
              fun v => { v with configurations := Exec.commit.pop i l.configurations }
            Exec.createAndRemoveNodeState
          else
            pure ())
        fun _ => RInv env v1 i o0 := by
  refine Hoare.bind (storeCompact_spec env lead hrc) fun _ => ?_
  refine Hoare.getV_bind fun s => ?_
  refine hoare_assume (φ := s.configurations = v1.configurations)
    (fun _ _ p => p.2 ▸ p.1.2.1) fun hc => ?_
  rw [hc]
  refine Hoare.ite (fun _ => ?_) fun hlen => ?_
  · refine Hoare.bind (Hoare.setV _ fun v o p => ?_) fun _ => createAndRemove_spec env cover
    obtain ⟨⟨kept, -, h⟩, rfl⟩ := p
    exact ⟨kept, rfl, h⟩
  · have e : Exec.commit.pop i v1.configurations = v1.configurations :=
      (pop_suffix _ _).eq_of_length (by simpa using hlen)
    refine Hoare.pure _ fun v o p => ?_
    obtain ⟨⟨kept, cfg, h⟩, rfl⟩ := p
    exact ⟨kept, cfg.trans e.symm, h⟩

theorem becomeRetiredCompleted_spec (seqno : Nat)
    : Spec env (Exec.becomeRetired seqno .completed)
        fun v o _ v' o' =>
          v' = { v with retired := true, retirementPhase := some .completed }
          /\ o' = o := by
  unfold Exec.becomeRetired
  exact Spec.setV _

/--
`commit i` by a leader `v1` between its commit and last indexes: the commit index set and the
configurations popped, either still leader with nothing sent and some of its peers, keeping
every peer the kept configurations name, or stepped down retired-committed having nominated
`v1`'s successor.
-/
theorem commit_spec (env : Env) (lead : v1.leadership = .leader) (lt : v1.commitIdx < i)
    (le : i <= v1.lastIdx) (cover : Cover v1)
    (hrc
      : forall e,
          e ∈ v1.rcEntries
          -> e.1 <= i
          -> forall id,
              id ∈ e.2
              -> id ≠ v1.nodeId
              -> ¬ MemIn (Exec.commit.pop e.1 v1.configurations) id)
    : Hoare env (fun v o => v = v1 /\ o = o0) (Exec.commit i)
        fun _ => RInv env v1 i o0 := by
  unfold Exec.commit
  refine Hoare.getV_bind fun s => ?_
  refine hoare_assume (φ := s = v1) (fun _ _ p => p.2.symm.trans p.1.1) fun e => ?_
  subst e
  simp only [show ¬ i > s.lastIdx by omega, show ¬ i <= s.commitIdx by omega, ↓reduceIte]
  refine Hoare.bind (Hoare.keeps (Spec.trace _) fun _ _ _ h => h) fun _ => ?_
  refine Hoare.bind (Hoare.keeps (Spec.emitNat _ _) fun _ _ _ h => h) fun _ => ?_
  refine Hoare.bind (Q := fun _ => RInv env s i o0)
    (R := fun _ v o => (CInv env s i o0 v o /\ v.allOtherNodes = s.allOtherNodes
      /\ v.rcEntries = s.rcEntries) /\ v.leadership = .leader)
    (Hoare.setV _ fun v o p => ?_) fun _ => ?_
  · obtain ⟨⟨e, f⟩, -⟩ := p
    rw [e, f]
    exact ⟨⟨⟨⟨rfl, rfl, rfl, rfl, rfl, rfl, rfl⟩, rfl,
      Or.inl ⟨lead, rfl, rfl, fun _ m => m, fun _ m _ => m⟩⟩, rfl, rfl⟩, lead⟩
  refine Hoare.getV_bind fun t => ?_
  have tail := Hoare.pre (commitTail_spec env lead cover hrc (o0 := o0))
    (P := fun v o => ((CInv env s i o0 v o /\ v.allOtherNodes = s.allOtherNodes
      /\ v.rcEntries = s.rcEntries) /\ v.leadership = .leader) /\ v = t) fun _ _ p => p.1.1
  refine Hoare.ite (fun _ => ?_) fun _ => tail
  split
  · refine Hoare.ite (fun _ => ?_) fun _ => tail
    refine Hoare.bind (Hoare.of_spec (becomeRetiredCompleted_spec i) fun v o _ v' o' p q => ?_)
      fun _ => commitTail_spec env lead cover hrc
    obtain ⟨⟨⟨⟨kept', cfg, h⟩, hp, hr⟩, hl⟩, -⟩ := p
    obtain ⟨rfl, rfl⟩ := q
    refine ⟨⟨kept', cfg, ?_⟩, hp, hr⟩
    rcases h with ⟨h1, h2, h3, h4, h5⟩ | h
    · exact Or.inl ⟨h1, h2, h3, h4, h5⟩
    · exact absurd (h.1.symm.trans hl) (by decide)
  · exact tail

end

end Consensus.TraceValidation.Proofs.AeResp
