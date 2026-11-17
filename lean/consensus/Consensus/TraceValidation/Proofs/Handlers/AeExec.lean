module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import Consensus.TraceValidation.Proofs.Handlers.AeCommit

@[expose] public section

/-!
# The execute phase of AppendEntries (not reviewed)

`recvAppendEntries_eq` restates the handler through named pieces: the scan loop's body
`scanBody`, the execute loop's body `execBody`, the finish `aeFinish`, and the phases after
the term handling (`aeMatch`, `aeApply`). `GT` says a handler takes the core from one
predicate to another and sends nothing. Executing entry `i` of the final ledger takes `Good`
at last index `i - 1` to `Good` at `i` (`gt_exec`), so the execute loop over the work list
ends with the whole final ledger (`gt_execLoop`), and the finish reaches the clean commit
bound and sends the ACK (`hoare_finish`).
-/

namespace Consensus.TraceValidation.Proofs.Ae

open Consensus.Model.Node
open Consensus.TraceValidation.Exec

/-- The scan loop's body. -/
def scanBody (from_ : NodeId) (r : AppendEntriesRequest) (payload : Array Exec.Entry)
    (i : Nat) (s : Option Unit × Array (Nat × Exec.Entry × Bool))
    : M (ForInStep (Option Unit × Array (Nat × Exec.Entry × Bool))) :=
  let toApply := s.snd
  let entry? := payload[i - r.prevLogIndex - 1]?
  if entry?.isNone = true then do
    nack from_
    pure (ForInStep.done (some (), toApply))
  else do
    let entry := entry?.get!
    let v ← getV
    let push : Unit -> M (ForInStep (Option Unit × Array (Nat × Exec.Entry × Bool))) :=
      fun _ => do
        if (!entry.retired.isEmpty) = true then
          setV fun v => { v with rcEntries := v.rcEntries ++ [(i, entry.retired)] }
        pure
          (ForInStep.yield (none, toApply.push (i, entry, entry.term == aeTermOfIdx r)))
    if i ≤ v.lastIdx then
      if (aeTermOfIdx r != v.viewAt i) = true then
        if v.isNewFollower = true then do
          rollback (i - 1)
          setV fun v => { v with isNewFollower := false }
          push ()
        else
          pure (ForInStep.done (some (), toApply))
      else
        pure (ForInStep.yield (none, toApply))
    else
      push ()

/-- The execute loop's body. -/
def execBody (from_ : NodeId) (r : AppendEntriesRequest) (x : Nat × Exec.Entry × Bool)
    (_s : Option Unit × Unit)
    : M (ForInStep (Option Unit × Unit)) :=
  match x with
  | (i, entry, ok) => do
      trace "execute_append_entries_sync"
      emitStr "from_node_id" from_
      if ok = true then do
        setV fun v => { v with lastIdx := i }
        forIn entry.retired PUnit.unit
          fun id _ => do
            trace "retired_committed_tx"
            emitNat "seqno" i
            emitStr "retired_node_id" id
            pure (ForInStep.yield PUnit.unit)
        let jp : Unit -> M (ForInStep (Option Unit × Unit)) :=
          fun _ =>
            let jp :=
              fun (_ : Unit) => do
                setV fun v => { v with ledger := (v.ledger.extract 0 (i - 1)).push entry }
                if entry.sig = true then do
                  let v ← getV
                  let jp : Unit -> M (ForInStep (Option Unit × Unit)) :=
                    fun _ => do
                      setV fun v => { v with committable := v.committable ++ [i] }
                      if (entry.term != 0) = true then
                        let jp :=
                          fun (_ : Unit) => do
                            commitIfPossible (min r.primaryCommit (aeIdx r))
                            pure (ForInStep.yield (none, ()))
                        if (aeTermOfIdx r == 0) = true then do
                          let x ← viewUpdate 1 r.term
                          jp x
                        else do
                          let x ← viewUpdate (r.prevLogIndex + 1) entry.term
                          jp x
                      else
                        pure (ForInStep.yield (none, ()))
                  if (v.retired && v.retirementPhase == some Phase.ordered) = true then do
                    let x ← becomeRetired i Phase.signed
                    jp x
                  else
                    jp ()
                else
                  pure (ForInStep.yield (none, ()))
            if entry.sig = true then do
              let x ← startTickingIfNecessary
              jp x
            else
              jp ()
        match entry.config with
        | some nodes => do
            let _ ← addConfiguration (some i) (some nodes)
            jp ()
        | _ => jp ()
      else do
        setV fun v => { v with ledger := v.ledger.extract 0 (i - 1) }
        nack from_
        pure (ForInStep.done (some (), ()))

/-- `execute_append_entries_finish` and the ACK. -/
def aeFinish (from_ : NodeId) (r : AppendEntriesRequest) : M Unit := do
  commitIfPossible (min r.primaryCommit (aeIdx r))
  let w ← getV
  let lci := w.lastCommittable
  let jp : Unit -> M Unit :=
    fun _ => do
      let w ← getV
      sendAer from_ w.currentView (aeIdx r) true
  if (aeTermOfIdx r == 0) = true then do
    let x ← viewUpdate 1 r.term
    jp x
  else if aeIdx r > lci then do
    let x ← viewUpdate (lci + 1) (aeTermOfIdx r)
    jp x
  else
    jp ()

/-- The scan and execute phases and the finish. -/
def aeApply (from_ : NodeId) (r : AppendEntriesRequest) (payload : Array Exec.Entry)
    : M Unit := do
  let s ← forIn [r.prevLogIndex + 1 : aeIdx r + 1] (none, #[]) (scanBody from_ r payload)
  match s.fst with
  | some x => pure x
  | none => do
      let t ← forIn s.snd (none, ()) (execBody from_ r)
      match t.fst with
      | some x => pure x
      | none => aeFinish from_ r

/-- After the term phase and the leader guard. -/
def aeMatch (from_ : NodeId) (r : AppendEntriesRequest) (payload : Array Exec.Entry)
    (v : State)
    : M Unit :=
  let prevTerm := v.getTerm r.prevLogIndex
  if (prevTerm != r.prevLogTerm) = true then
    let jp := fun (_ : Unit) => (pure () : M Unit)
    if (prevTerm == 0) = true then do
      let x ← nack from_
      jp x
    else do
      let x ← nackRejected from_ r.prevLogTerm r.prevLogIndex
      jp x
  else do
    setV fun v => { v with leaderId := some from_ }
    let v ← getV
    if r.prevLogIndex < v.commitIdx then
      pure ()
    else if r.prevLogIndex > v.lastIdx then
      pure ()
    else
      aeApply from_ r payload

theorem recvAppendEntries_eq (from_ : NodeId) (r : AppendEntriesRequest)
    : recvAppendEntries from_ r
      = (do
          traceRecv "recv_append_entries" from_ (.appendEntriesRequest r)
          let c ← get
          let payload := (r.entries.map (toExecEntry c.env)).toArray
          let v ← getV
          let jp : Unit -> M Unit :=
            fun _ => do
              let v ← getV
              let jp : Unit -> M Unit := fun _ => aeMatch from_ r payload v
              if (v.leadership == .leader && v.currentView == r.term) = true then do
                let l ← curLoc
                let x ←
                  fail
                    (toString l
                      ++ toString ": AppendEntries from "
                      ++ toString from_
                      ++ toString " to a leader in its own view "
                      ++ toString r.term)
                jp x
              else
                jp ()
          if (v.currentView == r.term
                && (v.leadership == .candidate || v.leadership == .preVoteCandidate))
              = true then do
            let x ← becomeAwareOfNewTerm r.term
            jp x
          else if v.currentView < r.term then
            do
              let x ← becomeAwareOfNewTerm r.term
              jp x
          else if v.currentView > r.term then
            do
              nack from_
              pure ()
          else
            jp ()) := by
  unfold recvAppendEntries
  refine congrArg (fun k => traceRecv _ _ _ >>= k) (funext fun _ => ?_)
  refine congrArg (fun k => get >>= k) (funext fun c => ?_)
  refine congrArg (fun k => getV >>= k) (funext fun v => ?_)
  refine ite_congr rfl (fun _ => ?_) fun _ => ite_congr rfl (fun _ => ?_) fun _ =>
    ite_congr rfl (fun _ => rfl) fun _ => ?_
  all_goals first
    | refine congrArg (fun k => Exec.becomeAwareOfNewTerm _ >>= k) (funext fun _ => ?_)
    | skip
  all_goals
    refine congrArg (fun k => getV >>= k) (funext fun w => ?_)
    refine ite_congr rfl (fun _ => ?_) (fun _ => ?_)
  all_goals first
    | refine congrArg (fun k => curLoc >>= k) (funext fun l => ?_)
      refine congrArg (fun k => Exec.fail _ >>= k) (funext fun x => ?_)
    | skip
  all_goals
    show _ = aeMatch from_ r _ w
    unfold aeMatch
    refine ite_congr rfl (fun _ => rfl) (fun _ => ?_)
    refine congrArg (fun k => setV _ >>= k) (funext fun _ => ?_)
    refine congrArg (fun k => getV >>= k) (funext fun u => ?_)
    refine ite_congr rfl (fun _ => rfl) (fun _ => ite_congr rfl (fun _ => rfl) (fun _ => ?_))
    unfold aeApply
    refine congr (congrArg (fun f k => forIn _ _ f >>= k) ?_) (funext fun t => ?_)
    · funext i s
      exact rfl
    · obtain ⟨a, b⟩ := t
      cases a
      · show _ = (do let t ← forIn b (none, ()) (execBody from_ r); _)
        refine congr (congrArg (fun f k => forIn _ _ f >>= k) ?_) (funext fun t => ?_)
        · funext x s
          exact rfl
        · obtain ⟨a, b⟩ := t
          cases a
          · exact rfl
          · rfl
      · rfl

/-- `Good` at a fixed last index. -/
def GN (p : Par) (n : Nat) (c : Core) : Prop :=
  Good p c /\ c.lastIdx = n

theorem GN.nl {p : Par} {n : Nat} : forall c, GN p n c -> c.leadership ≠ .leader :=
  fun _ g => g.1.nl

theorem ginv_viewUpdate {env : Env} {p : Par} {n : Nat} (idx t : Nat) (ht : t <= p.view)
    : GInv env (GN p n) (viewUpdate idx t) := by
  unfold viewUpdate
  refine GInv.getV_bind fun _ _ => ?_
  intro
  have hs : GInv env (GN p n) (setV fun v : State =>
      { v with views := v.views ++ Array.replicate (t - v.views.size) idx }) := by
    refine GInv.setV fun v g => ?_
    refine ⟨{ g.1 with views := ?_ }, g.2⟩
    have := g.1.views
    simp only [core, Array.size_append, Array.size_replicate] at this ⊢
    omega
  apply GInv.ite
  · intro _; exact GInv.bind (GInv.keeps Spec.curLoc) fun _ => GInv.bind (GInv.fail _) fun _ => hs
  · intro _; exact hs

theorem sigsIn_succ (ledger : Array Exec.Entry) {lo hi : Nat} (h : lo <= hi)
    : sigsIn ledger lo (hi + 1)
      = sigsIn ledger lo hi ++ (if ledger[hi]?.any (·.sig) then [hi + 1] else []) := by
  unfold sigsIn
  rw [show hi + 1 - lo = (hi - lo) + 1 by omega, List.range'_1_concat, List.filter_append,
    show lo + 1 + (hi - lo) = hi + 1 by omega]
  simp only [List.filter_cons, List.filter_nil, Nat.add_sub_cancel]

theorem sigsIn_congr {a b : Array Exec.Entry} {lo hi : Nat}
    (h : forall j, lo < j -> j <= hi -> a[j - 1]? = b[j - 1]?)
    : sigsIn a lo hi = sigsIn b lo hi := by
  unfold sigsIn
  apply List.filter_congr
  intro j hj
  rw [List.mem_range'_1] at hj
  rw [h j (by omega) (by omega)]

/-- The core after pushing entry `e` at index `i`, with its signature in `committable`. -/
def pushed (c : Core) (i : Nat) (e : Exec.Entry) : Core :=
  {
    c with
      ledger := (c.ledger.extract 0 (i - 1)).push e
      committable := c.committable ++ (if e.sig then [i] else [])
  }

theorem good_push {p : Par} {i : Nat} {e : Exec.Entry} {c : Core}
    (hi : p.lx[i - 1]? = some e) (h1 : 1 <= i)
    (g : Good p { c with lastIdx := i - 1 }) (hl : c.lastIdx = i)
    : Good p (pushed c i e) := by
  have gs := g.size
  have gl := g.ledger
  have gL := g.last
  have gc := g.committable
  have gci := g.ci
  simp only at gs gl gL gc gci
  have hx : c.ledger.extract 0 (i - 1) = c.ledger := by
    rw [Array.extract_eq_self_iff]; omega
  have hlx : i <= p.lx.length := by
    have := (List.getElem?_eq_some_iff.mp hi).1; omega
  unfold pushed
  refine { g with size := ?_, ledger := ?_, last := ?_, committable := ?_, ci := ?_ }
  · simp only [hx, Array.size_push, hl]; omega
  · simp only [hx, Array.toList_push, gl, hl]
    rw [show i = (i - 1) + 1 by omega, List.take_add_one, hi]
    simp
  · simp only [hl]; exact hlx
  · simp only [hx, hl]
    rw [show i = (i - 1) + 1 by omega, sigsIn_succ _ gci, gc]
    rw [sigsIn_congr (b := c.ledger.push e) fun j hj1 hj2 => ?_]
    · simp only [Array.getElem?_push]
      simp [gs]
    · rw [Array.getElem?_push]; simp only [gs]
      split
      · omega
      · rfl
  · simp only [hl]; omega

/-- `x` takes the core from `G` to `H` and sends nothing. -/
def GT {α : Type} (env : Env) (G : Core -> Prop) (H : α -> Core -> Prop) (x : M α)
    : Prop :=
  forall o0 : Outbox,
    Hoare env (fun v o => G (core v) /\ o = o0) x (fun a v o => H a (core v) /\ o = o0)

namespace GT
variable {env : Env}

theorem of_ginv {α : Type} {G : Core -> Prop} {x : M α} (h : GInv env G x)
    : GT env G (fun _ => G) x :=
  h

theorem bind {α β : Type} {G : Core -> Prop} {H : α -> Core -> Prop}
    {K : β -> Core -> Prop} {x : M α} {f : α -> M β} (hx : GT env G H x)
    (hf : forall a, GT env (H a) K (f a))
    : GT env G K (x >>= f) :=
  fun o0 => Hoare.bind (hx o0) fun a => hf a o0

theorem setV {G : Core -> Prop} {H : Unit -> Core -> Prop} {f : State -> State}
    (hf : forall v, G (core v) -> H () (core (f v)))
    : GT env G H (Exec.setV f) :=
  fun _ => Hoare.setV f fun v _ ⟨g, ho⟩ => ⟨hf v g, ho⟩

theorem pure {α : Type} {G : Core -> Prop} {H : α -> Core -> Prop} (a : α)
    (h : forall c, G c -> H a c)
    : GT env G H (Pure.pure a : M α) :=
  fun _ => Hoare.pure a fun _ _ ⟨g, ho⟩ => ⟨h _ g, ho⟩

theorem fail {α : Type} {G : Core -> Prop} {H : α -> Core -> Prop} (m : String)
    : GT env G H (Exec.fail m : M α) :=
  fun _ => Hoare.fail m

theorem getV_bind {β : Type} {G : Core -> Prop} {H : β -> Core -> Prop} {k : State -> M β}
    (hk : forall s, G (core s) -> GT env (fun c => G c /\ c = core s) H (k s))
    : GT env G H (Exec.getV >>= k) := by
  intro o0
  refine Hoare.getV_bind fun s => ?_
  refine Hoare.pin fun v0 o1 ⟨⟨g, ho1⟩, hv⟩ => ?_
  subst hv ho1
  exact Hoare.pre (hk v0 g o1) fun v o ⟨hv, ho⟩ => ⟨⟨by rw [hv]; exact g, by rw [hv]⟩, ho⟩

theorem pre {α : Type} {G G' : Core -> Prop} {H : α -> Core -> Prop} {x : M α}
    (h : GT env G' H x) (imp : forall c, G c -> G' c)
    : GT env G H x :=
  fun o0 => Hoare.pre (h o0) fun _ _ ⟨g, ho⟩ => ⟨imp _ g, ho⟩

theorem post {α : Type} {G : Core -> Prop} {H H' : α -> Core -> Prop} {x : M α}
    (h : GT env G H x) (imp : forall a c, H a c -> H' a c)
    : GT env G H' x :=
  fun o0 => Hoare.post (h o0) fun _ _ _ ⟨g, ho⟩ => ⟨imp _ _ g, ho⟩

theorem ite {α : Type} {G : Core -> Prop} {H : α -> Core -> Prop} {b : Prop} [Decidable b]
    {x y : M α} (hx : b -> GT env G H x) (hy : Not b -> GT env G H y)
    : GT env G H (if b then x else y) := by
  by_cases h : b
  · simpa [h] using hx h
  · simpa [h] using hy h

end GT

theorem ginv_execTail {env : Env} {p : Par} {i : Nat} (lim : Nat) (hlim : lim = p.lim)
    : GT env (GN p i) (fun _ => GN p i) (commitIfPossible lim) := by
  subst hlim
  intro o0
  exact Hoare.post (Hoare.pre (hoare_cip (n := i) o0) fun _ _ ⟨⟨g, hn⟩, ho⟩ => ⟨g, hn, ho⟩)
    fun _ _ _ ⟨g, hn, _, ho⟩ => ⟨⟨g, hn⟩, ho⟩

/-- Between setting `lastIdx := i` and pushing entry `i`. -/
def Mid (p : Par) (i : Nat) (c : Core) : Prop :=
  c.lastIdx = i /\ Good p { c with lastIdx := i - 1 }

theorem Mid.nl {p : Par} {i : Nat} : forall c, Mid p i c -> c.leadership ≠ .leader :=
  fun _ g => g.2.nl

/-- After pushing entry `i`, before recording it as committable. -/
def Pushed (p : Par) (i : Nat) (e : Exec.Entry) (c : Core) : Prop :=
  c.lastIdx = i
  /\ Good p { c with committable := c.committable ++ (if e.sig then [i] else []) }

theorem Pushed.nl {p : Par} {i : Nat} {e : Exec.Entry}
    : forall c, Pushed p i e c -> c.leadership ≠ .leader :=
  fun _ g => g.2.nl

theorem gt_exec {env : Env} {p : Par} (from_ : NodeId) (r : AppendEntriesRequest)
    {i : Nat} {e : Exec.Entry} (s : Option Unit × Unit) (hi : p.lx[i - 1]? = some e)
    (h1 : 1 <= i) (hv1 : r.term <= p.view) (hv2 : e.term <= p.view)
    (hlim : min r.primaryCommit (aeIdx r) = p.lim)
    : GT env (GN p (i - 1)) (fun st c => st = .yield (none, ()) /\ GN p i c)
        (execBody from_ r (i, e, true) s) := by
  unfold execBody
  refine GT.bind (GT.of_ginv (GInv.keeps (Spec.trace _))) fun _ => ?_
  refine GT.bind (GT.of_ginv (GInv.keeps (Spec.emitStr _ _))) fun _ => ?_
  refine GT.ite (fun _ => ?_) (fun h => absurd rfl h)
  refine GT.bind (H := fun _ => Mid p i) (GT.setV fun v g => ?_) fun _ => ?_
  · obtain ⟨g, hn⟩ := g
    refine ⟨rfl, ?_⟩
    have hc : { core { v with lastIdx := i } with lastIdx := i - 1 } = core v := by
      simp only [core] at hn ⊢
      rw [hn]
    rw [hc]
    exact g
  refine GT.bind (GT.of_ginv (GInv.forIn_list _ _ fun _ _ _ =>
    GInv.bind (GInv.keeps (Spec.trace _)) fun _ =>
    GInv.bind (GInv.keeps (Spec.emitNat _ _)) fun _ =>
    GInv.bind (GInv.keeps (Spec.emitStr _ _)) fun _ => GInv.pure _)) fun _ => ?_
  extract_lets j1 j2 j3 j4
  have k1 : forall u, GT env (GN p i) (fun (st : ForInStep (Option Unit × Unit)) c =>
      st = .yield (none, ()) /\ GN p i c) (j1 u) := fun _ =>
    GT.bind (ginv_execTail _ hlim) fun _ => GT.pure _ fun _ g => ⟨rfl, g⟩
  have k2 : e.sig = true -> forall u, GT env (Pushed p i e) (fun st c =>
      st = .yield (none, ()) /\ GN p i c) (j2 u) := fun hs _ => by
    refine GT.bind (H := fun _ => GN p i) (GT.setV fun v g => ?_) fun _ => ?_
    · obtain ⟨hl, g⟩ := g
      simp only [hs, ite_true] at g
      exact ⟨g, hl⟩
    · refine GT.ite (fun _ => GT.ite (fun _ => GT.bind (GT.of_ginv (ginv_viewUpdate _ _ hv1)) k1)
        (fun _ => GT.bind (GT.of_ginv (ginv_viewUpdate _ _ hv2)) k1))
        (fun _ => GT.pure _ fun _ g => ⟨rfl, g⟩)
  have k3 : forall u, GT env (Mid p i) (fun st c =>
      st = .yield (none, ()) /\ GN p i c) (j3 u) := fun _ => by
    refine GT.bind (H := fun _ => Pushed p i e) (GT.setV fun v g => ?_) fun _ => ?_
    · exact ⟨g.1, good_push hi h1 g.2 g.1⟩
    · refine GT.ite (fun hs => GT.getV_bind fun _ _ => GT.pre (G' := Pushed p i e) ?_ fun _ g => g.1)
        (fun hs => GT.pure _ fun c g => ⟨rfl, ?_, g.1⟩)
      · exact GT.ite (fun _ => GT.bind (GT.of_ginv (GInv.of_frame Pushed.nl
          (frame_becomeRetired _ _ _ (by decide)))) (k2 hs)) (fun _ => k2 hs ())
      · have g := g.2
        simp only [hs, Bool.false_eq_true, ite_false, List.append_nil] at g
        exact g
  have k4 : forall u, GT env (Mid p i) (fun st c =>
      st = .yield (none, ()) /\ GN p i c) (j4 u) := fun _ =>
    GT.ite (fun _ => GT.bind (GT.of_ginv (GInv.of_frame Mid.nl (frame_startTicking _))) k3)
      (fun _ => k3 ())
  split
  · exact GT.bind (GT.of_ginv (GInv.of_frame Mid.nl (frame_addConfiguration _ _ _))) fun _ => k4 ()
  · exact k4 ()

theorem ginv_viewUpdate' {env : Env} {p : Par} {n m : Nat} (idx t : Nat)
    (ht : t <= p.view)
    : GInv env (fun c => GN p n c /\ c.commitIdx = m) (viewUpdate idx t) := by
  unfold viewUpdate
  refine GInv.getV_bind fun _ _ => ?_
  extract_lets jp
  have hs : GInv env (fun c => GN p n c /\ c.commitIdx = m) (setV fun v : State =>
      { v with views := v.views ++ Array.replicate (t - v.views.size) idx }) := by
    refine GInv.setV fun v ⟨g, hm⟩ => ⟨⟨{ g.1 with views := ?_ }, g.2⟩, hm⟩
    have := g.1.views
    simp only [core, Array.size_append, Array.size_replicate] at this ⊢
    omega
  apply GInv.ite
  · intro _; exact GInv.bind (GInv.keeps Spec.curLoc) fun _ => GInv.bind (GInv.fail _) fun _ => hs
  · intro _; exact hs

theorem hoare_sendAer {env : Env} {P : State -> Outbox -> Prop}
    {Q : Unit -> State -> Outbox -> Prop} (to : NodeId) (term idx : Nat) (ok : Bool)
    (imp
      : forall v o,
          P v o
          -> Q () v
              (o
                ++ [CCF.Envelope.mk (env.names.id v.nodeId) (env.names.id to)
                      (.appendEntriesResponse
                        { term := term, success := ok, lastLogIndex := idx })]))
    : Hoare env P (sendAer to term idx ok) Q := by
  unfold sendAer
  refine Hoare.bind (Hoare.keeps (Spec.trace _) fun _ _ _ p => p) fun _ => ?_
  refine Hoare.bind (Hoare.keeps (Spec.emit _ _) fun _ _ _ p => p) fun _ => ?_
  refine Hoare.bind (Hoare.keeps (Spec.emitStr _ _) fun _ _ _ p => p) fun _ => ?_
  exact Hoare.send _ _ imp

/-- The ACK the accept path sends. -/
def ack (env : Env) (from_ : NodeId) (r : AppendEntriesRequest) (v : State) : Outbox :=
  [CCF.Envelope.mk (env.names.id v.nodeId) (env.names.id from_)
    (.appendEntriesResponse
      { term := v.currentView, success := true, lastLogIndex := aeIdx r })]

theorem hoare_finish {env : Env} {p : Par} (from_ : NodeId) (r : AppendEntriesRequest)
    (hv1 : r.term <= p.view) (hv2 : aeTermOfIdx r <= p.view)
    (hlim : min r.primaryCommit (aeIdx r) = p.lim)
    : Hoare env (fun v o => GN p p.lx.length (core v) /\ o = []) (aeFinish from_ r)
        (fun _ v o =>
          GN p p.lx.length (core v) /\ v.commitIdx = p.bd /\ o = ack env from_ r v) := by
  unfold aeFinish
  rw [hlim]
  refine Hoare.bind (R := fun _ v o => (GN p p.lx.length (core v) /\ v.commitIdx = p.bd)
    /\ o = []) (Hoare.post (Hoare.pre (hoare_cip (n := p.lx.length) [])
      fun _ _ ⟨⟨g, hn⟩, ho⟩ => ⟨g, hn, ho⟩)
    fun _ _ _ ⟨g, hn, hb, ho⟩ => ⟨⟨⟨g, hn⟩, hb rfl⟩, ho⟩) fun _ => ?_
  refine Hoare.getV_bind fun _ => Hoare.pre (P' := fun v o =>
    (GN p p.lx.length (core v) /\ v.commitIdx = p.bd) /\ o = []) ?_ fun _ _ h => h.1
  extract_lets lci jp
  have k : forall u, Hoare env (fun v o =>
      (GN p p.lx.length (core v) /\ v.commitIdx = p.bd) /\ o = []) (jp u)
      (fun _ v o => GN p p.lx.length (core v) /\ v.commitIdx = p.bd
        /\ o = ack env from_ r v) := fun _ =>
    Hoare.getV_bind fun _ => hoare_sendAer _ _ _ _ fun v o ⟨⟨⟨g, hb⟩, ho⟩, hv⟩ => by
      subst hv ho
      exact ⟨g, hb, rfl⟩
  refine Hoare.ite (fun _ => Hoare.bind (ginv_viewUpdate' _ _ hv1 []) k)
    (fun _ => Hoare.ite (fun _ => Hoare.bind (ginv_viewUpdate' _ _ hv2 []) k) fun _ => k ())

/-- The execute loop's work list: entries `n0 + 1 ..` of the final ledger, all accepted. -/
def Work (p : Par) (n0 : Nat) (l : List (Nat × Exec.Entry × Bool)) : Prop :=
  forall k (hk : k < l.length),
    l[k].1 = n0 + k + 1
    /\ p.lx[n0 + k]? = some l[k].2.1
    /\ l[k].2.2 = true
    /\ l[k].2.1.term <= p.view

theorem gt_execLoop {env : Env} {p : Par} (from_ : NodeId) (r : AppendEntriesRequest)
    (n0 : Nat) (l : List (Nat × Exec.Entry × Bool)) (hl : Work p n0 l)
    (hv1 : r.term <= p.view) (hlim : min r.primaryCommit (aeIdx r) = p.lim)
    : GT env (GN p n0) (fun t c => t.fst = none /\ GN p (n0 + l.length) c)
        (forIn l (none, ()) (execBody from_ r)) := by
  intro o0
  refine Hoare.pre
    (Hoare.forIn_list l (none, ()) _
      (fun pre b v o => b = (none, ()) /\ GN p (n0 + pre.length) (core v) /\ o = o0)
      (fun t v o => (t.fst = none /\ GN p (n0 + l.length) (core v)) /\ o = o0) ?_ ?_)
    fun _ _ ⟨g, ho⟩ => ⟨rfl, by simpa using g, ho⟩
  · intro pre a rest b he
    have hk : pre.length < l.length := by rw [he]; simp
    have ha : l[pre.length] = a := by simp [he]
    obtain ⟨h1, h2, h3, h4⟩ := hl _ hk
    rw [ha] at h1 h2 h3 h4
    obtain ⟨i, e, ok⟩ := a
    simp only at h1 h2 h3 h4
    subst h1 h3
    refine Hoare.pin fun v0 o1 ⟨hb, g, ho⟩ => ?_
    subst hb ho
    refine Hoare.post (Hoare.pre (gt_exec (env := env) (i := n0 + pre.length + 1) from_ r
      (none, ()) (by simpa using h2) (by omega) hv1 h4 hlim o1) ?_) ?_
    · rintro _ _ ⟨rfl, rfl⟩
      exact ⟨by simpa using g, rfl⟩
    · rintro st v o ⟨⟨rfl, g⟩, ho⟩
      refine ⟨rfl, ?_, ho⟩
      simpa [Nat.add_assoc] using g
  · rintro b v o ⟨rfl, g, ho⟩
    exact ⟨⟨rfl, g⟩, ho⟩

end Consensus.TraceValidation.Proofs.Ae
