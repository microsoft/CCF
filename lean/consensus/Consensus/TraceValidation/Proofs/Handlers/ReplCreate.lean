module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import Consensus.TraceValidation.Proofs.Handlers.ReplPeerSend
public import Consensus.TraceValidation.Proofs.Handlers.ReplFlush

@[expose] public section

/-!
# `create_and_remove_node_state` on a leader (not reviewed; `Replicate` obligation)

On a leader whose ledger satisfies `ViewHyps`, `create_and_remove_node_state` gives each node
of its configurations that is neither itself nor a peer a peer state at the end of the ledger,
unmatched, and sends it one empty AppendEntries from one past the ledger, in node id order.
-/

namespace Consensus.TraceValidation.Proofs.Repl

open Consensus.Model.Node
open Consensus.TraceValidation.Exec
open Consensus.TraceValidation.Proofs.Life

variable {env : Env}

/-- A loop over `l` that always continues, with an invariant indexed by the visited prefix. -/
theorem forIn_prefix {α : Type} {l : List α} {f : α -> PUnit -> M (ForInStep PUnit)}
    {I : List α -> State -> Outbox -> Prop}
    (h
      : forall pre a rest,
          pre ++ a :: rest = l
          -> Tri env (I pre) (f a PUnit.unit)
              fun r v o => r = .yield PUnit.unit /\ I (pre ++ [a]) v o)
    : Tri env (I []) (forIn l PUnit.unit f) fun _ => I l := by
  suffices gen : forall rest pre, pre ++ rest = l
      -> Tri env (I pre) (forIn rest PUnit.unit f) fun _ => I l from gen l [] rfl
  intro rest
  induction rest with
  | nil =>
      intro pre e
      rw [List.append_nil] at e
      subst e
      rw [List.forIn_nil]
      exact Tri.pure' (Q := fun _ => I pre) _
  | cons a rest ih =>
      intro pre e
      rw [List.forIn_cons]
      refine Tri.bind (h pre a rest e) fun r => ?_
      refine tri_fact (φ := r = .yield PUnit.unit) (fun _ _ p => p.1) fun yr => ?_
      subst yr
      exact Tri.conseq (ih (pre ++ [a]) (by rw [List.append_assoc]; exact e))
        (fun _ _ p => p.2) fun _ _ _ q => q

/-- The empty AppendEntries a new peer gets from one past the ledger. -/
def hb (env : Env) (w : State) (id : NodeId) : CCF.Envelope NodeID Message :=
  ⟨
    env.names.id w.nodeId,
    env.names.id id,
    .appendEntriesRequest (rangeRequest env.names w (w.lastIdx + 1) w.lastIdx)
  ⟩

/-- The nodes of `ids` that are neither the node nor its peers. -/
def newOf (w : State) (ids : List NodeId) : List NodeId :=
  ids.filter fun id => id != w.nodeId && (w.peer? id).isNone

/-- `ps` holds `w`'s peers and, for each node of `new`, an unmatched peer at the ledger's end. -/
def Added (w : State) (new : List NodeId) (ps : List (NodeId × Peer)) : Prop :=
  (ps.map Prod.fst).Nodup
  /\ forall k,
      ps.lookup k
      = if k ∈ new then some { sentIdx := w.lastIdx, matchIdx := 0 } else w.peer? k

/-- What `create_and_remove_node_state` leaves after visiting `pre` of the node ids. -/
def CarInv (env : Env) (w : State) (o0 : Outbox) (pre : List NodeId) (v : State)
    (o : Outbox)
    : Prop :=
  exists ps,
    v = { w with allOtherNodes := ps }
    /\ Added w (newOf w pre) ps
    /\ o = o0 ++ (newOf w pre).map (hb env w)

theorem newOf_snoc (w : State) (pre : List NodeId) (id : NodeId)
    : newOf w (pre ++ [id])
      = newOf w pre ++ (if id != w.nodeId && (w.peer? id).isNone then [id] else []) := by
  simp only [newOf, List.filter_append, List.filter_cons, List.filter_nil]

theorem mem_newOf {w : State} {pre : List NodeId} {k : NodeId}
    : k ∈ newOf w pre <-> k ∈ pre /\ k ≠ w.nodeId /\ w.peer? k = none := by
  simp [newOf]

theorem car_spec {w : State} (lead : w.leadership = .leader) (vh : ViewHyps w)
    (rc : w.isRetiredCommitted = false) (nd : (w.allOtherNodes.map Prod.fst).Nodup)
    {o0 : Outbox}
    : Tri env (fun v o => v = w /\ o = o0) createAndRemoveNodeState
        fun _ =>
          CarInv env w o0
            ((w.configurations.flatMap (·.nodes.map Prod.fst)).mergeSort (· <= ·)
              |>.eraseDups) := by
  unfold createAndRemoveNodeState
  refine Tri.getV_bind fun v => ?_
  refine tri_fact (φ := v = w) (fun _ _ p => p.2.symm.trans p.1.1) fun e => ?_
  subst e
  dsimp only
  have sd := sortDedup_spec (v.configurations.flatMap (·.nodes.map Prod.fst))
  refine Tri.bind
    (Tri.conseq (forIn_prefix (I := CarInv env v o0) fun pre id rest e => ?_)
      (fun v' o p => ?_) fun _ _ _ q => q)
    fun _ => Tri.pure' (Q := fun _ => _) _
  · have ndl : (pre ++ id :: rest).Nodup := by rw [e]; exact sd.1.imp fun h e => by subst e; exact String.lt_irrefl _ h
    have notPre : id ∉ pre := fun m => (List.nodup_append.mp ndl).2.2 id m id
      (List.mem_cons_self ..) rfl
    refine Tri.ite (fun self => ?_) (fun notSelf => ?_)
    · refine Tri.conseq (Tri.pure' (Q := fun r w o => r = .yield PUnit.unit
        /\ CarInv env v o0 (pre ++ [id]) w o) _) (fun v' o p => ⟨rfl, ?_⟩) fun _ _ _ q => q
      have : (id != v.nodeId && (v.peer? id).isNone) = false := by
        simp only [beq_iff_eq] at self; simp [self]
      unfold CarInv
      rw [newOf_snoc, this]
      simp only [Bool.false_eq_true, ite_false, List.append_nil]
      exact p
    · refine Tri.getV_bind fun u => ?_
      refine tri_pin fun u' o' hp => ?_
      obtain ⟨⟨ps, e1, ⟨ndps, lk⟩, e2⟩, e3⟩ := hp
      subst e3 e1 e2
      have look : ({ v with allOtherNodes := ps } : State).peer? id = v.peer? id := by
        show ps.lookup id = _
        rw [lk]
        simp [mem_newOf, notPre]
      simp only [look]
      cases hv : v.peer? id with
      | some q =>
          simp only [Option.isNone_some, Bool.false_eq_true, ite_false]
          refine Tri.conseq
            (Tri.pure'
              (Q :=
                fun r w o => r = .yield PUnit.unit /\ CarInv env v o0 (pre ++ [id]) w o)
              _)
            (fun v' o p => ⟨rfl, ?_⟩) fun _ _ _ q => q
          have : (id != v.nodeId && (v.peer? id).isNone) = false := by simp [hv]
          obtain ⟨rfl, rfl⟩ := p
          unfold CarInv
          rw [newOf_snoc, this]
          simp only [Bool.false_eq_true, ite_false, List.append_nil]
          exact ⟨ps, rfl, ⟨ndps, lk⟩, trivial⟩
      | none =>
          simp only [Option.isNone_none, ite_true]
          have new : (id != v.nodeId && (v.peer? id).isNone) = true := by
            simp only [beq_iff_eq] at notSelf; simp [notSelf, hv]
          let p : Peer := { sentIdx := v.lastIdx + 1, matchIdx := 0 }
          let u1 := ({ v with allOtherNodes := ps } : State).setPeer id p
          have nd1 : (u1.allOtherNodes.map Prod.fst).Nodup := setPeer_nodup ndps id p
          refine Tri.bind
            (Q := fun _ w o => w = u1 /\ o = o0 ++ (newOf v pre).map (hb env v))
            (Tri.setV fun _ _ p => by rw [p.1]; exact ⟨rfl, p.2⟩) fun _ => ?_
          have lead' : (({ v with allOtherNodes := ps } : State).leadership == .leader) = true := by
            simp [lead]
          simp only [lead', ↓reduceIte]
          refine Tri.bind
            (heartbeat_tri (v0 := u1) (p := p) (viewHyps_withPeers vh _) rc
              (by rw [setPeer_lookup ndps]; simp))
            fun _ => ?_
          refine Tri.conseq
            (Tri.pure'
              (Q :=
                fun r w o => r = .yield PUnit.unit /\ CarInv env v o0 (pre ++ [id]) w o)
              _)
            (fun v' o h => ⟨rfl, ?_⟩) fun _ _ _ q => q
          obtain ⟨rfl, rfl⟩ := h
          unfold CarInv
          rw [newOf_snoc, new]
          refine ⟨_, rfl, ⟨setPeer_nodup nd1 id _, fun k => ?_⟩, ?_⟩
          · show (u1.setPeer id _).peer? k = _
            rw [setPeer_lookup nd1]
            show _ = if k ∈ newOf v pre ++ [id] then _ else _
            by_cases hk : k = id
            · subst hk
              simp only [ite_true, List.mem_append, List.mem_singleton, or_true]
              rfl
            · simp only [hk, ↓reduceIte]
              rw [setPeer_lookup ndps]
              simp only [hk, ↓reduceIte]
              show ps.lookup k = _
              rw [lk]
              simp [hk]
          · simp only [List.map_append, List.append_assoc]
            rfl
  · obtain ⟨⟨rfl, rfl⟩, -⟩ := p
    refine ⟨v'.allOtherNodes, rfl, ⟨nd, fun k => ?_⟩, by simp [newOf]⟩
    simp [newOf, State.peer?]

end Consensus.TraceValidation.Proofs.Repl
