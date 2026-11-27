module

public import DisasterRecovery.Proofs.Transactions

import all Init.Control.State

@[expose] public section

namespace DisasterRecovery.Proofs.Transactions

open CCF OCC Model.Local

/-- Each queued attempt was produced by its own program on a snapshot. -/
def Authentic (config : Config) (a : Attempt) : Prop :=
  ∃ snap : Store,
    (transaction config a.event).exec snap
    = {normal := a.normal, outputs := a.outputs, result := .ok ()}

/-- The local store and pending queue invariants. -/
def WellFormed (config : Config) (s : NodeState) : Prop :=
  (s.store.map Prod.fst).Nodup ∧ ∀ a ∈ s.pending, Authentic config a

private theorem start_preserves {node : Location} {config : Config}
    {before after : NodeState} {e : Event}
    {outputs : Outputs Location Message Notification} (h : WellFormed config before)
    (run
      : (start (Capabilities.record node) config before e).run {} = some (after,outputs))
    : WellFormed config after := by
  let ran := (transaction config e).exec before.store
  cases hr : ((transaction config e).exec before.store).result with
  | error reason =>
      simp only [start, hr] at run
      exact (show before = after from congrArg Prod.fst (Option.some.inj run)) ▸ h
  | ok u =>
      cases u
      simp only [start, hr] at run
      have eq := congrArg Prod.fst (Option.some.inj run)
      change {before with pending := before.pending ++ [⟨e, ran.normal, ran.outputs⟩]} = after at eq
      subst after
      refine ⟨h.1, ?_⟩
      intro a mem
      rcases List.mem_append.mp mem with old | new
      · exact h.2 _ old
      · obtain rfl := List.mem_singleton.mp new
        refine ⟨before.store, ?_⟩
        change ran = ⟨ran.normal,ran.outputs,.ok ()⟩
        change ran.result = _ at hr
        generalize ran = r at hr ⊢
        cases r; congr

private theorem perform_preserves {node : Location} {config : Config} {tx : TxID}
    {before after : NodeState} {op : Operation}
    {out : Outputs Location Message Notification} (h : WellFormed config before)
    (run
      : (perform (Capabilities.record node) config tx before op).run {}
        = some (after,out))
    : WellFormed config after := by
  cases op with
  | run e => cases e <;> first | exact start_preserves h run | contradiction
  | retry =>
      simp only [perform] at run
      split at run
      · contradiction
      · change ((release _ _).run {}).bind _ = _ at run
        rw [Evaluation.release_record] at run
        exact (show before = after from congrArg Prod.fst (Option.some.inj run)) ▸ h
  | commit i =>
      simp only [perform] at run
      cases ha : before.pending[i]? with
      | none => rw [ha] at run; contradiction
      | some a =>
          simp only [ha] at run
          let rest := {before with pending := before.pending.eraseIdx i}
          have wf : WellFormed config rest := ⟨h.1,fun a mem =>
            h.2 a (List.eraseIdx_subset mem)⟩
          split at run
          · change ((release _ a.outputs).run {}).bind _ = _ at run
            rw [Evaluation.release_record] at run
            exact (show rest = after from congrArg Prod.fst (Option.some.inj run)) ▸ wf
          · split at run
            · change ((release _ a.outputs).run {}).bind _ = _ at run
              rw [Evaluation.release_record] at run
              have eq := congrArg Prod.fst (Option.some.inj run)
              dsimp only at eq
              subst after
              exact ⟨publish_unique _ _ _ wf.1, wf.2⟩
            · exact start_preserves wf run

/-- Neither overlapping runs nor conflict retries can introduce duplicate addresses or
fabricated pending attempts. -/
theorem reachable_wellFormed (config : Model.Config) (s : Model.State)
    (reachable : (Model.transitionSystem config).Reachable s)
    : ∀ entry ∈ s.nodes, WellFormed config.protocol entry.2 := by
  induction reachable
    using @TransitionSystem.Reachable.rec (Model.transitionSystem config) with
  | initial init =>
      intro entry mem
      have hi : entry.2 = initialNode entry.1 := init.2.2.2.2 entry mem
      rw [hi]
      exact ⟨by change (initialStore.map Prod.fst).Nodup; decide, by simp [initialNode]⟩
  | @step before after act _ step ih =>
      have next (n : Location) (op : Operation) (net : List Model.Envelope)
          (step : (do
            let st ← MultiNodeTransitionSystem.nodeState before n
            let (st',o) ← ((Model.protocol config).step (Capabilities.record n) n st op).run {}
            return { nodes := before.nodes.map (fun p => if p.1 == n then (n,st') else p)
                     network := net ++ o.outgoing : Model.State }) = some after) :
          ∀ entry ∈ after.nodes, WellFormed config.protocol entry.2 := by
        obtain ⟨st,lookup,step⟩ := Option.bind_eq_some_iff.mp step
        obtain ⟨⟨st',o⟩,run,step⟩ := Option.bind_eq_some_iff.mp step
        cases Option.some.inj step
        obtain ⟨entry,found,value⟩ := Option.map_eq_some_iff.mp lookup
        have h : WellFormed config.protocol st :=
          value ▸ ih entry (List.mem_of_find?_eq_some found)
        cases tx : Model.recoveredTxID config n with
        | none => simp only [Model.protocol,tx] at run; contradiction
        | some t =>
            simp only [Model.protocol,tx] at run
            have updated := perform_preserves h (tx := t) (op := op) (node := n) run
            intro p mem
            obtain ⟨x,hx,rfl⟩ := List.mem_map.mp mem
            split <;> first | exact updated | exact ih _ hx
      cases act with
      | «local» n input => exact next n _ _ step
      | deliver env =>
          simp only [MultiNodeTransitionSystem.next] at step
          obtain ⟨_,_,step⟩ := Option.bind_eq_some_iff.mp step
          exact next env.target _ _ step

end DisasterRecovery.Proofs.Transactions
