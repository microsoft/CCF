module

public import DisasterRecovery.Proofs.Representation
public import DisasterRecovery.Proofs.Reachable

import all Init.Control.State

@[expose] public section

namespace DisasterRecovery.Proofs.Atomic

open CCF OCC
open Model.Local (Tx Table Value Output)

private abbrev Result := Except String (Unit × Rows × List Output)
private abbrev Effects := Outputs Location Message Notification

/-- Relates a transaction body executed without versions to the atomic transition. -/
def Agrees (source : Location) (loc : Location)
    (real : Except String (Unit × Rows × List Output))
    (spec : Option (NodeState × Outputs Location Message Notification))
    : Prop :=
  match real with
  | .error _ => spec = none
  | .ok (_,ys,outs) =>
      ∃ s,
        Represents ys s
        ∧ s.location = loc
        ∧ spec = some (s,Evaluation.recordOutputs source {} outs)

private theorem readPhase_bind {α : Type} {xs : Rows} {s : NodeState}
    (r : Represents xs s) (outs : List Output) (f : Phase → Tx α)
    : ((Model.Local.readPhase .phase >>= f).serial xs outs)
      = (f s.phase).serial xs outs := by
  simp [Model.Local.readPhase,Program.read,Bind.bind,Program.bind,Program.serial,
    r.read, rows,find,Pure.pure]

private theorem readLane_bind {α : Type} {xs : Rows} {s : NodeState} (r : Represents xs s)
    (outs : List Output) (f : Phase → Tx α)
    : ((Model.Local.readPhase .timeoutPhase >>= f).serial xs outs)
      = (f s.timeoutState).serial xs outs := by
  simp [Model.Local.readPhase,Program.read,Bind.bind,Program.bind,Program.serial,
    r.read,rows,find,Pure.pure]

private theorem readChosen_bind {α : Type} {xs : Rows} {s : NodeState}
    (r : Represents xs s) (outs : List Output) (f : Option Location → Tx α)
    : ((Model.Local.readChosen >>= f).serial xs outs) = (f s.chosen).serial xs outs := by
  cases h : s.chosen <;> simp [Model.Local.readChosen,Program.read,Bind.bind,Program.bind,
    Program.serial,r.read,rows,find,h,Pure.pure]

private def laneProgram (lane : Phase) (timeout advanced : Bool) : Tx Unit := do
  if timeout && advanced then
    match lane with
    | .gossiping => Model.Local.writePhase .timeoutPhase .voting
    | .voting => Model.Local.writePhase .timeoutPhase .opening
    | _ => pure ()

private theorem lane_result {xs : Rows} {s : NodeState} (r : Represents xs s)
    (node : Location) (timeout : Bool) (outs : List Output)
    : Agrees node s.location ((laneProgram s.timeoutState timeout true).serial xs outs)
        (some (advanceTimeoutLane s timeout,Evaluation.recordOutputs node {} outs)) := by
  cases timeout <;> cases h : s.timeoutState <;>
    simp [Agrees,laneProgram,Model.Local.writePhase,Program.write,Pure.pure,Program.serial,
      advanceTimeoutLane,advanceTimeoutState,h] <;>
    first | exact r | apply r.lane | rw [← h]; exact r

private theorem advance_agrees (config : Config) (timeout : Bool) (node : Location)
    {xs : Rows} {s : NodeState} (r : Represents xs s)
    : Agrees node s.location ((Model.Local.advance config timeout).serial xs [])
        ((advance (Capabilities.record node) config s timeout).run {}) := by
  unfold Model.Local.advance
  rw [readPhase_bind r,readLane_bind r]
  let aligned := timeout && s.phase == s.timeoutState
  have valid : validTimeout s timeout = aligned := by
    by_cases eq : s.phase = s.timeoutState <;> simp [validTimeout,aligned,eq]
  cases ph : s.phase with
  | gossiping =>
      simp only [advance,valid,aligned,ph,Program.entries,Bind.bind,Program.bind,Program.serial,r.scanGossips]
      split
      · cases h : maximumGossip s.gossips with
        | none => show (none : Option (NodeState × Effects)) = none; rfl
        | some best =>
            obtain ⟨chosen, txid⟩ := best
            exact lane_result ((r.chosen chosen).phase .voting) node timeout []
      · exact lane_result r node timeout []
  | voting =>
      simp only [advance,valid,aligned,ph,Program.entries,Bind.bind,Program.bind,Program.serial,r.scanVotes]
      split
      · split
        · cases timeout <;> exact ⟨s,r,rfl,rfl⟩
        · let kind : OpenKind :=
            if timeout
                && (.voting : Phase) == s.timeoutState
                && !decide (s.votes.length >= voteQuorum config) then
              .failover
            else
              .quorum
          exact lane_result ((r.kind kind).phase .opening) node timeout
            [.notify (.opening kind)]
      · exact lane_result r node timeout []
  | joining =>
      rw [readChosen_bind r]
      cases h : s.chosen with
      | none =>
          simp only [advance,ph,h]; show (none : Option (NodeState × Effects)) = none; rfl
      | some chosen =>
          simp only [advance,ph,h]
          exact lane_result r node timeout [.notify (.restart chosen)]
  | opening =>
      simp only [advance,valid,aligned,ph]
      split
      · exact lane_result (r.phase .open) node timeout [.notify .completed]
      · exact lane_result r node timeout []
  | «open» =>
      simp only [advance,ph]
      exact lane_result r node timeout []

/-- A rejected transaction can be disabled in the atomic specification, or return
the unchanged state and one rejection. Successful bodies agree exactly. -/
def EventAgrees (source : Location) (before : NodeState)
    (real : Except String (Unit × Rows × List Output))
    (spec : Option (NodeState × Outputs Location Message Notification))
    : Prop :=
  match real with
  | .error _ =>
      spec = none ∨ ∃ reason, spec = some (before,{notifications := [.rejected reason]})
  | .ok (_,ys,outs) =>
      ∃ s,
        Represents ys s
        ∧ s.location = before.location
        ∧ spec = some (s,Evaluation.recordOutputs source {} outs)

private theorem orReject {node : Location} {before : NodeState} {real : Result}
    {spec : Option (NodeState × Effects)} (reason : String)
    (h : Agrees node before.location real spec)
    : EventAgrees node before real
        (spec <|> some (before,{notifications := [.rejected reason]})) := by
  cases real with
  | error e => exact Or.inr ⟨reason,by rw [show spec = none from h]; rfl⟩
  | ok v =>
      obtain ⟨u,ys,outs⟩ := v
      obtain ⟨s,r,loc,eq⟩ := h
      exact ⟨s,r,loc,by rw [eq]; rfl⟩

private theorem applyAdvance (c : Config) (node : Location) (s : NodeState) (xs : Rows)
    (s' : NodeState) (r : Represents xs s') (loc : s'.location = s.location)
    (reason : String)
    : EventAgrees node s ((Model.Local.advance c false).serial xs [])
        ((advance (Capabilities.record node) c s' false
          <|> rejected (Capabilities.record node) s reason).run
          {}) := by
  exact orReject reason (loc ▸ advance_agrees c false node r)

/-- Serialize any receive or timeout, preserving its committed state and outputs. -/
theorem event_agrees (c : Config) (node : Location) (tx : TxID) (s : NodeState)
    (xs : Rows) (r : Represents xs s) (e : Event) (ne : e ≠ .retry)
    : EventAgrees node s ((Model.Local.transaction c e).serial xs [])
        ((step (Capabilities.record node) c tx s e).run {}) := by
  cases e with
  | retry => contradiction
  | timeout =>
      have h := advance_agrees c true node r
      change EventAgrees node s ((Model.Local.advance c true).serial xs []) _
      cases eq : (Model.Local.advance c true).serial xs [] with
      | error _ => rw [eq] at h; exact Or.inl h
      | ok v => rw [eq] at h; exact h
  | receiveVote src v =>
      cases v with
      | rejected => exact Or.inr ⟨_,rfl⟩
      | accepted => exact applyAdvance c node s _ _ (r.vote src) rfl _
  | receiveIAmOpen src v =>
      cases v with
      | rejected => exact Or.inr ⟨_,rfl⟩
      | accepted =>
          simp only [Model.Local.transaction,readPhase_bind r,step]
          cases s.phase <;> first | exact Or.inr ⟨_,rfl⟩ |
            exact applyAdvance c node s _ _ ((r.phase .joining).chosen src) rfl _
  | receiveGossip src txid v =>
      cases v with
      | rejected => exact Or.inr ⟨_,rfl⟩
      | accepted =>
          simp only [Model.Local.transaction,readChosen_bind r,step]
          cases hc : s.chosen with
          | some _ => exact Or.inr ⟨_,rfl⟩
          | none =>
              simp only [Option.isSome_none, Bool.false_eq_true, ↓reduceIte, Program.read, Bind.bind,
                Program.bind,Program.serial,r.gossipAbsent]
              cases h : s.gossips.any (·.1 == src) with
              | true =>
                  simpa [insertGossip,h,←hc] using applyAdvance c node s xs s r rfl "empty-gossip-advance"
              | false =>
                  simpa [hc,Program.write,Program.bind,Program.serial]
                    using applyAdvance c node s _ _ (r.gossip src txid h) rfl
                      "empty-gossip-advance"

private def sendAll (m : Message) (targets : List Location) : Tx Unit := do
  for t in targets do
    Program.emit (.send m t)

private theorem sendAll_serial (xs : Rows) (outs : List Output) (m : Message)
    (targets : List Location)
    : (sendAll m targets).serial xs outs = .ok ((),xs,outs ++ targets.map (.send m)) := by
  induction targets generalizing outs with
  | nil => simp [sendAll,Program.serial,Pure.pure,Bind.bind,Program.bind]
  | cons t ts ih =>
      simp only [sendAll,List.forIn_cons,Program.emit,Bind.bind,Program.bind,Pure.pure,Program.serial]
      change (sendAll m ts).serial xs (outs ++ [.send m t]) = _
      simp [ih,List.append_assoc]

private theorem broadcast_run (source : Location) (message : Message)
    (targets : List Location) (outputs : Effects)
    : (targets.foldlM
          (fun (_ : Unit) target => (Capabilities.record source).send message target) ()
        : Effect Location Message Notification Unit).run
        outputs
      = some
          ((),Evaluation.recordOutputs source outputs (targets.map (.send message))) := by
  induction targets generalizing outputs with
  | nil => rfl
  | cons target _ ih =>
      exact ih {outputs with outgoing := outputs.outgoing ++ [⟨source,target,message⟩]}

private def retryPlan (c : Config) (s : NodeState) (tx : TxID) : Option (List Output) :=
  let gossip := c.expectedLocations.map (.send (.gossip tx))
  match s.phase with
  | .gossiping => if c.expectedLocations.isEmpty then none else some gossip
  | .voting =>
      match s.chosen with
      | some n => some (.send .vote n :: gossip)
      | none => if c.expectedLocations.isEmpty then none else some gossip
  | .opening =>
      let ts := c.expectedLocations.filter (· != s.location)
      if ts.isEmpty then none else some (ts.map (.send .iAmOpen))
  | _ => none

private theorem retry_serial (c : Config) (s : NodeState) (tx : TxID) (xs : Rows)
    (r : Represents xs s)
    : (Model.Local.retry c s.location tx).serial xs []
      = match retryPlan c s tx with
        | none => .error "nothing-to-send"
        | some outs => .ok ((),xs,outs) := by
  unfold Model.Local.retry
  rw [readPhase_bind r]
  cases h : s.phase <;> simp only [retryPlan,h]
  case gossiping =>
    split
    · rfl
    · exact sendAll_serial xs [] _ _
  case voting =>
    rw [readChosen_bind r]
    cases h : s.chosen with
    | some n => exact sendAll_serial xs [.send .vote n] _ _
    | none =>
        cases h : c.expectedLocations.isEmpty <;> first | rfl | exact sendAll_serial xs [] _ _
  case opening => split <;> first | rfl | exact sendAll_serial xs [] _ _
  all_goals rfl

private theorem retry_atomic (c : Config) (node : Location) (s : NodeState) (tx : TxID)
    : ((step (Capabilities.record node) c tx s .retry).run {})
      = (retryPlan c s tx).map
          (fun outs => (s,Evaluation.recordOutputs node {} outs)) := by
  have broadcast (m : Message) (targets : List Location) (outputs : Effects) :=
    broadcast_run node m targets outputs
  cases ph : s.phase with
  | gossiping =>
      cases h : c.expectedLocations.isEmpty <;> simp [step,retryPlan,ph,h,guard,StateT.run_map,broadcast]; intro _ _ h; contradiction
  | voting =>
      cases ch : s.chosen with
      | none =>
          cases h : c.expectedLocations.isEmpty <;> simp [step,retryPlan,ph,ch,h,guard,StateT.run_map,broadcast]; intro _ _ h; contradiction
      | some n =>
          simp [step,retryPlan,ph,ch,guard,StateT.run_bind,StateT.run_map,broadcast]
          rfl
  | opening =>
      cases h : (c.expectedLocations.filter (· != s.location)).isEmpty <;>
        simp [step,retryPlan,ph,h,guard,StateT.run_map,broadcast]; intro _ _ h; contradiction
  | joining | «open» => simp [step,retryPlan,ph]; rfl

/-- Retrying the real node produces exactly the atomic retry's sends and changes
neither the store nor the queue of transactions. -/
theorem retry_agrees (c : Config) (node : Location) (tx : TxID)
    (before : Model.Local.NodeState) (s : NodeState)
    (r : Represents (values before.store) s) (loc : before.location = s.location)
    : ((Model.Local.perform (Capabilities.record node) c tx before .retry).run {})
      = (((step (Capabilities.record node) c tx s .retry).run {}).map
          (fun p => (before,p.2))) := by
  rw [retry_atomic]
  have eq := Program.serial_eq_execFrom before.store {} [] (Model.Local.retry c s.location tx)
  change _ = ((Model.Local.retry c s.location tx).exec before.store).result.map _ at eq
  change (Model.Local.retry c s.location tx).serial (values before.store) [] = _ at eq
  rw [retry_serial c s tx _ r] at eq
  simp only [Model.Local.perform,loc]
  cases plan : retryPlan c s tx <;> rw [plan] at eq <;>
    cases result : ((Model.Local.retry c s.location tx).exec before.store).result <;>
    simp [result,Except.map] at eq
  · rfl
  · change ((Model.Local.release _ _).run {}).bind _ = _
    rw [Evaluation.release_record]
    have e : ((Model.Local.retry c s.location tx).exec before.store).outputs = _ := eq.2.symm
    rw [e]
    rfl

theorem retry_state (c : Config) (node : Location) (tx : TxID) {s next : NodeState}
    {out : Outputs Location Message Notification}
    (h : ((step (Capabilities.record node) c tx s .retry).run {}) = some (next,out))
    : s = next := by
  rw [retry_atomic] at h
  obtain ⟨_,_,eq⟩ := Option.map_eq_some_iff.mp h
  exact congrArg Prod.fst eq

/-- The successful commit of an authentic, validated attempt corresponds to one
atomic handler, even if the snapshot's scans enumerated cells in a different order. -/
theorem commit_agrees (c : Model.Config) (node : Location) (tx : TxID)
    (before : Model.Local.NodeState) (s : NodeState)
    (r : Represents (values before.store) s) (i : Nat) (a : Model.Local.Attempt)
    (commit : Properties.Commits c before i a) (ne : a.event ≠ .retry)
    : ∃ next,
        Represents (values (publish before.store (before.version + 1) a.normal.writes))
          next
        ∧ next.location = s.location
        ∧ ((step (Capabilities.record node) c.protocol tx s a.event).run {})
          = some (next,Evaluation.recordOutputs node {} a.outputs) := by
  obtain ⟨_,⟨snap,ran⟩,valid⟩ := commit
  have eq := Program.exec_replay snap before.store (Model.Local.transaction c.protocol a.event)
    (Transactions.transaction_respects _ _) (by simpa [ran] using valid)
  rw [ran] at eq
  obtain ⟨wr,outs,ok⟩ := Prod.mk.inj eq |>.imp_right Prod.mk.inj
  have serial := Program.serial_eq_execFrom before.store {} [] (Model.Local.transaction c.protocol a.event)
  change _ = ((Model.Local.transaction c.protocol a.event).exec before.store).result.map _ at serial
  rw [←ok] at serial
  have h := event_agrees c.protocol node tx s (values before.store) r a.event ne
  change (Model.Local.transaction c.protocol a.event).serial (values before.store) [] = _ at serial
  rw [serial] at h
  change ∃ _, Represents (overlay before.store _) _ ∧ _ ∧ _ at h
  change ∃ next, Represents (overlay (publish before.store (before.version + 1) a.normal.writes) []) next ∧ _
  change a.normal.writes = _ at wr
  change a.outputs = _ at outs
  rw [overlay_publish,wr,outs]
  exact h

end DisasterRecovery.Proofs.Atomic
