module

public import DisasterRecovery.Properties.Utils
public import DisasterRecovery.Proofs.Transactions

import all Init.Control.State

@[expose] public section

namespace DisasterRecovery.Proofs.Witnesses

open CCF
open Model.Local OCC

private theorem exists_recovered (config : Properties.ValidConfig)
    : exists node txid, Model.recoveredTxID config node = some txid := by
  cases recovered : config.val.recovered with
  | nil =>
      have valid := config.property.1
      simp [Config.isValid, ← config.property.2.2, recovered] at valid
  | cons entry rest =>
      obtain ⟨node, txid⟩ := entry
      exact ⟨node, txid, by simp [Model.recoveredTxID, recovered]⟩

private theorem commit_step (config : Properties.ValidConfig) (node : Location) (tx : TxID)
    (recovered : Model.recoveredTxID config node = some tx) (store : Store) (event : Event)
    (ok : ((transaction config.val.protocol event).exec store).result = .ok ()) :
    ∃ (s : Properties.LocalStep) (a : Attempt), (Model.protocol config).ValidStep s ∧
      s.action = .commit 0 ∧ Properties.Commits config s.before 0 a ∧
      a.event = event ∧ s.before.store = store := by
  let ran := (transaction config.val.protocol event).exec store
  let a : Attempt := ⟨event, ran.normal, ran.outputs⟩
  let before : NodeState := {location := node, store, pending := [a]}
  have valid := Program.exec_valid store (transaction config.val.protocol event)
  have hc : Properties.Commits config before 0 a := by
    refine ⟨rfl, ⟨store, ?_⟩, valid⟩
    change ran = ⟨ran.normal, ran.outputs, .ok ()⟩
    change ran.result = _ at ok
    generalize ran = r at ok ⊢
    cases r; congr
  have enabled : ∃ after effects, ((Model.protocol config).step (Capabilities.record node) node
      before (.commit 0)).run {} = some (after,effects) := by
    simp only [Model.protocol, recovered, liftM, monadLift, StateT.run, bind,
      StateT.bind, pure, perform, before,
      List.getElem?_cons_zero]
    split
    all_goals change ∃ _ _, ((release _ _).run {}).bind _ = _
    all_goals rw [Evaluation.release_record]; exact ⟨_,_,rfl⟩
  obtain ⟨after,effects,step⟩ := enabled
  exact ⟨⟨node,before,.commit 0,after,effects⟩,a,step,rfl,hc,rfl,rfl⟩


theorem gossip_freezes_after_choice_witness
    : forall (config : Properties.ValidConfig),
        exists localStep : Properties.LocalStep,
        exists (source : Location) (txid : TxID),
          (Model.protocol config).ValidStep localStep
          /\ localStep.action = .run (.receiveGossip source txid .accepted)
          /\ localStep.before.chosen.isSome = true := by
  intro config
  obtain ⟨node, txid, recovered⟩ := exists_recovered config
  let before : NodeState := {location := node, store := [((.chosen,none),⟨.location node,0⟩)]}
  refine ⟨⟨node, before, .run (.receiveGossip node txid .accepted), before,
    {notifications := [.rejected "gossip-frozen"]}⟩, node, txid, ?_, rfl, rfl⟩
  simp only [MultiNodeTransitionSystem.Protocol.ValidStep, Model.protocol, recovered]
  rfl

theorem rejected_gossip_stutters_witness
    : forall (config : Properties.ValidConfig),
        exists localStep : Properties.LocalStep,
        exists (source : Location) (txid : TxID),
          (Model.protocol config).ValidStep localStep
          /\ localStep.action = .run (.receiveGossip source txid .rejected) := by
  intro config
  obtain ⟨node, txid, recovered⟩ := exists_recovered config
  refine ⟨⟨node, initialNode node, .run (.receiveGossip node txid .rejected),
    initialNode node, {notifications := [.rejected "quote-or-certificate"]}⟩,
    node, txid, ?_, rfl⟩
  simp only [MultiNodeTransitionSystem.Protocol.ValidStep, Model.protocol, recovered]
  rfl

theorem aligned_opening_timeout_completes_witness
    : forall (config : Properties.ValidConfig),
        exists localStep : Properties.LocalStep,
        exists (index : Nat) (attempt : Attempt),
          (Model.protocol config).ValidStep localStep
          /\ localStep.action = .commit index
          /\ Properties.Commits config localStep.before index attempt
          /\ attempt.event = .timeout
          /\ localStep.before.phase = .opening
          /\ localStep.before.timeoutState = .opening := by
  intro config
  obtain ⟨node, txid, recovered⟩ := exists_recovered config
  let db : Store := [((.phase,none),⟨.phase .opening,0⟩),((.timeoutPhase,none),⟨.phase .opening,0⟩)]
  obtain ⟨s,a,valid,act,commit,event,store⟩ := commit_step config node txid recovered db .timeout rfl
  exact ⟨s,0,a,valid,act,commit,event,by unfold NodeState.phase; rw [store]; rfl,
    by unfold NodeState.timeoutState; rw [store]; rfl⟩

theorem quorum_advance_opens_witness
    : forall (config : Properties.ValidConfig),
        exists localStep : Properties.LocalStep,
        exists (index : Nat) (attempt : Attempt),
          (Model.protocol config).ValidStep localStep
          /\ localStep.action = .commit index
          /\ Properties.Commits config localStep.before index attempt
          /\ (attempt.event = .timeout
              \/ exists source, attempt.event = .receiveVote source .accepted)
          /\ (localStep.before.store.map Prod.fst).Nodup
          /\ localStep.before.phase = .voting
          /\ localStep.before.votes.length >= voteQuorum config.val.protocol := by
  intro config
  obtain ⟨node, txid, recovered⟩ := exists_recovered config
  let ns := config.val.protocol.expectedLocations
  let rows : Store := ns.map fun k => ((.votes,some k),⟨.present,0⟩)
  let db : Store := ((.phase,none),⟨.phase .voting,0⟩) :: ((.timeoutPhase,none),⟨.phase .open,0⟩) :: rows
  have votes : voteEntries (scanAt db [] .votes) = ns := by
    simp [db, rows, voteEntries, scanAt, writeValues, image, List.filterMap_map, Function.comp_def]
  have len : ns.length ≠ 0 := by
    have v := config.property.1
    simp [Config.isValid] at v
    simpa [ns] using v.1.1.2
  have sufficient : voteQuorum config.val.protocol ≤ ns.length := by
    change ns.length / 2 + 1 ≤ ns.length; omega
  have ok : ((transaction config.val.protocol .timeout).exec db).result = .ok () := by
    change ((advance config.val.protocol true).exec db).result = _
    simp [advance, readPhase, Program.read, Program.entries, Bind.bind, Program.bind, Program.exec,
      Program.execFrom, valueAt, find, db, recordOp, stage, Pure.pure, Program.write,
      writePhase, notify, Program.emit]
    split <;> rfl
  obtain ⟨s,a,valid,act,commit,event,store⟩ := commit_step config node txid recovered db .timeout ok
  refine ⟨s,0,a,valid,act,commit,Or.inl event,?_,?_,?_⟩
  · rw [store]
    simp [db, rows, List.map_map, Function.comp_def]
    exact config.property.2.1.map _ (by simp)
  · unfold NodeState.phase; rw [store]; rfl
  · unfold NodeState.votes; rw [store]
    change voteQuorum _ ≤ (voteEntries (scanAt db [] .votes)).length
    rwa [votes]

end DisasterRecovery.Proofs.Witnesses
