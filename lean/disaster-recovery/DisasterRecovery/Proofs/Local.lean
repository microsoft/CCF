module

public import DisasterRecovery.Proofs.Transactions

import all Init.Control.State

@[expose] public section

namespace DisasterRecovery.Proofs.Local

open CCF
open Model.Local OCC

@[local simp]
private theorem effect_bind {S A B : Type} (a : StateT S Option A)
    (f : A -> StateT S Option B) (s : S)
    : (a >>= f) s = (a s).bind (fun (a, s) => f a s) :=
  rfl

@[local simp]
private theorem effect_lift {S A : Type} (a : Option A) (s : S)
    : (liftM a : StateT S Option A) s = a.map (fun a => (a, s)) := by
  cases a <;> rfl

private theorem validStep_run {config : Model.Config}
    {s
      : MultiNodeTransitionSystem.LocalStep Location NodeState Operation Message Notification}
    (valid : (Model.protocol config).ValidStep s)
    : exists recovered,
        Model.recoveredTxID config s.node = some recovered
        /\ (perform (Capabilities.record s.node) config.protocol recovered s.before
              s.action).run
              {}
            = some (s.after, s.effects) := by
  simp [MultiNodeTransitionSystem.Protocol.ValidStep, Model.protocol, StateT.run,
    Option.bind_eq_some_iff, Option.map_eq_some_iff] at valid
  obtain ⟨_, _, ⟨_, found, rfl, rfl⟩, stepped⟩ := valid
  exact ⟨_, found, stepped⟩

private theorem replay {config : Model.Config} {s : NodeState} {i : Nat} {a : Attempt}
    (commit : Properties.Commits config s i a) :
    ((transaction config.protocol a.event).exec s.store).observable =
      (a.normal.writes, a.outputs, .ok ()) := by
  obtain ⟨_, ⟨snap, ran⟩, valid⟩ := commit
  have h := Program.exec_replay snap s.store (transaction config.protocol a.event)
    (Transactions.transaction_respects _ _) (by simpa [ran] using valid)
  simpa [ran, Program.Ran.observable] using h.symm

private theorem commit_of_writes {s : Properties.LocalStep} {config : Model.Config}
    {i : Nat} {a : Attempt} (valid : (Model.protocol config).ValidStep s)
    (action : s.action = .commit i) (commit : Properties.Commits config s.before i a)
    (writes : a.normal.writes.isEmpty = false) :
    s.after = { s.before with
      version := s.before.version + 1
      store := publish s.before.store (s.before.version + 1) a.normal.writes
      pending := s.before.pending.eraseIdx i } ∧
    s.effects = Evaluation.recordOutputs s.node {} a.outputs := by
  obtain ⟨tx, _, run⟩ := validStep_run valid
  rw [action] at run
  simp only [perform, commit.1, writes, Bool.false_eq_true, ↓reduceIte, commit.2.2,
    StateT.run, effect_bind] at run
  change ((release _ a.outputs).run {}).bind _ = _ at run
  rw [Evaluation.release_record] at run
  exact ⟨(congrArg Prod.fst (Option.some.inj run)).symm,
    (congrArg Prod.snd (Option.some.inj run)).symm⟩


theorem gossip_freezes_after_choice
    : forall (config : Model.Config),
      forall localStep : Properties.LocalStep,
      forall (source : Location) (txid : TxID),
        ((Model.protocol config).ValidStep localStep
          /\ localStep.action = .run (.receiveGossip source txid .accepted)
          /\ localStep.before.chosen.isSome = true)
        -> localStep.after = localStep.before
            /\ .rejected "gossip-frozen" ∈ localStep.effects.notifications := by
  rintro config s source txid ⟨valid, action, chosen⟩
  obtain ⟨tx, _, run⟩ := validStep_run valid
  obtain ⟨c, hc⟩ := Option.isSome_iff_exists.mp chosen
  have val : single s.before.store .chosen = some (.location c) := by
    unfold NodeState.chosen at hc
    split at hc <;> grind
  rw [action] at run
  unfold single at val
  have bad : ((transaction config.protocol (.receiveGossip source txid .accepted)).exec
      s.before.store).result = .error "gossip-frozen" := by
    simp [transaction, readChosen, Program.read, Bind.bind, Program.bind, Program.exec,
      Program.execFrom, valueAt, find, val, Pure.pure]
  simp only [perform, start, bad] at run
  change some (s.before, ({ notifications := [.rejected "gossip-frozen"] } :
    Outputs Location Message Notification)) = _ at run
  obtain ⟨states, effects⟩ := Prod.mk.inj (Option.some.inj run)
  exact ⟨states.symm, by rw [← effects]; simp⟩

theorem rejected_gossip_stutters
    : forall (config : Model.Config),
      forall localStep : Properties.LocalStep,
      forall (source : Location) (txid : TxID),
        ((Model.protocol config).ValidStep localStep
          /\ localStep.action = .run (.receiveGossip source txid .rejected))
        -> localStep.after = localStep.before
            /\ .rejected "quote-or-certificate" ∈ localStep.effects.notifications := by
  rintro config s source txid ⟨valid, action⟩
  obtain ⟨tx, _, run⟩ := validStep_run valid
  rw [action] at run
  change some (s.before, ({ notifications := [.rejected "quote-or-certificate"] } :
    Outputs Location Message Notification)) = _ at run
  obtain ⟨states, effects⟩ := Prod.mk.inj (Option.some.inj run)
  exact ⟨states.symm, by rw [← effects]; simp⟩

private def votesAt (db : Store) (ws : Writes Table Key Value) : List Location :=
  voteEntries (scanAt db ws .votes)

private theorem mem_votes {db : Store} {x : Location} :
    x ∈ votesAt db [] ↔ ∃ c, ((Table.votes, some x), c) ∈ db := by
  simp [votesAt, voteEntries, scanAt, writeValues, image, List.mem_filterMap,
    Option.eq_some_iff_get_eq]
  grind

private theorem nodup_votes (db : Store) (h : (db.map Prod.fst).Nodup) :
    (votesAt db []).Nodup := by
  induction db with
  | nil => simp [votesAt, voteEntries, scanAt, image, writeValues]
  | cons entry tail ih =>
      obtain ⟨⟨tab,k⟩,c⟩ := entry
      simp only [List.map_cons, List.nodup_cons] at h
      specialize ih h.2
      cases tab <;> cases k <;> first | exact ih | skip
      rename_i x
      change (x :: votesAt tail []).Nodup
      rw [List.nodup_cons, mem_votes]
      exact ⟨fun ⟨cell,mem⟩ => h.1 (List.mem_map.mpr ⟨_,mem,rfl⟩),ih⟩

private theorem vote_length (db : Store) (h : (db.map Prod.fst).Nodup) (source : Location) :
    (votesAt db []).length ≤
      (votesAt db [((.votes, some source), some .present)]).length := by
  apply (nodup_votes db h).length_le_of_subset
  intro x mem
  unfold votesAt voteEntries scanAt writeValues at *
  simp [OCC.set, erase, List.mem_filterMap] at *
  grind

private theorem voting_advance (c : Config) (b : Bool) (db : Store) (n : Normal Table Key Value)
    (phase : valueAt db n.writes (.phase, none) = some (.phase .voting))
    (quorum : voteQuorum c ≤ (votesAt db n.writes).length) :
    let ran := (advance c b).execFrom db n []
    ran.result = .ok () →
    find ran.normal.writes (.phase, none) = some (some (.phase .opening)) ∧
    find ran.normal.writes (.openKind, none) = some (some (.openKind .quorum)) ∧
    ran.outputs = [.notify (.opening .quorum)] := by
  have nonempty : votesAt db n.writes ≠ [] := by
    rintro h; simp [h, voteQuorum] at quorum
  unfold votesAt at quorum nonempty
  cases lane : valueAt db n.writes (.timeoutPhase, none) with
  | none => simp [advance, readPhase, Program.read, Bind.bind, Program.bind, Program.execFrom,
      recordOp, stage, phase, lane, Pure.pure]
  | some v =>
    cases v <;> try simp [advance, readPhase, Program.read, Bind.bind, Program.bind,
      Program.execFrom, recordOp, stage, phase, lane, Pure.pure]
    rename_i l
    cases b <;> cases l <;>
      simp [Program.entries, Program.bind,
        Program.execFrom, recordOp, stage, quorum, nonempty,
        writePhase, Program.write, notify, Program.emit, find_set_eq, Nat.not_lt.mpr quorum]

theorem quorum_advance_opens
    : forall (config : Model.Config),
      forall localStep : Properties.LocalStep,
      forall (index : Nat) (attempt : Attempt),
        ((Model.protocol config).ValidStep localStep
          /\ localStep.action = .commit index
          /\ Properties.Commits config localStep.before index attempt
          /\ (attempt.event = .timeout
              \/ exists source, attempt.event = .receiveVote source .accepted)
          /\ (localStep.before.store.map Prod.fst).Nodup
          /\ localStep.before.phase = .voting
          /\ localStep.before.votes.length >= voteQuorum config.protocol)
        -> localStep.after.phase = .opening
            /\ localStep.after.openKind = some .quorum
            /\ .opening .quorum ∈ localStep.effects.notifications := by
  rintro config s i a ⟨valid, act, commit, event, unique, phase, quorum⟩
  have p : single s.before.store .phase = some (.phase .voting) := by
    unfold NodeState.phase at phase
    split at phase <;> grind
  obtain ⟨wr,outs,ok⟩ := Prod.mk.inj (replay commit) |>.imp_right Prod.mk.inj
  let ran := (transaction config.protocol a.event).exec s.before.store
  have core : find ran.normal.writes (.phase, none) = some (some (.phase .opening)) ∧
      find ran.normal.writes (.openKind, none) = some (some (.openKind .quorum)) ∧
      ran.outputs = [.notify (.opening .quorum)] := by
    dsimp only [ran]
    rcases event with e | ⟨src,e⟩
    · rw [e] at ok ⊢
      exact voting_advance _ true _ {} p quorum ok
    · rw [e] at ok ⊢
      exact voting_advance _ false _ (recordOp s.before.store {} (.write (.votes, some src) (some .present)))
        p (Nat.le_trans quorum (vote_length _ unique src)) ok
  change ran.normal.writes = _ at wr
  change ran.outputs = _ at outs
  rw [wr,outs] at core
  obtain ⟨ph,kind,notifications⟩ := core
  have nonempty : a.normal.writes.isEmpty = false := by
    cases h : a.normal.writes <;> simp_all [find]
  obtain ⟨after,effects⟩ := commit_of_writes valid act commit nonempty
  rw [after, effects, notifications]
  simp [NodeState.phase, NodeState.openKind, single, publish_lookup, ph, kind, Evaluation.recordOutputs]

theorem aligned_opening_timeout_completes
    : forall (config : Model.Config),
      forall localStep : Properties.LocalStep,
      forall (index : Nat) (attempt : Attempt),
        ((Model.protocol config).ValidStep localStep
          /\ localStep.action = .commit index
          /\ Properties.Commits config localStep.before index attempt
          /\ attempt.event = .timeout
          /\ localStep.before.phase = .opening
          /\ localStep.before.timeoutState = .opening)
        -> localStep.after
              = {
                localStep.before with
                  store :=
                    CCF.OCC.publish localStep.before.store (localStep.before.version + 1)
                      [((.phase, none), some (.phase .open))]
                  version := localStep.before.version + 1
                  pending := localStep.before.pending.eraseIdx index
              }
            /\ .completed ∈ localStep.effects.notifications := by
  rintro config s i a ⟨valid, act, commit, event, phase, lane⟩
  have p : single s.before.store .phase = some (.phase .opening) := by
    unfold NodeState.phase at phase
    split at phase <;> grind
  have l : single s.before.store .timeoutPhase = some (.phase .opening) := by
    unfold NodeState.timeoutState at lane
    split at lane <;> grind
  have replayed := replay commit
  rw [event] at replayed
  unfold single at p l
  have result : ((transaction config.protocol .timeout).exec s.before.store).observable =
      ([((.phase, none), some (.phase .open))], [.notify .completed], .ok ()) := by
    simp [transaction, advance, readPhase, Program.read, Bind.bind, Program.bind, Program.exec,
      Program.execFrom, valueAt, find, recordOp, stage, p, l,
      Program.Ran.observable, writePhase, Program.write, notify, Program.emit, Pure.pure]
    rfl
  rw [result] at replayed
  obtain ⟨wr, outs, _⟩ := Prod.mk.inj replayed |>.imp_right Prod.mk.inj
  obtain ⟨after, effects⟩ := commit_of_writes valid act commit (by rw [← wr]; rfl)
  exact ⟨by simpa [← wr] using after, by rw [effects, ← outs]; simp [Evaluation.recordOutputs]⟩

end DisasterRecovery.Proofs.Local
