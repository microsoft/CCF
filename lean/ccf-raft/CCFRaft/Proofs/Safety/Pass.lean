module

public import CCFRaft.Proofs.Safety.Sends

@[expose] public section

set_option linter.unusedSectionVars false

/-!
# Send passes

A `sendEntries` pass changes only the destination's send frontier, which moves
forward but stays within the log. It sends one request per batch, built from
the state before the pass. Unless the primary's retirement is committed, it
sends every batch and moves the frontier to the log end.
-/

namespace CCFRaft.Proofs.Safety

open CCF
open Model.Node

/-! ## Batches -/

theorem passBatches_bounds {log : List Entry}
    : forall {previousIndex : Nat} {batchEnds : List Nat},
        isPass log previousIndex batchEnds = true
        -> forall batch,
            batch ∈ passBatches previousIndex batchEnds
            -> previousIndex <= batch.1
                /\ batch.1 <= batch.2
                /\ batch.2 <= log.length
                /\ singleTerm log batch.1 batch.2 = true
  | _, [], pass, _, _ => by simp [isPass] at pass
  | _, [_], pass, batch, member => by
      simp only [isPass, Bool.and_eq_true, decide_eq_true_eq, beq_iff_eq] at pass
      simp only [passBatches, List.mem_singleton] at member
      subst member
      exact ⟨le_rfl, pass.1.1, pass.1.2.le, pass.2⟩
  | _, endIndex :: next :: rest, pass, batch, member => by
      simp only [isPass, Bool.and_eq_true, decide_eq_true_eq] at pass
      obtain ⟨⟨⟨lt, bound⟩, single⟩, restPass⟩ := pass
      simp only [passBatches, List.mem_cons] at member
      rcases member with rfl | member
      · exact ⟨le_rfl, lt.le, bound.le, single⟩
      · obtain ⟨le, rest⟩ :=
          passBatches_bounds restPass batch (by simpa [passBatches] using member)
        exact ⟨lt.le.trans le, rest⟩

theorem isPass_le_length {log : List Entry} {previousIndex : Nat} {batchEnds : List Nat}
    (pass : isPass log previousIndex batchEnds = true)
    : previousIndex <= log.length := by
  cases batchEnds with
  | nil => simp [isPass] at pass
  | cons endIndex rest =>
      obtain ⟨_, le, bound, _⟩ :=
        passBatches_bounds pass (previousIndex, endIndex) (by simp [passBatches])
      exact le.trans bound

/-- The final batch of a pass ends at the log end. -/
theorem passBatches_last {log : List Entry}
    : forall {previousIndex : Nat} {batchEnds : List Nat},
        isPass log previousIndex batchEnds = true
        -> ((passBatches previousIndex batchEnds).getLast?.map Prod.snd).getD
              previousIndex
            = log.length
  | _, [], pass => by simp [isPass] at pass
  | _, [_], pass => by
      simp only [isPass, Bool.and_eq_true, decide_eq_true_eq, beq_iff_eq] at pass
      simp [passBatches, pass.1.2]
  | _, endIndex :: next :: rest, pass => by
      simp only [isPass, Bool.and_eq_true, decide_eq_true_eq] at pass
      have last := passBatches_last pass.2
      simp only [passBatches] at last ⊢
      rw [List.getLast?_cons_cons]
      exact last

/-! ## The pass -/

/-- The envelope carrying one batch of a pass. -/
def batchEnvelope (state : NodeState) (self destination : NodeID) (batch : Nat × Nat)
    : Model.Envelope :=
  {
    source := self
    target := destination
    payload := .appendEntriesRequest (makeAppendEntriesRequest state batch.1 batch.2)
  }

/-- What one `sendEntries` pass did. -/
structure Pass (node : NodeID) (before : NodeState) (destination : NodeID)
    (batchEnds : List Nat) (after : NodeState) (sent : List Model.Envelope)
    : Prop where
  primary : before.role = .primary
  eligible : destination ∈ eligiblePeers before node
  valid : isPass before.log (before.sentIndex destination) batchEnds = true
  state
    : after
      = {
        before with
          sentIndex :=
            Function.update before.sentIndex destination (after.sentIndex destination)
      }
  advances : before.sentIndex destination <= after.sentIndex destination
  bounded : after.sentIndex destination <= before.log.length
  sends
    : forall envelope,
        envelope ∈ sent
        -> exists batch,
            batch ∈ passBatches (before.sentIndex destination) batchEnds
            /\ envelope = batchEnvelope before node destination batch
  complete
    : Not (before.isRetiredCommitted node)
      -> after.sentIndex destination = before.log.length
          /\ sent
              = (passBatches (before.sentIndex destination) batchEnds).map
                  (batchEnvelope before node destination)

namespace Pass

variable {self : NodeID} {before : NodeState} {destination : NodeID}
  {batchEnds : List Nat}
  {after : NodeState} {sent : List Model.Envelope}

theorem other (pass : Pass self before destination batchEnds after sent) {peer : NodeID}
    (different : Not (peer = destination))
    : after.sentIndex peer = before.sentIndex peer := by
  rw [pass.state]
  exact Function.update_of_ne different _ _

theorem batch_bounds (pass : Pass self before destination batchEnds after sent)
    {batch : Nat × Nat}
    (member : batch ∈ passBatches (before.sentIndex destination) batchEnds)
    : before.sentIndex destination <= batch.1
      /\ batch.1 <= batch.2
      /\ batch.2 <= before.log.length :=
  (passBatches_bounds pass.valid batch member).imp_right fun rest => ⟨rest.1, rest.2.1⟩

theorem sent_of_mem (pass : Pass self before destination batchEnds after sent)
    (notRetired : Not (before.isRetiredCommitted self)) {batch : Nat × Nat}
    (member : batch ∈ passBatches (before.sentIndex destination) batchEnds)
    : batchEnvelope before self destination batch ∈ sent := by
  rw [(pass.complete notRetired).2]
  exact List.mem_map_of_mem member

end Pass

section Effects

variable (self : NodeID)

local notation "caps" => (Capabilities.record self : Caps)

theorem sendBatch_sends (before : NodeState) (destination : NodeID)
    (sentIndex : NodeID -> Nat) (batch : Nat × Nat)
    : Sends
        (fun after sent =>
          (before.isRetiredCommitted self
            /\ batch.2 <= batch.1 + 1
            /\ after = { before with sentIndex }
            /\ sent = [])
          \/ (Not (before.isRetiredCommitted self /\ batch.2 <= batch.1 + 1)
              /\ after
                  = {
                    before with
                      sentIndex := Function.update sentIndex destination batch.2
                  }
              /\ sent = [batchEnvelope before self destination batch]))
        (sendBatch caps self destination { before with sentIndex } batch) := by
  obtain ⟨previousIndex, endIndex⟩ := batch
  unfold sendBatch
  refine Sends.ite' (fun skip => Sends.pure' (Or.inl ⟨skip.1, skip.2, rfl, rfl⟩))
    fun send => ?_
  refine Sends.bind' (Sends.send _ _ _) fun _ sent eq => Sends.pure' (Or.inr ⟨send, rfl, ?_⟩)
  subst eq
  rfl

/-- Folding `sendBatch` over any batches from the state `before` with frontiers `sentIndex`. -/
theorem foldBatches_sends (before : NodeState) (destination : NodeID)
    : forall (batches : List (Nat × Nat)) (sentIndex : NodeID -> Nat),
        Sends
          (fun after sent =>
            after
              = {
                before with
                  sentIndex :=
                    Function.update sentIndex destination (after.sentIndex destination)
              }
            /\ (after.sentIndex destination = sentIndex destination
                \/ exists batch, batch ∈ batches /\ after.sentIndex destination = batch.2)
            /\ (forall envelope,
                  envelope ∈ sent
                  -> exists batch,
                      batch ∈ batches
                      /\ envelope = batchEnvelope before self destination batch)
            /\ (Not (before.isRetiredCommitted self)
                -> after.sentIndex destination
                      = (batches.getLast?.map Prod.snd).getD (sentIndex destination)
                    /\ sent = batches.map (batchEnvelope before self destination)))
          (batches.foldlM (sendBatch caps self destination) { before with sentIndex })
  | [], sentIndex => by
      refine Sends.pure' ⟨?_, Or.inl rfl, fun _ member => by simp at member, fun _ => ?_⟩
      · simp
      · simp
  | batch :: batches, sentIndex => by
      simp only [List.foldlM_cons]
      refine Sends.bind' (sendBatch_sends self before destination sentIndex batch)
        fun middle first done => ?_
      rcases done with ⟨retired, _, rfl, rfl⟩ | ⟨_, rfl, rfl⟩
      · refine Sends.mono (foldBatches_sends before destination batches sentIndex)
          fun after later ⟨state, moved, each, _⟩ => ⟨state, ?_, ?_, fun kept => absurd retired kept⟩
        · rcases moved with same | ⟨other, member, eq⟩
          · exact Or.inl same
          · exact Or.inr ⟨other, List.mem_cons_of_mem _ member, eq⟩
        · intro envelope member
          obtain ⟨other, inBatches, eq⟩ := each envelope (by simpa using member)
          exact ⟨other, List.mem_cons_of_mem _ inBatches, eq⟩
      · refine Sends.mono
          (foldBatches_sends before destination batches
            (Function.update sentIndex destination batch.2))
          fun after later ⟨state, moved, each, complete⟩ => ⟨?_, ?_, ?_, fun kept => ?_⟩
        · rw [state]
          simp
        · rcases moved with same | ⟨other, member, eq⟩
          · exact Or.inr ⟨batch, List.mem_cons_self, by simpa using same⟩
          · exact Or.inr ⟨other, List.mem_cons_of_mem _ member, eq⟩
        · intro envelope member
          rcases List.mem_cons.mp member with rfl | member
          · exact ⟨batch, List.mem_cons_self, rfl⟩
          · obtain ⟨other, inBatches, eq⟩ := each envelope member
            exact ⟨other, List.mem_cons_of_mem _ inBatches, eq⟩
        · obtain ⟨frontier, all⟩ := complete kept
          refine ⟨?_, by rw [all]; rfl⟩
          rw [frontier, List.getLast?_cons]
          cases batches.getLast? <;> simp

theorem sendEntries_pass (before : NodeState) (destination : NodeID)
    (batchEnds : List Nat)
    : Sends (Pass self before destination batchEnds)
        (sendEntries caps self before destination batchEnds) := by
  unfold sendEntries
  refine Sends.bind' Sends.guard' fun _ sent ⟨⟨primary, eligible, valid⟩, empty⟩ => ?_
  subst empty
  refine Sends.mono
    (foldBatches_sends self before destination
      (passBatches (before.sentIndex destination) batchEnds) before.sentIndex)
    fun after later ⟨state, moved, each, complete⟩ => ?_
  have startLe := isPass_le_length valid
  refine ⟨primary, eligible, valid, by simpa using state, ?_, ?_, each, fun kept => ?_⟩
  · rcases moved with same | ⟨batch, member, eq⟩
    · exact same.ge
    · rw [eq]
      obtain ⟨le, ordered, _⟩ := passBatches_bounds valid batch member
      exact le.trans ordered
  · rcases moved with same | ⟨batch, member, eq⟩
    · rw [same]
      exact startLe
    · rw [eq]
      exact (passBatches_bounds valid batch member).2.2.1
  · obtain ⟨frontier, all⟩ := complete kept
    exact ⟨frontier.trans (passBatches_last valid), by simpa using all⟩

end Effects

end CCFRaft.Proofs.Safety
