module

public import CCFRaft.Proofs.StablePrimary

@[expose] public section

set_option linter.unusedSectionVars false

/-!
# In-order delivery

Sent packets have distinct sequence numbers, and on one channel a packet with a
smaller number is delivered first. The batches of one send pass get consecutive
numbers, so no other packet on the channel is delivered between two of them.
-/

open CCF.Execution (Trace)

namespace CCFRaft.Proofs.Timed

open CCF CCF.MultiNodeTransitionSystem
open CCFRaft.Liveness
open Model.Node
open HasProtocol (proto)
open HasNetwork (pending issued)
open CCFRaft.Proofs.Liveness (Admissible)

variable {W : Type} [HasProtocol W Model.State] [HasTime W] [HasLive W] [HasNetwork W]

section General

variable {config : Finset NodeID} {nodes : List NodeID}
  {trace : Trace W Liveness.Event} (admissible : Admissible config nodes trace)

include admissible

/-- Packets sent at a later step carry larger sequence numbers. -/
private theorem id_lt_of_sent_lt {sent sent' : Nat} {packet packet' : Packet}
    (sentAt : SentAt trace sent packet) (sentAt' : SentAt trace sent' packet')
    (lt : sent < sent')
    : packet.id < packet'.id := by
  obtain ⟨step, _, _, stepped, _, _, _, _, high, _⟩ := admissible.sentAt_emitted sentAt
  obtain ⟨step', _, _, stepped', _, _, _, low', _, _⟩ := admissible.sentAt_emitted sentAt'
  have := admissible.issued_mono (Nat.succ_le_of_lt lt) (Trace.stateAt_succ_of_stepAt stepped)
    (Trace.stateAt_of_stepAt stepped')
  omega

/-- A sequence number identifies the sent packet and its sending step. -/
theorem sent_unique {sent sent' : Nat} {packet packet' : Packet}
    (sentAt : SentAt trace sent packet) (sentAt' : SentAt trace sent' packet')
    (same : packet.id = packet'.id)
    : sent = sent' /\ packet = packet' := by
  have eq : sent = sent' := by
    rcases Nat.lt_trichotomy sent sent' with lt | eq | gt
    · have := id_lt_of_sent_lt admissible sentAt sentAt' lt
      omega
    · exact eq
    · have := id_lt_of_sent_lt admissible sentAt' sentAt gt
      omega
  subst eq
  obtain ⟨step, stepped, member, _⟩ := sentAt
  obtain ⟨step', stepped', member', _⟩ := sentAt'
  rw [stepped, Option.some.injEq] at stepped'
  subst stepped'
  exact ⟨rfl, List.inj_on_of_nodup_map
    (admissible.ids_nodup (Trace.stateAt_succ_of_stepAt stepped)) member member' same⟩

/-- A packet outstanding at a state after its sending step was outstanding at
every earlier state after its sending step. -/
private theorem pending_back {sent : Nat} {packet : Packet}
    (sentAt : SentAt trace sent packet) {later : Nat} (gt : sent < later) (offset : Nat)
    {point : W} (found : trace.stateAt (later + offset) = some point)
    (member : packet ∈ pending point)
    : exists point', trace.stateAt later = some point' /\ packet ∈ pending point' := by
  induction offset generalizing point with
  | zero => exact ⟨point, found, member⟩
  | succ offset ih =>
      obtain ⟨step, stepped, rfl⟩ :=
        Trace.stateAt_succ_eq_some.mp (show trace.stateAt (later + offset + 1) = _ from found)
      by_cases old : packet ∈ pending step.before
      · exact ih (Trace.stateAt_of_stepAt stepped) old
      · have := (sent_unique admissible sentAt ⟨step, stepped, member, old⟩ rfl).1
        omega

/-- On one channel, the packet with the smaller sequence number is delivered first. -/
theorem fifo {sent sent' first second : Nat} {packet packet' : Packet}
    {step step' : CCF.Execution.Step W Liveness.Event} (sentAt : SentAt trace sent packet)
    (sentAt' : SentAt trace sent' packet')
    (source : packet.envelope.source = packet'.envelope.source)
    (target : packet.envelope.target = packet'.envelope.target)
    (lt : packet.id < packet'.id) (stepped : trace.stepAt first = some step)
    (event : step.action = .deliver packet) (stepped' : trace.stepAt second = some step')
    (event' : step'.action = .deliver packet')
    : first < second := by
  have consumed : step.action.consumedPacket = some packet := by
    rw [event]
    rfl
  have consumed' : step'.action.consumedPacket = some packet' := by
    rw [event']
    rfl
  obtain ⟨delivered', deliveredLt, deliveredAt'⟩ := admissible.consumed_sent stepped' consumed'
  obtain ⟨eq', -⟩ := sent_unique admissible deliveredAt' sentAt' rfl
  subst eq'
  have sentLe : sent <= delivered' := by
    by_contra gt
    have := id_lt_of_sent_lt admissible deliveredAt' sentAt (by omega)
    omega
  by_contra notLt
  rcases Nat.lt_or_eq_of_le (Nat.le_of_not_lt notLt) with lt' | eq
  · obtain ⟨point, found, member⟩ :=
      pending_back admissible sentAt (later := second) (by omega) (first - second)
        (by rw [Nat.add_sub_cancel' (Nat.le_of_lt lt')]; exact Trace.stateAt_of_stepAt stepped)
        (admissible.consumed_pending stepped consumed)
    rw [Trace.stateAt_of_stepAt stepped', Option.some.injEq] at found
    subst found
    have inOrder := (admissible.delivery.next stepped').2.1
    rw [event'] at inOrder
    have := inOrder packet member source target
    omega
  · subst eq
    rw [stepped, Option.some.injEq] at stepped'
    subst stepped'
    rw [event] at event'
    cases event'
    omega

end General

section Pass

variable [Proofs.Config.InitialConfiguration] {nodes : List NodeID}
  {trace : Trace W Liveness.Event}
  (admissible : Admissible Proofs.Config.INITIAL_CONFIGURATION nodes trace)

include admissible

/-- The batches of a send pass are sent as packets with consecutive sequence
numbers, in batch order. -/
theorem pass_packets {index : Nat} {step : CCF.Execution.Step W Liveness.Event}
    (stepped : trace.stepAt index = some step) {leader peer : NodeID}
    {batchEnds : List Nat}
    (event : step.action = .local leader (.sendEntries peer batchEnds))
    {before : NodeState} (found : nodeState (proto step.before) leader = some before)
    (notRetired : Not (before.isRetiredCommitted leader))
    : exists base,
        (forall position
                (bound
                  : position < (passBatches (before.sentIndex peer) batchEnds).length),
          exists packet,
            SentAt trace index packet
            /\ packet.id = base + position
            /\ packet.envelope
                = Safety.batchEnvelope before leader peer
                    ((passBatches (before.sentIndex peer) batchEnds)[position]'bound))
        /\ (forall packet,
              SentAt trace index packet
              -> exists position,
              exists bound
                      : position < (passBatches (before.sentIndex peer) batchEnds).length,
                packet.id = base + position
                /\ packet.envelope
                    = Safety.batchEnvelope before leader peer
                        ((passBatches (before.sentIndex peer) batchEnds)[position
                          ]'bound)) := by
  have selected : step.action.action = some (.local leader (.sendEntries peer batchEnds)) := by
    rw [event]
    rfl
  obtain ⟨actor, localEvent, current, next, outputs, ⟨actorEq, eventEq⟩, actorFound, ran,
      nextFound, out, _⟩ :=
    StablePrimary.step_found (admissible.reachable_before stepped)
      (admissible.step stepped selected)
  subst actorEq eventEq
  rw [found, Option.some.injEq] at actorFound
  subst actorFound
  obtain ⟨sent, outEq, pass⟩ := Safety.sendEntries_pass actor before peer batchEnds {} _ _ ran
  rw [outEq] at out
  have sentEq := (pass.complete notRetired).2
  obtain ⟨_, _, emitted, produced, _, ledger⟩ := admissible.delivery.next stepped
  simp only [selected, out, Option.bind_eq_bind, Option.bind_eq_some_iff,
    Option.some.injEq] at produced
  obtain ⟨_, _, rfl⟩ := produced
  refine ⟨issued step.before, fun position bound => ?_, fun packet sentAt => ?_⟩
  rotate_left
  · obtain ⟨step', stepped', member, fresh⟩ := sentAt
    rw [stepped, Option.some.injEq] at stepped'
    subst stepped'
    rw [ledger, List.mem_append] at member
    rcases member with kept | new
    · exact absurd (Event.mem_remaining kept) fresh
    · obtain ⟨ordinal, entry, idEq, _⟩ := Packet.mem_batch.mp new
      rw [List.nil_append, sentEq, List.getElem?_map, Option.map_eq_some_iff] at entry
      obtain ⟨batch, batchFound, envelopeEq⟩ := entry
      obtain ⟨bound, batchEq⟩ := List.getElem?_eq_some_iff.mp batchFound
      exact ⟨ordinal, bound, idEq, by rw [← envelopeEq, batchEq]⟩
  refine ⟨⟨issued step.before + position,
      Safety.batchEnvelope before actor peer
        ((passBatches (before.sentIndex peer) batchEnds)[position]'bound),
      HasTime.time step.before⟩,
    ⟨step, stepped, ?_, fun old => ?_⟩, rfl, rfl⟩
  · rw [ledger, List.mem_append]
    refine Or.inr (Packet.mem_batch.mpr ⟨position, ?_, rfl, rfl⟩)
    rw [List.nil_append, sentEq, List.getElem?_map, List.getElem?_eq_getElem bound]
    rfl
  · have := admissible.id_lt (Trace.stateAt_of_stepAt stepped) old
    simp at this

end Pass

end CCFRaft.Proofs.Timed
