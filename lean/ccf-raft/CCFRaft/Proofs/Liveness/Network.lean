module

public import CCFRaft.Proofs.Liveness.Admissible

@[expose] public section

/-!
# The packet ledger

Where the packets of an admissible execution come from, and when the network
stops consuming packets sent before a given index.
-/

open CCF.Execution (Trace)

namespace CCFRaft.Liveness

theorem Event.remaining_sublist (event : Event) (pending : List Packet)
    : List.Sublist (event.remaining pending) pending := by
  unfold Event.remaining
  split
  · exact List.eraseP_sublist
  · exact List.Sublist.refl _

theorem Event.mem_remaining {event : Event} {pending : List Packet} {packet : Packet}
    (member : packet ∈ event.remaining pending)
    : packet ∈ pending :=
  (event.remaining_sublist pending).subset member

/-- The packets of a batch are its envelopes, numbered in order from `first`. -/
theorem Packet.mem_batch {packet : Packet} {emitted : List Model.Envelope} {first : Nat}
    {sentAt : Real}
    : packet ∈ Packet.batch emitted first sentAt
      <-> exists ordinal,
            emitted[ordinal]? = some packet.envelope
            /\ packet.id = first + ordinal
            /\ packet.sentAt = sentAt := by
  unfold Packet.batch
  rw [List.mem_map]
  constructor
  · rintro ⟨⟨envelope, id⟩, member, rfl⟩
    obtain ⟨le, found⟩ := List.mem_zipIdx_iff_le_and_getElem?_sub.mp member
    exact ⟨id - first, found, by simp only; omega, rfl⟩
  · rintro ⟨ordinal, found, idEq, sentAtEq⟩
    refine ⟨(packet.envelope, first + ordinal), ?_, ?_⟩
    · rw [List.mem_zipIdx_iff_le_and_getElem?_sub]
      simpa using found
    · cases packet
      simp_all

theorem Packet.id_mem_batch {packet : Packet} {emitted : List Model.Envelope}
    {first : Nat} {sentAt : Real} (member : packet ∈ Packet.batch emitted first sentAt)
    : first <= packet.id /\ packet.id < first + emitted.length := by
  obtain ⟨ordinal, found, idEq, _⟩ := Packet.mem_batch.mp member
  have := (List.getElem?_eq_some_iff.mp found).1
  omega

end CCFRaft.Liveness

namespace CCFRaft.Proofs.Liveness.Admissible

open CCFRaft.Liveness
open Model.Node
open HasProtocol (proto)
open HasTime (time)
open HasNetwork (pending issued)

variable {W : Type} [HasProtocol W Model.State] [HasTime W] [HasLive W] [HasNetwork W]
  {config : Finset NodeID} {nodes : List NodeID}
  {trace : Trace W Liveness.Event}
  (admissible : Admissible config nodes trace)

include admissible

/-- A consumed packet was outstanding. -/
theorem consumed_pending {index : Nat} {step : CCF.Execution.Step W Liveness.Event}
    (stepped : trace.stepAt index = some step) {packet : Packet}
    (consumed : step.action.consumedPacket = some packet)
    : packet ∈ pending step.before := by
  have outstanding := (admissible.delivery.next stepped).1
  simp only [consumed] at outstanding
  exact outstanding

theorem issued_step {index : Nat} {step : CCF.Execution.Step W Liveness.Event}
    (stepped : trace.stepAt index = some step)
    : issued step.before <= issued step.after := by
  obtain ⟨_, _, emitted, _, count, _⟩ := admissible.delivery.next stepped
  omega

theorem issued_mono {earlier later : Nat} (le : earlier <= later) {first last : W}
    (firstFound : trace.stateAt earlier = some first)
    (lastFound : trace.stateAt later = some last)
    : issued first <= issued last :=
  trace.chain (relation := fun first last => issued first <= issued last)
    (fun _ => Nat.le_refl _) (fun _ _ _ => Nat.le_trans)
    (fun _ _ stepped => admissible.issued_step stepped) le firstFound lastFound

/-- Outstanding packets have already been issued. -/
theorem id_lt {index : Nat} {point : W} (found : trace.stateAt index = some point)
    {packet : Packet} (member : packet ∈ pending point)
    : packet.id < issued point :=
  admissible.delivery.invariant
    (invariant :=
      fun point => forall packet, packet ∈ pending point -> packet.id < issued point)
    (fun point init packet member => by
      rw [init.1] at member
      cases member)
    (fun step next held packet member => by
      obtain ⟨_, _, emitted, _, count, ledger⟩ := next
      rw [ledger, List.mem_append] at member
      rw [count]
      rcases member with kept | new
      · have := held packet (Event.mem_remaining kept)
        omega
      · exact (Packet.id_mem_batch new).2)
    found packet member

/-- Outstanding packets carry distinct sequence numbers. -/
theorem ids_nodup {index : Nat} {point : W} (found : trace.stateAt index = some point)
    : ((pending point).map Packet.id).Nodup :=
  trace.induction
    (start := 0)
    (motive := fun _ point => ((pending point).map Packet.id).Nodup)
    (fun point found => by
      rw [Trace.stateAt_zero, Option.some.injEq] at found
      subst found
      rw [admissible.delivery.init.1]
      exact List.nodup_nil)
    (fun _ step _ stepped held => by
      obtain ⟨_, _, emitted, _, _, ledger⟩ := admissible.delivery.next stepped
      have batchIds
          : (Packet.batch emitted (issued step.before) (time step.before)).map Packet.id
            = List.range' (issued step.before) emitted.length := by
        unfold Packet.batch
        rw [List.map_map, ← List.zipIdx_map_snd]
        rfl
      rw [ledger, List.map_append, List.nodup_append, batchIds]
      refine ⟨((Event.remaining_sublist _ _).map Packet.id).nodup held, List.nodup_range',
        fun old oldMember new newMember => ?_⟩
      obtain ⟨packet, kept, rfl⟩ := List.mem_map.mp oldMember
      have := admissible.id_lt (Trace.stateAt_of_stepAt stepped) (Event.mem_remaining kept)
      rw [List.mem_range'_1] at newMember
      omega)
    index point
    (Nat.zero_le _)
    found

/-- A packet that leaves the ledger at a step is the packet the step consumes. -/
theorem consumed_of_left {index : Nat} {step : CCF.Execution.Step W Liveness.Event}
    (stepped : trace.stepAt index = some step) {packet : Packet}
    (before : packet ∈ pending step.before) (after : Not (packet ∈ pending step.after))
    : step.action.consumedPacket = some packet := by
  obtain ⟨outstanding, _, _, _, _, ledger⟩ := admissible.delivery.next stepped
  rw [ledger, List.mem_append, not_or] at after
  have kept := after.1
  unfold Event.remaining at kept
  cases consumed : step.action.consumedPacket with
  | none =>
      simp only [consumed] at kept
      exact absurd before kept
  | some other =>
      simp only [consumed] at kept outstanding
      have same : other.sameIdentity packet = true := by
        by_contra different
        exact kept ((List.mem_eraseP_of_neg different).mpr before)
      simp only [Packet.sameIdentity, beq_iff_eq] at same
      rw [List.inj_on_of_nodup_map (admissible.ids_nodup (Trace.stateAt_of_stepAt stepped))
        outstanding before same]

/-- Every outstanding packet was sent at an earlier step. -/
theorem pending_sent {index : Nat} {point : W} (found : trace.stateAt index = some point)
    {packet : Packet} (member : packet ∈ pending point)
    : exists sent, sent < index /\ SentAt trace sent packet := by
  induction index generalizing point with
  | zero =>
      rw [Trace.stateAt_zero, Option.some.injEq] at found
      subst found
      rw [admissible.delivery.init.1] at member
      cases member
  | succ index ih =>
      obtain ⟨step, stepped, rfl⟩ := Trace.stateAt_succ_eq_some.mp found
      by_cases old : packet ∈ pending step.before
      · obtain ⟨sent, lt, sentAt⟩ := ih (Trace.stateAt_of_stepAt stepped) old
        exact ⟨sent, Nat.lt_succ_of_lt lt, sentAt⟩
      · exact ⟨index, Nat.lt_succ_self _, step, stepped, member, old⟩

/-- Every consumed packet was sent at an earlier step. -/
theorem consumed_sent {index : Nat} {step : CCF.Execution.Step W Liveness.Event}
    (stepped : trace.stepAt index = some step) {packet : Packet}
    (consumed : step.action.consumedPacket = some packet)
    : exists sent, sent < index /\ SentAt trace sent packet :=
  admissible.pending_sent (Trace.stateAt_of_stepAt stepped)
    (admissible.consumed_pending stepped consumed)

/-- A packet is sent by a protocol action, as one of the envelopes the action emits,
with the next sequence numbers and the time of its sending step. -/
theorem sentAt_emitted {index : Nat} {packet : Packet} (sent : SentAt trace index packet)
    : exists step action emitted,
        trace.stepAt index = some step
        /\ step.action.action = some action
        /\ outgoing (proto step.before) action = some emitted
        /\ packet.envelope ∈ emitted
        /\ issued step.before <= packet.id
        /\ packet.id < issued step.after
        /\ packet.sentAt = time step.before := by
  obtain ⟨step, stepped, member, fresh⟩ := sent
  obtain ⟨_, _, emitted, produced, count, ledger⟩ := admissible.delivery.next stepped
  rw [ledger, List.mem_append] at member
  rcases member with kept | new
  · exact absurd (Event.mem_remaining kept) fresh
  · obtain ⟨ordinal, found, _, sentAtEq⟩ := Packet.mem_batch.mp new
    have emits := List.mem_of_getElem? found
    have ids := Packet.id_mem_batch new
    cases selected : step.action.action with
    | none =>
        simp only [selected, Option.some.injEq] at produced
        subst produced
        cases emits
    | some action =>
        simp only [selected, Option.bind_eq_bind, Option.bind_eq_some_iff] at produced
        obtain ⟨_, _, out⟩ := produced
        exact ⟨
          step,
          action,
          emitted,
          stepped,
          selected,
          out,
          emits,
          ids.1,
          by omega,
          sentAtEq
        ⟩

/-- Each envelope a recorded protocol action emits is sent as a packet. -/
theorem sentAt_of_emitted {index : Nat} {step : CCF.Execution.Step W Liveness.Event}
    (stepped : trace.stepAt index = some step) {action : Model.Action}
    (selected : step.action.action = some action) {emitted : List Model.Envelope}
    (out : outgoing (proto step.before) action = some emitted) {envelope : Model.Envelope}
    (member : envelope ∈ emitted)
    : exists packet,
        SentAt trace index packet
        /\ packet.envelope = envelope
        /\ packet.sentAt = time step.before := by
  obtain ⟨_, _, emitted', produced, _, ledger⟩ := admissible.delivery.next stepped
  simp only [selected, out, Option.bind_eq_bind, Option.bind_eq_some_iff,
    Option.some.injEq] at produced
  obtain ⟨_, _, rfl⟩ := produced
  obtain ⟨ordinal, found⟩ := List.mem_iff_getElem?.mp member
  refine ⟨⟨issued step.before + ordinal, envelope, time step.before⟩,
    ⟨step, stepped, ?_, fun old => ?_⟩, rfl, rfl⟩
  · rw [ledger, List.mem_append]
    exact Or.inr (Packet.mem_batch.mpr ⟨ordinal, found, rfl, rfl⟩)
  · have := admissible.id_lt (Trace.stateAt_of_stepAt stepped) old
    simp at this

end CCFRaft.Proofs.Liveness.Admissible
