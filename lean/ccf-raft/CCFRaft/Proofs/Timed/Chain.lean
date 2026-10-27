module

public import CCFRaft.Proofs.Timed.Clock
public import CCFRaft.Proofs.Timed.Fifo
public import CCFRaft.Proofs.Timed.Follower

@[expose] public section

set_option linter.unusedSectionVars false

/-!
# A pass whose batch is accepted

The batches of one send pass reach the peer in order, with no other request of
the primary between them. Once one batch starts inside the peer's agreement and
at or above its commit index, every later batch of the pass does too, so the
last batch is accepted and acknowledged at the end of the primary's log.
-/

open CCF.Execution (Trace)

namespace CCFRaft.Proofs.Timed

open CCF CCF.MultiNodeTransitionSystem
open CCFRaft.Liveness
open Model.Node
open HasProtocol (proto)
open CCFRaft.Proofs.Liveness (Admissible)
open CCFRaft.Proofs.Replication
open CCFRaft.Proofs.Safety
open CCFRaft.Proofs.StablePrimary

variable {W : Type} [HasProtocol W Model.State] [HasTime W] [HasLive W] [HasNetwork W]

/-- Each batch of a pass starts where the previous one ended. -/
theorem passBatches_succ
    : forall {previousIndex : Nat} {batchEnds : List Nat} {k : Nat}
              (bound : k + 1 < (passBatches previousIndex batchEnds).length),
        ((passBatches previousIndex batchEnds)[k + 1]'bound).1
        = ((passBatches previousIndex batchEnds)[k]'(by omega)).2
  | _, [], _, bound => by simp [passBatches] at bound
  | _, [_], _, bound => by simp [passBatches] at bound
  | _, _ :: _ :: _, 0, _ => by simp [passBatches]
  | _, endIndex :: next :: rest, k + 1, bound => by
      simp only [passBatches] at bound ⊢
      exact passBatches_succ (previousIndex := endIndex) (batchEnds := next :: rest)
        (by simpa [passBatches] using bound)

/-- The last batch of a pass ends at the log end. -/
theorem passBatches_end {log : List Entry} {previousIndex : Nat} {batchEnds : List Nat}
    (pass : isPass log previousIndex batchEnds = true) {k : Nat}
    (bound : k < (passBatches previousIndex batchEnds).length)
    (lastK : k + 1 = (passBatches previousIndex batchEnds).length)
    : ((passBatches previousIndex batchEnds)[k]'bound).2 = log.length := by
  have last := Safety.passBatches_last pass
  rw [List.getLast?_eq_getElem?, List.getElem?_eq_getElem (by omega)] at last
  simp only [Option.map_some, Option.getD_some] at last
  rw [← last]
  congr 2
  omega

/-- A batch's request carries the entries from its start to its end. -/
theorem passBatches_entries {log : List Entry} {previousIndex : Nat}
    {batchEnds : List Nat} (pass : isPass log previousIndex batchEnds = true) {k : Nat}
    (bound : k < (passBatches previousIndex batchEnds).length)
    : ((passBatches previousIndex batchEnds)[k]'bound).1
        + (messageEntries log ((passBatches previousIndex batchEnds)[k]'bound).1
            ((passBatches previousIndex batchEnds)[k]'bound).2).length
      = ((passBatches previousIndex batchEnds)[k]'bound).2 := by
  obtain ⟨_, le, le', _⟩ := Safety.passBatches_bounds pass _ (List.getElem_mem bound)
  simp only [messageEntries, List.length_take, List.length_drop]
  omega

section Network

variable {config : Finset NodeID} {nodes : List NodeID}
  {trace : Trace W Liveness.Event} (admissible : Admissible config nodes trace)

include admissible

/-- A consumed packet is no longer outstanding after its step. -/
theorem consumed_gone {index : Nat} {step : CCF.Execution.Step W Liveness.Event}
    (stepped : trace.stepAt index = some step) {packet : Packet}
    (consumed : step.action.consumedPacket = some packet)
    : Not (packet ∈ HasNetwork.pending step.after) := by
  intro member
  have before := admissible.consumed_pending stepped consumed
  obtain ⟨_, _, emitted, _, _, ledger⟩ := admissible.delivery.next stepped
  rw [ledger, List.mem_append] at member
  rcases member with kept | new
  · simp only [Event.remaining, consumed] at kept
    obtain ⟨erased, front, back, _, same, split, erasedEq⟩ :=
      List.exists_of_eraseP before (p := packet.sameIdentity) (by simp [Packet.sameIdentity])
    simp only [Packet.sameIdentity, beq_iff_eq] at same
    rw [erasedEq] at kept
    have nodup := admissible.ids_nodup (Trace.stateAt_of_stepAt stepped)
    rw [split, List.map_append, List.map_cons, List.nodup_middle, List.nodup_cons,
      ← List.map_append] at nodup
    exact nodup.1 (List.mem_map.mpr ⟨packet, kept, same⟩)
  · have := (Packet.id_mem_batch new).1
    have := admissible.id_lt (Trace.stateAt_of_stepAt stepped) before
    omega

/-- A packet is consumed at most once. -/
theorem consumed_once {first second : Nat}
    {step step' : CCF.Execution.Step W Liveness.Event} {packet : Packet}
    (stepped : trace.stepAt first = some step)
    (consumed : step.action.consumedPacket = some packet)
    (stepped' : trace.stepAt second = some step')
    (consumed' : step'.action.consumedPacket = some packet)
    : first = second := by
  have gone : forall {first second : Nat} {step step' : CCF.Execution.Step W Liveness.Event},
      trace.stepAt first = some step -> step.action.consumedPacket = some packet
      -> trace.stepAt second = some step' -> step'.action.consumedPacket = some packet
      -> Not (first < second) := by
    intro first second step step' stepped consumed stepped' consumed' lt
    obtain ⟨sent, _, sentAt⟩ := admissible.consumed_sent stepped consumed
    have absent := trace.induction (start := first + 1)
      (motive := fun _ point => Not (packet ∈ HasNetwork.pending point))
      (fun point found => by
        rw [Trace.stateAt_succ_of_stepAt stepped, Option.some.injEq] at found
        subst found
        exact consumed_gone admissible stepped consumed)
      (fun index next le nextStepped held member => by
        have := (sent_unique admissible sentAt ⟨next, nextStepped, member, held⟩ rfl).1
        omega)
      second step'.before lt (Trace.stateAt_of_stepAt stepped')
    exact absent (admissible.consumed_pending stepped' consumed')
  rcases Nat.lt_trichotomy first second with lt | eq | gt
  · exact absurd lt (gone stepped consumed stepped' consumed')
  · exact eq
  · exact absurd gt (gone stepped' consumed' stepped consumed)

end Network

variable [Proofs.Config.InitialConfiguration] {nodes : List NodeID}
  {trace : Trace W Liveness.Event}
  (admissible : Admissible Proofs.Config.INITIAL_CONFIGURATION nodes trace)
  {start last : Nat} {stop delay interval : Real} {leader : NodeID} {term : Nat}
  (stable : StableLeader trace start leader term)
  {peer : NodeID} (different : Not (peer = leader))
  (env : Env trace start last stop delay interval leader peer)
  (current
    : forall index point,
        start <= index
        -> index <= last
        -> trace.stateAt index = some point
        -> exists state,
            nodeState (proto point) peer = some state /\ state.currentTerm = term)

include admissible stable different env current

/-- If a batch of a timely pass arrives inside the peer's agreement and at or
above its commit index, the peer acknowledges the primary's whole log at the
pass, and the acknowledgement arrives within two delays of the pass. -/
theorem pass_chain {pass : Nat} (afterStart : start <= pass)
    {step : CCF.Execution.Step W Liveness.Event} (stepped : trace.stepAt pass = some step)
    {batchEnds : List Nat}
    (event : step.action = .local leader (.sendEntries peer batchEnds))
    {before : NodeState} (found : nodeState (proto step.before) leader = some before)
    (timely : clock trace pass + 2 * delay <= stop) {position : Nat}
    (bound : position < (passBatches (before.sentIndex peer) batchEnds).length)
    {packet : Packet} (sentAt : SentAt trace pass packet)
    (envelope
      : packet.envelope
        = batchEnvelope before leader peer
            ((passBatches (before.sentIndex peer) batchEnds)[position]'bound))
    {index : Nat} {step' : CCF.Execution.Step W Liveness.Event}
    (stepped' : trace.stepAt index = some step')
    (delivered : step'.action = .deliver packet) {pre primary : NodeState}
    (preFound : nodeState (proto step'.before) peer = some pre)
    (leaderFound : nodeState (proto step'.before) leader = some primary)
    (agreed
      : ((passBatches (before.sentIndex peer) batchEnds)[position]'bound).1
        <= agree pre.log primary.log)
    (committed
      : pre.commitIndex
        <= ((passBatches (before.sentIndex peer) batchEnds)[position]'bound).1)
    : exists later step'' reply,
        index < later
        /\ clock trace later <= clock trace pass + 2 * delay
        /\ trace.stepAt later = some step''
        /\ step''.action = .deliver reply
        /\ reply.envelope
            = {
              source := peer
              target := leader
              payload :=
                .appendEntriesResponse
                  { term, success := true, lastLogIndex := before.log.length }
            } := by
  have passFound : nodeAt trace pass leader = some before := by
    rw [nodeAt_before stepped, found]
  have beforeTerm : before.currentTerm = term := stable.current afterStart passFound
  have valid : isPass before.log (before.sentIndex peer) batchEnds = true := by
    have selected : step.action.action = some (.local leader (.sendEntries peer batchEnds)) := by
      rw [event]
      rfl
    obtain ⟨actor, localEvent, current', next, outputs, ⟨actorEq, eventEq⟩, actorFound, ran,
        nextFound, out, _⟩ :=
      StablePrimary.step_found (admissible.reachable_before stepped)
        (admissible.step stepped selected)
    subst actorEq eventEq
    rw [found, Option.some.injEq] at actorFound
    subst actorFound
    obtain ⟨_, _, pass'⟩ := Safety.sendEntries_pass actor before peer batchEnds {} _ _ ran
    exact pass'.valid
  obtain ⟨base, packets, sentOnly⟩ :=
    pass_packets admissible stepped event found (stable.notRetired afterStart passFound)
  have consumedOf : forall {step' : CCF.Execution.Step W Liveness.Event}
      {packet : Packet}, step'.action = .deliver packet
      -> step'.action.consumedPacket = some packet := by
    intro step' packet delivered
    rw [delivered]
    rfl
  have accept : forall k (bound : k < (passBatches (before.sentIndex peer) batchEnds).length)
      packet, SentAt trace pass packet
      -> packet.envelope
          = batchEnvelope before leader peer
              ((passBatches (before.sentIndex peer) batchEnds)[k]'bound)
      -> forall x (step' : CCF.Execution.Step W Liveness.Event), trace.stepAt x = some step'
      -> step'.action = .deliver packet
      -> forall pre primary : NodeState, nodeState (proto step'.before) peer = some pre
      -> nodeState (proto step'.before) leader = some primary
      -> ((passBatches (before.sentIndex peer) batchEnds)[k]'bound).1
          <= agree pre.log primary.log
      -> pre.commitIndex <= ((passBatches (before.sentIndex peer) batchEnds)[k]'bound).1
      -> pass < x /\ x < last /\ clock trace x <= clock trace pass + delay
        /\ clock trace pass <= clock trace x
        /\ exists post,
          nodeState (proto step'.after) peer = some post
          /\ ((passBatches (before.sentIndex peer) batchEnds)[k]'bound).2
              <= agree post.log primary.log
          /\ post.commitIndex <= ((passBatches (before.sentIndex peer) batchEnds)[k]'bound).2
          /\ exists reply,
              SentAt trace x reply
              /\ reply.envelope
                  = {
                    source := peer
                    target := leader
                    payload :=
                      .appendEntriesResponse
                        {
                          term
                          success := true
                          lastLogIndex
                            := ((passBatches (before.sentIndex peer) batchEnds)[k]'bound).2
                        }
                  } := by
    intro k bound packet sentAt' envelope' x step' stepped' delivered pre primary preFound
      leaderFound agreed committed
    obtain ⟨sent, sentLt, sentAt''⟩ := admissible.consumed_sent stepped' (consumedOf delivered)
    have passLt : pass < x := by
      rw [← (sent_unique admissible sentAt'' sentAt' rfl).1]
      exact sentLt
    have xLt : x < last := env.ends x step' stepped'
    obtain ⟨state, stateFound, stateTerm⟩ :=
      current x step'.before (by omega) xLt.le (Trace.stateAt_of_stepAt stepped')
    rw [preFound, Option.some.injEq] at stateFound
    subst stateFound
    obtain ⟨post, postFound, _, agreeEnd, commitEnd, reply, replySent, replyEnvelope⟩ :=
      accept_good admissible stable different (by omega) stepped' delivered
        (by rw [envelope']; rfl) (by rw [envelope']; rfl) (by rw [envelope']; rfl)
        beforeTerm preFound stateTerm leaderFound agreed committed
    have entries := passBatches_entries valid bound
    simp only [makeAppendEntriesRequest] at agreeEnd commitEnd replyEnvelope
    rw [entries] at agreeEnd commitEnd replyEnvelope
    exact ⟨passLt, xLt, env.prompt x step' packet pass stepped' delivered sentAt',
      env.mono pass x passLt.le xLt.le, post, postFound, agreeEnd, commitEnd, reply, replySent,
      replyEnvelope⟩
  have chain : forall d k (bound : k < (passBatches (before.sentIndex peer) batchEnds).length),
      k + d + 1 = (passBatches (before.sentIndex peer) batchEnds).length
      -> forall packet, SentAt trace pass packet -> packet.id = base + k
      -> packet.envelope
          = batchEnvelope before leader peer
              ((passBatches (before.sentIndex peer) batchEnds)[k]'bound)
      -> forall x (step' : CCF.Execution.Step W Liveness.Event), trace.stepAt x = some step'
      -> step'.action = .deliver packet
      -> forall pre primary : NodeState, nodeState (proto step'.before) peer = some pre
      -> nodeState (proto step'.before) leader = some primary
      -> ((passBatches (before.sentIndex peer) batchEnds)[k]'bound).1
          <= agree pre.log primary.log
      -> pre.commitIndex <= ((passBatches (before.sentIndex peer) batchEnds)[k]'bound).1
      -> exists later step'' reply,
          x < later
          /\ clock trace later <= clock trace pass + 2 * delay
          /\ trace.stepAt later = some step''
          /\ step''.action = .deliver reply
          /\ reply.envelope
              = {
                source := peer
                target := leader
                payload :=
                  .appendEntriesResponse
                    { term, success := true, lastLogIndex := before.log.length }
              } := by
    intro d
    induction d with
    | zero =>
        intro k bound total packet sentAt' _ envelope' x step' stepped' delivered pre primary
          preFound leaderFound agreed committed
        obtain ⟨passLt, _, xClock, _, _, _, _, _, reply, replySent, replyEnvelope⟩ :=
          accept k bound packet sentAt' envelope' x step' stepped' delivered pre primary preFound
            leaderFound agreed committed
        rw [passBatches_end valid bound (by omega)] at replyEnvelope
        obtain ⟨later, step'', laterGt, stepped'', delivered''⟩ :=
          env.arrives x reply (by omega) replySent
            (Or.inr ⟨by rw [replyEnvelope], by rw [replyEnvelope]⟩) (by linarith)
        have laterClock := env.prompt later step'' reply x stepped'' delivered'' replySent
        exact ⟨
          later,
          step'',
          reply,
          laterGt,
          by linarith,
          stepped'',
          delivered'',
          replyEnvelope
        ⟩
    | succ d ih =>
        intro k bound total packet sentAt' idEq envelope' x step' stepped' delivered pre primary
          preFound leaderFound agreed committed
        obtain ⟨passLt, xLt, xClock, passClock, post, postFound, agreeEnd, commitEnd, -⟩ :=
          accept k bound packet sentAt' envelope' x step' stepped' delivered pre primary preFound
            leaderFound agreed committed
        have bound1 : k + 1 < (passBatches (before.sentIndex peer) batchEnds).length := by omega
        obtain ⟨packet1, sent1, id1, envelope1⟩ := packets (k + 1) bound1
        obtain ⟨y, step1, _, stepped1, delivered1⟩ :=
          env.arrives pass packet1 afterStart sent1
            (Or.inl ⟨by rw [envelope1]; rfl, by rw [envelope1]; rfl⟩) (by linarith)
        have xy : x < y :=
          fifo admissible sentAt' sent1 (by rw [envelope', envelope1]; rfl)
            (by rw [envelope', envelope1]; rfl) (by omega) stepped' delivered stepped1 delivered1
        have yLt : y < last := env.ends y step1 stepped1
        have settled : forall z point, x + 1 <= z -> trace.stateAt z = some point -> z <= y
            -> exists state, nodeState (proto point) peer = some state
              /\ state.log = post.log /\ state.commitIndex = post.commitIndex :=
          trace.induction (start := x + 1)
            (motive := fun z point => z <= y
              -> exists state, nodeState (proto point) peer = some state
                /\ state.log = post.log /\ state.commitIndex = post.commitIndex)
            (fun point found _ => by
              rw [Trace.stateAt_succ_of_stepAt stepped', Option.some.injEq] at found
              subst found
              exact ⟨post, postFound, rfl, rfl⟩)
            (fun z next le nextStepped held le' => by
              obtain ⟨old, oldFound, oldLog, oldCommit⟩ := held (by omega)
              obtain ⟨old', oldFound', oldTerm⟩ :=
                current z next.before (by omega) (by omega) (Trace.stateAt_of_stepAt nextStepped)
              rw [oldFound, Option.some.injEq] at oldFound'
              subst oldFound'
              obtain ⟨new, newFound, newTerm⟩ :=
                current (z + 1) next.after (by omega) (by omega)
                  (Trace.stateAt_succ_of_stepAt nextStepped)
              refine ⟨new, newFound, ?_⟩
              by_contra changed
              obtain ⟨q, _, qDelivered, qSource, qTarget, _, _⟩ :=
                peer_changes admissible stable different (by omega) nextStepped oldFound newFound
                  oldTerm newTerm (by
                    rw [oldLog, oldCommit]
                    by_contra both
                    simp only [not_or, not_not] at both
                    exact changed both)
              obtain ⟨_, _, sentAtQ⟩ := admissible.consumed_sent nextStepped (consumedOf qDelivered)
              rcases Nat.lt_trichotomy q.id (base + k) with lt | eq | gt
              · have := fifo admissible sentAtQ sentAt' (by rw [qSource, envelope']; rfl)
                  (by rw [qTarget, envelope']; rfl) (by omega) nextStepped qDelivered stepped'
                  delivered
                omega
              · obtain ⟨_, rfl⟩ := sent_unique admissible sentAtQ sentAt' (by omega)
                have := consumed_once admissible nextStepped (consumedOf qDelivered) stepped'
                  (consumedOf delivered)
                omega
              · rcases Nat.lt_or_ge q.id (base + k + 2) with lt' | ge
                · obtain ⟨_, rfl⟩ := sent_unique admissible sentAtQ sent1 (by omega)
                  have := consumed_once admissible nextStepped (consumedOf qDelivered) stepped1
                    (consumedOf delivered1)
                  omega
                · have := fifo admissible sent1 sentAtQ (by rw [qSource, envelope1]; rfl)
                    (by rw [qTarget, envelope1]; rfl) (by omega) stepped1 delivered1 nextStepped
                    qDelivered
                  omega)
        obtain ⟨atY, atYFound, atYLog, atYCommit⟩ :=
          settled y step1.before (by omega) (Trace.stateAt_of_stepAt stepped1) le_rfl
        obtain ⟨_, primaryY, primaryYFound, _⟩ :=
          stable.leads (by omega : start <= y) (Trace.stateAt_of_stepAt stepped1)
        have grown :=
          CommitLiveness.stable_log_prefix admissible stable (by omega : start <= x) xy.le
            (by rw [nodeAt_before stepped', leaderFound])
            (by rw [nodeAt_before stepped1, primaryYFound])
        have link := passBatches_succ bound1
        obtain ⟨later, step'', reply, laterGt, rest⟩ :=
          ih (k + 1) bound1 (by omega) packet1 sent1 id1 envelope1 y step1 stepped1 delivered1
            atY primaryY atYFound primaryYFound
            (by rw [link, atYLog]; exact agreeEnd.trans (agree_mono grown))
            (by rw [link, atYCommit]; exact commitEnd)
        exact ⟨later, step'', reply, by omega, rest⟩
  obtain ⟨position', bound', id', envelope''⟩ := sentOnly packet sentAt
  have same : ((passBatches (before.sentIndex peer) batchEnds)[position]'bound).1 = ((passBatches (before.sentIndex peer) batchEnds)[position']'bound').1 := by
    have := congrArg
      (fun e : Model.Envelope =>
        match e.payload with
        | .appendEntriesRequest request => request.prevLogIndex
        | _ => 0)
      (envelope.symm.trans envelope'')
    simpa [batchEnvelope, makeAppendEntriesRequest] using this
  exact chain ((passBatches (before.sentIndex peer) batchEnds).length - 1 - position')
    position' bound' (by omega) packet sentAt id' envelope'' index step' stepped'
    delivered pre primary preFound leaderFound (same ▸ agreed) (same ▸ committed)

end CCFRaft.Proofs.Timed
