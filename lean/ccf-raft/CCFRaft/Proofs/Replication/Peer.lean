module

public import CCFRaft.Proofs.Replication.Link
public import CCFRaft.Proofs.Replication.Retry

@[expose] public section

set_option linter.unusedSectionVars false

/-!
# A peer with a fixed log

Fix a peer of a stable primary whose log and term stay fixed from a recorded `origin` (`Regime`).
A request from the primary is rejected beyond their agreement, ignored below it, or accepted up to it; a rejection retries at or above the agreement, and the primary's match index stays within it and never drops.
-/

open CCF CCF.MultiNodeTransitionSystem
open CCFRaft
open CCFRaft.Model.Node
open CCFRaft.Liveness
open CCFRaft.Proofs.Config
open CCFRaft.Proofs.Safety
open CCFRaft.Proofs.StablePrimary
open CCFRaft.Proofs.Liveness (Admissible)
open CCFRaft.Proofs.CommitLiveness (stable_log_prefix)
open HasProtocol (proto)

open CCF.Execution (Trace)

namespace CCFRaft.Proofs.Replication

variable {W : Type} [HasProtocol W Model.State]

theorem zip_prefix_eq {α : Type}
    : forall {left right common : List α},
        left <+: common
        -> right <+: common
        -> forall pair, pair ∈ left.zip right -> pair.1 = pair.2
  | [], _, _, _, _, _, member => by simp at member
  | _ :: _, [], _, _, _, _, member => by simp at member
  | _ :: _, _ :: _, [], left, _, _, _ => by simp at left
  | _ :: _, _ :: _, _ :: _, left, right, pair, member => by
      rw [List.cons_prefix_cons] at left right
      rcases List.mem_cons.mp member with rfl | member
      · simp [left.1, right.1]
      · exact zip_prefix_eq left.2 right.2 pair member

/-- No conflict when the follower's suffix and the batch are both prefixes of one list. -/
theorem conflictIndex_eq_none {log common : List Entry} {request : AppendEntriesRequest}
    (left : log.drop request.prevLogIndex <+: common) (right : request.entries <+: common)
    : conflictIndex log request = none := by
  unfold conflictIndex
  rw [Option.map_eq_none_iff, List.find?_eq_none]
  rintro ⟨⟨existing, incoming⟩, position⟩ member
  have same : existing = incoming :=
    zip_prefix_eq left right _ (List.fst_mem_of_mem_zipIdx member)
  simp [same]

/-- From a recorded `origin` during stable leadership, the peer has a fixed log
and term, and a fixed agreement with the primary at every recorded state. -/
structure Regime [HasLive W] [HasNetwork W] {trace : Trace W Liveness.Event} {start : Nat}
    {leader : NodeID} {term : Nat} (stable : StableLeader trace start leader term)
    (peer : NodeID) (log : List Entry) (agreed origin : Nat)
    : Prop where
  afterStart : start <= origin
  recorded : exists point, trace.stateAt origin = some point
  state
    : forall index point,
        origin <= index
        -> trace.stateAt index = some point
        -> exists state,
            nodeState (proto point) peer = some state
            /\ state.currentTerm = term
            /\ state.log = log
  agreement
    : forall index state,
        origin <= index
        -> nodeAt trace index leader = some state
        -> agree log state.log = agreed
  fresh
    : forall index step packet,
        origin <= index
        -> trace.stepAt index = some step
        -> step.action = .deliver packet
        -> exists sent, start <= sent /\ sent < index /\ SentAt trace sent packet

theorem nackResponse_failure (w : NodeState) (r : AppendEntriesRequest)
    : (nackResponse w r).success = false := by
  unfold nackResponse
  split <;> rfl

variable [Config.InitialConfiguration] [HasTime W] [HasLive W] [HasNetwork W]

section Peer

variable {nodes : List NodeID} {trace : Trace W Liveness.Event}
  (admissible : Admissible Config.INITIAL_CONFIGURATION nodes trace)
  {start : Nat} {leader : NodeID} {term : Nat}
  (stable : StableLeader trace start leader term)
  {peer : NodeID}

include admissible stable

variable (different : Not (peer = leader))

include different

section Regime

variable {log : List Entry} {agreed origin : Nat}

/-- A request from the primary is rejected beyond the agreement, ignored below it,
or accepted up to it. Responses to other senders go back to those senders. -/
theorem request_outcome (regime : Regime stable peer log agreed origin) {index : Nat}
    {step : CCF.Execution.Step W Liveness.Event}
    (stepped : trace.stepAt index = some step) {packet : Packet}
    (event : step.action = .deliver packet) (began : origin <= index)
    (target : packet.envelope.target = peer) {request : AppendEntriesRequest}
    (payload : packet.envelope.payload = .appendEntriesRequest request)
    {primary : NodeState}
    (leaderFound : nodeState (proto step.before) leader = some primary)
    : exists w sends,
        w.currentTerm = term
        /\ w.log = log
        /\ outgoing (proto step.before) (.deliver packet.envelope) = some sends
        /\ (forall x, x ∈ sends -> x.target = packet.envelope.source)
        /\ (packet.envelope.source = leader
            -> request.term = term
                /\ request.prevLogIndex <= primary.log.length
                /\ request.prevLogTerm = termAt primary.log request.prevLogIndex
                /\ ((agreed < request.prevLogIndex
                      /\ Not
                          (termAt log request.prevLogIndex
                            = termAt primary.log request.prevLogIndex)
                      /\ sends
                          = [{
                              source := peer
                              target := leader
                              payload := .appendEntriesResponse (nackResponse w request)
                            }])
                    \/ (request.prevLogIndex < agreed /\ sends = [])
                    \/ (request.prevLogIndex + request.entries.length <= agreed
                        /\ sends
                            = [{
                                source := peer
                                target := leader
                                payload :=
                                  .appendEntriesResponse
                                    {
                                      term
                                      success := true
                                      lastLogIndex :=
                                        request.prevLogIndex + request.entries.length
                                    }
                              }]))) := by
  have delivered : step.action.delivered = some packet.envelope := by rw [event]; rfl
  obtain ⟨z, found, zTerm, zLog⟩ := regime.state index step.before began (Trace.stateAt_of_stepAt stepped)
  obtain ⟨z', found', zTerm', zLog'⟩ :=
    regime.state (index + 1) step.after (Nat.le_succ_of_le began)
      (Trace.stateAt_succ_of_stepAt stepped)
  have foundAt : nodeState (proto step.before) packet.envelope.target = some z := by
    rw [target]; exact found
  have foundAt' : nodeState (proto step.after) packet.envelope.target = some z' := by
    rw [target]; exact found'
  have le : request.term <= z.currentTerm := by
    have := request_term_le admissible stepped delivered payload foundAt'
    omega
  obtain ⟨after, sends, foundAfter, received, out⟩ :=
    receive_step admissible stepped delivered payload foundAt le
  have afterLog : after.log = log := by
    rw [foundAt', Option.some.injEq] at foundAfter
    rw [← foundAfter, zLog']
  have wTerm : (awareState z request).currentTerm = term :=
    (awareState_term z request).trans zTerm
  have wLog : (awareState z request).log = log := (awareState_log z request).trans zLog
  refine ⟨awareState z request, sends, wTerm, wLog, out, ?_, fun source => ?_⟩
  · rcases received with ⟨_, _, rfl⟩ | ⟨_, _, _, _, rfl⟩
        | ⟨_, _, _, _, _, _, _, _, _, _, rfl⟩ <;> simp
  obtain ⟨sent, sentLate, _, sentAt⟩ := regime.fresh index step packet began stepped event
  have rTerm := stable_requests admissible stable sentLate sentAt source payload
  obtain ⟨_, _, prevLe, prevTerm, entries⟩ :=
    request_at admissible stable (regime.afterStart.trans began) stepped delivered payload
      rTerm leaderFound
  have leaderNode : nodeAt trace index leader = some primary := by
    rw [nodeAt_before stepped, leaderFound]
  have view := view_at admissible stable different (regime.afterStart.trans began) leaderNode
    (by rw [nodeAt_before stepped, found]) zTerm
  have agreement := regime.agreement index primary began leaderNode
  refine ⟨rTerm, prevLe, prevTerm, ?_⟩
  rw [target, source] at received
  rcases received with ⟨reject, _, sendsEq⟩ | ⟨_, _, ignore, _, sendsEq⟩
      | ⟨_, matched, _, _, _, _, acceptEq, _, _, _, sendsEq⟩
  · have mismatch
        : Not (termAt log request.prevLogIndex = termAt primary.log request.prevLogIndex) := by
      intro same
      rcases reject with stale | notMatched
      · omega
      by_cases short : request.prevLogIndex <= log.length
      · exact notMatched ⟨by rw [wLog]; exact short, by rw [wLog, same, prevTerm]⟩
      · have positive := view.leaderPositive _ (by omega) prevLe
        rw [termAt_of_length_lt (by omega)] at same
        omega
    refine Or.inl ⟨?_, mismatch, sendsEq⟩
    by_contra low
    exact mismatch (termAt_agree (by omega))
  · refine Or.inr (Or.inl ⟨?_, sendsEq⟩)
    have commit := view.commit
    rw [zLog, agreement] at commit
    rcases ignore with low | ⟨conflict, settledFlag⟩
    · have : (awareState z request).commitIndex = z.commitIndex := by
        unfold awareState
        split <;> rfl
      omega
    · exfalso
      obtain ⟨same, campaigning⟩ := awareState_settled settledFlag
      obtain ⟨notCandidate, notPre⟩ := campaigning (rTerm.trans zTerm.symm)
      have sub := view.settled ⟨notCandidate, notPre, by rw [← same]; exact settledFlag⟩
      rw [zLog] at sub
      rw [wLog, conflictIndex_eq_none (sub.drop request.prevLogIndex) entries] at conflict
      simp at conflict
  · refine Or.inr (Or.inr ⟨?_, by rw [sendsEq, wTerm]⟩)
    rw [afterLog, wLog] at acceptEq
    obtain ⟨prevBound, prevMatch⟩ := matched
    rw [wLog] at prevBound prevMatch
    have aligned
        : forall j, 0 < j -> j <= log.length -> j <= primary.log.length
          -> termAt log j = termAt primary.log j -> log.take j = primary.log.take j := by
      intro j positive bound leaderBound same
      have := view.matching j positive (by rw [zLog]; exact bound) leaderBound
        (by rw [zLog]; exact same)
      rwa [zLog] at this
    have prevAgree : log.take request.prevLogIndex = primary.log.take request.prevLogIndex := by
      by_cases zero : request.prevLogIndex = 0
      · simp [zero]
      · exact aligned _ (by omega) prevBound prevLe (by rw [prevMatch, prevTerm])
    have shape := acceptLog_eq prevBound prevLe prevAgree entries aligned
    rw [← acceptEq] at shape
    have batch := entries.length_le
    rw [List.length_drop] at batch
    have lengthLe : request.prevLogIndex + request.entries.length <= log.length := by
      rw [shape, List.length_append, List.length_take]
      omega
    have takeEq : log.take (request.prevLogIndex + request.entries.length)
        = primary.log.take (request.prevLogIndex + request.entries.length) := by
      rw [shape]
      exact List.take_left' (by rw [List.length_take]; omega)
    have := le_agree _ _ _ lengthLe (by omega) takeEq
    omega

/-- A rejection sent in the regime answers a current-term request beyond the
agreement, at a position mismatching the peer's fixed log. -/
theorem nack_origin (regime : Regime stable peer log agreed origin) {index : Nat}
    {packet : Packet} (sent : SentAt trace index packet) (began : origin <= index)
    (source : packet.envelope.source = peer) (target : packet.envelope.target = leader)
    {response : AppendEntriesResponse}
    (payload : packet.envelope.payload = .appendEntriesResponse response)
    (failure : response.success = false) {primary : NodeState}
    (leaderFound : nodeAt trace index leader = some primary)
    : exists w request,
        w.currentTerm = term
        /\ w.log = log
        /\ response = nackResponse w request
        /\ request.term = term
        /\ agreed < request.prevLogIndex
        /\ request.prevLogIndex <= primary.log.length
        /\ request.prevLogTerm = termAt primary.log request.prevLogIndex
        /\ Not
            (termAt log request.prevLogIndex
              = termAt primary.log request.prevLogIndex) := by
  obtain ⟨step, envelope, request, _, stepped, delivered, envelopeTarget, requestPayload, _⟩ :=
    response_origin admissible sent payload
  obtain ⟨delivery, event, rfl⟩ := packet_of_delivered delivered
  rw [nodeAt_before stepped] at leaderFound
  obtain ⟨w, sends, wTerm, wLog, out, aimed, detail⟩ :=
    request_outcome admissible stable different regime stepped event began
      (envelopeTarget.trans source) requestPayload leaderFound
  obtain ⟨sentStep, action, emitted, sentStepped, selected, out', member, -⟩ :=
    admissible.sentAt_emitted sent
  rw [stepped, Option.some.injEq] at sentStepped
  subst sentStep
  have selected' : step.action.action = some (.deliver delivery.envelope) := by rw [event]; rfl
  rw [selected', Option.some.injEq] at selected
  subst action
  rw [out, Option.some.injEq] at out'
  subst emitted
  have fromLeader : delivery.envelope.source = leader := by rw [← aimed _ member, target]
  obtain ⟨rTerm, prevLe, prevTerm, outcome⟩ := detail fromLeader
  rcases outcome with ⟨above, mismatch, sendsEq⟩ | ⟨_, sendsEq⟩ | ⟨_, sendsEq⟩
  · rw [sendsEq, List.mem_singleton] at member
    rw [member] at payload
    injection payload with responseEq
    exact ⟨w, request, wTerm, wLog, responseEq.symm, rTerm, above, prevLe, prevTerm, mismatch⟩
  · rw [sendsEq] at member
    simp at member
  · rw [sendsEq, List.mem_singleton] at member
    rw [member] at payload
    injection payload with responseEq
    rw [← responseEq] at failure
    simp at failure

/-- Read against the primary's later log, a rejection retries at or above the
agreement and below the rejected position. -/
theorem retry_bounds (regime : Regime stable peer log agreed origin) {w : NodeState}
    {request : AppendEntriesRequest} (wTerm : w.currentTerm = term) (wLog : w.log = log)
    (rTerm : request.term = term) {sent later : Nat} (began : origin <= sent)
    (le : sent <= later) {before after : NodeState}
    (found : nodeAt trace sent leader = some before)
    (found' : nodeAt trace later leader = some after)
    (prevLe : request.prevLogIndex <= before.log.length)
    (prevTerm : request.prevLogTerm = termAt before.log request.prevLogIndex)
    (mismatch
      : Not (termAt log request.prevLogIndex = termAt before.log request.prevLogIndex))
    : agreed <= retry after.log w request
      /\ retry after.log w request < min request.prevLogIndex (log.length + 1) := by
  obtain ⟨point, pointFound, _⟩ := nodeAt_eq_some.mp found'
  obtain ⟨z, zFound, zTerm, zLog⟩ := regime.state later point (began.trans le) pointFound
  have view := view_at admissible stable different (by have := regime.afterStart; omega) found'
    (by rw [nodeAt_of_stateAt pointFound, zFound]) zTerm
  have grows := stable_log_prefix admissible stable (regime.afterStart.trans began) le found found'
  have transfer : termAt after.log request.prevLogIndex = termAt before.log request.prevLogIndex :=
    termAt_of_prefix grows prevLe
  rw [← transfer] at prevTerm mismatch
  have sorted := view.sorted
  have positive := view.positive
  rw [zLog] at sorted positive
  have agreement := regime.agreement later after (began.trans le) found'
  constructor
  · have := agree_le_retry (w := w) (by rw [wLog]; exact sorted) view.leaderSorted
      (fun index => by rw [wTerm]; exact view.leaderTerms index) (prevLe.trans grows.length_le)
      prevTerm (by rw [wLog]; exact mismatch)
    rwa [wLog, agreement] at this
  · have := retry_lt (w := w) (log := after.log) (by rw [wLog]; exact positive)
      (by omega) prevTerm (by rw [wLog]; exact mismatch)
    rwa [wLog] at this

/-- The primary's match frontier cannot exceed its agreement with a fixed peer log. -/
theorem match_le_agreed (regime : Regime stable peer log agreed origin) {index : Nat}
    (began : origin <= index) {primary : NodeState}
    (leaderFound : nodeAt trace index leader = some primary)
    : primary.matchIndex peer <= agreed := by
  obtain ⟨point, pointFound, _⟩ := nodeAt_eq_some.mp leaderFound
  obtain ⟨z, found, zTerm, zLog⟩ := regime.state index point began pointFound
  have := (view_at admissible stable different (regime.afterStart.trans began) leaderFound
    (by rw [nodeAt_of_stateAt pointFound, found]) zTerm).matchLe
  rwa [zLog, regime.agreement index primary began leaderFound] at this

/-- Once in-flight rejections come from the regime, the retry floor never drops. -/
theorem floor_step (regime : Regime stable peer log agreed origin)
    (eligible
      : forall index state,
          origin <= index
          -> nodeAt trace index leader = some state
          -> peer ∈ eligiblePeers state leader)
    {index : Nat} {step : CCF.Execution.Step W Liveness.Event}
    (stepped : trace.stepAt index = some step) (began : origin <= index)
    (late
      : forall packet,
          step.action = .deliver packet
          -> exists sent, origin <= sent /\ sent < index /\ SentAt trace sent packet)
    {before after : NodeState}
    (found : nodeState (proto step.before) leader = some before)
    (found' : nodeState (proto step.after) leader = some after)
    : min (before.sentIndex peer) agreed <= min (after.sentIndex peer) agreed := by
  have beforeNode : nodeAt trace index leader = some before := by
    rw [nodeAt_before stepped, found]
  rcases (leader_move admissible stable peer (regime.afterStart.trans began) stepped found found').2
      with same | ⟨_, _, _, pass, _⟩
      | ⟨envelope, response, delivered, source, target, payload, failure, value⟩
      | ⟨_, _, _, _, _, aimed⟩
  · rw [same]
  · have := pass.advances
    omega
  · obtain ⟨packet, event, rfl⟩ := packet_of_delivered delivered
    obtain ⟨sent, sentLate, sentBefore, sentAt⟩ := late packet event
    obtain ⟨point, pointFound⟩ := Trace.stateAt_ge_stable sentBefore.le (Trace.stateAt_of_stepAt stepped)
    obtain ⟨sender, senderFound⟩ := stable.found (regime.afterStart.trans sentLate) pointFound
    obtain ⟨w, request, wTerm, wLog, responseEq, rTerm, _, prevLe, prevTerm, mismatch⟩ :=
      nack_origin admissible stable different regime sentAt sentLate source target payload failure
        senderFound
    obtain ⟨floor, _⟩ :=
      retry_bounds admissible stable different regime wTerm wLog rTerm sentLate sentBefore.le
        senderFound beforeNode prevLe prevTerm mismatch
    have retryEq : retry before.log w request
        = findHighestPossibleMatch before.log response.lastLogIndex response.term := by
      rw [responseEq]
      rfl
    rw [value]
    omega
  · exact absurd (eligible index before began beforeNode) aimed

/-- A primary request sent above the retry floor is rejected beyond the agreement
or acknowledged exactly at it. Both outcomes record the actual emitted packet. -/
theorem answer (regime : Regime stable peer log agreed origin)
    (eligible
      : forall index state,
          origin <= index
          -> nodeAt trace index leader = some state
          -> peer ∈ eligiblePeers state leader)
    {index : Nat} {step : CCF.Execution.Step W Liveness.Event}
    (stepped : trace.stepAt index = some step) {packet : Packet}
    (event : step.action = .deliver packet) {sent : Nat}
    (sentAt : SentAt trace sent packet) (sentLate : origin <= sent)
    (sentBefore : sent < index) (source : packet.envelope.source = leader)
    (target : packet.envelope.target = peer) {request : AppendEntriesRequest}
    (payload : packet.envelope.payload = .appendEntriesRequest request)
    {before primary : NodeState} (found : nodeAt trace sent leader = some before)
    (leaderFound : nodeState (proto step.before) leader = some primary)
    (floor : agreed <= before.sentIndex peer)
    : request.term = term
      /\ before.sentIndex peer <= request.prevLogIndex
      /\ request.prevLogIndex + request.entries.length <= before.log.length
      /\ ((agreed < request.prevLogIndex
            /\ exists w,
                w.currentTerm = term
                /\ w.log = log
                /\ request.prevLogIndex <= primary.log.length
                /\ request.prevLogTerm = termAt primary.log request.prevLogIndex
                /\ Not
                    (termAt log request.prevLogIndex
                      = termAt primary.log request.prevLogIndex)
                /\ exists reply,
                    SentAt trace index reply
                    /\ reply.envelope
                        = {
                          source := peer
                          target := leader
                          payload := .appendEntriesResponse (nackResponse w request)
                        })
          \/ (request.prevLogIndex + request.entries.length = agreed
              /\ exists reply,
                  SentAt trace index reply
                  /\ reply.envelope
                      = {
                        source := peer
                        target := leader
                        payload :=
                          .appendEntriesResponse
                            { term, success := true, lastLogIndex := agreed }
                      })) := by
  obtain ⟨sending, _, _, sendStepped, -⟩ := admissible.sentAt_emitted sentAt
  have foundBefore : nodeState (proto sending.before) leader = some before := by
    rwa [nodeAt_before sendStepped] at found
  obtain ⟨rTerm, prevGe, endLe⟩ :=
    leader_request_shape admissible stable (regime.afterStart.trans sentLate) sendStepped
      foundBefore (by rw [target]; exact eligible sent before sentLate found)
      sentAt source payload
  rw [target] at prevGe
  obtain ⟨w, sends, wTerm, wLog, out, _, detail⟩ :=
    request_outcome admissible stable different regime stepped event (by omega) target payload leaderFound
  obtain ⟨_, prevLe, prevTerm, outcome⟩ := detail source
  have selected : step.action.action = some (.deliver packet.envelope) := by rw [event]; rfl
  refine ⟨rTerm, prevGe, endLe, ?_⟩
  rcases outcome with ⟨above, mismatch, sendsEq⟩ | ⟨_, _⟩ | ⟨_, sendsEq⟩
  · rw [sendsEq] at out
    obtain ⟨reply, replySent, replyEnvelope, -⟩ :=
      admissible.sentAt_of_emitted stepped selected out (List.mem_singleton_self _)
    exact Or.inl ⟨above, w, wTerm, wLog, prevLe, prevTerm, mismatch, reply, replySent, replyEnvelope⟩
  · omega
  · have reached : request.prevLogIndex + request.entries.length = agreed := by omega
    rw [sendsEq, reached] at out
    obtain ⟨reply, replySent, replyEnvelope, -⟩ :=
      admissible.sentAt_of_emitted stepped selected out (List.mem_singleton_self _)
    exact Or.inr ⟨reached, reply, replySent, replyEnvelope⟩

end Regime

omit different in
/-- The stable primary's match index never drops between recorded states. -/
theorem match_mono {index later : Nat} (afterStart : start <= index) (le : index <= later)
    {before after : NodeState} (found : nodeAt trace index leader = some before)
    (found' : nodeAt trace later leader = some after)
    : before.matchIndex peer <= after.matchIndex peer := by
  obtain ⟨first, firstFound, firstNode⟩ := nodeAt_eq_some.mp found
  obtain ⟨last, lastFound, lastNode⟩ := nodeAt_eq_some.mp found'
  have grows : forall i point, index <= i -> trace.stateAt i = some point
      -> forall state, nodeState (proto point) leader = some state
        -> before.matchIndex peer <= state.matchIndex peer :=
    trace.induction (start := index)
      (motive := fun _ point => forall state, nodeState (proto point) leader = some state
        -> before.matchIndex peer <= state.matchIndex peer)
      (fun point pointFound state nodeFound => by
        rw [firstFound, Option.some.injEq] at pointFound
        subst pointFound
        rw [firstNode, Option.some.injEq] at nodeFound
        subst state
        exact le_rfl)
      (fun i step le stepped ih next nextFound => by
        obtain ⟨_, current, currentFound, _⟩ :=
          stable.leads (afterStart.trans le) (Trace.stateAt_of_stepAt stepped)
        have beforeLe := ih current currentFound
        rcases (leader_move admissible stable peer (afterStart.trans le) stepped currentFound nextFound).1
            with same | ⟨_, _, _, _, _, _, _, _, value⟩ <;> omega)
  exact grows later last le lastFound after lastNode

end Peer

end CCFRaft.Proofs.Replication
