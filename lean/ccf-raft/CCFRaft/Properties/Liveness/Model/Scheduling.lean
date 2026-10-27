module

public import CCFRaft.Properties.Liveness.Model.Timing

@[expose] public section

/-!
CCF background-task scheduling assumptions and election-timer spacing.
Background tasks take an optional real-time bound: `none` requires only eventual
execution, `some bound` additionally requires it before `bound` has elapsed.
`ElectionSpacing` is only the minimum-delay constraint; `ElectionScheduling` in
`Model.Timers` combines it with election-timeout progress.
Network delivery is bounded separately, by `boundedDelayModel`.
-/

open CCF.Execution (Trace)

namespace CCFRaft.Liveness

open Model.Node

open HasProtocol (proto)
open HasTime (time)
open HasLive (live)

variable {W : Type} [HasProtocol W Model.State] [HasTime W] [HasLive W]

/-- Abstract wall-clock bounds. -/
structure Bounds where
  /-- An upper bound on the real time a primary takes to complete a due
  heartbeat send pass. CCF sends once `request_timeout` has elapsed, checked on
  each `periodic` tick (`raft.h`, `Aft::periodic`). This includes the tick delay
  and the work of issuing every batch, not just starting the first batch. -/
  heartbeatInterval : Real
  /-- Twice a lower bound on the real time from an election-timer reset to an
  election timeout. CCF draws a timeout between half and all of its configured
  `election_timeout` (`raft.h`, `restart_election_timeout`), but counts it in
  `periodic` ticks on the node's own clock, and the first tick after a reset also
  counts the time before it. So this is at most `election_timeout` minus twice
  the tick interval, and less if node clocks drift. -/
  electionTimeout : Real
  /-- An upper bound on the real time a primary with unsigned entries takes to
  append a signature. CCF signs once `sig_ms_interval` elapses, checked on each
  tick, so this is at least that plus the tick interval. -/
  signatureInterval : Real

/-- No deadline, or at most `bound` after `origin`. -/
def Deadline (bound : Option Real) (origin point : W) : Prop :=
  match bound with
  | none => True
  | some bound => time point <= time origin + bound

/-- Whenever `Due` holds, it later ceases to hold or `Fires` runs, from a state
within the optional bound. A due obligation must resolve before a finite
execution ends. -/
def Scheduled (trace : Trace W Event) (bound : Option Real) (Due : W -> Prop)
    (Fires : CCF.Execution.Step W Event -> Prop)
    : Prop :=
  forall index point,
    trace.stateAt index = some point
    -> Due point
    -> Eventually trace index
        fun later laterPoint =>
          Deadline bound point laterPoint
          /\ (Not (Due laterPoint)
              \/ exists step, trace.stepAt later = some step /\ Fires step)

/-- An active primary with an eligible, live replication peer. -/
def PeerDue (point : W) (leader peer : NodeID) : Prop :=
  Membership.mem (live point) leader
  /\ Membership.mem (live point) peer
  /\ exists state,
      CCF.MultiNodeTransitionSystem.nodeState (proto point) leader = some state
      /\ state.role = .primary
      /\ Not (state.isRetiredCommitted leader)
      /\ peer ∈ eligiblePeers state leader

/-- A send pass to `peer`. CCF's `send_append_entries` sends every batch from the
peer's `sent_idx` to the primary's `last_idx` under the consensus lock, so the
model's `sendEntries` is the whole pass and always reaches the log end. -/
def SendPass (step : CCF.Execution.Step W Event) (leader peer : NodeID) : Prop :=
  exists batchEnds, step.action = .local leader (.sendEntries peer batchEnds)

/-- A primary sends AppendEntries from `sent_idx + 1` to every other node each
time `request_timeout` elapses (`raft.h`, `Aft::periodic`); `eligiblePeers`
is a subset of `all_other_nodes`, from which CCF drops a node only once its
retirement confirmation commits (`set_retired_committed`). Needed: without it a
primary that appends a signature and then never sends again leaves a lagging
follower, whose acknowledgement the signature needs, behind forever.
With `some bound`, a send pass must happen within the deadline.
Needed: if the primary could wait longer than half an election timeout between
heartbeats, a follower could time out and depose it. -/
def HeartbeatScheduling (trace : Trace W Event) (bound : Option Real) : Prop :=
  forall leader peer,
    Scheduled trace bound (fun point => PeerDue point leader peer)
      (fun step => SendPass step leader peer)

/-- Unsigned entries or a signature from an older term require a new signature. -/
def SignatureDue (point : W) (leader : NodeID) : Prop :=
  Membership.mem (live point) leader
  /\ exists state,
      CCF.MultiNodeTransitionSystem.nodeState (proto point) leader = some state
      /\ state.role = .primary
      /\ Not (state.isRetiredCommitted leader)
      /\ (maxCommittableIndex state.log < state.log.length
          \/ maxCommittableTerm state.log ≠ state.currentTerm)

/-- The input actually appends a signature, rather than merely enabling one. -/
def Signs (step : CCF.Execution.Step W Event) (leader : NodeID) : Prop :=
  exists entries,
    step.action = .local leader (.append entries) /\ List.Mem .signature entries

/-- CCF's periodic signature task signs every `sig_ms_interval` when there are
unsigned entries (`committable_gap() > 0`) or the consensus asks for one
(`src/node/history.h`, `start_signature_emit_timer`); `raft.h` asks
(`get_signature_disposition`) while `should_sign`, which `become_leader` sets.
Needed: otherwise a stable, reliable execution with a submitted request may
never commit because it never signs. CCF signs within `sig_ms_interval`, which
bounds the commit time in `Properties.commit_liveness`. -/
def SignatureScheduling (trace : Trace W Event) (bound : Option Real) : Prop :=
  forall leader,
    Scheduled trace bound (fun point => SignatureDue point leader)
      (fun step => Signs step leader)

/-- `leader` is a primary at `point`. -/
def IsPrimary (point : W) (leader : NodeID) : Prop :=
  exists state,
    CCF.MultiNodeTransitionSystem.nodeState (proto point) leader = some state
    /\ state.role = .primary

/-- The step zeroes `leader`'s `last_ack_timeout` for `peer` (`raft.h`): the
primary receives an AppendEntries response from `peer`
(`recv_append_entries_response`), `leader` becomes primary, which zeroes it
for every peer (`become_leader`), or the primary starts tracking `peer`
(`create_and_remove_node_state`), modelled as `peer` joining its
`eligiblePeers`. While primary this happens only when it appends a configuration
naming a new member. CCF also zeroes it on stepping down, and when a non-primary
starts tracking a peer, and treats untracked members as live; omitting these only
lets `CheckQuorumScheduling` permit more step-downs. -/
def AckReset (step : CCF.Execution.Step W Event) (leader peer : NodeID) : Prop :=
  (IsPrimary step.before leader
    /\ exists packet response,
        step.action = .deliver packet
        /\ packet.envelope.source = peer
        /\ packet.envelope.target = leader
        /\ packet.envelope.payload = .appendEntriesResponse response)
  \/ (Not (IsPrimary step.before leader) /\ IsPrimary step.after leader)
  \/ exists before after,
      CCF.MultiNodeTransitionSystem.nodeState (proto step.before) leader = some before
      /\ before.role = .primary
      /\ CCF.MultiNodeTransitionSystem.nodeState (proto step.after) leader = some after
      /\ after.role = .primary
      /\ peer ∉ eligiblePeers before leader
      /\ peer ∈ eligiblePeers after leader

/-- Before `index`, some `AckReset` of `leader` for `peer` happened strictly
after time `since`. -/
def AckedAfter (trace : Trace W Event) (index : Nat) (leader peer : NodeID) (since : Real)
    : Prop :=
  exists earlier reset,
    earlier < index
    /\ trace.stepAt earlier = some reset
    /\ AckReset reset leader peer
    /\ since < time reset.before

/-- CCF's quorum check (`raft.h`, `Aft::periodic`): a primary steps down only
when some active configuration has no majority of nodes it counts as live,
namely itself and every peer with an `AckReset` less than `window` before the
check. A new primary therefore keeps its role for at least `window`.
Pass `Bounds.electionTimeout`. CCF compares a tick-counted acknowledgement age
with its configured `election_timeout`, and counting from the previous tick
overstates the real age by at most one tick, so the real-time window may be
anything up to `election_timeout` less a tick.
This models only the guard: CCF also steps down as soon as the check fails,
but no theorem needs that.
Needed: the protocol's `checkQuorum` step-down is otherwise unconstrained, so
every new primary of a multi-node configuration may step down before it
signs, and no request need ever commit. -/
def CheckQuorumScheduling (trace : Trace W Event) (window : Real) : Prop :=
  forall index step leader,
    trace.stepAt index = some step
    -> step.action = .local leader (.timeout .checkQuorum)
    -> exists state,
        CCF.MultiNodeTransitionSystem.nodeState (proto step.before) leader = some state
        /\ exists configuration,
            configuration ∈ state.activeConfigurations
            /\ Not
                (exists responders,
                  hasConfigurationMajority responders configuration
                  /\ forall peer,
                      peer ∈ responders
                      -> peer = leader
                          \/ AckedAfter trace index leader peer
                              (time step.before - window))

/-- Steps that call `restart_election_timeout` in CCF: starting a pre-vote or
regular election, stepping down on a quorum check, adopting a newer term,
granting a regular vote, or accepting an AppendEntries term/log check.
On a valid protocol step, an increased local term records `become_candidate` or
`become_aware_of_new_term`; inspecting the actual transition preserves the
message-specific guards (unknown responses, non-primary AE responses, and vote
proposals cannot cause spurious resets).
A same-term AppendEntries also resets a candidate through `become_follower`,
even if its log check fails; an established follower resets only after that
check. Multiple resets within one atomic step record the final draw. -/
def ElectionReset (step : CCF.Execution.Step W Event) (node : NodeID) : Prop :=
  match step.action with
  | .local actor (.timeout _) => actor = node
  | .deliver packet =>
      packet.envelope.target = node
      /\ match CCF.MultiNodeTransitionSystem.nodeState (proto step.before) node with
          | none => False
          | some state =>
              (match CCF.MultiNodeTransitionSystem.nodeState (proto step.after) node with
                | some after => state.currentTerm < after.currentTerm
                | none => False)
              \/ match packet.envelope.payload with
                  | .appendEntriesRequest request =>
                      state.currentTerm < request.term
                      \/ (state.currentTerm = request.term
                          /\ (state.role = .candidate
                              \/ state.role = .preVoteCandidate
                              \/ termAt state.log request.prevLogIndex
                                  = request.prevLogTerm))
                  | .requestVoteRequest request =>
                      state.currentTerm = request.term
                      /\ voteLogUpToDate state request
                      /\ !state.primaryKnown
                      /\ (state.votedFor = none
                          \/ state.votedFor = some packet.envelope.source)
                  | _ => False
  | _ => False

/-- The spacing component of `ElectionScheduling`: no election timeout within
`minimum` of a reset; `none` adds no spacing constraint.
This alone does not require a timeout to fire. Pass half of `Bounds.electionTimeout`.
Needed: without it any node may time out at any time, and depose the primary. -/
def ElectionSpacing (trace : Trace W Event) (minimum : Option Real) : Prop :=
  match minimum with
  | none => True
  | some minimum =>
      forall earlier index reset timeout node,
        earlier < index
        -> trace.stepAt earlier = some reset
        -> trace.stepAt index = some timeout
        -> timeout.action = .local node (.timeout .election)
        -> ElectionReset reset node
        -> time reset.before + minimum <= time timeout.before

end CCFRaft.Liveness
