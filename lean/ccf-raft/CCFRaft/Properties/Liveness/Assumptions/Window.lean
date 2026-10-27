module

public import CCFRaft.Properties.Liveness.Model
public import CCFRaft.Properties.Liveness.Assumptions.Submitted

@[expose] public section

/-!
# Stable windows

The deterministic commit argument runs inside a window of real time in which
one primary is uncontested, live, quorate and reachable. The proof of
`Properties.commit_liveness` derives such a window from its starting snapshot
and runs the timed commit argument inside it. Every window predicate is bounded
by the window; none holds forever.
-/

open CCF.Execution (Trace)

namespace CCFRaft.Liveness

open Model.Node
open HasProtocol (proto)
open HasTime (time)
open HasLive (live)

/-- The local ledger has one active configuration, and every completed removal
has a committed retirement confirmation. An uncommitted confirmation is still
unfinished work. The sole initial configuration need not yet be committed. -/
def ReconfigurationSettled (state : NodeState) : Prop :=
  state.activeConfigurations.length = 1 /\ state.retirementCompletedNodes = ∅

instance (state : NodeState) : Decidable (ReconfigurationSettled state) := by
  unfold ReconfigurationSettled
  infer_instance

/-- Quiet among `participants`: no participant or message between participants
has moved past `term`, no participant is a pre-vote candidate in it, and
`leader` is its primary. Outstanding proposals are excluded separately, over the
packet ledger (`NoProposals`).
Nodes outside `participants`, such as a crashed or partitioned pre-vote
candidate of a newer term, are unconstrained; isolation keeps them from
reaching participants. -/
structure QuietAmong (participants : Finset NodeID) (leader : NodeID) (term : Nat)
    (state : Model.State)
    : Prop where
  terms
    : forall node local_,
        (node, local_) ∈ state.nodes -> node ∈ participants -> local_.currentTerm <= term
  preVotes
    : forall node local_,
        (node, local_) ∈ state.nodes
        -> node ∈ participants
        -> local_.role = .preVoteCandidate
        -> local_.currentTerm < term
  messages
    : forall envelope,
        envelope ∈ state.network
        -> envelope.source ∈ participants
        -> envelope.target ∈ participants
        -> envelope.payload.term <= term
  leader
    : exists local_,
        (leader, local_) ∈ state.nodes
        /\ local_.role = .primary
        /\ local_.currentTerm = term

/-- `QuietAmong` without its pre-vote clause: no participant or message between
participants has moved past `term`, and `leader` is its primary. Participants may be pre-vote
candidates of `term`; an anchor of nodes that grant no pre-vote keeps them from
winning. -/
structure QuietTerm (participants : Finset NodeID) (leader : NodeID) (term : Nat)
    (state : Model.State)
    : Prop where
  terms
    : forall node local_,
        (node, local_) ∈ state.nodes -> node ∈ participants -> local_.currentTerm <= term
  messages
    : forall envelope,
        envelope ∈ state.network
        -> envelope.source ∈ participants
        -> envelope.target ∈ participants
        -> envelope.payload.term <= term
  leader
    : exists local_,
        (leader, local_) ∈ state.nodes
        /\ local_.role = .primary
        /\ local_.currentTerm = term

/-- A term quiet among participants is quiet without its pre-vote clause. -/
theorem QuietAmong.quietTerm {participants : Finset NodeID} {leader : NodeID} {term : Nat}
    {state : Model.State} (quiet : QuietAmong participants leader term state)
    : QuietTerm participants leader term state :=
  ⟨quiet.terms, quiet.messages, quiet.leader⟩

variable {W : Type} [HasProtocol W Model.State] [HasTime W] [HasLive W]

/-- No outstanding packet between participants proposes a vote in `term`.

Over the packet ledger, not the protocol network. A drop is an environment
event that leaves the protocol state alone, so a dropped envelope stays in the
network for ever but can never be delivered. Over the network, a proposal for
`term` dropped before the start would rule out every quiet window (CE-I4). -/
def NoProposals [HasNetwork W] (participants : Finset NodeID) (term : Nat) (point : W)
    : Prop :=
  forall packet,
    packet ∈ HasNetwork.pending point
    -> packet.envelope.source ∈ participants
    -> packet.envelope.target ∈ participants
    -> Not (packet.envelope.payload = .proposeRequestVoteRequest term)

namespace Window

/-- Throughout the window `leader` is the primary of `term`, and `term` is the
newest term among `participants`: no participant, participant pre-vote
candidate, or message or proposal between participants has moved past it. -/
def StableLeader [HasNetwork W] (trace : Trace W Event) (start : Nat) (duration : Real)
    (leader : NodeID) (term : Nat) (participants : Finset NodeID)
    : Prop :=
  forall index point,
    Within trace start duration index
    -> trace.stateAt index = some point
    -> QuietAmong participants leader term (proto point)
        /\ NoProposals participants term point

/-- `StableLeader` without the pre-vote clause: throughout the window `leader` is
the primary of `term`, and no participant, or message or proposal between
participants, has moved past it. Participants outside an anchor may be pre-vote
candidates of `term`. -/
def StableTerm [HasNetwork W] (trace : Trace W Event) (start : Nat) (duration : Real)
    (leader : NodeID) (term : Nat) (participants : Finset NodeID)
    : Prop :=
  forall index point,
    Within trace start duration index
    -> trace.stateAt index = some point
    -> QuietTerm participants leader term (proto point)
        /\ NoProposals participants term point

/-- Throughout the window the primary is live and its retirement has not committed. -/
structure StaysActive (trace : Trace W Event) (start : Nat) (duration : Real)
    (leader : NodeID)
    : Prop where
  live
    : forall index point,
        Within trace start duration index
        -> trace.stateAt index = some point
        -> leader ∈ live point
  notRetired
    : forall index point state,
        Within trace start duration index
        -> trace.stateAt index = some point
        -> CCF.MultiNodeTransitionSystem.nodeState (proto point) leader = some state
        -> Not (state.isRetiredCommitted leader)

/-- Throughout the window every configuration active at the primary has a live
majority among `participants`. -/
def LiveQuorum (trace : Trace W Event) (start : Nat) (duration : Real) (leader : NodeID)
    (participants : Finset NodeID)
    : Prop :=
  forall index point state,
    Within trace start duration index
    -> trace.stateAt index = some point
    -> CCF.MultiNodeTransitionSystem.nodeState (proto point) leader = some state
    -> hasQuorum state.activeConfigurations (Inter.inter (live point) participants)

/-- Reconfiguration work is finished at the leader throughout the window.
This excludes both inherited cleanup and new pending configuration changes,
without requiring followers to have learned that completion. It is separate
from `StableWindow`: stable leadership alone does not finish retirement work. -/
def ReconfigurationSettled (trace : Trace W Event) (start : Nat) (duration : Real)
    (leader : NodeID)
    : Prop :=
  forall index point state,
    Within trace start duration index
    -> trace.stateAt index = some point
    -> CCF.MultiNodeTransitionSystem.nodeState (proto point) leader = some state
    -> Liveness.ReconfigurationSettled state

/-- No packet between the primary and a participant is dropped in the window.
With `boundedDelayModel maxDelay`, each is delivered within `maxDelay`. -/
def Lossless (trace : Trace W Event) (start : Nat) (duration : Real) (leader : NodeID)
    (participants : Finset NodeID)
    : Prop :=
  forall index step packet,
    Within trace start duration index
    -> trace.stepAt index = some step
    -> step.action = .drop packet
    -> Not
        ((packet.envelope.source = leader /\ packet.envelope.target ∈ participants)
          \/ (packet.envelope.source ∈ participants /\ packet.envelope.target = leader))

end Window

/-- A window of real time, from index `start` for `duration`, in which `leader`
is the uncontested primary of `term`, stays live and unretired, keeps a live
majority among `participants`, and exchanges packets with them without loss. -/
structure StableWindow [HasNetwork W] (trace : Trace W Event) (start : Nat)
    (duration : Real) (leader : NodeID) (term : Nat) (participants : Finset NodeID)
    : Prop where
  stableLeader : Window.StableLeader trace start duration leader term participants
  staysActive : Window.StaysActive trace start duration leader
  liveQuorum : Window.LiveQuorum trace start duration leader participants
  lossless : Window.Lossless trace start duration leader participants

/-- The length of the common prefix of two logs. -/
def agreedPrefix (leaderLog followerLog : List Entry) : Nat :=
  ((leaderLog.zip followerLog).takeWhile fun pair => decide (pair.1 = pair.2)).length

/-- At `start`, for every participant, the primary's log beyond their common
prefix spans at most `backlog` distinct terms (terms, not entries). A rejected AppendEntries moves the
primary's probe back past a whole term of its log (CCF's
`find_highest_possible_match`), so catching a participant up takes at most two
rounds per such term, plus two for the entries the primary appends in its own
term. A log `n` entries beyond the common prefix spans at most `n` terms. -/
def BacklogTerms (trace : Trace W Event) (start : Nat) (leader : NodeID)
    (participants : Finset NodeID) (backlog : Nat)
    : Prop :=
  forall first leaderState follower followerState,
    trace.stateAt start = some first
    -> CCF.MultiNodeTransitionSystem.nodeState (proto first) leader = some leaderState
    -> follower ∈ participants
    -> CCF.MultiNodeTransitionSystem.nodeState (proto first) follower = some followerState
    -> ((leaderState.log.drop (agreedPrefix leaderState.log followerState.log)).map
          Entry.term).toFinset.card
        <= backlog

/-- At `start` every participant is a node that has adopted `term`. With
`Window.LiveQuorum`, a live quorum is then in `term` throughout the window. The
voters that elected `leader` qualify, as do nodes that acknowledged its
AppendEntries: terms only grow, and `Window.StableLeader` caps them at `term`.
Naming the voters instead would be too strong, since a reconfiguration in `term`
can leave them short of a quorum of the active configuration.
Needed: a participant behind `term` still accepts AppendEntries of an older term.
Let `leader` and another node alternate as primary for `2 n` terms, each appending
one entry per term, with `leader`'s entries replicated to a participant and the
other's to nobody. A delayed AppendEntries from the other's last term can then
replace that participant's log, which matched `leader`'s at `start`, with `n`
entries of alternating terms. Each rejection moves the primary's probe back one
entry, so catching it up takes `n` rounds for any `n`. -/
def InTermAt (trace : Trace W Event) (start : Nat) (term : Nat)
    (participants : Finset NodeID)
    : Prop :=
  forall follower,
    follower ∈ participants
    -> exists first state,
        trace.stateAt start = some first
        /\ CCF.MultiNodeTransitionSystem.nodeState (proto first) follower = some state
        /\ state.currentTerm = term

/-- At `start` the primary's log holds `request`, or the step at `start` appends
it. A longer stable window may be cut down to start here. -/
def SubmittedAt (trace : Trace W Event) (start : Nat) (leader : NodeID) (request : ReqID)
    : Prop :=
  (exists point state,
    trace.stateAt start = some point
    /\ CCF.MultiNodeTransitionSystem.nodeState (proto point) leader = some state
    /\ HasRequest state.log request)
  \/ exists step entries,
      trace.stepAt start = some step
      /\ step.action = .local leader (.append entries)
      /\ .transaction request {} ∈ entries

end CCFRaft.Liveness
