module

public import DisasterRecovery.Properties.Utils
public import CCF.Execution
public import DisasterRecovery.Model

import CCF.Lemma
import all Init.Control.State

@[expose] public section

namespace DisasterRecovery.Proofs.Trace

open CCF
variable {State : Type}

/-- Enabled steps through the listed successor states, from a start state to a final state. -/
private inductive Path (system : TransitionSystem)
    : system.State -> List system.State -> system.State -> Prop where
  /-- An empty path starts and ends at the same state. -/
  | nil (state) : Path system state [] state
  /-- Prepend one enabled step and its successor to the remaining path. -/
  | cons {before middle after tail} {action}
    (step : system.step before action = some middle)
    (rest : Path system middle tail after)
    : Path system before (middle :: tail) after

private lemma Path.reachable {system : TransitionSystem} {before tail after}
    (path : Path system before tail after) (reachable : system.Reachable before)
    : system.Reachable after := by
  induction path with
  | nil => exact reachable
  | cons step _ ih => exact ih (.step reachable step)

end DisasterRecovery.Proofs.Trace

namespace DisasterRecovery.Proofs.Execution.Local

open CCF (TransitionSystem)

export DisasterRecovery.Model.Local (
  Location TxID Phase OpenKind Validation Config NodeState Event
  initialNode voteQuorum validTimeout txScoreGreater
  selectMaximum maximumGossip insertGossip insertVote advanceTimeoutState
  advanceTimeoutLane
)

/-- Proof-only representation of the local model's sends and notifications. -/
private inductive Effect where
  /-- Send the source location's recovered transaction ID to a destination. -/
  | sendGossip (destination : Location)
  /-- Vote for the destination as the recovery location. -/
  | sendVote (destination : Location)
  /-- Tell the destination that the source is opening the service. -/
  | sendIAmOpen (destination : Location)
  /-- Notify the host that opening should begin with the given evidence. -/
  | opening (kind : OpenKind)
  /-- Notify the host to restart against the chosen location. -/
  | restart (chosen : Location)
  /-- Notify the host that recovery has completed. -/
  | completed
  /-- Report a rejected event without changing the local state. -/
  | rejected (reason : String)

/-- Extracts a host notification from an effect, ignoring sends. -/
private def Effect.diagnostic : Effect -> Option Model.Local.Notification
  | .opening kind => some (.opening kind)
  | .restart chosen => some (.restart chosen)
  | .completed => some .completed
  | .rejected reason => some (.rejected reason)
  | _ => none

/-- Converts send effects into model envelopes, supplying the sender's recovered TxID. -/
private def messages (source : Location) (recovered : TxID) (effects : List Effect)
    : List Model.Envelope :=
  effects.filterMap
    fun effect =>
      match effect with
      | .sendGossip target => some { source, target, payload := .gossip recovered }
      | .sendVote target => some { source, target, payload := .vote }
      | .sendIAmOpen target => some { source, target, payload := .iAmOpen }
      | _ => none

/-- Instrumented local-step result, including rejection status and ordered effects. -/
private structure StepOutput where
  /-- Local state after executing the step. -/
  state : NodeState
  /-- Sends and notifications produced by the step, in emission order. -/
  effects : List Effect := []
  /-- Whether the local transition accepted the event. -/
  accepted : Bool := true

/-- The node-state table used by decorated executions. -/
private structure SystemState where
  /-- Current state of each stored recovery node. -/
  nodes : List (Prod Location NodeState)

/-- Instrumented phase advance with the same notifications as the executable model. -/
private def advance (config : Config) (state : NodeState) (timeout : Bool)
    : Option StepOutput :=
  let aligned := validTimeout state timeout
  match state.phase with
  | .gossiping =>
      if decide (state.gossips.length >= config.expectedLocations.length) || aligned then
        match maximumGossip state.gossips with
        | none => none
        | some (chosen, _) =>
            let next := { state with phase := .voting, chosen := some chosen }
            some { state := advanceTimeoutLane next timeout }
      else
        some { state := advanceTimeoutLane state timeout }
  | .voting =>
      let sufficient := decide (state.votes.length >= voteQuorum config)
      if sufficient || aligned then
        if aligned && state.votes.isEmpty then
          some { state }
        else
          let kind := if aligned && !sufficient then .failover else .quorum
          let next :=
            {
              state with
                phase := .opening
                openKind := some kind
            }
          some
            {
              state := advanceTimeoutLane next timeout
              effects := [.opening kind]
            }
      else
        some { state := advanceTimeoutLane state timeout }
  | .joining =>
      match state.chosen with
      | none => none
      | some chosen =>
          some
            {
              state := advanceTimeoutLane { state with restartRequested := true } timeout
              effects := [.restart chosen]
            }
  | .opening =>
      if aligned then
        some
          {
            state := advanceTimeoutLane { state with phase := .open } timeout
            effects := [.completed]
          }
      else
        some { state := advanceTimeoutLane state timeout }
  | .open =>
      some { state := advanceTimeoutLane state timeout }

/-- A rejected event that preserves state and records its diagnostic. -/
private def rejected (state : NodeState) (reason : String) : StepOutput :=
  { state, effects := [.rejected reason], accepted := false }

/-- Local instrumentation whose disabled transitions are converted to stutters by `step`. -/
private abbrev transitionSystem (config : Config) (location : Location)
    : TransitionSystem where
  State := StepOutput
  Action := Event
  init := fun current => current = { state := initialNode location }
  step current event :=
    let state := current.state
    match event with
    | .receiveGossip source txid validation => do
        guard (validation = .accepted)
        guard (state.chosen = none)
        let received := { state with gossips := insertGossip source txid state.gossips }
        advance config received false
    | .receiveVote source validation => do
        guard (validation = .accepted)
        let received := { state with votes := insertVote source state.votes }
        advance config received false
    | .receiveIAmOpen source validation => do
        guard (validation = .accepted)
        guard (state.phase ≠ .opening ∧ state.phase ≠ .open)
        let received :=
          {
            state with
              phase := .joining
              chosen := some source
          }
        advance config received false
    | .timeout =>
        advance config state true
    | .retry =>
        let effects :=
          match state.phase with
          | .gossiping =>
              config.expectedLocations.map .sendGossip
          | .voting =>
              match state.chosen with
              | none => config.expectedLocations.map .sendGossip
              | some chosen =>
                  .sendVote chosen :: config.expectedLocations.map .sendGossip
          | .opening =>
              (config.expectedLocations.filter
                (fun location => location != state.location)).map
                .sendIAmOpen
          | .joining | .open => []
        pure { state, effects }

/-- The diagnostic associated with a disabled instrumented local event. -/
private def rejectionReason (state : NodeState) : Event -> String
  | .receiveGossip _ _ .rejected
  | .receiveVote _ .rejected
  | .receiveIAmOpen _ .rejected => "quote-or-certificate"
  | .receiveGossip _ _ .accepted =>
      if state.chosen != none then "gossip-frozen" else "empty-gossip-advance"
  | .receiveVote _ .accepted => "vote-advance"
  | .receiveIAmOpen _ .accepted =>
      match state.phase with
      | .opening | .open => "already-opening-or-open"
      | _ => "join-without-chosen"
  | .timeout => "empty-gossip-timeout-aborts"
  | .retry => "retry-disabled"

/-- Preserve rejected receives as stutters for the global delivery model. -/
private def step (config : Config) (state : NodeState) (event : Event) : StepOutput :=
  ((transitionSystem config state.location).step { state } event).getD
    (rejected state (rejectionReason state event))

/-- Replaces a node's local state without changing the node table's keys or order. -/
private def replaceNode
    (target : Location)
    (next : NodeState)
    (nodes : List (Prod Location NodeState))
    : List (Prod Location NodeState) :=
  nodes.map fun entry => if entry.1 == target then (target, next) else entry

/-- Executes a local event on a known node and updates its entry in the node table. -/
private def systemStep (config : Config) (state : SystemState) (target : Location)
    (event : Event)
    : Option (Prod SystemState StepOutput) := do
  let node <- (state.nodes.find? fun entry => entry.1 == target).map Prod.snd
  let output := step config node event
  pure ({ nodes := replaceNode target output.state state.nodes }, output)

end DisasterRecovery.Proofs.Execution.Local

namespace DisasterRecovery.Proofs.Execution.Global

open CCF (TransitionSystem)
open Local

@[inherit_doc Model.Config]
private abbrev Config := Model.Config

@[inherit_doc Model.Config.Valid]
private abbrev Config.Valid (config : Config) := Model.Config.Valid config

@[inherit_doc Model.recoveredTxID]
private def recoveredTxID (config : Config) (source : Location) : Option TxID :=
  (config.recovered.find? fun entry => entry.1 == source).map Prod.snd

@[inherit_doc DisasterRecovery.Model.Local.Message]
private abbrev Payload := DisasterRecovery.Model.Local.Message

/-- A queued message decorated with the sender's state at emission time. -/
private structure Envelope where
  /-- The node that emitted the message. -/
  source : Location
  /-- The node to which the message is addressed. -/
  target : Location
  /-- The recovery message content. -/
  payload : Payload
  /-- The sender's local state when the message was emitted. -/
  sourceState : NodeState
deriving BEq, ReflBEq, LawfulBEq

/-- A recorded opening notification and the local state that produced it. -/
private structure Opening where
  /-- The node that started opening. -/
  node : Location
  /-- Whether the opening was by quorum or failover. -/
  kind : OpenKind
  /-- The node's state after the step that emitted the notification. -/
  state : NodeState

/-- The network decorated with send snapshots and terminal-notification histories. -/
private structure State where
  /-- Current local states of the stored recovery nodes. -/
  system : SystemState
  /-- Messages still queued for delivery. -/
  network : List Envelope := []
  /-- All messages emitted so far, retaining their send-time snapshots. -/
  sent : List Envelope := []
  /-- Recorded openings, newest first. -/
  openings : List Opening := []
  /-- Nodes that requested a restart, newest first. -/
  restarts : List Location := []
  /-- Nodes that completed opening, newest first. -/
  completed : List Location := []

/-- A retry, delivery, or timeout in the decorated network. -/
private inductive Action where
  /-- Emit a location's current retry messages with their source-state snapshots. -/
  | retry (source : Location)
  /-- Deliver one queued instrumented envelope to its target. -/
  | deliver (envelope : Envelope)
  /-- Fire a timeout at the target location. -/
  | timeout (target : Location)

/-- Looks up a node's current state in the decorated network. -/
private def nodeState (state : State) (node : Location) : Option NodeState :=
  (state.system.nodes.find? fun entry => entry.1 == node).map Prod.snd

/-- Decorates a send effect with its sender and send-time state; ignores notifications. -/
private def messageForEffect (config : Config) (source : Location)
    (sourceState : NodeState)
    : Effect -> Option Envelope
  | .sendGossip target => do
      let txid <- recoveredTxID config source
      pure { source, target, payload := .gossip txid, sourceState }
  | .sendVote target =>
      some { source, target, payload := .vote, sourceState }
  | .sendIAmOpen target =>
      some { source, target, payload := .iAmOpen, sourceState }
  | _ => none

/-- The decorated messages emitted by a node's retry. -/
private def retryMessages (config : Config) (source : Location) (sourceState : NodeState)
    : List Envelope :=
  (step config.protocol sourceState .retry).effects.filterMap
    (messageForEffect config source sourceState)

/-- The envelope was emitted by a retry of the node identified in its snapshot. -/
private def Envelope.Valid (config : Config) (envelope : Envelope) : Prop :=
  envelope.sourceState.location = envelope.source
  /\ envelope ∈ retryMessages config envelope.source envelope.sourceState

/-- The accepted receive event corresponding to a decorated envelope. -/
private def eventFor (envelope : Envelope) : Event :=
  match envelope.payload with
  | .gossip txid => .receiveGossip envelope.source txid .accepted
  | .vote => .receiveVote envelope.source .accepted
  | .iAmOpen => .receiveIAmOpen envelope.source .accepted

/-- Removes one queued copy of a value, preserving any other identical copies. -/
private def removeOne {α : Type _} [BEq α] (value : α) : List α -> List α
  | [] => []
  | head :: tail =>
      if head == value then tail else head :: removeOne value tail

/-- Adds a terminal notification to its proof-only history. -/
private def recordEffect (node : Location) (nodeState : NodeState) (state : State)
    : Effect -> State
  | .opening kind =>
      { state with openings := { node, kind, state := nodeState } :: state.openings }
  | .restart _ =>
      { state with restarts := node :: state.restarts }
  | .completed =>
      { state with completed := node :: state.completed }
  | _ => state

/-- Records terminal notifications from a step in emission order. -/
private def recordEffects
    (node : Location)
    (nodeState : NodeState)
    (effects : List Effect)
    (state : State)
    : State :=
  effects.foldl (recordEffect node nodeState) state

/-- Initializes the given nodes with empty queues and histories. -/
private def initial (config : Config)
    (nodes : List Location := config.protocol.expectedLocations)
    : State :=
  { system := { nodes := nodes.map fun node => (node, initialNode node) } }

/-- Executes a decorated network action and updates its proof-only histories. -/
private def next (config : Config) (state : State) : Action -> Option State
  | .retry source => do
      guard (recoveredTxID config source).isSome
      let sourceState <- nodeState state source
      let messages := retryMessages config source sourceState
      guard (!messages.isEmpty)
      pure
        {
          state with
            network := state.network ++ messages
            sent := state.sent ++ messages
        }
  | .deliver envelope => do
      guard (state.network.contains envelope)
      guard (recoveredTxID config envelope.target).isSome
      let (system, output) <- systemStep config.protocol state.system envelope.target
                                (eventFor envelope)
      let delivered :=
        {
          state with
            system
            network := removeOne envelope state.network
        }
      pure (recordEffects envelope.target output.state output.effects delivered)
  | .timeout target => do
      guard (recoveredTxID config target).isSome
      let (system, output) <- systemStep config.protocol state.system target .timeout
      guard output.accepted
      pure (recordEffects target output.state output.effects { state with system })

/-- The decorated execution system with valid recovery configurations. -/
private abbrev transitionSystem (config : Config) : TransitionSystem where
  State := State
  Action := Action
  init :=
    fun state =>
      config.Valid
      /\ exists nodes : List Location,
          nodes.Nodup
          /\ (forall node, node ∈ config.protocol.expectedLocations -> node ∈ nodes)
          /\ state = initial config nodes
  step := next config

/-- States reachable by enabled actions in the decorated execution system. -/
private abbrev Reachable (config : Config) : State -> Prop :=
  (transitionSystem config).Reachable

end DisasterRecovery.Proofs.Execution.Global

namespace DisasterRecovery.Proofs.Predicates

open Execution.Local hiding Config
open Execution.Global

/-- Only configured nodes appear in terminal-notification histories. -/
private structure HistoriesConfigured (config : Config) (state : State) : Prop where
  /-- Only configured locations have recorded opening notifications. -/
  openings
    : forall opening,
        opening ∈ state.openings -> opening.node ∈ config.protocol.expectedLocations
  /-- Only configured locations have recorded restart notifications. -/
  restarts
    : forall node, node ∈ state.restarts -> node ∈ config.protocol.expectedLocations
  /-- Only configured locations have recorded completion notifications. -/
  completed
    : forall node, node ∈ state.completed -> node ∈ config.protocol.expectedLocations

/-- Node identities and message provenance are consistent. -/
private structure WellFormed (config : Config) (state : State) : Prop where
  /-- Every configured location has a node-table entry; unused nodes may also exist. -/
  nodeKeys
    : forall node,
        node ∈ config.protocol.expectedLocations -> node ∈ state.system.nodes.map Prod.fst
  /-- Each location has at most one node-table entry. -/
  nodeKeysNodup : (state.system.nodes.map Prod.fst).Nodup
  /-- Every local state's location agrees with its node-table key. -/
  nodeLocations : forall entry, entry ∈ state.system.nodes -> entry.2.location = entry.1
  /-- Recovered ledgers belong exactly to the configured locations. -/
  recoveredKeys : config.recovered.map Prod.fst = config.protocol.expectedLocations
  /-- Every recorded send has valid local-step evidence. -/
  sentValid : forall envelope, envelope ∈ state.sent -> envelope.Valid config
  /-- Only configured locations have sent messages. -/
  sentSourceConfigured
    : forall envelope,
        envelope ∈ state.sent -> envelope.source ∈ config.protocol.expectedLocations
  /-- Every queued envelope has a corresponding recorded send. -/
  networkSent : forall envelope, envelope ∈ state.network -> envelope ∈ state.sent
  /-- Host-notification histories refer only to configured locations. -/
  historiesConfigured : HistoriesConfigured config state

/-- A vote from `voter` to `target` appears in the send history. -/
private def SentVote (state : State) (voter target : Location) : Prop :=
  exists envelope,
    envelope ∈ state.sent
    /\ envelope.source = voter
    /\ envelope.target = target
    /\ envelope.payload = .vote

/-- Every node's received-vote collection contains distinct voters. -/
private def NodeVotesNodup (state : State) : Prop :=
  forall entry, entry ∈ state.system.nodes -> entry.2.votes.Nodup

/-- Every received vote has a corresponding vote in the send history. -/
private def NodeVotesSent (state : State) : Prop :=
  forall entry,
    entry ∈ state.system.nodes
    -> forall voter, voter ∈ entry.2.votes -> SentVote state voter entry.1

/-- Each voter has sent votes to at most one target. -/
private def SentVotesFunctional (state : State) : Prop :=
  forall voter first second,
    SentVote state voter first -> SentVote state voter second -> first = second

/-- A sent vote's source no longer gossips and keeps its chosen target while voting. -/
private def SentVoteStable (state : State) : Prop :=
  forall envelope,
    envelope ∈ state.sent
    -> envelope.payload = .vote
    -> forall entry,
        entry ∈ state.system.nodes
        -> entry.1 = envelope.source
        -> entry.2.phase ≠ .gossiping
            /\ (entry.2.phase = .voting -> entry.2.chosen = some envelope.target)

/-- The chosen node is the maximum-scoring gossip source. -/
private def NodeVotingSelection (state : NodeState) : Prop :=
  exists target txid,
    state.chosen = some target /\ maximumGossip state.gossips = some (target, txid)

/-- Every node in the voting phase has chosen its maximum-scoring gossip source. -/
private def VotingSelectionsValid (state : State) : Prop :=
  forall entry,
    entry ∈ state.system.nodes -> entry.2.phase = .voting -> NodeVotingSelection entry.2

/-- Every sent vote's snapshot records a maximum-scoring gossip selection. -/
private def SentVotesSelected (state : State) : Prop :=
  forall envelope,
    envelope ∈ state.sent
    -> envelope.payload = .vote
    -> NodeVotingSelection envelope.sourceState

/-- A recorded opening preserves node identity, vote provenance, and its quorum threshold. -/
private structure Opening.Valid (config : Config) (globalState : State)
    (opening : Opening)
    : Prop where
  /-- The opening snapshot belongs to the notifying location. -/
  location : opening.state.location = opening.node
  /-- The snapshot records the opening phase. -/
  phase : opening.state.phase = .opening
  /-- The snapshot and notification agree on the opening evidence. -/
  kind : opening.state.openKind = some opening.kind
  /-- The snapshot does not count duplicate voters. -/
  votesNodup : opening.state.votes.Nodup
  /-- A quorum opening has at least the configured majority threshold. -/
  quorum
    : opening.kind = .quorum -> voteQuorum config.protocol <= opening.state.votes.length
  /-- Every counted vote was actually sent to the opening location. -/
  votesSent
    : forall voter, voter ∈ opening.state.votes -> SentVote globalState voter opening.node

/-- Every recorded opening satisfies its identity and vote-provenance invariants. -/
private def OpeningsValid (config : Config) (state : State) : Prop :=
  forall opening, opening ∈ state.openings -> Opening.Valid config state opening

/-- Vote uniqueness, provenance, stable selection, and validity of recorded openings. -/
private structure QuorumInvariant (config : Config) (state : State) : Prop where
  /-- Counted votes contain no duplicate sources. -/
  votesNodup : NodeVotesNodup state
  /-- Counted votes are backed by the send history. -/
  votesSent : NodeVotesSent state
  /-- Past voters retain their voting choice until leaving voting. -/
  sentVoteStable : SentVoteStable state
  /-- A source never votes for two different locations. -/
  sentVotesFunctional : SentVotesFunctional state
  /-- Current voting choices are justified by the nodes' gossips. -/
  votingSelections : VotingSelectionsValid state
  /-- Historical votes have snapshots with justified gossip choices. -/
  sentVotesSelected : SentVotesSelected state
  /-- Historical openings have valid evidence and snapshots. -/
  openingsValid : OpeningsValid config state

/-- Extracts the source of an accepted vote receive, ignoring other events. -/
private def acceptedVoteSource : Event -> Option Location
  | .receiveVote source .accepted => some source
  | _ => none

/-- The history records a quorum opening by the given node. -/
private def QuorumOpened (state : State) (node : Location) : Prop :=
  exists opening,
    opening ∈ state.openings /\ opening.node = node /\ opening.kind = .quorum

end DisasterRecovery.Proofs.Predicates

namespace DisasterRecovery.Proofs.Predicates.TxID

open Execution.Local hiding Config
open Execution.Global

/-- Non-strict lexicographic TxID ordering by view and then sequence number. -/
private def EarlierThan (left right : TxID) : Prop :=
  left.view < right.view \/ (left.view = right.view /\ left.seqno <= right.seqno)

end DisasterRecovery.Proofs.Predicates.TxID

namespace DisasterRecovery.Proofs.Invariants
end DisasterRecovery.Proofs.Invariants

namespace DisasterRecovery.Proofs.Quorum

open Execution
open Execution.Local hiding Config
open Execution.Global Predicates
open DisasterRecovery.Proofs.Invariants
attribute [local simp] Execution.Local.transitionSystem rejectionReason guard failure

/-- The facts about one successful `advance` used by the quorum invariants. -/
private structure AdvanceSpec
    (config : Execution.Local.Config) (input : NodeState) (out : StepOutput)
    : Prop where
  votes : out.state.votes = input.votes
  gossips : out.state.gossips = input.gossips
  nonGossiping : input.phase ≠ .gossiping -> out.state.phase ≠ .gossiping
  voting
    : out.state.phase = .voting
      -> (input.phase = .voting /\ out.state.chosen = input.chosen)
          \/ (input.phase = .gossiping /\ NodeVotingSelection out.state)
  opening
    : forall kind,
        .opening kind ∈ out.effects
        -> out.state.phase = .opening
            /\ out.state.openKind = some kind
            /\ (kind = .quorum -> voteQuorum config <= input.votes.length)

/-- How an accepted event's pre-advance state relates to the original state. -/
private structure Received (state : NodeState) (event : Event) (received : NodeState)
    : Prop where
  gossiping : received.phase = .gossiping -> state.phase = .gossiping
  voting
    : received.phase = .voting
      -> state.phase = .voting
          /\ received.chosen = state.chosen
          /\ (received.gossips = state.gossips \/ state.chosen = none)
  votes
    : received.votes = state.votes
      \/ exists source,
          acceptedVoteSource event = some source
          /\ received.votes = insertVote source state.votes

/-- A local step either keeps the state without opening, or advances a related state. -/
private def StepSpec (config : Execution.Local.Config) (state : NodeState) (event : Event)
    (out : StepOutput)
    : Prop :=
  (out.state = state /\ forall kind, .opening kind ∉ out.effects)
  \/ exists received timeout,
      Received state event received /\ advance config received timeout = some out

end DisasterRecovery.Proofs.Quorum

namespace DisasterRecovery.Proofs.Local
end DisasterRecovery.Proofs.Local

namespace DisasterRecovery.Proofs.Lifting

open CCF
open DisasterRecovery.Model.Local
open Execution.Local (messages)
open DisasterRecovery.Proofs.Local
attribute [local simp] StateT.run

/-- Local state and notifications retained when comparing decorated and model steps. -/
private structure Result where
  /-- The local state produced by the step. -/
  state : NodeState
  /-- Host-visible notifications produced by the step. -/
  effects : List Notification := []

/-- Retains the local state and notifications of an executable model step. -/
private def capture (run : NodeState × Outputs Location Message Notification) : Result :=
  { state := run.1, effects := run.2.notifications }

/-- Removes a decorated envelope's proof-only sender snapshot. -/
private def eraseEnvelope (envelope : Execution.Global.Envelope) : Model.Envelope :=
  { source := envelope.source, target := envelope.target, payload := envelope.payload }

/-- Removes send snapshots and histories to recover the executable network state. -/
private def erase (state : Execution.Global.State) : Model.State :=
  { nodes := state.system.nodes, network := state.network.map eraseEnvelope }

/-- Translates a decorated action into its executable model counterpart. -/
private def eraseAction : Execution.Global.Action -> Model.Action
  | .retry source => .local source .retry
  | .timeout target => .local target .timeout
  | .deliver envelope => .deliver (eraseEnvelope envelope)

/-- Retains a decorated local step's state and notifications, ignoring send effects. -/
private def eraseOutput (output : Execution.Local.StepOutput) : Result :=
  {
    state := output.state,
    effects := output.effects.filterMap Execution.Local.Effect.diagnostic
  }

/-- A model run reconstructed from an instrumented step for sender `source`. -/
private def toRun (source : Location) (recovered : TxID)
    (output : Execution.Local.StepOutput)
    : NodeState × Outputs Location Message Notification :=
  (
    output.state,
    {
      outgoing := messages source recovered output.effects,
      notifications := output.effects.filterMap Execution.Local.Effect.diagnostic
    }
  )

end DisasterRecovery.Proofs.Lifting

namespace DisasterRecovery.Proofs.History

open CCF
open Lifting

/-- Decorated steps whose erased successor states form the given model-state list. -/
private inductive Decoration (config : Model.Config)
    : Execution.Global.State -> List Model.State -> Execution.Global.State -> Prop where
  /-- An empty decoration leaves the instrumented state unchanged. -/
  | nil (state) : Decoration config state [] state
  /-- Prepend an instrumented step and its erased successor. -/
  | cons {before middle after tail} {action}
    (step : Execution.Global.next config before action = some middle)
    (rest : Decoration config middle tail after)
    : Decoration config before (erase middle :: tail) after

/-- A reachable decorated state with a model execution suffix from every trace state
up to `bound`. -/
private structure Correspondence (config : Model.Config)
    (trace : Properties.GlobalTrace config) (bound : Nat) (ghost : Execution.Global.State)
    : Prop where
  /-- The instrumented state is reachable under the same recovery configuration. -/
  reachable : Execution.Global.Reachable config ghost
  /-- Every trace state up to `bound` has a model path to the erased ghost state. -/
  suffix
    : forall i state,
        i <= bound
        -> trace.stateAt i = some state
        -> exists tail,
            Trace.Path (Model.transitionSystem config) state tail (erase ghost)

end DisasterRecovery.Proofs.History

namespace DisasterRecovery.Proofs.Observed

open Execution.Local
open Execution.Global hiding Config
open Predicates

/-- Every node with an open kind retains enough votes for that kind of opening. -/
private def OpeningThresholds (config : Model.Config) (state : State) : Prop :=
  forall entry,
    entry ∈ state.system.nodes
    -> forall kind,
        entry.2.openKind = some kind
        -> (if kind = .quorum then voteQuorum config.protocol else 1)
            <= entry.2.votes.length

private abbrev Threshold (config : Config) (state : NodeState) : Prop :=
  forall kind,
    state.openKind = some kind
    -> (if kind = .quorum then voteQuorum config else 1) <= state.votes.length

end DisasterRecovery.Proofs.Observed

namespace DisasterRecovery.Proofs.Committed
end DisasterRecovery.Proofs.Committed

namespace DisasterRecovery.Proofs.Gossip

open Execution
open Execution.Local hiding Config
open Execution.Global
open Invariants Quorum

/-- Gossip and votes grow monotonically, and choosing a node freezes its gossip. -/
private structure Evolves (before after : NodeState) : Prop where
  /-- Previously accepted gossips remain present. -/
  gossips : before.gossips ⊆ after.gossips
  /-- Previously accepted votes remain present. -/
  votes : before.votes ⊆ after.votes
  /-- Once chosen, a node retains a choice and cannot change its gossips. -/
  frozen
    : before.chosen.isSome = true
      -> after.chosen.isSome = true /\ after.gossips = before.gossips

private abbrev Frame (before after : NodeState) : Prop :=
  after.gossips = before.gossips
  /\ after.votes = before.votes
  /\ (before.chosen.isSome = true -> after.chosen.isSome = true)

/-- Every node's accepted gossip comes from the configured recovered ledger tips. -/
private def Genuine (config : Config) (nodes : List (Location × NodeState)) : Prop :=
  forall entry, entry ∈ nodes -> entry.2.gossips ⊆ config.recovered

/-- An accepted gossip event carries its source's configured recovered ledger tip. -/
private def EventGenuine (config : Config) : Event -> Prop
  | .receiveGossip source txid .accepted => (source, txid) ∈ config.recovered
  | _ => True

/-- Every sent vote's snapshot still matches its sender's frozen gossip. -/
private def FrozenVotes (state : State) : Prop :=
  forall envelope,
    envelope ∈ state.sent
    -> envelope.payload = .vote
    -> exists current,
        (envelope.source, current) ∈ state.system.nodes
        /\ current.chosen.isSome = true
        /\ current.gossips = envelope.sourceState.gossips

/-- `node` has accepted gossip from itself in a trace state up to `bound`. -/
private def OwnGossipBy {config : Model.Config} (trace : Properties.GlobalTrace config)
    (bound : Nat) (node : Location)
    : Prop :=
  exists i state,
    i <= bound
    /\ trace.stateAt i = some state
    /\ exists nodeState txid,
        (node, nodeState) ∈ state.nodes /\ (node, txid) ∈ nodeState.gossips

end DisasterRecovery.Proofs.Gossip

namespace DisasterRecovery.Proofs.Trace

open CCF
variable {State : Type}

private lemma Path.run {system : TransitionSystem} {before tail after}
    (path : Path system before tail after)
    : exists actions, Execution.Run system before actions after := by
  induction path with
  | nil => exact ⟨[], .nil _⟩
  | cons step _ ih =>
      obtain ⟨actions, rest⟩ := ih
      exact ⟨_, .cons step rest⟩

/-- Enabled steps connect a state of a valid trace to every later state of the trace. -/
private lemma valid_path {system : TransitionSystem} {trace : Execution.Trace system}
    (start count : Nat) {before after : system.State}
    (first : trace.stateAt start = some before)
    (last : trace.stateAt (start + count) = some after)
    : exists tail, Path system before tail after := by
  induction count generalizing start before with
  | zero =>
      cases first.symm.trans last
      exact ⟨[], .nil _⟩
  | succ count ih =>
      cases next : trace.stateAt (start + 1) with
      | none =>
          have absent := trace.states.le_stable
            (show start + 1 <= start + (count + 1) by omega) next
          change trace.states.get? (start + (count + 1)) = some after at last
          simp [absent] at last
      | some middle =>
          obtain ⟨action, step⟩ := trace.step start before middle first next
          obtain ⟨tail, rest⟩ :=
            ih (start + 1) next (by rwa [show start + 1 + count = start + (count + 1) by omega])
          exact ⟨_, .cons step rest⟩

/-- The later of two trace positions is also a trace position. -/
private lemma max_isSome {trace : CCF.Seq State} {first second : Nat}
    (firstIn : (trace.get? first).isSome) (secondIn : (trace.get? second).isSome)
    : (trace.get? (max first second)).isSome := by
  rcases Nat.le_total first second with le | le
  · rwa [Nat.max_eq_right le]
  · rwa [Nat.max_eq_left le]

/-- Finitely many trace positions all lie at or before one trace position after `start`. -/
private lemma exists_bound {α : Type} {trace : CCF.Seq State} {P : α -> Nat -> Prop}
    {start : Nat} (startIn : (trace.get? start).isSome) (items : List α)
    (indexed
      : forall item,
          item ∈ items -> exists index, (trace.get? index).isSome /\ P item index)
    : exists bound,
        (trace.get? bound).isSome
        /\ start <= bound
        /\ forall item, item ∈ items -> exists index, index <= bound /\ P item index := by
  induction items with
  | nil => exact ⟨start, startIn, Nat.le_refl _, by simp⟩
  | cons head tail ih =>
      obtain ⟨headIndex, headIn, headHolds⟩ := indexed head (by simp)
      obtain ⟨bound, boundIn, startLe, bounded⟩ :=
        ih fun item member => indexed item (by simp [member])
      refine ⟨
        max headIndex bound,
        max_isSome headIn boundIn,
        Nat.le_trans startLe (Nat.le_max_right _ _),
        fun item member => ?_
      ⟩
      rcases List.mem_cons.mp member with rfl | member
      · exact ⟨headIndex, Nat.le_max_left _ _, headHolds⟩
      · obtain ⟨index, le, holds⟩ := bounded item member
        exact ⟨index, Nat.le_trans le (Nat.le_max_right _ _), holds⟩

end DisasterRecovery.Proofs.Trace

namespace DisasterRecovery.Proofs.Invariants

open Execution
open Execution.Local hiding Config
open Execution.Global Predicates

private lemma recovered_configured
    {config : Config}
    {node : Location}
    (keys : config.recovered.map Prod.fst = config.protocol.expectedLocations)
    (found : recoveredTxID config node ≠ none)
    : node ∈ config.protocol.expectedLocations := by
  obtain ⟨txid, found⟩ := Option.ne_none_iff_exists.mp found
  obtain ⟨entry, selected, _⟩ := Option.map_eq_some_iff.mp found.symm
  have member := List.mem_of_find?_eq_some selected
  have key : entry.1 = node :=
    beq_iff_eq.mp
      (List.find?_some (p := fun entry : Location × TxID => entry.1 == node) selected)
  rw [←keys, ←key]
  exact List.mem_map_of_mem member

private lemma retryMessages_source
    {config : Config}
    {source : Location}
    {sourceState : NodeState}
    {envelope : Envelope}
    (created : envelope ∈ retryMessages config source sourceState)
    : envelope.source = source /\ envelope.sourceState = sourceState := by
  have messageForEffect_source
      {config : Config}
      {source : Location}
      {sourceState : NodeState}
      {effect : Effect}
      {envelope : Envelope}
      (created : messageForEffect config source sourceState effect = some envelope)
      : envelope.source = source /\ envelope.sourceState = sourceState := by
    cases effect with
    | sendGossip target =>
        simp only [messageForEffect, Option.bind_eq_bind, Option.bind_eq_some_iff,
          Option.pure_def, Option.some.injEq] at created
        obtain ⟨_, _, rfl⟩ := created
        exact ⟨rfl, rfl⟩
    | sendVote target | sendIAmOpen target =>
        cases created
        exact ⟨rfl, rfl⟩
    | opening _ | restart _ | completed | rejected _ => cases created
  rw [retryMessages, List.mem_filterMap] at created
  rcases created with ⟨effect, _, produced⟩
  exact messageForEffect_source produced

private lemma retryMessages_valid
    (config : Config)
    (source : Location)
    (sourceState : NodeState)
    (sourceLocation : sourceState.location = source)
    : forall envelope,
        envelope ∈ retryMessages config source sourceState -> envelope.Valid config := by
  intro envelope created
  rcases retryMessages_source created with
    ⟨sourceEq, stateEq⟩
  constructor
  · rw [stateEq, sourceEq]
    exact sourceLocation
  · rw [sourceEq, stateEq]
    exact created

private lemma valid_envelope_effect
    {config : Config}
    {envelope : Envelope}
    (valid : envelope.Valid config)
    : exists effect,
        effect ∈ (step config.protocol envelope.sourceState .retry).effects
        /\ messageForEffect config envelope.source envelope.sourceState effect
            = some envelope := by
  rcases valid with ⟨_, created⟩
  rw [retryMessages, List.mem_filterMap] at created
  exact created

private lemma valid_gossip_uses_recovered_txid
    {config : Config}
    {envelope : Envelope}
    {txid : TxID}
    (valid : envelope.Valid config)
    (gossip : envelope.payload = .gossip txid)
    : recoveredTxID config envelope.source = some txid := by
  rcases valid_envelope_effect valid with
    ⟨effect, _, created⟩
  cases effect with
  | sendGossip target =>
      simp only [messageForEffect, Option.bind_eq_bind, Option.bind_eq_some_iff,
        Option.pure_def, Option.some.injEq] at created
      obtain ⟨recovered, found, created⟩ := created
      rw [← created] at gossip
      cases gossip
      exact found
  | sendVote target | sendIAmOpen target =>
      rw [← Option.some.inj created] at gossip
      cases gossip
  | opening _ | restart _ | completed | rejected _ => cases created

private lemma advance_location {config : Execution.Local.Config} {state : NodeState}
    {timeout : Bool} {output : StepOutput}
    (advanced : advance config state timeout = some output)
    : output.state.location = state.location := by
  have lane_location (state : NodeState) (timeout : Bool)
      : (advanceTimeoutLane state timeout).location = state.location := by
    cases timeout <;> rfl
  unfold advance at advanced
  cases phase : state.phase <;> simp only [phase] at advanced
  · split at advanced
    · split at advanced
      · cases advanced
      · cases advanced
        exact lane_location _ timeout
    · cases advanced
      exact lane_location _ timeout
  · split at advanced
    · split at advanced <;> cases advanced
      · rfl
      · exact lane_location _ timeout
    · cases advanced
      exact lane_location _ timeout
  · split at advanced <;> cases advanced <;> exact lane_location _ timeout
  · split at advanced <;> cases advanced
    exact lane_location _ timeout
  · cases advanced
    exact lane_location _ timeout

private lemma step_preserves_location
    (config : Execution.Local.Config)
    (state : NodeState)
    (event : Event)
    : (step config state event).state.location = state.location := by
  suffices stepped :
    forall output,
      (Execution.Local.transitionSystem config state.location).step { state } event
        = some output
      -> output.state.location = state.location by
    unfold step
    cases found
          : (Execution.Local.transitionSystem config state.location).step
              { state } event with
    | none => rfl
    | some output => exact stepped output found
  intro output stepped
  cases event with
  | receiveGossip source txid validation =>
      simp only [Execution.Local.transitionSystem, guard] at stepped
      split at stepped
      · split at stepped
        · exact (advance_location stepped :)
        · cases stepped
      · cases stepped
  | receiveVote source validation =>
      simp only [Execution.Local.transitionSystem, guard] at stepped
      split at stepped
      · exact (advance_location stepped :)
      · cases stepped
  | receiveIAmOpen source validation =>
      simp only [Execution.Local.transitionSystem, guard] at stepped
      split at stepped
      · split at stepped
        · exact advance_location (config := config) (timeout := false)
            (state := { state with phase := .joining, chosen := some source }) stepped
        · cases stepped
      · cases stepped
  | timeout => exact advance_location stepped
  | retry =>
      cases stepped
      rfl

private lemma nodeState_location
    {state : State}
    {node : Location}
    {foundState : NodeState}
    (locations : forall entry, entry ∈ state.system.nodes -> entry.2.location = entry.1)
    (found : nodeState state node = some foundState)
    : foundState.location = node := by
  rw [nodeState, Option.map_eq_some_iff] at found
  rcases found with ⟨entry, findEq, stateEq⟩
  have membership : entry ∈ state.system.nodes :=
    List.mem_of_find?_eq_some findEq
  have condition : (entry.1 == node) = true :=
    List.find?_some
      (p := fun entry : Prod Location NodeState =>
        entry.1 == node) findEq
  have keyEq : entry.1 = node := beq_iff_eq.mp condition
  rw [←stateEq, locations entry membership, keyEq]

private lemma initial_well_formed
    (config : Config)
    (nodes : List Location)
    (valid : config.Valid)
    (nodesNodup : nodes.Nodup)
    (covered : forall node, node ∈ config.protocol.expectedLocations -> node ∈ nodes)
    : WellFormed config (initial config nodes) := by
  constructor
  · simpa [Execution.Global.initial, Function.comp_def] using covered
  · simpa [Execution.Global.initial, Function.comp_def] using nodesNodup
  · simp [Execution.Global.initial, initialNode]
  · exact valid.2.2
  · simp [Execution.Global.initial]
  · simp [Execution.Global.initial]
  · simp [Execution.Global.initial]
  · constructor <;> simp [Execution.Global.initial]

@[simp]
private lemma recordEffects_system
    (node : Location)
    (nodeState : NodeState)
    (effects : List Effect)
    (state : State)
    : (recordEffects node nodeState effects state).system = state.system := by
  induction effects generalizing state with
  | nil => rfl
  | cons effect tail ih =>
      simp only [recordEffects, List.foldl_cons]
      change (recordEffects node nodeState tail
                (recordEffect node nodeState state effect)).system
      = state.system
      rw [ih]
      cases effect <;> rfl

@[simp]
private lemma recordEffects_network
    (node : Location)
    (nodeState : NodeState)
    (effects : List Effect)
    (state : State)
    : (recordEffects node nodeState effects state).network = state.network := by
  induction effects generalizing state with
  | nil => rfl
  | cons effect tail ih =>
      simp only [recordEffects, List.foldl_cons]
      change (recordEffects node nodeState tail
                (recordEffect node nodeState state effect)).network
      = state.network
      rw [ih]
      cases effect <;> rfl

@[simp]
private lemma recordEffects_sent
    (node : Location)
    (nodeState : NodeState)
    (effects : List Effect)
    (state : State)
    : (recordEffects node nodeState effects state).sent = state.sent := by
  induction effects generalizing state with
  | nil => rfl
  | cons effect tail ih =>
      simp only [recordEffects, List.foldl_cons]
      change (recordEffects node nodeState tail
                (recordEffect node nodeState state effect)).sent
      = state.sent
      rw [ih]
      cases effect <;> rfl

private lemma reachable_config_valid
    {config : Config}
    {state : State}
    (reachable : Reachable config state)
    : config.Valid := by
  induction reachable
    using @CCF.TransitionSystem.Reachable.rec (transitionSystem config) with
  | initial initialized =>
      rcases initialized with ⟨valid, _⟩
      exact valid
  | step _ _ valid => exact valid

private lemma recordEffects_preserves_histories_configured
    {config : Config}
    {node : Location}
    {nodeState : NodeState}
    {effects : List Effect}
    {state : State}
    (wellFormed : HistoriesConfigured config state)
    (nodeConfigured : node ∈ config.protocol.expectedLocations)
    : HistoriesConfigured config (recordEffects node nodeState effects state) := by
  have recordEffect_preserves_histories_configured
      {config : Config}
      {node : Location}
      {nodeState : NodeState}
      {state : State}
      {effect : Effect}
      (wellFormed : HistoriesConfigured config state)
      (nodeConfigured : node ∈ config.protocol.expectedLocations)
      : HistoriesConfigured config (recordEffect node nodeState state effect) := by
    rcases wellFormed with ⟨openings, restarts, completed⟩
    cases effect with
    | opening kind =>
        refine ⟨fun opening member => ?_, restarts, completed⟩
        rcases List.mem_cons.mp member with rfl | old
        · exact nodeConfigured
        · exact openings opening old
    | restart chosen =>
        refine ⟨openings, fun restarted member => ?_, completed⟩
        rcases List.mem_cons.mp member with rfl | old
        · exact nodeConfigured
        · exact restarts restarted old
    | completed =>
        refine ⟨openings, restarts, fun finished member => ?_⟩
        rcases List.mem_cons.mp member with rfl | old
        · exact nodeConfigured
        · exact completed finished old
    | sendGossip | sendVote | sendIAmOpen | rejected =>
        exact ⟨openings, restarts, completed⟩
  induction effects generalizing state with
  | nil => exact wellFormed
  | cons effect tail ih =>
      simp only [recordEffects, List.foldl_cons]
      apply ih
      exact recordEffect_preserves_histories_configured wellFormed nodeConfigured

private lemma replaceNode_keys
    (target : Location)
    (nextState : NodeState)
    (nodes : List (Prod Location NodeState))
    : (replaceNode target nextState nodes).map Prod.fst = nodes.map Prod.fst := by
  induction nodes with
  | nil => rfl
  | cons entry tail ih =>
      simp only [replaceNode, List.map_cons]
      split
      ·
        rename_i condition
        have same : entry.1 = target := beq_iff_eq.mp condition
        simp only [List.cons.injEq]
        constructor
        · exact same.symm
        · simpa [replaceNode] using ih
      ·
        simp only [List.cons.injEq, true_and]
        simpa [replaceNode] using ih

private lemma systemStep_node_keys_eq
    {config : Execution.Local.Config}
    {before after : SystemState}
    {target : Location}
    {event : Event}
    {output : StepOutput}
    (transition : systemStep config before target event = some (after, output))
    : after.nodes.map Prod.fst = before.nodes.map Prod.fst := by
  simp only [systemStep, Option.bind_eq_bind, Option.bind_eq_some_iff, Option.map_eq_some_iff,
    Option.pure_def, Option.some.injEq, Prod.mk.injEq] at transition
  rcases transition with ⟨node, _, stateEq, _⟩
  rw [←stateEq]
  exact replaceNode_keys target
    (step config node event).state before.nodes

private lemma systemStep_preserves_node_locations
    {config : Execution.Local.Config}
    {before after : SystemState}
    {target : Location}
    {event : Event}
    {output : StepOutput}
    (locations : forall entry, entry ∈ before.nodes -> entry.2.location = entry.1)
    (transition : systemStep config before target event = some (after, output))
    : forall entry, entry ∈ after.nodes -> entry.2.location = entry.1 := by
  have replaceNode_locations
      (target : Location)
      (nextState : NodeState)
      (nodes : List (Prod Location NodeState))
      (locations : forall entry, entry ∈ nodes -> entry.2.location = entry.1)
      (nextLocation : nextState.location = target)
      : forall entry,
          entry ∈ replaceNode target nextState nodes -> entry.2.location = entry.1 := by
    intro entry membership
    rw [replaceNode, List.mem_map] at membership
    rcases membership with ⟨previous, previousMember, rfl⟩
    split
    · exact nextLocation
    · exact locations previous previousMember
  simp only [systemStep, Option.bind_eq_bind, Option.bind_eq_some_iff, Option.map_eq_some_iff,
    Option.pure_def, Option.some.injEq, Prod.mk.injEq] at transition
  rcases transition with
    ⟨_, ⟨⟨key, node⟩, found, rfl⟩, stateEq, _⟩
  rw [←stateEq]
  apply replaceNode_locations
  · exact locations
  · calc
      (step config node event).state.location =
          node.location := step_preserves_location config node event
      _ = key :=
        locations (key, node) (List.mem_of_find?_eq_some found)
      _ = target :=
        beq_iff_eq.mp
          (List.find?_some
            (p := fun entry : Prod Location NodeState =>
              entry.1 == target) found)

private lemma retry_cases
    {config : Config}
    {before after : State}
    {source : Location}
    (transition : next config before (.retry source) = some after)
    : (recoveredTxID config source).isSome = true
      /\ exists sourceState,
          nodeState before source = some sourceState
          /\ {
                  before with
                    network := before.network ++ retryMessages config source sourceState
                    sent := before.sent ++ retryMessages config source sourceState
                }
              = after := by
  simp only [next, guard, failure, Option.bind_eq_bind, Option.bind_eq_some_iff,
    Option.pure_def, Option.some.injEq, Option.ite_none_right_eq_some, exists_const,
    and_true] at transition
  obtain ⟨recovered, sourceState, found, _, rfl⟩ := transition
  exact ⟨recovered, sourceState, found, rfl⟩

private lemma deliver_cases
    {config : Config}
    {before after : State}
    {envelope : Envelope}
    (transition : next config before (.deliver envelope) = some after)
    : envelope ∈ before.network
      /\ (recoveredTxID config envelope.target).isSome = true
      /\ exists system output,
          systemStep config.protocol before.system envelope.target (eventFor envelope)
            = some (system, output)
          /\ recordEffects envelope.target output.state output.effects
                { before with system, network := removeOne envelope before.network }
              = after := by
  simp only [next, guard, failure, Option.bind_eq_bind, Option.bind_eq_some_iff,
    Option.pure_def, Option.some.injEq, Option.ite_none_right_eq_some,
    List.contains_iff_mem, exists_const, and_true] at transition
  obtain ⟨pending, recovered, ⟨system, output⟩, stepped, rfl⟩ := transition
  exact ⟨pending, recovered, system, output, stepped, rfl⟩

private lemma timeout_cases
    {config : Config}
    {before after : State}
    {target : Location}
    (transition : next config before (.timeout target) = some after)
    : (recoveredTxID config target).isSome = true
      /\ exists system output,
          systemStep config.protocol before.system target .timeout = some (system, output)
          /\ output.accepted = true
          /\ recordEffects target output.state output.effects { before with system }
              = after := by
  simp only [next, guard, failure, Option.bind_eq_bind, Option.bind_eq_some_iff,
    Option.pure_def, Option.some.injEq, Option.ite_none_right_eq_some, exists_const,
    and_true] at transition
  obtain ⟨recovered, ⟨system, output⟩, stepped, accepted, rfl⟩ := transition
  exact ⟨recovered, system, output, stepped, accepted, rfl⟩

private lemma retry_system_eq
    {config : Config}
    {before after : State}
    {source : Location}
    (transition : next config before (.retry source) = some after)
    : after.system = before.system := by
  obtain ⟨_, sourceState, _, rfl⟩ := retry_cases transition
  rfl

private lemma deliver_preserves_well_formed
    {config : Config}
    {before after : State}
    {envelope : Envelope}
    (wellFormed : WellFormed config before)
    (transition : next config before (.deliver envelope) = some after)
    : WellFormed config after := by
  have mem_of_mem_removeOne {α : Type _} [BEq α] (value member : α) (values : List α)
      : member ∈ removeOne value values -> member ∈ values := by
    induction values with
    | nil => simp [removeOne]
    | cons head tail ih =>
        simp only [removeOne]
        split
        · exact List.mem_cons_of_mem head
        · intro membership
          rw [List.mem_cons] at membership ⊢
          exact membership.imp_right ih
  obtain ⟨_, targetRecovered, system, output, systemStep, stateEq⟩ := deliver_cases transition
  rw [←stateEq]
  constructor
  · simp only [recordEffects_system]
    rw [systemStep_node_keys_eq systemStep]
    exact wellFormed.nodeKeys
  · rw [recordEffects_system, systemStep_node_keys_eq systemStep]
    exact wellFormed.nodeKeysNodup
  · simp only [recordEffects_system]
    exact systemStep_preserves_node_locations
      wellFormed.nodeLocations systemStep
  · simpa using wellFormed.recoveredKeys
  · intro sent membership
    rw [recordEffects_sent] at membership
    exact wellFormed.sentValid sent membership
  · intro sent membership
    rw [recordEffects_sent] at membership
    exact wellFormed.sentSourceConfigured sent membership
  · intro pending membership
    rw [recordEffects_network] at membership
    rw [recordEffects_sent]
    exact wellFormed.networkSent pending
      (mem_of_mem_removeOne envelope pending before.network membership)
  · apply recordEffects_preserves_histories_configured
    · constructor
      · simpa using wellFormed.historiesConfigured.openings
      · simpa using wellFormed.historiesConfigured.restarts
      · simpa using wellFormed.historiesConfigured.completed
    · exact recovered_configured wellFormed.recoveredKeys
        (Option.isSome_iff_ne_none.mp targetRecovered)

private lemma timeout_preserves_well_formed
    {config : Config}
    {before after : State}
    {target : Location}
    (wellFormed : WellFormed config before)
    (transition : next config before (.timeout target) = some after)
    : WellFormed config after := by
  obtain ⟨targetRecovered, system, output, systemStep, _, stateEq⟩ := timeout_cases transition
  rw [←stateEq]
  constructor
  · simp only [recordEffects_system]
    rw [systemStep_node_keys_eq systemStep]
    exact wellFormed.nodeKeys
  · rw [recordEffects_system, systemStep_node_keys_eq systemStep]
    exact wellFormed.nodeKeysNodup
  · simp only [recordEffects_system]
    exact systemStep_preserves_node_locations
      wellFormed.nodeLocations systemStep
  · simpa using wellFormed.recoveredKeys
  · intro sent membership
    rw [recordEffects_sent] at membership
    exact wellFormed.sentValid sent membership
  · intro sent membership
    rw [recordEffects_sent] at membership
    exact wellFormed.sentSourceConfigured sent membership
  · intro pending membership
    rw [recordEffects_network] at membership
    rw [recordEffects_sent]
    exact wellFormed.networkSent pending membership
  · apply recordEffects_preserves_histories_configured
    · constructor
      · simpa using wellFormed.historiesConfigured.openings
      · simpa using wellFormed.historiesConfigured.restarts
      · simpa using wellFormed.historiesConfigured.completed
    · exact recovered_configured wellFormed.recoveredKeys
        (Option.isSome_iff_ne_none.mp targetRecovered)

private lemma reachable_well_formed
    {config : Config}
    {state : State}
    (reachable : Reachable config state)
    : WellFormed config state := by
  have retry_preserves_well_formed
      {config : Config}
      {before after : State}
      {source : Location}
      (wellFormed : WellFormed config before)
      (transition : next config before (.retry source) = some after)
      : WellFormed config after := by
    obtain ⟨sourceRecovered, sourceState, found, stateEq⟩ := retry_cases transition
    have sourceLocation : sourceState.location = source :=
      nodeState_location wellFormed.nodeLocations found
    rw [←stateEq]
    constructor
    · exact wellFormed.nodeKeys
    · exact wellFormed.nodeKeysNodup
    · exact wellFormed.nodeLocations
    · exact wellFormed.recoveredKeys
    · intro envelope membership
      rw [List.mem_append] at membership
      rcases membership with membership | membership
      · exact wellFormed.sentValid envelope membership
      · exact retryMessages_valid config source sourceState
          sourceLocation envelope membership
    · intro envelope membership
      rw [List.mem_append] at membership
      rcases membership with membership | membership
      · exact wellFormed.sentSourceConfigured envelope membership
      · rw [(retryMessages_source membership).1]
        exact recovered_configured wellFormed.recoveredKeys
          (Option.isSome_iff_ne_none.mp sourceRecovered)
    · intro envelope membership
      rw [List.mem_append] at membership ⊢
      rcases membership with membership | membership
      · exact Or.inl (wellFormed.networkSent envelope membership)
      · exact Or.inr membership
    · constructor
      · exact wellFormed.historiesConfigured.openings
      · exact wellFormed.historiesConfigured.restarts
      · exact wellFormed.historiesConfigured.completed
  have next_preserves_well_formed
      {config : Config}
      {before after : State}
      {action : Action}
      (wellFormed : WellFormed config before)
      (transition : next config before action = some after)
      : WellFormed config after := by
    cases action with
    | retry source =>
        exact retry_preserves_well_formed wellFormed transition
    | deliver envelope =>
        exact deliver_preserves_well_formed wellFormed transition
    | timeout target =>
        exact timeout_preserves_well_formed wellFormed transition
  induction reachable
    using @CCF.TransitionSystem.Reachable.rec (transitionSystem config) with
  | initial initialized =>
      rcases initialized with
        ⟨valid, nodes, nodesNodup, covered, rfl⟩
      exact initial_well_formed config nodes valid nodesNodup covered
  | step _ transition wellFormed =>
      exact next_preserves_well_formed wellFormed transition

end DisasterRecovery.Proofs.Invariants

namespace DisasterRecovery.Proofs.Quorum

open Execution
open Execution.Local hiding Config
open Execution.Global Predicates
open DisasterRecovery.Proofs.Invariants
attribute [local simp] Execution.Local.transitionSystem rejectionReason guard failure

@[local simp]
private lemma lane_phase (state : NodeState) (timeout : Bool)
    : (advanceTimeoutLane state timeout).phase = state.phase := by
  cases timeout <;> rfl

@[local simp]
private lemma lane_votes (state : NodeState) (timeout : Bool)
    : (advanceTimeoutLane state timeout).votes = state.votes := by
  cases timeout <;> rfl

@[local simp]
private lemma lane_gossips (state : NodeState) (timeout : Bool)
    : (advanceTimeoutLane state timeout).gossips = state.gossips := by
  cases timeout <;> rfl

@[local simp]
private lemma lane_chosen (state : NodeState) (timeout : Bool)
    : (advanceTimeoutLane state timeout).chosen = state.chosen := by
  cases timeout <;> rfl

@[local simp]
private lemma lane_openKind (state : NodeState) (timeout : Bool)
    : (advanceTimeoutLane state timeout).openKind = state.openKind := by
  cases timeout <;> rfl

private lemma eq_of_key_eq
    {α : Type}
    {nodes : List (Prod Location α)}
    (nodup : (nodes.map Prod.fst).Nodup)
    {first second : Prod Location α}
    (firstMember : first ∈ nodes)
    (secondMember : second ∈ nodes)
    (keyEq : first.1 = second.1)
    : first = second := by
  induction nodes generalizing first second with
  | nil => simp at firstMember
  | cons head tail ih =>
      rw [List.map_cons, List.nodup_cons] at nodup
      rcases nodup with ⟨headFresh, tailNodup⟩
      rw [List.mem_cons] at firstMember secondMember
      rcases firstMember with rfl | firstTail
      · rcases secondMember with rfl | secondTail
        · rfl
        · exfalso
          apply headFresh
          rw [List.mem_map]
          exact ⟨second, secondTail, keyEq.symm⟩
      · rcases secondMember with rfl | secondTail
        · exfalso
          apply headFresh
          rw [List.mem_map]
          exact ⟨first, firstTail, keyEq⟩
        · exact ih tailNodup firstTail secondTail keyEq

private lemma AdvanceSpec.lane {config : Execution.Local.Config} {input : NodeState}
    {timeout : Bool} {out : StepOutput}
    (stateEq : out.state = advanceTimeoutLane input timeout)
    (effectsEq : out.effects = [])
    : AdvanceSpec config input out where
  votes := by simp [stateEq]
  gossips := by simp [stateEq]
  nonGossiping := by simp [stateEq]
  voting voting := Or.inl ⟨by simpa [stateEq] using voting, by simp [stateEq]⟩
  opening := by simp [effectsEq]

/-- Characterizes every successful phase advance once, so callers avoid re-unfolding it. -/
private lemma advance_spec {config : Execution.Local.Config} {input : NodeState}
    {timeout : Bool} {out : StepOutput}
    (advanced : advance config input timeout = some out)
    : AdvanceSpec config input out := by
  cases phase : input.phase <;> simp only [advance, phase] at advanced
  · split at advanced
    · split at advanced
      · cases advanced
      · cases advanced
        rename_i chosen txid found
        exact {
          votes := by simp
          gossips := by simp
          nonGossiping := fun pastGossip => absurd phase pastGossip
          voting := fun _ => Or.inr ⟨phase, by simp [NodeVotingSelection, found]⟩
          opening := by simp }
    · cases advanced
      exact AdvanceSpec.lane rfl rfl
  · split at advanced
    · split at advanced
      · cases advanced
        exact AdvanceSpec.lane (timeout := false) rfl rfl
      · cases advanced
        rename_i sufficient _
        exact {
          votes := by simp
          gossips := by simp
          nonGossiping := by simp
          voting := by simp
          opening := by
            simp only [List.mem_singleton, Effect.opening.injEq]
            rintro kind rfl
            refine ⟨by simp, by simp, ?_⟩
            intro quorum
            split at quorum
            · cases quorum
            · grind }
    · cases advanced
      exact AdvanceSpec.lane rfl rfl
  · split at advanced
    · cases advanced
      exact {
        votes := by simp
        gossips := by simp
        nonGossiping := by simp
        voting := by simp
        opening := by simp }
    · cases advanced
      exact AdvanceSpec.lane rfl rfl
  · split at advanced
    · cases advanced
    · cases advanced
      exact {
        votes := by simp
        gossips := by simp
        nonGossiping := by simp [phase]
        voting := by simp [phase]
        opening := by simp }
  · cases advanced
    exact AdvanceSpec.lane rfl rfl

/-- Characterizes every local step once; the per-field step lemmas below follow from it. -/
private lemma step_spec (config : Execution.Local.Config) (state : NodeState)
    (event : Event)
    : StepSpec config state event (step config state event) := by
  have advance_getD_spec
      {config : Execution.Local.Config} {state received : NodeState} {event : Event}
      {timeout : Bool} (reason : String) (related : Received state event received)
      : StepSpec config state event
          ((advance config received timeout).getD (rejected state reason)) := by
    cases advanced : advance config received timeout with
    | none => exact Or.inl ⟨rfl, by simp [rejected]⟩
    | some out => exact Or.inr ⟨received, timeout, related, advanced⟩
  have rejected_spec {config : Execution.Local.Config} {state : NodeState}
      {event : Event} (reason : String)
      : StepSpec config state event (rejected state reason) :=
    Or.inl ⟨rfl, by simp [rejected]⟩
  cases event with
  | receiveGossip source txid validation =>
      cases validation
      · by_cases chosen : state.chosen = none
        · simp only [step, Execution.Local.transitionSystem, guard, chosen]
          exact advance_getD_spec _
            { gossiping := id
              voting := fun voting => ⟨voting, chosen.symm, Or.inr chosen⟩
              votes := Or.inl rfl }
        · simp only [step, Execution.Local.transitionSystem, guard, chosen]
          exact rejected_spec _
      · exact rejected_spec _
  | receiveVote source validation =>
      cases validation
      · exact advance_getD_spec _
          { gossiping := id
            voting := fun voting => ⟨voting, rfl, Or.inl rfl⟩
            votes := Or.inr ⟨source, rfl, rfl⟩ }
      · exact rejected_spec _
  | receiveIAmOpen source validation =>
      cases validation
      · by_cases active : state.phase ≠ .opening /\ state.phase ≠ .open
        · obtain ⟨notOpening, notOpen⟩ := active
          simp only [step, Execution.Local.transitionSystem, guard, ne_eq, notOpening, notOpen,
            not_false_eq_true, and_self, ↓reduceIte, pure_bind]
          refine advance_getD_spec _ ⟨?_, ?_, Or.inl rfl⟩ <;> intro joining <;> cases joining
        · simp only [step, Execution.Local.transitionSystem, guard, active, ↓reduceIte]
          exact rejected_spec _
      · exact rejected_spec _
  | timeout =>
      exact advance_getD_spec _
        { gossiping := id
          voting := fun voting => ⟨voting, rfl, Or.inl rfl⟩
          votes := Or.inl rfl }
  | retry =>
      refine Or.inl ⟨rfl, ?_⟩
      simp only [step, Execution.Local.transitionSystem]
      split <;> try split
      all_goals simp

private lemma retry_sendVote_state
    {config : Execution.Local.Config} {state : NodeState} {target : Location}
    (member : .sendVote target ∈ (step config state .retry).effects)
    : state.phase = .voting /\ state.chosen = some target := by
  simp only [step, Execution.Local.transitionSystem] at member
  cases phase : state.phase <;> simp [phase] at member
  cases chosen : state.chosen <;> simp_all

private lemma retry_vote_state
    {config : Config}
    {envelope : Envelope}
    (valid : envelope.Valid config)
    (vote : envelope.payload = .vote)
    : envelope.sourceState.phase = .voting
      /\ envelope.sourceState.chosen = some envelope.target := by
  rcases valid_envelope_effect valid with
    ⟨effect, member, created⟩
  cases effect with
  | sendGossip target =>
      cases found : recoveredTxID config envelope.source <;>
        rw [messageForEffect, found] at created
      · cases created
      · rw [← Option.some.inj created] at vote
        cases vote
  | sendVote target =>
      rw [← Option.some.inj created]
      exact retry_sendVote_state member
  | sendIAmOpen target =>
      rw [← Option.some.inj created] at vote
      cases vote
  | opening kind => cases created
  | restart chosen => cases created
  | completed => cases created
  | rejected reason => cases created

private lemma opening_effect_state
    (config : Execution.Local.Config)
    (state : NodeState)
    (event : Event)
    (kind : OpenKind)
    (opening : .opening kind ∈ (step config state event).effects)
    : (step config state event).state.phase = .opening
      /\ (step config state event).state.openKind = some kind := by
  rcases step_spec config state event with ⟨_, noOpening⟩ | ⟨received, _, _, advanced⟩
  · exact absurd opening (noOpening kind)
  · obtain ⟨phase, openKind, _⟩ := (advance_spec advanced).opening kind opening
    exact ⟨phase, openKind⟩

private lemma sentVote_mono
    {before after : State}
    {voter target : Location}
    (sent : forall envelope, envelope ∈ before.sent -> envelope ∈ after.sent)
    (vote : SentVote before voter target)
    : SentVote after voter target := by
  rcases vote with
    ⟨envelope, membership, source, destination, payload⟩
  exact ⟨envelope, sent envelope membership, source, destination, payload⟩

private lemma opening_valid_of_sent_eq
    {config : Config}
    {before after : State}
    {opening : Opening}
    (sentEq : after.sent = before.sent)
    (valid : Opening.Valid config before opening)
    : Opening.Valid config after opening := by
  rcases valid with
    ⟨location, phase, kind, nodup, quorum, votesSent⟩
  constructor
  · exact location
  · exact phase
  · exact kind
  · exact nodup
  · exact quorum
  · intro voter membership
    apply sentVote_mono
    · intro envelope sent
      rw [sentEq]
      exact sent
    · exact votesSent voter membership

private lemma recordEffects_preserves_openings_valid
    {config : Config}
    {node : Location}
    {nodeState : NodeState}
    {state : State}
    {effects : List Effect}
    (valid : OpeningsValid config state)
    (newValid
      : forall kind,
          .opening kind ∈ effects
          -> Opening.Valid config state { node, kind, state := nodeState })
    : OpeningsValid config (recordEffects node nodeState effects state) := by
  have recordEffect_preserves_openings_valid
      {config : Config}
      {node : Location}
      {nodeState : NodeState}
      {state : State}
      {effect : Effect}
      (valid : OpeningsValid config state)
      (newValid
        : forall kind,
            effect = .opening kind
            -> Opening.Valid config state { node, kind, state := nodeState })
      : OpeningsValid config (recordEffect node nodeState state effect) := by
    intro opening membership
    cases effect with
    | opening kind =>
        simp [recordEffect] at membership
        rcases membership with rfl | old
        · apply opening_valid_of_sent_eq
            (before := state)
            (after := recordEffect node nodeState state (.opening kind))
            rfl
          exact newValid kind rfl
        · apply opening_valid_of_sent_eq
            (before := state)
            (after := recordEffect node nodeState state (.opening kind))
            rfl
          exact valid opening old
    | sendGossip target =>
        exact valid opening membership
    | sendVote target =>
        exact valid opening membership
    | sendIAmOpen target =>
        exact valid opening membership
    | restart target =>
        apply opening_valid_of_sent_eq
          (before := state)
          (after := recordEffect node nodeState state (.restart target))
          rfl
        exact valid opening membership
    | completed =>
        apply opening_valid_of_sent_eq
          (before := state)
          (after := recordEffect node nodeState state .completed)
          rfl
        exact valid opening membership
    | rejected reason =>
        exact valid opening membership
  induction effects generalizing state with
  | nil => exact valid
  | cons effect tail ih =>
      simp only [recordEffects, List.foldl_cons]
      apply ih
      · apply recordEffect_preserves_openings_valid valid
        intro kind effectEq
        subst effect
        exact newValid kind (by simp)
      · intro kind membership
        apply opening_valid_of_sent_eq
          (before := state)
          (after := recordEffect node nodeState state effect)
          (by cases effect <;> rfl)
        exact newValid kind (by simp [membership])

private lemma systemStep_preserves_votes_nodup
    {config : Execution.Local.Config}
    {before after : SystemState}
    {target : Location}
    {event : Event}
    {output : StepOutput}
    (nodup : forall entry, entry ∈ before.nodes -> entry.2.votes.Nodup)
    (transition : systemStep config before target event = some (after, output))
    : forall entry, entry ∈ after.nodes -> entry.2.votes.Nodup := by
  have insertVote_nodup (source : Location) {votes : List Location} (nodup : votes.Nodup)
      : (insertVote source votes).Nodup := by
    unfold insertVote
    split
    · exact nodup
    · rename_i absent
      apply (List.mergeSort_perm _ _).symm.nodup
      rw [List.nodup_cons]
      exact ⟨fun member => absent (List.contains_iff_mem.mpr member), nodup⟩
  have step_preserves_votes_nodup
      (config : Execution.Local.Config)
      (state : NodeState)
      (event : Event)
      (nodup : state.votes.Nodup)
      : (step config state event).state.votes.Nodup := by
    rcases step_spec config state event with ⟨same, _⟩ | ⟨received, _, fromState, advanced⟩
    · rw [same]
      exact nodup
    · rw [(advance_spec advanced).votes]
      rcases fromState.votes with same | ⟨source, _, inserted⟩
      · rw [same]
        exact nodup
      · rw [inserted]
        exact insertVote_nodup source nodup
  simp [systemStep, Option.bind_eq_some_iff] at transition
  rcases transition with
    ⟨node, ⟨key, found⟩, stateEq, _⟩
  rw [←stateEq]
  intro entry membership
  rw [replaceNode, List.mem_map] at membership
  rcases membership with ⟨previous, previousMember, rfl⟩
  split
  · apply step_preserves_votes_nodup
    exact nodup (key, node) (List.mem_of_find?_eq_some found)
  · exact nodup previous previousMember

private lemma systemStep_preserves_voting_selections
    {config : Execution.Local.Config}
    {before after : SystemState}
    {target : Location}
    {event : Event}
    {output : StepOutput}
    (valid
      : forall entry,
          entry ∈ before.nodes -> entry.2.phase = .voting -> NodeVotingSelection entry.2)
    (transition : systemStep config before target event = some (after, output))
    : forall entry,
        entry ∈ after.nodes
        -> entry.2.phase = .voting
        -> NodeVotingSelection entry.2 := by
  have step_preserves_voting_selection
      (config : Execution.Local.Config)
      (state : NodeState)
      (event : Event)
      (before : state.phase = .voting -> NodeVotingSelection state)
      (voting : (step config state event).state.phase = .voting)
      : NodeVotingSelection (step config state event).state := by
    rcases step_spec config state event with ⟨same, _⟩ | ⟨received, _, fromState, advanced⟩
    · rw [same] at voting ⊢
      exact before voting
    · have spec := advance_spec advanced
      rcases spec.voting voting with ⟨receivedVoting, chosen⟩ | ⟨_, selection⟩
      · obtain ⟨stateVoting, receivedChosen, gossips⟩ := fromState.voting receivedVoting
        obtain ⟨target, txid, stateChosen, maximum⟩ := before stateVoting
        refine ⟨target, txid, by rw [chosen, receivedChosen, stateChosen], ?_⟩
        rcases gossips with gossips | unchosen
        · rw [spec.gossips, gossips]
          exact maximum
        · rw [stateChosen] at unchosen
          cases unchosen
      · exact selection
  simp [systemStep, Option.bind_eq_some_iff] at transition
  rcases transition with
    ⟨node, ⟨key, found⟩, systemEq, outputEq⟩
  rw [←systemEq]
  intro entry membership voting
  rw [replaceNode, List.mem_map] at membership
  rcases membership with ⟨previous, previousMember, rfl⟩
  split
  · rename_i atTarget
    apply step_preserves_voting_selection config node event
    · exact valid (key, node)
        (List.mem_of_find?_eq_some found)
    · simpa [atTarget, outputEq] using voting
  · rename_i notTarget
    exact valid previous previousMember
      (by simpa [notTarget] using voting)

private lemma systemStep_output_location
    {config : Execution.Local.Config}
    {before after : SystemState}
    {target : Location}
    {event : Event}
    {output : StepOutput}
    (locations : forall entry, entry ∈ before.nodes -> entry.2.location = entry.1)
    (transition : systemStep config before target event = some (after, output))
    : output.state.location = target := by
  simp [systemStep, Option.bind_eq_some_iff] at transition
  rcases transition with
    ⟨node, ⟨key, found⟩, _, outputEq⟩
  calc
    output.state.location = node.location := by
      rw [←outputEq]
      exact step_preserves_location config node event
    _ = key :=
      locations (key, node) (List.mem_of_find?_eq_some found)
    _ = target :=
      beq_iff_eq.mp
        (List.find?_some
          (p :=
            fun entry : Prod Location NodeState =>
              entry.1 == target) found)

private lemma systemStep_output_mem
    {config : Execution.Local.Config}
    {before after : SystemState}
    {target : Location}
    {event : Event}
    {output : StepOutput}
    (transition : systemStep config before target event = some (after, output))
    : (target, output.state) ∈ after.nodes := by
  simp [systemStep, Option.bind_eq_some_iff] at transition
  rcases transition with
    ⟨node, ⟨key, found⟩, systemEq, outputEq⟩
  rw [←systemEq, replaceNode, List.mem_map]
  refine ⟨(key, node), List.mem_of_find?_eq_some found, ?_⟩
  have keyEq : key = target :=
    beq_iff_eq.mp
      (List.find?_some
        (p := fun entry : Prod Location NodeState =>
          entry.1 == target) found)
  simp [keyEq, outputEq]

private lemma systemStep_opening_effect_state
    {config : Execution.Local.Config}
    {before after : SystemState}
    {target : Location}
    {event : Event}
    {output : StepOutput}
    {kind : OpenKind}
    (transition : systemStep config before target event = some (after, output))
    (opening : .opening kind ∈ output.effects)
    : output.state.phase = .opening /\ output.state.openKind = some kind := by
  simp [systemStep, Option.bind_eq_some_iff] at transition
  rcases transition with
    ⟨node, _, _, outputEq⟩
  rw [←outputEq] at opening ⊢
  exact opening_effect_state config node event kind opening

private lemma systemStep_quorum_effect_has_threshold
    {config : Execution.Local.Config}
    {before after : SystemState}
    {target : Location}
    {event : Event}
    {output : StepOutput}
    (transition : systemStep config before target event = some (after, output))
    (opening : .opening .quorum ∈ output.effects)
    : voteQuorum config <= output.state.votes.length := by
  have quorum_effect_has_threshold
      (config : Execution.Local.Config)
      (state : NodeState)
      (event : Event)
      (opening : .opening .quorum ∈ (step config state event).effects)
      : voteQuorum config <= (step config state event).state.votes.length := by
    rcases step_spec config state event with ⟨_, noOpening⟩ | ⟨received, _, _, advanced⟩
    · exact absurd opening (noOpening .quorum)
    · have spec := advance_spec advanced
      rw [spec.votes]
      exact (spec.opening .quorum opening).2.2 rfl
  simp [systemStep, Option.bind_eq_some_iff] at transition
  rcases transition with
    ⟨node, _, _, outputEq⟩
  rw [←outputEq] at opening ⊢
  exact quorum_effect_has_threshold config node event opening

private lemma systemStep_preserves_node_votes_sent
    {config : Execution.Local.Config}
    {before after : SystemState}
    {target : Location}
    {event : Event}
    {output : StepOutput}
    {beforeState afterState : State}
    (beforeSystem : beforeState.system = before)
    (votesSent : NodeVotesSent beforeState)
    (carry
      : forall voter destination,
          SentVote beforeState voter destination -> SentVote afterState voter destination)
    (introduced
      : forall voter,
          acceptedVoteSource event = some voter -> SentVote afterState voter target)
    (transition : systemStep config before target event = some (after, output))
    : forall entry,
        entry ∈ after.nodes
        -> forall voter, voter ∈ entry.2.votes -> SentVote afterState voter entry.1 := by
  have mem_insertVote
      {member source : Location}
      {votes : List Location}
      (membership : member ∈ insertVote source votes)
      : member ∈ votes \/ member = source := by
    unfold insertVote at membership
    split at membership
    · exact Or.inl membership
    · have unsorted :=
        (List.mergeSort_perm _ _).mem_iff.mp membership
      rw [List.mem_cons] at unsorted
      exact unsorted.symm
  have step_votes_shape
      (config : Execution.Local.Config)
      (state : NodeState)
      (event : Event)
      : (step config state event).state.votes = state.votes
        \/ exists source,
            acceptedVoteSource event = some source
            /\ (step config state event).state.votes = insertVote source state.votes := by
    rcases step_spec config state event with ⟨same, _⟩ | ⟨received, _, fromState, advanced⟩
    · exact Or.inl (by rw [same])
    · rw [(advance_spec advanced).votes]
      exact fromState.votes
  have step_vote_origin
      (config : Execution.Local.Config)
      (state : NodeState)
      (event : Event)
      (voter : Location)
      (membership : voter ∈ (step config state event).state.votes)
      : voter ∈ state.votes \/ acceptedVoteSource event = some voter := by
    rcases step_votes_shape config state event with
      unchanged | ⟨source, sourceEq, changed⟩
    · rw [unchanged] at membership
      exact Or.inl membership
    · rw [changed] at membership
      rcases mem_insertVote membership with old | added
      · exact Or.inl old
      · subst source
        exact Or.inr sourceEq
  simp [systemStep, Option.bind_eq_some_iff] at transition
  rcases transition with
    ⟨node, ⟨key, found⟩, systemEq, outputEq⟩
  rw [←systemEq]
  intro entry membership voter vote
  rw [replaceNode, List.mem_map] at membership
  rcases membership with ⟨previous, previousMember, rfl⟩
  split
  · rename_i atTarget
    rcases step_vote_origin config node event voter
      (by simpa [outputEq, atTarget] using vote) with
      old | added
    · have keyEq : key = target :=
        beq_iff_eq.mp
          (List.find?_some
            (p := fun entry : Prod Location NodeState =>
              entry.1 == target) found)
      apply carry
      rw [←keyEq]
      exact votesSent (key, node)
        (by
          rw [beforeSystem]
          exact List.mem_of_find?_eq_some found)
        voter old
    · exact introduced voter added
  · rename_i notTarget
    apply carry
    exact votesSent previous
      (by
        rw [beforeSystem]
        exact previousMember)
      voter (by simpa [notTarget] using vote)

private lemma systemStep_preserves_vote_stability
    {config : Execution.Local.Config}
    {before after : SystemState}
    {target : Location}
    {event : Event}
    {output : StepOutput}
    {envelope : Envelope}
    (stable
      : forall entry,
          entry ∈ before.nodes
          -> entry.1 = envelope.source
          -> entry.2.phase ≠ .gossiping
              /\ (entry.2.phase = .voting -> entry.2.chosen = some envelope.target))
    (transition : systemStep config before target event = some (after, output))
    : forall entry,
        entry ∈ after.nodes
        -> entry.1 = envelope.source
        -> entry.2.phase ≠ .gossiping
            /\ (entry.2.phase = .voting -> entry.2.chosen = some envelope.target) := by
  have step_preserves_non_gossiping
      (config : Execution.Local.Config)
      (state : NodeState)
      (event : Event)
      (pastGossip : state.phase ≠ .gossiping)
      : (step config state event).state.phase ≠ .gossiping := by
    rcases step_spec config state event with ⟨same, _⟩ | ⟨received, _, fromState, advanced⟩
    · rw [same]
      exact pastGossip
    · exact (advance_spec advanced).nonGossiping
        (fun gossiping => pastGossip (fromState.gossiping gossiping))
  have voting_step_preserves_choice
      (config : Execution.Local.Config)
      (state : NodeState)
      (event : Event)
      (pastGossip : state.phase ≠ .gossiping)
      (stillVoting : (step config state event).state.phase = .voting)
      : state.phase = .voting /\ (step config state event).state.chosen = state.chosen := by
    rcases step_spec config state event with ⟨same, _⟩ | ⟨received, _, fromState, advanced⟩
    · rw [same] at stillVoting ⊢
      exact ⟨stillVoting, rfl⟩
    · rcases (advance_spec advanced).voting stillVoting with
        ⟨receivedVoting, chosen⟩ | ⟨gossiping, _⟩
      · obtain ⟨stateVoting, receivedChosen, _⟩ := fromState.voting receivedVoting
        exact ⟨stateVoting, chosen.trans receivedChosen⟩
      · exact absurd (fromState.gossiping gossiping) pastGossip
  simp [systemStep, Option.bind_eq_some_iff] at transition
  rcases transition with
    ⟨node, ⟨key, found⟩, systemEq, _⟩
  rw [←systemEq]
  intro entry membership sourceEq
  rw [replaceNode, List.mem_map] at membership
  rcases membership with ⟨previous, previousMember, rfl⟩
  split
  · rename_i atTarget
    have targetSource : target = envelope.source := by simpa [atTarget] using sourceEq
    have keyEq : key = target :=
      beq_iff_eq.mp
        (List.find?_some
          (p := fun entry : Prod Location NodeState =>
            entry.1 == target) found)
    have beforeStable :=
      stable (key, node) (List.mem_of_find?_eq_some found)
        (keyEq.trans targetSource)
    constructor
    · exact step_preserves_non_gossiping config node event
        beforeStable.1
    · intro voting
      rcases voting_step_preserves_choice config node event
        beforeStable.1 voting with ⟨beforeVoting, chosenEq⟩
      rw [chosenEq]
      exact beforeStable.2 beforeVoting
  · rename_i notTarget
    exact stable previous previousMember
      (by simpa [notTarget] using sourceEq)

/-- Inverts a successful retry transition. -/
private lemma next_retry_inv
    {config : Config} {before after : State} {source : Location}
    (transition : next config before (.retry source) = some after)
    : exists sourceState,
        nodeState before source = some sourceState
        /\ {
                before with
                  network := before.network ++ retryMessages config source sourceState
                  sent := before.sent ++ retryMessages config source sourceState
              }
            = after := by
  simp [next, Option.bind_eq_some_iff] at transition
  rcases transition with ⟨_, sourceState, found, _, stateEq⟩
  exact ⟨sourceState, found, stateEq⟩

/-- Inverts a successful delivery transition. -/
private lemma next_deliver_inv
    {config : Config} {before after : State} {envelope : Envelope}
    (transition : next config before (.deliver envelope) = some after)
    : exists system output,
        envelope ∈ before.network
        /\ systemStep config.protocol before.system envelope.target (eventFor envelope)
            = some (system, output)
        /\ recordEffects envelope.target output.state output.effects
              { before with system, network := removeOne envelope before.network }
            = after := by
  simp [next, Option.bind_eq_some_iff] at transition
  rcases transition with ⟨inNetwork, _, system, output, stepped, stateEq⟩
  exact ⟨system, output, inNetwork, stepped, stateEq⟩

/-- Inverts a successful timeout transition. -/
private lemma next_timeout_inv
    {config : Config} {before after : State} {target : Location}
    (transition : next config before (.timeout target) = some after)
    : exists system output,
        systemStep config.protocol before.system target .timeout = some (system, output)
        /\ recordEffects target output.state output.effects { before with system }
            = after := by
  simp [next, Option.bind_eq_some_iff] at transition
  rcases transition with ⟨_, system, output, stepped, _, stateEq⟩
  exact ⟨system, output, stepped, stateEq⟩

private lemma next_preserves_node_votes_nodup
    {config : Config}
    {before after : State}
    {action : Action}
    (nodup : NodeVotesNodup before)
    (transition : next config before action = some after)
    : NodeVotesNodup after := by
  cases action with
  | retry source =>
      rcases next_retry_inv transition with ⟨sourceState, _, rfl⟩
      exact nodup
  | deliver envelope =>
      rcases next_deliver_inv transition with
        ⟨system, output, _, systemStep, rfl⟩
      intro entry membership
      rw [recordEffects_system] at membership
      exact systemStep_preserves_votes_nodup nodup systemStep
        entry membership
  | timeout target =>
      rcases next_timeout_inv transition with ⟨system, output, systemStep, rfl⟩
      intro entry membership
      rw [recordEffects_system] at membership
      exact systemStep_preserves_votes_nodup nodup systemStep
        entry membership

private lemma deliver_preserves_node_votes_sent
    {config : Config}
    {before after : State}
    {envelope : Envelope}
    (wellFormed : WellFormed config before)
    (votesSent : NodeVotesSent before)
    (transition : next config before (.deliver envelope) = some after)
    : NodeVotesSent after := by
  have eventFor_vote_source
      {envelope : Envelope}
      {voter : Location}
      (source : acceptedVoteSource (eventFor envelope) = some voter)
      : envelope.payload = .vote /\ envelope.source = voter := by
    cases payload : envelope.payload <;>
      simp_all [eventFor, acceptedVoteSource]
  rcases next_deliver_inv transition with
    ⟨system, output, inNetwork, systemStep, stateEq⟩
  rw [←stateEq]
  intro entry membership voter vote
  rw [recordEffects_system] at membership
  let afterState :=
    recordEffects envelope.target output.state output.effects
      {
        before with
        system
        network := removeOne envelope before.network
      }
  have carry :
      forall oldVoter oldTarget,
        SentVote before oldVoter oldTarget ->
          SentVote afterState oldVoter oldTarget := by
    intro oldVoter oldTarget oldVote
    apply sentVote_mono (before := before) (after := afterState)
    · intro sent sentMember
      simpa [afterState] using sentMember
    · exact oldVote
  have introducedVote :
      forall newVoter,
        acceptedVoteSource (eventFor envelope) = some newVoter ->
          SentVote afterState newVoter envelope.target := by
    intro newVoter introduced
    rcases eventFor_vote_source introduced with
      ⟨payload, source⟩
    subst newVoter
    refine ⟨envelope, ?_, rfl, rfl, payload⟩
    simp [afterState]
    exact wellFormed.networkSent envelope
      inNetwork
  exact systemStep_preserves_node_votes_sent
    (before := before.system)
    (after := system)
    (beforeState := before)
    (afterState := afterState)
    rfl votesSent carry introducedVote systemStep
    entry membership voter vote

private lemma timeout_preserves_node_votes_sent
    {config : Config}
    {before after : State}
    {target : Location}
    (votesSent : NodeVotesSent before)
    (transition : next config before (.timeout target) = some after)
    : NodeVotesSent after := by
  rcases next_timeout_inv transition with ⟨system, output, systemStep, stateEq⟩
  rw [←stateEq]
  intro entry membership voter vote
  rw [recordEffects_system] at membership
  let afterState :=
    recordEffects target output.state output.effects
      { before with system }
  have carry :
      forall oldVoter oldTarget,
        SentVote before oldVoter oldTarget ->
          SentVote afterState oldVoter oldTarget := by
    intro oldVoter oldTarget oldVote
    apply sentVote_mono (before := before) (after := afterState)
    · intro sent sentMember
      simpa [afterState] using sentMember
    · exact oldVote
  have introducedVote :
      forall newVoter,
        acceptedVoteSource (.timeout : Event) = some newVoter ->
          SentVote afterState newVoter target := by
    intro newVoter introduced
    simp [acceptedVoteSource] at introduced
  exact systemStep_preserves_node_votes_sent
    (before := before.system)
    (after := system)
    (beforeState := before)
    (afterState := afterState)
    rfl votesSent carry introducedVote systemStep
    entry membership voter vote

private lemma deliver_preserves_openings_valid
    {config : Config}
    {before after : State}
    {envelope : Envelope}
    (wellFormed : WellFormed config before)
    (votesNodup : NodeVotesNodup before)
    (votesSent : NodeVotesSent before)
    (valid : OpeningsValid config before)
    (transition : next config before (.deliver envelope) = some after)
    : OpeningsValid config after := by
  have afterNodup :=
    next_preserves_node_votes_nodup votesNodup transition
  have afterVotesSent :=
    deliver_preserves_node_votes_sent wellFormed votesSent transition
  rcases next_deliver_inv transition with
    ⟨system, output, _, systemStep, stateEq⟩
  rw [←stateEq] at afterNodup afterVotesSent ⊢
  let delivered : State := {
    before with
    system
    network := removeOne envelope before.network
  }
  apply recordEffects_preserves_openings_valid
  · intro opening membership
    apply opening_valid_of_sent_eq
      (before := before) (after := delivered) rfl
    exact valid opening membership
  · intro kind openingEffect
    have effectState :=
      systemStep_opening_effect_state systemStep openingEffect
    constructor
    · exact systemStep_output_location
        wellFormed.nodeLocations systemStep
    · exact effectState.1
    · exact effectState.2
    · apply afterNodup (envelope.target, output.state)
      rw [recordEffects_system]
      exact systemStep_output_mem systemStep
    · intro quorumKind
      have kindEq : kind = .quorum := by simpa using quorumKind
      rw [kindEq] at openingEffect
      simpa using
        systemStep_quorum_effect_has_threshold systemStep openingEffect
    · intro voter vote
      have sent :=
        afterVotesSent (envelope.target, output.state)
          (by
            rw [recordEffects_system]
            exact systemStep_output_mem systemStep)
          voter vote
      simpa [SentVote, delivered] using sent

private lemma timeout_preserves_openings_valid
    {config : Config}
    {before after : State}
    {target : Location}
    (wellFormed : WellFormed config before)
    (votesNodup : NodeVotesNodup before)
    (votesSent : NodeVotesSent before)
    (valid : OpeningsValid config before)
    (transition : next config before (.timeout target) = some after)
    : OpeningsValid config after := by
  have afterNodup :=
    next_preserves_node_votes_nodup votesNodup transition
  have afterVotesSent :=
    timeout_preserves_node_votes_sent votesSent transition
  rcases next_timeout_inv transition with ⟨system, output, systemStep, stateEq⟩
  rw [←stateEq] at afterNodup afterVotesSent ⊢
  let timedOut : State := { before with system }
  apply recordEffects_preserves_openings_valid
  · intro opening membership
    apply opening_valid_of_sent_eq
      (before := before) (after := timedOut) rfl
    exact valid opening membership
  · intro kind openingEffect
    have effectState :=
      systemStep_opening_effect_state systemStep openingEffect
    constructor
    · exact systemStep_output_location
        wellFormed.nodeLocations systemStep
    · exact effectState.1
    · exact effectState.2
    · apply afterNodup (target, output.state)
      rw [recordEffects_system]
      exact systemStep_output_mem systemStep
    · intro quorumKind
      have kindEq : kind = .quorum := by simpa using quorumKind
      rw [kindEq] at openingEffect
      simpa using
        systemStep_quorum_effect_has_threshold systemStep openingEffect
    · intro voter vote
      have sent :=
        afterVotesSent (target, output.state)
          (by
            rw [recordEffects_system]
            exact systemStep_output_mem systemStep)
          voter vote
      simpa [SentVote, timedOut] using sent

private lemma deliver_preserves_sent_votes_functional
    {config : Config}
    {before after : State}
    {envelope : Envelope}
    (functional : SentVotesFunctional before)
    (transition : next config before (.deliver envelope) = some after)
    : SentVotesFunctional after := by
  rcases next_deliver_inv transition with
    ⟨system, output, _, _, stateEq⟩
  rw [←stateEq]
  intro voter first second firstVote secondVote
  apply functional voter first second
  · simpa [SentVote] using firstVote
  · simpa [SentVote] using secondVote

private lemma timeout_preserves_sent_votes_functional
    {config : Config}
    {before after : State}
    {target : Location}
    (functional : SentVotesFunctional before)
    (transition : next config before (.timeout target) = some after)
    : SentVotesFunctional after := by
  rcases next_timeout_inv transition with ⟨system, output, _, stateEq⟩
  rw [←stateEq]
  intro voter first second firstVote secondVote
  apply functional voter first second
  · simpa [SentVote] using firstVote
  · simpa [SentVote] using secondVote

private lemma reachable_quorum_invariant
    {config : Config}
    {state : State}
    (reachable : Reachable config state)
    : QuorumInvariant config state := by
  have opening_valid_mono
      {config : Config}
      {before after : State}
      {opening : Opening}
      (sent : forall envelope, envelope ∈ before.sent -> envelope ∈ after.sent)
      (valid : Opening.Valid config before opening)
      : Opening.Valid config after opening := by
    rcases valid with
      ⟨location, phase, kind, nodup, quorum, votesSent⟩
    constructor
    · exact location
    · exact phase
    · exact kind
    · exact nodup
    · exact quorum
    · intro voter membership
      exact sentVote_mono sent (votesSent voter membership)
  have initial_node_votes_nodup (config : Config) (nodes : List Location)
      : NodeVotesNodup (initial config nodes) := by
    intro _ membership
    obtain ⟨_, _, rfl⟩ := List.mem_map.mp membership
    exact List.nodup_nil
  have initial_node_votes_sent (config : Config) (nodes : List Location)
      : NodeVotesSent (initial config nodes) := by
    intro _ membership _ vote
    obtain ⟨_, _, rfl⟩ := List.mem_map.mp membership
    nomatch vote
  have initial_sent_votes_functional (config : Config) (nodes : List Location)
      : SentVotesFunctional (initial config nodes) :=
    fun _ _ _ ⟨_, sent, _⟩ => nomatch sent
  have initial_sent_vote_stable (config : Config) (nodes : List Location)
      : SentVoteStable (initial config nodes) :=
    fun _ sent => nomatch sent
  have initial_voting_selections (config : Config) (nodes : List Location)
      : VotingSelectionsValid (initial config nodes) := by
    intro _ membership voting
    obtain ⟨_, _, rfl⟩ := List.mem_map.mp membership
    nomatch voting
  have initial_sent_votes_selected (config : Config) (nodes : List Location)
      : SentVotesSelected (initial config nodes) :=
    fun _ sent => nomatch sent
  have initial_openings_valid (config : Config) (nodes : List Location)
      : OpeningsValid config (initial config nodes) :=
    fun _ opened => nomatch opened
  have next_preserves_voting_selections
      {config : Config}
      {before after : State}
      {action : Action}
      (valid : VotingSelectionsValid before)
      (transition : next config before action = some after)
      : VotingSelectionsValid after := by
    cases action with
    | retry source =>
        rcases next_retry_inv transition with ⟨sourceState, _, rfl⟩
        exact valid
    | deliver envelope =>
        rcases next_deliver_inv transition with
          ⟨system, output, _, systemStep, rfl⟩
        intro entry membership voting
        rw [recordEffects_system] at membership
        exact systemStep_preserves_voting_selections valid systemStep
          entry membership voting
    | timeout target =>
        rcases next_timeout_inv transition with ⟨system, output, systemStep, rfl⟩
        intro entry membership voting
        rw [recordEffects_system] at membership
        exact systemStep_preserves_voting_selections valid systemStep
          entry membership voting
  have retry_preserves_sent_votes_selected
      {config : Config}
      {before after : State}
      {source : Location}
      (wellFormed : WellFormed config before)
      (votingSelections : VotingSelectionsValid before)
      (selected : SentVotesSelected before)
      (transition : next config before (.retry source) = some after)
      : SentVotesSelected after := by
    rcases next_retry_inv transition with ⟨sourceState, found, stateEq⟩
    have sourceLocation : sourceState.location = source :=
      nodeState_location wellFormed.nodeLocations found
    rw [←stateEq]
    intro envelope membership payload
    rw [List.mem_append] at membership
    rcases membership with old | added
    · exact selected envelope old payload
    · have valid : envelope.Valid config :=
        retryMessages_valid config source sourceState sourceLocation
          envelope added
      have voteState := retry_vote_state valid payload
      have identity := retryMessages_source added
      rw [identity.2] at voteState
      rw [nodeState, Option.map_eq_some_iff] at found
      rcases found with ⟨entry, findEq, stateEq⟩
      have sourceSelection :=
        votingSelections entry (List.mem_of_find?_eq_some findEq)
          (by simpa [stateEq] using voteState.1)
      simpa [identity.2, stateEq] using sourceSelection
  have deliver_preserves_sent_votes_selected
      {config : Config}
      {before after : State}
      {envelope : Envelope}
      (selected : SentVotesSelected before)
      (transition : next config before (.deliver envelope) = some after)
      : SentVotesSelected after := by
    rcases next_deliver_inv transition with
      ⟨system, output, _, _, stateEq⟩
    rw [←stateEq]
    intro vote membership payload
    rw [recordEffects_sent] at membership
    exact selected vote membership payload
  have timeout_preserves_sent_votes_selected
      {config : Config}
      {before after : State}
      {target : Location}
      (selected : SentVotesSelected before)
      (transition : next config before (.timeout target) = some after)
      : SentVotesSelected after := by
    rcases next_timeout_inv transition with ⟨system, output, _, stateEq⟩
    rw [←stateEq]
    intro vote membership payload
    rw [recordEffects_sent] at membership
    exact selected vote membership payload
  have retry_preserves_node_votes_sent
      {config : Config}
      {before after : State}
      {source : Location}
      (votesSent : NodeVotesSent before)
      (transition : next config before (.retry source) = some after)
      : NodeVotesSent after := by
    rcases next_retry_inv transition with ⟨sourceState, _, rfl⟩
    intro entry membership voter vote
    apply sentVote_mono (before := before)
    · intro envelope sent
      exact List.mem_append_left _ sent
    · exact votesSent entry membership voter vote
  have retry_preserves_openings_valid
      {config : Config}
      {before after : State}
      {source : Location}
      (valid : OpeningsValid config before)
      (transition : next config before (.retry source) = some after)
      : OpeningsValid config after := by
    rcases next_retry_inv transition with ⟨sourceState, _, stateEq⟩
    rw [←stateEq]
    intro opening membership
    apply opening_valid_mono
    · intro envelope sent
      exact List.mem_append_left _ sent
    · exact valid opening membership
  have retry_preserves_sent_vote_stable
      {config : Config}
      {before after : State}
      {source : Location}
      (wellFormed : WellFormed config before)
      (stable : SentVoteStable before)
      (transition : next config before (.retry source) = some after)
      : SentVoteStable after := by
    rcases next_retry_inv transition with ⟨sourceState, found, stateEq⟩
    have sourceLocation : sourceState.location = source :=
      nodeState_location wellFormed.nodeLocations found
    rw [←stateEq]
    intro envelope membership payload entry entryMember keyEq
    rw [List.mem_append] at membership
    rcases membership with old | added
    · exact stable envelope old payload entry entryMember keyEq
    · have valid : envelope.Valid config :=
        retryMessages_valid config source sourceState sourceLocation
          envelope added
      have voteState := retry_vote_state valid payload
      rcases retryMessages_source added with
        ⟨sourceEq, stateEq⟩
      rw [nodeState, Option.map_eq_some_iff] at found
      rcases found with ⟨foundEntry, findEq, foundStateEq⟩
      have foundMember : foundEntry ∈ before.system.nodes :=
        List.mem_of_find?_eq_some findEq
      have foundKey : foundEntry.1 = source :=
        beq_iff_eq.mp
          (List.find?_some
            (p := fun entry : Prod Location NodeState =>
              entry.1 == source) findEq)
      have sameEntry : entry = foundEntry :=
        eq_of_key_eq wellFormed.nodeKeysNodup entryMember foundMember
          ((keyEq.trans sourceEq).trans foundKey.symm)
      subst entry
      rw [foundStateEq, ←stateEq]
      exact ⟨by simp [voteState.1], fun _ => voteState.2⟩
  have deliver_preserves_sent_vote_stable
      {config : Config}
      {before after : State}
      {delivered : Envelope}
      (stable : SentVoteStable before)
      (transition : next config before (.deliver delivered) = some after)
      : SentVoteStable after := by
    rcases next_deliver_inv transition with
      ⟨system, output, _, systemStep, stateEq⟩
    rw [←stateEq]
    intro envelope membership payload entry entryMember keyEq
    rw [recordEffects_sent] at membership
    rw [recordEffects_system] at entryMember
    exact systemStep_preserves_vote_stability
      (fun previous previousMember source =>
        stable envelope membership payload previous previousMember source)
      systemStep entry entryMember keyEq
  have timeout_preserves_sent_vote_stable
      {config : Config}
      {before after : State}
      {target : Location}
      (stable : SentVoteStable before)
      (transition : next config before (.timeout target) = some after)
      : SentVoteStable after := by
    rcases next_timeout_inv transition with ⟨system, output, systemStep, stateEq⟩
    rw [←stateEq]
    intro envelope membership payload entry entryMember keyEq
    rw [recordEffects_sent] at membership
    rw [recordEffects_system] at entryMember
    exact systemStep_preserves_vote_stability
      (fun previous previousMember source =>
        stable envelope membership payload previous previousMember source)
      systemStep entry entryMember keyEq
  have sentVote_stable_at_node
      {state : State}
      {voter target : Location}
      {current : NodeState}
      (stable : SentVoteStable state)
      (vote : SentVote state voter target)
      (found : nodeState state voter = some current)
      : current.phase ≠ .gossiping
        /\ (current.phase = .voting -> current.chosen = some target) := by
    rcases vote with
      ⟨envelope, sent, sourceEq, targetEq, payload⟩
    rw [nodeState, Option.map_eq_some_iff] at found
    rcases found with ⟨entry, findEq, stateEq⟩
    have entryMember : entry ∈ state.system.nodes :=
      List.mem_of_find?_eq_some findEq
    have entryKey : entry.1 = voter :=
      beq_iff_eq.mp
        (List.find?_some
          (p := fun entry : Prod Location NodeState =>
            entry.1 == voter) findEq)
    have result :=
      stable envelope sent payload entry entryMember
        (entryKey.trans sourceEq.symm)
    rw [stateEq] at result
    simpa [targetEq] using result
  have retry_preserves_sent_votes_functional
      {config : Config}
      {before after : State}
      {source : Location}
      (wellFormed : WellFormed config before)
      (functional : SentVotesFunctional before)
      (stable : SentVoteStable before)
      (transition : next config before (.retry source) = some after)
      : SentVotesFunctional after := by
    rcases next_retry_inv transition with ⟨sourceState, found, stateEq⟩
    have sourceLocation : sourceState.location = source :=
      nodeState_location wellFormed.nodeLocations found
    rw [←stateEq]
    have classify :
        forall voter target,
          SentVote
              {
                before with
                network := before.network ++
                  retryMessages config source sourceState
                sent := before.sent ++
                  retryMessages config source sourceState
              }
              voter target ->
            SentVote before voter target \/
              (voter = source /\
                sourceState.phase = .voting /\
                sourceState.chosen = some target) := by
      intro voter target vote
      rcases vote with
        ⟨envelope, membership, sourceEq, targetEq, payload⟩
      rw [List.mem_append] at membership
      rcases membership with old | added
      · exact Or.inl
          ⟨envelope, old, sourceEq, targetEq, payload⟩
      · have valid : envelope.Valid config :=
          retryMessages_valid config source sourceState sourceLocation
            envelope added
        have voteState := retry_vote_state valid payload
        have retryIdentity := retryMessages_source added
        rw [retryIdentity.2] at voteState
        exact Or.inr
          ⟨sourceEq.symm.trans retryIdentity.1,
            voteState.1,
            by simpa [targetEq] using voteState.2⟩
    intro voter first second firstVote secondVote
    rcases classify voter first firstVote with
      firstOld | ⟨firstSource, firstPhase, firstChoice⟩
    · rcases classify voter second secondVote with
        secondOld | ⟨secondSource, secondPhase, secondChoice⟩
      · exact functional voter first second firstOld secondOld
      · have oldState :=
          sentVote_stable_at_node stable firstOld
            (by simpa [secondSource] using found)
        have oldChoice := oldState.2 secondPhase
        rw [oldChoice] at secondChoice
        exact Option.some.inj secondChoice
    · rcases classify voter second secondVote with
        secondOld | ⟨_, _, secondChoice⟩
      · have oldState :=
          sentVote_stable_at_node stable secondOld
            (by simpa [firstSource] using found)
        have oldChoice := oldState.2 firstPhase
        rw [oldChoice] at firstChoice
        exact (Option.some.inj firstChoice).symm
      · rw [firstChoice] at secondChoice
        exact Option.some.inj secondChoice
  have initial_quorum_invariant (config : Config) (nodes : List Location)
      : QuorumInvariant config (initial config nodes) :=
    {
      votesNodup := initial_node_votes_nodup config nodes
      votesSent := initial_node_votes_sent config nodes
      sentVoteStable := initial_sent_vote_stable config nodes
      sentVotesFunctional := initial_sent_votes_functional config nodes
      votingSelections := initial_voting_selections config nodes
      sentVotesSelected := initial_sent_votes_selected config nodes
      openingsValid := initial_openings_valid config nodes
    }
  have next_preserves_quorum_invariant
      {config : Config}
      {before after : State}
      {action : Action}
      (wellFormed : WellFormed config before)
      (invariant : QuorumInvariant config before)
      (transition : next config before action = some after)
      : QuorumInvariant config after := by
    cases action with
    | retry source =>
        constructor
        · exact next_preserves_node_votes_nodup
            invariant.votesNodup transition
        · exact retry_preserves_node_votes_sent
            invariant.votesSent transition
        · exact retry_preserves_sent_vote_stable
            wellFormed invariant.sentVoteStable transition
        · exact retry_preserves_sent_votes_functional
            wellFormed invariant.sentVotesFunctional
              invariant.sentVoteStable transition
        · exact next_preserves_voting_selections
            invariant.votingSelections transition
        · exact retry_preserves_sent_votes_selected
            wellFormed invariant.votingSelections
              invariant.sentVotesSelected transition
        · exact retry_preserves_openings_valid
            invariant.openingsValid transition
    | deliver envelope =>
        constructor
        · exact next_preserves_node_votes_nodup
            invariant.votesNodup transition
        · exact deliver_preserves_node_votes_sent
            wellFormed invariant.votesSent transition
        · exact deliver_preserves_sent_vote_stable
            invariant.sentVoteStable transition
        · exact deliver_preserves_sent_votes_functional
            invariant.sentVotesFunctional transition
        · exact next_preserves_voting_selections
            invariant.votingSelections transition
        · exact deliver_preserves_sent_votes_selected
            invariant.sentVotesSelected transition
        · exact deliver_preserves_openings_valid
            wellFormed invariant.votesNodup invariant.votesSent
              invariant.openingsValid transition
    | timeout target =>
        constructor
        · exact next_preserves_node_votes_nodup
            invariant.votesNodup transition
        · exact timeout_preserves_node_votes_sent
            invariant.votesSent transition
        · exact timeout_preserves_sent_vote_stable
            invariant.sentVoteStable transition
        · exact timeout_preserves_sent_votes_functional
            invariant.sentVotesFunctional transition
        · exact next_preserves_voting_selections
            invariant.votingSelections transition
        · exact timeout_preserves_sent_votes_selected
            invariant.sentVotesSelected transition
        · exact timeout_preserves_openings_valid
            wellFormed invariant.votesNodup invariant.votesSent
              invariant.openingsValid transition
  induction reachable
    using @CCF.TransitionSystem.Reachable.rec (transitionSystem config) with
  | initial initialized =>
      rcases initialized with ⟨_, nodes, _, _, rfl⟩
      exact initial_quorum_invariant config nodes
  | step reachable transition invariant =>
      exact next_preserves_quorum_invariant
        (reachable_well_formed reachable) invariant transition

private lemma quorum_lists_intersect
    {α : Type}
    (expected first second : List α)
    (firstNodup : first.Nodup)
    (secondNodup : second.Nodup)
    (firstSubset : forall value, value ∈ first -> value ∈ expected)
    (secondSubset : forall value, value ∈ second -> value ∈ expected)
    (firstQuorum : expected.length / 2 + 1 <= first.length)
    (secondQuorum : expected.length / 2 + 1 <= second.length)
    : exists value, value ∈ first /\ value ∈ second := by
  apply Classical.byContradiction
  intro noShared
  have nodup : (first ++ second).Nodup :=
    List.nodup_append.mpr ⟨firstNodup, secondNodup,
      fun value firstMember _ secondMember same =>
        noShared ⟨value, firstMember, same ▸ secondMember⟩⟩
  have bound := nodup.length_le_of_subset (l₂ := expected) fun value member =>
    (List.mem_append.mp member).elim (firstSubset value) (secondSubset value)
  rw [List.length_append] at bound
  omega

private lemma quorum_opener_unique
    {config : Config}
    {state : State}
    {first second : Location}
    (reachable : Reachable config state)
    (firstOpened : QuorumOpened state first)
    (secondOpened : QuorumOpened state second)
    : first = second := by
  have opening_vote_configured
      {config : Config}
      {state : State}
      {opening : Opening}
      (wellFormed : WellFormed config state)
      (valid : Opening.Valid config state opening)
      {voter : Location}
      (vote : voter ∈ opening.state.votes)
      : voter ∈ config.protocol.expectedLocations := by
    rcases valid.votesSent voter vote with
      ⟨envelope, sent, sourceEq, _, _⟩
    simpa [sourceEq] using wellFormed.sentSourceConfigured envelope sent
  have wellFormed := reachable_well_formed reachable
  have invariant := reachable_quorum_invariant reachable
  rcases firstOpened with
    ⟨firstOpening, firstMember, firstNode, firstKind⟩
  rcases secondOpened with
    ⟨secondOpening, secondMember, secondNode, secondKind⟩
  have firstValid :=
    invariant.openingsValid firstOpening firstMember
  have secondValid :=
    invariant.openingsValid secondOpening secondMember
  rcases quorum_lists_intersect
      config.protocol.expectedLocations
      firstOpening.state.votes
      secondOpening.state.votes
      firstValid.votesNodup
      secondValid.votesNodup
      (fun voter vote =>
        opening_vote_configured wellFormed firstValid vote)
      (fun voter vote =>
        opening_vote_configured wellFormed secondValid vote)
      (by
        simpa [voteQuorum] using firstValid.quorum firstKind)
      (by
        simpa [voteQuorum] using secondValid.quorum secondKind) with
    ⟨voter, firstVote, secondVote⟩
  have targetEq :=
    invariant.sentVotesFunctional voter
      firstOpening.node secondOpening.node
      (firstValid.votesSent voter firstVote)
      (secondValid.votesSent voter secondVote)
  exact firstNode.symm.trans (targetEq.trans secondNode)

end DisasterRecovery.Proofs.Quorum

namespace DisasterRecovery.Proofs.Local

open CCF
open Model.Local

@[simp]
private lemma effect_pure {S A : Type} (a : A) (s : S)
    : (pure a : StateT S Option A) s = some (a, s) :=
  rfl

@[simp]
private lemma effect_bind {S A B : Type} (a : StateT S Option A)
    (f : A -> StateT S Option B) (s : S)
    : (a >>= f) s = (a s).bind (fun (a, s) => f a s) :=
  rfl

@[simp]
private lemma effect_modify {S : Type} (f : S -> S) (s : S)
    : (modify f : StateT S Option Unit) s = some ((), f s) :=
  rfl

@[simp]
private lemma effect_lift {S A : Type} (a : Option A) (s : S)
    : (liftM a : StateT S Option A) s = a.map (fun a => (a, s)) := by
  cases a <;> rfl

@[simp]
private lemma effect_failure {S A : Type} (s : S)
    : (failure : StateT S Option A) s = none := by
  have effect_failure_internal {S A : Type} (s : S)
      : (failure : StateT S Option A) s = none :=
    rfl
  exact effect_failure_internal s

@[simp]
private lemma effect_alternative {S A : Type} (a b : StateT S Option A) (s : S)
    : (a <|> b) s = (a s <|> b s) := by
  have effect_orElse_internal {S A : Type} (a : StateT S Option A)
      (b : Unit -> StateT S Option A) (s : S)
      : (StateT.orElse a b) s = (a s <|> b () s) :=
    rfl
  exact effect_orElse_internal a (fun _ => b) s

private lemma validStep_run {config : Model.Config}
    {s
      : MultiNodeTransitionSystem.LocalStep Location NodeState Event Message Notification}
    (valid : (Model.protocol config).ValidStep s)
    : exists recovered,
        Model.recoveredTxID config s.node = some recovered
        /\ (step (Capabilities.record s.node) config.protocol recovered s.before
              s.action).run
              {}
            = some (s.after, s.effects) := by
  simp [MultiNodeTransitionSystem.Protocol.ValidStep, Model.protocol, StateT.run,
    Option.bind_eq_some_iff, Option.map_eq_some_iff] at valid
  obtain ⟨_, _, ⟨_, found, rfl, rfl⟩, stepped⟩ := valid
  exact ⟨_, found, stepped⟩

end DisasterRecovery.Proofs.Local

namespace DisasterRecovery.Proofs.Lifting

open CCF
open DisasterRecovery.Model.Local
open Execution.Local (messages)
open DisasterRecovery.Proofs.Local
attribute [local simp] StateT.run

private lemma messages_cons (source : Location) (recovered : TxID)
    (effect : Execution.Local.Effect) (effects : List Execution.Local.Effect)
    : messages source recovered (effect :: effects)
      = messages source recovered [effect] ++ messages source recovered effects := by
  cases effect <;> rfl

private lemma messages_map (source : Location) (recovered : TxID)
    (send : Location -> Execution.Local.Effect) (message : Message)
    (sends
      : forall target,
          messages source recovered [send target]
          = [{ source, target, payload := message }])
    (targets : List Location)
    : messages source recovered (targets.map send)
      = targets.map fun target => { source, target, payload := message } := by
  induction targets with
  | nil => rfl
  | cons head tail ih => rw [List.map_cons, messages_cons, sends, ih]; rfl

/-- The executable and instrumented phase advances agree, case by case, by computation. -/
private lemma advance_run (config : Config) (source : Location) (recovered : TxID)
    (state : NodeState) (timeout : Bool)
    : advance (Capabilities.record source) config state timeout {}
      = (Execution.Local.advance config state timeout).map (toRun source recovered) := by
  rcases state with ⟨location, phase, timeoutState, gossips, votes, chosen, openKind, restart⟩
  unfold advance Execution.Local.advance
  cases phase <;> dsimp only
  case gossiping =>
    split
    · cases maximumGossip gossips
      · exact effect_failure _
      · rfl
    · rfl
  case joining =>
    cases chosen
    · exact effect_failure _
    · rfl
  all_goals repeat' split
  all_goals rfl

/-- Every instrumented advance is accepted and emits only notifications. -/
private lemma advance_output (config : Config) (state : NodeState) (timeout : Bool)
    (output : Execution.Local.StepOutput)
    (h : Execution.Local.advance config state timeout = some output)
    (source : Location) (recovered : TxID)
    : output.accepted = true /\ messages source recovered output.effects = [] := by
  revert h
  rcases state with ⟨location, phase, timeoutState, gossips, votes, chosen, openKind, restart⟩
  unfold Execution.Local.advance
  cases phase <;> dsimp only
  case gossiping =>
    split
    · cases maximumGossip gossips
      · nofun
      · rintro ⟨⟩
        exact ⟨rfl, rfl⟩
    · rintro ⟨⟩
      exact ⟨rfl, rfl⟩
  case joining =>
    cases chosen
    · nofun
    · rintro ⟨⟩
      exact ⟨rfl, rfl⟩
  all_goals repeat' split
  all_goals rintro ⟨⟩
  all_goals exact ⟨rfl, rfl⟩

/-- Receive events never disable the executable step; they match the instrumented step. -/
private lemma receive_run (config : Config) (source : Location) (recovered : TxID)
    (state : NodeState) (event : Event) (notRetry : event ≠ .retry)
    (notTimeout : event ≠ .timeout)
    : (step (Capabilities.record source) config recovered state event).run {}
      = some (toRun source recovered (Execution.Local.step config state event)) := by
  have orElse_rejected (source : Location) (recovered : TxID)
      (result : Option Execution.Local.StepOutput) (state : NodeState) (reason : String)
      : (result.map (toRun source recovered)
          <|> rejected (Capabilities.record source) state reason {})
        = some
            (toRun source recovered
              (result.getD (Execution.Local.rejected state reason))) := by
    cases result <;> rfl
  rcases state with ⟨location, phase, timeoutState, gossips, votes, chosen, openKind, restart⟩
  unfold StateT.run
  cases event with
  | retry | timeout => contradiction
  | receiveGossip sender txid validation =>
      cases validation
      · cases chosen
        · simp (config := { decide := true }) only [step, reduceIte, effect_alternative,
            advance_run _ source recovered]
          rw [orElse_rejected]
          rfl
        · rfl
      · rfl
  | receiveVote sender validation =>
      cases validation
      · simp only [step, effect_alternative, advance_run _ source recovered]
        rw [orElse_rejected]
        rfl
      · rfl
  | receiveIAmOpen sender validation =>
      cases validation
      · cases phase
        case opening | «open» => rfl
        all_goals
          simp only [step, effect_alternative, advance_run _ source recovered]
          rw [orElse_rejected]
          rfl
      · rfl

private lemma timeout_run (config : Config) (source : Location) (recovered : TxID)
    (state : NodeState)
    : (step (Capabilities.record source) config recovered state .timeout).run {}
      = (Execution.Local.advance config state true).map (toRun source recovered) :=
  advance_run config source recovered state true

private lemma retry_recorded (config : Config) (source : Location) (recovered : TxID)
    (state : NodeState)
    : (step (Capabilities.record source) config recovered state .retry).run {}
      = (do
          let outgoing :=
            messages source recovered (Execution.Local.step config state .retry).effects
          guard (!outgoing.isEmpty)
          pure (state, { outgoing, notifications := [] })) := by
  have effect_guard {S : Type} (c : Prop) [Decidable c] (s : S)
      : (guard c : StateT S Option Unit) s
        = (guard c : Option Unit).map fun _ => ((), s) := by
    unfold guard
    split
    · rfl
    · exact effect_failure s
  have option_guard (c : Prop) [Decidable c]
      : (guard c : Option Unit) = if c then some () else none := by
    unfold guard
    rfl
  have send_all_run (source : Location) (recovered : TxID) (message : Message)
      (send : Location -> Execution.Local.Effect)
      (sends
        : forall target,
            messages source recovered [send target]
            = [{ source, target, payload := message }])
      (targets : List Location) (accumulated : Outputs Location Message Notification)
      : (forIn targets PUnit.unit
            fun target (_ : PUnit) => do
              modify
                fun (outputs : Outputs Location Message Notification) =>
                  {
                    outputs with
                      outgoing :=
                        outputs.outgoing ++ [{ source, target, payload := message }]
                  }
              pure (ForInStep.yield PUnit.unit)
          : Effect Location Message Notification PUnit)
          accumulated
        = some
            (
              PUnit.unit,
              {
                accumulated with
                  outgoing :=
                    accumulated.outgoing ++ messages source recovered (targets.map send)
              }
            ) := by
    rw [messages_map source recovered send message sends]
    induction targets generalizing accumulated with
    | nil => simp
    | cons head tail ih =>
        simp only [List.forIn_cons, effect_bind, effect_modify, Option.bind_some, effect_pure, ih,
          List.map_cons, List.append_assoc, List.singleton_append]
  rcases state with ⟨location, phase, timeoutState, gossips, votes, chosen, openKind, restart⟩
  rcases config with ⟨instanceId, targets⟩
  cases phase
  case gossiping =>
    cases targets <;>
      simp only [StateT.run, step, effect_bind, effect_guard, Capabilities.record,
        show (Phase.gossiping == Phase.voting) = false from rfl, Bool.false_eq_true, reduceIte,
        Option.bind_some, effect_pure,
        send_all_run source recovered (.gossip recovered) .sendGossip (fun _ => rfl)]
    all_goals rfl
  case voting =>
    cases chosen <;> cases targets <;>
      simp only [StateT.run, step, effect_bind, effect_guard, Capabilities.record,
        beq_self_eq_true, reduceIte, Option.bind_some, effect_pure,
        send_all_run source recovered (.gossip recovered) .sendGossip (fun _ => rfl)]
    all_goals rfl
  case opening =>
    simp only [StateT.run, step, effect_bind, effect_guard, Capabilities.record,
      Option.bind_some, effect_pure,
      send_all_run source recovered .iAmOpen .sendIAmOpen (fun _ => rfl),
      Execution.Local.step, Option.pure_def, Option.getD, option_guard, List.isEmpty_map,
      messages_map source recovered .sendIAmOpen .iAmOpen (fun _ => rfl)]
    split <;> rfl
  all_goals exact effect_failure (A := NodeState) _

private lemma step_erases (config : Config) (recovered : TxID) (state : NodeState)
    (event : Event) {source : Location} (output : Result)
    (h
      : ((step (Capabilities.record source) config recovered state event).run {}).map
          capture
        = some output)
    : eraseOutput (Execution.Local.step config state event) = output := by
  have diagnostics_map (send : Location -> Execution.Local.Effect)
      (sends : forall target, (send target).diagnostic = none) (targets : List Location)
      : (targets.map send).filterMap Execution.Local.Effect.diagnostic = [] := by
    induction targets with
    | nil => rfl
    | cons head tail ih => rw [List.map_cons, List.filterMap_cons, sends, ih]
  have retry_diagnostics (config : Config) (state : NodeState)
      : (Execution.Local.step config state .retry).effects.filterMap
          Execution.Local.Effect.diagnostic
        = [] := by
    rcases state with ⟨location, phase, timeoutState, gossips, votes, chosen, openKind, restart⟩
    cases phase
    case voting =>
      cases chosen
      · exact diagnostics_map _ (fun _ => rfl) _
      · exact diagnostics_map _ (fun _ => rfl) _
    case gossiping | opening => exact diagnostics_map _ (fun _ => rfl) _
    all_goals rfl
  cases event
  case retry =>
    rw [retry_recorded] at h
    generalize messages source recovered _ = outgoing at h
    cases outgoing <;> cases h
    show ({ state, effects := _ } : Result) = { state }
    rw [retry_diagnostics]
  case timeout =>
    rw [timeout_run _ _ recovered] at h
    cases advanced : Execution.Local.advance config state true <;>
      rw [advanced] at h <;> cases h
    show eraseOutput ((Execution.Local.advance config state true).getD _) = _
    rw [advanced]
    rfl
  all_goals
    rw [receive_run config source recovered state _ ?_ ?_] at h
    · cases h
      rfl
    all_goals nofun

/-- Erasing snapshots can merge envelopes. Select before removing, using projected equality. -/
private lemma first_matching_envelope
    (envelopes : List Execution.Global.Envelope) (envelope : Model.Envelope)
    (present : envelope ∈ envelopes.map eraseEnvelope)
    : exists decorated,
        decorated ∈ envelopes
        /\ eraseEnvelope decorated = envelope
        /\ (Execution.Global.removeOne decorated envelopes).map eraseEnvelope
            = MultiNodeTransitionSystem.removeOne envelope (envelopes.map eraseEnvelope)
        /\ envelopes.find? (fun candidate => eraseEnvelope candidate == envelope)
            = some decorated := by
  induction envelopes with
  | nil => simp at present
  | cons head tail ih =>
      by_cases first : eraseEnvelope head = envelope
      · refine ⟨head, by simp, first, ?_, ?_⟩
        · simp [Execution.Global.removeOne, MultiNodeTransitionSystem.removeOne, first]
        · simp [first]
      · have member : envelope ∈ tail.map eraseEnvelope := by
          rcases List.mem_cons.mp present with same | member
          · exact False.elim (first same.symm)
          · exact member
        rcases ih member with ⟨decorated, member, projected, removed, selected⟩
        have different : head ≠ decorated := by
          intro same
          exact first (same ▸ projected)
        refine ⟨decorated, by simp [member], projected, ?_, ?_⟩
        · simp [Execution.Global.removeOne, MultiNodeTransitionSystem.removeOne, first,
            different, removed]
        · simp [first, selected]

private lemma transition_messages_empty (config : Config) (state : NodeState)
    (event : Event) (source : Location) (recovered : TxID)
    (notRetry : event ≠ .retry)
    : messages source recovered (Execution.Local.step config state event).effects
      = [] := by
  have advance_messages (config : Config) (state : NodeState) (timeout : Bool)
      (source : Location) (recovered : TxID) (fallback : Execution.Local.StepOutput)
      (empty : messages source recovered fallback.effects = [])
      : messages source recovered
          ((Execution.Local.advance config state timeout).getD fallback).effects
        = [] := by
    cases h : Execution.Local.advance config state timeout with
    | none => exact empty
    | some output =>
        exact (advance_output config state timeout output h source recovered).2
  rcases state with ⟨location, phase, timeoutState, gossips, votes, chosen, openKind, restart⟩
  cases event with
  | retry => contradiction
  | timeout =>
      refine advance_messages config _ true source recovered _ ?_
      rfl
  | receiveGossip _ _ validation =>
      cases validation
      · cases chosen
        · refine advance_messages config _ false source recovered _ ?_
          rfl
        · rfl
      · rfl
  | receiveVote _ validation =>
      cases validation
      · refine advance_messages config _ false source recovered _ ?_
        rfl
      · rfl
  | receiveIAmOpen sender validation =>
      cases validation
      · cases phase
        case opening | «open» => rfl
        all_goals
          refine advance_messages config
            { location, phase := .joining, timeoutState, gossips, votes, chosen := some sender,
              openKind, restartRequested := restart }
            false source recovered _ ?_
          rfl
      · rfl

private lemma retry_messages_erases (config : Model.Config) (source : Location)
    (state : NodeState) (recovered : TxID)
    (found : Model.recoveredTxID config source = some recovered)
    : (Execution.Global.retryMessages config source state).map eraseEnvelope
      = messages source recovered
          (Execution.Local.step config.protocol state .retry).effects := by
  unfold Execution.Global.retryMessages
  have found' : Execution.Global.recoveredTxID config source = some recovered := found
  generalize (Execution.Local.step config.protocol state .retry).effects = effects
  induction effects with
  | nil => rfl
  | cons effect tail ih =>
      rw [List.filterMap_cons, messages_cons, ← ih]
      cases effect
      case sendGossip target =>
        simp only [Execution.Global.messageForEffect, found']
        rfl
      all_goals rfl

private lemma local_step_run (config : Config) (source : Location) (recovered : TxID)
    (state : NodeState) (event : Event)
    : (step (Capabilities.record source) config recovered state event).run {}
      = (do
          let output <- ((step (Capabilities.record source)
                            config recovered state event).run
                          {}).map
                          capture
          let outgoing :=
            messages source recovered (Execution.Local.step config state event).effects
          match event with
          | .retry => guard (!outgoing.isEmpty)
          | _ => pure ()
          pure (output.state, { outgoing, notifications := output.effects })) := by
  cases event
  case retry =>
    rw [retry_recorded]
    generalize messages source recovered _ = outgoing
    cases outgoing <;> rfl
  case timeout =>
    rw [timeout_run _ _ recovered,
      transition_messages_empty config state .timeout source recovered nofun]
    cases advanced : Execution.Local.advance config state true with
    | none => rfl
    | some output =>
        simp only [Option.map_some, toRun,
          (advance_output _ _ _ output advanced source recovered).2]
        rfl
  all_goals
    rw [receive_run config source recovered state _ ?_ ?_]
    · rfl
    all_goals nofun

private lemma scheduled_step_some (config : Model.Config) (before after : Model.State)
    (node : Location) (event : Event)
    (h
      : (do
          let current <- MultiNodeTransitionSystem.nodeState before node
          let (next, effects) <- ((Model.protocol config).step (Capabilities.record node)
                                    node current event).run
                                  {}
          pure
            {
              before with
                nodes :=
                  before.nodes.map
                    fun entry => if entry.1 == node then (node, next) else entry
                network := before.network ++ effects.outgoing
            })
        = some after)
    : exists state output recovered,
        MultiNodeTransitionSystem.nodeState before node = some state
        /\ ((step (Capabilities.record node) config.protocol recovered state event).run
              {}).map
              capture
            = some output
        /\ Model.recoveredTxID config node = some recovered
        /\ (event = .retry
            -> messages node recovered
                  (Execution.Local.step config.protocol state event).effects
                ≠ [])
        /\ after
            = {
              before with
                nodes :=
                  before.nodes.map
                    fun entry => if entry.1 == node then (node, output.state) else entry
                network :=
                  before.network
                  ++ messages node recovered
                      (Execution.Local.step config.protocol state event).effects
            } := by
  have protocol_run (config : Model.Config) (node : Location) (state : NodeState)
      (event : Event)
      : ((Model.protocol config).step (Capabilities.record node) node state event).run {}
        = (Model.recoveredTxID config node).bind
            fun recovered =>
              (step (Capabilities.record node) config.protocol recovered state event).run
                {} := by
    simp only [Model.protocol, StateT.run, effect_bind, effect_lift]
    cases Model.recoveredTxID config node <;> rfl
  obtain ⟨state, found, h⟩ := Option.bind_eq_some_iff.mp h
  obtain ⟨⟨next, sent⟩, run, h⟩ := Option.bind_eq_some_iff.mp h
  cases h
  rw [protocol_run] at run
  obtain ⟨recovered, recoveredFound, run⟩ := Option.bind_eq_some_iff.mp run
  rw [local_step_run] at run
  obtain ⟨output, localEnabled, rest⟩ := Option.bind_eq_some_iff.mp run
  refine ⟨state, output, recovered, found, localEnabled, recoveredFound, ?_⟩
  cases event
  case retry =>
    generalize messages node recovered _ = outgoing at rest ⊢
    cases outgoing
    · cases rest
    · cases rest
      exact ⟨fun _ => nofun, rfl⟩
  all_goals
    cases rest
    exact ⟨nofun, rfl⟩

@[simp]
private lemma erase_recordEffects (node : Location) (state : NodeState)
    (effects : List Execution.Local.Effect) (before : Execution.Global.State)
    : erase (Execution.Global.recordEffects node state effects before)
      = erase before := by
  simp [erase]

end DisasterRecovery.Proofs.Lifting

namespace DisasterRecovery.Proofs.Committed

open Execution
open Execution.Local hiding Config
open Execution.Global Predicates
open DisasterRecovery.Proofs.Invariants DisasterRecovery.Proofs.Quorum

private lemma maximumGossip_mem
    {gossips : List (Prod Location TxID)}
    {selected : Prod Location TxID}
    (maximum : maximumGossip gossips = some selected)
    : selected ∈ gossips := by
  have foldl_selectMaximum_mem (current : Prod Location TxID)
      (tail : List (Prod Location TxID))
      : tail.foldl selectMaximum current ∈ current :: tail := by
    induction tail generalizing current with
    | nil => simp
    | cons candidate rest ih =>
        simp only [List.foldl_cons]
        have selected :
            selectMaximum current candidate = current \/
              selectMaximum current candidate = candidate := by
          unfold selectMaximum
          split <;> simp
        have member :=
          ih (selectMaximum current candidate)
        rw [List.mem_cons] at member
        rcases member with currentMember | restMember
        · rw [currentMember]
          rcases selected with selected | selected
          · simp [selected]
          · simp [selected]
        · simp [restMember]
  cases gossips with
  | nil => simp [maximumGossip] at maximum
  | cons head tail =>
      simp [maximumGossip] at maximum
      rw [←maximum]
      exact foldl_selectMaximum_mem head tail

private lemma recoveredTxID_of_mem
    {config : Config}
    {location : Location}
    {txid : TxID}
    (valid : config.Valid)
    (membership : (location, txid) ∈ config.recovered)
    : recoveredTxID config location = some txid := by
  have keysNodup : (config.recovered.map Prod.fst).Nodup := by
    rw [valid.2.2]
    exact valid.2.1
  unfold recoveredTxID
  cases found : config.recovered.find? fun entry => entry.1 == location with
  | none =>
      rw [List.find?_eq_none] at found
      exact False.elim (found (location, txid) membership (by simp))
  | some entry =>
      have foundMember : entry ∈ config.recovered :=
        List.mem_of_find?_eq_some found
      have foundLocation : entry.1 = location :=
        beq_iff_eq.mp
          (List.find?_some
            (p := fun entry : Prod Location TxID =>
              entry.1 == location) found)
      have same :
          entry = (location, txid) :=
        eq_of_key_eq keysNodup foundMember membership foundLocation
      simp [same]

private lemma up_to_date_with_quorum_of_voters
    {config : Config} {candidate : TxID} {voters : List Location}
    (nodup : voters.Nodup)
    (threshold : voteQuorum config.protocol <= voters.length)
    (fresh
      : forall voter,
          voter ∈ voters
          -> exists txid,
              recoveredTxID config voter = some txid /\ TxID.EarlierThan txid candidate)
    : Properties.UpToDateWithQuorum config candidate := by
  have mem_of_recoveredTxID
      {config : Config} {location : Location} {txid : TxID}
      (recovered : recoveredTxID config location = some txid)
      : (location, txid) ∈ config.recovered := by
    obtain ⟨entry, found, value⟩ := Option.map_eq_some_iff.mp recovered
    have key := beq_iff_eq.mp
      (List.find?_some (p := fun entry : Location × TxID => entry.1 == location) found)
    have same : entry = (location, txid) := Prod.ext key value
    rw [← same]
    exact List.mem_of_find?_eq_some found
  let eligible := config.recovered.filter fun (_, voter) =>
    decide (Properties.LogUpToDate candidate voter)
  have subset : voters ⊆ eligible.map Prod.fst := by
    intro voter member
    obtain ⟨txid, recovered, earlier⟩ := fresh voter member
    apply List.mem_map.mpr
    refine ⟨(voter, txid), List.mem_filter.mpr ⟨mem_of_recoveredTxID recovered, ?_⟩, rfl⟩
    exact decide_eq_true earlier
  have count := nodup.length_le_of_subset subset
  rw [List.length_map] at count
  exact Nat.le_trans threshold count

end DisasterRecovery.Proofs.Committed

namespace DisasterRecovery.Proofs.Lifting

open CCF
open DisasterRecovery.Model.Local
open Execution.Local (messages)
open DisasterRecovery.Proofs.Local
attribute [local simp] StateT.run

private lemma step_lifts (config : Model.Config)
    (before : Execution.Global.State) (action : Model.Action) (after : Model.State)
    (nodup : (before.system.nodes.map Prod.fst).Nodup)
    (h : (Model.transitionSystem config).step (erase before) action = some after)
    : exists decoratedAction decoratedAfter,
        eraseAction decoratedAction = action
        /\ Execution.Global.next config before decoratedAction = some decoratedAfter
        /\ erase decoratedAfter = after := by
  have advance_accepted (config : Config) (state : NodeState) (timeout : Bool)
      (output : Execution.Local.StepOutput)
      (h : Execution.Local.advance config state timeout = some output)
      : output.accepted = true :=
    (advance_output config state timeout output h "" default).1
  have timeout_accepted (config : Config) (recovered : TxID) (state : NodeState)
      (output : Result) {source : Location}
      (h
        : ((step (Capabilities.record source) config recovered state .timeout).run {}).map
            capture
          = some output)
      : (Execution.Local.step config state .timeout).accepted = true := by
    rw [timeout_run _ _ recovered] at h
    cases advanced : Execution.Local.advance config state true <;>
      rw [advanced] at h <;> cases h
    show ((Execution.Local.advance config state true).getD _).accepted = true
    rw [advanced]
    exact advance_accepted config state true _ advanced
  have replace_found
      (nodes : List (Location × NodeState)) (node : Location) (state : NodeState)
      (nodup : (nodes.map Prod.fst).Nodup)
      (found : (nodes.find? fun entry => entry.1 == node).map Prod.snd = some state)
      : (nodes.map fun entry => if entry.1 == node then (node, state) else entry)
        = nodes := by
    rcases Option.map_eq_some_iff.mp found with ⟨entry, selected, value⟩
    have member := List.mem_of_find?_eq_some selected
    have key : entry.1 = node := beq_iff_eq.mp
      (List.find?_some (p := fun entry : Location × NodeState => entry.1 == node) selected)
    conv => rhs; rw [← List.map_id nodes]
    apply List.map_congr_left
    intro other membership
    split
    · rename_i same
      have eq : other = entry :=
        Quorum.eq_of_key_eq nodup membership member
          ((beq_iff_eq.mp same).trans key.symm)
      subst other
      exact Prod.ext key.symm value.symm
    · rfl
  have systemStep_of_result (config : Model.Config)
      (before : Execution.Global.State) (node : Location) (event : Event)
      (recovered : TxID) (state : NodeState) (output : Result)
      {source : Location}
      (found : Execution.Global.nodeState before node = some state)
      (trans
        : ((step (Capabilities.record source) config.protocol recovered state event).run
            {}).map
            capture
          = some output)
      : Execution.Local.systemStep config.protocol before.system node event
        = some
            (
              {
                nodes :=
                  before.system.nodes.map
                    fun entry =>
                      if entry.1 == node then (node, output.state) else entry
              },
              Execution.Local.step config.protocol state event
            ) := by
    have states := congrArg Result.state (step_erases config.protocol recovered state event output trans)
    change (Execution.Local.step config.protocol state event).state = output.state at states
    unfold Execution.Global.nodeState at found
    simp [Execution.Local.systemStep, found, states,
      Execution.Local.replaceNode]
  cases action with
  | «local» node input =>
      cases input with
      | retry =>
          rcases scheduled_step_some config (erase before) after node .retry h with
            ⟨state, output, recovered, found, trans, recoveredFound, nonempty, result⟩
          have projectedOutput := step_erases config.protocol recovered state .retry output trans
          have outputState : output.state = state :=
            (congrArg Result.state projectedOutput).symm
          have projectedMessages := retry_messages_erases config node state recovered recoveredFound
          have hasMessages
              : (Execution.Global.retryMessages config node state).isEmpty = false := by
            cases empty : Execution.Global.retryMessages config node state
            · rw [empty] at projectedMessages
              exact absurd projectedMessages.symm (nonempty rfl)
            · rfl
          refine ⟨.retry node, {
            before with
            network := before.network ++ Execution.Global.retryMessages config node state
            sent := before.sent ++ Execution.Global.retryMessages config node state
          }, rfl, ?_, ?_⟩
          · have ghostFound : Execution.Global.nodeState before node = some state := found
            have ghostRecovered : Execution.Global.recoveredTxID config node = some recovered :=
              recoveredFound
            simp only [Execution.Global.next, ghostRecovered, ghostFound, Option.bind_eq_bind,
              Option.bind_some, hasMessages]
            rfl
          · rw [result, outputState]
            have unchanged := replace_found before.system.nodes node state nodup found
            simp only [erase, unchanged, List.map_append, projectedMessages]
      | timeout =>
          rcases scheduled_step_some config (erase before) after node .timeout h with
            ⟨state, output, recovered, found, trans, recoveredFound, _, result⟩
          have system := systemStep_of_result config before node .timeout recovered state output found trans
          have accepted := timeout_accepted config.protocol recovered state output trans
          have noMessages := transition_messages_empty config.protocol state .timeout node recovered
            (by intro impossible; cases impossible)
          have ghostRecovered : Execution.Global.recoveredTxID config node = some recovered :=
            recoveredFound
          refine ⟨.timeout node,
            Execution.Global.recordEffects node
              (Execution.Local.step config.protocol state .timeout).state
              (Execution.Local.step config.protocol state .timeout).effects
              { before with system := {
                nodes := before.system.nodes.map fun entry =>
                  if entry.1 == node then (node, output.state) else entry } },
            rfl, ?_, ?_⟩
          · simp only [Execution.Global.next, ghostRecovered, system, Option.bind_eq_bind,
              Option.bind_some, accepted]
            rfl
          · rw [erase_recordEffects, result, noMessages]
            simp [erase]
  | deliver envelope =>
      dsimp only [Model.transitionSystem, MultiNodeTransitionSystem.lift,
        MultiNodeTransitionSystem.next] at h
      cases contains : (erase before).network.contains envelope <;> rw [contains] at h
      · cases h
      have membership : envelope ∈ (erase before).network := List.elem_iff.mp contains
      rcases first_matching_envelope before.network envelope membership with
        ⟨decorated, member, projected, removed, _⟩
      rcases scheduled_step_some config
          { erase before with network := MultiNodeTransitionSystem.removeOne envelope (erase before).network }
          after envelope.target (Model.receive envelope.source envelope.payload) h with
        ⟨state, output, recovered, found, trans, recoveredFound, _, result⟩
      have eventEq : Execution.Global.eventFor decorated =
          Model.receive envelope.source envelope.payload := by
        rw [← projected]
        cases decorated.payload <;> rfl
      have targetEq : decorated.target = envelope.target := congrArg CCF.Envelope.target projected
      have ghostFound : Execution.Global.nodeState before decorated.target = some state := by
        rw [targetEq]
        exact found
      have ghostTrans :
          ((step (Capabilities.record envelope.target)
            config.protocol recovered state (Execution.Global.eventFor decorated)).run {}).map capture =
          some output := by
        rw [eventEq]
        exact trans
      have system := systemStep_of_result config before decorated.target
        (Execution.Global.eventFor decorated) recovered state output ghostFound ghostTrans
      have noMessages := transition_messages_empty config.protocol state
        (Model.receive envelope.source envelope.payload) envelope.target recovered
        (by cases envelope.payload <;> nofun)
      refine ⟨
        .deliver decorated,
        Execution.Global.recordEffects decorated.target
          (Execution.Local.step config.protocol state
            (Execution.Global.eventFor decorated)).state
          (Execution.Local.step config.protocol state
            (Execution.Global.eventFor decorated)).effects
          {
            before with
              system :=
                {
                  nodes :=
                    before.system.nodes.map
                      fun entry =>
                        if entry.1 == decorated.target then
                          (decorated.target, output.state)
                        else
                          entry
                }
              network := Execution.Global.removeOne decorated before.network
          },
        congrArg MultiNodeTransitionSystem.Action.deliver projected,
        ?_,
        ?_
      ⟩
      · have ghostRecovered : Execution.Global.recoveredTxID config decorated.target =
            some recovered := by rw [targetEq]; exact recoveredFound
        simp only [Execution.Global.next, List.elem_eq_true_of_mem member, ghostRecovered,
          system, Option.bind_eq_bind, Option.bind_some]
        rfl
      · rw [erase_recordEffects, result, noMessages]
        simp [erase, removed, targetEq]

private theorem model_initial_lifts (config : Model.Config) (state : Model.State)
    (initialized : (Model.transitionSystem config).init state)
    : exists decorated,
        (Execution.Global.transitionSystem config).init decorated
        /\ erase decorated = state := by
  rcases initialized with
    ⟨valid, covered, nodesNodup, network, nodes⟩
  have initialNodes :
      (state.nodes.map Prod.fst).map (fun node => (node, initialNode node)) =
        state.nodes := by
    rw [List.map_map]
    conv => rhs; rw [← List.map_id state.nodes]
    apply List.map_congr_left
    intro entry member
    have initialized := nodes entry member
    change entry.2 = initialNode entry.1 at initialized
    exact Prod.ext rfl initialized.symm
  refine ⟨Execution.Global.initial config (state.nodes.map Prod.fst),
    ⟨valid, _, nodesNodup, covered, rfl⟩, ?_⟩
  rcases state with ⟨nodes, network⟩
  simp_all [erase, Execution.Global.initial]

private theorem model_reachable_lifts {config : Model.Config} {state : Model.State}
    (reachable : (Model.transitionSystem config).Reachable state)
    : exists decorated,
        Execution.Global.Reachable config decorated /\ erase decorated = state := by
  induction reachable
    using @CCF.TransitionSystem.Reachable.rec (Model.transitionSystem config) with
  | initial initialized =>
      obtain ⟨decorated, init, projected⟩ := model_initial_lifts config _ initialized
      exact ⟨decorated, .initial init, projected⟩
  | @step before after action _ transition ih =>
      obtain ⟨decorated, ghostReachable, projected⟩ := ih
      obtain ⟨ghostAction, ghostAfter, _, ghostStep, erased⟩ :=
        step_lifts config decorated action after
          (Invariants.reachable_well_formed ghostReachable).nodeKeysNodup
          (by simpa only [projected] using transition)
      exact ⟨ghostAfter, .step ghostReachable ghostStep, erased⟩

end DisasterRecovery.Proofs.Lifting

namespace DisasterRecovery.Proofs.History

open CCF
open Lifting

/-- The prefix of a valid trace up to any of its positions is decorated by a reachable
ghost execution. -/
private theorem history_correspondence {config : Model.Config}
    (trace : Properties.GlobalTrace config) {bound : Nat}
    (inTrace : (trace.stateAt bound).isSome)
    : exists ghost, Correspondence config trace bound ghost := by
  have trace_lifts {config : Model.Config} {before after : Model.State} {tail}
      (path : Trace.Path (Model.transitionSystem config) before tail after)
      (ghost : Execution.Global.State) (reachable : Execution.Global.Reachable config ghost)
      (linked : erase ghost = before)
      : exists final,
          Decoration config ghost tail final
          /\ Execution.Global.Reachable config final
          /\ erase final = after := by
    induction path
      using @Trace.Path.rec (Model.transitionSystem config) generalizing ghost with
    | nil => exact ⟨ghost, .nil _, reachable, linked⟩
    | @cons before middle after tail action step _ ih =>
        obtain ⟨ghostAction, ghostMiddle, _, ghostStep, middleEq⟩ :=
          step_lifts config ghost action middle
            (Invariants.reachable_well_formed reachable).nodeKeysNodup
            (by simpa only [linked] using step)
        obtain ⟨final, decorated, reachableFinal, finalEq⟩ :=
          ih ghostMiddle (.step reachable ghostStep) middleEq
        exact ⟨
          final,
          middleEq ▸ Decoration.cons ghostStep decorated,
          reachableFinal,
          finalEq
        ⟩
  obtain ⟨last, found⟩ := Option.isSome_iff_exists.mp inTrace
  obtain ⟨before, first, initialized⟩ := trace.valid_init
  obtain ⟨initial, init, linked⟩ := model_initial_lifts config before initialized
  obtain ⟨tail, path⟩ := Trace.valid_path 0 bound first (by simpa using found)
  obtain ⟨final, _, reachable, finalEq⟩ := trace_lifts path initial (.initial init) linked
  refine ⟨final, reachable, fun i state le atI => ?_⟩
  obtain ⟨suffix, rest⟩ :=
    Trace.valid_path i (bound - i) atI (by rwa [Nat.add_sub_cancel' le])
  exact ⟨suffix, finalEq ▸ rest⟩

end DisasterRecovery.Proofs.History

namespace DisasterRecovery.Proofs.Lifting

open CCF
open DisasterRecovery.Model.Local
open Execution.Local (messages)
open DisasterRecovery.Proofs.Local
attribute [local simp] StateT.run

private theorem model_step_lifts {config : Model.Config} {before after : Model.State}
    {action : Model.Action}
    (reachable : (Model.transitionSystem config).Reachable before)
    (transition : (Model.transitionSystem config).step before action = some after)
    : exists decoratedBefore decoratedAction decoratedAfter,
        Execution.Global.Reachable config decoratedBefore
        /\ erase decoratedBefore = before
        /\ eraseAction decoratedAction = action
        /\ Execution.Global.next config decoratedBefore decoratedAction
            = some decoratedAfter
        /\ erase decoratedAfter = after := by
  obtain ⟨decoratedBefore, ghostReachable, linked⟩ := model_reachable_lifts reachable
  obtain ⟨decoratedAction, decoratedAfter, projectedAction, ghostStep, projectedAfter⟩ :=
    step_lifts config decoratedBefore action after
      (Invariants.reachable_well_formed ghostReachable).nodeKeysNodup
      (by simpa only [linked] using transition)
  exact ⟨decoratedBefore, decoratedAction, decoratedAfter,
    ghostReachable, linked, projectedAction, ghostStep, projectedAfter⟩

end DisasterRecovery.Proofs.Lifting

namespace DisasterRecovery.Proofs.Committed

open Execution
open Execution.Local hiding Config
open Execution.Global Predicates
open DisasterRecovery.Proofs.Invariants DisasterRecovery.Proofs.Quorum

private lemma prefix_refl (txid : TxID) : TxID.EarlierThan txid txid := by
  simp [TxID.EarlierThan]

private lemma prefix_of_score_false
    (leftName rightName : Location)
    (left right : TxID)
    (score : txScoreGreater leftName left rightName right = false)
    : TxID.EarlierThan left right := by
  simp [txScoreGreater] at score
  simp [TxID.EarlierThan]
  omega

private lemma maximumGossip_upper_bound
    {gossips : List (Prod Location TxID)}
    {selected member : Prod Location TxID}
    (maximum : maximumGossip gossips = some selected)
    (membership : member ∈ gossips)
    : TxID.EarlierThan member.2 selected.2 := by
  have prefix_trans
      {first second third : TxID}
      (firstSecond : TxID.EarlierThan first second)
      (secondThird : TxID.EarlierThan second third)
      : TxID.EarlierThan first third := by
    simp [TxID.EarlierThan] at firstSecond secondThird ⊢
    omega
  have prefix_of_score_true
      (leftName rightName : Location)
      (left right : TxID)
      (score : txScoreGreater leftName left rightName right = true)
      : TxID.EarlierThan right left := by
    simp [txScoreGreater] at score
    simp [TxID.EarlierThan]
    omega
  have current_prefix_selectMaximum (current candidate : Prod Location TxID)
      : TxID.EarlierThan current.2 (selectMaximum current candidate).2 := by
    unfold selectMaximum
    split
    · rename_i score
      exact prefix_of_score_true
        candidate.1 current.1 candidate.2 current.2 score
    · exact prefix_refl current.2
  have candidate_prefix_selectMaximum (current candidate : Prod Location TxID)
      : TxID.EarlierThan candidate.2 (selectMaximum current candidate).2 := by
    unfold selectMaximum
    split
    · exact prefix_refl candidate.2
    · rename_i score
      exact prefix_of_score_false
        candidate.1 current.1 candidate.2 current.2
        (Bool.eq_false_iff.mpr score)
  have foldl_selectMaximum_upper_bound
      (current member : Prod Location TxID)
      (tail : List (Prod Location TxID))
      (membership : member = current \/ member ∈ tail)
      : TxID.EarlierThan member.2 (tail.foldl selectMaximum current).2 := by
    induction tail generalizing current member with
    | nil =>
        simp at membership
        subst member
        exact prefix_refl current.2
    | cons candidate rest ih =>
        simp only [List.foldl_cons]
        rcases membership with currentMember | tailMember
        · subst member
          exact prefix_trans
            (current_prefix_selectMaximum current candidate)
            (ih (selectMaximum current candidate)
              (selectMaximum current candidate) (Or.inl rfl))
        · rw [List.mem_cons] at tailMember
          rcases tailMember with candidateMember | restMember
          · subst member
            exact prefix_trans
              (candidate_prefix_selectMaximum current candidate)
              (ih (selectMaximum current candidate)
                (selectMaximum current candidate) (Or.inl rfl))
          · exact ih (selectMaximum current candidate) member
              (Or.inr restMember)
  cases gossips with
  | nil => simp at membership
  | cons head tail =>
      simp [maximumGossip] at maximum
      rw [←maximum]
      apply foldl_selectMaximum_upper_bound head member tail
      simpa using membership

end DisasterRecovery.Proofs.Committed

namespace DisasterRecovery.Proofs.Gossip

open Execution
open Execution.Local hiding Config
open Execution.Global
open Invariants Quorum

private lemma evolves_refl (state : NodeState) : Evolves state state :=
  ⟨fun _ h => h, fun _ h => h, fun h => ⟨h, rfl⟩⟩

private lemma advance_frame {config : Execution.Local.Config} {state : NodeState}
    {timeout : Bool} {output : StepOutput}
    (advanced : advance config state timeout = some output)
    : Frame state output.state := by
  have frame_lane {before after : NodeState} (timeout : Bool)
      (frame : Frame before after)
      : Frame before (advanceTimeoutLane after timeout) := by
    cases timeout <;> exact frame
  unfold advance at advanced
  cases phase : state.phase <;> simp only [phase] at advanced
  · split at advanced
    · split at advanced
      · cases advanced
      · cases advanced
        exact frame_lane timeout ⟨rfl, rfl, fun _ => rfl⟩
    · cases advanced
      exact frame_lane timeout ⟨rfl, rfl, id⟩
  · split at advanced
    · split at advanced <;> cases advanced
      · exact ⟨rfl, rfl, id⟩
      · exact frame_lane timeout ⟨rfl, rfl, id⟩
    · cases advanced
      exact frame_lane timeout ⟨rfl, rfl, id⟩
  · split at advanced <;> cases advanced <;> exact frame_lane timeout ⟨rfl, rfl, id⟩
  · split at advanced <;> cases advanced
    exact frame_lane timeout ⟨rfl, rfl, id⟩
  · cases advanced
    exact frame_lane timeout ⟨rfl, rfl, id⟩

private lemma step_genuine (config : Config) (state : NodeState) (event : Event)
    (prior : state.gossips ⊆ config.recovered) (incoming : EventGenuine config event)
    : (step config.protocol state event).state.gossips ⊆ config.recovered := by
  have insertGossip_genuine {config : Config} {state : NodeState} {source : Location}
      {txid : TxID} (prior : state.gossips ⊆ config.recovered)
      (incoming : (source, txid) ∈ config.recovered)
      : insertGossip source txid state.gossips ⊆ config.recovered := by
    intro entry member
    unfold insertGossip at member
    split at member
    · exact prior member
    · have original := (List.mergeSort_perm _ _).mem_iff.mp member
      rcases List.mem_cons.mp original with rfl | old
      · exact incoming
      · exact prior old
  suffices stepped :
    forall output,
      (Execution.Local.transitionSystem config.protocol state.location).step { state }
          event
        = some output
      -> output.state.gossips ⊆ config.recovered by
    unfold step
    cases found
          : (Execution.Local.transitionSystem config.protocol state.location).step
              { state } event with
    | none => exact prior
    | some output => exact stepped output found
  intro output stepped
  cases event with
  | receiveGossip source txid validation =>
      simp only [Execution.Local.transitionSystem, guard] at stepped
      split at stepped
      · split at stepped
        · rename_i accepted _
          subst accepted
          rw [(advance_frame stepped).1]
          exact insertGossip_genuine prior incoming
        · cases stepped
      · cases stepped
  | receiveVote source validation =>
      simp only [Execution.Local.transitionSystem, guard] at stepped
      split at stepped
      · rw [(advance_frame stepped).1]
        exact prior
      · cases stepped
  | receiveIAmOpen source validation =>
      simp only [Execution.Local.transitionSystem, guard] at stepped
      split at stepped
      · split at stepped
        · rw [(advance_frame (config := config.protocol) (timeout := false)
            (state := { state with phase := .joining, chosen := some source }) stepped).1]
          exact prior
        · cases stepped
      · cases stepped
  | timeout =>
      rw [(advance_frame stepped).1]
      exact prior
  | retry =>
      cases stepped
      exact prior

private lemma next_genuine {config : Config} {before after : State} {action : Action}
    (wf : Predicates.WellFormed config before)
    (prior : Genuine config before.system.nodes)
    (transition : next config before action = some after)
    : Genuine config after.system.nodes := by
  have systemStep_genuine {config : Config} {before after : SystemState}
      {target : Location} {event : Event} {output : StepOutput}
      (prior : Genuine config before.nodes) (incoming : EventGenuine config event)
      (transition : systemStep config.protocol before target event = some (after, output))
      : Genuine config after.nodes := by
    simp only [systemStep, Option.bind_eq_bind, Option.bind_eq_some_iff, Option.map_eq_some_iff,
      Option.pure_def, Option.some.injEq, Prod.mk.injEq] at transition
    obtain ⟨_, ⟨⟨key, current⟩, found, rfl⟩, rfl, _⟩ := transition
    intro entry member
    obtain ⟨previous, present, rfl⟩ := List.mem_map.mp member
    split
    · exact step_genuine config current event
        (prior (key, current) (List.mem_of_find?_eq_some found)) incoming
    · exact prior previous present
  cases action with
  | retry source =>
      simpa only [retry_system_eq transition] using prior
  | deliver envelope =>
      simp only [next, guard, failure, Option.bind_eq_bind, Option.bind_eq_some_iff,
        Option.pure_def, Option.some.injEq, Option.ite_none_right_eq_some,
        List.contains_iff_mem, exists_const, and_true] at transition
      obtain ⟨pending, _, ⟨system, output⟩, updated, rfl⟩ := transition
      have incoming : EventGenuine config (eventFor envelope) := by
        cases payload : envelope.payload with
        | vote | iAmOpen =>
            unfold eventFor
            rw [payload]
            trivial
        | gossip txid =>
            unfold eventFor
            rw [payload]
            show (envelope.source, txid) ∈ config.recovered
            have recovered := valid_gossip_uses_recovered_txid
              (wf.sentValid _ (wf.networkSent _ pending)) payload
            obtain ⟨entry, found, value⟩ := Option.map_eq_some_iff.mp recovered
            have key := beq_iff_eq.mp
              (List.find?_some found :)
            have entryEq : entry = (envelope.source, txid) := Prod.ext key value
            rw [← entryEq]
            exact List.mem_of_find?_eq_some found
      simpa only [recordEffects_system] using systemStep_genuine prior incoming updated
  | timeout target =>
      simp only [next, guard, failure, Option.bind_eq_bind, Option.bind_eq_some_iff,
        Option.pure_def, Option.some.injEq, Option.ite_none_right_eq_some, exists_const,
        and_true] at transition
      obtain ⟨_, ⟨system, output⟩, updated, _, rfl⟩ := transition
      simpa only [recordEffects_system]
        using systemStep_genuine prior (by trivial) updated

private lemma step_evolves (config : Execution.Local.Config) (state : NodeState)
    (event : Event)
    : Evolves state (step config state event).state := by
  have insertGossip_extends (source : Location) (txid : TxID)
      (gossips : List (Location × TxID))
      : gossips ⊆ insertGossip source txid gossips := by
    intro entry member
    unfold insertGossip
    split
    · exact member
    · exact (List.mergeSort_perm _ _).mem_iff.mpr (List.mem_cons_of_mem _ member)
  have insertVote_extends (source : Location) (votes : List Location)
      : votes ⊆ insertVote source votes := by
    intro voter member
    unfold insertVote
    split
    · exact member
    · exact (List.mergeSort_perm _ _).mem_iff.mpr (List.mem_cons_of_mem _ member)
  have evolves_of_advance {config : Execution.Local.Config}
      {state received : NodeState} {timeout : Bool} {output : StepOutput}
      (advanced : advance config received timeout = some output)
      (gossips : state.gossips ⊆ received.gossips) (votes : state.votes ⊆ received.votes)
      (frozen
        : state.chosen.isSome = true
          -> received.chosen.isSome = true /\ received.gossips = state.gossips)
      : Evolves state output.state := by
    obtain ⟨sameGossips, sameVotes, keepsChoice⟩ := advance_frame advanced
    refine ⟨sameGossips ▸ gossips, sameVotes ▸ votes, fun chosen => ?_⟩
    obtain ⟨chosen', same⟩ := frozen chosen
    exact ⟨keepsChoice chosen', sameGossips.trans same⟩
  suffices stepped :
    forall output,
      (Execution.Local.transitionSystem config state.location).step { state } event
        = some output
      -> Evolves state output.state by
    unfold step
    cases found
          : (Execution.Local.transitionSystem config state.location).step
              { state } event with
    | none => exact evolves_refl state
    | some output => exact stepped output found
  intro output stepped
  cases event with
  | receiveGossip source txid validation =>
      simp only [Execution.Local.transitionSystem, guard] at stepped
      split at stepped
      · split at stepped
        · rename_i unchosen
          refine evolves_of_advance stepped (insertGossip_extends _ _ _) (fun _ h => h)
            fun chosen => ?_
          rw [unchosen] at chosen
          cases chosen
        · cases stepped
      · cases stepped
  | receiveVote source validation =>
      simp only [Execution.Local.transitionSystem, guard] at stepped
      split at stepped
      · exact evolves_of_advance stepped (fun _ h => h) (insertVote_extends _ _)
          fun chosen => ⟨chosen, rfl⟩
      · cases stepped
  | receiveIAmOpen source validation =>
      simp only [Execution.Local.transitionSystem, guard] at stepped
      split at stepped
      · split at stepped
        · exact evolves_of_advance (config := config) (timeout := false)
            (received := { state with phase := .joining, chosen := some source })
            stepped (fun _ h => h) (fun _ h => h) fun _ => ⟨rfl, rfl⟩
        · cases stepped
      · cases stepped
  | timeout =>
      exact evolves_of_advance stepped (fun _ h => h) (fun _ h => h) fun chosen => ⟨chosen, rfl⟩
  | retry =>
      cases stepped
      exact evolves_refl state

private lemma systemStep_evolves {config : Execution.Local.Config}
    {before after : SystemState} {target : Location} {event : Event} {output : StepOutput}
    (nodup : (before.nodes.map Prod.fst).Nodup)
    (transition : systemStep config before target event = some (after, output))
    {node : Location} {current : NodeState} (member : (node, current) ∈ before.nodes)
    : exists next, (node, next) ∈ after.nodes /\ Evolves current next := by
  simp only [systemStep, Option.bind_eq_bind, Option.bind_eq_some_iff, Option.map_eq_some_iff,
    Option.pure_def, Option.some.injEq, Prod.mk.injEq] at transition
  obtain ⟨_, ⟨⟨key, foundState⟩, found, rfl⟩, rfl, _⟩ := transition
  have foundMember := List.mem_of_find?_eq_some found
  have keyEq : key = target := beq_iff_eq.mp
    (List.find?_some found :)
  by_cases same : node = target
  · have equal := eq_of_key_eq nodup member foundMember (same.trans keyEq.symm)
    have stateEq := congrArg Prod.snd equal
    change current = foundState at stateEq
    subst foundState
    refine ⟨(step config current event).state, ?_, step_evolves config current event⟩
    exact List.mem_map.mpr ⟨(node, current), member, by simp [same]⟩
  · refine ⟨current, ?_, evolves_refl current⟩
    exact List.mem_map.mpr ⟨(node, current), member, by simp [same]⟩

private lemma next_evolves {config : Config} {before after : State} {action : Action}
    (wf : Predicates.WellFormed config before)
    (transition : next config before action = some after) {node : Location}
    {current : NodeState} (member : (node, current) ∈ before.system.nodes)
    : exists updated,
        (node, updated) ∈ after.system.nodes /\ Evolves current updated := by
  cases action with
  | retry source =>
      rw [retry_system_eq transition]
      exact ⟨current, member, evolves_refl current⟩
  | deliver envelope =>
      simp only [next, guard, failure, Option.bind_eq_bind, Option.bind_eq_some_iff,
        Option.pure_def, Option.some.injEq, Option.ite_none_right_eq_some,
        List.contains_iff_mem, exists_const, and_true] at transition
      obtain ⟨_, _, ⟨system, output⟩, updated, rfl⟩ := transition
      simpa only [recordEffects_system] using systemStep_evolves wf.nodeKeysNodup updated member
  | timeout target =>
      simp only [next, guard, failure, Option.bind_eq_bind, Option.bind_eq_some_iff,
        Option.pure_def, Option.some.injEq, Option.ite_none_right_eq_some, exists_const,
        and_true] at transition
      obtain ⟨_, ⟨system, output⟩, updated, _, rfl⟩ := transition
      simpa only [recordEffects_system] using systemStep_evolves wf.nodeKeysNodup updated member

private lemma trace_node_final {config : Model.Config}
    {trace : Properties.GlobalTrace config} {bound : Nat} {ghost : State}
    (linked : History.Correspondence config trace bound ghost) {i : Nat}
    {state : Model.State} (le : i <= bound) (found : trace.stateAt i = some state)
    {node : Location} {current : NodeState} (present : (node, current) ∈ state.nodes)
    : exists final, (node, final) ∈ ghost.system.nodes /\ Evolves current final := by
  have evolves_trans {first second third : NodeState}
      (left : Evolves first second) (right : Evolves second third)
      : Evolves first third :=
    ⟨
      fun _ h => right.gossips (left.gossips h),
      fun _ h => right.votes (left.votes h),
      fun chosen => by
        obtain ⟨chosen', same⟩ := left.frozen chosen
        obtain ⟨chosen'', same'⟩ := right.frozen chosen'
        exact ⟨chosen'', same'.trans same⟩
    ⟩
  have model_step_evolves {config : Model.Config} {before after : Model.State}
      {action : Model.Action} (reachable : (Model.transitionSystem config).Reachable before)
      (transition : (Model.transitionSystem config).step before action = some after)
      {node : Location} {current : NodeState} (member : (node, current) ∈ before.nodes)
      : exists updated, (node, updated) ∈ after.nodes /\ Evolves current updated := by
    obtain ⟨ghostBefore, ghostAction, ghostAfter, reachable', projected, _, step, projected'⟩ :=
      Lifting.model_step_lifts reachable transition
    have original : (node, current) ∈ ghostBefore.system.nodes := by
      simpa only [← projected, Lifting.erase] using member
    simpa only [← projected', Lifting.erase]
      using next_evolves (reachable_well_formed reachable') step original
  have steps_evolve {config : Model.Config} {before after : Model.State} {steps}
      (run : Trace.Path (Model.transitionSystem config) before steps after)
      (reachable : (Model.transitionSystem config).Reachable before)
      {node : Location} {current : NodeState} (member : (node, current) ∈ before.nodes)
      : exists updated, (node, updated) ∈ after.nodes /\ Evolves current updated := by
    induction run
      using @Trace.Path.rec (Model.transitionSystem config) generalizing current with
    | nil => exact ⟨current, member, evolves_refl current⟩
    | cons transition _ ih =>
        obtain ⟨middle, present, evolves⟩ := model_step_evolves reachable transition member
        obtain ⟨updated, present', evolves'⟩ := ih (.step reachable transition) present
        exact ⟨updated, present', evolves_trans evolves evolves'⟩
  obtain ⟨suffix, run⟩ := linked.suffix i state le found
  exact steps_evolve run (trace.reachable (CCF.Execution.Trace.stateAt_mem found)) present

private lemma next_frozen {config : Config} {before after : State} {action : Action}
    (wf : Predicates.WellFormed config before)
    (prior : FrozenVotes before)
    (transition : next config before action = some after)
    : FrozenVotes after := by
  have lookup_member {state : State} {node : Location} {current : NodeState}
      (found : nodeState state node = some current)
      : (node, current) ∈ state.system.nodes := by
    obtain ⟨entry, found, same⟩ := Option.map_eq_some_iff.mp found
    have key := beq_iff_eq.mp
      (List.find?_some found :)
    have entryEq : entry = (node, current) := Prod.ext key same
    rw [← entryEq]
    exact List.mem_of_find?_eq_some found
  have carry : forall envelope, envelope ∈ before.sent -> envelope.payload = .vote ->
      exists current, (envelope.source, current) ∈ after.system.nodes /\
        current.chosen.isSome = true /\ current.gossips = envelope.sourceState.gossips := by
    intro envelope sent vote
    obtain ⟨current, present, chosen, same⟩ := prior envelope sent vote
    obtain ⟨updated, present', evolves⟩ := next_evolves wf transition present
    obtain ⟨chosen', same'⟩ := evolves.frozen chosen
    exact ⟨updated, present', chosen', same'.trans same⟩
  cases action with
  | retry source =>
      simp only [next, guard, failure, Option.bind_eq_bind, Option.bind_eq_some_iff,
        Option.pure_def, Option.some.injEq, Option.ite_none_right_eq_some, exists_const,
        and_true] at transition
      obtain ⟨_, current, found, _, rfl⟩ := transition
      intro envelope sent vote
      rcases List.mem_append.mp sent with old | fresh
      · exact carry envelope old vote
      · have snapshot := retryMessages_source fresh
        have present := lookup_member found
        have location := nodeState_location wf.nodeLocations found
        have selected := (retry_vote_state (retryMessages_valid config source current location _ fresh) vote).2
        refine ⟨current, ?_, ?_, snapshot.2.symm ▸ rfl⟩
        · simpa only [snapshot.1] using present
        · rw [← snapshot.2, selected]
          rfl
  | deliver envelope =>
      simp only [next, guard, failure, Option.bind_eq_bind, Option.bind_eq_some_iff,
        Option.pure_def, Option.some.injEq, Option.ite_none_right_eq_some,
        List.contains_iff_mem, exists_const, and_true] at transition
      obtain ⟨_, _, ⟨system, output⟩, _, rfl⟩ := transition
      simpa only [FrozenVotes, recordEffects_sent] using carry
  | timeout target =>
      simp only [next, guard, failure, Option.bind_eq_bind, Option.bind_eq_some_iff,
        Option.pure_def, Option.some.injEq, Option.ite_none_right_eq_some, exists_const,
        and_true] at transition
      obtain ⟨_, ⟨system, output⟩, _, _, rfl⟩ := transition
      simpa only [FrozenVotes, recordEffects_sent] using carry

private lemma reachable_gossip_invariant {config : Config} {state : State}
    (reachable : Reachable config state)
    : Genuine config state.system.nodes /\ FrozenVotes state := by
  induction reachable
    using @CCF.TransitionSystem.Reachable.rec (transitionSystem config) with
  | initial initialized =>
      obtain ⟨_, nodes, _, _, rfl⟩ := initialized
      constructor
      · intro entry member
        obtain ⟨node, _, rfl⟩ := List.mem_map.mp member
        exact List.nil_subset _
      · intro envelope sent
        cases sent
  | step reachable transition ih =>
      have wf := reachable_well_formed reachable
      exact ⟨next_genuine wf ih.1 transition, next_frozen wf ih.2 transition⟩

end DisasterRecovery.Proofs.Gossip

namespace DisasterRecovery.Proofs.Observed

open Execution.Local
open Execution.Global hiding Config
open Predicates

private lemma advance_threshold {config : Config} {state : NodeState} {timeout : Bool}
    {output : StepOutput} (advanced : advance config state timeout = some output)
    (threshold : Threshold config state)
    : Threshold config output.state := by
  have lane_threshold {config : Config} {state : NodeState} (timeout : Bool)
      (threshold : Threshold config state)
      : Threshold config (advanceTimeoutLane state timeout) := by
    cases timeout <;> exact threshold
  unfold advance at advanced
  cases phase : state.phase <;> simp only [phase] at advanced
  · split at advanced
    · split at advanced
      · cases advanced
      · cases advanced
        exact lane_threshold timeout threshold
    · cases advanced
      exact lane_threshold timeout threshold
  · split at advanced
    · split at advanced
      · cases advanced
        exact threshold
      · cases advanced
        apply lane_threshold
        rintro kind ⟨⟩
        by_cases enough : voteQuorum config <= state.votes.length
        · simp [enough]
        · rename_i sufficient _
          have aligned : validTimeout state timeout = true := by
            simpa [enough] using sufficient
          cases votes : state.votes <;> simp_all
    · cases advanced
      exact lane_threshold timeout threshold
  · split at advanced <;> cases advanced <;> exact lane_threshold timeout threshold
  · split at advanced
    · cases advanced
    · cases advanced
      exact lane_threshold timeout threshold
  · cases advanced
    exact lane_threshold timeout threshold

private lemma step_preserves_opening_threshold (config : Config) (state : NodeState)
    (event : Event)
    (threshold
      : forall kind,
          state.openKind = some kind
          -> (if kind = .quorum then voteQuorum config else 1) <= state.votes.length)
    : forall kind,
        (step config state event).state.openKind = some kind
        -> (if kind = .quorum then voteQuorum config else 1)
            <= (step config state event).state.votes.length := by
  suffices stepped :
    forall output,
      (Execution.Local.transitionSystem config state.location).step { state } event
        = some output
      -> Threshold config output.state by
    unfold step
    cases found
          : (Execution.Local.transitionSystem config state.location).step
              { state } event with
    | none => exact threshold
    | some output => exact stepped output found
  intro output stepped
  cases event with
  | receiveGossip source txid validation =>
      simp only [Execution.Local.transitionSystem, guard] at stepped
      split at stepped
      · split at stepped
        · exact advance_threshold stepped threshold
        · cases stepped
      · cases stepped
  | receiveVote source validation =>
      simp only [Execution.Local.transitionSystem, guard] at stepped
      split at stepped
      · refine advance_threshold stepped fun kind opened => ?_
        refine Nat.le_trans (threshold kind opened) ?_
        unfold insertVote
        split <;> simp
      · cases stepped
  | receiveIAmOpen source validation =>
      simp only [Execution.Local.transitionSystem, guard] at stepped
      split at stepped
      · split at stepped
        · exact advance_threshold (timeout := false)
            (state := { state with phase := .joining, chosen := some source })
            stepped threshold
        · cases stepped
      · cases stepped
  | timeout => exact advance_threshold stepped threshold
  | retry =>
      cases stepped
      exact threshold

private lemma systemStep_preserves_opening_thresholds
    (config : Model.Config) (before after : SystemState)
    (target : Location) (event : Event) (output : StepOutput)
    (threshold
      : forall entry,
          entry ∈ before.nodes
          -> forall kind,
              entry.2.openKind = some kind
              -> (if kind = .quorum then voteQuorum config.protocol else 1)
                  <= entry.2.votes.length)
    (trans : systemStep config.protocol before target event = some (after, output))
    : forall entry,
        entry ∈ after.nodes
        -> forall kind,
            entry.2.openKind = some kind
            -> (if kind = .quorum then voteQuorum config.protocol else 1)
                <= entry.2.votes.length := by
  simp [systemStep, Option.bind_eq_some_iff] at trans
  rcases trans with ⟨state, found, rfl, rfl⟩
  rcases found with ⟨key, selectedFound⟩
  have selectedMember := List.mem_of_find?_eq_some selectedFound
  intro entry membership
  simp only [replaceNode, List.mem_map] at membership
  rcases membership with ⟨previous, member, entryEq⟩
  split at entryEq
  · subst entry
    exact step_preserves_opening_threshold config.protocol state event
      (threshold (key, state) selectedMember)
  · subst entry
    exact threshold previous member

private lemma next_preserves_opening_thresholds (config : Model.Config)
    (before after : State) (action : Action) (threshold : OpeningThresholds config before)
    (trans : next config before action = some after)
    : OpeningThresholds config after := by
  cases action with
  | retry source =>
      simpa only [OpeningThresholds, Invariants.retry_system_eq trans] using threshold
  | deliver envelope =>
      simp only [next, guard, failure, Option.bind_eq_bind, Option.bind_eq_some_iff,
        Option.pure_def, Option.some.injEq] at trans
      obtain ⟨_, _, _, _, ⟨system, output⟩, systemStep, rfl⟩ := trans
      intro entry member
      rw [Invariants.recordEffects_system] at member
      exact systemStep_preserves_opening_thresholds config before.system system
        envelope.target (eventFor envelope) output threshold systemStep entry member
  | timeout target =>
      simp only [next, guard, failure, Option.bind_eq_bind, Option.bind_eq_some_iff,
        Option.pure_def, Option.some.injEq] at trans
      obtain ⟨_, _, ⟨system, output⟩, systemStep, _, _, rfl⟩ := trans
      intro entry member
      rw [Invariants.recordEffects_system] at member
      exact systemStep_preserves_opening_thresholds config before.system system
        target .timeout output threshold systemStep entry member

private lemma reachable_opening_thresholds {config : Model.Config} {state : State}
    (reachable : Reachable config state)
    : OpeningThresholds config state := by
  induction reachable
    using @CCF.TransitionSystem.Reachable.rec (transitionSystem config) with
  | initial initialized =>
      rcases initialized with ⟨_, nodes, _, _, rfl⟩
      simp [OpeningThresholds, initial, initialNode]
  | step _ trans ih =>
      exact next_preserves_opening_thresholds config _ _ _ ih trans

private lemma reachable_quorum_thresholds {config : Model.Config} {state : State}
    (reachable : Reachable config state)
    (entry : Location × NodeState) (member : entry ∈ state.system.nodes)
    (quorum : entry.2.openKind = some .quorum)
    : voteQuorum config.protocol <= entry.2.votes.length := by
  simpa using reachable_opening_thresholds reachable entry member .quorum quorum

end DisasterRecovery.Proofs.Observed

namespace DisasterRecovery.Proofs.Gossip

open Execution
open Execution.Local hiding Config
open Execution.Global
open Invariants Quorum

lemma quorum_open_preserves_commit
    : forall (config : Model.Config) (trace : Properties.GlobalTrace config)
              (openedState : Model.State),
      forall (opener : Model.Local.Location) (openerState : Model.Local.NodeState),
        (openedState ∈ trace
          /\ (opener, openerState) ∈ openedState.nodes
          /\ openerState.openKind = some .quorum
          /\ (forall voter,
                voter ∈ openerState.votes -> Properties.ReceivedOwnGossip trace voter))
        -> exists openerTxID,
            Model.recoveredTxID config opener = some openerTxID
            /\ Properties.UpToDateWithQuorum config openerTxID := by
  have sent_vote_preserves_own {config : Config} {trace : Properties.GlobalTrace config}
      {bound : Nat} {ghost : State}
      (linked : History.Correspondence config trace bound ghost) {envelope : Envelope}
      (sent : envelope ∈ ghost.sent) (vote : envelope.payload = .vote)
      (own : OwnGossipBy trace bound envelope.source)
      : exists sourceTx targetTx,
          Model.recoveredTxID config envelope.source = some sourceTx
          /\ Model.recoveredTxID config envelope.target = some targetTx
          /\ Predicates.TxID.EarlierThan sourceTx targetTx := by
    have wf := reachable_well_formed linked.reachable
    obtain ⟨genuine, frozen⟩ := reachable_gossip_invariant linked.reachable
    obtain ⟨current, present, _, same⟩ := frozen envelope sent vote
    obtain ⟨i, witness, le, found, original, txid, originalPresent, ownGossip⟩ := own
    obtain ⟨final, finalMember, evolves⟩ := trace_node_final linked le found originalPresent
    have states : final = current :=
      congrArg Prod.snd (eq_of_key_eq wf.nodeKeysNodup finalMember present rfl)
    have ownCurrent : (envelope.source, txid) ∈ current.gossips := by
      simpa only [states] using evolves.gossips ownGossip
    have ownSnapshot : (envelope.source, txid) ∈ envelope.sourceState.gossips := same ▸ ownCurrent
    obtain ⟨selected, maximum, choice, greatest⟩ :=
      (reachable_quorum_invariant linked.reachable).sentVotesSelected envelope sent vote
    have selectedEq : selected = envelope.target :=
      Option.some.inj (choice.symm.trans (retry_vote_state (wf.sentValid envelope sent) vote).2)
    rw [selectedEq] at greatest
    have maximumCurrent : (envelope.target, maximum) ∈ current.gossips := by
      rw [same]
      exact Committed.maximumGossip_mem greatest
    have configValid := reachable_config_valid linked.reachable
    exact ⟨txid, maximum,
      Committed.recoveredTxID_of_mem configValid (genuine _ present ownCurrent),
      Committed.recoveredTxID_of_mem configValid (genuine _ present maximumCurrent),
      Committed.maximumGossip_upper_bound greatest ownSnapshot⟩
  rintro config trace state opener current ⟨inTrace, present, opened, own⟩
  obtain ⟨openIndex, found⟩ := CCF.Execution.Trace.mem_iff_exists_stateAt.mp inTrace
  obtain ⟨bound, boundIn, openLe, bounded⟩ :=
    Trace.exists_bound (P := fun voter i => exists witness, trace.stateAt i = some witness
        /\ exists nodeState txid,
            (voter, nodeState) ∈ witness.nodes /\ (voter, txid) ∈ nodeState.gossips)
      (Option.isSome_iff_exists.mpr ⟨_, found.symm⟩) current.votes fun voter voted => by
        obtain ⟨witness, member, rest⟩ := own voter voted
        obtain ⟨i, atI⟩ := CCF.Execution.Trace.mem_iff_exists_stateAt.mp member
        exact ⟨i, Option.isSome_iff_exists.mpr ⟨_, atI.symm⟩, witness, atI.symm, rest⟩
  have own : forall voter, voter ∈ current.votes -> OwnGossipBy trace bound voter :=
    fun voter voted => by
      obtain ⟨i, le, witness, atI, rest⟩ := bounded voter voted
      exact ⟨i, witness, le, atI, rest⟩
  obtain ⟨ghost, linked⟩ := History.history_correspondence trace boundIn
  have invariant := reachable_quorum_invariant linked.reachable
  have stateReachable := trace.reachable inTrace
  obtain ⟨atOpening, openingReachable, projected⟩ := Lifting.model_reachable_lifts stateReachable
  have openingPresent : (opener, current) ∈ atOpening.system.nodes := by
    simpa only [← projected, Lifting.erase] using present
  have nodup := (reachable_quorum_invariant openingReachable).votesNodup _ openingPresent
  have threshold := Observed.reachable_quorum_thresholds openingReachable _ openingPresent opened
  obtain ⟨final, finalMember, evolves⟩ :=
    trace_node_final linked openLe found.symm present
  have votesSent : forall voter, voter ∈ current.votes -> Predicates.SentVote ghost voter opener :=
    fun voter member => invariant.votesSent _ finalMember voter (evolves.votes member)
  have anyVote : exists voter, voter ∈ current.votes := by
    cases votes : current.votes with
    | nil => simp [votes, voteQuorum] at threshold
    | cons voter rest => exact ⟨voter, by simp⟩
  obtain ⟨voter, voted⟩ := anyVote
  obtain ⟨envelope, sent, source, target, vote⟩ := votesSent voter voted
  obtain ⟨_, targetTx, _, targetRecovered, _⟩ :=
    sent_vote_preserves_own linked sent vote (by simpa only [source] using own voter voted)
  rw [target] at targetRecovered
  refine ⟨targetTx, targetRecovered, ?_⟩
  apply Committed.up_to_date_with_quorum_of_voters nodup threshold
  intro voter voted
  obtain ⟨envelope, sent, source, target, vote⟩ := votesSent voter voted
  obtain ⟨sourceTx, candidateTx, sourceRecovered, candidateRecovered, earlier⟩ :=
    sent_vote_preserves_own linked sent vote (by simpa only [source] using own voter voted)
  rw [source] at sourceRecovered
  rw [target] at candidateRecovered
  have same := Option.some.inj (candidateRecovered.symm.trans targetRecovered)
  exact ⟨sourceTx, sourceRecovered, same ▸ earlier⟩

end DisasterRecovery.Proofs.Gossip

namespace DisasterRecovery.Proofs.Observed

open Execution.Local
open Execution.Global hiding Config
open Predicates

private lemma reachable_opening_has_vote {config : Model.Config} {state : State}
    (reachable : Reachable config state)
    (entry : Location × NodeState) (member : entry ∈ state.system.nodes)
    (opened : entry.2.openKind.isSome = true)
    : exists voter, voter ∈ entry.2.votes := by
  cases selected : entry.2.openKind with
  | none => simp [selected] at opened
  | some kind =>
      have threshold := reachable_opening_thresholds reachable entry member kind selected
      cases votes : entry.2.votes with
      | nil => cases kind <;> simp [votes, voteQuorum] at threshold
      | cons voter rest => exact ⟨voter, by simp⟩

end DisasterRecovery.Proofs.Observed

namespace DisasterRecovery.Proofs.Committed

open Execution
open Execution.Local hiding Config
open Execution.Global Predicates
open DisasterRecovery.Proofs.Invariants DisasterRecovery.Proofs.Quorum

private lemma up_to_date_with_quorum_of_all
    {config : Config} {candidate : TxID}
    (valid : config.Valid)
    (fresh : forall entry, entry ∈ config.recovered -> TxID.EarlierThan entry.2 candidate)
    : Properties.UpToDateWithQuorum config candidate := by
  apply up_to_date_with_quorum_of_voters valid.2.1
  · have nonempty : config.protocol.expectedLocations ≠ [] := by
      intro empty
      have configured := valid.1
      simp [Model.Local.Config.isValid, empty] at configured
    have positive := List.length_pos_iff.mpr nonempty
    unfold voteQuorum
    omega
  · intro voter member
    rw [← valid.2.2] at member
    obtain ⟨entry, present, key⟩ := List.mem_map.mp member
    subst voter
    exact ⟨entry.2, recoveredTxID_of_mem valid present, fresh entry present⟩

end DisasterRecovery.Proofs.Committed

namespace DisasterRecovery.Proofs.Gossip

open Execution
open Execution.Local hiding Config
open Execution.Global
open Invariants Quorum

lemma full_gossip_preserves_commit
    : forall (config : Model.Config) (trace : Properties.GlobalTrace config)
              (gossipedState openedState : Model.State),
      forall (opener : Model.Local.Location) (openerState : Model.Local.NodeState),
        (gossipedState ∈ trace
          /\ (forall node nodeState,
                node ∈ config.protocol.expectedLocations
                -> (node, nodeState) ∈ gossipedState.nodes
                -> forall gossip,
                    gossip ∈ nodeState.gossips <-> gossip ∈ config.recovered)
          /\ openedState ∈ trace
          /\ (opener, openerState) ∈ openedState.nodes
          /\ openerState.openKind.isSome = true)
        -> exists openerTxID,
            Model.recoveredTxID config opener = some openerTxID
            /\ Properties.UpToDateWithQuorum config openerTxID := by
  have sent_vote_full_gossip {config : Config} {trace : Properties.GlobalTrace config}
      {bound : Nat} {ghost : State}
      (linked : History.Correspondence config trace bound ghost) {i : Nat}
      {gossiped : Model.State} (le : i <= bound) (inTrace : trace.stateAt i = some gossiped)
      (full
        : forall node nodeState,
            node ∈ config.protocol.expectedLocations
            -> (node, nodeState) ∈ gossiped.nodes
            -> forall gossip, gossip ∈ nodeState.gossips <-> gossip ∈ config.recovered)
      {envelope : Envelope} (sent : envelope ∈ ghost.sent) (vote : envelope.payload = .vote)
      : forall gossip,
          gossip ∈ envelope.sourceState.gossips <-> gossip ∈ config.recovered := by
    have wf := reachable_well_formed linked.reachable
    obtain ⟨genuine, frozen⟩ := reachable_gossip_invariant linked.reachable
    obtain ⟨current, present, _, same⟩ := frozen envelope sent vote
    obtain ⟨atGossip, gossipReachable, projected⟩ :=
      Lifting.model_reachable_lifts (trace.reachable (CCF.Execution.Trace.stateAt_mem inTrace))
    have configured := wf.sentSourceConfigured envelope sent
    have sourceKey : envelope.source ∈ atGossip.system.nodes.map Prod.fst := by
      exact (reachable_well_formed gossipReachable).nodeKeys _ configured
    obtain ⟨entry, entryMember, key⟩ := List.mem_map.mp sourceKey
    have originalPresent : (envelope.source, entry.2) ∈ gossiped.nodes := by
      simpa only [← projected, Lifting.erase, ← key] using entryMember
    obtain ⟨final, finalMember, evolves⟩ :=
      trace_node_final linked le inTrace originalPresent
    have states : final = current :=
      congrArg Prod.snd (eq_of_key_eq wf.nodeKeysNodup finalMember present rfl)
    intro gossip
    constructor
    · intro member
      exact genuine _ present (same.symm ▸ member)
    · intro member
      have original := (full envelope.source entry.2 configured originalPresent gossip).mpr member
      have finalGossip := evolves.gossips original
      simpa only [states, same] using finalGossip
  rintro config trace gossiped opened opener current
    ⟨gossipedMember, full, openedMember, present, opening⟩
  obtain ⟨gossipIndex, gossipFound⟩ := CCF.Execution.Trace.mem_iff_exists_stateAt.mp gossipedMember
  obtain ⟨openIndex, openFound⟩ := CCF.Execution.Trace.mem_iff_exists_stateAt.mp openedMember
  obtain ⟨ghost, linked⟩ := History.history_correspondence trace
    (Trace.max_isSome (Option.isSome_iff_exists.mpr ⟨_, gossipFound.symm⟩)
      (Option.isSome_iff_exists.mpr ⟨_, openFound.symm⟩))
  obtain ⟨atOpening, openingReachable, projected⟩ :=
    Lifting.model_reachable_lifts (trace.reachable openedMember)
  have openingPresent : (opener, current) ∈ atOpening.system.nodes := by
    simpa only [← projected, Lifting.erase] using present
  obtain ⟨voter, voted⟩ :=
    Observed.reachable_opening_has_vote openingReachable _ openingPresent opening
  obtain ⟨final, finalMember, evolves⟩ :=
    trace_node_final linked (Nat.le_max_right _ _) openFound.symm present
  have invariant := reachable_quorum_invariant linked.reachable
  obtain ⟨envelope, sent, _, target, vote⟩ :=
    invariant.votesSent _ finalMember voter (evolves.votes voted)
  have complete :=
    sent_vote_full_gossip linked (Nat.le_max_left _ _) gossipFound.symm full sent vote
  obtain ⟨selected, txid, choice, maximum⟩ := invariant.sentVotesSelected envelope sent vote
  have wf := reachable_well_formed linked.reachable
  have selectedEq : selected = envelope.target :=
    Option.some.inj (choice.symm.trans (retry_vote_state (wf.sentValid envelope sent) vote).2)
  rw [selectedEq, target] at maximum
  have configValid := reachable_config_valid linked.reachable
  refine ⟨txid, Committed.recoveredTxID_of_mem configValid
    ((complete _).mp (Committed.maximumGossip_mem maximum)), ?_⟩
  apply Committed.up_to_date_with_quorum_of_all configValid
  intro entry member
  exact Committed.maximumGossip_upper_bound maximum ((complete entry).mpr member)

end DisasterRecovery.Proofs.Gossip

namespace DisasterRecovery.Proofs.Observed

open Execution.Local
open Execution.Global hiding Config
open Predicates

private lemma notification_opening_state {config : Model.Config}
    {trace : Properties.GlobalTrace config} {index : Nat} {node : Location}
    {kind : OpenKind}
    (notification
      : Properties.Trace.NotificationAt config trace index node (.opening kind))
    : exists after current,
        trace.stateAt (index + 1) = some after
        /\ (node, current) ∈ after.nodes
        /\ current.openKind = some kind := by
  obtain ⟨before, after, action, nodeBefore, nodeAfter, outputs,
    _, atAfter, _, _, _, foundAfter, enabled, notified⟩ := notification
  obtain ⟨recovered, _, enabled⟩ :=
    DisasterRecovery.Proofs.Local.validStep_run
      (s := ⟨node, nodeBefore, Properties.Trace.event action, nodeAfter, outputs⟩) enabled
  have erased := Lifting.step_erases config.protocol recovered nodeBefore (source := node)
    (Properties.Trace.event action) { state := nodeAfter, effects := outputs.notifications }
    (by simp [enabled, Lifting.capture])
  have stateEq := congrArg Lifting.Result.state erased
  have notifications := congrArg Lifting.Result.effects erased
  change (step config.protocol nodeBefore (Properties.Trace.event action)).state = nodeAfter at stateEq
  change
    (step config.protocol nodeBefore (Properties.Trace.event action)).effects.filterMap
      Effect.diagnostic = outputs.notifications at notifications
  have recorded : .opening kind ∈
      (step config.protocol nodeBefore (Properties.Trace.event action)).effects := by
    rw [← notifications] at notified
    obtain ⟨effect, member, diagnostic⟩ := List.mem_filterMap.mp notified
    cases effect <;> cases diagnostic
    exact member
  have opened := (Quorum.opening_effect_state config.protocol nodeBefore
    (Properties.Trace.event action) kind recorded).2
  rw [stateEq] at opened
  refine ⟨after, nodeAfter, atAfter, ?_, opened⟩
  obtain ⟨entry, found, value⟩ := Option.map_eq_some_iff.mp foundAfter
  have key := beq_iff_eq.mp
    (List.find?_some found :)
  have same : entry = (node, nodeAfter) := Prod.ext key value
  rw [← same]
  exact List.mem_of_find?_eq_some found

private lemma current_quorum_unique_of_thresholds {config : Model.Config} {state : State}
    (reachable : Reachable config state)
    (first second : Location × NodeState)
    (firstMember : first ∈ state.system.nodes)
    (secondMember : second ∈ state.system.nodes)
    (firstQuorum : voteQuorum config.protocol <= first.2.votes.length)
    (secondQuorum : voteQuorum config.protocol <= second.2.votes.length)
    : first.1 = second.1 := by
  have wf := Invariants.reachable_well_formed reachable
  have invariant := Quorum.reachable_quorum_invariant reachable
  have configured (entry : Location × NodeState) (member : entry ∈ state.system.nodes)
      (voter : Location) (vote : voter ∈ entry.2.votes) :
      voter ∈ config.protocol.expectedLocations := by
    obtain ⟨sent, sentMember, source, _, _⟩ := invariant.votesSent entry member voter vote
    simpa [source] using wf.sentSourceConfigured sent sentMember
  obtain ⟨voter, firstVote, secondVote⟩ :=
    Quorum.quorum_lists_intersect config.protocol.expectedLocations
      first.2.votes second.2.votes
      (invariant.votesNodup first firstMember)
      (invariant.votesNodup second secondMember)
      (configured first firstMember)
      (configured second secondMember)
      firstQuorum secondQuorum
  exact invariant.sentVotesFunctional voter first.1 second.1
    (invariant.votesSent first firstMember voter firstVote)
    (invariant.votesSent second secondMember voter secondVote)

end DisasterRecovery.Proofs.Observed

namespace DisasterRecovery.Proofs.Gossip

open Execution
open Execution.Local hiding Config
open Execution.Global
open Invariants Quorum

private lemma quorum_notification_final_votes {config : Model.Config}
    {trace : Properties.GlobalTrace config} {bound : Nat} {ghost : State}
    (linked : History.Correspondence config trace bound ghost) {index : Nat}
    (le : index + 1 <= bound) {node : Location}
    (notification
      : Properties.Trace.NotificationAt config trace index node (.opening .quorum))
    : exists final,
        (node, final) ∈ ghost.system.nodes
        /\ voteQuorum config.protocol <= final.votes.length := by
  obtain ⟨after, current, inTrace, present, opened⟩ :=
    Observed.notification_opening_state notification
  obtain ⟨atOpening, openingReachable, projected⟩ :=
    Lifting.model_reachable_lifts (trace.reachable (CCF.Execution.Trace.stateAt_mem inTrace))
  have openingPresent : (node, current) ∈ atOpening.system.nodes := by
    simpa only [← projected, Lifting.erase] using present
  have nodup := (reachable_quorum_invariant openingReachable).votesNodup _ openingPresent
  have threshold := Observed.reachable_quorum_thresholds openingReachable _ openingPresent opened
  obtain ⟨final, finalMember, evolves⟩ := trace_node_final linked le inTrace present
  have count := nodup.length_le_of_subset fun _ member => evolves.votes member
  exact ⟨final, finalMember, Nat.le_trans threshold count⟩

end DisasterRecovery.Proofs.Gossip

namespace DisasterRecovery.Proofs.Model

lemma quorum_opener_unique
    : forall (config : Model.Config) (trace : Properties.GlobalTrace config),
      forall (firstStep secondStep : Nat)
              (firstOpener secondOpener : Model.Local.Location),
        (Properties.Trace.NotificationAt config trace firstStep firstOpener
            (.opening .quorum)
          /\ Properties.Trace.NotificationAt config trace secondStep secondOpener
              (.opening .quorum))
        -> firstOpener = secondOpener := by
  rintro config trace firstStep secondStep firstOpener secondOpener ⟨first, second⟩
  obtain ⟨_, _, firstFound, _⟩ := Observed.notification_opening_state first
  obtain ⟨_, _, secondFound, _⟩ := Observed.notification_opening_state second
  obtain ⟨ghost, linked⟩ := History.history_correspondence trace
    (Trace.max_isSome (Option.isSome_iff_exists.mpr ⟨_, firstFound⟩)
      (Option.isSome_iff_exists.mpr ⟨_, secondFound⟩))
  obtain ⟨firstState, firstMember, firstThreshold⟩ :=
    Gossip.quorum_notification_final_votes linked (Nat.le_max_left _ _) first
  obtain ⟨secondState, secondMember, secondThreshold⟩ :=
    Gossip.quorum_notification_final_votes linked (Nat.le_max_right _ _) second
  exact Observed.current_quorum_unique_of_thresholds linked.reachable
    (firstOpener, firstState) (secondOpener, secondState)
    firstMember secondMember firstThreshold secondThreshold

end DisasterRecovery.Proofs.Model
