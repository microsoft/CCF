import DisasterRecovery.Protocol.Committed
import DisasterRecovery.Protocol.Temporal

/-! Human-reviewed global execution, termination and fairness assumptions. -/

namespace DisasterRecovery.Protocol.GlobalTemporal

open Model hiding Config
open Global Quorum
open Temporal (EventuallyFrom)

structure Execution (config : Config) where
  states : Nat -> State
  actions : Nat -> Action
  step_succ : forall n,
    next config (states n) (actions n) = some (states (n + 1))

def HasPhase (state : State) (node : Location) (phase : Phase) : Prop :=
  exists nodeState,
    Global.nodeState state node = some nodeState /\
      nodeState.phase = phase

def HasGossip (state : State) (node : Location) : Prop :=
  exists nodeState,
    Global.nodeState state node = some nodeState /\
      nodeState.gossips ≠ []

def HasVote (state : State) (node : Location) : Prop :=
  exists nodeState,
    Global.nodeState state node = some nodeState /\
      nodeState.votes ≠ []

def LaneAdvanced (state : State) (node : Location) : Prop :=
  exists nodeState,
    Global.nodeState state node = some nodeState /\
      nodeState.timeoutState ≠ .gossiping

def Terminal (state : State) (node : Location) : Prop :=
  node ∈ state.restarts \/ node ∈ state.completed

def CompletedOpen (state : State) (node : Location) : Prop :=
  node ∈ state.completed

def AnnouncementsLive (state : State) : Prop :=
  forall envelope, envelope ∈ state.sent ->
    envelope.payload = .iAmOpen ->
      HasPhase state envelope.source .opening \/
        CompletedOpen state envelope.source

def SentAnnouncementTo (state : State) (target : Location) : Prop :=
  exists envelope,
    envelope ∈ state.sent /\
      envelope.target = target /\
      envelope.payload = .iAmOpen

def JoiningAnnouncements (state : State) : Prop :=
  forall entry, entry ∈ state.system.nodes ->
    entry.2.phase = .joining ->
      SentAnnouncementTo state entry.1

def OpenCompleted (state : State) : Prop :=
  forall entry, entry ∈ state.system.nodes ->
    entry.2.phase = .open ->
      CompletedOpen state entry.1

def AdvancedNodesActive (state : State) : Prop :=
  forall entry, entry ∈ state.system.nodes ->
    entry.2.phase ≠ .gossiping ->
      entry.1 ∈ state.active

def OpenerWitness (state : State) : Prop :=
  exists node,
    HasPhase state node .opening \/
      CompletedOpen state node

def OnlyOpenerCompletesFrom
    {config : Config}
    (execution : Execution config)
    (start : Nat)
    (opener : Location) : Prop :=
  forall n node,
    start <= n ->
    CompletedOpen (execution.states n) node ->
      node = opener

def QuorumOnlyCompletions
    {config : Config}
    (execution : Execution config) : Prop :=
  forall n node,
    CompletedOpen (execution.states n) node ->
      QuorumOpened (execution.states n) node

def SentAnnouncement
    (state : State)
    (source target : Location) : Prop :=
  exists envelope,
    envelope ∈ state.sent /\
      envelope.source = source /\
      envelope.target = target /\
      envelope.payload = .iAmOpen

def BroadcastBeforeCompletion
    {config : Config}
    (execution : Execution config) : Prop :=
  forall n opener,
    CompletedOpen (execution.states n) opener ->
    forall target, target ∈ (execution.states n).active ->
      target ≠ opener ->
      SentAnnouncement (execution.states n) opener target

def AnnouncementsResolved (state : State) : Prop :=
  forall envelope, envelope ∈ state.sent ->
    envelope.payload = .iAmOpen ->
      envelope ∈ state.network \/
        Terminal state envelope.target \/
        HasPhase state envelope.target .opening

def Enabled (config : Config) (state : State) (action : Action) : Prop :=
  exists nextState, next config state action = some nextState

def LaneValid (state : NodeState) : Prop :=
  (state.phase = .gossiping ->
    state.timeoutState = .gossiping) /\
  (state.phase = .voting ->
    state.timeoutState = .gossiping \/
      state.timeoutState = .voting) /\
  (state.phase = .opening ->
    state.timeoutState = .gossiping \/
      state.timeoutState = .voting \/
      state.timeoutState = .opening) /\
  (state.phase = .gossiping ->
    state.chosen = none)

def NodeLanesValid (state : State) : Prop :=
  forall entry, entry ∈ state.system.nodes ->
    LaneValid entry.2

structure Fair
    {config : Config}
    (execution : Execution config) : Prop where
  retry :
    forall start node phase,
      node ∈ (execution.states start).active ->
      HasPhase (execution.states start) node phase ->
      (phase = .gossiping \/ phase = .voting \/ phase = .opening) ->
      Enabled config (execution.states start) (.retry node) ->
      EventuallyFrom start (fun n =>
        Not (HasPhase (execution.states n) node phase) \/
          execution.actions n = .retry node)
  delivery :
    forall start envelope,
      envelope ∈ (execution.states start).network ->
      EventuallyFrom start (fun n =>
        execution.actions n = .deliver envelope)
  timeout :
    forall start node phase,
      node ∈ (execution.states start).active ->
      HasPhase (execution.states start) node phase ->
      (phase = .gossiping \/ phase = .voting \/ phase = .opening) ->
      Enabled config (execution.states start) (.timeout node) ->
      EventuallyFrom start (fun n =>
        Not (HasPhase (execution.states n) node phase) \/
          execution.actions n = .timeout node)
  openingTimeout :
    forall start node,
      node ∈ (execution.states start).active ->
      HasPhase (execution.states start) node .opening ->
      Enabled config (execution.states start) (.timeout node) ->
      EventuallyFrom start (fun n =>
        CompletedOpen (execution.states n) node \/
          (HasPhase (execution.states n) node .opening /\
            execution.actions n = .timeout node))

def acceptedIAmOpenSource : Event -> Option Location
  | .receiveIAmOpen source .accepted => some source
  | _ => none

def openingDistance : Phase -> Nat
  | .gossiping => 3
  | .voting => 2
  | .opening => 1
  | .joining | .open => 0

end DisasterRecovery.Protocol.GlobalTemporal
