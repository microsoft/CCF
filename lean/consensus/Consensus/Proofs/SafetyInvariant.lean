module

public import Consensus.Model

import all Init.Control.State

public import Consensus.Model.Node
public import CCF.Proofs.Execution
public import CCF.Proofs.Finset

namespace Consensus.Proofs.Config

open CCF (Finset)
open Model.Node

/-- The initial membership passed to the model, possibly empty. -/
private class InitialConfiguration where
  configuration : Finset NodeID

end Consensus.Proofs.Config

namespace Consensus.Proofs.Config

open CCF (Finset)
open Model.Node
section Initial
variable [config : InitialConfiguration]

private abbrev INITIAL_CONFIGURATION : Finset NodeID := config.configuration

/-- The smallest initial member, which the model makes the bootstrap primary.
Meaningful only for a nonempty initial membership. -/
private abbrev INITIAL_PRIMARY : NodeID := INITIAL_CONFIGURATION.min?.getD 0

/-- The unsigned bootstrap configuration transaction of the initial primary. -/
private abbrev GENESIS : Entry :=
  {
    term := Model.BOOTSTRAP_TERM
    content := .transaction 0 { configuration := some INITIAL_CONFIGURATION }
  }

end Initial
end Consensus.Proofs.Config

namespace Consensus.Proofs.Config

open CCF (Finset)
open Model.Node

/-- Collect the reconfiguration entries of a log with their one-based indices. -/
private def configurationsInLogFrom : Nat -> List Entry -> List Configuration
  | _, [] => []
  | index, entry :: entries =>
      let remaining := configurationsInLogFrom (index + 1) entries
      (entry.content.metadata.configuration.map fun nodes => { index, nodes }).toList
      ++ remaining

/-- The current configuration and every later configuration in the node's log. -/
private def activeConfigurationsOf (state : NodeState) : List Configuration :=
  Model.Node.activeConfigurations state.log state.commitIndex

/-- Union of the nodes in a node's active configurations. -/
private def activeNodeUnion (state : NodeState) : Finset NodeID :=
  (activeConfigurationsOf state).foldl
    (fun nodes configuration => nodes ∪ configuration.nodes) ∅

end Consensus.Proofs.Config

namespace Consensus.Proofs.Concrete

set_option linter.unusedSectionVars false
open Consensus.Proofs.Config
open CCF CCF.MultiNodeTransitionSystem
open Model.Node

/-- Replace the state of `node` in a node table. -/
private def replaceNode (nodes : List (NodeID × NodeState)) (node : NodeID)
    (value : NodeState)
    : List (NodeID × NodeState) :=
  nodes.map fun entry => if entry.1 == node then (node, value) else entry

end Consensus.Proofs.Concrete

namespace Consensus.Proofs.Direct

set_option linter.unusedSectionVars false
open Consensus.Proofs.Config
open CCF CCF.MultiNodeTransitionSystem Concrete
open Model.Node
open Model (initialNodeState)
variable [Config.InitialConfiguration]

/-- A node-local predicate that holds initially and survives every local step. -/
private structure NodeInvariant (P : NodeID -> NodeState -> Prop) : Prop where
  initial : forall node, P node (initialNodeState Config.INITIAL_CONFIGURATION node)
  step
    : forall node state event after outputs,
        P node state
        -> (Model.Node.step (Capabilities.record node) node state event).run {}
            = some (after, outputs)
        -> P node after

end Consensus.Proofs.Direct

namespace Consensus.Proofs.Direct

set_option linter.unusedSectionVars false
open CCF
variable {Node Message Notification : Type}

/-- Every successful run of `m` returns a value satisfying `P`. -/
private def Keeps {α : Type} (P : α -> Prop) (m : Effect Node Message Notification α)
    : Prop :=
  forall outputs result after, m.run outputs = some (result, after) -> P result

end Consensus.Proofs.Direct

namespace Consensus.Proofs.Safety

set_option linter.unusedSectionVars false
open CCF
variable {Node Message Notification : Type}

/-- Every successful run of `m` appends `new` to the outgoing envelopes and
returns `result` with `P result new`. -/
private def Sends {α : Type} (P : α -> List (Envelope Node Message) -> Prop)
    (m : Effect Node Message Notification α)
    : Prop :=
  forall outputs result after,
    m.run outputs = some (result, after)
    -> exists new, after.outgoing = outputs.outgoing ++ new /\ P result new

end Consensus.Proofs.Safety

namespace Consensus.Proofs.Safety

set_option linter.unusedSectionVars false
open Consensus.Proofs.Config
open CCF CCF.MultiNodeTransitionSystem Concrete Direct
open Model.Node
variable [Config.InitialConfiguration]

/-- An execution of the network of `nodes`, newest state first. -/
private inductive Exec (nodes : List NodeID) : List Model.State -> Prop where
  | initial {state : Model.State}
    (initialized : (Model.transitionSystem Config.INITIAL_CONFIGURATION nodes).init state)
    : Exec nodes [state]
  | step {before after : Model.State} {history : List Model.State}
    {action : Model.Action}
    (prior : Exec nodes (before :: history))
    (stepped
      : (Model.transitionSystem Config.INITIAL_CONFIGURATION nodes).step before action
        = some after)
    : Exec nodes (after :: before :: history)

/-- One node step: the actor's local step, other nodes unchanged, the network
losing at most the delivered envelope and gaining the actor's sends. -/
private structure LocalTransition (before after : Model.State) where
  actor : NodeID
  pre : NodeState
  post : NodeState
  event : Event
  outputs : Outputs NodeID (Message) Notification
  pending : List Model.Envelope
  found : nodeState before actor = some pre
  ran
    : (Model.Node.step (Capabilities.record actor) actor pre event).run {}
      = some (post, outputs)
  nodesEq : after.nodes = replaceNode before.nodes actor post
  networkEq : after.network = pending ++ outputs.outgoing
  pendingSub : forall envelope, envelope ∈ pending -> envelope ∈ before.network
  source
    : (exists input, event = .internal input /\ pending = before.network)
      \/ (exists envelope,
            envelope ∈ before.network
            /\ envelope.target = actor
            /\ event = .receive envelope.source envelope.payload
            /\ pending = removeOne envelope before.network)
  available
    : forall entries,
        event = .internal (.initAsBackup entries)
        -> Model.committedPrefixOf before entries = true

end Consensus.Proofs.Safety

namespace Consensus.Proofs.Safety

set_option linter.unusedSectionVars false
open Model.Node

/-- The one-based index of the first overlapping entry whose term conflicts. -/
private def conflictIndex (log : List Entry) (request : AppendEntriesRequest)
    : Option Nat :=
  ((((log.drop request.prevLogIndex).zip request.entries).zipIdx
      (request.prevLogIndex + 1)).find?
    fun ((existing, incoming), _) => existing.term != incoming.term).map
    Prod.snd

/-- The follower log after accepting `request` on `log`. -/
private def acceptLog (log : List Entry) (request : AppendEntriesRequest) : List Entry :=
  let kept :=
    match conflictIndex log request with
    | some index => log.take (index - 1)
    | none => log
  kept ++ request.entries.drop (kept.length - request.prevLogIndex)

/-- A log is empty or starts with `root`. -/
private def Rooted (root : Entry) (log : List Entry) : Prop :=
  log = [] \/ log.take 1 = [root]

end Consensus.Proofs.Safety

namespace Consensus.Proofs.Ledger
end Consensus.Proofs.Ledger

namespace Consensus.Proofs.Direct.Keeps
end Consensus.Proofs.Direct.Keeps

namespace Consensus.Proofs.Direct

set_option linter.unusedSectionVars false
open Consensus.Proofs.Config
open CCF
open Model.Node

/-- The commit index lies within the log and, when positive, is a signature. -/
private def CommitFrontier (state : NodeState) : Prop :=
  state.commitIndex <= state.log.length
  /\ (0 < state.commitIndex -> isSignatureAt state.log state.commitIndex = true)

end Consensus.Proofs.Direct

namespace Consensus.Proofs.Direct

set_option linter.unusedSectionVars false
open Consensus.Proofs.Config
open CCF CCF.MultiNodeTransitionSystem Concrete
open Model.Node

/-- `after` commits no less than `before` and its log extends the committed log
of `before`. No relation between `before`'s commit index and log is assumed. -/
private def Extends (before after : NodeState) : Prop :=
  before.commitIndex <= after.commitIndex /\ before.committedLog <+: after.log

end Consensus.Proofs.Direct

namespace Consensus.Proofs.Safety.Sends
end Consensus.Proofs.Safety.Sends

namespace Consensus.Proofs.Safety

set_option linter.unusedSectionVars false
open Consensus.Proofs.Config Consensus.Proofs.Ledger
open CCF
open Model.Node

/-- An AppendEntries request consistent with its sender's resulting state. -/
private def AEOk (self target : NodeID) (state : NodeState)
    (request : AppendEntriesRequest)
    : Prop :=
  Not (target = self)
  /\ request.term = state.currentTerm
  /\ request.prevLogIndex <= state.log.length
  /\ request.prevLogTerm = termAt state.log request.prevLogIndex
  /\ request.entries <+: state.log.drop request.prevLogIndex
  /\ request.primaryCommit <= state.commitIndex

/-- The state change of `advanceCommit`. -/
private def Advance (self : NodeID) (middle state : NodeState) : Prop :=
  state = middle
  \/ (state.log = middle.log
      /\ state.currentTerm = middle.currentTerm
      /\ state.votedFor = middle.votedFor
      /\ state.matchIndex = middle.matchIndex
      /\ state.sentIndex = middle.sentIndex
      /\ state.votesGranted = middle.votesGranted
      /\ middle.commitIndex < state.commitIndex
      /\ state.commitIndex = highestCommittableIndex middle self
      /\ (state.role = middle.role \/ state.role = .none))

/-- Messages whose receipt may raise the receiver's term. -/
private def Bumping : Message -> Prop
  | .appendEntriesResponse _ => False
  | .proposeRequestVoteRequest _ => False
  | _ => True

/-- A node taking part in elections: it has a role and is not a joined node
still waiting, in term zero with an empty log, for its first consensus message. -/
private def Engaged (state : NodeState) : Prop :=
  Not (state.role = .none)
  /\ Not (state.role = .follower /\ state.currentTerm = 0 /\ state.log = [])

/-- The candidate state a step campaigns with: a fresh election or the
existing candidacy with possibly more votes. -/
private def Campaign (self : NodeID) (before : NodeState) (event : Event)
    (candidate : NodeState)
    : Prop :=
  candidate.role = .candidate
  /\ candidate.log = before.log
  /\ candidate.commitIndex = before.commitIndex
  /\ ((Engaged before
        /\ candidate.currentTerm = before.currentTerm + 1
        /\ candidate.votedFor = some self
        /\ candidate.votesGranted = {self})
      \/ (before.role = .candidate
          /\ candidate.currentTerm = before.currentTerm
          /\ (candidate.votedFor = before.votedFor \/ before.votedFor = none)
          /\ forall voter,
              voter ∈ candidate.votesGranted
              -> voter ∈ before.votesGranted
                  \/ exists response,
                      event = .receive voter (.requestVoteResponse response)
                      /\ response.term = before.currentTerm
                      /\ response.voteGranted = true))

/-- The step wins an election with `candidate`. -/
private def Wins (self : NodeID) (before : NodeState) (event : Event) (after : NodeState)
    : Prop :=
  exists candidate,
    Campaign self before event candidate
    /\ hasQuorum (candidate.activeConfigurations) candidate.votesGranted
    /\ Advance self (primaryState candidate) after

/-- The follower accepted AppendEntries `request`. -/
private def Accepted (before : NodeState) (request : AppendEntriesRequest)
    (after : NodeState)
    : Prop :=
  request.term = after.currentTerm
  /\ before.currentTerm <= request.term
  /\ before.commitIndex <= request.prevLogIndex
  /\ request.prevLogIndex <= before.log.length
  /\ termAt before.log request.prevLogIndex = request.prevLogTerm
  /\ after.log = acceptLog before.log request
  /\ after.commitIndex
      = max before.commitIndex
          (maxCommittableIndexUpTo after.log
            (min request.primaryCommit (request.prevLogIndex + request.entries.length)))

/-- How a step changes the log and commit index. -/
private inductive Kind (self : NodeID) (before : NodeState) (event : Event)
    (after : NodeState)
    : Prop where
  | same (log : after.log = before.log) (commit : after.commitIndex = before.commitIndex)
  | append (entries : List Entry) (sent : NodeID -> Nat)
    (leader : before.role = .primary)
    (terms : forall entry, entry ∈ entries -> entry.term = before.currentTerm)
    (advance
      : Advance self { before with log := before.log ++ entries, sentIndex := sent }
          after)
  | ack (source : NodeID) (response : AppendEntriesResponse)
    (received : event = .receive source (.appendEntriesResponse response))
    (leader : before.role = .primary) (success : response.success = true)
    (term : response.term = before.currentTerm)
    (advance
      : Advance self
          {
            before with
              matchIndex :=
                Function.update before.matchIndex source
                  (max (before.matchIndex source) response.lastLogIndex)
          }
          after)
  | accept (source : NodeID) (request : AppendEntriesRequest)
    (received : event = .receive source (.appendEntriesRequest request))
    (accepted : Accepted before request after)
  | elect (elected : Wins self before event after)
  | install (entries : List Entry)
    (initialized : event = .internal (.initAsBackup entries))
    (positive : 0 < entries.length)
    (signature : isSignatureAt entries entries.length = true)
    (fresh : before.isFresh) (log : after.log = entries)
    (commit : after.commitIndex = entries.length)
    (term : after.currentTerm = termAt entries entries.length)
    (role : after.role = .follower)

/-- What a step may send, relative to its sender's states. -/
private def SendOK (self : NodeID) (before : NodeState) (event : Event)
    (after : NodeState) (envelope : Model.Envelope)
    : Prop :=
  envelope.source = self
  /\ match envelope.payload with
      | .appendEntriesRequest request =>
          AEOk self envelope.target after request
          /\ Not (after.role = .candidate)
          /\ ((before.role = .primary /\ after.currentTerm = before.currentTerm)
              \/ Wins self before event after)
      | .appendEntriesResponse response =>
          response.success = true
          -> exists source request,
              event = .receive source (.appendEntriesRequest request)
              /\ Accepted before request after
              /\ response.term = after.currentTerm
              /\ response.lastLogIndex = request.prevLogIndex + request.entries.length
      | .requestVoteRequest request =>
          request.term = after.currentTerm
          /\ before.currentTerm < after.currentTerm
          /\ (after.role = .candidate -> makeRequestVoteRequest after = request)
      | .requestVoteResponse response =>
          response.term = after.currentTerm
          /\ (response.voteGranted = true
              -> exists request,
                  event = .receive envelope.target (.requestVoteRequest request)
                  /\ request.term = after.currentTerm
                  /\ voteLogUpToDate before request
                  /\ after.votedFor = some envelope.target)
      | message => message.term = after.currentTerm

/-- Everything the safety proof needs to know about one local step. -/
private structure Summary (self : NodeID) (before : NodeState) (event : Event)
    (after : NodeState) (sent : List Model.Envelope)
    : Prop where
  term_le : before.currentTerm <= after.currentTerm
  vote_keep
    : after.currentTerm = before.currentTerm
      -> forall voted, before.votedFor = some voted -> after.votedFor = some voted
  active
    : (Engaged after \/ exists envelope, envelope ∈ sent /\ Bumping envelope.payload)
      -> Engaged before
          \/ 2 <= before.currentTerm
          \/ (exists source message,
                event = .receive source message
                /\ Bumping message
                /\ message.term <= after.currentTerm)
          \/ exists entries,
              event = .internal (.initAsBackup entries)
              /\ 0 < entries.length
              /\ isSignatureAt entries entries.length = true
              /\ after.currentTerm = termAt entries entries.length
  candidate : after.role = .candidate -> Campaign self before event after
  leader
    : after.role = .primary
      -> (before.role = .primary /\ after.currentTerm = before.currentTerm)
          \/ Wins self before event after
  matchIndex
    : after.role = .primary -> before.role = .primary
      -> after.currentTerm = before.currentTerm
      -> forall peer,
          after.matchIndex peer = before.matchIndex peer
          \/ exists response,
              event = .receive peer (.appendEntriesResponse response)
              /\ response.success = true
              /\ response.term = before.currentTerm
              /\ after.matchIndex peer = response.lastLogIndex
  kind : Kind self before event after
  sends : forall envelope, envelope ∈ sent -> SendOK self before event after envelope

/-- An AppendEntries request from `self` consistent with `log` and `commit`. -/
private def AEFrom (self : NodeID) (term commit : Nat) (log : List Entry)
    (envelope : Model.Envelope)
    : Prop :=
  envelope.source = self
  /\ Not (envelope.target = self)
  /\ exists request,
      envelope.payload = .appendEntriesRequest request
      /\ request.term = term
      /\ request.prevLogIndex <= log.length
      /\ request.prevLogTerm = termAt log request.prevLogIndex
      /\ request.entries <+: log.drop request.prevLogIndex
      /\ request.primaryCommit <= commit

end Consensus.Proofs.Safety

namespace Consensus.Proofs.Safety

set_option linter.unusedSectionVars false
open Consensus.Proofs.Config Consensus.Proofs.Ledger
open CCF
open Model.Node
section Effects
variable (self : NodeID)

/-- The sends of a new leader: a nomination or a heartbeat. -/
private def LeaderStart (self : NodeID) (term : Nat) (state : NodeState)
    (envelope : Model.Envelope)
    : Prop :=
  (envelope.source = self /\ envelope.payload = .proposeRequestVoteRequest term)
  \/ AEFrom self state.currentTerm state.commitIndex state.log envelope

/-- The candidate state `becomeCandidate` builds from `state`. -/
private def freshCandidate (self : NodeID) (state : NodeState) : NodeState :=
  {
    state with
      role := .candidate
      currentTerm := state.currentTerm + 1
      votedFor := some self
      primaryKnown := false
      votesGranted := {self}
      preVotesGranted := ∅
  }

end Effects
end Consensus.Proofs.Safety

namespace Consensus.Proofs.Safety

set_option linter.unusedSectionVars false
open Consensus.Proofs.Config Consensus.Proofs.Ledger
open CCF
open Model.Node

/-- What a campaigning step sends or becomes. -/
private def CampaignResult (self : NodeID) (before candidate after : NodeState)
    (sent : List Model.Envelope)
    : Prop :=
  let request (e : Model.Envelope) :=
    e.source = self
    /\ e.payload = .requestVoteRequest (makeRequestVoteRequest candidate)
    /\ before.currentTerm < candidate.currentTerm
  (after = candidate /\ forall e, e ∈ sent -> request e)
  \/ (hasQuorum (candidate.activeConfigurations) candidate.votesGranted
      /\ Advance self (primaryState candidate) after
      /\ forall e,
          e ∈ sent -> LeaderStart self candidate.currentTerm after e \/ request e)

/-- The state after adopting a newer term. -/
private def bumpedState (state : NodeState) (term : Nat) : NodeState :=
  {
    state with
      role := .follower,
      currentTerm := term,
      votedFor := none,
      primaryKnown := false,
      isNewFollower := true,
      votesGranted := ∅,
      preVotesGranted := ∅
  }

/-- What the AppendEntries request handler does, relative to the observed state. -/
private def AEReply (self source : NodeID) (state : NodeState)
    (request : AppendEntriesRequest) (after : NodeState)
    (sent : List Model.Envelope)
    : Prop :=
  after.currentTerm = state.currentTerm
  /\ after.votedFor = state.votedFor
  /\ after.matchIndex = state.matchIndex
  /\ (after.role = state.role \/ after.role = .follower \/ after.role = .none)
  /\ (after.role = .candidate -> after = state)
  /\ ((after.log = state.log
        /\ after.commitIndex = state.commitIndex
        /\ forall e,
            e ∈ sent
            -> e.source = self
                /\ exists response,
                    e.payload = .appendEntriesResponse response
                    /\ response.success = false)
      \/ (request.term = state.currentTerm
          /\ state.commitIndex <= request.prevLogIndex
          /\ appendEntryMatchesLog state request
          /\ after.log = acceptLog state.log request
          /\ after.commitIndex
              = max state.commitIndex
                  (maxCommittableIndexUpTo after.log
                    (min request.primaryCommit
                      (request.prevLogIndex + request.entries.length)))
          /\ exists e,
              sent = [e]
              /\ e.source = self
              /\ e.target = source
              /\ e.payload
                  = .appendEntriesResponse
                      {
                        term := state.currentTerm,
                        success := true,
                        lastLogIndex := request.prevLogIndex + request.entries.length
                      }))

/-- A partially appended batch: new entries at the leader's term, and
packets consistent with the current log. -/
private def BatchState (self : NodeID) (before state : NodeState)
    (sent : List Model.Envelope)
    : Prop :=
  (exists entries sentIndex,
    state = { before with log := before.log ++ entries, sentIndex := sentIndex }
    /\ forall entry, entry ∈ entries -> entry.term = before.currentTerm)
  /\ forall e, e ∈ sent -> AEFrom self before.currentTerm before.commitIndex state.log e

end Consensus.Proofs.Safety

namespace Consensus.Proofs.Safety

set_option linter.unusedSectionVars false
open CCF
open Model.Node
open Consensus.Proofs.Config
open Model (BOOTSTRAP_TERM)
variable [Config.InitialConfiguration]

private abbrev History := List Model.State

/-- `node` has `state` in the newest state of `history`. -/
private def Now : History -> NodeID -> NodeState -> Prop
  | [], _, _ => False
  | current :: _, node, state => (node, state) ∈ current.nodes

/-- `envelope` is queued in the newest state of `history`. -/
private def Pending : History -> Model.Envelope -> Prop
  | [], _ => False
  | current :: _, envelope => envelope ∈ current.network

/-- `node` had `state` at some point of `history`. -/
private def Seen (history : History) (node : NodeID) (state : NodeState) : Prop :=
  exists current, current ∈ history /\ (node, state) ∈ current.nodes

/-- The vote request of a candidate with this term, log and commit index. -/
private def vals (term : Nat) (log : List Entry) (commit : Nat) : RequestVoteRequest where
  term
  lastCommittableTerm := termAt log (max commit (maxCommittableIndex log))
  lastCommittableIndex := max commit (maxCommittableIndex log)

/-- `voter` votes for `candidate` in `term`, its log up to date for `request`. -/
private def GrantStep (after before : Model.State) (voter candidate : NodeID) (term : Nat)
    (request : RequestVoteRequest)
    : Prop :=
  exists granting granted,
    (voter, granting) ∈ before.nodes
    /\ (voter, granted) ∈ after.nodes
    /\ granting.currentTerm <= term
    /\ granted.currentTerm = term
    /\ granted.votedFor = some candidate
    /\ voteLogUpToDate granting request

private def Granted (history : History) (voter candidate : NodeID) (term : Nat)
    (request : RequestVoteRequest)
    : Prop :=
  exists after before rest,
    after :: before :: rest <:+ history
    /\ GrantStep after before voter candidate term request
    /\ (voter = candidate
        \/ exists state,
            Seen (before :: rest) candidate state /\ state.currentTerm = term)

/-- `node` becomes the leader of `term`, campaigning with `log` and `commit`. -/
private def ElectStep (after before : Model.State) (rest : History)
    (node : NodeID) (term : Nat) (log : List Entry) (commit : Nat)
    : Prop :=
  exists candidate leader,
    (node, candidate) ∈ before.nodes
    /\ (node, leader) ∈ after.nodes
    /\ candidate.log = log
    /\ candidate.commitIndex = commit
    /\ commit <= log.length
    /\ (candidate.currentTerm < term
        \/ (candidate.currentTerm = term /\ candidate.role = .candidate))
    /\ leader.currentTerm = term
    /\ (leader.role = .primary \/ leader.role = .none)
    /\ log.take (maxCommittableIndex log) <+: leader.log
    /\ 3 <= term
    /\ exists voters,
        hasQuorum (activeConfigurations log commit) voters
        /\ forall voter,
            voter ∈ voters
            -> Granted (after :: before :: rest) voter node term (vals term log commit)

private def Elected (history : History) (node : NodeID) (term : Nat)
    (log : List Entry) (commit : Nat)
    : Prop :=
  exists after before rest,
    after :: before :: rest <:+ history
    /\ ElectStep after before rest node term log commit

/-- `node` led `term`: the bootstrap leader, or elected. -/
private def Led (history : History) (node : NodeID) (term : Nat) : Prop :=
  (term = BOOTSTRAP_TERM /\ node = INITIAL_PRIMARY)
  \/ exists log commit, Elected history node term log commit

/-- `node` now has `state` as the leader of `term`, possibly stepped down. -/
private def CanonNow (history : History) (node : NodeID) (state : NodeState) (term : Nat)
    : Prop :=
  Now history node state
  /\ state.currentTerm = term
  /\ Not (state.role = .candidate)
  /\ Led history node term

/-- `log` was the log of the leader of `term` at some point. -/
private def Canon (history : History) (term : Nat) (log : List Entry) : Prop :=
  exists earlier,
    earlier <:+ history
    /\ exists node state, CanonNow earlier node state term /\ state.log = log

/-- A leader of `term` with `state` has its first `index` entries acknowledged
by a quorum of the configurations active at `base` and no later than `index`. -/
private def CommitStep (history : History) (leader : NodeID) (state : NodeState)
    (term base index : Nat)
    : Prop :=
  CanonNow history leader state term
  /\ base <= index
  /\ index <= state.log.length
  /\ isSignatureAt state.log index = true
  /\ termAt state.log index = term
  /\ exists voters,
      hasQuorum
        ((activeConfigurations state.log base).filter
          fun configuration => configuration.index <= index)
        voters
      /\ forall voter,
          voter ∈ voters
          -> exists acker,
              Seen history voter acker
              /\ acker.currentTerm = term
              /\ state.log.take index <+: acker.log

/--
Prefixes committed by a leader, each backed by earlier commits, possibly made by the
same step, as one commit can pass several configurations.
-/
private inductive Committed : History -> Nat -> List Entry -> Prop where
  | fresh {current : Model.State} {rest : History} {leader : NodeID}
    {state : NodeState} {term index : Nat}
    (step : CommitStep (current :: rest) leader state term 0 index)
    : Committed (current :: rest) term (state.log.take index)
  | chained {current : Model.State} {rest : History} {leader : NodeID}
    {state : NodeState} {term base index earlier : Nat}
    {part : List Entry}
    (step : CommitStep (current :: rest) leader state term base index)
    (backing : Committed (current :: rest) earlier part) (le : earlier <= term)
    (within : state.log.take base <+: part)
    : Committed (current :: rest) term (state.log.take index)
  | past {current : Model.State} {rest : History} {term : Nat}
    {part : List Entry} (old : Committed rest term part)
    : Committed (current :: rest) term part

/-- The first `commit` entries of `log` lie within a part committed by `term`. -/
private def Backed (history : History) (log : List Entry) (commit term : Nat) : Prop :=
  commit = 0
  \/ exists earlier part,
      Committed history earlier part /\ earlier <= term /\ log.take commit <+: part

/-- `voter` held the first `index` entries of a leader log of `term` in `term`. -/
private def Acked (history : History) (voter : NodeID) (term index : Nat) : Prop :=
  exists acker log,
    Seen history voter acker
    /\ acker.currentTerm = term
    /\ Canon history term log
    /\ index <= log.length
    /\ log.take index <+: acker.log

/-- A leader of a term in `(term, bound]` lacked `part`. -/
private def Bad (history : History) (part : List Entry) (term bound : Nat) : Prop :=
  exists later log,
    term < later /\ later <= bound /\ Canon history later log /\ Not (part <+: log)

/-- A snapshot is a signed prefix of a leader log, within a committed part. -/
private def SnapOK (history : History) (entries : List Entry) : Prop :=
  0 < entries.length
  /\ isSignatureAt entries entries.length = true
  /\ (exists log, Canon history (termAt entries entries.length) log /\ entries <+: log)
  /\ exists term part, Committed history term part /\ entries <+: part

/-- What a queued message tells about its sender. -/
private def MessageOK (history : History) (envelope : Model.Envelope) : Prop :=
  match envelope.payload with
  | .appendEntriesRequest request =>
      exists earlier,
        earlier <:+ history
        /\ exists state,
            CanonNow earlier envelope.source state request.term
            /\ AEOk envelope.source envelope.target state request
  | .appendEntriesResponse response =>
      response.success = true
      -> Acked history envelope.source response.term response.lastLogIndex
  | .requestVoteRequest request =>
      (exists state,
        Seen history envelope.source state /\ state.currentTerm = request.term)
      /\ forall state,
          Now history envelope.source state
          -> state.role = .candidate
          -> state.currentTerm = request.term
          -> makeRequestVoteRequest state = request
  | .requestVoteResponse response =>
      response.voteGranted = true
      -> exists request,
          Granted history envelope.source envelope.target response.term request
          /\ (exists state,
                Seen history envelope.target state /\ state.currentTerm = response.term)
          /\ forall state,
              Now history envelope.target state
              -> state.role = .candidate
              -> state.currentTerm = response.term
              -> makeRequestVoteRequest state = request
  | _ => True

private def Terms (history : History) : Prop :=
  forall node state,
    Now history node state
    -> forall entry, entry ∈ state.log -> entry.term <= state.currentTerm

private def Sorted (history : History) : Prop :=
  forall node state,
    Now history node state
    -> state.log.Pairwise fun first second => first.term <= second.term

private def Active (history : History) : Prop :=
  forall node state, Now history node state -> Engaged state -> 2 <= state.currentTerm

private def TermMono (history : History) : Prop :=
  forall node state earlier,
    Now history node state
    -> Seen history node earlier
    -> earlier.currentTerm <= state.currentTerm

private def VoteRecord (history : History) : Prop :=
  forall node state earlier candidate,
    Now history node state
    -> Seen history node earlier
    -> earlier.votedFor = some candidate
    -> earlier.currentTerm < state.currentTerm
        \/ (earlier.currentTerm = state.currentTerm /\ state.votedFor = some candidate)

private def LedCur (history : History) : Prop :=
  forall node state term,
    Now history node state
    -> Led history node term
    -> term < state.currentTerm
        \/ (term = state.currentTerm /\ Not (state.role = .candidate))

private def LeaderLed (history : History) : Prop :=
  forall node state,
    Now history node state -> state.role = .primary -> Led history node state.currentTerm

/--
A candidate whose committed prefix a commit step of its term or later covers,
from a base within that prefix, before any of its vote requests was granted.
Such a candidate cannot win: a voter of that commit outranks its log.
-/
private def Doomed (history : History) (node : NodeID) (state : NodeState) : Prop :=
  exists current past leader leaderState term base index,
    current :: past <:+ history
    /\ CommitStep (current :: past) leader leaderState term base index
    /\ state.currentTerm <= term
    /\ base <= state.commitIndex
    /\ state.log.take state.commitIndex <+: leaderState.log.take index
    /\ forall earlier,
        earlier <:+ history
        -> (exists seen, Seen earlier node seen /\ seen.currentTerm = state.currentTerm)
        -> current :: past <:+ earlier

private def Candidate (history : History) : Prop :=
  forall node state,
    Now history node state
    -> state.role = .candidate
    -> 3 <= state.currentTerm
        /\ state.votedFor = some node
        /\ (forall voter,
              voter ∈ state.votesGranted
              -> Granted history voter node state.currentTerm
                  (vals state.currentTerm state.log state.commitIndex))
        /\ (Backed history state.log state.commitIndex (state.currentTerm - 1)
            \/ Doomed history node state)
        /\ forall entry, entry ∈ state.log -> entry.term < state.currentTerm

private def ElectBacked (history : History) : Prop :=
  forall after before rest node term log commit,
    after :: before :: rest <:+ history
    -> ElectStep after before rest node term log commit
    -> Backed (before :: rest) log commit (term - 1)

private def ElectionSafety (history : History) : Prop :=
  forall node other term, Led history node term -> Led history other term -> node = other

private def CanonMono (history : History) : Prop :=
  forall node state,
    Now history node state
    -> Not (state.role = .candidate)
    -> Led history node state.currentTerm
    -> (forall log, Canon history state.currentTerm log -> log <+: state.log)
        /\ forall log commit,
            Elected history node state.currentTerm log commit
            -> log.take (maxCommittableIndex log) <+: state.log

private def Anchor (history : History) : Prop :=
  forall node state index,
    Now history node state
    -> 0 < index
    -> index <= state.log.length
    -> exists log,
        Canon history (termAt state.log index) log
        /\ index <= log.length
        /\ state.log.take index = log.take index

private def Completeness (history : History) : Prop :=
  forall term part node later log commit,
    Committed history term part
    -> Elected history node later log commit
    -> term < later
    -> part <+: log

/--
Committed prefixes lie within committed parts; a leader's of its current term,
even after it steps down, within one committed no later than that term. A node
joined from a snapshot may have a committed prefix that only a later term committed.
-/
private def CommitBacked (history : History) : Prop :=
  forall node state,
    Now history node state
    -> (exists term, Backed history state.log state.commitIndex term)
        /\ (Not (state.role = .candidate)
            -> Led history node state.currentTerm
            -> Backed history state.log state.commitIndex state.currentTerm)

private def Persist (history : History) : Prop :=
  forall node state earlier index,
    Now history node state
    -> Seen history node earlier
    -> isSignatureAt earlier.log index = true
    -> earlier.log.take index <+: state.log
        \/ Bad history (earlier.log.take index) (termAt earlier.log index)
            state.currentTerm

private def MatchAck (history : History) : Prop :=
  forall node state peer,
    Now history node state
    -> state.role = .primary
    -> Not (peer = node)
    -> 0 < state.matchIndex peer
    -> Acked history peer state.currentTerm (state.matchIndex peer)

private def Messages (history : History) : Prop :=
  forall envelope, Pending history envelope -> MessageOK history envelope

/-- Every log is empty or starts with the bootstrap configuration. -/
private def RootedLogs (history : History) : Prop :=
  forall node state, Now history node state -> Rooted GENESIS state.log

private def LeaderLogs (history : History) : Prop :=
  forall node state, Now history node state -> state.role = .primary -> state.log ≠ []

private def MessageTerms (history : History) : Prop :=
  forall envelope,
    Pending history envelope -> Bumping envelope.payload -> 2 <= envelope.payload.term

private structure Inv (history : History) : Prop where
  terms : Terms history
  sorted : Sorted history
  active : Active history
  term_mono : TermMono history
  vote_record : VoteRecord history
  led_cur : LedCur history
  leader_led : LeaderLed history
  candidate : Candidate history
  elect_backed : ElectBacked history
  election_safety : ElectionSafety history
  canon_mono : CanonMono history
  anchor : Anchor history
  completeness : Completeness history
  commit_backed : CommitBacked history
  persist : Persist history
  match_ack : MatchAck history
  messages : Messages history
  message_terms : MessageTerms history
  rooted : RootedLogs history
  leader_logs : LeaderLogs history

/-- The invariant holds at every point of the history. -/
private def Good (history : History) : Prop :=
  forall earlier, earlier <:+ history -> Not (earlier = []) -> Inv earlier

end Consensus.Proofs.Safety

namespace Consensus.Proofs.Safety

set_option linter.unusedSectionVars false
open CCF
open Model.Node
open Consensus.Proofs.Config
open Model (initialNodeState BOOTSTRAP_TERM)
variable [Config.InitialConfiguration]
section Initial

/-- The model's initial node state, with the bootstrap primary named directly. -/
private def initialLocal (node : NodeID) : NodeState where
  role :=
    if node = INITIAL_PRIMARY then
      .primary
    else if node ∈ INITIAL_CONFIGURATION then
      .follower
    else
      .none
  currentTerm := if node ∈ INITIAL_CONFIGURATION then BOOTSTRAP_TERM else 0
  log := if node = INITIAL_PRIMARY then [GENESIS] else []
  commitIndex := 0
  sentIndex := fun _ => 0
  matchIndex := fun _ => 0
  isNewFollower := false
  votedFor := none
  primaryKnown := node = INITIAL_PRIMARY
  votesGranted := ∅

end Initial
end Consensus.Proofs.Safety

namespace Consensus.Proofs.Safety

set_option linter.unusedSectionVars false
open CCF
open Model.Node
open Consensus.Proofs.Ledger
variable [Config.InitialConfiguration]

/-- `clause` holds at every nonempty suffix of `history`. -/
private def Everywhere (clause : History -> Prop) (history : History) : Prop :=
  forall earlier, earlier <:+ history -> Not (earlier = []) -> clause earlier

/-- One step of an execution, the invariant holding before it. -/
private structure Ctx (nodes : List NodeID) (after before : Model.State)
    (rest : History) where
  exec : Exec nodes (after :: before :: rest)
  tr : LocalTransition before after
  good : Good (before :: rest)

end Consensus.Proofs.Safety

namespace Consensus.Proofs.Safety.Ctx

set_option linter.unusedSectionVars false
open CCF
open Model.Node
open Consensus.Proofs.Ledger
variable [Config.InitialConfiguration]
variable {nodes : List NodeID} {after before : Model.State}
  {rest : History} (c : Ctx nodes after before rest)
include c

private abbrev actor : NodeID := c.tr.actor

private abbrev pre : NodeState := c.tr.pre

private abbrev post : NodeState := c.tr.post

private abbrev event : Event := c.tr.event

private abbrev sent : List Model.Envelope := c.tr.outputs.outgoing

end Consensus.Proofs.Safety.Ctx

namespace Consensus.Proofs.Config

open CCF (Finset)
open Model.Node
section Initial
variable [config : InitialConfiguration]

private theorem initial_primary_iff (nonempty : INITIAL_CONFIGURATION.Nonempty)
    {node : NodeID}
    : INITIAL_CONFIGURATION.min? = some node <-> node = INITIAL_PRIMARY := by
  obtain ⟨least, found⟩ := Option.isSome_iff_exists.mp (Finset.min?_isSome nonempty)
  simp only [INITIAL_PRIMARY, found, Option.getD_some, Option.some.injEq]
  exact eq_comm

private theorem INITIAL_PRIMARY_mem (nonempty : INITIAL_CONFIGURATION.Nonempty)
    : INITIAL_PRIMARY ∈ INITIAL_CONFIGURATION := by
  obtain ⟨least, found⟩ := Option.isSome_iff_exists.mp (Finset.min?_isSome nonempty)
  simp only [INITIAL_PRIMARY, found, Option.getD_some]
  exact Finset.min?_mem found

private theorem GENESIS_configured : GENESIS.content.metadata.configuration.isSome := by
  simp [EntryContent.metadata]

end Initial
end Consensus.Proofs.Config

namespace Consensus.Proofs.Concrete

set_option linter.unusedSectionVars false
open Consensus.Proofs.Config
open CCF CCF.MultiNodeTransitionSystem
open Model.Node
section Steps
variable [Config.InitialConfiguration]

private theorem step_next
    {nodes : List NodeID} {before after : Model.State} {action : Model.Action}
    (stepped
      : (Model.transitionSystem Config.INITIAL_CONFIGURATION nodes).step before action
        = some after)
    : next (Model.protocol Config.INITIAL_CONFIGURATION) before action = some after := by
  simp only [Model.transitionSystem, Model.networkStep] at stepped
  split at stepped
  · split at stepped
    · exact stepped
    · cases stepped
  · exact stepped

private theorem step_local
    {nodes : List NodeID} {before after : Model.State}
    {node : NodeID} {input : Model.Node.Input}
    (stepped
      : (Model.transitionSystem Config.INITIAL_CONFIGURATION nodes).step before
          (.local node input)
        = some after)
    : exists state next outputs,
        nodeState before node = some state
        /\ (Model.Node.act (Capabilities.record node) node state input).run {}
            = some (next, outputs)
        /\ after
            = {
              before with
                nodes := replaceNode before.nodes node next
                network := before.network ++ outputs.outgoing
            } := by
  replace stepped := step_next stepped
  simp only [next, Model.protocol] at stepped
  simp [Model.Node.step, Option.bind_eq_some_iff] at stepped
  obtain ⟨state, found, next, outputs, ran, rfl⟩ := stepped
  refine ⟨state, next, outputs, found, ?_, by simp [replaceNode]⟩
  exact ran

private theorem step_deliver
    {nodes : List NodeID} {before after : Model.State}
    {envelope : Model.Envelope}
    (stepped
      : (Model.transitionSystem Config.INITIAL_CONFIGURATION nodes).step before
          (.deliver envelope)
        = some after)
    : envelope ∈ before.network
      /\ exists state next outputs,
          nodeState before envelope.target = some state
          /\ (Model.Node.receive (Capabilities.record envelope.target)
                envelope.target envelope.source state
                envelope.payload).run
                {}
              = some (next, outputs)
          /\ after
              = {
                before with
                  nodes := replaceNode before.nodes envelope.target next
                  network := removeOne envelope before.network ++ outputs.outgoing
              } := by
  replace stepped := step_next stepped
  simp only [next, Model.protocol] at stepped
  simp [Model.Node.step, Option.bind_eq_some_iff, guard] at stepped
  obtain ⟨queued, state, found, next, outputs, ran, rfl⟩ := stepped
  exact ⟨queued, state, next, outputs, found, ran, by simp [replaceNode]⟩

end Steps
end Consensus.Proofs.Concrete

namespace Consensus.Proofs.Concrete

set_option linter.unusedSectionVars false
open Consensus.Proofs.Config
open CCF CCF.MultiNodeTransitionSystem
open Model.Node

private theorem mem_replaceNode {nodes : List (NodeID × NodeState)} {node member : NodeID}
    {value state : NodeState}
    (found : (member, state) ∈ replaceNode nodes node value)
    : (member = node /\ state = value)
      \/ (Not (member = node) /\ (member, state) ∈ nodes) := by
  simp only [replaceNode, List.mem_map] at found
  obtain ⟨⟨key, old⟩, listed, same⟩ := found
  by_cases here : key = node
  · simp only [here, beq_self_eq_true, ite_true, Prod.mk.injEq] at same
    exact Or.inl ⟨same.1.symm, same.2.symm⟩
  · have different : (key == node) = false := by simpa using here
    simp only [different, Bool.false_eq_true, ite_false, Prod.mk.injEq] at same
    obtain ⟨rfl, rfl⟩ := same
    exact Or.inr ⟨here, listed⟩

private theorem replaceNode_keys (nodes : List (NodeID × NodeState)) (node : NodeID)
    (value : NodeState)
    : (replaceNode nodes node value).map Prod.fst = nodes.map Prod.fst := by
  simp only [replaceNode, List.map_map]
  congr 1
  funext entry
  by_cases here : entry.1 = node <;> simp [here]

private theorem mem_of_nodeState {concrete : Model.State} {node : NodeID}
    {state : NodeState} (found : nodeState concrete node = some state)
    : (node, state) ∈ concrete.nodes := by
  simp only [nodeState, Option.map_eq_some_iff] at found
  obtain ⟨⟨key, value⟩, located, rfl⟩ := found
  have same : key = node := by simpa using List.find?_some located
  subst same
  exact List.mem_of_find?_eq_some located

private theorem observeTerm_log (state : NodeState) (message : Model.Node.Message)
    : (Model.Node.observeTerm state message).log = state.log := by
  unfold Model.Node.observeTerm Model.Node.updateTerm
  split <;> (try split) <;> (try split) <;> rfl

private theorem observeTerm_commitIndex (state : NodeState) (message : Model.Node.Message)
    : (Model.Node.observeTerm state message).commitIndex = state.commitIndex := by
  unfold Model.Node.observeTerm Model.Node.updateTerm
  split <;> (try split) <;> (try split) <;> rfl

@[simp]
private theorem run_failure {σ α : Type} (s : σ)
    : (failure : StateT σ Option α).run s = none :=
  Option.eq_none_iff_forall_ne_some.mpr fun _ ran => nomatch ran

end Consensus.Proofs.Concrete

namespace Consensus.Proofs.Ledger

set_option linter.unusedSectionVars false
open Consensus.Proofs.Config
open Consensus.Model.Node

@[simp]
private theorem EntryContent.isSignature_eq_true {content : EntryContent}
    : content.isSignature = true <-> content = .signature := by
  cases content <;> simp [EntryContent.isSignature]

/-- A successful one-based lookup proves the index lies within the log. -/
private theorem entryAtSomeIndexBound
    {log : List Entry}
    {index : Nat}
    {entry : Entry}
    (found : entryAt? log index = some entry)
    : index <= log.length := by
  unfold entryAt? at found
  split at found
  · simp_all
  · rename_i indexNotZero
    rw [List.getElem?_eq_some_iff] at found
    rcases found with ⟨within, _⟩
    rw [← Nat.sub_add_cancel (Nat.pos_of_ne_zero indexNotZero)]
    exact within

/-- A successful one-based lookup is membership evidence. -/
private theorem entryAt_mem
    {log : List Entry}
    {index : Nat}
    {entry : Entry}
    (found : entryAt? log index = some entry)
    : entry ∈ log := by
  unfold entryAt? at found
  split at found
  · simp_all
  · rw [List.getElem?_eq_some_iff] at found
    rcases found with ⟨within, value⟩
    rw [← value]
    exact List.getElem_mem within

/-- A successful lookup is unchanged when the log is extended at the end. -/
private theorem entryAt_of_prefix
    {left right : List Entry}
    (isPrefix : left <+: right)
    {index : Nat}
    {entry : Entry}
    (found : entryAt? left index = some entry)
    : entryAt? right index = some entry := by
  rcases isPrefix with ⟨suffix, rightEq⟩
  rw [← rightEq]
  unfold entryAt? at found ⊢
  by_cases zero : index = 0
  · simp [zero] at found
  · simp only [zero, ↓reduceIte] at found ⊢
    have within : index - 1 < left.length := by
      rw [List.getElem?_eq_some_iff] at found
      exact found.1
    rw [List.getElem?_append_left within]
    exact found

/-- A positive signature test identifies a concrete signature entry. -/
private theorem isSignatureAtTrue
    {log : List Entry}
    {index : Nat}
    (signature : isSignatureAt log index = true)
    : Exists
        fun entry =>
          entryAt? log index = some entry /\ entry.content = .signature := by
  cases found : entryAt? log index with
  | none =>
      simp [isSignatureAt, found] at signature
  | some entry =>
      refine ⟨entry, rfl, ?_⟩
      simpa [isSignatureAt, found] using signature

/-- The latest signature index lies within the log. -/
private theorem maxCommittableIndexBounded (log : List Entry)
    : maxCommittableIndex log <= log.length := by
  unfold maxCommittableIndex
  let candidates := List.range (log.length + 1)
  let choose :=
    fun best index =>
      if isSignatureAt log index then max best index else best
  have allBounded :
      forall index,
        index ∈ candidates ->
          index <= log.length := by
    intro index member
    simp [candidates] at member
    exact Nat.le_of_lt_succ member
  have foldBounded :
      forall (values : List Nat) (best : Nat),
        (forall index, index ∈ values -> index <= log.length) ->
        best <= log.length ->
        values.foldl choose best <= log.length := by
    intro values
    induction values with
    | nil =>
        intro best _ bestBound
        exact bestBound
    | cons head tail inductionHypothesis =>
        intro best valuesBound bestBound
        apply inductionHypothesis
        · intro index member
          exact valuesBound index (by simp [member])
        · have headBound := valuesBound head (by simp)
          simp only [choose]
          split
          · exact Nat.max_le.mpr ⟨bestBound, headBound⟩
          · exact bestBound
  change candidates.foldl choose 0 <= log.length
  exact foldBounded candidates 0 allBounded (Nat.zero_le _)

/-- A positive latest committable index points to a signature. -/
private theorem maxCommittableIndexPositiveIsSignature
    {log : List Entry}
    (positive : 0 < maxCommittableIndex log)
    : isSignatureAt log (maxCommittableIndex log) = true := by
  unfold maxCommittableIndex at positive ⊢
  let valid := fun index => isSignatureAt log index = true
  let choose :=
    fun best index =>
      if valid index then max best index else best
  have foldValid :
      forall (values : List Nat) (best : Nat),
        (best = 0 \/ valid best) ->
        let result := values.foldl choose best
        result = 0 \/ valid result := by
    intro values
    induction values with
    | nil =>
        intro best bestValid
        exact bestValid
    | cons head tail inductionHypothesis =>
        intro best bestValid
        apply inductionHypothesis
        simp only [choose]
        by_cases headValid : valid head
        · simp [headValid]
          rcases bestValid with bestZero | bestIsValid
          · subst best
            exact Or.inr headValid
          · by_cases bestLeHead : best <= head
            · right
              simpa [Nat.max_eq_right bestLeHead] using headValid
            · right
              have headLeBest : head <= best := Nat.le_of_lt (Nat.lt_of_not_le bestLeHead)
              simpa [Nat.max_eq_left headLeBest] using bestIsValid
        · simp [headValid, bestValid]
  have resultValid :=
    foldValid (List.range (log.length + 1)) 0 (Or.inl rfl)
  rcases resultValid with resultZero | resultValid
  · rw [resultZero] at positive
    exact absurd positive (Nat.lt_irrefl 0)
  · exact resultValid

/-- Every signature index is no later than the latest signature index. -/
private theorem signatureIndex_le_maxCommittableIndex
    {log : List Entry}
    {index : Nat}
    (signature : isSignatureAt log index = true)
    : index <= maxCommittableIndex log := by
  have indexBound : index <= log.length := by
    rcases isSignatureAtTrue signature with ⟨entry, found, _⟩
    exact entryAtSomeIndexBound found
  unfold maxCommittableIndex
  let candidates := List.range (log.length + 1)
  let choose :=
    fun best candidate =>
      if isSignatureAt log candidate then
        max best candidate
      else
        best
  have foldAboveStart :
      forall (values : List Nat) (best : Nat),
        best <= values.foldl choose best := by
    intro values
    induction values with
    | nil =>
        intro best
        exact Nat.le.refl
    | cons head tail inductionHypothesis =>
        intro best
        apply Nat.le_trans (m := choose best head)
        · simp only [choose]
          split
          · exact Nat.le_max_left _ _
          · exact Nat.le.refl
        · exact inductionHypothesis (choose best head)
  have foldContains :
      forall (values : List Nat) (best : Nat),
        index ∈ values ->
          index <= values.foldl choose best := by
    intro values
    induction values with
    | nil =>
        simp
    | cons head tail inductionHypothesis =>
        intro best member
        simp only [List.foldl_cons]
        rcases List.mem_cons.mp member with headEq | tailMember
        · subst head
          have selected :
              choose best index = max best index := by
            simp [choose, signature]
          rw [selected]
          exact Nat.le_trans (Nat.le_max_right best index) (foldAboveStart tail (max best index))
        · exact
            inductionHypothesis
              (choose best head) tailMember
  change index <= candidates.foldl choose 0
  exact foldContains candidates 0
    (by
      simp [candidates]
      exact Nat.lt_succ_of_le indexBound)

/-- Extending a log preserves every earlier signature lookup. -/
private theorem isSignatureAt_of_prefix
    {left right : List Entry}
    (isPrefix : left <+: right)
    {index : Nat}
    (signature : isSignatureAt left index = true)
    : isSignatureAt right index = true := by
  rcases isSignatureAtTrue signature with ⟨entry, found, content⟩
  have extended := entryAt_of_prefix isPrefix found
  simp [isSignatureAt, extended, content]

/-- Extending a log cannot move its latest signature backwards. -/
private theorem maxCommittableIndex_le_of_prefix
    {left right : List Entry}
    (isPrefix : left <+: right)
    : maxCommittableIndex left <= maxCommittableIndex right := by
  by_cases zero : maxCommittableIndex left = 0
  · rw [zero]
    exact Nat.zero_le _
  · have positive : 0 < maxCommittableIndex left :=
      Nat.pos_of_ne_zero zero
    exact
      signatureIndex_le_maxCommittableIndex
        (isSignatureAt_of_prefix isPrefix
          (maxCommittableIndexPositiveIsSignature positive))

/-- Taking a log prefix leaves lookups inside that prefix unchanged. -/
private theorem isSignatureAt_take_of_le
    {log : List Entry}
    {index count : Nat}
    (within : index <= count)
    (signature : isSignatureAt log index = true)
    : isSignatureAt (log.take count) index = true := by
  rcases isSignatureAtTrue signature with ⟨entry, found, content⟩
  have taken : entryAt? (log.take count) index = some entry := by
    by_cases zero : index = 0
    · subst index
      simp [entryAt?] at found
    · unfold entryAt? at found ⊢
      simp only [zero, ↓reduceIte] at found ⊢
      rw [List.getElem?_take]
      split
      · exact found
      · rename_i outside
        exact absurd (Nat.lt_of_lt_of_le (Nat.sub_one_lt zero) within) outside
  simp [isSignatureAt, taken, content]

/-- The bounded committable frontier does not exceed the complete log. -/
private theorem maxCommittableIndexUpTo_le_length (log : List Entry) (frontier : Nat)
    : maxCommittableIndexUpTo log frontier <= log.length := by
  unfold maxCommittableIndexUpTo
  have bounded :=
    maxCommittableIndexBounded (log.take frontier)
  simp only [List.length_take] at bounded
  exact Nat.le_trans bounded (Nat.min_le_right _ _)

/-- Restricting the search frontier cannot reveal a later signature. -/
private theorem maxCommittableIndexUpTo_le (log : List Entry) (frontier : Nat)
    : maxCommittableIndexUpTo log frontier <= maxCommittableIndex log := by
  unfold maxCommittableIndexUpTo
  exact
    maxCommittableIndex_le_of_prefix
      (List.take_prefix frontier log)

/-- A positive bounded committable frontier points to a signature in the log. -/
private theorem maxCommittableIndexUpToPositiveIsSignature
    {log : List Entry}
    {frontier : Nat}
    (positive : 0 < maxCommittableIndexUpTo log frontier)
    : isSignatureAt log (maxCommittableIndexUpTo log frontier) = true := by
  unfold maxCommittableIndexUpTo at positive ⊢
  exact
    isSignatureAt_of_prefix
      (List.take_prefix frontier log)
      (maxCommittableIndexPositiveIsSignature positive)

private theorem configurationHistory_filterMap (index : Nat) (log : List Entry)
    : (log.zipIdx index).filterMap
        (fun (entry, index) =>
          entry.content.metadata.configuration.map
            (fun nodes => ({ index, nodes } : Configuration)))
      = configurationsInLogFrom index log := by
  induction log generalizing index with
  | nil => rfl
  | cons entry entries ih =>
      rcases entry with ⟨term, content⟩
      cases h : content.metadata.configuration <;>
        simp [configurationsInLogFrom, h, ih]

@[simp]
private theorem activeConfigurations_eq (state : NodeState)
    : Model.Node.activeConfigurations state.log state.commitIndex
      = activeConfigurationsOf state := by
  rfl

@[simp]
private theorem NodeState.activeConfigurations_eq (state : NodeState)
    : state.activeConfigurations = activeConfigurationsOf state :=
  Consensus.Proofs.Ledger.activeConfigurations_eq state

@[simp]
private theorem NodeState.activeMembers_eq (state : NodeState)
    : state.activeMembers = activeNodeUnion state := by
  simp [Model.Node.NodeState.activeMembers, activeNodeUnion, configurationMembers]

/-- Recording a commit changes the commit index and retirement latch, and may
clear the role and primary knowledge. -/
private theorem NodeState.recordCommit_eq (node : NodeID) (state : NodeState)
    (index : Nat)
    : exists retiredCommittedIndex role primaryKnown,
        state.recordCommit node index
          = { state with commitIndex := index, retiredCommittedIndex, role, primaryKnown }
        /\ (role = state.role \/ role = .none) := by
  unfold NodeState.recordCommit
  dsimp only
  split
  · exact ⟨_, _, _, rfl, Or.inr rfl⟩
  · exact ⟨_, _, _, rfl, Or.inl rfl⟩

@[simp]
private theorem NodeState.recordCommit_log (node : NodeID) (state : NodeState)
    (index : Nat)
    : (state.recordCommit node index).log = state.log := by
  obtain ⟨_, _, _, eq, _⟩ := NodeState.recordCommit_eq node state index
  rw [eq]

@[simp]
private theorem NodeState.recordCommit_commitIndex (node : NodeID) (state : NodeState)
    (index : Nat)
    : (state.recordCommit node index).commitIndex = index := by
  obtain ⟨_, _, _, eq, _⟩ := NodeState.recordCommit_eq node state index
  rw [eq]

/-- Extending a log cannot move its bounded committable frontier backwards. -/
private theorem maxCommittableIndexUpTo_mono {left right : List Entry}
    (isPrefix : left <+: right) (frontier : Nat)
    : maxCommittableIndexUpTo left frontier <= maxCommittableIndexUpTo right frontier :=
  maxCommittableIndex_le_of_prefix
    (List.prefix_take_iff.mpr
      ⟨(List.take_prefix _ _).trans isPrefix, List.length_take_le _ _⟩)

/-- The follower append loop changes only the log, commit and retirement
fields, and may clear the role. -/
private theorem fromLeader_loop (self : NodeID) (limit : Nat) (entries : List Entry)
    : forall (state : NodeState),
        exists commitIndex retiredCommittedIndex role primaryKnown,
          entries.foldl
              (fun state entry =>
                let state := { state with log := state.log ++ [entry] }
                if entry.content.isSignature then
                  state.recordCommit self
                    (max state.commitIndex (maxCommittableIndexUpTo state.log limit))
                else
                  state)
              state
            = {
              state with
                log := state.log ++ entries,
                commitIndex,
                retiredCommittedIndex,
                role,
                primaryKnown
            }
          /\ (role = state.role \/ role = .none)
          /\ state.commitIndex <= commitIndex
          /\ commitIndex
              <= max state.commitIndex
                  (maxCommittableIndexUpTo (state.log ++ entries) limit) := by
  induction entries with
  | nil =>
      intro state
      exact ⟨
        state.commitIndex,
        state.retiredCommittedIndex,
        state.role,
        state.primaryKnown,
        by simp,
        Or.inl rfl,
        Nat.le.refl,
        Nat.le_max_left _ _
      ⟩
  | cons entry entries ih =>
      intro state
      simp only [List.foldl_cons]
      have mono :=
        maxCommittableIndexUpTo_mono (List.prefix_append (state.log ++ [entry]) entries) limit
      simp only [List.append_assoc, List.cons_append, List.nil_append] at mono
      by_cases signature : entry.content.isSignature
      · simp only [signature, ↓reduceIte]
        obtain ⟨retired₀, role₀, known₀, eq₀, roleCase₀⟩ :=
          NodeState.recordCommit_eq self { state with log := state.log ++ [entry] }
            (max state.commitIndex
              (maxCommittableIndexUpTo (state.log ++ [entry]) limit))
        rw [eq₀]
        obtain ⟨commitIndex, retired, role, known, eq, roleCase, lower, upper⟩ := ih _
        rw [eq]
        simp only [List.append_assoc, List.cons_append, List.nil_append] at lower upper roleCase ⊢
        refine ⟨commitIndex, retired, role, known, rfl, ?_,
          Nat.le_trans (Nat.le_max_left _ _) lower,
          Nat.le_trans upper (Nat.max_le.mpr ⟨Nat.max_le.mpr ⟨Nat.le_max_left _ _,
            Nat.le_trans mono (Nat.le_max_right _ _)⟩, Nat.le_max_right _ _⟩)⟩
        rcases roleCase with same | none
        · rw [same]
          exact roleCase₀
        · exact Or.inr none
      · simp only [signature, Bool.false_eq_true, ↓reduceIte]
        obtain ⟨commitIndex, retired, role, known, eq, roleCase, lower, upper⟩ := ih _
        rw [eq]
        simp only [List.append_assoc, List.cons_append, List.nil_append] at lower upper roleCase ⊢
        exact ⟨commitIndex, retired, role, known, rfl, roleCase, lower, upper⟩

/--
Intermediate commits use prefixes of the final log, so the follower's final
commit index is the bounded committable frontier of the extended log.
-/
private theorem handleAppendEntiresFromPrimary_eq (self : NodeID) (state : NodeState)
    (request : AppendEntriesRequest)
    : let log :=
        state.log ++ request.entries.drop (state.log.length - request.prevLogIndex)
      exists retiredCommittedIndex role primaryKnown,
        handleAppendEntiresFromPrimary self state request
          = (
            {
              state with
                log
                commitIndex :=
                  max state.commitIndex
                    (maxCommittableIndexUpTo log
                      (min request.primaryCommit
                        (request.prevLogIndex + request.entries.length)))
                retiredCommittedIndex
                role
                primaryKnown
            },
            {
              term := state.currentTerm
              success := true
              lastLogIndex := request.prevLogIndex + request.entries.length
            }
          )
        /\ (role = state.role \/ role = .none) := by
  intro log
  obtain ⟨commitIndex, retired, role, known, eq, roleCase, lower, upper⟩ :=
    fromLeader_loop self
      (min request.primaryCommit (request.prevLogIndex + request.entries.length))
      (request.entries.drop (state.log.length - request.prevLogIndex)) state
  unfold handleAppendEntiresFromPrimary
  dsimp only
  rw [eq]
  obtain ⟨retired', role', known', eq', roleCase'⟩ := NodeState.recordCommit_eq self _ _
  rw [eq']
  refine ⟨retired', role', known', ?_, ?_⟩
  · simp only [log]
    congr 2
    exact Nat.le_antisymm (Nat.max_le.mpr ⟨upper, Nat.le_max_right _ _⟩)
      (Nat.max_le.mpr ⟨Nat.le_trans lower (Nat.le_max_left _ _), Nat.le_max_right _ _⟩)
  · rcases roleCase' with same | none
    · rw [same]
      exact roleCase
    · exact Or.inr none

/-- A rollback point lies after the request's previous index. -/
private theorem firstTermConflictIndex_ge {state : NodeState}
    {request : AppendEntriesRequest} {index : Nat}
    (conflict : firstTermConflictIndex state request = some index)
    : request.prevLogIndex + 1 <= index := by
  unfold firstTermConflictIndex at conflict
  obtain ⟨pair, found, rfl⟩ := Option.map_eq_some_iff.mp conflict
  obtain ⟨_, offset, lt, rfl, _⟩ := List.find?_eq_some_iff_getElem.mp found
  simp

end Consensus.Proofs.Ledger

namespace Consensus.Proofs.Direct

set_option linter.unusedSectionVars false
open Consensus.Proofs.Config
open CCF CCF.MultiNodeTransitionSystem Concrete
open Model.Node
open Model (initialNodeState)
variable [Config.InitialConfiguration]

private theorem NodeInvariant.reachable {P : NodeID -> NodeState -> Prop}
    (invariant : NodeInvariant P) {nodes : List NodeID} {state : Model.State}
    (reachable
      : (Model.transitionSystem Config.INITIAL_CONFIGURATION nodes).Reachable state)
    : forall node local_, (node, local_) ∈ state.nodes -> P node local_ := by
  induction reachable
    using @TransitionSystem.Reachable.rec
      (Model.transitionSystem Config.INITIAL_CONFIGURATION nodes) with
  | initial initialized =>
      intro node local_ member
      have initial : local_ = initialNodeState Config.INITIAL_CONFIGURATION node := initialized.2.2.2.2 (node, local_) member
      subst initial
      exact invariant.initial node
  | @step before after action _ stepped ih =>
      have preserved : forall {actor : NodeID} {old : NodeState}
          {event : Model.Node.Event} {new outputs},
          nodeState before actor = some old ->
          (Model.Node.step (Capabilities.record actor) actor old event).run {}
            = some (new, outputs) ->
          forall node local_,
            (node, local_) ∈ replaceNode before.nodes actor new ->
            P node local_ := by
        intro actor old event new outputs found acted node local_ member
        rcases mem_replaceNode member with ⟨rfl, rfl⟩ | ⟨_, listed⟩
        · exact invariant.step _ _ _ _ _ (ih _ _ (mem_of_nodeState found)) acted
        · exact ih _ _ listed
      cases action with
      | «local» actor input =>
          obtain ⟨old, new, outputs, found, acted, rfl⟩ := step_local stepped
          exact preserved (event := .internal input) found
            (by cases input <;> exact acted)
      | deliver envelope =>
          obtain ⟨_, old, new, outputs, found, received, rfl⟩ := step_deliver stepped
          exact preserved (event := .receive envelope.source envelope.payload) found received

private theorem keys_nodup {nodes : List NodeID} {state : Model.State}
    (reachable
      : (Model.transitionSystem Config.INITIAL_CONFIGURATION nodes).Reachable state)
    : (state.nodes.map Prod.fst).Nodup := by
  induction reachable
    using @TransitionSystem.Reachable.rec
      (Model.transitionSystem Config.INITIAL_CONFIGURATION nodes) with
  | initial initialized => exact initialized.2.2.1
  | @step before after action _ stepped ih =>
      cases action with
      | «local» actor input =>
          obtain ⟨_, _, _, _, _, rfl⟩ := step_local stepped
          simpa [replaceNode_keys] using ih
      | deliver envelope =>
          obtain ⟨_, _, _, _, _, _, rfl⟩ := step_deliver stepped
          simpa [replaceNode_keys] using ih

private theorem find_of_mem {entries : List (NodeID × NodeState)} {node : NodeID}
    {local_ : NodeState} (distinct : (entries.map Prod.fst).Nodup)
    (member : (node, local_) ∈ entries)
    : entries.find? (fun entry => entry.1 == node) = some (node, local_) := by
  induction entries with
  | nil => simp at member
  | cons head tail ih =>
      obtain ⟨key, value⟩ := head
      simp only [List.map_cons, List.nodup_cons] at distinct
      by_cases here : key = node
      · subst here
        rcases List.mem_cons.mp member with same | later
        · rw [same]
          simp
        · exact absurd (List.mem_map.mpr ⟨_, later, rfl⟩) distinct.1
      · rcases List.mem_cons.mp member with same | later
        · simp only [Prod.mk.injEq] at same
          exact absurd same.1.symm here
        · simp [here, ih distinct.2 later]

private theorem nodeState_of_mem {state : Model.State} {node : NodeID}
    {local_ : NodeState} (distinct : (state.nodes.map Prod.fst).Nodup)
    (member : (node, local_) ∈ state.nodes)
    : nodeState state node = some local_ := by
  simp [nodeState, find_of_mem distinct member]

end Consensus.Proofs.Direct

namespace Consensus.Proofs.Direct.Keeps

set_option linter.unusedSectionVars false
open CCF
variable {Node Message Notification : Type}
variable {α β : Type}

private theorem pure' {P : α -> Prop} {value : α} (holds : P value)
    : Keeps (Node := Node) (Message := Message) (Notification := Notification) P
        (pure value) := by
  intro _ _ _ ran
  cases ran
  exact holds

private theorem trivial' (m : Effect Node Message Notification α)
    : Keeps (fun _ => True) m :=
  fun _ _ _ _ => True.intro

private theorem guard' {c : Prop} [Decidable c]
    : Keeps (Node := Node) (Message := Message) (Notification := Notification)
        (fun _ => c) (guard c) := by
  intro outputs _ after ran
  by_cases holds : c
  · exact holds
  · simp [guard, holds] at ran

private theorem bind' {Q : α -> Prop} {P : β -> Prop}
    {m : Effect Node Message Notification α} {f : α -> Effect Node Message Notification β}
    (first : Keeps Q m) (rest : forall value, Q value -> Keeps P (f value))
    : Keeps P (m >>= f) := by
  intro outputs result after ran
  simp only [StateT.run_bind] at ran
  cases ranFirst : m.run outputs with
  | none => simp [ranFirst] at ran
  | some pair =>
      obtain ⟨value, middle⟩ := pair
      simp only [ranFirst] at ran
      exact rest value (first _ _ _ ranFirst) _ _ _ ran

private theorem seq' {P : β -> Prop} {m : Effect Node Message Notification α}
    {f : α -> Effect Node Message Notification β}
    (rest : forall value, Keeps P (f value))
    : Keeps P (m >>= f) :=
  bind' (trivial' m) fun value _ => rest value

private theorem mono {P Q : α -> Prop} {m : Effect Node Message Notification α}
    (kept : Keeps P m) (weaker : forall value, P value -> Q value)
    : Keeps Q m :=
  fun outputs result after ran => weaker _ (kept outputs result after ran)

private theorem ite' {P : α -> Prop} {c : Prop} [Decidable c]
    {m n : Effect Node Message Notification α}
    (yes : c -> Keeps P m) (no : Not c -> Keeps P n)
    : Keeps P (if c then m else n) := by
  split
  · exact yes ‹_›
  · exact no ‹_›

private theorem foldlM' {γ : Type} {P : α -> Prop}
    {f : α -> γ -> Effect Node Message Notification α}
    (step : forall value item, P value -> Keeps P (f value item))
    : forall (items : List γ) (init : α), P init -> Keeps P (items.foldlM f init)
  | [], _, holds => by simpa using pure' holds
  | item :: items, init, holds => by
      simp only [List.foldlM_cons]
      exact bind' (step init item holds) fun value kept => foldlM' step items value kept

end Consensus.Proofs.Direct.Keeps

namespace Consensus.Proofs.Safety.Sends

set_option linter.unusedSectionVars false
open CCF
variable {Node Message Notification : Type}
variable {α β γ : Type}

private theorem pure' {P : α -> List (Envelope Node Message) -> Prop} {value : α}
    (holds : P value [])
    : Sends (Notification := Notification) P (pure value) := by
  intro outputs _ _ ran
  cases ran
  exact ⟨[], by simp, holds⟩

private theorem bind' {Q : α -> List (Envelope Node Message) -> Prop}
    {P : β -> List (Envelope Node Message) -> Prop}
    {m : Effect Node Message Notification α} {f : α -> Effect Node Message Notification β}
    (first : Sends Q m)
    (rest
      : forall value sent,
          Q value sent -> Sends (fun result later => P result (sent ++ later)) (f value))
    : Sends P (m >>= f) := by
  intro outputs result after ran
  simp only [StateT.run_bind] at ran
  cases ranFirst : m.run outputs with
  | none => simp [ranFirst] at ran
  | some pair =>
      obtain ⟨value, middle⟩ := pair
      simp only [ranFirst] at ran
      obtain ⟨sent, sentEq, holds⟩ := first _ _ _ ranFirst
      obtain ⟨later, laterEq, done⟩ := rest value sent holds _ _ _ ran
      exact ⟨sent ++ later, by rw [laterEq, sentEq, List.append_assoc], done⟩

private theorem mono {P Q : α -> List (Envelope Node Message) -> Prop}
    {m : Effect Node Message Notification α} (sends : Sends P m)
    (weaker : forall value sent, P value sent -> Q value sent)
    : Sends Q m := by
  intro outputs result after ran
  obtain ⟨sent, eq, holds⟩ := sends _ _ _ ran
  exact ⟨sent, eq, weaker _ _ holds⟩

private theorem ite' {P : α -> List (Envelope Node Message) -> Prop} {c : Prop}
    [Decidable c] {m n : Effect Node Message Notification α} (yes : c -> Sends P m)
    (no : Not c -> Sends P n)
    : Sends P (if c then m else n) := by
  split
  · exact yes ‹_›
  · exact no ‹_›

private theorem guard' {c : Prop} [Decidable c]
    : Sends (Node := Node) (Message := Message) (Notification := Notification)
        (fun _ sent => c /\ sent = []) (guard c) := by
  intro outputs _ after ran
  by_cases holds : c
  · simp [guard, holds] at ran
    obtain ⟨_, rfl⟩ := ran
    exact ⟨[], by simp, holds, rfl⟩
  · simp [guard, holds] at ran

private theorem guard_bind {P : α -> List (Envelope Node Message) -> Prop} {c : Prop}
    [Decidable c] {m : Effect Node Message Notification α} (rest : c -> Sends P m)
    : Sends P (guard c >>= fun _ => m) :=
  bind' guard'
    fun _ _ ⟨holds, empty⟩ => by
      subst empty
      exact mono (rest holds) fun _ _ done => by simpa using done

private theorem send (source target : Node) (payload : Message)
    : Sends (Notification := Notification)
        (fun _ sent => sent = [{ source, target, payload }])
        ((Capabilities.record source).send payload target) := by
  intro outputs _ after ran
  simp only [Capabilities.record, modify, modifyGet, StateT.run] at ran
  cases ran
  exact ⟨_, rfl, rfl⟩

/-- A `for` loop whose bodies each only send envelopes satisfying `R`. -/
private theorem forIn' {β : Type} {items : List γ} {init : β}
    {f : γ -> β -> Effect Node Message Notification (ForInStep β)}
    {R : Envelope Node Message -> Prop}
    (each
      : forall item value,
          item ∈ items -> Sends (fun _ sent => forall e, e ∈ sent -> R e) (f item value))
    : Sends (fun _ sent => forall e, e ∈ sent -> R e) (forIn items init f) := by
  induction items generalizing init with
  | nil =>
      simpa using pure' (P := fun (_ : β) sent => forall e, e ∈ sent -> R e) (by simp)
  | cons head tail ih =>
      rw [List.forIn_cons]
      refine bind' (each head init List.mem_cons_self) fun step sent first => ?_
      cases step with
      | done value => exact pure' fun e member => first e (by simpa using member)
      | yield value =>
          refine mono (ih fun item value member => each item value (List.mem_cons_of_mem _ member))
            fun _ later rest e member => ?_
          rcases List.mem_append.mp member with old | new
          · exact first e old
          · exact rest e new

/-- A fold that keeps `I` of its accumulator and everything sent so far. -/
private theorem foldlM' {I : α -> List (Envelope Node Message) -> Prop}
    {f : α -> γ -> Effect Node Message Notification α}
    (step
      : forall value sent item,
          I value sent -> Sends (fun next later => I next (sent ++ later)) (f value item))
    : forall (items : List γ) (init : α) (sent : List (Envelope Node Message)),
        I init sent
        -> Sends (fun result later => I result (sent ++ later)) (items.foldlM f init)
  | [], _, _, holds => by simpa using pure' (P := fun result later => I result (_ ++ later)) (by simpa using holds)
  | item :: items, init, sent, holds => by
      simp only [List.foldlM_cons]
      refine bind' (step init sent item holds) fun value later kept => ?_
      refine mono (foldlM' step items value (sent ++ later) kept) fun _ rest done => ?_
      simpa [List.append_assoc] using done

end Consensus.Proofs.Safety.Sends

namespace Consensus.Proofs.Safety

set_option linter.unusedSectionVars false
open Consensus.Proofs.Config
open CCF CCF.MultiNodeTransitionSystem Concrete Direct
open Model.Node
variable [Config.InitialConfiguration]

private theorem exec_of_reachable {nodes : List NodeID} {state : Model.State}
    (reachable
      : (Model.transitionSystem Config.INITIAL_CONFIGURATION nodes).Reachable state)
    : exists history, Exec nodes (state :: history) := by
  induction reachable
    using @TransitionSystem.Reachable.rec
      (Model.transitionSystem Config.INITIAL_CONFIGURATION nodes) with
  | initial initialized => exact ⟨[], .initial initialized⟩
  | step _ stepped ih =>
      obtain ⟨history, prior⟩ := ih
      exact ⟨_, .step prior stepped⟩

private theorem Exec.reachable {nodes : List NodeID} {state : Model.State}
    {history : List Model.State} (exec : Exec nodes (state :: history))
    : (Model.transitionSystem Config.INITIAL_CONFIGURATION nodes).Reachable state := by
  generalize equal : state :: history = states at exec
  induction exec generalizing state history with
  | initial initialized =>
      cases equal
      exact .initial initialized
  | step prior stepped ih =>
      cases equal
      exact .step (ih rfl) stepped

/-- Every nonempty suffix of an execution is an execution. -/
private theorem Exec.suffix {nodes : List NodeID} {history : List Model.State}
    (exec : Exec nodes history) {earlier : List Model.State}
    (suffix : earlier <:+ history) (nonempty : Not (earlier = []))
    : Exec nodes earlier := by
  induction exec with
  | initial initialized =>
      rcases List.suffix_cons_iff.mp suffix with same | inner
      · rw [same]
        exact .initial initialized
      · exact absurd (List.eq_nil_of_suffix_nil inner) nonempty
  | step prior stepped ih =>
      rcases List.suffix_cons_iff.mp suffix with same | inner
      · rw [same]
        exact .step prior stepped
      · exact ih inner

private theorem Exec.keys {nodes : List NodeID} {history : List Model.State}
    (exec : Exec nodes history) {state : Model.State} (member : state ∈ history)
    : (state.nodes.map Prod.fst).Nodup := by
  obtain ⟨front, back, split⟩ := List.append_of_mem member
  have tail : Exec nodes (state :: back) :=
    exec.suffix ⟨front, split.symm⟩ (by simp)
  exact keys_nodup tail.reachable

private theorem mem_removeOne {α : Type} [BEq α] {value item : α} {items : List α}
    (member : item ∈ removeOne value items)
    : item ∈ items := by
  induction items with
  | nil => simp [removeOne] at member
  | cons head tail ih =>
      simp only [removeOne] at member
      split at member
      · exact List.mem_cons_of_mem _ member
      · rcases List.mem_cons.mp member with rfl | later
        · exact List.mem_cons_self
        · exact List.mem_cons_of_mem _ (ih later)

private theorem LocalTransition.ofStep {nodes : List NodeID} {before after : Model.State}
    {action : Model.Action}
    (stepped
      : (Model.transitionSystem Config.INITIAL_CONFIGURATION nodes).step before action
        = some after)
    : Nonempty (LocalTransition before after) := by
  cases action with
  | «local» actor input =>
      have available : forall entries, input = .initAsBackup entries
          -> Model.committedPrefixOf before entries = true := by
        intro entries rfl
        refine Decidable.by_contra fun absent => ?_
        simp [Model.transitionSystem, Model.networkStep, absent] at stepped
      obtain ⟨pre, post, outputs, found, ran, rfl⟩ := step_local stepped
      exact ⟨{
              actor,
              pre,
              post,
              event := .internal input,
              outputs,
              pending := before.network
              found
              ran := by cases input <;> exact ran
              nodesEq := rfl
              networkEq := rfl
              pendingSub := fun _ member => member
              source := Or.inl ⟨input, rfl, rfl⟩
              available := fun entries eq => available entries (Event.internal.inj eq)
            }⟩
  | deliver envelope =>
      obtain ⟨queued, pre, post, outputs, found, ran, rfl⟩ := step_deliver stepped
      exact ⟨{
        actor := envelope.target, pre, post
        event := .receive envelope.source envelope.payload, outputs
        pending := removeOne envelope before.network
        found, ran
        nodesEq := rfl
        networkEq := rfl
        pendingSub := fun _ member => mem_removeOne member
        source := Or.inr ⟨envelope, queued, rfl, rfl, rfl⟩
        available := fun _ eq => by cases eq
      }⟩

private theorem LocalTransition.mem_after {before after : Model.State}
    (transition : LocalTransition before after) {node : NodeID}
    {state : NodeState} (member : (node, state) ∈ after.nodes)
    : (node = transition.actor /\ state = transition.post)
      \/ (Not (node = transition.actor) /\ (node, state) ∈ before.nodes) := by
  rw [transition.nodesEq] at member
  exact mem_replaceNode member

private theorem LocalTransition.pre_mem {before after : Model.State}
    (transition : LocalTransition before after)
    : (transition.actor, transition.pre) ∈ before.nodes :=
  mem_of_nodeState transition.found

private theorem LocalTransition.post_mem {before after : Model.State}
    (transition : LocalTransition before after)
    : (transition.actor, transition.post) ∈ after.nodes := by
  rw [transition.nodesEq]
  simp only [replaceNode, List.mem_map]
  exact ⟨_, transition.pre_mem, by simp⟩

private theorem LocalTransition.mem_network {before after : Model.State}
    (transition : LocalTransition before after) {envelope : Model.Envelope}
    (member : envelope ∈ after.network)
    : envelope ∈ before.network \/ envelope ∈ transition.outputs.outgoing := by
  rw [transition.networkEq] at member
  rcases List.mem_append.mp member with old | new
  · exact Or.inl (transition.pendingSub _ old)
  · exact Or.inr new

/-- Two entries of one reachable state for the same node agree. -/
private theorem state_unique {state : Model.State}
    (distinct : (state.nodes.map Prod.fst).Nodup) {node : NodeID}
    {first second : NodeState} (left : (node, first) ∈ state.nodes)
    (right : (node, second) ∈ state.nodes)
    : first = second := by
  have := (nodeState_of_mem distinct left).symm.trans (nodeState_of_mem distinct right)
  exact Option.some.inj this

end Consensus.Proofs.Safety

namespace Consensus.Proofs.Safety

set_option linter.unusedSectionVars false
open CCF (Finset)
open Model.Node

private theorem take_eq_of_prefix {α : Type} {small large : List α} {n : Nat}
    (sub : small <+: large) (bound : n <= small.length)
    : large.take n = small.take n := by
  obtain ⟨rest, rfl⟩ := sub
  rw [List.take_append_of_le_length bound]

private theorem take_prefix_take {α : Type} (list : List α) {m n : Nat} (le : m <= n)
    : list.take m <+: list.take n := by
  have := List.take_prefix m (list.take n)
  rwa [List.take_take, Nat.min_eq_left le] at this

private theorem comparable_of_prefix {α : Type} {left right common : List α}
    (leftSub : left <+: common) (rightSub : right <+: common)
    : left <+: right \/ right <+: left :=
  List.prefix_or_prefix_of_prefix leftSub rightSub

private theorem take_eq_take_of_comparable {α : Type} {left right : List α} {n : Nat}
    (comparable : left <+: right \/ right <+: left)
    (leftBound : n <= left.length) (rightBound : n <= right.length)
    : left.take n = right.take n := by
  rcases comparable with sub | sub
  · exact (take_eq_of_prefix sub leftBound).symm
  · exact take_eq_of_prefix sub rightBound

private theorem termAt_eq {log : List Entry} {index : Nat} (positive : 0 < index)
    (bound : index <= log.length)
    : termAt log index = log[index - 1].term := by
  simp [termAt, entryAt?, Nat.pos_iff_ne_zero.mp positive,
    List.getElem?_eq_getElem (Nat.lt_of_lt_of_le (Nat.sub_one_lt (Nat.ne_of_gt positive)) bound)]

private theorem termAt_zero (log : List Entry) : termAt log 0 = 0 := by
  simp [termAt, entryAt?]

private theorem termAt_take {log : List Entry} {index n : Nat} (le : index <= n)
    : termAt (log.take n) index = termAt log index := by
  unfold termAt entryAt?
  split
  · rfl
  · rename_i nonzero
    rw [List.getElem?_take_of_lt (Nat.lt_of_lt_of_le (Nat.sub_one_lt nonzero) le)]

private theorem termAt_of_prefix {small large : List Entry} {index : Nat}
    (sub : small <+: large) (bound : index <= small.length)
    : termAt large index = termAt small index := by
  rw [List.prefix_iff_eq_take.mp sub, termAt_take bound]

private theorem firstTermConflictIndex_eq (state : NodeState)
    (request : AppendEntriesRequest)
    : firstTermConflictIndex state request = conflictIndex state.log request :=
  rfl

/--
The accepted log is the sender's prefix up to the end of the batch, followed by
the follower's own suffix exactly when the follower already agreed with that
prefix. `aligned` is log matching between the two logs.
-/
private theorem acceptLog_eq {follower sender : List Entry}
    {request : AppendEntriesRequest}
    (prevBound : request.prevLogIndex <= follower.length)
    (prevSender : request.prevLogIndex <= sender.length)
    (prevAgree : follower.take request.prevLogIndex = sender.take request.prevLogIndex)
    (entries : request.entries <+: sender.drop request.prevLogIndex)
    (aligned
      : forall j,
          0 < j
          -> j <= follower.length
          -> j <= sender.length
          -> termAt follower j = termAt sender j
          -> follower.take j = sender.take j)
    : acceptLog follower request
      = sender.take (request.prevLogIndex + request.entries.length)
        ++ (if follower.take (request.prevLogIndex + request.entries.length)
                = sender.take (request.prevLogIndex + request.entries.length) then
              follower.drop (request.prevLogIndex + request.entries.length)
            else
              []) := by
  obtain ⟨term, prev, prevTerm, batch, primaryCommit⟩ := request
  simp only at prevBound prevSender prevAgree entries ⊢
  have batchEq : batch = (sender.drop prev).take batch.length :=
    List.prefix_iff_eq_take.mp entries
  have batchBound : prev + batch.length <= sender.length := by
    exact Nat.add_le_of_le_sub' prevSender
      (Nat.le_trans entries.length_le (Nat.le_of_eq List.length_drop))
  have senderTake : sender.take (prev + batch.length) = sender.take prev ++ batch := by
    rw [List.take_add, ← batchEq]
  unfold acceptLog
  simp only
  split
  · -- A conflicting term: the follower keeps only the agreeing prefix.
    rename_i index conflict
    unfold conflictIndex at conflict
    obtain ⟨pair, found, indexEq⟩ := Option.map_eq_some_iff.mp conflict
    obtain ⟨different, offset, lt, pairEq, before⟩ :=
      List.find?_eq_some_iff_getElem.mp found
    simp only [List.length_zipIdx, List.length_zip, List.length_drop] at lt
    rw [List.getElem_zipIdx] at pairEq
    subst pairEq indexEq
    simp only [List.getElem_zip, List.getElem_drop, bne_iff_ne, ne_eq] at different
    have offFollower : prev + offset < follower.length :=
      Nat.add_lt_of_lt_sub' (Nat.lt_of_lt_of_le lt (Nat.min_le_left _ _))
    have offBatch : offset < batch.length := Nat.lt_of_lt_of_le lt (Nat.min_le_right _ _)
    have offSender : prev + offset < sender.length :=
      Nat.lt_of_lt_of_le (Nat.add_lt_add_left offBatch prev) batchBound
    have prefixTerms : forall j (jLt : j < offset),
        (follower[prev + j]'(Nat.lt_trans (Nat.add_lt_add_left jLt prev) offFollower)).term
          = (sender[prev + j]'(Nat.lt_trans (Nat.add_lt_add_left jLt prev) offSender)).term := by
      intro j jLt
      have := before j jLt
      simp only [List.getElem_zipIdx, List.getElem_zip, List.getElem_drop,
        Bool.not_eq_true', bne_eq_false_iff_eq] at this
      rw [this]
      congr 1
      rw [List.getElem_of_eq batchEq]
      simp
    have keptEq : prev + 1 + offset - 1 = prev + offset := by
      rw [Nat.add_right_comm, Nat.add_sub_cancel]
    simp only [keptEq]
    have keptAgree : follower.take (prev + offset) = sender.take (prev + offset) := by
      rcases Nat.eq_zero_or_pos offset with zero | positive
      · simp only [zero, Nat.add_zero]
        exact prevAgree
      · have pos : 0 < prev + offset := Nat.lt_of_lt_of_le positive (Nat.le_add_left _ _)
        apply aligned _ pos (Nat.le_of_lt offFollower) (Nat.le_of_lt offSender)
        rw [termAt_eq pos (Nat.le_of_lt offFollower), termAt_eq pos (Nat.le_of_lt offSender)]
        have := prefixTerms (offset - 1) (Nat.sub_lt positive Nat.one_pos)
        simpa only [(Nat.add_sub_assoc positive prev).symm] using this
    have takeLength : (follower.take (prev + offset)).length = prev + offset := by
      rw [List.length_take, Nat.min_eq_left (Nat.le_of_lt offFollower)]
    have senderOffset : sender.take (prev + offset) = sender.take prev ++ batch.take offset := by
      rw [List.take_add]
      congr 1
      conv => rhs; rw [batchEq]
      rw [List.take_take, Nat.min_eq_left (Nat.le_of_lt offBatch)]
    rw [takeLength, Nat.add_sub_cancel_left, keptAgree, senderOffset,
      List.append_assoc, List.take_append_drop, ← senderTake]
    have differ : Not (follower.take (prev + batch.length) = sender.take (prev + batch.length)) := by
      intro same
      have := congrArg (fun list => list[prev + offset]?) same
      have inBatch := Nat.add_lt_add_left offBatch prev
      rw [List.getElem?_take_of_lt inBatch, List.getElem?_take_of_lt inBatch,
        List.getElem?_eq_getElem offFollower, List.getElem?_eq_getElem offSender] at this
      have entryEq := Option.some.inj this
      have senderEntry : sender[prev + offset]'offSender = batch[offset] := by
        rw [List.getElem_of_eq batchEq]
        simp
      rw [entryEq, senderEntry] at different
      exact different rfl
    simp [differ]
  · -- No conflicting term: the overlap agrees, so the follower log is extended.
    rename_i noConflict
    unfold conflictIndex at noConflict
    have notFound := Option.map_eq_none_iff.mp noConflict
    have overlapTerms : forall offset (lt : offset < batch.length)
        (inFollower : prev + offset < follower.length),
        follower[prev + offset].term
          = (sender[prev + offset]'
              (Nat.lt_of_lt_of_le (Nat.add_lt_add_left lt prev) batchBound)).term := by
      intro offset lt inFollower
      have member : ((follower[prev + offset], batch[offset]), prev + 1 + offset)
          ∈ ((follower.drop prev).zip batch).zipIdx (prev + 1) := by
        apply List.mem_iff_getElem.mpr
        refine ⟨offset, ?_, ?_⟩
        · simp only [List.length_zipIdx, List.length_zip, List.length_drop]
          exact Nat.lt_min.mpr ⟨Nat.lt_sub_iff_add_lt'.mpr inFollower, lt⟩
        simp
      have := List.find?_eq_none.mp notFound _ member
      simp only [Bool.not_eq_true, bne_eq_false_iff_eq] at this
      rw [this]
      congr 1
      rw [List.getElem_of_eq batchEq]
      simp
    by_cases long : prev + batch.length <= follower.length
    · have agree : follower.take (prev + batch.length) = sender.take (prev + batch.length) := by
        rcases Nat.eq_zero_or_pos batch.length with empty | nonempty
        · simp only [empty, Nat.add_zero]
          exact prevAgree
        · have pos : 0 < prev + batch.length := Nat.lt_of_lt_of_le nonempty (Nat.le_add_left _ _)
          have last := Nat.sub_lt nonempty Nat.one_pos
          apply aligned _ pos long batchBound
          rw [termAt_eq pos long, termAt_eq pos batchBound]
          have := overlapTerms (batch.length - 1) last
            (Nat.lt_of_lt_of_le (Nat.add_lt_add_left last prev) long)
          simpa only [(Nat.add_sub_assoc nonempty prev).symm] using this
      rw [ite_eq_left agree, ← agree, List.take_append_drop,
        List.drop_eq_nil_of_le (Nat.le_sub_of_add_le' long), List.append_nil]
    · have agree : follower = sender.take follower.length := by
        rcases Nat.eq_or_lt_of_le prevBound with same | ahead
        · rw [← same]
          have := prevAgree
          rwa [List.take_of_length_le (Nat.le_of_eq same.symm)] at this
        · have pos : 0 < follower.length := Nat.lt_of_le_of_lt (Nat.zero_le _) ahead
          have fs : follower.length <= sender.length :=
            Nat.le_of_lt (Nat.lt_of_lt_of_le (Nat.lt_of_not_le long) batchBound)
          have := aligned follower.length pos Nat.le.refl fs (by
            rw [termAt_eq pos Nat.le.refl, termAt_eq pos fs]
            have eq : prev + (follower.length - 1 - prev) = follower.length - 1 :=
              Nat.add_sub_of_le (Nat.le_sub_one_of_lt ahead)
            have lastLt : prev + (follower.length - 1 - prev) < follower.length := by
              rw [eq]
              exact Nat.sub_one_lt (Nat.ne_of_gt pos)
            have := overlapTerms (follower.length - 1 - prev)
              (Nat.lt_of_add_lt_add_left
                (Nat.lt_trans lastLt (Nat.lt_of_not_le long)))
              lastLt
            simpa only [eq] using this)
          rwa [List.take_of_length_le Nat.le.refl] at this
      have differ : Not (follower.take (prev + batch.length)
          = sender.take (prev + batch.length)) := by
        intro same
        have := congrArg List.length same
        simp only [List.length_take] at this
        rw [Nat.min_eq_right (Nat.le_of_lt (Nat.lt_of_not_le long)),
          Nat.min_eq_left batchBound] at this
        exact long (Nat.le_of_eq this.symm)
      rw [ite_eq_right differ, List.append_nil]
      have followerEq : follower = sender.take prev ++ batch.take (follower.length - prev) := by
        have viaTake : follower = (sender.take (prev + batch.length)).take follower.length := by
          rw [List.take_take, Nat.min_eq_left (Nat.le_of_lt (Nat.lt_of_not_le long))]
          exact agree
        rw [senderTake, List.take_append, List.length_take, Nat.min_eq_left prevSender,
          List.take_of_length_le (Nat.le_trans (List.length_take_le _ _) prevBound)] at viaTake
        exact viaTake
      rw (occs := .pos [1]) [followerEq]
      rw [List.append_assoc, List.take_append_drop, senderTake]

private theorem mem_history_filterMap {log : List Entry} {start : Nat}
    {configuration : Configuration}
    (member
      : configuration
        ∈ (log.zipIdx start).filterMap
            fun (entry, index) =>
              entry.content.metadata.configuration.map
                fun nodes => ({ index, nodes } : Configuration))
    : start <= configuration.index /\ configuration.index < start + log.length := by
  obtain ⟨⟨entry, index⟩, pairMember, configMember⟩ := List.mem_filterMap.mp member
  obtain ⟨nodes, _, rfl⟩ := Option.map_eq_some_iff.mp configMember
  have := List.mem_zipIdx pairMember
  simp only
  exact ⟨this.1, this.2.1⟩

/-- The configuration history of a log extends that of any of its prefixes by
configurations from later positions. -/
private theorem configurationHistory_split (log : List Entry) (k : Nat)
    : exists rest,
        configurationHistory log = configurationHistory (log.take k) ++ rest
        /\ forall configuration, configuration ∈ rest -> k < configuration.index := by
  have split : log = log.take k ++ log.drop k := (List.take_append_drop k log).symm
  refine ⟨((log.drop k).zipIdx (1 + (log.take k).length)).filterMap fun (entry, index) =>
      entry.content.metadata.configuration.map
        fun nodes => ({ index, nodes } : Configuration),
    ?_, ?_⟩
  · unfold configurationHistory
    conv => lhs; rw [split]
    rw [List.zipIdx_append, List.filterMap_append]
  · intro configuration member
    have := mem_history_filterMap member
    by_cases short : log.length <= k
    · simp [List.drop_eq_nil_of_le short] at member
    · simp at this
      rw [Nat.min_eq_left (Nat.le_of_lt (Nat.lt_of_not_le short))] at this
      exact Nat.le_trans (Nat.le_of_eq (Nat.add_comm k 1)) this.1

/-- A log with a configuration history is nonempty. -/
private theorem ne_nil_of_configurationHistory {log : List Entry}
    (nonempty : configurationHistory log ≠ [])
    : log ≠ [] := by
  rintro rfl
  exact nonempty rfl

/-- Active configurations are drawn from the configuration history. -/
private theorem activeConfigurations_sublist (log : List Entry) (commit : Nat)
    : (activeConfigurations log commit).Sublist (configurationHistory log) :=
  List.drop_sublist _ _

/-- A log whose first entry is a configuration has a configuration history. -/
private theorem configurationHistory_ne_nil {log : List Entry} {root : Entry}
    (head : log.take 1 = [root]) (configured : root.content.metadata.configuration.isSome)
    : configurationHistory log ≠ [] := by
  obtain ⟨rest, eq, _⟩ := configurationHistory_split log 1
  rw [eq, head]
  obtain ⟨nodes, some⟩ := Option.isSome_iff_exists.mp configured
  simp [configurationHistory, some]

private theorem filter_index_append {front rest : List Configuration} {bound k : Nat}
    (le : bound <= k)
    (later : forall configuration, configuration ∈ rest -> k < configuration.index)
    : ((front ++ rest).filter fun configuration => configuration.index <= bound)
      = front.filter fun configuration => configuration.index <= bound := by
  have empty : (rest.filter fun configuration => configuration.index <= bound) = [] := by
    apply List.filter_eq_nil_iff.mpr
    intro configuration member
    have := later configuration member
    simp
    exact Nat.lt_of_le_of_lt le this
  rw [List.filter_append, empty, List.append_nil]

private theorem length_filter_index_mono (configurations : List Configuration)
    {small large : Nat} (le : small <= large)
    : (configurations.filter fun configuration => configuration.index <= small).length
      <= (configurations.filter
            fun configuration => configuration.index <= large).length := by
  simp only [← List.countP_eq_length_filter]
  apply List.countP_mono_left
  intro configuration _ holds
  simp at holds ⊢
  exact Nat.le_trans holds le

private theorem length_filter_le (configurations : List Configuration) (bound : Nat)
    : (configurations.filter fun configuration => configuration.index <= bound).length
      <= configurations.length :=
  List.length_filter_le _ _

private theorem zipIdx_sorted {α : Type} (log : List α) (start : Nat)
    : (log.zipIdx start).Pairwise fun first second => first.2 < second.2 := by
  induction log generalizing start with
  | nil => simp
  | cons head tail ih =>
      rw [List.zipIdx_cons, List.pairwise_cons]
      refine ⟨fun pair member => ?_, ih (start + 1)⟩
      have := List.mem_zipIdx member
      exact this.1

/-- Configuration histories are ordered by index. -/
private theorem configurationHistory_sorted (log : List Entry)
    : (configurationHistory log).Pairwise
        fun first second => first.index < second.index := by
  unfold configurationHistory
  refine List.Pairwise.filterMap _ (fun first second lt left leftMem right rightMem => ?_)
    (zipIdx_sorted log 1)
  obtain ⟨_, _, rfl⟩ := Option.map_eq_some_iff.mp leftMem
  obtain ⟨_, _, rfl⟩ := Option.map_eq_some_iff.mp rightMem
  exact lt

/-- In an index-sorted list, the positions counted by an index bound hold
configurations within it. -/
private theorem getElem_le_of_lt_length_filter {configurations : List Configuration}
    (sorted : configurations.Pairwise fun first second => first.index < second.index)
    {bound i : Nat}
    (lt
      : i
        < (configurations.filter
            fun configuration => configuration.index <= bound).length)
    : (configurations[i]'(Nat.lt_of_lt_of_le lt (List.length_filter_le _ _))).index
      <= bound := by
  induction configurations generalizing i with
  | nil => simp at lt
  | cons head tail ih =>
      rw [List.pairwise_cons] at sorted
      by_cases within : head.index <= bound
      · rw [List.filter_cons_of_pos (by simpa using within)] at lt
        rcases i with _ | i
        · exact within
        · exact ih sorted.2 (by simpa using lt)
      · have empty : (tail.filter fun configuration => configuration.index <= bound) = [] := by
          refine List.filter_eq_nil_iff.mpr fun configuration member => ?_
          have := sorted.1 configuration member
          simp
          exact Nat.lt_trans (Nat.lt_of_not_le within) this
        rw [List.filter_cons_of_neg (by simpa using within), empty] at lt
        simp at lt

/-- The configuration chosen by an index bound is within it, or is the first. -/
private theorem chosen_bound {configurations : List Configuration}
    (sorted : configurations.Pairwise fun first second => first.index < second.index)
    (bound : Nat) (positive : 0 < configurations.length)
    : let chosen :=
        configurations[
          (configurations.filter fun configuration => configuration.index <= bound).length
          - 1
          ]'(by
              have :=
                List.length_filter_le
                  (fun configuration : Configuration =>
                    decide (configuration.index <= bound))
                  configurations
              omega)
      chosen.index <= bound
      \/ forall other, other ∈ configurations -> chosen.index <= other.index := by
  intro chosen
  by_cases counted : 0 < (configurations.filter
      fun configuration => configuration.index <= bound).length
  · exact Or.inl (getElem_le_of_lt_length_filter sorted (Nat.sub_one_lt (Nat.ne_of_gt counted)))
  · refine Or.inr fun other member => ?_
    rcases configurations with _ | ⟨head, tail⟩
    · simp at positive
    · simp only [chosen, Nat.eq_zero_of_not_pos counted, Nat.zero_sub, List.getElem_cons_zero]
      rcases List.mem_cons.mp member with rfl | later
      · exact Nat.le.refl
      · exact Nat.le_of_lt ((List.pairwise_cons.mp sorted).1 other later)

/--
Two logs agreeing up to `k`, with commit indices at most `k` and a configuration
among their first `k` entries, share an active configuration: the last one
committed by the larger commit index, or the first one if neither commits one.
-/
private theorem activeConfigurations_overlap {left right : List Entry}
    {leftCommit rightCommit k : Nat}
    (agree : left.take k = right.take k) (leftLe : leftCommit <= k)
    (rightLe : rightCommit <= k) (configured : configurationHistory (right.take k) ≠ [])
    : exists configuration,
        configuration ∈ activeConfigurations left leftCommit
        /\ configuration ∈ activeConfigurations right rightCommit
        /\ (configuration.index <= max leftCommit rightCommit
            \/ forall other,
                other ∈ configurationHistory (right.take k)
                -> configuration.index <= other.index) := by
  obtain ⟨leftRest, leftEq, leftLater⟩ := configurationHistory_split left k
  obtain ⟨rightRest, rightEq, rightLater⟩ := configurationHistory_split right k
  rw [agree] at leftEq
  have sorted := configurationHistory_sorted (right.take k)
  generalize configurationHistory (right.take k) = common at leftEq rightEq configured sorted ⊢
  have commonPos : 0 < common.length := List.length_pos_iff.mpr configured
  have count : forall {log : List Entry} {rest commit},
      configurationHistory log = common ++ rest
      -> (forall configuration, configuration ∈ rest -> k < configuration.index)
      -> commit <= k
      -> ((configurationHistory log).filter
            fun configuration => configuration.index <= commit)
          = common.filter fun configuration => configuration.index <= commit := by
    intro log rest commit eq later le
    rw [eq]
    exact filter_index_append le later
  have inDrop : forall {log : List Entry} {rest} {m p : Nat}
      (lt : p < common.length),
      configurationHistory log = common ++ rest -> m <= p
      -> common[p] ∈ (configurationHistory log).drop m := by
    intro log rest m p lt eq le
    rw [eq, List.mem_iff_getElem]
    refine ⟨p - m, ?_, ?_⟩
    · rw [List.length_drop, List.length_append]
      exact Nat.sub_lt_sub_right le (Nat.lt_of_lt_of_le lt (Nat.le_add_right _ _))
    simp only [List.getElem_drop]
    rw [List.getElem_append_left (Nat.lt_of_le_of_lt (Nat.le_of_eq (Nat.add_sub_of_le le)) lt)]
    congr 1
    exact Nat.add_sub_of_le le
  unfold activeConfigurations
  simp only
  rw [count leftEq leftLater leftLe, count rightEq rightLater rightLe]
  have leftBound := length_filter_le common leftCommit
  have rightBound := length_filter_le common rightCommit
  have last : common.length - 1 < common.length := Nat.sub_one_lt (Nat.ne_of_gt commonPos)
  rcases Nat.le_total leftCommit rightCommit with ordered | ordered
  · have mono := length_filter_index_mono common ordered
    have chosenLt := Nat.lt_of_le_of_lt (Nat.sub_le_sub_right rightBound 1) last
    refine ⟨common[_ - 1]'chosenLt, inDrop chosenLt leftEq (Nat.sub_le_sub_right mono 1),
      inDrop chosenLt rightEq Nat.le.refl, ?_⟩
    rcases chosen_bound sorted rightCommit commonPos with within | first
    · exact Or.inl (Nat.le_trans within (Nat.le_max_right _ _))
    · exact Or.inr first
  · have mono := length_filter_index_mono common ordered
    have chosenLt := Nat.lt_of_le_of_lt (Nat.sub_le_sub_right leftBound 1) last
    refine ⟨common[_ - 1]'chosenLt, inDrop chosenLt leftEq Nat.le.refl,
      inDrop chosenLt rightEq (Nat.sub_le_sub_right mono 1), ?_⟩
    rcases chosen_bound sorted leftCommit commonPos with within | first
    · exact Or.inl (Nat.le_trans within (Nat.le_max_left _ _))
    · exact Or.inr first

/-- Two strict majorities of one configuration share a member. -/
private theorem majorities_intersect {configuration : Configuration}
    {left right : Finset NodeID}
    (leftMajority : hasConfigurationMajority left configuration)
    (rightMajority : hasConfigurationMajority right configuration)
    : exists node, node ∈ left /\ node ∈ right := by
  unfold hasConfigurationMajority at leftMajority rightMajority
  obtain ⟨node, member⟩ := Finset.inter_nonempty_of_card_lt_card_add_card
    (show left ∩ configuration.nodes ⊆ configuration.nodes from Finset.inter_subset_right)
    (show right ∩ configuration.nodes ⊆ configuration.nodes from Finset.inter_subset_right)
    (by
      apply Nat.lt_of_mul_lt_mul_right (a := 2)
      rw [Nat.add_mul, Nat.mul_two]
      exact Nat.add_lt_add leftMajority rightMajority)
  simp only [Finset.mem_inter] at member
  exact ⟨node, member.1.1, member.2.1⟩

private theorem hasQuorum_majority {configurations : List Configuration}
    {voters : Finset NodeID} (quorum : hasQuorum configurations voters)
    {configuration : Configuration} (member : configuration ∈ configurations)
    : hasConfigurationMajority voters configuration := by
  have := List.all_eq_true.mp quorum.2 configuration member
  simpa using this

private theorem Rooted.prefix {root : Entry} {small large : List Entry}
    (rooted : Rooted root large) (sub : small <+: large)
    : Rooted root small := by
  rcases small with _ | ⟨first, rest⟩
  · exact Or.inl rfl
  · refine Or.inr ?_
    obtain ⟨suffix, rfl⟩ := sub
    rcases rooted with empty | head
    · simp at empty
    · simpa using head

private theorem Rooted.take {root : Entry} {log : List Entry} (rooted : Rooted root log)
    (n : Nat)
    : Rooted root (log.take n) :=
  rooted.prefix (List.take_prefix n log)

private theorem Rooted.append {root : Entry} {log : List Entry} (rooted : Rooted root log)
    (nonempty : log ≠ []) (entries : List Entry)
    : Rooted root (log ++ entries) := by
  rcases rooted with empty | head
  · exact absurd empty nonempty
  · refine Or.inr ?_
    have := List.length_pos_iff.mpr nonempty
    rw [List.take_append_of_le_length (Nat.succ_le_of_lt this), head]

private theorem Rooted.head {root : Entry} {log : List Entry} (rooted : Rooted root log)
    (nonempty : log ≠ [])
    : log.take 1 = [root] := by
  rcases rooted with empty | head
  · exact absurd empty nonempty
  · exact head

private theorem hasQuorum_nonempty {log : List Entry} {commit : Nat}
    {voters : Finset NodeID} (quorum : hasQuorum (activeConfigurations log commit) voters)
    : log ≠ [] := by
  apply ne_nil_of_configurationHistory
  intro empty
  apply quorum.1
  have := activeConfigurations_sublist log commit
  rw [empty] at this
  exact List.sublist_nil.mp this

/-- Two nonempty rooted logs agreeing on both committed prefixes share an active
configuration within both commit indices or at the root's index; a
configuration-bearing root supplies it. -/
private theorem rooted_overlap {root : Entry}
    (configured : root.content.metadata.configuration.isSome)
    {left right : List Entry} {leftCommit rightCommit k : Nat}
    (leftRooted : Rooted root left) (rightRooted : Rooted root right)
    (leftNonempty : left ≠ []) (rightNonempty : right ≠ [])
    (agree : left.take k = right.take k) (leftLe : leftCommit <= k)
    (rightLe : rightCommit <= k)
    : exists configuration,
        configuration ∈ activeConfigurations left leftCommit
        /\ configuration ∈ activeConfigurations right rightCommit
        /\ configuration.index <= max (max leftCommit rightCommit) 1 := by
  have leftHead := leftRooted.head leftNonempty
  have rightHead := rightRooted.head rightNonempty
  have agree' : left.take (max k 1) = right.take (max k 1) := by
    rcases Nat.eq_zero_or_pos k with zero | positive
    · subst zero
      simp [leftHead, rightHead]
    · rwa [Nat.max_eq_left positive]
  have rooted : (right.take (max k 1)).take 1 = [root] := by
    rw [List.take_take, Nat.min_eq_left (Nat.le_max_right _ _), rightHead]
  obtain ⟨configuration, leftMember, rightMember, bound⟩ :=
    activeConfigurations_overlap agree' (Nat.le_trans leftLe (Nat.le_max_left _ _))
      (Nat.le_trans rightLe (Nat.le_max_left _ _))
      (configurationHistory_ne_nil rooted configured)
  refine ⟨configuration, leftMember, rightMember, ?_⟩
  rcases bound with within | first
  · exact Nat.le_trans within (Nat.le_max_left _ _)
  · obtain ⟨rest, eq, _⟩ := configurationHistory_split (right.take (max k 1)) 1
    obtain ⟨nodes, some⟩ := Option.isSome_iff_exists.mp configured
    have genesis : ({ index := 1, nodes } : Configuration)
        ∈ configurationHistory (right.take (max k 1)) := by
      rw [eq, rooted]
      simp [configurationHistory, some]
    exact Nat.le_trans (first _ genesis) (Nat.le_max_right _ _)

/-- Quorums for two rooted logs agreeing on both committed prefixes share a
voter; a configuration-bearing root supplies a common configuration. -/
private theorem quorums_intersect {root : Entry}
    (configured : root.content.metadata.configuration.isSome)
    {left right : List Entry} {leftCommit rightCommit k : Nat}
    (leftRooted : Rooted root left) (rightRooted : Rooted root right)
    (agree : left.take k = right.take k) (leftLe : leftCommit <= k)
    (rightLe : rightCommit <= k) {leftVoters rightVoters : Finset NodeID}
    (leftQuorum : hasQuorum (activeConfigurations left leftCommit) leftVoters)
    (rightQuorum : hasQuorum (activeConfigurations right rightCommit) rightVoters)
    : exists node, node ∈ leftVoters /\ node ∈ rightVoters := by
  obtain ⟨configuration, leftMember, rightMember, _⟩ :=
    rooted_overlap configured leftRooted rightRooted (hasQuorum_nonempty leftQuorum)
      (hasQuorum_nonempty rightQuorum) agree leftLe rightLe
  exact majorities_intersect (hasQuorum_majority leftQuorum leftMember)
    (hasQuorum_majority rightQuorum rightMember)

/-- As `quorums_intersect`, with the left quorum taken over the active
configurations no later than a positive `bound` covering both commit indices. -/
private theorem quorums_intersect_bounded {root : Entry}
    (configured : root.content.metadata.configuration.isSome)
    {left right : List Entry} {leftCommit rightCommit k bound : Nat}
    (leftRooted : Rooted root left) (rightRooted : Rooted root right)
    (agree : left.take k = right.take k) (leftLe : leftCommit <= k)
    (rightLe : rightCommit <= k) (leftBound : leftCommit <= bound)
    (rightBound : rightCommit <= bound) (positive : 0 < bound)
    {leftVoters rightVoters : Finset NodeID}
    (leftQuorum
      : hasQuorum
          ((activeConfigurations left leftCommit).filter
            fun configuration => configuration.index <= bound)
          leftVoters)
    (rightQuorum : hasQuorum (activeConfigurations right rightCommit) rightVoters)
    : exists node, node ∈ leftVoters /\ node ∈ rightVoters := by
  have leftNonempty : left ≠ [] := by
    apply ne_nil_of_configurationHistory
    intro empty
    apply leftQuorum.1
    have := activeConfigurations_sublist left leftCommit
    rw [empty] at this
    rw [List.sublist_nil.mp this, List.filter_nil]
  obtain ⟨configuration, leftMember, rightMember, within⟩ :=
    rooted_overlap configured leftRooted rightRooted leftNonempty
      (hasQuorum_nonempty rightQuorum) agree leftLe rightLe
  have filtered : configuration
      ∈ (activeConfigurations left leftCommit).filter
          fun configuration => configuration.index <= bound := by
    refine List.mem_filter.mpr ⟨leftMember, ?_⟩
    simp only [decide_eq_true_eq]
    exact Nat.le_trans within (Nat.max_le.mpr ⟨Nat.max_le.mpr ⟨leftBound, rightBound⟩, positive⟩)
  exact majorities_intersect (hasQuorum_majority leftQuorum filtered)
    (hasQuorum_majority rightQuorum rightMember)

end Consensus.Proofs.Safety

namespace Consensus.Proofs.Direct

set_option linter.unusedSectionVars false
open Consensus.Proofs.Config
open CCF
open Model.Node
open Ledger (
  isSignatureAt_of_prefix isSignatureAt_take_of_le signatureIndex_le_maxCommittableIndex
    maxCommittableIndexUpTo_le_length maxCommittableIndexUpToPositiveIsSignature
  )

private theorem CommitFrontier.of_log {state after : NodeState}
    (frontier : CommitFrontier state) (logEq : after.log = state.log)
    (commitEq : after.commitIndex = state.commitIndex)
    : CommitFrontier after := by
  unfold CommitFrontier at *
  rw [logEq, commitEq]
  exact frontier

private theorem CommitFrontier.extend {state : NodeState}
    (frontier : CommitFrontier state) {log : List Entry}
    (extends_ : state.log <+: log)
    : CommitFrontier { state with log } := by
  refine ⟨Nat.le_trans frontier.1 extends_.length_le, fun positive => ?_⟩
  exact isSignatureAt_of_prefix extends_ (frontier.2 positive)

private theorem CommitFrontier.keep {state : NodeState}
    (frontier : CommitFrontier state) {count : Nat} (within : state.commitIndex <= count)
    {suffix : List Entry}
    : CommitFrontier { state with log := state.log.take count ++ suffix } := by
  refine ⟨?_, fun positive => ?_⟩
  · simp only [List.length_append, List.length_take]
    exact Nat.le_trans (Nat.le_min.mpr ⟨within, frontier.1⟩) (Nat.le_add_right _ _)
  · exact isSignatureAt_of_prefix (List.prefix_append _ _)
      (isSignatureAt_take_of_le within (frontier.2 positive))

/-- A new commit frontier chosen from the latest covered signature. -/
private theorem CommitFrontier.advance {state : NodeState}
    {log : List Entry} {bound : Nat}
    (extends_ : CommitFrontier { state with log })
    : CommitFrontier
        {
          state with
            log, commitIndex := max state.commitIndex (maxCommittableIndexUpTo log bound)
        } := by
  refine ⟨Nat.max_le.mpr ⟨extends_.1, maxCommittableIndexUpTo_le_length log bound⟩,
    fun positive => ?_⟩
  simp only at positive ⊢
  rcases Nat.le_total state.commitIndex (maxCommittableIndexUpTo log bound) with le | le
  · rw [Nat.max_eq_right le] at positive ⊢
    exact maxCommittableIndexUpToPositiveIsSignature positive
  · rw [Nat.max_eq_left le] at positive ⊢
    exact extends_.2 positive

/-- A fold that only moves its accumulator to elements satisfying `P` keeps any
property those moves keep. -/
private theorem foldl_select_step (P : Nat -> Nat -> Prop) [forall a b, Decidable (P a b)]
    (Q : Nat -> Prop) (values : List Nat) (init : Nat) (start : Q init)
    (step : forall acc value, value ∈ values -> Q acc -> P acc value -> Q value)
    : Q (values.foldl (fun acc value => if P acc value then value else acc) init) := by
  induction values generalizing init with
  | nil => exact start
  | cons head tail ih =>
      simp only [List.foldl_cons]
      refine ih _ ?_ fun acc value mem => step acc value (List.mem_cons_of_mem _ mem)
      split
      · exact step init head (List.mem_cons.mpr (Or.inl rfl)) start ‹_›
      · exact start

private theorem highestCommittableIndex_signature (state : NodeState) (self : NodeID)
    (ahead : state.commitIndex < highestCommittableIndex state self)
    : isSignatureAt state.log (highestCommittableIndex state self) = true := by
  have holds
      : highestCommittableIndex state self = state.commitIndex
        \/ isSignatureAt state.log (highestCommittableIndex state self) = true := by
    dsimp only [highestCommittableIndex]
    exact foldl_select_step _
      (fun index => index = state.commitIndex \/ isSignatureAt state.log index = true) _ _
      (Or.inl rfl) fun _ _ _ _ selected => Or.inr selected.2.1
  rcases holds with same | signature
  · rw [same] at ahead
    exact absurd ahead (Nat.lt_irrefl _)
  · exact signature

private theorem signature_le_length {log : List Entry} {index : Nat}
    (signature : isSignatureAt log index = true)
    : index <= log.length := by
  obtain ⟨entry, found, _⟩ := Ledger.isSignatureAtTrue signature
  exact Ledger.entryAtSomeIndexBound found

private theorem CommitFrontier.leaderAppendState {state : NodeState}
    (frontier : CommitFrontier state) (content : EntryContent)
    : CommitFrontier
        { state with log := state.log ++ [{ term := state.currentTerm, content }] } :=
  frontier.extend (List.prefix_append _ _)

end Consensus.Proofs.Direct

namespace Consensus.Proofs.Direct

set_option linter.unusedSectionVars false
open Consensus.Proofs.Config
open CCF
open Model.Node
open Ledger (
  isSignatureAt_of_prefix isSignatureAt_take_of_le signatureIndex_le_maxCommittableIndex
    maxCommittableIndexUpTo_le_length maxCommittableIndexUpToPositiveIsSignature
  )
section AppendEntries
variable {self : NodeID} {state : NodeState}
  {request : AppendEntriesRequest}

private theorem CommitFrontier.fromLeader (frontier : CommitFrontier state)
    : CommitFrontier (handleAppendEntiresFromPrimary self state request).1 := by
  obtain ⟨retired, role, known, eq, -⟩ :=
    Ledger.handleAppendEntiresFromPrimary_eq self state request
  rw [eq]
  exact (CommitFrontier.advance
          (bound :=
            min request.primaryCommit (request.prevLogIndex + request.entries.length))
          (frontier.extend (List.prefix_append _ _))).of_log
    rfl rfl

private theorem CommitFrontier.handleAppendEntriesRequest
    (frontier : CommitFrontier state) (caps : Caps) (source : NodeID)
    : Keeps CommitFrontier
        (Model.Node.handleAppendEntriesRequest caps self source state request) := by
  unfold Model.Node.handleAppendEntriesRequest
  have stepped : CommitFrontier (if request.term = state.currentTerm /\
      (state.role = .candidate \/ state.role = .preVoteCandidate) then
        becomeAwareOfNewTerm state request.term else state) := by
    split
    · exact frontier.of_log rfl rfl
    · exact frontier
  generalize (if request.term = state.currentTerm /\
      (state.role = .candidate \/ state.role = .preVoteCandidate) then
        becomeAwareOfNewTerm state request.term else state) = current
    at stepped
  refine Keeps.ite' (fun _ => by
    dsimp only
    split <;> exact Keeps.seq' fun _ => Keeps.pure' stepped) fun _ => ?_
  dsimp only
  refine Keeps.ite' (fun _ => Keeps.pure' (stepped.of_log rfl rfl)) fun notBefore => ?_
  have within : current.commitIndex <= request.prevLogIndex :=
    Nat.le_of_not_lt fun lt => notBefore (Or.inl lt)
  split
  · exact Keeps.seq' fun _ => Keeps.pure'
      (CommitFrontier.of_log stepped (after := { current with primaryKnown := true }) rfl
        rfl).fromLeader
  · rename_i index conflict
    have := Ledger.firstTermConflictIndex_ge conflict
    exact Keeps.seq' fun _ => Keeps.pure'
      (CommitFrontier.of_log (stepped.keep (count := index - 1)
        (Nat.le_trans within (Nat.le_sub_of_add_le this)) (suffix := []))
        (after :=
          {
            current with
              primaryKnown := true, log := current.log.take (index - 1), isNewFollower := false
          })
        (by simp) rfl).fromLeader

end AppendEntries
end Consensus.Proofs.Direct

namespace Consensus.Proofs.Direct

set_option linter.unusedSectionVars false
open Consensus.Proofs.Config
open CCF
open Model.Node
open Ledger (
  isSignatureAt_of_prefix isSignatureAt_take_of_le signatureIndex_le_maxCommittableIndex
    maxCommittableIndexUpTo_le_length maxCommittableIndexUpToPositiveIsSignature
  )

private theorem CommitFrontier.advanced {state : NodeState} (self : NodeID)
    (frontier : CommitFrontier state) (caps : Caps)
    : Keeps CommitFrontier (Model.Node.advanceCommit caps state self) := by
  unfold Model.Node.advanceCommit
  refine Keeps.ite' (fun _ => Keeps.pure' frontier) fun ahead => ?_
  have signature := highestCommittableIndex_signature state self (Nat.lt_of_not_le ahead)
  have advanced : CommitFrontier
      (state.recordCommit self (highestCommittableIndex state self)) :=
    ⟨by simpa using signature_le_length signature, fun _ => by simpa using signature⟩
  dsimp only
  exact Keeps.ite'
    (fun _ =>
      Keeps.ite' (fun _ => Keeps.seq' fun _ => Keeps.pure' advanced)
        fun _ => Keeps.pure' advanced)
    fun _ => Keeps.pure' advanced

private theorem CommitFrontier.withSent {state : NodeState}
    (frontier : CommitFrontier state) {sentIndex : NodeID -> Nat}
    : CommitFrontier { state with sentIndex } :=
  frontier.of_log rfl rfl

/-- The log a new leader keeps: its signed prefix, or everything at startup. -/
private theorem CommitFrontier.promotedLog {state : NodeState}
    (frontier : CommitFrontier state)
    : CommitFrontier
        {
          state with
            log :=
              if state.commitIndex > 0 then
                state.log.take (lastCommittableIndex state)
              else
                state.log
        } := by
  split
  · have kept := frontier.keep (count := lastCommittableIndex state)
      (by unfold lastCommittableIndex; exact Nat.le_max_left _ _) (suffix := [])
    exact kept.of_log (by simp) rfl
  · exact frontier.of_log rfl rfl

end Consensus.Proofs.Direct

namespace Consensus.Proofs.Direct

set_option linter.unusedSectionVars false
open Consensus.Proofs.Config
open CCF
open Model.Node
open Ledger (
  isSignatureAt_of_prefix isSignatureAt_take_of_le signatureIndex_le_maxCommittableIndex
    maxCommittableIndexUpTo_le_length maxCommittableIndexUpToPositiveIsSignature
  )
section Handlers
variable (caps : Caps) (self : NodeID)

private theorem CommitFrontier.appendEntry {state : NodeState}
    (frontier : CommitFrontier state) (content : EntryContent)
    : Keeps CommitFrontier (Model.Node.appendEntry caps self state content) := by
  unfold Model.Node.appendEntry
  simp only [pure_bind]
  repeat'
    first
    | exact Keeps.pure' ((frontier.leaderAppendState content).of_log rfl rfl)
    | refine Keeps.ite' (fun _ => ?_) fun _ => ?_
    | refine Keeps.seq' fun _ => ?_
    | split

private theorem CommitFrontier.becomePrimary {state : NodeState}
    (frontier : CommitFrontier state)
    : Keeps CommitFrontier (Model.Node.becomePrimary caps self state) := by
  unfold Model.Node.becomePrimary
  refine Keeps.bind' (CommitFrontier.advanced self ?_ caps) fun _ kept =>
      Keeps.seq' fun _ => Keeps.pure' kept
  unfold Model.Node.primaryState
  exact frontier.promotedLog.of_log rfl rfl

private theorem CommitFrontier.electIfQuorum {state : NodeState}
    (frontier : CommitFrontier state)
    : Keeps CommitFrontier (Model.Node.electIfQuorum caps self state) := by
  unfold Model.Node.electIfQuorum
  exact Keeps.ite' (fun _ => frontier.becomePrimary caps self) fun _ => Keeps.pure' frontier

private theorem CommitFrontier.becomeCandidate {state : NodeState}
    (frontier : CommitFrontier state)
    : Keeps CommitFrontier (Model.Node.becomeCandidate caps state self) := by
  unfold Model.Node.becomeCandidate
  refine Keeps.bind' (CommitFrontier.electIfQuorum caps self ?_) fun _ kept =>
    Keeps.seq' fun _ => Keeps.pure' kept
  exact frontier.of_log rfl rfl

private theorem CommitFrontier.becomePreVoteCandidate {state : NodeState}
    (frontier : CommitFrontier state)
    : Keeps CommitFrontier (Model.Node.becomePreVoteCandidate caps state self) := by
  unfold Model.Node.becomePreVoteCandidate
  refine Keeps.ite' (fun _ => CommitFrontier.becomeCandidate caps self ?_)
    fun _ => Keeps.seq' fun _ => Keeps.pure' ?_ <;> exact frontier.of_log rfl rfl

/-- Successor nomination only sends; on success it returns its input state. -/
private theorem Keeps.nominateSuccessor (state : NodeState)
    : Keeps (fun result => result = state)
        (Model.Node.nominateSuccessor caps state self) := by
  unfold Model.Node.nominateSuccessor
  refine Keeps.seq' fun _ => ?_
  split
  · exact Keeps.seq' fun _ => Keeps.pure' rfl
  · exact Keeps.pure' rfl

private theorem CommitFrontier.act {state : NodeState}
    (frontier : CommitFrontier state) (input : Input)
    : Keeps CommitFrontier (Model.Node.act caps self state input) := by
  cases input with
  | append entries =>
      unfold Model.Node.act Model.Node.appendBatch
      exact Keeps.seq' fun _ => Keeps.bind'
        (Keeps.foldlM' (fun current entry kept =>
          Keeps.bind' (kept.appendEntry caps self entry.content) fun appended frontier =>
            Keeps.foldlM'
              (fun current (destination, endIndex) kept => by
                unfold Model.Node.sendEntries
                exact Keeps.seq' fun _ => Keeps.seq' fun _ => Keeps.pure' kept.withSent)
              entry.flushes appended frontier)
          entries state frontier)
        fun _ kept => kept.advanced self caps
  | sendEntries destination endIndex =>
      unfold Model.Node.act Model.Node.sendEntries
      exact Keeps.seq' fun _ => Keeps.seq' fun _ => Keeps.pure' frontier.withSent
  | timeout kind =>
      cases kind with
      | election =>
          unfold Model.Node.act Model.Node.startElection
          exact Keeps.seq' fun _ => frontier.becomePreVoteCandidate caps self
      | checkQuorum =>
          unfold Model.Node.act Model.Node.checkQuorum
          exact Keeps.seq' fun _ => Keeps.pure' (frontier.of_log rfl rfl)
  | nominateSuccessor =>
      exact (Keeps.nominateSuccessor caps self state).mono fun _ same => same ▸ frontier
  | initAsBackup entries =>
      unfold Model.Node.act Model.Node.initAsBackup
      refine Keeps.bind' Keeps.guard'
        fun _ ⟨_, signed⟩ =>
          Keeps.pure' ⟨by simp [becomeAwareOfNewTerm], fun positive => ?_⟩
      rcases signed with empty | signature
      · subst empty
        simp [becomeAwareOfNewTerm] at positive
      · simpa [becomeAwareOfNewTerm] using signature

private theorem CommitFrontier.receive {state : NodeState}
    (frontier : CommitFrontier state) (source : NodeID) (message : Message)
    : Keeps CommitFrontier (Model.Node.receive caps self source state message) := by
  have observed : CommitFrontier (observeTerm state message) :=
    frontier.of_log (Concrete.observeTerm_log _ _) (Concrete.observeTerm_commitIndex _ _)
  unfold Model.Node.receive
  refine Keeps.ite' (fun _ => Keeps.pure' frontier) fun _ => ?_
  dsimp only
  generalize observeTerm state message = current at observed ⊢
  cases message with
  | appendEntriesRequest request => exact observed.handleAppendEntriesRequest caps source
  | appendEntriesResponse response =>
      unfold Model.Node.handleAppendEntriesResponse
      refine Keeps.ite' (fun _ => Keeps.pure' observed) fun _ => ?_
      refine Keeps.ite' (fun _ => ?_) fun _ => Keeps.pure' (observed.of_log rfl rfl)
      refine Keeps.ite' (fun _ => CommitFrontier.advanced self ?_ caps)
        fun _ => Keeps.pure' observed
      exact observed.of_log rfl rfl
  | requestVoteRequest request =>
      unfold Model.Node.handleRequestVoteRequest
      exact Keeps.seq' fun _ => Keeps.pure' (by split <;> exact observed.of_log rfl rfl)
  | requestVoteResponse response =>
      unfold Model.Node.handleRequestVoteResponse
      exact Keeps.ite' (fun _ => CommitFrontier.electIfQuorum caps self (observed.of_log rfl rfl))
        fun _ => Keeps.pure' observed
  | requestPreVoteRequest request =>
      unfold Model.Node.handleRequestPreVoteRequest
      exact Keeps.seq' fun _ => Keeps.pure' observed
  | requestPreVoteResponse response =>
      unfold Model.Node.handleRequestPreVoteResponse
      refine Keeps.ite' (fun _ => ?_) fun _ => Keeps.pure' observed
      dsimp only
      exact Keeps.ite' (fun _ => CommitFrontier.becomeCandidate caps self (observed.of_log rfl rfl))
        fun _ => Keeps.pure' (observed.of_log rfl rfl)
  | proposeRequestVoteRequest term =>
      unfold Model.Node.handleProposeRequestVoteRequest
      exact Keeps.ite' (fun _ => CommitFrontier.becomeCandidate caps self observed)
        fun _ => Keeps.pure' observed

end Handlers
end Consensus.Proofs.Direct

namespace Consensus.Proofs.Direct

set_option linter.unusedSectionVars false
open Consensus.Proofs.Config
open CCF
open Model.Node
open Ledger (
  isSignatureAt_of_prefix isSignatureAt_take_of_le signatureIndex_le_maxCommittableIndex
    maxCommittableIndexUpTo_le_length maxCommittableIndexUpToPositiveIsSignature
  )

private theorem commitFrontier_invariant [Config.InitialConfiguration]
    : Direct.NodeInvariant fun _ state => CommitFrontier state := by
  refine ⟨
    fun node =>
      ⟨Nat.zero_le _, fun positive => by simp [Model.initialNodeState] at positive⟩,
    ?_
  ⟩
  intro self state event after outputs frontier stepped
  cases event with
  | internal input =>
      simp only [Model.Node.step] at stepped
      exact frontier.act _ self _ _ _ _ stepped
  | receive source message =>
      simp only [Model.Node.step] at stepped
      exact frontier.receive _ self source message _ _ _ stepped

end Consensus.Proofs.Direct

namespace Consensus.Proofs.Direct

set_option linter.unusedSectionVars false
open Consensus.Proofs.Config
open CCF CCF.MultiNodeTransitionSystem Concrete
open Model.Node

private theorem Extends.committedLog {before after : NodeState}
    (extended : Extends before after)
    : before.committedLog <+: after.committedLog :=
  List.prefix_take_iff.mpr ⟨extended.2, Nat.le_trans (List.length_take_le _ _) extended.1⟩

private theorem Extends.refl (state : NodeState) : Extends state state :=
  ⟨Nat.le.refl, List.take_prefix _ _⟩

private theorem Extends.trans {first second third : NodeState}
    (left : Extends first second) (right : Extends second third)
    : Extends first third :=
  ⟨Nat.le_trans left.1 right.1, left.committedLog.trans right.2⟩

/-- Keeping the log below `count`, at or above the commit index, and committing no
less extends the committed log. -/
private theorem Extends.of_prefix {before after : NodeState} {count : Nat}
    (within : before.commitIndex <= count) (kept : before.log.take count <+: after.log)
    (grows : before.commitIndex <= after.commitIndex)
    : Extends before after := by
  refine ⟨grows, List.IsPrefix.trans ?_ kept⟩
  unfold NodeState.committedLog
  exact List.take_prefix_take_left within

private theorem Extends.of_log {before after : NodeState}
    (logEq : after.log = before.log) (commitEq : after.commitIndex = before.commitIndex)
    : Extends before after :=
  ⟨Nat.le_of_eq commitEq.symm, logEq ▸ List.take_prefix _ _⟩

private theorem Extends.append {state : NodeState} (entry : Entry)
    : Extends state { state with log := state.log ++ [entry] } :=
  ⟨Nat.le.refl, (List.take_prefix _ _).trans (List.prefix_append _ _)⟩

end Consensus.Proofs.Direct

namespace Consensus.Proofs.Direct

set_option linter.unusedSectionVars false
open Consensus.Proofs.Config
open CCF CCF.MultiNodeTransitionSystem Concrete
open Model.Node
section AppendEntries
variable {self : NodeID} {state : NodeState}
  {request : AppendEntriesRequest}

private theorem Extends.fromLeader
    : Extends state (handleAppendEntiresFromPrimary self state request).1 := by
  obtain ⟨retired, role, known, eq, -⟩ :=
    Ledger.handleAppendEntiresFromPrimary_eq self state request
  rw [eq]
  exact ⟨Nat.le_max_left _ _, (List.take_prefix _ _).trans (List.prefix_append _ _)⟩

private theorem Extends.handleAppendEntriesRequest (caps : Caps) (source : NodeID)
    : Keeps (Extends state)
        (Model.Node.handleAppendEntriesRequest caps self source state request) := by
  unfold Model.Node.handleAppendEntriesRequest
  have stepped : Extends state (if request.term = state.currentTerm /\
      (state.role = .candidate \/ state.role = .preVoteCandidate) then
        becomeAwareOfNewTerm state request.term else state) := by
    split
    · exact Extends.of_log rfl rfl
    · exact Extends.refl _
  generalize (if request.term = state.currentTerm /\
      (state.role = .candidate \/ state.role = .preVoteCandidate) then
        becomeAwareOfNewTerm state request.term else state) = current
    at stepped
  refine Keeps.ite' (fun _ => by
    dsimp only
    split <;> exact Keeps.seq' fun _ => Keeps.pure' stepped) fun _ => ?_
  dsimp only
  refine Keeps.ite' (fun _ => Keeps.pure' (stepped.trans (Extends.of_log rfl rfl)))
    fun notBefore => ?_
  have within : current.commitIndex <= request.prevLogIndex :=
    Nat.le_of_not_lt fun lt => notBefore (Or.inl lt)
  split
  · exact Keeps.seq' fun _ => Keeps.pure'
      ((stepped.trans (Extends.of_log (after := { current with primaryKnown := true }) rfl
        rfl)).trans Extends.fromLeader)
  · rename_i index conflict
    have := Ledger.firstTermConflictIndex_ge conflict
    have truncated : Extends current {
        current with
          primaryKnown := true, log := current.log.take (index - 1), isNewFollower := false
      } :=
      Extends.of_prefix (count := index - 1)
        (Nat.le_trans within (Nat.le_sub_of_add_le this)) (List.prefix_refl _) Nat.le.refl
    exact Keeps.seq' fun _ => Keeps.pure' ((stepped.trans truncated).trans Extends.fromLeader)

end AppendEntries
end Consensus.Proofs.Direct

namespace Consensus.Proofs.Direct

set_option linter.unusedSectionVars false
open Consensus.Proofs.Config
open CCF CCF.MultiNodeTransitionSystem Concrete
open Model.Node
section Handlers
variable (caps : Caps) (self : NodeID)

private theorem Extends.advanced (state : NodeState)
    : Keeps (Extends state) (Model.Node.advanceCommit caps state self) := by
  unfold Model.Node.advanceCommit
  refine Keeps.ite' (fun _ => Keeps.pure' (Extends.refl _)) fun ahead => ?_
  have advanced : Extends state
      (state.recordCommit self (highestCommittableIndex state self)) :=
    ⟨by
      rw [Ledger.NodeState.recordCommit_commitIndex]
      exact Nat.le_of_lt (Nat.lt_of_not_le ahead),
      by rw [Ledger.NodeState.recordCommit_log]; exact List.take_prefix _ _⟩
  dsimp only
  exact Keeps.ite'
    (fun _ => Keeps.ite'
      (fun _ => Keeps.seq' fun _ => Keeps.pure' (advanced.trans (Extends.of_log rfl rfl)))
      fun _ => Keeps.pure' (advanced.trans (Extends.of_log rfl rfl)))
    fun _ => Keeps.pure' advanced

private theorem Extends.appendEntry (state : NodeState) (content : EntryContent)
    : Keeps (Extends state) (Model.Node.appendEntry caps self state content) := by
  unfold Model.Node.appendEntry
  simp only [pure_bind]
  repeat'
    first
    | exact Keeps.pure' ((Extends.append _).trans (Extends.of_log rfl rfl))
    | refine Keeps.ite' (fun _ => ?_) fun _ => ?_
    | refine Keeps.seq' fun _ => ?_
    | split

private theorem Extends.becomePrimary (state : NodeState)
    : Keeps (Extends state) (Model.Node.becomePrimary caps self state) := by
  unfold Model.Node.becomePrimary Model.Node.primaryState
  have promoted : Extends state
      {
        state with
          role := .primary
          log :=
            if state.commitIndex > 0 then state.log.take (lastCommittableIndex state)
            else state.log
          primaryKnown := true
          sentIndex := fun _ =>
            (if state.commitIndex > 0 then state.log.take (lastCommittableIndex state)
              else state.log).length
          matchIndex := fun _ => 0
      } := by
    split
    · exact Extends.of_prefix (by unfold lastCommittableIndex; exact Nat.le_max_left _ _)
        (List.prefix_refl _) Nat.le.refl
    · exact Extends.of_log rfl rfl
  exact Keeps.bind' (Extends.advanced caps self _) fun _ kept =>
    Keeps.seq' fun _ => Keeps.pure' (promoted.trans kept)

private theorem Extends.electIfQuorum (state : NodeState)
    : Keeps (Extends state) (Model.Node.electIfQuorum caps self state) := by
  unfold Model.Node.electIfQuorum
  exact Keeps.ite' (fun _ => Extends.becomePrimary caps self state)
    fun _ => Keeps.pure' (Extends.refl _)

private theorem Extends.becomeCandidate (state : NodeState)
    : Keeps (Extends state) (Model.Node.becomeCandidate caps state self) := by
  unfold Model.Node.becomeCandidate
  exact Keeps.bind' (Extends.electIfQuorum caps self _) fun _ kept =>
    Keeps.seq' fun _ => Keeps.pure' ((Extends.of_log rfl rfl).trans kept)

private theorem Extends.becomePreVoteCandidate (state : NodeState)
    : Keeps (Extends state) (Model.Node.becomePreVoteCandidate caps state self) := by
  unfold Model.Node.becomePreVoteCandidate
  refine Keeps.ite' (fun _ => ?_) fun _ => Keeps.seq' fun _ =>
    Keeps.pure' (Extends.of_log rfl rfl)
  exact (Extends.becomeCandidate caps self _).mono fun _ kept =>
    (Extends.of_log rfl rfl).trans kept

private theorem Extends.act (state : NodeState) (input : Input)
    : Keeps (Extends state) (Model.Node.act caps self state input) := by
  cases input with
  | append entries =>
      unfold Model.Node.act Model.Node.appendBatch
      refine Keeps.seq' fun _ => ?_
      exact Keeps.bind'
        (Keeps.foldlM' (P := Extends state) (fun current entry kept =>
          Keeps.bind' (Extends.appendEntry caps self current entry.content)
            fun appended next => Keeps.foldlM'
              (fun current (destination, endIndex) kept => by
                unfold Model.Node.sendEntries
                exact Keeps.seq' fun _ => Keeps.seq' fun _ => Keeps.pure' kept)
              entry.flushes appended (kept.trans next))
          entries state (Extends.refl _))
        fun current kept => (Extends.advanced caps self current).mono fun _ next =>
          kept.trans next
  | sendEntries destination endIndex =>
      unfold Model.Node.act Model.Node.sendEntries
      exact Keeps.seq' fun _ => Keeps.seq' fun _ => Keeps.pure' (Extends.of_log rfl rfl)
  | timeout kind =>
      cases kind with
      | election =>
          unfold Model.Node.act Model.Node.startElection
          exact Keeps.seq' fun _ => Extends.becomePreVoteCandidate caps self state
      | checkQuorum =>
          unfold Model.Node.act Model.Node.checkQuorum
          exact Keeps.seq' fun _ => Keeps.pure' (Extends.of_log rfl rfl)
  | nominateSuccessor =>
      exact (Keeps.nominateSuccessor caps self state).mono fun _ same =>
        same ▸ Extends.of_log rfl rfl
  | initAsBackup entries =>
      unfold Model.Node.act Model.Node.initAsBackup
      refine Keeps.bind' Keeps.guard' fun _ ⟨⟨_, _, empty, zero⟩, _⟩ => Keeps.pure' ?_
      exact ⟨
        by simp [becomeAwareOfNewTerm, zero],
        by simp [NodeState.committedLog, empty]
      ⟩

private theorem Extends.receive (state : NodeState) (source : NodeID) (message : Message)
    : Keeps (Extends state) (Model.Node.receive caps self source state message) := by
  have observedExtends : Extends state (observeTerm state message) :=
    Extends.of_log (Concrete.observeTerm_log _ _) (Concrete.observeTerm_commitIndex _ _)
  unfold Model.Node.receive
  refine Keeps.ite' (fun _ => Keeps.pure' (Extends.refl _)) fun _ => ?_
  dsimp only
  generalize observeTerm state message = current at observedExtends ⊢
  refine Keeps.mono (P := Extends current) ?_ fun _ next => observedExtends.trans next
  cases message with
  | appendEntriesRequest request =>
      exact Extends.handleAppendEntriesRequest caps source
  | appendEntriesResponse response =>
      unfold Model.Node.handleAppendEntriesResponse
      refine Keeps.ite' (fun _ => Keeps.pure' (Extends.refl _)) fun _ => ?_
      refine Keeps.ite' (fun _ => ?_) fun _ => Keeps.pure' (Extends.of_log rfl rfl)
      refine Keeps.ite' (fun _ => ?_) fun _ => Keeps.pure' (Extends.refl _)
      exact (Extends.advanced caps self _).mono fun _ next =>
        (Extends.of_log rfl rfl).trans next
  | requestVoteRequest request =>
      unfold Model.Node.handleRequestVoteRequest
      exact Keeps.seq' fun _ => Keeps.pure' (by split <;> exact Extends.of_log rfl rfl)
  | requestVoteResponse response =>
      unfold Model.Node.handleRequestVoteResponse
      refine Keeps.ite' (fun _ => ?_) fun _ => Keeps.pure' (Extends.refl _)
      exact (Extends.electIfQuorum caps self _).mono fun _ next =>
        (Extends.of_log rfl rfl).trans next
  | requestPreVoteRequest request =>
      unfold Model.Node.handleRequestPreVoteRequest
      exact Keeps.seq' fun _ => Keeps.pure' (Extends.refl _)
  | requestPreVoteResponse response =>
      unfold Model.Node.handleRequestPreVoteResponse
      refine Keeps.ite' (fun _ => ?_) fun _ => Keeps.pure' (Extends.refl _)
      dsimp only
      refine Keeps.ite' (fun _ => ?_) fun _ => Keeps.pure' (Extends.of_log rfl rfl)
      exact (Extends.becomeCandidate caps self _).mono fun _ next =>
        (Extends.of_log rfl rfl).trans next
  | proposeRequestVoteRequest term =>
      unfold Model.Node.handleProposeRequestVoteRequest
      exact Keeps.ite' (fun _ => Extends.becomeCandidate caps self current)
        fun _ => Keeps.pure' (Extends.refl _)

end Handlers
end Consensus.Proofs.Direct

namespace Consensus.Proofs.Direct

set_option linter.unusedSectionVars false
open Consensus.Proofs.Config
open CCF CCF.MultiNodeTransitionSystem Concrete
open Model.Node
section Global
variable [Config.InitialConfiguration]

/-- From any state with distinct node identifiers, a step keeps every other node's
state and extends the actor's committed log. -/
private theorem committed_log_step {nodes : List NodeID} {before after : Model.State}
    {action : Model.Action}
    (distinct : (before.nodes.map Prod.fst).Nodup)
    (stepped
      : (Model.transitionSystem Config.INITIAL_CONFIGURATION nodes).step before action
        = some after)
    {node : NodeID} {beforeState afterState : NodeState}
    (beforeMember : (node, beforeState) ∈ before.nodes)
    (afterMember : (node, afterState) ∈ after.nodes)
    : beforeState.committedLog <+: afterState.committedLog := by
  have extended : forall {actor : NodeID} {old : NodeState}
      {new : NodeState},
      nodeState before actor = some old
      -> Extends old new
      -> (node, afterState) ∈ replaceNode before.nodes actor new
      -> beforeState.committedLog <+: afterState.committedLog := by
    intro actor old new found grown member
    rcases mem_replaceNode member with ⟨rfl, rfl⟩ | ⟨_, listed⟩
    · have same : beforeState = old :=
        Option.some.inj ((nodeState_of_mem distinct beforeMember).symm.trans found)
      subst same
      exact grown.committedLog
    · have same : afterState = beforeState :=
        Option.some.inj
          ((nodeState_of_mem distinct listed).symm.trans (nodeState_of_mem distinct beforeMember))
      subst same
      exact List.prefix_refl _
  cases action with
  | «local» actor input =>
      obtain ⟨old, new, outputs, found, acted, rfl⟩ := step_local stepped
      exact extended found (Extends.act _ actor old input _ _ _ acted) afterMember
  | deliver envelope =>
      obtain ⟨_, old, new, outputs, found, received, rfl⟩ := step_deliver stepped
      exact extended found (Extends.receive _ _ old _ _ _ _ _ received) afterMember

/-- A node present before a step is present after it. -/
private theorem present_after_step {nodes : List NodeID} {before after : Model.State}
    {action : Model.Action}
    (stepped
      : (Model.transitionSystem Config.INITIAL_CONFIGURATION nodes).step before action
        = some after)
    {node : NodeID} {beforeState : NodeState}
    (member : (node, beforeState) ∈ before.nodes)
    : exists afterState, (node, afterState) ∈ after.nodes := by
  have present : forall {actor : NodeID} {value : NodeState},
      exists afterState, (node, afterState) ∈ replaceNode before.nodes actor value := by
    intro actor value
    by_cases same : node = actor
    · subst same
      exact ⟨value, List.mem_map.mpr ⟨_, member, by simp⟩⟩
    · exact ⟨beforeState, List.mem_map.mpr ⟨_, member, by simp [same]⟩⟩
  cases action with
  | «local» actor input =>
      obtain ⟨_, _, _, _, _, rfl⟩ := step_local stepped
      exact present
  | deliver envelope =>
      obtain ⟨_, _, _, _, _, _, rfl⟩ := step_deliver stepped
      exact present

/-- A node's committed log at one state of a trace is a prefix of the same node's
committed log at every later state of the trace. -/
private theorem committed_log_later {nodes : List NodeID}
    {trace
      : CCF.Execution.Trace (Model.transitionSystem Config.INITIAL_CONFIGURATION nodes)}
    {index : Nat} {state : Model.State} (found : trace.stateAt index = some state)
    {node : NodeID} {firstState : NodeState} (member : (node, firstState) ∈ state.nodes)
    : forall offset later,
        trace.stateAt (index + offset) = some later
        -> exists laterState,
            (node, laterState) ∈ later.nodes
            /\ firstState.committedLog <+: laterState.committedLog := by
  intro offset
  induction offset with
  | zero =>
      intro later atLater
      rw [Nat.add_zero, found] at atLater
      cases atLater
      exact ⟨firstState, member, List.prefix_refl _⟩
  | succ offset ih =>
      intro later atLater
      rw [← Nat.add_assoc] at atLater
      cases atMiddle : trace.stateAt (index + offset) with
      | none => simp [trace.states.le_stable (Nat.le_succ _) atMiddle] at atLater
      | some middle =>
          obtain ⟨middleState, middleMember, prefixed⟩ := ih middle atMiddle
          obtain ⟨action, stepped⟩ := trace.step (index + offset) middle later atMiddle atLater
          obtain ⟨laterState, laterMember⟩ := present_after_step stepped middleMember
          refine ⟨laterState, laterMember, prefixed.trans ?_⟩
          exact committed_log_step (keys_nodup (trace.reachable (CCF.Execution.Trace.stateAt_mem atMiddle)))
            stepped middleMember laterMember

end Global
end Consensus.Proofs.Direct

namespace Consensus.Proofs.Safety

set_option linter.unusedSectionVars false
open Consensus.Proofs.Config Consensus.Proofs.Ledger
open CCF
open Model.Node

private theorem AEFrom.extend {self : NodeID} {term commit commit' : Nat}
    {log log' : List Entry} {envelope : Model.Envelope}
    (sent : AEFrom self term commit log envelope) (extends_ : log <+: log')
    (le : commit <= commit')
    : AEFrom self term commit' log' envelope := by
  obtain ⟨source, target, request, payload, term, prev, prevTerm, entries, primaryCommit⟩ := sent
  refine ⟨source, target, request, payload, term, Nat.le_trans prev extends_.length_le, ?_, ?_,
    Nat.le_trans primaryCommit le⟩
  · rw [prevTerm, termAt_of_prefix extends_ prev]
  · obtain ⟨rest, rfl⟩ := extends_
    rw [List.drop_append_of_le_length prev]
    exact entries.trans (List.prefix_append _ _)

private theorem AEFrom.ok {self : NodeID} {state : NodeState}
    {envelope : Model.Envelope}
    (sent : AEFrom self state.currentTerm state.commitIndex state.log envelope)
    : exists request,
        envelope.payload = .appendEntriesRequest request
        /\ AEOk self envelope.target state request := by
  obtain ⟨_, target, request, payload, term, prev, prevTerm, entries, primaryCommit⟩ := sent
  exact ⟨request, payload, target, term, prev, prevTerm, entries, primaryCommit⟩

private theorem Advance.log {self : NodeID} {middle state : NodeState}
    (advance : Advance self middle state)
    : state.log = middle.log := by
  rcases advance with rfl | h <;> grind

private theorem Advance.term {self : NodeID} {middle state : NodeState}
    (advance : Advance self middle state)
    : state.currentTerm = middle.currentTerm := by
  rcases advance with rfl | h <;> grind

private theorem Advance.votedFor {self : NodeID} {middle state : NodeState}
    (advance : Advance self middle state)
    : state.votedFor = middle.votedFor := by
  rcases advance with rfl | h <;> grind

private theorem Advance.matchIndex {self : NodeID} {middle state : NodeState}
    (advance : Advance self middle state)
    : state.matchIndex = middle.matchIndex := by
  rcases advance with rfl | h <;> grind

private theorem Advance.sentIndex {self : NodeID} {middle state : NodeState}
    (advance : Advance self middle state)
    : state.sentIndex = middle.sentIndex := by
  rcases advance with rfl | h <;> grind

private theorem Advance.votesGranted {self : NodeID} {middle state : NodeState}
    (advance : Advance self middle state)
    : state.votesGranted = middle.votesGranted := by
  rcases advance with rfl | h <;> grind

private theorem Advance.commit_le {self : NodeID} {middle state : NodeState}
    (advance : Advance self middle state)
    : middle.commitIndex <= state.commitIndex := by
  rcases advance with rfl | h <;> grind

private theorem Advance.role {self : NodeID} {middle state : NodeState}
    (advance : Advance self middle state)
    : state.role = middle.role \/ state.role = .none := by
  rcases advance with rfl | h <;> grind

end Consensus.Proofs.Safety

namespace Consensus.Proofs.Safety

set_option linter.unusedSectionVars false
open Consensus.Proofs.Config Consensus.Proofs.Ledger
open CCF
open Model.Node
section Effects
variable (self : NodeID)

private theorem nominate_sends (state : NodeState)
    : Sends
        (fun result sent =>
          result = state
          /\ state.role = .primary
          /\ forall e,
              e ∈ sent
              -> e.source = self
                  /\ e.payload = .proposeRequestVoteRequest state.currentTerm)
        (nominateSuccessor (Capabilities.record self : Caps) state self) := by
  unfold nominateSuccessor
  refine Sends.bind' Sends.guard' fun _ _ ⟨leader, empty⟩ => ?_
  subst empty
  split
  · exact Sends.bind' (Sends.send _ _ _) fun _ sent eq =>
      Sends.pure' ⟨rfl, leader, by simp [eq]⟩
  · exact Sends.pure' ⟨rfl, leader, by simp⟩

private theorem advanceCommit_sends (middle : NodeState)
    : Sends
        (fun state sent =>
          Advance self middle state
          /\ forall e,
              e ∈ sent
              -> e.source = self
                  /\ e.payload = .proposeRequestVoteRequest middle.currentTerm)
        (advanceCommit (Capabilities.record self : Caps) middle self) := by
  unfold advanceCommit
  dsimp only
  refine Sends.ite' (fun _ => Sends.pure' ⟨Or.inl rfl, by simp⟩) fun ahead => ?_
  have advanced : Advance self middle
      (middle.recordCommit self (highestCommittableIndex middle self)) := by
    obtain ⟨_, _, _, eq, roleCase⟩ :=
      NodeState.recordCommit_eq self middle (highestCommittableIndex middle self)
    rw [eq]
    exact Or.inr ⟨rfl, rfl, rfl, rfl, rfl, rfl, by simp only; exact Nat.lt_of_not_le ahead, rfl,
      roleCase⟩
  refine Sends.ite'
    (fun _ => Sends.ite' (fun _ => ?_) fun _ => Sends.pure' ⟨advanced, by simp⟩)
    fun _ => Sends.pure' ⟨advanced, by simp⟩
  exact Sends.bind' (nominate_sends self middle)
    fun _ sent nominated =>
      Sends.pure' ⟨advanced, by simpa using nominated.2.2⟩

private theorem broadcast_sends (state : NodeState) (message : Message)
    : Sends
        (fun _ sent =>
          forall e,
            e ∈ sent -> e.source = self /\ Not (e.target = self) /\ e.payload = message)
        (broadcastToOthers (Capabilities.record self : Caps) self state message) := by
  unfold broadcastToOthers
  refine Sends.bind'
    (Sends.forIn'
      (R := fun e => e.source = self /\ Not (e.target = self) /\ e.payload = message)
      fun peer _ member => ?_)
    fun _ sent done => Sends.pure' (by simpa using done)
  refine Sends.bind' (Sends.send _ _ _) fun _ sent eq => Sends.pure' ?_
  have : Not (peer = self) := by simp [Finset.mem_sort] at member; exact member.1
  simp [eq, this]

private theorem becomePrimary_sends (candidate : NodeState)
    : Sends
        (fun state sent =>
          Advance self (primaryState candidate) state
          /\ forall e, e ∈ sent -> LeaderStart self candidate.currentTerm state e)
        (becomePrimary (Capabilities.record self : Caps) self candidate) := by
  unfold becomePrimary
  refine Sends.bind' (advanceCommit_sends self _)
    fun leader sent ⟨advance, nominated⟩ => ?_
  refine Sends.bind' (Q := fun _ later => forall e, e ∈ later ->
      AEFrom self leader.currentTerm leader.commitIndex leader.log e)
    (Sends.forIn' fun peer _ member => ?_) fun _ later beats => Sends.pure' ⟨advance, ?_⟩
  · refine Sends.bind' (Sends.send _ _ _) fun _ sent eq => Sends.pure' fun e member => ?_
    simp only [eq, List.append_nil, List.mem_singleton] at member
    subst member
    have other : Not (peer = self) := by simp [Finset.mem_sort, eligiblePeers] at member; exact member.1
    have sentEq : leader.sentIndex peer = leader.log.length := by
      rw [advance.sentIndex, advance.log]
      simp [primaryState]
    refine ⟨rfl, other, _, rfl, rfl, ?_, rfl, ?_, Nat.le.refl⟩ <;>
      simp [makeAppendEntriesRequest, sentEq, messageEntries]
  · intro e member
    rcases List.mem_append.mp (by simpa using member) with old | new
    · have := nominated e old
      exact Or.inl ⟨this.1, by simpa [primaryState] using this.2⟩
    · exact Or.inr (beats e new)

private theorem electIfQuorum_sends (candidate : NodeState)
    : Sends
        (fun state sent =>
          (state = candidate /\ sent = [])
          \/ (candidate.role = .candidate
              /\ hasQuorum (candidate.activeConfigurations) candidate.votesGranted
              /\ Advance self (primaryState candidate) state
              /\ forall e, e ∈ sent -> LeaderStart self candidate.currentTerm state e))
        (electIfQuorum (Capabilities.record self : Caps) self candidate) := by
  unfold electIfQuorum
  refine Sends.ite' (fun won => ?_) fun _ => Sends.pure' (Or.inl ⟨rfl, rfl⟩)
  exact Sends.mono (becomePrimary_sends self candidate) fun _ _ done =>
    Or.inr ⟨won.1, won.2.1, done⟩

private theorem becomeCandidate_sends (state : NodeState)
    : Sends
        (fun next sent =>
          ((next = freshCandidate self state
              /\ forall e,
                  e ∈ sent
                  -> e.source = self
                      /\ e.payload
                          = .requestVoteRequest
                              (makeRequestVoteRequest (freshCandidate self state)))
            \/ (hasQuorum ((freshCandidate self state).activeConfigurations) {self}
                /\ Advance self (primaryState (freshCandidate self state)) next
                /\ forall e,
                    e ∈ sent
                    -> LeaderStart self (state.currentTerm + 1) next e
                        \/ (e.source = self
                            /\ e.payload
                                = .requestVoteRequest
                                    (makeRequestVoteRequest
                                      (freshCandidate self state))))))
        (becomeCandidate (Capabilities.record self : Caps) state self) := by
  unfold becomeCandidate
  refine Sends.bind' (electIfQuorum_sends self (freshCandidate self state))
    fun next sent elected => ?_
  refine Sends.bind' (broadcast_sends self _ _) fun _ later requests => Sends.pure' ?_
  simp only [List.append_nil]
  rcases elected with ⟨rfl, rfl⟩ | ⟨_, quorum, advance, started⟩
  · exact Or.inl ⟨rfl, fun e member => by
      have := requests e (by simpa using member)
      exact ⟨this.1, this.2.2⟩⟩
  · refine Or.inr ⟨by simpa [freshCandidate] using quorum, advance, fun e member => ?_⟩
    rcases List.mem_append.mp member with old | new
    · exact Or.inl (by simpa [freshCandidate] using started e old)
    · have := requests e new
      exact Or.inr ⟨this.1, this.2.2⟩

end Effects
end Consensus.Proofs.Safety

namespace Consensus.Proofs.Safety

set_option linter.unusedSectionVars false
open Consensus.Proofs.Config Consensus.Proofs.Ledger
open CCF
open Model.Node

private theorem campaign_summary {self : NodeID} {before candidate after : NodeState}
    {event : Event} {sent : List Model.Envelope}
    (campaign : Campaign self before event candidate)
    (result : CampaignResult self before candidate after sent)
    : Summary self before event after sent := by
  have termLe : before.currentTerm <= candidate.currentTerm := by
    rcases campaign.2.2.2 with fresh | kept
    · exact Nat.le_trans (Nat.le_succ _) (Nat.le_of_eq fresh.2.1.symm)
    · exact Nat.le_of_eq kept.2.1.symm
  have engaged : Engaged before := by
    rcases campaign.2.2.2 with fresh | kept
    · exact fresh.1
    · simp [Engaged, kept.1]
  have notLeaderKeep : before.role = .primary -> candidate.currentTerm = before.currentTerm
      -> False := by
    intro leader same
    rcases campaign.2.2.2 with fresh | kept
    · exact Nat.succ_ne_self _ (fresh.2.1.symm.trans same)
    · rw [kept.1] at leader; cases leader
  have voteKeep : candidate.currentTerm = before.currentTerm -> forall voted,
      before.votedFor = some voted -> candidate.votedFor = some voted := by
    intro same voted votedEq
    rcases campaign.2.2.2 with fresh | kept
    · exact (Nat.succ_ne_self _ (fresh.2.1.symm.trans same)).elim
    · rcases kept.2.2.1 with eq | none
      · rw [eq]; exact votedEq
      · rw [none] at votedEq; cases votedEq
  unfold CampaignResult at result
  rcases result with ⟨rfl, requests⟩ | ⟨quorum, advance, started⟩
  · refine ⟨termLe, voteKeep, fun _ => Or.inl engaged, fun _ => campaign,
      fun leader => (by rw [campaign.1] at leader; cases leader),
      fun _ leader same => (notLeaderKeep leader same).elim,
      Kind.same campaign.2.1 campaign.2.2.1, fun e member => ?_⟩
    obtain ⟨source, payload, lt⟩ := requests e member
    refine ⟨source, ?_⟩
    rw [payload]
    exact ⟨rfl, lt, fun _ => rfl⟩
  · replace advance : Advance self (primaryState candidate) after :=
      advance
    have termEq : after.currentTerm = candidate.currentTerm := by
      rw [advance.term]; rfl
    have elected : Wins self before event after := ⟨candidate, campaign, quorum, advance⟩
    have notCandidate : Not (after.role = .candidate) := by
      rcases advance.role with eq | eq <;> rw [eq] <;> simp [primaryState]
    refine ⟨termEq ▸ termLe, fun same voted votedEq => ?_, fun _ => Or.inl engaged,
      fun candidate' => (notCandidate candidate').elim, fun _ => Or.inr elected,
      fun _ leader same => (notLeaderKeep leader (termEq ▸ same)).elim,
      Kind.elect elected, fun e member => ?_⟩
    · rw [advance.votedFor]
      exact voteKeep (termEq ▸ same) voted votedEq
    · rcases started e member with (⟨source, payload⟩ | beat) | ⟨source, payload, lt⟩
      · refine ⟨source, ?_⟩
        rw [payload]
        exact termEq.symm
      · obtain ⟨request, payload, ok⟩ := beat.ok
        refine ⟨beat.1, ?_⟩
        rw [payload]
        exact ⟨ok, notCandidate, Or.inr elected⟩
      · refine ⟨source, ?_⟩
        rw [payload]
        exact ⟨termEq.symm, termEq ▸ lt, fun c => (notCandidate c).elim⟩

private theorem quiet_summary {self : NodeID} {before after : NodeState}
    {event : Event} {sent : List Model.Envelope}
    (role : after.role = before.role) (term : after.currentTerm = before.currentTerm)
    (log : after.log = before.log) (commit : after.commitIndex = before.commitIndex)
    (voted : after.votedFor = before.votedFor)
    (votes : after.votesGranted = before.votesGranted)
    (matchEq : after.matchIndex = before.matchIndex)
    (active
      : (exists envelope, envelope ∈ sent /\ Bumping envelope.payload)
        -> Engaged before
            \/ 2 <= before.currentTerm
            \/ (exists source message,
                  event = .receive source message
                  /\ Bumping message
                  /\ message.term <= after.currentTerm)
            \/ exists entries,
                event = .internal (.initAsBackup entries)
                /\ 0 < entries.length
                /\ isSignatureAt entries entries.length = true
                /\ after.currentTerm = termAt entries entries.length)
    (sends : forall e, e ∈ sent -> SendOK self before event after e)
    : Summary self before event after sent := by
  refine ⟨
    Nat.le_of_eq term.symm,
    fun _ voted' votedEq => voted ▸ votedEq,
    fun either => ?_,
    fun candidate =>
      ⟨
        candidate,
        log,
        commit,
        Or.inr
          ⟨
            role ▸ candidate,
            term,
            Or.inl voted,
            fun voter member => Or.inl (votes ▸ member)
          ⟩
      ⟩,
    fun leader => Or.inl ⟨role ▸ leader, term⟩,
    fun _ _ _ peer => Or.inl (congrFun matchEq peer),
    Kind.same log commit,
    sends
  ⟩
  rcases either with engaged | bumping
  · exact Or.inl (by simpa only [Engaged, role, term, log] using engaged)
  · exact active bumping

/-- No envelope in an empty send list is a term-bumping message. -/
private theorem no_bumping_sends {P : Prop}
    : (exists envelope, envelope ∈ ([] : List Model.Envelope) /\ Bumping envelope.payload)
      -> P :=
  fun ⟨_, member, _⟩ => by simp at member

private theorem bumped_summary {self : NodeID} {before after : NodeState}
    {event : Event} {sent : List Model.Envelope}
    (lt : before.currentTerm < after.currentTerm)
    (notCandidate : Not (after.role = .candidate))
    (notLeader : Not (after.role = .primary))
    (active
      : exists source message,
          event = .receive source message
          /\ Bumping message
          /\ message.term <= after.currentTerm)
    (kind : Kind self before event after)
    (sends : forall e, e ∈ sent -> SendOK self before event after e)
    : Summary self before event after sent :=
  ⟨
    Nat.le_of_lt lt,
    fun same => (Nat.lt_irrefl _ (Nat.lt_of_lt_of_le lt (Nat.le_of_eq same))).elim,
    fun _ => Or.inr (Or.inr (Or.inl active)),
    fun candidate => (notCandidate candidate).elim,
    fun leader => (notLeader leader).elim,
    fun leader => (notLeader leader).elim,
    kind,
    sends
  ⟩

private theorem observe_bumping (before : NodeState) {message : Message}
    (bumping : Bumping message)
    : (before.currentTerm < message.term
        /\ observeTerm before message = bumpedState before message.term)
      \/ (message.term <= before.currentTerm /\ observeTerm before message = before) := by
  by_cases bump : before.currentTerm < message.term
  · refine Or.inl ⟨bump, ?_⟩
    have ne := Nat.ne_of_lt bump
    cases message <;>
      simp_all [Bumping, observeTerm, updateTerm, becomeAwareOfNewTerm, bumpedState]
  · refine Or.inr ⟨Nat.not_lt.mp bump, ?_⟩
    cases message <;> simp_all [Bumping, observeTerm, updateTerm, Nat.not_lt_of_le]

end Consensus.Proofs.Safety

namespace Consensus.Proofs.Safety

set_option linter.unusedSectionVars false
open Consensus.Proofs.Config Consensus.Proofs.Ledger
open CCF
open Model.Node
section Election
variable (self : NodeID)

private theorem becomeCandidate_result (state : NodeState)
    (before : NodeState) (term : state.currentTerm = before.currentTerm)
    : Sends
        (fun next sent =>
          CampaignResult self before (freshCandidate self state) next sent)
        (becomeCandidate (Capabilities.record self : Caps) state self) := by
  refine Sends.mono (becomeCandidate_sends self state) fun next sent done => ?_
  have lt : before.currentTerm < (freshCandidate self state).currentTerm := by
    simp [freshCandidate, term]
  rcases done with ⟨rfl, requests⟩ | ⟨quorum, advance, started⟩
  · exact Or.inl ⟨rfl, fun e member => ⟨(requests e member).1, (requests e member).2, lt⟩⟩
  · refine Or.inr ⟨by simpa [freshCandidate] using quorum, advance, fun e member => ?_⟩
    rcases started e member with start | ⟨source, payload⟩
    · exact Or.inl start
    · exact Or.inr ⟨source, payload, lt⟩

/-- A node that can start an election has a ledger, so it is engaged. -/
private theorem canStartElection_engaged {state : NodeState} {self : NodeID}
    (can : canStartElection state self)
    : Engaged state := by
  refine ⟨by rcases can.1 with eq | eq | eq <;> rw [eq] <;> simp, fun ⟨_, _, empty⟩ => ?_⟩
  rcases can.2.1 with member | member <;>
    simp [empty, NodeState.signedActiveConfigurations, NodeState.activeConfigurations,
      activeConfigurations, configurationHistory, configurationMembers,
      NodeState.retirementCompletedNodes, NodeState.committedLog] at member

private theorem fresh_campaign {self : NodeID} {before state : NodeState}
    {event : Event} (active : Engaged before)
    (term : state.currentTerm = before.currentTerm) (log : state.log = before.log)
    (commit : state.commitIndex = before.commitIndex)
    : Campaign self before event (freshCandidate self state) := by
  refine ⟨rfl, log, commit, Or.inl ⟨active, ?_, rfl, rfl⟩⟩
  simp [freshCandidate, term]

private theorem checkQuorum_summary (state : NodeState) (input : Input)
    : Sends (fun after sent => Summary self state (.internal input) after sent)
        (checkQuorum state self) := by
  unfold checkQuorum
  refine Sends.bind' Sends.guard' fun _ sent ⟨⟨leader, _⟩, empty⟩ => Sends.pure' ?_
  subst empty
  refine ⟨
    Nat.le.refl,
    fun _ voted eq => eq,
    fun _ => Or.inl (by simp [Engaged, leader]),
    fun c => by simp at c,
    fun c => by simp at c,
    fun c => by simp at c,
    Kind.same rfl rfl,
    by simp
  ⟩

private theorem nominate_summary (state : NodeState)
    : Sends
        (fun after sent => Summary self state (.internal .nominateSuccessor) after sent)
        (act (Capabilities.record self : Caps) self state .nominateSuccessor) := by
  refine Sends.mono (nominate_sends self state) fun _ sent ⟨same, leader, nominated⟩ => ?_
  subst same
  refine quiet_summary rfl rfl rfl rfl rfl rfl rfl
    (fun _ => Or.inl (by simp [Engaged, leader])) fun e member => ?_
  obtain ⟨source, payload⟩ := nominated e member
  refine ⟨source, ?_⟩
  rw [payload]
  rfl

private theorem sendEntries_summary (state : NodeState) (destination : NodeID)
    (endIndex : Nat)
    : Sends
        (fun after sent =>
          Summary self state (.internal (.sendEntries destination endIndex)) after sent)
        (sendEntries (Capabilities.record self : Caps) self state destination
          endIndex) := by
  unfold sendEntries
  refine Sends.bind' Sends.guard' fun _ sent ⟨⟨leader, peer, le, bound, _⟩, empty⟩ => ?_
  subst empty
  refine Sends.bind' (Sends.send _ _ _) fun _ sent eq => Sends.pure' ?_
  subst eq
  refine quiet_summary rfl rfl rfl rfl rfl rfl rfl
    (fun _ => Or.inl (by simp [Engaged, leader])) fun e member => ?_
  simp only [List.nil_append, List.append_nil, List.mem_singleton] at member
  subst member
  have other : Not (destination = self) := by
    simp [eligiblePeers] at peer; exact peer.1
  refine ⟨
    rfl,
    ⟨other, rfl, Nat.le_trans le bound, rfl, ?_, Nat.le.refl⟩,
    by simp [leader],
    Or.inl ⟨leader, rfl⟩
  ⟩
  exact List.take_prefix _ _

private theorem startElection_summary (state : NodeState)
    : Sends
        (fun after sent => Summary self state (.internal (.timeout .election)) after sent)
        (startElection (Capabilities.record self : Caps) state self) := by
  unfold startElection
  refine Sends.bind' Sends.guard' fun _ sent ⟨can, empty⟩ => ?_
  subst empty
  have engaged := canStartElection_engaged can
  unfold becomePreVoteCandidate
  dsimp only
  refine Sends.ite' (fun _ => ?_) fun _ => ?_
  · exact Sends.mono (becomeCandidate_result self _ state rfl) fun after sent result =>
      campaign_summary (fresh_campaign engaged rfl rfl rfl) result
  · refine Sends.bind' (broadcast_sends self _ _) fun _ sent requests => Sends.pure' ?_
    simp only [List.append_nil]
    refine ⟨Nat.le.refl, fun _ voted eq => eq, fun _ => Or.inl engaged, fun c => by simp at c,
      fun c => by simp at c, fun c => by simp at c, Kind.same rfl rfl, fun e member => ?_⟩
    obtain ⟨source, _, payload⟩ := requests e member
    refine ⟨source, ?_⟩
    rw [payload]
    rfl

private theorem voteRequest_summary (before : NodeState) (source : NodeID)
    (request : RequestVoteRequest)
    : Sends
        (fun after sent =>
          Summary self before (.receive source (.requestVoteRequest request)) after sent)
        (receive (Capabilities.record self : Caps) self source before
          (.requestVoteRequest request)) := by
  simp only [receive]
  rcases observe_bumping before (message := .requestVoteRequest request) trivial
    with ⟨bump, eq⟩ | ⟨le, eq⟩ <;> rw [eq]
  · simp only [handleRequestVoteRequest]
    refine Sends.bind' (Sends.send _ _ _) fun _ sent eq => Sends.pure' ?_
    subst eq
    have active : exists source' message,
        Event.receive source (Message.requestVoteRequest request)
          = (Event.receive source' message : Event)
        /\ Bumping message /\ message.term <= (bumpedState before request.term).currentTerm :=
      ⟨source, _, rfl, trivial, Nat.le.refl⟩
    split <;> rename_i granted <;> simp only [decide_eq_true_eq] at granted
    · refine bumped_summary bump (by simp [bumpedState]) (by simp [bumpedState]) active
        (Kind.same rfl rfl) fun e member => ?_
      simp at member
      subst member
      exact ⟨rfl, rfl, fun _ => ⟨request, rfl, granted.1, granted.2.1, rfl⟩⟩
    · refine bumped_summary bump (by simp [bumpedState]) (by simp [bumpedState]) active
        (Kind.same rfl rfl) fun e member => ?_
      simp at member
      subst member
      exact ⟨rfl, rfl, fun yes => by simp_all⟩
  · simp only [handleRequestVoteRequest]
    refine Sends.bind' (Sends.send _ _ _) fun _ sent eq => Sends.pure' ?_
    subst eq
    have active : exists source' message,
        Event.receive source (Message.requestVoteRequest request)
          = (Event.receive source' message : Event)
        /\ Bumping message /\ message.term <= before.currentTerm :=
      ⟨source, _, rfl, trivial, le⟩
    split <;> rename_i granted <;> simp only [decide_eq_true_eq] at granted
    · refine ⟨Nat.le.refl, fun _ voted votedEq => ?_, fun _ => Or.inr (Or.inr (Or.inl active)),
        fun candidate => ⟨candidate, rfl, rfl, Or.inr ⟨candidate, rfl, ?_,
          fun voter member => Or.inl member⟩⟩,
        fun leader => Or.inl ⟨leader, rfl⟩, fun _ _ _ _ => Or.inl rfl, Kind.same rfl rfl,
        fun e member => ?_⟩
      · rcases granted.2.2.2 with none | some
        · rw [none] at votedEq; cases votedEq
        · rw [some] at votedEq; exact votedEq
      · rcases granted.2.2.2 with none | some
        · exact Or.inr none
        · exact Or.inl some.symm
      · simp at member
        subst member
        exact ⟨rfl, rfl, fun _ => ⟨request, rfl, granted.1, granted.2.1, rfl⟩⟩
    · refine quiet_summary rfl rfl rfl rfl rfl rfl rfl
        (fun _ => Or.inr (Or.inr (Or.inl active))) fun e member => ?_
      simp at member
      subst member
      exact ⟨rfl, rfl, fun yes => by simp_all⟩

private theorem preVoteRequest_summary (before : NodeState) (source : NodeID)
    (request : RequestVoteRequest)
    : Sends
        (fun after sent =>
          Summary self before (.receive source (.requestPreVoteRequest request)) after
            sent)
        (receive (Capabilities.record self : Caps) self source before
          (.requestPreVoteRequest request)) := by
  simp only [receive]
  rcases observe_bumping before (message := .requestPreVoteRequest request) trivial
    with ⟨bump, eq⟩ | ⟨le, eq⟩ <;> rw [eq] <;>
    simp only [handleRequestPreVoteRequest] <;>
    refine Sends.bind' (Sends.send _ _ _) fun _ sent eq => Sends.pure' ?_ <;>
    subst eq
  · refine bumped_summary bump (by simp [bumpedState]) (by simp [bumpedState])
      ⟨source, _, rfl, trivial, Nat.le.refl⟩ (Kind.same rfl rfl) fun e member => ?_
    simp only [List.mem_singleton, List.append_nil] at member
    subst member
    exact ⟨rfl, rfl⟩
  · refine quiet_summary rfl rfl rfl rfl rfl rfl rfl
      (fun _ => Or.inr (Or.inr (Or.inl ⟨source, _, rfl, trivial, le⟩))) fun e member => ?_
    simp only [List.mem_singleton, List.append_nil] at member
    subst member
    exact ⟨rfl, rfl⟩

private theorem proposeVote_summary (before : NodeState) (source : NodeID) (term : Nat)
    : Sends
        (fun after sent =>
          Summary self before (.receive source (.proposeRequestVoteRequest term)) after
            sent)
        (receive (Capabilities.record self : Caps) self source before
          (.proposeRequestVoteRequest term)) := by
  simp only [receive]
  refine Sends.ite'
    (fun _ =>
      Sends.pure' (quiet_summary rfl rfl rfl rfl rfl rfl rfl no_bumping_sends (by simp)))
    fun _ => ?_
  simp only [observeTerm, handleProposeRequestVoteRequest]
  refine Sends.ite' (fun start => ?_)
    fun _ =>
      Sends.pure' (quiet_summary rfl rfl rfl rfl rfl rfl rfl no_bumping_sends (by simp))
  have engaged := canStartElection_engaged start.2
  exact Sends.mono (becomeCandidate_result self before before rfl)
    fun after sent result =>
      campaign_summary (fresh_campaign engaged rfl rfl rfl) result

/-- A fresh node follows from an empty prefix in term zero, or installs a snapshot. -/
private theorem initAsBackup_summary (before : NodeState) (entries : List Entry)
    : Sends
        (fun after sent =>
          Summary self before (.internal (.initAsBackup entries)) after sent)
        (initAsBackup before entries : NodeEffect NodeState) := by
  unfold initAsBackup
  refine Sends.bind' Sends.guard' fun _ sent ⟨⟨fresh, signed⟩, empty⟩ => Sends.pure' ?_
  subst empty
  obtain ⟨none, zero, emptyLog, noCommit⟩ := fresh
  rcases Nat.eq_zero_or_pos entries.length with length | positive
  · have nil : entries = [] := List.eq_nil_of_length_eq_zero length
    subst nil
    refine ⟨
      by simp [becomeAwareOfNewTerm, zero, termAt, entryAt?],
      fun _ voted eq => by simpa [becomeAwareOfNewTerm, zero, termAt, entryAt?] using eq,
      fun active => ?_,
      fun c => by simp [becomeAwareOfNewTerm] at c,
      fun c => by simp [becomeAwareOfNewTerm] at c,
      fun c => by simp [becomeAwareOfNewTerm] at c,
      Kind.same (by simp [becomeAwareOfNewTerm, emptyLog])
        (by simp [becomeAwareOfNewTerm, noCommit]),
      by simp
    ⟩
    rcases active with engaged | bumping
    · exact (engaged.2 ⟨by simp [becomeAwareOfNewTerm], by simp [becomeAwareOfNewTerm,
        termAt, entryAt?], by simp [becomeAwareOfNewTerm]⟩).elim
    · exact no_bumping_sends bumping
  · have signature : isSignatureAt entries entries.length = true := by
      rcases signed with nil | signature
      · subst nil
        simp at positive
      · exact signature
    refine ⟨by simp [becomeAwareOfNewTerm, zero], fun same voted eq => ?_,
      fun _ => Or.inr (Or.inr (Or.inr ⟨entries, rfl, positive, signature,
        by simp [becomeAwareOfNewTerm]⟩)),
      fun c => by simp [becomeAwareOfNewTerm] at c, fun c => by simp [becomeAwareOfNewTerm] at c,
      fun c => by simp [becomeAwareOfNewTerm] at c,
      Kind.install entries rfl positive signature ⟨none, zero, emptyLog, noCommit⟩
        (by simp [becomeAwareOfNewTerm]) (by simp [becomeAwareOfNewTerm])
        (by simp [becomeAwareOfNewTerm]) (by simp [becomeAwareOfNewTerm]), by simp⟩
    by_cases termZero : termAt entries entries.length = 0
    · simpa [becomeAwareOfNewTerm, zero, termZero] using eq
    · simp [becomeAwareOfNewTerm, zero, termZero] at same

private theorem elect_result {before candidate after : NodeState}
    {sent : List Model.Envelope}
    (elected
      : (after = candidate /\ sent = [])
        \/ (candidate.role = .candidate
            /\ hasQuorum (candidate.activeConfigurations) candidate.votesGranted
            /\ Advance self (primaryState candidate) after
            /\ forall e, e ∈ sent -> LeaderStart self candidate.currentTerm after e))
    : CampaignResult self before candidate after sent := by
  rcases elected with ⟨rfl, rfl⟩ | ⟨_, quorum, advance, started⟩
  · exact Or.inl ⟨rfl, by simp⟩
  · exact Or.inr ⟨quorum, advance, fun e member => Or.inl (started e member)⟩

private theorem voteResponse_summary (before : NodeState) (source : NodeID)
    (response : RequestVoteResponse)
    : Sends
        (fun after sent =>
          Summary self before (.receive source (.requestVoteResponse response)) after
            sent)
        (receive (Capabilities.record self : Caps) self source before
          (.requestVoteResponse response)) := by
  simp only [receive]
  refine Sends.ite'
    (fun _ =>
      Sends.pure' (quiet_summary rfl rfl rfl rfl rfl rfl rfl no_bumping_sends (by simp)))
    fun _ => ?_
  rcases observe_bumping before (message := .requestVoteResponse response) trivial
    with ⟨bump, eq⟩ | ⟨le, eq⟩ <;> rw [eq] <;> simp only [handleRequestVoteResponse]
  · refine Sends.ite' (fun won => absurd won.1 (by simp [bumpedState])) fun _ =>
      Sends.pure' (bumped_summary bump (by simp [bumpedState]) (by simp [bumpedState])
        ⟨source, _, rfl, trivial, Nat.le.refl⟩ (Kind.same rfl rfl) (by simp))
  · refine Sends.ite' (fun won => ?_) fun _ =>
      Sends.pure' (quiet_summary rfl rfl rfl rfl rfl rfl rfl
        no_bumping_sends (by simp))
    have campaign : Campaign self before (.receive source (.requestVoteResponse response))
        { before with votesGranted := insert source before.votesGranted } := by
      refine ⟨won.1, rfl, rfl, Or.inr ⟨won.1, rfl, Or.inl rfl, fun voter member => ?_⟩⟩
      rcases Finset.mem_insert.mp member with rfl | old
      · exact Or.inr ⟨response, rfl, won.2.1, won.2.2⟩
      · exact Or.inl old
    exact Sends.mono (electIfQuorum_sends self _) fun after sent elected =>
      campaign_summary campaign (elect_result self elected)

private theorem preVoteResponse_summary (before : NodeState) (source : NodeID)
    (response : RequestVoteResponse)
    : Sends
        (fun after sent =>
          Summary self before (.receive source (.requestPreVoteResponse response)) after
            sent)
        (receive (Capabilities.record self : Caps) self source before
          (.requestPreVoteResponse response)) := by
  simp only [receive]
  refine Sends.ite'
    (fun _ =>
      Sends.pure' (quiet_summary rfl rfl rfl rfl rfl rfl rfl no_bumping_sends (by simp)))
    fun _ => ?_
  rcases observe_bumping before (message := .requestPreVoteResponse response) trivial
    with ⟨bump, eq⟩ | ⟨le, eq⟩ <;> rw [eq] <;> simp only [handleRequestPreVoteResponse]
  · refine Sends.ite' (fun won => absurd won.1 (by simp [bumpedState])) fun _ =>
      Sends.pure' (bumped_summary bump (by simp [bumpedState]) (by simp [bumpedState])
        ⟨source, _, rfl, trivial, Nat.le.refl⟩ (Kind.same rfl rfl) (by simp))
  · refine Sends.ite' (fun won => ?_) fun _ =>
      Sends.pure' (quiet_summary rfl rfl rfl rfl rfl rfl rfl
        no_bumping_sends (by simp))
    have engaged : Engaged before := by simp [Engaged, won.1]
    refine Sends.ite' (fun _ => ?_) fun _ =>
      Sends.pure' (quiet_summary rfl rfl rfl rfl rfl rfl rfl
        no_bumping_sends (by simp))
    exact Sends.mono (becomeCandidate_result self _ before rfl) fun after sent result =>
      campaign_summary (fresh_campaign engaged rfl rfl rfl) result

private theorem observe_response (before : NodeState) (response : AppendEntriesResponse)
    : (before.role = .primary
        /\ before.currentTerm < response.term
        /\ observeTerm before (.appendEntriesResponse response)
            = bumpedState before response.term)
      \/ ((before.role = .primary -> response.term <= before.currentTerm)
          /\ observeTerm before (.appendEntriesResponse response) = before) := by
  by_cases leader : before.role = .primary
  · by_cases bump : before.currentTerm < response.term
    · exact Or.inl ⟨leader, bump, by
        simp [observeTerm, updateTerm, becomeAwareOfNewTerm, leader, bump, bumpedState,
          Nat.ne_of_lt bump]⟩
    · exact Or.inr ⟨fun _ => Nat.not_lt.mp bump, by simp [observeTerm, updateTerm, bump]⟩
  · exact Or.inr ⟨fun yes => (leader yes).elim, by simp [observeTerm, leader]⟩

private theorem appendEntriesResponse_summary (before : NodeState) (source : NodeID)
    (response : AppendEntriesResponse)
    : Sends
        (fun after sent =>
          Summary self before (.receive source (.appendEntriesResponse response)) after
            sent)
        (receive (Capabilities.record self : Caps) self source before
          (.appendEntriesResponse response)) := by
  simp only [receive]
  refine Sends.ite'
    (fun _ =>
      Sends.pure' (quiet_summary rfl rfl rfl rfl rfl rfl rfl no_bumping_sends (by simp)))
    fun _ => ?_
  rcases observe_response before response with ⟨leader, bump, eq⟩ | ⟨le, eq⟩ <;> rw [eq] <;>
    simp only [handleAppendEntriesResponse]
  · refine Sends.ite' (fun _ => Sends.pure' ?_) fun notFollower => absurd notFollower
      (by simp [bumpedState])
    refine ⟨Nat.le_of_lt bump,
      fun same => (Nat.lt_irrefl _ (Nat.lt_of_lt_of_le bump (Nat.le_of_eq same))).elim,
      fun _ => Or.inl (by simp [Engaged, leader]), fun c => by simp [bumpedState] at c,
      fun c => by simp [bumpedState] at c, fun c => by simp [bumpedState] at c,
      Kind.same rfl rfl, by simp⟩
  · have quiet := fun (after : NodeState) (role : after.role = before.role)
        (term : after.currentTerm = before.currentTerm) (log : after.log = before.log)
        (commit : after.commitIndex = before.commitIndex)
        (voted : after.votedFor = before.votedFor)
        (votes : after.votesGranted = before.votesGranted)
        (matchEq : after.matchIndex = before.matchIndex) =>
      quiet_summary (self := self) (event := .receive source (.appendEntriesResponse response))
        (sent := []) role term log commit voted votes matchEq
        no_bumping_sends (by simp)
    refine Sends.ite' (fun _ => Sends.pure' (quiet before rfl rfl rfl rfl rfl rfl rfl))
      fun leader => ?_
    simp only [bne_iff_ne, ne_eq, Decidable.not_not] at leader
    refine Sends.ite' (fun success => ?_) fun _ =>
      Sends.pure' (quiet _ rfl rfl rfl rfl rfl rfl rfl)
    refine Sends.ite' (fun term => ?_) fun _ => Sends.pure' (quiet before rfl rfl rfl rfl rfl rfl rfl)
    refine Sends.mono (advanceCommit_sends self _) fun after sent ⟨advance, nominated⟩ => ?_
    have notCandidate : Not (after.role = .candidate) := by
      rcases advance.role with eq | eq <;> rw [eq] <;> simp [leader]
    refine ⟨Nat.le_of_eq advance.term.symm, fun _ voted eq => by rw [advance.votedFor]; exact eq,
      fun _ => Or.inl (by simp [Engaged, leader]), fun c => (notCandidate c).elim,
      fun _ => Or.inl ⟨leader, advance.term⟩, fun _ _ _ peer => ?_,
      Kind.ack source response rfl leader success term advance, fun e member => ?_⟩
    · rw [advance.matchIndex]
      by_cases same : peer = source
      · subst same
        simp only [Function.update_self]
        rcases Std.max_eq_or (a := before.matchIndex peer) (b := response.lastLogIndex) with eq | eq <;>
          rw [eq]
        · exact Or.inl rfl
        · exact Or.inr ⟨response, rfl, success, term, rfl⟩
      · exact Or.inl (by simp [Function.update, same])
    · obtain ⟨source', payload⟩ := nominated e member
      refine ⟨source', ?_⟩
      rw [payload]
      exact advance.term.symm

end Election
end Consensus.Proofs.Safety

namespace Consensus.Proofs.Safety

set_option linter.unusedSectionVars false
open Consensus.Proofs.Config Consensus.Proofs.Ledger
open CCF
open Model.Node

private theorem fromLeader_spec (self : NodeID) (state : NodeState)
    (request : AppendEntriesRequest)
    : let result := handleAppendEntiresFromPrimary self state request
      result.1.currentTerm = state.currentTerm
      /\ result.1.votedFor = state.votedFor
      /\ result.1.matchIndex = state.matchIndex
      /\ result.1.votesGranted = state.votesGranted
      /\ (result.1.role = state.role \/ result.1.role = .none)
      /\ result.1.log
          = state.log ++ request.entries.drop (state.log.length - request.prevLogIndex)
      /\ result.1.commitIndex
          = max state.commitIndex
              (maxCommittableIndexUpTo result.1.log
                (min request.primaryCommit
                  (request.prevLogIndex + request.entries.length)))
      /\ result.2
          = {
            term := state.currentTerm,
            success := true,
            lastLogIndex := request.prevLogIndex + request.entries.length
          } := by
  obtain ⟨_, _, _, eq, roleCase⟩ := Ledger.handleAppendEntiresFromPrimary_eq self state request
  simp [eq, roleCase]

private theorem aeReply (self source : NodeID) (z : NodeState)
    (r : AppendEntriesRequest) (le : r.term <= z.currentTerm)
    : Sends (AEReply self source z r)
        (handleAppendEntriesRequest (Capabilities.record self) self source z r) := by
  unfold handleAppendEntriesRequest
  dsimp only
  generalize hw : (if r.term = z.currentTerm
      /\ (z.role = Role.candidate \/ z.role = Role.preVoteCandidate) then
    becomeAwareOfNewTerm z r.term else z) = w
  have wTerm : w.currentTerm = z.currentTerm := by
    rw [← hw]; split
    · rename_i h; simp [becomeAwareOfNewTerm, h.1]
    · rfl
  have wLog : w.log = z.log := by rw [← hw]; split <;> rfl
  have wCommit : w.commitIndex = z.commitIndex := by rw [← hw]; split <;> rfl
  have wVoted : w.votedFor = z.votedFor := by
    rw [← hw]; split
    · rename_i h; simp [becomeAwareOfNewTerm, h.1]
    · rfl
  have wMatch : w.matchIndex = z.matchIndex := by rw [← hw]; split <;> rfl
  have wRole : w.role = z.role \/ w.role = .follower := by
    rw [← hw]; split <;> simp [becomeAwareOfNewTerm]
  have wCand : w.role = .candidate -> w = z := by
    rw [← hw]; split
    · simp [becomeAwareOfNewTerm]
    · intro _; rfl
  have wSame : r.term = z.currentTerm -> Not (w.role = .candidate) := by
    intro same
    rw [← hw]
    split
    · simp [becomeAwareOfNewTerm]
    · rename_i keep
      intro role
      exact keep ⟨same, by simp [role]⟩
  have common := fun (after : NodeState) (sent : List Model.Envelope)
      (rest : (after.log = z.log /\ after.commitIndex = z.commitIndex
        /\ forall e, e ∈ sent -> e.source = self /\ exists response,
          e.payload = .appendEntriesResponse response /\ response.success = false)
      \/ (r.term = z.currentTerm /\ z.commitIndex <= r.prevLogIndex
        /\ appendEntryMatchesLog z r
        /\ after.log = acceptLog z.log r
        /\ after.commitIndex = max z.commitIndex
          (maxCommittableIndexUpTo after.log
            (min r.primaryCommit (r.prevLogIndex + r.entries.length)))
        /\ exists e, sent = [e] /\ e.source = self /\ e.target = source
          /\ e.payload = .appendEntriesResponse
            { term := z.currentTerm, success := true,
              lastLogIndex := r.prevLogIndex + r.entries.length }))
      (term : after.currentTerm = w.currentTerm) (voted : after.votedFor = w.votedFor)
      (matchEq : after.matchIndex = w.matchIndex)
      (role : after.role = w.role \/ after.role = .none)
      (cand : after.role = .candidate -> after = w) =>
    (⟨term.trans wTerm, voted.trans wVoted, matchEq.trans wMatch,
      by
        rcases role with role | role <;> rw [role]
        · rcases wRole with r | r <;> simp [*]
        · simp [*],
      fun c => (cand c).trans (wCand (by
        rcases role with role | role <;> rw [role] at c
        · exact c
        · cases c)), rest⟩
      : AEReply self source z r after sent)
  refine Sends.ite' (fun reject => ?_) fun accept => ?_
  · have nack : forall payload, (exists response, payload = Message.appendEntriesResponse response
        /\ response.success = false) -> Sends (AEReply self source z r)
        (do (Capabilities.record self).send payload source; pure w
          : NodeEffect _) :=
      fun payload isNack => Sends.bind' (Sends.send _ _ _) fun _ sent eq => Sends.pure' (by
        subst eq
        refine common w _ (Or.inl ⟨wLog, wCommit, fun e member => ?_⟩) rfl rfl rfl
          (Or.inl rfl) fun _ => rfl
        simp at member
        subst member
        exact ⟨rfl, isNack⟩)
    exact Sends.ite' (fun _ => nack _ ⟨_, rfl, rfl⟩) fun _ => nack _ ⟨_, rfl, rfl⟩
  have same : r.term = z.currentTerm := Nat.le_antisymm le
    (Nat.le_trans (Nat.le_of_eq wTerm.symm) (Nat.le_of_not_lt fun lt => accept (Or.inl lt)))
  have notCand := wSame same
  refine Sends.ite'
    (fun _ =>
      Sends.pure'
        (common _ [] (Or.inl ⟨wLog, wCommit, by simp⟩)
          rfl rfl rfl (Or.inl rfl) fun c => (notCand c).elim))
    fun go => ?_
  have matches_ : appendEntryMatchesLog z r := by
    have m : appendEntryMatchesLog w r := Classical.not_not.mp (not_or.mp accept).2
    unfold appendEntryMatchesLog at m ⊢
    rw [wLog] at m
    exact m
  have commitLe : z.commitIndex <= r.prevLogIndex := by
    rw [← wCommit]
    exact Nat.le_of_not_lt fun lt => go (Or.inl lt)
  have tail : forall v : NodeState,
      v.log
          = (match conflictIndex z.log r with
            | some index => z.log.take (index - 1)
            | none => z.log)
      -> v.currentTerm = w.currentTerm -> v.commitIndex = w.commitIndex
      -> v.votedFor = w.votedFor -> v.matchIndex = w.matchIndex -> v.role = w.role
      -> Sends (AEReply self source z r)
          (do
            let (state, response) := handleAppendEntiresFromPrimary self v r
            (Capabilities.record self).send (.appendEntriesResponse response) source
            return state : NodeEffect _) := by
    intro v vLog vTerm vCommit vVoted vMatch vRole
    have spec := fromLeader_spec self v r
    obtain ⟨⟨result, reply⟩, hres⟩ : exists p, handleAppendEntiresFromPrimary self v r = p :=
      ⟨_, rfl⟩
    simp only [hres] at spec ⊢
    obtain ⟨term, voted, matchEq, _, role, log, commit, response⟩ := spec
    refine Sends.bind' (Sends.send _ _ _) fun _ sent eq => Sends.pure' ?_
    subst eq
    refine common _ _ (Or.inr ⟨same, commitLe, matches_, ?_, ?_, _, rfl, rfl, rfl, ?_⟩)
      (term.trans vTerm) (voted.trans vVoted) (matchEq.trans vMatch) (vRole ▸ role) fun c => by
        rcases role with role | role <;> rw [role] at c
        · exact (notCand (vRole ▸ c)).elim
        · cases c
    · rw [log, vLog]
      rfl
    · rw [commit, vCommit, wCommit]
    · rw [response, vTerm, wTerm]
  have conflictEq : firstTermConflictIndex { w with primaryKnown := true } r
      = conflictIndex z.log r := by
    rw [firstTermConflictIndex_eq]
    simp only [wLog]
  split
  · rename_i heq
    rw [conflictEq] at heq
    exact tail _ (by simp only [heq]; exact wLog) rfl rfl rfl rfl rfl
  · rename_i index heq
    rw [conflictEq] at heq
    exact tail _ (by simp only [heq, wLog]) rfl rfl rfl rfl rfl

private theorem aeReply_summary {self source : NodeID} {before z after : NodeState}
    {request : AppendEntriesRequest} {sent : List Model.Envelope}
    (log : z.log = before.log) (commit : z.commitIndex = before.commitIndex)
    (termLe : before.currentTerm <= z.currentTerm)
    (reply : AEReply self source z request after sent)
    : Kind self before (.receive source (.appendEntriesRequest request)) after
      /\ forall e,
          e ∈ sent
          -> SendOK self before (.receive source (.appendEntriesRequest request)) after
              e := by
  obtain ⟨term, _, _, _, _, rest⟩ := reply
  rcases rest with ⟨log', commit', nacks⟩ | ⟨same, commitLe, matches_, accepted, committed, e,
    rfl, source', _, payload⟩
  · refine ⟨Kind.same (log'.trans log) (commit'.trans commit), fun e member => ?_⟩
    obtain ⟨source', response, payload, failed⟩ := nacks e member
    refine ⟨source', ?_⟩
    rw [payload]
    intro success
    rw [failed] at success
    cases success
  · have acceptedBy : Accepted before request after := by
      unfold appendEntryMatchesLog at matches_
      rw [log] at matches_
      refine ⟨same.trans term.symm, same ▸ termLe, commit ▸ commitLe, matches_.1, matches_.2,
        log ▸ accepted, ?_⟩
      rw [committed, commit]
    refine ⟨Kind.accept source request rfl acceptedBy, fun e' member => ?_⟩
    simp only [List.mem_singleton] at member
    subst member
    refine ⟨source', ?_⟩
    rw [payload]
    exact fun _ => ⟨source, request, rfl, acceptedBy, term.symm, rfl⟩

private theorem appendEntriesRequest_summary (self : NodeID) (before : NodeState)
    (source : NodeID) (request : AppendEntriesRequest)
    : Sends
        (fun after sent =>
          Summary self before (.receive source (.appendEntriesRequest request)) after
            sent)
        (receive (Capabilities.record self) self source before
          (.appendEntriesRequest request)) := by
  simp only [receive]
  rcases observe_bumping before (message := .appendEntriesRequest request) trivial
    with ⟨bump, eq⟩ | ⟨le, eq⟩ <;> rw [eq]
  · refine Sends.mono (aeReply self source _ request (Nat.le.refl)) fun after sent reply => ?_
    obtain ⟨kind, sends⟩ := aeReply_summary (before := before) (z := bumpedState before request.term) rfl rfl
      (Nat.le_of_lt bump) reply
    obtain ⟨term, _, _, role, _, _⟩ := reply
    have follower : after.role = .follower \/ after.role = .none := by
      rcases role with eq | eq | eq <;> rw [eq] <;> simp [bumpedState]
    exact bumped_summary (term ▸ bump) (by rcases follower with f | f <;> simp [f])
      (by rcases follower with f | f <;> simp [f])
      ⟨source, _, rfl, trivial, term ▸ Nat.le.refl⟩ kind sends
  · refine Sends.mono (aeReply self source _ request le) fun after sent reply => ?_
    obtain ⟨kind, sends⟩ := aeReply_summary (before := before) rfl rfl Nat.le.refl reply
    obtain ⟨term, voted, matchEq, role, cand, _⟩ := reply
    refine ⟨Nat.le_of_eq term.symm, fun _ voted' eq => voted ▸ eq,
      fun _ => Or.inr (Or.inr (Or.inl ⟨source, _, rfl, trivial, term ▸ le⟩)), fun c => ?_,
      fun leader => ?_, fun _ _ _ peer => Or.inl (congrFun matchEq peer), kind, sends⟩
    · have eq := cand c
      rw [eq] at c ⊢
      exact ⟨c, rfl, rfl, Or.inr ⟨c, rfl, Or.inl rfl, fun voter member => Or.inl member⟩⟩
    · rcases role with eq | eq | eq
      · exact Or.inl ⟨eq ▸ leader, term⟩
      · rw [eq] at leader; cases leader
      · rw [eq] at leader; cases leader

private theorem BatchState.push {self : NodeID} {before state : NodeState}
    {sent : List Model.Envelope} (batch : BatchState self before state sent)
    (content : EntryContent)
    : BatchState self before
        { state with log := state.log ++ [{ term := state.currentTerm, content }] }
        sent := by
  obtain ⟨⟨entries, sentIndex, rfl, terms⟩, beats⟩ := batch
  refine ⟨
    ⟨entries ++ [{ term := before.currentTerm, content }], sentIndex, by simp, ?_⟩,
    fun e member => (beats e member).extend (List.prefix_append _ _) Nat.le.refl
  ⟩
  intro entry member
  rcases List.mem_append.mp member with old | new
  · exact terms entry old
  · simp at new; rw [new]

private theorem appendEntry_batch (self : NodeID) (before : NodeState)
    (state : NodeState) (sent : List Model.Envelope)
    (content : EntryContent) (batch : BatchState self before state sent)
    : Sends (fun next later => BatchState self before next (sent ++ later))
        (appendEntry (Capabilities.record self) self state content) := by
  unfold appendEntry
  simp only [pure_bind]
  repeat'
    first
    | refine Sends.ite' (fun _ => ?_) fun _ => ?_
    | refine Sends.guard_bind fun _ => ?_
  all_goals
    split
    · exact Sends.pure' (by simpa using batch.push content)
    · rename_i nodes _
      refine Sends.guard_bind fun _ => ?_
      obtain ⟨⟨entries, sentIndex, rfl, terms⟩, beats⟩ := batch
      refine Sends.bind'
        (Sends.forIn' (R := AEFrom self before.currentTerm before.commitIndex
          (before.log ++ entries)) fun peer _ member => ?_)
        fun _ later sentBeats => Sends.pure' ?_
      · refine Sends.bind' (Sends.send _ _ _) fun _ sent eq => Sends.pure' fun e member' => ?_
        simp only [eq, List.append_nil, List.mem_singleton] at member'
        subst member'
        have added := Finset.mem_sort.mp member
        have other : Not (peer = self) := (Finset.mem_erase.mp added).1
        refine ⟨rfl, other, _, rfl, rfl, ?_, ?_, ?_, Nat.le.refl⟩ <;>
          simp only [makeAppendEntriesRequest, ite_eq_left added, messageEntries] <;> simp
      · have batch : BatchState self before
            { before with
                log := before.log ++ entries
                sentIndex := fun peer =>
                  if peer ∈ (nodes \ eligiblePeers
                      { before with log := before.log ++ entries, sentIndex } self).erase self
                  then (before.log ++ entries).length else sentIndex peer }
            (sent ++ later) :=
          ⟨⟨entries, _, rfl, terms⟩, fun e member => by
            rcases List.mem_append.mp member with old | new
            · exact beats e old
            · exact sentBeats e new⟩
        simpa using batch.push content

private theorem sendEntries_batch (self : NodeID) (before state : NodeState)
    (sent : List Model.Envelope) (destination : NodeID) (endIndex : Nat)
    (batch : BatchState self before state sent)
    : Sends (fun next later => BatchState self before next (sent ++ later))
        (sendEntries (Capabilities.record self) self state destination endIndex) := by
  unfold sendEntries
  refine Sends.guard_bind fun ⟨_, peer, le, bound, _⟩ => ?_
  refine Sends.bind' (Sends.send _ _ _) fun _ later eq => Sends.pure' ?_
  obtain ⟨⟨entries, sentIndex, rfl, terms⟩, packets⟩ := batch
  refine ⟨⟨entries, _, rfl, terms⟩, fun e member => ?_⟩
  simp only [List.append_nil] at member
  rcases List.mem_append.mp member with old | new
  · exact packets e old
  · simp only [eq, List.mem_singleton] at new
    subst e
    have other : Not (destination = self) := (Finset.mem_erase.mp peer).1
    exact ⟨rfl, other, _, rfl, rfl, Nat.le_trans le bound, rfl, List.take_prefix _ _, Nat.le.refl⟩

private theorem appendBatch_summary (self : NodeID) (state : NodeState)
    (contents : List AppendEntryInput)
    : Sends
        (fun after sent => Summary self state (.internal (.append contents)) after sent)
        (act (Capabilities.record self) self state (.append contents)) := by
  simp only [act]
  unfold appendBatch
  refine Sends.bind' Sends.guard' fun _ sent ⟨⟨leader, _⟩, empty⟩ => ?_
  subst empty
  have start : BatchState self state state [] :=
    ⟨⟨[], state.sentIndex, by simp, by simp⟩, by simp⟩
  refine Sends.bind' (Sends.mono (Sends.foldlM' (I := BatchState self state)
      (fun value sent' item batch =>
        Sends.bind' (appendEntry_batch self state value sent' item.content batch)
          fun appended later kept =>
            (Sends.foldlM'
              (fun value sent' (destination, endIndex) batch =>
                sendEntries_batch self state value sent' destination endIndex batch)
              item.flushes appended (sent' ++ later) kept).mono
              fun _ _ done => by simpa [List.append_assoc] using done)
      contents state [] start) fun _ _ done => by simpa using done)
    fun appended sent batch => ?_
  refine Sends.mono (advanceCommit_sends self appended)
    fun after later ⟨advance, nominated⟩ => ?_
  obtain ⟨⟨entries, sentIndex, eq, terms⟩, beats⟩ := batch
  have term : after.currentTerm = state.currentTerm := by rw [advance.term, eq]
  have log : after.log = appended.log := advance.log
  have role : after.role = .primary \/ after.role = .none := by
    rcases advance.role with r | r
    · rw [r, eq]; exact Or.inl leader
    · exact Or.inr r
  have commit : state.commitIndex <= after.commitIndex := by
    have := advance.commit_le; rw [eq] at this; exact this
  refine ⟨
    Nat.le_of_eq term.symm,
    fun _ voted votedEq => by rw [advance.votedFor, eq]; exact votedEq,
    fun _ => Or.inl (by simp [Engaged, leader]),
    fun c => by rcases role with r | r <;> simp [r] at c,
    fun _ => Or.inl ⟨leader, term⟩,
    fun _ _ _ peer => Or.inl (by rw [advance.matchIndex, eq]),
    Kind.append entries sentIndex leader terms (eq ▸ advance),
    fun e member => ?_
  ⟩
  rcases List.mem_append.mp (by simpa using member) with old | new
  · have from_ : AEFrom self after.currentTerm after.commitIndex after.log e :=
      term ▸ (beats e old).extend (log ▸ List.prefix_refl _) commit
    obtain ⟨request, payload, ok⟩ := from_.ok
    refine ⟨from_.1, ?_⟩
    rw [payload]
    exact ⟨ok, by rcases role with r | r <;> simp [r], Or.inl ⟨leader, term⟩⟩
  · obtain ⟨source, payload⟩ := nominated e new
    refine ⟨source, ?_⟩
    rw [payload]
    show appended.currentTerm = after.currentTerm
    rw [advance.term]

/-- Every local step satisfies the step summary. -/
private theorem summary (self : NodeID) (before : NodeState) (event : Event)
    : Sends (fun after sent => Summary self before event after sent)
        (Model.Node.step (Capabilities.record self) self before event) := by
  cases event with
  | internal input =>
      cases input with
      | append contents => exact appendBatch_summary self before contents
      | sendEntries destination endIndex =>
          exact sendEntries_summary self before destination endIndex
      | timeout kind =>
          cases kind with
          | election => exact startElection_summary self before
          | checkQuorum => exact checkQuorum_summary self before _
      | nominateSuccessor => exact nominate_summary self before
      | initAsBackup entries => exact initAsBackup_summary self before entries
  | receive source message =>
      cases message with
      | appendEntriesRequest request =>
          exact appendEntriesRequest_summary self before source request
      | appendEntriesResponse response =>
          exact appendEntriesResponse_summary self before source response
      | requestVoteRequest request => exact voteRequest_summary self before source request
      | requestVoteResponse response =>
          exact voteResponse_summary self before source response
      | requestPreVoteRequest request =>
          exact preVoteRequest_summary self before source request
      | requestPreVoteResponse response =>
          exact preVoteResponse_summary self before source response
      | proposeRequestVoteRequest term =>
          exact proposeVote_summary self before source term

private theorem LocalTransition.summary {before after : Model.State}
    (transition : LocalTransition before after)
    : Summary transition.actor transition.pre transition.event transition.post
        transition.outputs.outgoing := by
  obtain ⟨new, eq, holds⟩ := Safety.summary transition.actor transition.pre transition.event {}
    _ _ transition.ran
  simpa [eq] using holds

end Consensus.Proofs.Safety

namespace Consensus.Proofs.Safety

set_option linter.unusedSectionVars false
open CCF
open Model.Node
variable [Config.InitialConfiguration]
section Mono
variable {history later : History}

private theorem Seen.mono (suffix : history <:+ later) {node : NodeID} {state : NodeState}
    (seen : Seen history node state)
    : Seen later node state := by
  obtain ⟨current, member, mem⟩ := seen
  exact ⟨current, suffix.subset member, mem⟩

private theorem Granted.mono (suffix : history <:+ later) {voter candidate : NodeID}
    {term : Nat} {request : RequestVoteRequest}
    (granted : Granted history voter candidate term request)
    : Granted later voter candidate term request := by
  obtain ⟨after, before, rest, inner, step, seen⟩ := granted
  exact ⟨after, before, rest, inner.trans suffix, step, seen⟩

private theorem Elected.mono (suffix : history <:+ later) {node : NodeID}
    {term commit : Nat} {log : List Entry}
    (elected : Elected history node term log commit)
    : Elected later node term log commit := by
  obtain ⟨after, before, rest, inner, step⟩ := elected
  exact ⟨after, before, rest, inner.trans suffix, step⟩

private theorem Led.mono (suffix : history <:+ later) {node : NodeID} {term : Nat}
    (led : Led history node term)
    : Led later node term := by
  rcases led with bootstrap | ⟨log, commit, elected⟩
  · exact Or.inl bootstrap
  · exact Or.inr ⟨log, commit, elected.mono suffix⟩

private theorem Canon.mono (suffix : history <:+ later) {term : Nat}
    {log : List Entry} (canon : Canon history term log)
    : Canon later term log := by
  obtain ⟨earlier, inner, rest⟩ := canon
  exact ⟨earlier, inner.trans suffix, rest⟩

private theorem Committed.append {term : Nat} {part : List Entry}
    (committed : Committed history term part) (front : History)
    : Committed (front ++ history) term part := by
  induction front with
  | nil => exact committed
  | cons _ _ ih => exact .past ih

private theorem Committed.mono (suffix : history <:+ later) {term : Nat}
    {part : List Entry} (committed : Committed history term part)
    : Committed later term part := by
  obtain ⟨front, rfl⟩ := suffix
  exact committed.append front

private theorem SnapOK.mono (suffix : history <:+ later) {entries : List Entry}
    (ok : SnapOK history entries)
    : SnapOK later entries := by
  obtain ⟨positive, signature, ⟨log, canon, inLog⟩, term, part, committed, inPart⟩ := ok
  exact ⟨positive, signature, ⟨log, canon.mono suffix, inLog⟩, term, part,
    committed.mono suffix, inPart⟩

private theorem Backed.mono (suffix : history <:+ later) {log : List Entry}
    {commit term : Nat} (backed : Backed history log commit term)
    : Backed later log commit term := by
  rcases backed with zero | ⟨earlier, part, committed, le, within⟩
  · exact Or.inl zero
  · exact Or.inr ⟨earlier, part, committed.mono suffix, le, within⟩

private theorem Backed.weaken {log : List Entry} {commit term term' : Nat}
    (backed : Backed history log commit term) (le : term <= term')
    : Backed history log commit term' := by
  rcases backed with zero | ⟨earlier, part, committed, le', within⟩
  · exact Or.inl zero
  · exact Or.inr ⟨earlier, part, committed, Nat.le_trans le' le, within⟩

private theorem Acked.mono (suffix : history <:+ later) {voter : NodeID}
    {term index : Nat} (acked : Acked history voter term index)
    : Acked later voter term index := by
  obtain ⟨acker, log, seen, termEq, canon, bound, sub⟩ := acked
  exact ⟨acker, log, seen.mono suffix, termEq, canon.mono suffix, bound, sub⟩

private theorem Bad.mono (suffix : history <:+ later) {part : List Entry}
    {term bound : Nat} (bad : Bad history part term bound)
    : Bad later part term bound := by
  obtain ⟨term', log, lt, le, canon, missing⟩ := bad
  exact ⟨term', log, lt, le, canon.mono suffix, missing⟩

end Mono
end Consensus.Proofs.Safety

namespace Consensus.Proofs.Safety

set_option linter.unusedSectionVars false
open CCF
open Model.Node
variable [Config.InitialConfiguration]

private theorem Now.seen {history : History} {node : NodeID} {state : NodeState}
    (now : Now history node state)
    : Seen history node state := by
  cases history with
  | nil => exact absurd now id
  | cons current rest => exact ⟨current, List.mem_cons_self, now⟩

private theorem Seen.cons {current : Model.State} {rest : History}
    {node : NodeID} {state : NodeState} (seen : Seen (current :: rest) node state)
    : (node, state) ∈ current.nodes \/ Seen rest node state := by
  obtain ⟨state', member, mem⟩ := seen
  rcases List.mem_cons.mp member with rfl | inner
  · exact Or.inl mem
  · exact Or.inr ⟨state', inner, mem⟩

/-- Two suffixes of one list are comparable. -/
private theorem suffix_comparable {α : Type} {first second whole : List α}
    (left : first <:+ whole) (right : second <:+ whole)
    : first <:+ second \/ second <:+ first := by
  rcases Nat.le_total first.length second.length with le | le
  · exact Or.inl (List.suffix_of_suffix_length_le left right le)
  · exact Or.inr (List.suffix_of_suffix_length_le right left le)

end Consensus.Proofs.Safety

namespace Consensus.Proofs.Safety

set_option linter.unusedSectionVars false
open CCF
open Model.Node
open Consensus.Proofs.Config
open Model (initialNodeState BOOTSTRAP_TERM)
variable [Config.InitialConfiguration]
section Initial

private theorem initialNodeState_eq (nonempty : INITIAL_CONFIGURATION.Nonempty)
    (node : NodeID)
    : initialNodeState INITIAL_CONFIGURATION node = initialLocal node := by
  simp only [initialNodeState, initialLocal, initial_primary_iff nonempty]

end Initial
end Consensus.Proofs.Safety

namespace Consensus.Proofs.Safety

set_option linter.unusedSectionVars false
open CCF
open Model.Node
open Consensus.Proofs.Config
open Model (initialNodeState BOOTSTRAP_TERM)
variable [Config.InitialConfiguration]
section Initial
variable {nodes : List NodeID} {initial : Model.State}
  (initialized : (Model.transitionSystem Config.INITIAL_CONFIGURATION nodes).init initial)
include initialized

private theorem initial_state {node : NodeID} {state : NodeState}
    (member : (node, state) ∈ initial.nodes)
    : state = initialLocal node := by
  rw [← initialNodeState_eq initialized.1]
  exact initialized.2.2.2.2 _ member

private theorem initial_seen {node : NodeID} {state : NodeState}
    (seen : Seen [initial] node state)
    : state = initialLocal node := by
  obtain ⟨current, member, mem⟩ := seen
  rw [List.mem_singleton.mp member] at mem
  exact initial_state initialized mem

omit initialized in
private theorem not_elected_single {current : Model.State} {node : NodeID}
    {term commit : Nat} {log : List Entry}
    : Not (Elected [current] node term log commit) := by
  rintro ⟨after, before, rest, suffix, -⟩
  have := suffix.length_le
  simp at this

omit initialized in
private theorem led_single {current : Model.State} {node : NodeID} {term : Nat}
    (led : Led [current] node term)
    : term = BOOTSTRAP_TERM /\ node = INITIAL_PRIMARY := by
  rcases led with bootstrap | ⟨log, commit, elected⟩
  · exact bootstrap
  · exact absurd elected not_elected_single

private theorem initial_canon {term : Nat} {log : List Entry}
    (canon : Canon [initial] term log)
    : term = BOOTSTRAP_TERM /\ log = (initialLocal INITIAL_PRIMARY).log := by
  obtain ⟨earlier, suffix, node, state, ⟨now, termEq, -, led⟩, rfl⟩ := canon
  rcases List.suffix_cons_iff.mp suffix with rfl | inner
  · obtain ⟨bootstrap, rfl⟩ := led_single led
    exact ⟨bootstrap, by rw [initial_state initialized now]⟩
  · rw [List.eq_nil_of_suffix_nil inner] at now
    exact absurd now id

private theorem inv_initial : Inv [initial] := by
  have leaderMem := INITIAL_PRIMARY_mem initialized.1
  have stateOf : forall {node : NodeID} {state : NodeState},
      Now [initial] node state -> state = initialLocal node :=
    fun now => initial_state initialized now
  constructor
  · intro node state now entry member
    rw [stateOf now] at member ⊢
    by_cases leader : node = INITIAL_PRIMARY
    · subst leader
      simp_all [initialLocal]
    · simp [initialLocal, leader] at member
  · intro node state now
    rw [stateOf now]
    unfold initialLocal
    split <;> simp
  · intro node state now active
    rw [stateOf now] at active ⊢
    simp only [Engaged, initialLocal] at active ⊢
    by_cases primary : node = INITIAL_PRIMARY <;> by_cases member : node ∈ INITIAL_CONFIGURATION
      <;> simp_all [BOOTSTRAP_TERM]
  · intro node state earlier now seen
    rw [stateOf now, initial_seen initialized seen]
    exact Nat.le_refl _
  · intro node state earlier candidate now seen voted
    rw [initial_seen initialized seen] at voted
    simp [initialLocal] at voted
  · intro node state term now led
    obtain ⟨rfl, rfl⟩ := led_single led
    rw [stateOf now]
    right
    simp [initialLocal, leaderMem]
  · intro node state now leader
    left
    rw [stateOf now] at leader ⊢
    by_cases isLeader : node = INITIAL_PRIMARY
    · subst isLeader
      simp [initialLocal, leaderMem]
    · simp only [initialLocal, isLeader, ite_false] at leader
      split at leader <;> cases leader
  · intro node state now candidate
    rw [stateOf now] at candidate
    simp only [initialLocal] at candidate
    by_cases primary : node = INITIAL_PRIMARY <;> by_cases member : node ∈ INITIAL_CONFIGURATION
      <;> simp [primary, member] at candidate
  · intro after before rest node term log commit suffix
    have := suffix.length_le
    simp at this
  · intro node other term left right
    rw [(led_single left).2, (led_single right).2]
  · intro node state now _ led
    obtain ⟨-, rfl⟩ := led_single led
    refine ⟨fun log canon => ?_, fun log commit elected => absurd elected not_elected_single⟩
    rw [(initial_canon initialized canon).2, stateOf now]
    exact List.prefix_refl _
  · intro node state index now positive bound
    rw [stateOf now] at bound ⊢
    by_cases isLeader : node = INITIAL_PRIMARY
    · subst isLeader
      have one : index = 1 := by
        simp [initialLocal] at bound
        exact Nat.le_antisymm bound (Nat.succ_le_of_lt positive)
      subst one
      refine ⟨_, ⟨[initial], List.suffix_refl _, _, _,
        ⟨now, ?_, ?_, Or.inl ⟨?_, rfl⟩⟩, rfl⟩, ?_, ?_⟩
      · rw [stateOf now]
        simp [initialLocal, leaderMem, BOOTSTRAP_TERM, termAt, entryAt?]
      · rw [stateOf now]
        simp [initialLocal]
      · simp [initialLocal, BOOTSTRAP_TERM, termAt, entryAt?]
      · rw [stateOf now]
        exact bound
      · rw [stateOf now]
    · simp [initialLocal, isLeader] at bound
      exact absurd (Nat.lt_of_lt_of_le positive (Nat.le_of_eq bound)) (Nat.lt_irrefl 0)
  · intro term part node later log commit _ elected
    exact absurd elected not_elected_single
  · intro node state now
    have zero : state.commitIndex = 0 := by rw [stateOf now]; rfl
    exact ⟨⟨0, Or.inl zero⟩, fun _ _ => Or.inl zero⟩
  · intro node state earlier index now seen _
    left
    rw [stateOf now, initial_seen initialized seen]
    exact List.take_prefix _ _
  · intro node state peer now _ _ positive
    rw [stateOf now] at positive
    simp [initialLocal] at positive
  · intro envelope pending
    simp [Pending, initialized.2.2.2.1] at pending
  · intro envelope pending
    simp [Pending, initialized.2.2.2.1] at pending
  · intro node state now
    rw [stateOf now]
    by_cases isLeader : node = INITIAL_PRIMARY
    · subst isLeader
      exact Or.inr (by simp [initialLocal])
    · exact Or.inl (by simp [initialLocal, isLeader])
  · intro node state now leader
    rw [stateOf now] at leader ⊢
    by_cases isLeader : node = INITIAL_PRIMARY
    · subst isLeader
      simp [initialLocal]
    · simp only [initialLocal, isLeader, ite_false] at leader
      split at leader <;> cases leader

end Initial
end Consensus.Proofs.Safety

namespace Consensus.Proofs.Safety

set_option linter.unusedSectionVars false
open CCF
open Model.Node
open Consensus.Proofs.Ledger
variable [Config.InitialConfiguration]
section Everywhere
variable {clause : History -> Prop} {history : History}

private theorem Everywhere.cons {current : Model.State}
    (old : Everywhere clause history) (now : clause (current :: history))
    : Everywhere clause (current :: history) := by
  intro earlier suffix nonempty
  rcases List.suffix_cons_iff.mp suffix with rfl | inner
  · exact now
  · exact old earlier inner nonempty

private theorem Everywhere.suffix (all : Everywhere clause history) {earlier : History}
    (suffix : earlier <:+ history)
    : Everywhere clause earlier :=
  fun inner within nonempty => all inner (within.trans suffix) nonempty

private theorem Good.everywhere (good : Good history)
    (project : forall {h}, Inv h -> clause h)
    : Everywhere clause history :=
  fun earlier suffix nonempty => project (good earlier suffix nonempty)

end Everywhere
end Consensus.Proofs.Safety

namespace Consensus.Proofs.Safety

set_option linter.unusedSectionVars false
open CCF
open Model.Node
open Consensus.Proofs.Ledger
variable [Config.InitialConfiguration]
section Exec
variable {nodes : List NodeID}

private theorem Now.nonempty {history : History} {node : NodeID}
    {state : NodeState} (now : Now history node state)
    : exists current rest, history = current :: rest := by
  cases history with
  | nil => exact absurd now id
  | cons current rest => exact ⟨current, rest, rfl⟩

private theorem now_unique {history : History} (exec : Exec nodes history) {node : NodeID}
    {first second : NodeState} (left : Now history node first)
    (right : Now history node second)
    : first = second := by
  obtain ⟨current, rest, rfl⟩ := left.nonempty
  exact state_unique (exec.keys List.mem_cons_self) left right

/-- A state seen in a history is the current state of one of its suffixes. -/
private theorem Seen.now {history : History} {node : NodeID} {state : NodeState}
    (seen : Seen history node state)
    : exists earlier, earlier <:+ history /\ Now earlier node state := by
  obtain ⟨current, member, mem⟩ := seen
  obtain ⟨front, back, split⟩ := List.append_of_mem member
  exact ⟨current :: back, ⟨front, split.symm⟩, mem⟩

private theorem Seen.frontier {history : History} (exec : Exec nodes history)
    {node : NodeID} {state : NodeState} (seen : Seen history node state)
    : Direct.CommitFrontier state := by
  obtain ⟨current, member, mem⟩ := seen
  obtain ⟨front, back, split⟩ := List.append_of_mem member
  have tail : Exec nodes (current :: back) := exec.suffix ⟨front, split.symm⟩ (by simp)
  exact Direct.commitFrontier_invariant.reachable tail.reachable node state mem

private theorem Seen.commit_le {history : History} (exec : Exec nodes history)
    {node : NodeID} {state : NodeState} (seen : Seen history node state)
    : state.commitIndex <= state.log.length :=
  (seen.frontier exec).1

end Exec
end Consensus.Proofs.Safety

namespace Consensus.Proofs.Safety

set_option linter.unusedSectionVars false
open CCF
open Model.Node
open Consensus.Proofs.Ledger
variable [Config.InitialConfiguration]

private theorem termAt_mono {log : List Entry}
    (sorted : log.Pairwise fun first second => first.term <= second.term) {i j : Nat}
    (le : i <= j) (bound : j <= log.length)
    : termAt log i <= termAt log j := by
  rcases Nat.eq_zero_or_pos i with rfl | positive
  · rw [termAt_zero]
    exact Nat.zero_le _
  rw [termAt_eq positive (Nat.le_trans le bound), termAt_eq (Nat.lt_of_lt_of_le positive le) bound]
  rcases Nat.eq_or_lt_of_le le with rfl | lt
  · exact Nat.le.refl
  · exact List.pairwise_iff_getElem.mp sorted _ _ _ _
      (Nat.sub_lt_sub_right (Nat.succ_le_of_lt positive) lt)

private theorem termAt_le_of_mem {log : List Entry} {bound : Nat}
    (terms : forall entry, entry ∈ log -> entry.term <= bound) (index : Nat)
    : termAt log index <= bound := by
  unfold termAt
  cases found : entryAt? log index with
  | none => exact Nat.zero_le _
  | some entry => exact terms entry (entryAt_mem found)

private theorem signature_pos {log : List Entry} {index : Nat}
    (signature : isSignatureAt log index = true)
    : 0 < index := by
  rcases Nat.eq_zero_or_pos index with rfl | positive
  · simp [isSignatureAt, entryAt?] at signature
  · exact positive

private theorem signature_bound {log : List Entry} {index : Nat}
    (signature : isSignatureAt log index = true)
    : index <= log.length := by
  obtain ⟨entry, found, _⟩ := isSignatureAtTrue signature
  exact entryAtSomeIndexBound found

/-- The winning prefix `log.take (maxCommittableIndex log)` contains every
prefix of `log` ending in a signature. -/
private theorem prefix_committable {part log : List Entry} (sub : part <+: log)
    (signature : isSignatureAt part part.length = true)
    : part <+: log.take (maxCommittableIndex log) := by
  have le := signatureIndex_le_maxCommittableIndex (isSignatureAt_of_prefix sub signature)
  rw [List.prefix_iff_eq_take.mp sub]
  exact take_prefix_take log le

private theorem take_signature {log : List Entry} {index : Nat}
    (signature : isSignatureAt log index = true)
    : isSignatureAt (log.take index) (log.take index).length = true := by
  rw [List.length_take, Nat.min_eq_left (signature_bound signature)]
  exact isSignatureAt_take_of_le Nat.le.refl signature

private theorem Led.two_le {history : History} {node : NodeID} {term : Nat}
    (led : Led history node term)
    : 2 <= term := by
  rcases led with ⟨rfl, -⟩ | ⟨log, commit, after, before, rest, -, candidate, leader, -, -, -,
    -, -, -, -, -, -, three, -⟩
  · decide
  · exact Nat.le_trans (Nat.le_succ 2) three

private theorem Led.elected {history : History} {node : NodeID} {term : Nat}
    (led : Led history node term) (above : 2 < term)
    : exists log commit, Elected history node term log commit := by
  rcases led with ⟨rfl, -⟩ | elected
  · exact absurd above (by decide)
  · exact elected

/-- Logs of leaders of one term form a chain. -/
private theorem canon_chain {history : History} (mono : Everywhere CanonMono history)
    {term : Nat} {first second : List Entry} (left : Canon history term first)
    (right : Canon history term second)
    : first <+: second \/ second <+: first := by
  obtain ⟨early, earlySuffix, earlyNode, earlyState,
    ⟨earlyNow, earlyTerm, earlyRole, earlyLed⟩, rfl⟩ := left
  obtain ⟨late, lateSuffix, lateNode, lateState,
    ⟨lateNow, lateTerm, lateRole, lateLed⟩, rfl⟩ := right
  have contains : forall {inner outer : History} {innerNode outerNode : NodeID}
      {innerState outerState : NodeState},
      inner <:+ outer -> outer <:+ history
      -> Now inner innerNode innerState -> innerState.currentTerm = term
      -> Not (innerState.role = .candidate) -> Led inner innerNode term
      -> Now outer outerNode outerState -> outerState.currentTerm = term
      -> Not (outerState.role = .candidate) -> Led outer outerNode term
      -> innerState.log <+: outerState.log := by
    intro inner outer innerNode outerNode innerState outerState within outerSuffix
      innerNow innerTerm innerRole innerLed outerNow outerTerm outerRole outerLed
    obtain ⟨current, rest, rfl⟩ := outerNow.nonempty
    have clause := mono _ outerSuffix (List.cons_ne_nil _ _)
    refine (clause outerNode outerState outerNow outerRole (outerTerm ▸ outerLed)).1 _ ?_
    rw [outerTerm]
    exact ⟨inner, within, innerNode, innerState, ⟨innerNow, innerTerm, innerRole, innerLed⟩,
      rfl⟩
  rcases suffix_comparable earlySuffix lateSuffix with within | within
  · exact Or.inl (contains within lateSuffix earlyNow earlyTerm earlyRole earlyLed lateNow
      lateTerm lateRole lateLed)
  · exact Or.inr (contains within earlySuffix lateNow lateTerm lateRole lateLed earlyNow
      earlyTerm earlyRole earlyLed)

/-- Two seen logs agreeing on the term at `index` agree up to `index`. -/
private theorem log_matching {history : History} (anchor : Everywhere Anchor history)
    (mono : Everywhere CanonMono history) {node other : NodeID}
    {first second : NodeState} (left : Seen history node first)
    (right : Seen history other second) {index : Nat} (positive : 0 < index)
    (leftBound : index <= first.log.length) (rightBound : index <= second.log.length)
    (same : termAt first.log index = termAt second.log index)
    : first.log.take index = second.log.take index := by
  obtain ⟨leftHistory, leftSuffix, leftNow⟩ := left.now
  obtain ⟨rightHistory, rightSuffix, rightNow⟩ := right.now
  obtain ⟨_, _, rfl⟩ := leftNow.nonempty
  obtain ⟨_, _, rfl⟩ := rightNow.nonempty
  obtain ⟨leftLog, leftCanon, leftLength, leftTake⟩ :=
    anchor _ leftSuffix (List.cons_ne_nil _ _) node first index leftNow positive leftBound
  obtain ⟨rightLog, rightCanon, rightLength, rightTake⟩ :=
    anchor _ rightSuffix (List.cons_ne_nil _ _) other second index rightNow positive
      rightBound
  rw [same] at leftCanon
  rw [leftTake, rightTake]
  exact take_eq_take_of_comparable
    (canon_chain mono (leftCanon.mono leftSuffix) (rightCanon.mono rightSuffix))
    leftLength rightLength

/-- A voter grants at most one candidate per term. -/
private theorem vote_unique {nodes : List NodeID} {history : History}
    (exec : Exec nodes history) (record : Everywhere VoteRecord history)
    {voter first second : NodeID} {term : Nat}
    {firstRequest secondRequest : RequestVoteRequest}
    (left : Granted history voter first term firstRequest)
    (right : Granted history voter second term secondRequest)
    : first = second := by
  have ordered : forall {early late : NodeID} {earlyRequest lateRequest : RequestVoteRequest},
      Granted history voter early term earlyRequest
      -> Granted history voter late term lateRequest
      -> (forall a b r a' b' r', a :: b :: r <:+ history -> a' :: b' :: r' <:+ history
          -> GrantStep a b voter early term earlyRequest
          -> GrantStep a' b' voter late term lateRequest
          -> a :: b :: r <:+ a' :: b' :: r' -> early = late) := by
    intro early late _ _ _ _ a b r a' b' r' suffix suffix' step step' within
    obtain ⟨granting, granted, grantingMem, grantedMem, _, grantedTerm, grantedVote, _⟩ := step
    obtain ⟨granting', granted', grantingMem', grantedMem', grantingTerm', grantedTerm',
      grantedVote', _⟩ := step'
    rcases List.suffix_cons_iff.mp within with same | inner
    · cases same
      have := state_unique (exec.keys (suffix'.subset List.mem_cons_self)) grantedMem
        grantedMem'
      subst this
      rw [grantedVote] at grantedVote'
      exact Option.some.inj grantedVote'
    · have tail : b' :: r' <:+ history := (List.suffix_cons _ _).trans suffix'
      have seen : Seen (b' :: r') voter granted := ⟨a, inner.subset List.mem_cons_self, grantedMem⟩
      rcases record _ tail (List.cons_ne_nil _ _) voter granting' granted early grantingMem'
          seen grantedVote with lt | ⟨termEq, keep⟩
      · exact (Nat.lt_irrefl _ (Nat.lt_of_lt_of_le lt
          (Nat.le_trans grantingTerm' (Nat.le_of_eq grantedTerm.symm)))).elim
      · have seen' : Seen (a' :: b' :: r') voter granting' :=
          ⟨b', List.mem_cons_of_mem _ List.mem_cons_self, grantingMem'⟩
        rcases record _ suffix' (List.cons_ne_nil _ _) voter granted' granting' early grantedMem'
            seen' keep with lt | ⟨_, final⟩
        · exact (Nat.lt_irrefl _ (Nat.lt_of_lt_of_le lt
            (Nat.le_of_eq (grantedTerm'.trans (grantedTerm.symm.trans termEq))))).elim
        · rw [final] at grantedVote'
          exact Option.some.inj grantedVote'
  obtain ⟨a, b, r, suffix, step, seen⟩ := left
  obtain ⟨a', b', r', suffix', step', seen'⟩ := right
  rcases suffix_comparable suffix suffix' with within | within
  · exact ordered ⟨a, b, r, suffix, step, seen⟩ ⟨a', b', r', suffix', step', seen'⟩ a b r a' b'
      r' suffix suffix' step step' within
  · exact (ordered ⟨a', b', r', suffix', step', seen'⟩ ⟨a, b, r, suffix, step, seen⟩ a' b' r' a
      b r suffix' suffix step' step within).symm

/-- The commit step behind a committed part, with its backing. -/
private theorem Committed.shape {history : History} {term : Nat}
    {part : List Entry} (committed : Committed history term part)
    : exists current rest leader state base index,
        current :: rest <:+ history
        /\ CommitStep (current :: rest) leader state term base index
        /\ part = state.log.take index
        /\ (base = 0
            \/ exists earlier part',
                Committed (current :: rest) earlier part'
                /\ earlier <= term
                /\ state.log.take base <+: part') := by
  induction committed with
  | fresh step => exact ⟨_, _, _, _, _, _, List.suffix_refl _, step, rfl, Or.inl rfl⟩
  | chained step backing le within =>
      exact ⟨_, _, _, _, _, _, List.suffix_refl _, step, rfl,
        Or.inr ⟨_, _, backing, le, within⟩⟩
  | past _ ih =>
      obtain ⟨current, rest, leader, state, base, index, suffix, step, eq, backing⟩ := ih
      exact ⟨current, rest, leader, state, base, index, suffix.trans (List.suffix_cons _ _),
        step, eq, backing⟩

private theorem Committed.signature {history : History} {term : Nat}
    {part : List Entry} (committed : Committed history term part)
    : isSignatureAt part part.length = true
      /\ termAt part part.length = term
      /\ 2 <= term := by
  obtain ⟨_, _, _, state, _, index, _, ⟨⟨_, _, _, led⟩, _, _, signature, termEq, _⟩, rfl,
    _⟩ := committed.shape
  refine ⟨take_signature signature, ?_, led.two_le⟩
  rw [List.length_take, Nat.min_eq_left (signature_bound signature),
    termAt_take Nat.le.refl, termEq]

/-- A part committed in a term is in every later leader log. -/
private theorem committed_in_canon {history : History} (complete : Completeness history)
    (mono : Everywhere CanonMono history) {term later : Nat}
    {part log : List Entry} (committed : Committed history term part)
    (canon : Canon history later log) (lt : term < later)
    : part <+: log := by
  obtain ⟨earlier, suffix, node, state, ⟨now, termEq, role, led⟩, rfl⟩ := canon
  obtain ⟨signature, _, two⟩ := committed.signature
  obtain ⟨elected, commit, election⟩ := led.elected (Nat.lt_of_le_of_lt two lt)
  have inLog := complete term part node later elected commit committed
    (election.mono suffix) lt
  obtain ⟨_, _, rfl⟩ := now.nonempty
  have clause := mono _ suffix (List.cons_ne_nil _ _)
  exact (prefix_committable inLog signature).trans
    ((clause node state now role (termEq ▸ led)).2 elected commit (termEq ▸ election))

/-- Committed parts are comparable. -/
private theorem committed_comparable {history : History}
    (complete : Completeness history) (mono : Everywhere CanonMono history)
    {first second : Nat} {left right : List Entry}
    (leftCommitted : Committed history first left)
    (rightCommitted : Committed history second right)
    : left <+: right \/ right <+: left := by
  have inCanon : forall {term term' : Nat} {part part' : List Entry},
      Committed history term part -> Committed history term' part' -> term <= term'
      -> part <+: part' \/ part' <+: part := by
    intro term term' part part' committed committed' le
    obtain ⟨current, rest, leader, state, _, index, suffix, ⟨⟨now, termEq, role, led⟩, _⟩,
      rfl, _⟩ := committed'.shape
    have canon' : Canon history term' state.log :=
      ⟨_, suffix, leader, state, ⟨now, termEq, role, led⟩, rfl⟩
    rcases Nat.eq_or_lt_of_le le with rfl | lt
    · obtain ⟨current₀, rest₀, leader₀, state₀, _, index₀, suffix₀,
        ⟨⟨now₀, termEq₀, role₀, led₀⟩, _⟩, rfl, _⟩ := committed.shape
      have canon : Canon history term state₀.log :=
        ⟨_, suffix₀, leader₀, state₀, ⟨now₀, termEq₀, role₀, led₀⟩, rfl⟩
      rcases canon_chain mono canon canon' with sub | sub
      · exact comparable_of_prefix ((List.take_prefix _ _).trans sub) (List.take_prefix _ _)
      · exact comparable_of_prefix (List.take_prefix _ _) ((List.take_prefix _ _).trans sub)
    · exact comparable_of_prefix (committed_in_canon complete mono committed canon' lt)
        (List.take_prefix _ _)
  rcases Nat.le_total first second with le | le
  · exact inCanon leftCommitted rightCommitted le
  · exact (inCanon rightCommitted leftCommitted le).symm

/--
A committed prefix is committed no later than `bound`, or a commit step of a
later term covers it from a base within it.
-/
private theorem backing_split {history : History} {log : List Entry}
    {commit term bound : Nat} {part : List Entry}
    (committed : Committed history term part) (within : log.take commit <+: part)
    (length : commit <= log.length)
    : Backed history log commit bound
      \/ exists current past leader leaderState term' base index,
          current :: past <:+ history
          /\ CommitStep (current :: past) leader leaderState term' base index
          /\ bound < term'
          /\ base <= commit
          /\ log.take commit <+: leaderState.log.take index := by
  have lengthEq : (log.take commit).length = commit := List.length_take_of_le length
  revert within
  induction committed with
  | @fresh current rest leader state term index step =>
      intro within
      by_cases low : term <= bound
      · exact Or.inl (Or.inr ⟨term, _, .fresh step, low, within⟩)
      · exact Or.inr ⟨current, rest, leader, state, term, 0, index, List.suffix_refl _, step,
          Nat.lt_of_not_le low, Nat.zero_le _, within⟩
  | @chained current rest leader state term base index earlier part' step backing le
      inBacking ih =>
      intro within
      by_cases low : term <= bound
      · exact Or.inl (Or.inr ⟨term, _, .chained step backing le inBacking, low, within⟩)
      by_cases baseLe : base <= commit
      · exact Or.inr ⟨current, rest, leader, state, term, base, index, List.suffix_refl _,
          step, Nat.lt_of_not_le low, baseLe, within⟩
      have commitIndex : commit <= index := Nat.le_trans (Nat.le_of_lt (Nat.lt_of_not_le baseLe))
        step.2.1
      have short : log.take commit <+: state.log.take base := by
        have eq := List.prefix_iff_eq_take.mp within
        rw [lengthEq, List.take_take, Nat.min_eq_left commitIndex] at eq
        rw [eq]
        exact take_prefix_take _ (Nat.le_of_lt (Nat.lt_of_not_le baseLe))
      exact ih (short.trans inBacking)
  | @past current rest term part old ih =>
      intro within
      rcases ih within with backed | ⟨c', p', l', s', t', b', i', suffix, rest'⟩
      · exact Or.inl (backed.mono (List.suffix_cons _ _))
      · exact Or.inr ⟨c', p', l', s', t', b', i', suffix.trans (List.suffix_cons _ _), rest'⟩

private theorem Doomed.cons' {history : History} {current : Model.State} {node : NodeID}
    {state state' : NodeState} (doomed : Doomed history node state)
    (logEq : state'.log = state.log) (commitEq : state'.commitIndex = state.commitIndex)
    (termEq : state'.currentTerm = state.currentTerm)
    : Doomed (current :: history) node state' := by
  obtain ⟨first, past, leader, leaderState, late, base, index, suffix, step, le, baseLe,
    within, order⟩ := doomed
  refine ⟨
    first,
    past,
    leader,
    leaderState,
    late,
    base,
    index,
    suffix.trans (List.suffix_cons _ _),
    step,
    by omega,
    by omega,
    by rw [logEq, commitEq]; exact within,
    fun earlier inner seen => ?_
  ⟩
  rcases List.suffix_cons_iff.mp inner with rfl | inner
  · exact suffix.trans (List.suffix_cons _ _)
  · obtain ⟨other, seenOther, otherTerm⟩ := seen
    exact order earlier inner ⟨other, seenOther, otherTerm.trans termEq⟩

private theorem primaryState_log_prefix (state : NodeState)
    : (primaryState state).log <+: state.log := by
  simp only [primaryState]
  split
  · exact List.take_prefix _ _
  · exact List.prefix_refl _

/-- The facts of a won election used by the safety proof. -/
private theorem Wins.facts {self : NodeID} {before' : NodeState} {event : Event}
    {after' : NodeState} (wins : Wins self before' event after')
    : exists candidate,
        Campaign self before' event candidate
        /\ hasQuorum
            (activeConfigurations before'.log before'.commitIndex)
            candidate.votesGranted
        /\ after'.log = (primaryState candidate).log
        /\ after'.currentTerm = candidate.currentTerm
        /\ after'.votedFor = candidate.votedFor
        /\ (forall peer, after'.matchIndex peer = 0)
        /\ (after'.role = .primary \/ after'.role = .none)
        /\ candidate.commitIndex <= after'.commitIndex := by
  obtain ⟨candidate, campaign, quorum, advance⟩ := wins
  have ⟨_, logEq, commitEq, _⟩ := campaign
  refine ⟨candidate, campaign, ?_, ?_⟩
  · have : candidate.activeConfigurations
        = activeConfigurations before'.log before'.commitIndex := by
      rw [← logEq, ← commitEq]
      rfl
    rw [← this]
    exact quorum
  rcases advance with rfl | ⟨log, term, voted, matchEq, _, _, lt, _, role⟩
  · exact ⟨rfl, rfl, rfl, fun _ => rfl, Or.inl rfl, Nat.le.refl⟩
  · refine ⟨log, term, voted, fun peer => by rw [matchEq]; rfl, ?_, ?_⟩
    · rcases role with role | role
      · exact Or.inl role
      · exact Or.inr role
    · exact Nat.le_of_lt lt

end Consensus.Proofs.Safety

namespace Consensus.Proofs.Safety.Ctx

set_option linter.unusedSectionVars false
open CCF
open Model.Node
open Consensus.Proofs.Ledger
variable [Config.InitialConfiguration]
variable {nodes : List NodeID} {after before : Model.State}
  {rest : History} (c : Ctx nodes after before rest)
include c

private theorem sum : Summary c.actor c.pre c.event c.post c.sent := c.tr.summary

private theorem prior : Exec nodes (before :: rest) :=
  c.exec.suffix (List.suffix_cons _ _) (List.cons_ne_nil _ _)

private theorem all {clause : History -> Prop} (project : forall {h}, Inv h -> clause h)
    : Everywhere clause (before :: rest) :=
  c.good.everywhere project

private theorem inv : Inv (before :: rest) :=
  c.good _ (List.suffix_refl _) (List.cons_ne_nil _ _)

private theorem suffix_tail : before :: rest <:+ after :: before :: rest :=
  List.suffix_cons _ _

private theorem pre_now : Now (before :: rest) c.actor c.pre := c.tr.pre_mem

private theorem post_now : Now (after :: before :: rest) c.actor c.post := c.tr.post_mem

private theorem now_pre {state : NodeState} (now : Now (before :: rest) c.actor state)
    : state = c.pre :=
  now_unique c.prior now c.pre_now

private theorem now_post {state : NodeState}
    (now : Now (after :: before :: rest) c.actor state)
    : state = c.post :=
  now_unique c.exec now c.post_now

private theorem now_after {node : NodeID} {state : NodeState}
    (now : Now (after :: before :: rest) node state)
    : (node = c.actor /\ state = c.post)
      \/ (Not (node = c.actor) /\ Now (before :: rest) node state) :=
  c.tr.mem_after now

private theorem seen_after {node : NodeID} {state : NodeState}
    (seen : Seen (after :: before :: rest) node state)
    : Seen (before :: rest) node state \/ (node = c.actor /\ state = c.post) := by
  rcases seen.cons with now | old
  · rcases c.now_after now with ⟨rfl, rfl⟩ | ⟨_, now⟩
    · exact Or.inr ⟨rfl, rfl⟩
    · exact Or.inl now.seen
  · exact Or.inl old

private theorem pre_seen : Seen (before :: rest) c.actor c.pre := c.pre_now.seen

private theorem post_seen : Seen (after :: before :: rest) c.actor c.post :=
  c.post_now.seen

private theorem frontier_pre : c.pre.commitIndex <= c.pre.log.length :=
  c.pre_seen.commit_le c.prior

private theorem received {source : NodeID} {message : Message}
    (eq : c.event = .receive source message)
    : exists envelope,
        Pending (before :: rest) envelope
        /\ envelope.source = source
        /\ envelope.target = c.actor
        /\ envelope.payload = message := by
  rcases c.tr.source with ⟨input, internal, _⟩ | ⟨envelope, queued, target, receive, _⟩
  · have : c.tr.event = _ := eq
    rw [internal] at this
    cases this
  · have : c.tr.event = _ := eq
    rw [receive] at this
    cases this
    exact ⟨envelope, queued, rfl, target, rfl⟩

/-- The evidence carried by a received message. -/
private theorem received_ok {source : NodeID} {message : Message}
    (eq : c.event = .receive source message)
    : exists envelope,
        MessageOK (before :: rest) envelope
        /\ envelope.source = source
        /\ envelope.target = c.actor
        /\ envelope.payload = message := by
  obtain ⟨envelope, pending, sourceEq, targetEq, payload⟩ := c.received eq
  exact ⟨envelope, c.inv.messages envelope pending, sourceEq, targetEq, payload⟩

private theorem received_term {source : NodeID} {message : Message}
    (eq : c.event = .receive source message) (bumping : Bumping message)
    : 2 <= message.term := by
  obtain ⟨envelope, pending, _, _, rfl⟩ := c.received eq
  exact c.inv.message_terms envelope pending bumping

private theorem term_le : c.pre.currentTerm <= c.post.currentTerm := Summary.term_le c.sum

/-- A node's committed prefix ending at a signature is a signed prefix of a leader log. -/
private theorem snap_of_committed {node : NodeID} {state : NodeState}
    (now : Now (before :: rest) node state) {index : Nat} (positive : 0 < index)
    (le : index <= state.commitIndex) (signature : isSignatureAt state.log index = true)
    : SnapOK (before :: rest) (state.log.take index) := by
  have bound := signature_bound signature
  have lengthEq : (state.log.take index).length = index := List.length_take_of_le bound
  refine ⟨
    by omega,
    by rw [lengthEq]; exact isSignatureAt_take_of_le Nat.le.refl signature,
    ?_,
    ?_
  ⟩
  · obtain ⟨log, canon, _, agree⟩ := c.inv.anchor node state index now positive bound
    refine ⟨log, ?_, ?_⟩
    · rw [lengthEq, termAt_take Nat.le.refl]
      exact canon
    · rw [agree]
      exact List.take_prefix _ _
  · obtain ⟨⟨_, backed⟩, _⟩ := c.inv.commit_backed node state now
    rcases backed with zero | ⟨term, part, committed, _, inPart⟩
    · omega
    · exact ⟨term, part, committed, (take_prefix_take _ le).trans inPart⟩

/-- A node initializes from a committed, signed prefix of a leader log. -/
private theorem snap_available {entries : List Entry}
    (eq : c.event = .internal (.initAsBackup entries)) (positive : 0 < entries.length)
    (signature : isSignatureAt entries entries.length = true)
    : SnapOK (before :: rest) entries := by
  have available := c.tr.available entries eq
  simp only [Model.committedPrefixOf, List.any_eq_true, Bool.and_eq_true, decide_eq_true_eq,
    beq_iff_eq] at available
  obtain ⟨⟨node, state⟩, member, le, prefixEq⟩ := available
  have sub : entries <+: state.log := prefixEq ▸ List.take_prefix _ _
  have ok := c.snap_of_committed member positive le (isSignatureAt_of_prefix sub signature)
  rwa [prefixEq] at ok

private theorem pre_two (active : Engaged c.pre) : 2 <= c.pre.currentTerm :=
  c.inv.active c.actor c.pre c.pre_now active

/-- An engaged node, or a sender of a term-bumping message, has term at least two. -/
private theorem post_two
    (active
      : Engaged c.post \/ exists envelope, envelope ∈ c.sent /\ Bumping envelope.payload)
    : 2 <= c.post.currentTerm := by
  have le := c.term_le
  rcases Summary.active c.sum active with role | two | ⟨source, message, eq, bumping, bound⟩
      | ⟨entries, stash, positive, signature, termEq⟩
  · exact Nat.le_trans (c.pre_two role) le
  · exact Nat.le_trans two le
  · exact Nat.le_trans (c.received_term eq bumping) bound
  · obtain ⟨_, _, ⟨_, ⟨_, _, _, _, ⟨_, _, _, led⟩, _⟩, _⟩, _⟩ := c.snap_available stash positive signature
    rw [termEq]
    exact led.two_le

private theorem elected_after {node : NodeID} {term commit : Nat} {log : List Entry}
    (elected : Elected (after :: before :: rest) node term log commit)
    : Elected (before :: rest) node term log commit
      \/ ElectStep after before rest node term log commit := by
  obtain ⟨a, b, r, suffix, step⟩ := elected
  rcases List.suffix_cons_iff.mp suffix with same | inner
  · cases same
    exact Or.inr step
  · exact Or.inl ⟨a, b, r, inner, step⟩

/-- A new election is the actor's, campaigning with its state before the step. -/
private theorem electStep {node : NodeID} {term commit : Nat} {log : List Entry}
    (step : ElectStep after before rest node term log commit)
    : node = c.actor
      /\ c.pre.log = log
      /\ c.pre.commitIndex = commit
      /\ (c.pre.currentTerm < term
          \/ (c.pre.currentTerm = term /\ c.pre.role = .candidate))
      /\ c.post.currentTerm = term
      /\ (c.post.role = .primary \/ c.post.role = .none)
      /\ log.take (maxCommittableIndex log) <+: c.post.log
      /\ 3 <= term := by
  obtain ⟨candidate, leader, candidateMem, leaderMem, logEq, commitEq, _, termCase, leaderTerm,
    leaderRole, winning, three, _⟩ := step
  rcases c.now_after leaderMem with ⟨rfl, rfl⟩ | ⟨different, old⟩
  · have := c.now_pre candidateMem
    subst this
    exact ⟨rfl, logEq, commitEq, termCase, leaderTerm, leaderRole, winning, three⟩
  · have := now_unique c.prior old candidateMem
    subst this
    rcases termCase with lt | ⟨_, role⟩
    · exact absurd leaderTerm (Nat.ne_of_lt lt)
    · rcases leaderRole with role' | role' <;> rw [role'] at role <;> cases role

private theorem led_after {node : NodeID} {term : Nat}
    (led : Led (after :: before :: rest) node term)
    : Led (before :: rest) node term
      \/ exists log commit, ElectStep after before rest node term log commit := by
  rcases led with bootstrap | ⟨log, commit, elected⟩
  · exact Or.inl (Or.inl bootstrap)
  · rcases c.elected_after elected with old | step
    · exact Or.inl (Or.inr ⟨log, commit, old⟩)
    · exact Or.inr ⟨log, commit, step⟩

private theorem led_other {node : NodeID} {term : Nat} (different : Not (node = c.actor))
    (led : Led (after :: before :: rest) node term)
    : Led (before :: rest) node term := by
  rcases c.led_after led with old | ⟨_, _, step⟩
  · exact old
  · exact absurd (c.electStep step).1 different

private theorem canon_after {term : Nat} {log : List Entry}
    (canon : Canon (after :: before :: rest) term log)
    : Canon (before :: rest) term log
      \/ exists node state,
          CanonNow (after :: before :: rest) node state term /\ state.log = log := by
  obtain ⟨earlier, suffix, rest'⟩ := canon
  rcases List.suffix_cons_iff.mp suffix with rfl | inner
  · exact Or.inr rest'
  · exact Or.inl ⟨earlier, inner, rest'⟩

end Consensus.Proofs.Safety.Ctx

namespace Consensus.Proofs.Safety

set_option linter.unusedSectionVars false
open CCF
open Model.Node
open Consensus.Proofs.Ledger
variable [Config.InitialConfiguration]

private theorem Advance.facts {self : NodeID} {middle state : NodeState}
    (advance : Advance self middle state)
    : state.log = middle.log
      /\ state.currentTerm = middle.currentTerm
      /\ (state.role = middle.role \/ state.role = .none) := by
  rcases advance with rfl | ⟨log, term, _, _, _, _, _, _, role⟩
  · exact ⟨rfl, rfl, Or.inl rfl⟩
  · exact ⟨log, term, role⟩

private theorem makeRequestVoteRequest_eq (state : NodeState)
    : makeRequestVoteRequest state = vals state.currentTerm state.log state.commitIndex :=
  rfl

/-- A candidate's own log is up to date for its vote request. -/
private theorem vals_upToDate {state : NodeState} (term : Nat)
    (sorted : state.log.Pairwise fun first second => first.term <= second.term)
    (frontier : state.commitIndex <= state.log.length)
    : voteLogUpToDate state (vals term state.log state.commitIndex) := by
  have mono : maxCommittableTerm state.log
      <= termAt state.log (max state.commitIndex (maxCommittableIndex state.log)) :=
    termAt_mono sorted (Nat.le_max_right _ _)
      (Nat.max_le.mpr ⟨frontier, maxCommittableIndexBounded state.log⟩)
  rcases Nat.lt_or_eq_of_le mono with lt | eq
  · exact Or.inl lt
  · exact Or.inr ⟨eq.symm, Nat.le_max_right _ _⟩

end Consensus.Proofs.Safety

namespace Consensus.Proofs.Safety.Ctx

set_option linter.unusedSectionVars false
open CCF
open Model.Node
open Consensus.Proofs.Ledger
variable [Config.InitialConfiguration]
variable {nodes : List NodeID} {after before : Model.State}
  {rest : History} (c : Ctx nodes after before rest)
include c

private theorem anchors : Everywhere Anchor (before :: rest) := c.all Inv.anchor

private theorem monos : Everywhere CanonMono (before :: rest) := c.all Inv.canon_mono

private theorem pre_sorted
    : c.pre.log.Pairwise fun first second => first.term <= second.term :=
  c.inv.sorted c.actor c.pre c.pre_now

/-- An accepted request copies its sender's log up to the end of the batch,
keeping the follower's suffix exactly when the follower already agreed. -/
private theorem accept_shape {source : NodeID} {request : AppendEntriesRequest}
    (eq : c.event = .receive source (.appendEntriesRequest request))
    (accepted : Accepted c.pre request c.post)
    : exists earlier sender,
        earlier <:+ before :: rest
        /\ CanonNow earlier source sender request.term
        /\ AEOk source c.actor sender request
        /\ request.prevLogIndex + request.entries.length <= sender.log.length
        /\ c.post.log.take (request.prevLogIndex + request.entries.length)
            = sender.log.take (request.prevLogIndex + request.entries.length)
        /\ (c.post.log = c.pre.log
            \/ (c.post.log
                  = sender.log.take (request.prevLogIndex + request.entries.length)
                /\ Not
                    (c.pre.log.take (request.prevLogIndex + request.entries.length)
                      = sender.log.take (request.prevLogIndex + request.entries.length))))
        /\ c.pre.log.take request.prevLogIndex
            = sender.log.take request.prevLogIndex := by
  obtain ⟨envelope, ok, sourceEq, targetEq, payload⟩ := c.received_ok eq
  simp only [MessageOK, payload] at ok
  obtain ⟨earlier, suffix, sender, canon, aeok⟩ := ok
  rw [sourceEq] at canon aeok
  rw [targetEq] at aeok
  refine ⟨earlier, sender, suffix, canon, aeok, ?_⟩
  obtain ⟨_, _, prevBound, prevTerm, entries, _⟩ := aeok
  obtain ⟨_, _, _, followerBound, termEq, logEq, _⟩ := accepted
  have senderSeen : Seen (before :: rest) source sender := canon.1.seen.mono suffix
  have batchBound : request.prevLogIndex + request.entries.length <= sender.log.length := by
    exact Nat.le_trans (Nat.add_le_add_left (Nat.le_trans entries.length_le (Nat.le_of_eq List.length_drop))
      _) (Nat.le_of_eq (Nat.add_sub_of_le prevBound))
  have match' : forall j, 0 < j -> j <= c.pre.log.length -> j <= sender.log.length
      -> termAt c.pre.log j = termAt sender.log j -> c.pre.log.take j = sender.log.take j :=
    fun _ positive left right same =>
      log_matching c.anchors c.monos c.pre_seen senderSeen positive left right same
  have prevAgree : c.pre.log.take request.prevLogIndex = sender.log.take request.prevLogIndex := by
    rcases Nat.eq_zero_or_pos request.prevLogIndex with zero | positive
    · rw [zero, List.take_zero, List.take_zero]
    · exact match' _ positive followerBound prevBound (termEq.trans prevTerm)
  have shape := acceptLog_eq followerBound prevBound prevAgree entries match'
  rw [← logEq] at shape
  refine ⟨batchBound, ?_⟩
  split at shape
  · rename_i agree
    have same : c.post.log = c.pre.log := by
      rw [shape, ← agree, List.take_append_drop]
    rw [same]
    exact ⟨agree, Or.inl rfl, prevAgree⟩
  · rename_i differ
    rw [List.append_nil] at shape
    rw [shape, List.take_take, Nat.min_self]
    exact ⟨rfl, Or.inr ⟨rfl, differ⟩, prevAgree⟩

/-- The log after a step: a prefix of the old log, the old log extended by the
leader, or a prefix of a leader log. -/
private theorem post_log
    : c.post.log <+: c.pre.log
      \/ (exists entries,
            c.post.log = c.pre.log ++ entries
            /\ (forall entry, entry ∈ entries -> entry.term = c.pre.currentTerm)
            /\ c.pre.role = .primary
            /\ c.post.currentTerm = c.pre.currentTerm
            /\ Not (c.post.role = .candidate))
      \/ (exists earlier source sender n,
            earlier <:+ before :: rest
            /\ CanonNow earlier source sender c.post.currentTerm
            /\ n <= sender.log.length
            /\ c.post.log = sender.log.take n) := by
  cases Summary.kind c.sum with
  | same log _ =>
      rw [log]
      exact Or.inl (List.prefix_refl _)
  | append entries sent leader terms advance =>
      obtain ⟨log, term, role⟩ := Advance.facts advance
      refine Or.inr (Or.inl ⟨entries, log, terms, leader, term, ?_⟩)
      rcases role with role | role <;> rw [role] <;> simp [leader]
  | ack _ _ _ _ _ _ advance =>
      obtain ⟨log, _, _⟩ := Advance.facts advance
      rw [log]
      exact Or.inl (List.prefix_refl _)
  | accept source request eq accepted =>
      obtain ⟨earlier, sender, suffix, canon, _, bound, _, same | ⟨fresh, _⟩, _⟩ :=
        c.accept_shape eq accepted
      · rw [same]
        exact Or.inl (List.prefix_refl _)
      · rw [accepted.1] at canon
        exact Or.inr (Or.inr ⟨earlier, source, sender, _, suffix, canon, bound, fresh⟩)
  | elect wins =>
      obtain ⟨_, ⟨_, candidateLog, _⟩, _, log, _⟩ := Wins.facts wins
      rw [log, ← candidateLog]
      exact Or.inl (primaryState_log_prefix _)
  | install entries initialized positive signature _ log _ term _ =>
      obtain ⟨_, _, ⟨leaderLog, ⟨earlier, suffix, source, sender, canon, senderLog⟩, inLog⟩, _⟩ :=
        c.snap_available initialized positive signature
      refine Or.inr (Or.inr ⟨earlier, source, sender, entries.length, suffix, ?_, ?_, ?_⟩)
      · rw [term]
        exact canon
      · rw [senderLog]
        exact inLog.length_le
      · rw [log, senderLog]
        exact List.prefix_iff_eq_take.mp inLog

/-- Every log stays empty or rooted at the bootstrap configuration. -/
private theorem rooted : RootedLogs (after :: before :: rest) := by
  intro node state now
  rcases c.now_after now with ⟨rfl, rfl⟩ | ⟨_, old⟩
  · have preRooted := c.inv.rooted c.actor c.pre c.pre_now
    rcases c.post_log with sub | ⟨entries, log, _, leader, _, _⟩
        | ⟨earlier, source, sender, n, suffix, canon, _, log⟩
    · exact preRooted.prefix sub
    · rw [log]
      exact preRooted.append (c.inv.leader_logs c.actor c.pre c.pre_now leader) entries
    · rw [log]
      obtain ⟨_, _, rfl⟩ := canon.1.nonempty
      exact (c.all Inv.rooted _ suffix (List.cons_ne_nil _ _) source sender canon.1).take n
  · exact c.inv.rooted node state old

private theorem terms : Terms (after :: before :: rest) := by
  intro node state now entry mem
  rcases c.now_after now with ⟨rfl, rfl⟩ | ⟨_, old⟩
  · have le := c.term_le
    have preTerms := c.inv.terms c.actor c.pre c.pre_now
    rcases c.post_log with sub | ⟨entries, log, terms, _, term, _⟩
        | ⟨earlier, source, sender, n, suffix, canon, _, log⟩
    · exact Nat.le_trans (preTerms entry (sub.subset mem)) le
    · rw [log] at mem
      rcases List.mem_append.mp mem with old | new
      · exact Nat.le_trans (preTerms entry old) le
      · rw [terms entry new]
        exact le
    · rw [log] at mem
      obtain ⟨_, _, rfl⟩ := canon.1.nonempty
      have := c.all Inv.terms _ suffix (List.cons_ne_nil _ _) source sender canon.1 entry
        (List.mem_of_mem_take mem)
      rw [canon.2.1] at this
      exact this
  · exact c.inv.terms node state old entry mem

private theorem sorted : Sorted (after :: before :: rest) := by
  intro node state now
  rcases c.now_after now with ⟨rfl, rfl⟩ | ⟨_, old⟩
  · have preTerms := c.inv.terms c.actor c.pre c.pre_now
    rcases c.post_log with sub | ⟨entries, log, terms, _, _, _⟩
        | ⟨earlier, source, sender, n, suffix, canon, _, log⟩
    · exact c.pre_sorted.sublist sub.sublist
    · rw [log, List.pairwise_append]
      refine ⟨c.pre_sorted, ?_, ?_⟩
      · exact List.pairwise_of_forall_mem_list fun first firstMem second secondMem => by
          rw [terms first firstMem, terms second secondMem]
          exact Nat.le_refl _
      · intro first firstMem second secondMem
        rw [terms second secondMem]
        exact preTerms first firstMem
    · rw [log]
      obtain ⟨_, _, rfl⟩ := canon.1.nonempty
      exact (c.all Inv.sorted _ suffix (List.cons_ne_nil _ _) source sender canon.1).sublist
        (List.take_sublist _ _)
  · exact c.inv.sorted node state old

private theorem active : Active (after :: before :: rest) := by
  intro node state now role
  rcases c.now_after now with ⟨rfl, rfl⟩ | ⟨_, old⟩
  · exact c.post_two (Or.inl role)
  · exact c.inv.active node state old role

private theorem term_mono : TermMono (after :: before :: rest) := by
  intro node state earlier now seen
  rcases c.now_after now with ⟨rfl, rfl⟩ | ⟨different, old⟩
  · rcases c.seen_after seen with seen | ⟨_, rfl⟩
    · exact Nat.le_trans (c.inv.term_mono c.actor c.pre earlier c.pre_now seen) c.term_le
    · exact Nat.le.refl
  · rcases c.seen_after seen with seen | ⟨same, _⟩
    · exact c.inv.term_mono node state earlier old seen
    · exact absurd same different

private theorem vote_record : VoteRecord (after :: before :: rest) := by
  intro node state earlier candidate now seen voted
  rcases c.now_after now with ⟨rfl, rfl⟩ | ⟨different, old⟩
  · rcases c.seen_after seen with seen | ⟨_, rfl⟩
    · have le := c.term_le
      rcases c.inv.vote_record c.actor c.pre earlier candidate c.pre_now seen voted with
        lt | ⟨termEq, keep⟩
      · exact Or.inl (Nat.lt_of_lt_of_le lt le)
      · rcases Nat.lt_or_eq_of_le le with lt | same
        · exact Or.inl (Nat.lt_of_le_of_lt (Nat.le_of_eq termEq) lt)
        · exact Or.inr ⟨termEq.trans same, Summary.vote_keep c.sum same.symm candidate keep⟩
    · exact Or.inr ⟨rfl, voted⟩
  · rcases c.seen_after seen with seen | ⟨same, _⟩
    · exact c.inv.vote_record node state earlier candidate old seen voted
    · exact absurd same different

/-- The actor's own vote in the step. -/
private theorem self_granted {term : Nat} (le : c.pre.currentTerm <= term)
    (termEq : c.post.currentTerm = term) (voted : c.post.votedFor = some c.actor)
    : Granted (after :: before :: rest) c.actor c.actor term
        (vals term c.pre.log c.pre.commitIndex) :=
  ⟨
    after,
    before,
    rest,
    List.suffix_refl _,
    ⟨
      c.pre,
      c.post,
      c.tr.pre_mem,
      c.tr.post_mem,
      le,
      termEq,
      voted,
      vals_upToDate term c.pre_sorted c.frontier_pre
    ⟩,
    Or.inl rfl
  ⟩

/-- Every vote counted by a campaign was granted for its vote request. -/
private theorem campaign_votes {candidate : NodeState}
    (campaign : Campaign c.actor c.pre c.event candidate)
    (termEq : c.post.currentTerm = candidate.currentTerm)
    (votedEq : c.post.votedFor = candidate.votedFor)
    : forall voter,
        voter ∈ candidate.votesGranted
        -> Granted (after :: before :: rest) voter c.actor candidate.currentTerm
            (vals candidate.currentTerm c.pre.log c.pre.commitIndex) := by
  obtain ⟨_, _, _, ⟨_, freshTerm, freshVote, freshVotes⟩
    | ⟨preRole, sameTerm, _, more⟩⟩ := campaign
  · intro voter mem
    rw [freshVotes, Finset.mem_singleton] at mem
    subst mem
    exact c.self_granted (Nat.le_trans (Nat.le_succ _) (Nat.le_of_eq freshTerm.symm)) termEq
      (votedEq.trans freshVote)
  · intro voter mem
    rw [sameTerm]
    rcases more voter mem with old | ⟨response, eq, responseTerm, granted⟩
    · exact ((c.inv.candidate c.actor c.pre c.pre_now preRole).2.2.1 voter old).mono
        c.suffix_tail
    · obtain ⟨envelope, ok, sourceEq, targetEq, payload⟩ := c.received_ok eq
      simp only [MessageOK, payload] at ok
      obtain ⟨request, granted', _, forNow⟩ := ok granted
      rw [targetEq] at forNow
      rw [sourceEq, targetEq, responseTerm] at granted'
      have requestEq := forNow c.pre c.pre_now preRole responseTerm.symm
      rw [makeRequestVoteRequest_eq] at requestEq
      rw [← requestEq] at granted'
      exact granted'.mono c.suffix_tail

/-- A campaign's term is above the bootstrap term. -/
private theorem campaign_three {candidate : NodeState}
    (campaign : Campaign c.actor c.pre c.event candidate)
    : 3 <= candidate.currentTerm
      /\ (c.pre.currentTerm < candidate.currentTerm
          \/ (c.pre.currentTerm = candidate.currentTerm /\ c.pre.role = .candidate)) := by
  obtain ⟨_, _, _, ⟨active, freshTerm, _⟩ | ⟨preRole, sameTerm, _⟩⟩ := campaign
  · have := c.pre_two active
    exact ⟨Nat.le_trans (Nat.add_le_add_right this 1) (Nat.le_of_eq freshTerm.symm),
      Or.inl (Nat.lt_of_lt_of_le (Nat.lt_add_one _) (Nat.le_of_eq freshTerm.symm))⟩
  · have := (c.inv.candidate c.actor c.pre c.pre_now preRole).1
    exact ⟨Nat.le_trans this (Nat.le_of_eq sameTerm.symm), Or.inr ⟨sameTerm.symm, preRole⟩⟩

/-- Winning an election records it in the extended history. -/
private theorem wins_elect (wins : Wins c.actor c.pre c.event c.post)
    : ElectStep after before rest c.actor c.post.currentTerm c.pre.log
        c.pre.commitIndex := by
  obtain ⟨candidate, campaign, quorum, logEq, termEq, votedEq, _, role, _⟩ := Wins.facts wins
  have ⟨_, candidateLog, candidateCommit, _⟩ := campaign
  obtain ⟨three, termCase⟩ := c.campaign_three campaign
  refine ⟨
    c.pre,
    c.post,
    c.tr.pre_mem,
    c.tr.post_mem,
    rfl,
    rfl,
    c.frontier_pre,
    ?_,
    rfl,
    role,
    ?_,
    Nat.le_trans three (Nat.le_of_eq termEq.symm),
    candidate.votesGranted,
    quorum,
    ?_
  ⟩
  · rw [termEq]
    exact termCase
  · rw [logEq]
    simp only [primaryState]
    split
    · rw [candidateLog]
      exact take_prefix_take _ (by
        simp only [lastCommittableIndex, candidateLog]
        exact Nat.le_max_right _ _)
    · rw [candidateLog]
      exact List.take_prefix _ _
  · intro voter mem
    rw [termEq]
    exact c.campaign_votes campaign termEq votedEq voter mem

private theorem led_cur : LedCur (after :: before :: rest) := by
  intro node state term now led
  rcases c.now_after now with ⟨rfl, rfl⟩ | ⟨different, old⟩
  · rcases c.led_after led with led | ⟨_, _, step⟩
    · have le := c.term_le
      rcases c.inv.led_cur c.actor c.pre term c.pre_now led with lt | ⟨termEq, role⟩
      · exact Or.inl (Nat.lt_of_lt_of_le lt le)
      · rcases Nat.lt_or_eq_of_le le with lt | same
        · exact Or.inl (Nat.lt_of_le_of_lt (Nat.le_of_eq termEq) lt)
        · refine Or.inr ⟨termEq.trans same, fun candidate => ?_⟩
          obtain ⟨_, _, _, ⟨_, fresh, _⟩ | ⟨preRole, _⟩⟩ := Summary.candidate c.sum candidate
          · exact Nat.succ_ne_self _ (fresh.symm.trans same.symm)
          · exact role preRole
    · obtain ⟨_, _, _, _, termEq, role, _⟩ := c.electStep step
      refine Or.inr ⟨termEq.symm, ?_⟩
      rcases role with role | role <;> rw [role] <;> simp
  · exact c.inv.led_cur node state term old (c.led_other different led)

private theorem leader_led : LeaderLed (after :: before :: rest) := by
  intro node state now role
  rcases c.now_after now with ⟨rfl, rfl⟩ | ⟨_, old⟩
  · rcases Summary.leader c.sum role with ⟨preRole, termEq⟩ | wins
    · rw [termEq]
      exact (c.inv.leader_led c.actor c.pre c.pre_now preRole).mono c.suffix_tail
    · exact Or.inr ⟨_, _, after, before, rest, List.suffix_refl _, c.wins_elect wins⟩
  · exact (c.inv.leader_led node state old role).mono c.suffix_tail

/--
A candidate whose committed prefix a commit step of its term or later covers,
from a base within it, cannot win if that commit precedes every grant of its
vote requests: a voter of both holds a later-term signature, so its log is more
up to date than the candidate's.
-/
private theorem doomed_absurd {term commit : Nat} {log : List Entry}
    (step : ElectStep after before rest c.actor term log commit)
    (low : forall entry, entry ∈ log -> entry.term < term)
    {current : Model.State} {past : History} {leader : NodeID} {leaderState : NodeState}
    {late base index : Nat}
    (suffix : current :: past <:+ before :: rest)
    (commitStep : CommitStep (current :: past) leader leaderState late base index)
    (le : term <= late) (baseLe : base <= commit)
    (within : log.take commit <+: leaderState.log.take index)
    (order
      : forall earlier,
          earlier <:+ before :: rest
          -> (exists seen, Seen earlier c.actor seen /\ seen.currentTerm = term)
          -> current :: past <:+ earlier)
    : False := by
  obtain ⟨_, preLog, preCommit, termCase, _, _, _, three⟩ := c.electStep step
  obtain ⟨_, _, _, _, _, _, _, _, _, _, _, _, voters, quorum, granted⟩ := step
  obtain ⟨⟨leaderNow, _, _, _⟩, baseIndex, indexLe, signature, termAtIndex, ackers, ackQuorum,
    acked⟩ := commitStep
  have commitLe : commit <= log.length := by
    rw [← preLog, ← preCommit]; exact c.frontier_pre
  have lengthEq : (log.take commit).length = commit := List.length_take_of_le commitLe
  have commitIndex : commit <= index := by
    have := within.length_le
    rw [lengthEq, List.length_take] at this
    exact Nat.le_trans this (Nat.min_le_left _ _)
  have agree : leaderState.log.take commit = log.take commit := by
    have eq := List.prefix_iff_eq_take.mp within
    rw [lengthEq, List.take_take, Nat.min_eq_left commitIndex] at eq
    exact eq.symm
  have nonempty : Not (current :: past = []) := List.cons_ne_nil _ _
  have leaderRooted := c.all Inv.rooted _ suffix nonempty leader leaderState leaderNow
  have rooted : Rooted Config.GENESIS log := preLog ▸ c.inv.rooted c.actor c.pre c.pre_now
  obtain ⟨voter, inAckers, inVoters⟩ :=
    quorums_intersect_bounded Config.GENESIS_configured leaderRooted rooted agree baseLe Nat.le.refl
      (Nat.le_trans baseLe commitIndex) commitIndex (signature_pos signature) ackQuorum quorum
  obtain ⟨acker, ackerSeen, ackerTerm, ackerPrefix⟩ := acked voter inAckers
  have takeSignature : isSignatureAt (leaderState.log.take index) index = true :=
    isSignatureAt_take_of_le Nat.le.refl signature
  have ackSignature : isSignatureAt acker.log index = true :=
    isSignatureAt_of_prefix ackerPrefix takeSignature
  have ackTerm : termAt acker.log index = late := by
    rw [termAt_of_prefix ackerPrefix (by rw [List.length_take, Nat.min_eq_left indexLe]; exact Nat.le.refl),
      termAt_take Nat.le.refl, termAtIndex]
  have lowTerm : forall i, termAt log i <= term - 1 :=
    termAt_le_of_mem fun entry member => Nat.le_sub_one_of_lt (low entry member)
  have bound' : index <= (acker.log.take index).length := by
    rw [List.length_take, Nat.min_eq_left (signature_bound ackSignature)]
    exact Nat.le.refl
  -- A later state of a voter of the commit keeps its signature, so `log` cannot outrank it.
  have keeps : forall (history : History) (state : NodeState),
      Good history -> Now history voter state -> Seen history voter acker
      -> state.currentTerm <= late
      -> termAt state.log index = late /\ isSignatureAt state.log index = true := by
    intro history state good now seen bound
    have inv := good _ (List.suffix_refl _) (fun empty => by simp [empty, Now] at now)
    rcases inv.persist voter state acker index now seen ackSignature with inLog
        | ⟨later, _, lt, laterLe, _, _⟩
    · refine ⟨?_, isSignatureAt_of_prefix inLog (isSignatureAt_take_of_le Nat.le.refl ackSignature)⟩
      rw [termAt_of_prefix inLog bound', termAt_take Nat.le.refl, ackTerm]
    · rw [ackTerm] at lt
      omega
  by_cases self : voter = c.actor
  · subst self
    have seen := ackerSeen.mono suffix
    have mono := c.inv.term_mono c.actor c.pre acker c.pre_now seen
    rw [ackerTerm] at mono
    have preLe : c.pre.currentTerm <= term := by
      rcases termCase with lt | ⟨same, _⟩
      · exact Nat.le_of_lt lt
      · exact Nat.le_of_eq same
    obtain ⟨atIndex, _⟩ := keeps _ c.pre c.good c.pre_now seen (Nat.le_trans preLe le)
    rw [preLog] at atIndex
    have := lowTerm index
    omega
  obtain ⟨a', b', r', grantSuffix, ⟨granting, _, grantingMem, _, grantingLe, _, _, upToDate⟩,
    seenOr⟩ := granted voter inVoters
  have tail : b' :: r' <:+ before :: rest := by
    rcases List.suffix_cons_iff.mp grantSuffix with same | inner
    · simp only [List.cons.injEq] at same
      obtain ⟨_, rfl, rfl⟩ := same
      exact List.suffix_refl _
    · exact (List.suffix_cons _ _).trans inner
  rcases seenOr with same | candidateSeen
  · exact self same
  have ordered := order _ tail candidateSeen
  have good : Good (b' :: r') := fun earlier within nonempty =>
    c.good earlier (within.trans tail) nonempty
  have seen := ackerSeen.mono ordered
  have grantInv := good _ (List.suffix_refl _) (List.cons_ne_nil _ _)
  have mono := grantInv.term_mono voter granting acker grantingMem seen
  rw [ackerTerm] at mono
  obtain ⟨atIndex, signed⟩ := keeps _ granting good grantingMem seen
    (Nat.le_trans grantingLe le)
  have committable : late <= maxCommittableTerm granting.log := by
    rw [← atIndex]
    exact termAt_mono (grantInv.sorted voter granting grantingMem)
      (signatureIndex_le_maxCommittableIndex signed) (maxCommittableIndexBounded _)
  have requestTerm := lowTerm (max commit (maxCommittableIndex log))
  simp only [voteLogUpToDate, vals] at upToDate
  omega

/-- The actor's committed prefix is committed no later than `bound`, or a later
commit step covers it from a base within it. -/
private theorem pre_split (bound : Nat)
    : Backed (before :: rest) c.pre.log c.pre.commitIndex bound
      \/ exists current past leader leaderState term base index,
          current :: past <:+ before :: rest
          /\ CommitStep (current :: past) leader leaderState term base index
          /\ bound < term
          /\ base <= c.pre.commitIndex
          /\ c.pre.log.take c.pre.commitIndex <+: leaderState.log.take index := by
  obtain ⟨⟨_, backed⟩, _⟩ := c.inv.commit_backed c.actor c.pre c.pre_now
  rcases backed with zero | ⟨_, _, committed, _, within⟩
  · exact Or.inl (Or.inl zero)
  · exact backing_split committed within c.frontier_pre

/-- The actor's earlier states have terms at most its current one. -/
private theorem pre_terms {earlier : History} (suffix : earlier <:+ before :: rest)
    {state : NodeState} (seen : Seen earlier c.actor state)
    : state.currentTerm <= c.pre.currentTerm :=
  c.inv.term_mono c.actor c.pre state c.pre_now (seen.mono suffix)

/-- A fresh campaign's committed prefix is backed, or doomed from the start. -/
private theorem campaign_backed {state : NodeState} (logEq : state.log = c.pre.log)
    (commitEq : state.commitIndex = c.pre.commitIndex)
    (termEq : state.currentTerm = c.pre.currentTerm + 1)
    : Backed (after :: before :: rest) state.log state.commitIndex (state.currentTerm - 1)
      \/ Doomed (after :: before :: rest) c.actor state := by
  rcases c.pre_split c.pre.currentTerm with backed
      | ⟨current, past, leader, leaderState, late, base, index, suffix, step, lt, baseLe,
        within⟩
  · left
    rw [logEq, commitEq, termEq, Nat.add_sub_cancel]
    exact backed.mono c.suffix_tail
  · refine Or.inr ⟨current, past, leader, leaderState, late, base, index,
      suffix.trans c.suffix_tail, step, by omega, by omega, by rw [logEq, commitEq]; exact within,
      fun earlier inner seen => ?_⟩
    rcases List.suffix_cons_iff.mp inner with rfl | inner
    · exact suffix.trans c.suffix_tail
    · obtain ⟨other, seenOther, otherTerm⟩ := seen
      have := c.pre_terms inner seenOther
      omega

private theorem candidate : Candidate (after :: before :: rest) := by
  intro node state now role
  rcases c.now_after now with ⟨rfl, rfl⟩ | ⟨_, old⟩
  · have campaign := Summary.candidate c.sum role
    have ⟨_, logEq, commitEq, kind⟩ := campaign
    obtain ⟨three, _⟩ := c.campaign_three campaign
    refine ⟨three, ?_, ?_, ?_, ?_⟩
    · rcases kind with ⟨_, _, voted, _⟩ | ⟨preRole, _, voted, _⟩
      · exact voted
      · have own := (c.inv.candidate c.actor c.pre c.pre_now preRole).2.1
        rcases voted with voted | none
        · rw [voted, own]
        · rw [own] at none
          cases none
    · intro voter mem
      rw [logEq, commitEq]
      exact c.campaign_votes campaign rfl rfl voter mem
    · rcases kind with ⟨_, fresh, _⟩ | ⟨preRole, same, _⟩
      · exact c.campaign_backed logEq commitEq fresh
      · rcases (c.inv.candidate c.actor c.pre c.pre_now preRole).2.2.2.1 with backed | doomed
        · left
          rw [logEq, commitEq, same]
          exact backed.mono c.suffix_tail
        · exact Or.inr (Doomed.cons' doomed logEq commitEq same)
    · intro entry member
      rw [logEq] at member
      rcases kind with ⟨_, fresh, _⟩ | ⟨preRole, same, _⟩
      · have := c.inv.terms c.actor c.pre c.pre_now entry member
        omega
      · rw [same]
        exact (c.inv.candidate c.actor c.pre c.pre_now preRole).2.2.2.2 entry member
  · obtain ⟨three, voted, votes, backed, low⟩ := c.inv.candidate node state old role
    refine ⟨three, voted, fun voter mem => (votes voter mem).mono c.suffix_tail, ?_, low⟩
    rcases backed with backed | doomed
    · exact Or.inl (backed.mono c.suffix_tail)
    · exact Or.inr (Doomed.cons' doomed rfl rfl rfl)

private theorem elect_backed : ElectBacked (after :: before :: rest) := by
  intro a b r node term log commit suffix step
  rcases List.suffix_cons_iff.mp suffix with same | inner
  · simp only [List.cons.injEq] at same
    obtain ⟨rfl, rfl, rfl⟩ := same
    have ⟨actorEq, logEq, commitEq, termCase, _, _, _, three⟩ := c.electStep step
    subst actorEq
    rcases termCase with lt | ⟨same, preRole⟩
    · rcases c.pre_split (term - 1) with backed
          | ⟨current, past, leader, leaderState, late, base, index, inner, commitStep, below,
            baseLe, within⟩
      · rw [← logEq, ← commitEq]
        exact backed
      · exfalso
        refine c.doomed_absurd step ?_ inner commitStep (by omega) (by omega)
          (by rw [← logEq, ← commitEq]; exact within) ?_
        · intro entry member
          rw [← logEq] at member
          have := c.inv.terms c.actor c.pre c.pre_now entry member
          omega
        · intro earlier earlierSuffix seen
          obtain ⟨other, seenOther, otherTerm⟩ := seen
          have := c.pre_terms earlierSuffix seenOther
          omega
    · obtain ⟨_, _, _, backed, low⟩ := c.inv.candidate c.actor c.pre c.pre_now preRole
      rcases backed with backed
          | ⟨current, past, leader, leaderState, late, base, index, inner, commitStep, le,
            baseLe, within, order⟩
      · rw [← logEq, ← commitEq, ← same]
        exact backed
      · exfalso
        refine c.doomed_absurd step ?_ inner commitStep (by omega) (by omega)
          (by rw [← logEq, ← commitEq]; exact within)
          fun earlier earlierSuffix seen => order earlier earlierSuffix ?_
        · intro entry member
          rw [← logEq] at member
          have := low entry member
          omega
        · obtain ⟨other, seenOther, otherTerm⟩ := seen
          exact ⟨other, seenOther, otherTerm.trans same.symm⟩
  · exact c.inv.elect_backed a b r node term log commit inner step

end Consensus.Proofs.Safety.Ctx

namespace Consensus.Proofs.Safety

set_option linter.unusedSectionVars false
open CCF
open Model.Node
open Consensus.Proofs.Ledger
open Consensus.Proofs.Config
variable [Config.InitialConfiguration]

private theorem suffix_of_cons_suffix {α : Type} {x y : α} {first second : List α}
    (suffix : x :: first <:+ y :: second)
    : first <:+ second := by
  rcases List.suffix_cons_iff.mp suffix with same | inner
  · rw [(List.cons.inj same).2]
    exact List.suffix_refl _
  · exact (List.suffix_cons _ _).trans inner

/-- A state with a lower term than one at `a` was seen before `a`. -/
private theorem seen_split {history : History} (termMono : Everywhere TermMono history)
    {a : Model.State} {rest : History}
    (suffix : a :: rest <:+ history) {node : NodeID} {granted state : NodeState}
    (mem : (node, granted) ∈ a.nodes) (seen : Seen history node state)
    (lt : state.currentTerm < granted.currentTerm)
    : Seen rest node state := by
  obtain ⟨earlier, earlierSuffix, now⟩ := seen.now
  have late : a :: rest <:+ earlier -> False := by
    intro within
    obtain ⟨_, _, rfl⟩ := now.nonempty
    have := termMono _ earlierSuffix (List.cons_ne_nil _ _) node state granted now
      ⟨a, within.subset List.mem_cons_self, mem⟩
    exact Nat.lt_irrefl _ (Nat.lt_of_lt_of_le lt this)
  rcases suffix_comparable earlierSuffix suffix with inner | outer
  · rcases List.suffix_cons_iff.mp inner with same | inner
    · exact (late (same ▸ List.suffix_refl _)).elim
    · exact now.seen.mono inner
  · exact (late outer).elim

/-- Prefix of a list of known length. -/
private theorem take_of_prefix_length {α : Type} {small large : List α} {n : Nat}
    (sub : small <+: large) (length : small.length = n)
    : small = large.take n := by
  rw [← length]
  exact List.prefix_iff_eq_take.mp sub

/--
A commit step at `term` and a later election whose logs agree up to both
commit indices: the committed part is in the elected log, provided `clean`:
every leader log of a term in `(term, later]` before the election contains it.
-/
private theorem core {small large : History} (within : small <:+ large)
    (termMono : Everywhere TermMono large) (canonMono : Everywhere CanonMono small)
    (sorted : Everywhere Sorted small) (rooted : Everywhere RootedLogs small)
    {current : Model.State}
    {past : History} {leader : NodeID} {state : NodeState}
    {term base index : Nat} (commitSuffix : current :: past <:+ small)
    (step : CommitStep (current :: past) leader state term base index)
    {a b : Model.State} {r : History} {node : NodeID}
    {later commit : Nat} {log : List Entry}
    (electSuffix : a :: b :: r <:+ large) (electInner : b :: r <:+ small)
    (elect : ElectStep a b r node later log commit)
    (persist : Everywhere Persist (b :: r)) (anchor : Everywhere Anchor (b :: r))
    (terms : Everywhere Terms (b :: r)) (lt : term < later) {k : Nat}
    (agree : state.log.take k = log.take k) (baseLe : base <= k) (commitLe : commit <= k)
    (clean
      : forall later' log',
          term < later'
          -> later' <= later
          -> Canon (b :: r) later' log'
          -> state.log.take index <+: log')
    : state.log.take index <+: log := by
  obtain ⟨⟨leaderNow, leaderTerm, leaderRole, leaderLed⟩, baseIndex, indexLe, signature,
    termAtIndex, ackers, ackQuorum, acked⟩ := step
  obtain ⟨candidate, _, candidateMem, _, candidateLog, _, frontier, termCase, _, _, _, _,
    voters, voteQuorum, granted⟩ := elect
  -- An elector committed through `index` already agrees on the committed part.
  by_cases covered : index <= commit
  · have agreeIndex : state.log.take index = log.take index := by
      have := congrArg (List.take index) agree
      rwa [List.take_take, List.take_take, Nat.min_eq_left (Nat.le_trans covered commitLe)] at this
    rw [agreeIndex]
    exact List.take_prefix _ _
  obtain ⟨voter, ackMem, voteMem⟩ :=
    quorums_intersect_bounded GENESIS_configured
      (rooted _ commitSuffix (List.cons_ne_nil _ _) leader state leaderNow)
      (candidateLog ▸ rooted _ electInner (List.cons_ne_nil _ _) node candidate candidateMem)
      agree baseLe commitLe baseIndex (Nat.le_of_lt (Nat.lt_of_not_le covered))
      (Nat.lt_of_le_of_lt (Nat.zero_le _) (Nat.lt_of_not_le covered)) ackQuorum voteQuorum
  obtain ⟨acker, ackerSeen, ackerTerm, ackerLog⟩ := acked voter ackMem
  obtain ⟨a', b', r', grantSuffix, ⟨granting, grantedState, grantingMem, grantedMem,
    grantingTerm, grantedTerm, _, upToDate⟩, _⟩ := granted voter voteMem
  have innerB : b' :: r' <:+ b :: r := suffix_of_cons_suffix grantSuffix
  have ackerB : Seen (b' :: r') voter acker :=
    seen_split termMono (grantSuffix.trans electSuffix) grantedMem
      (ackerSeen.mono (commitSuffix.trans within)) (by rw [ackerTerm, grantedTerm]; exact lt)
  -- The committed part and its signature.
  have partLength : (state.log.take index).length = index := by
    rw [List.length_take, Nat.min_eq_left indexLe]
  have partSignature : isSignatureAt (state.log.take index) index = true :=
    isSignatureAt_take_of_le Nat.le.refl signature
  have partTerm : termAt (state.log.take index) index = term := by
    rw [termAt_take Nat.le.refl, termAtIndex]
  have ackerTake : acker.log.take index = state.log.take index :=
    (take_of_prefix_length ackerLog partLength).symm
  have ackerTerm' : termAt acker.log index = term := by
    rw [termAt_of_prefix ackerLog (Nat.le_of_eq partLength.symm), partTerm]
  -- The granting state holds the part.
  have inGranting : state.log.take index <+: granting.log := by
    rcases persist _ innerB (List.cons_ne_nil _ _) voter granting acker index grantingMem ackerB
        (isSignatureAt_of_prefix ackerLog partSignature) with sub | bad
    · rw [ackerTake] at sub
      exact sub
    · obtain ⟨later', log', above, below, canon, missing⟩ := bad
      rw [ackerTake, ackerTerm'] at *
      exact absurd (clean later' log' above (Nat.le_trans below grantingTerm) (canon.mono innerB))
        missing
  have grantingSorted := sorted _ (innerB.trans electInner) (List.cons_ne_nil _ _) voter granting
    grantingMem
  have grantingSignature : isSignatureAt granting.log index = true :=
    isSignatureAt_of_prefix inGranting partSignature
  have maxGe : index <= maxCommittableIndex granting.log :=
    signatureIndex_le_maxCommittableIndex grantingSignature
  have maxTermGe : term <= maxCommittableTerm granting.log := by
    have := termAt_mono grantingSorted maxGe (maxCommittableIndexBounded granting.log)
    rw [termAt_of_prefix inGranting (Nat.le_of_eq partLength.symm), partTerm] at this
    exact this
  -- The election's last committable position.
  simp only [voteLogUpToDate, vals] at upToDate
  generalize jEq : max commit (maxCommittableIndex log) = j at upToDate ⊢
  have two : 2 <= term := by
    have := leaderLed.two_le
    exact this
  have jBound : j <= log.length := jEq ▸ Nat.max_le.mpr ⟨frontier, maxCommittableIndexBounded log⟩
  have termGe : term <= termAt log j :=
    upToDate.elim (fun gt => Nat.le_trans maxTermGe (Nat.le_of_lt gt))
      (fun eq => Nat.le_trans maxTermGe (Nat.le_of_eq eq.1.symm))
  have jPos : 0 < j := by
    rcases Nat.eq_zero_or_pos j with zero | positive
    · rw [zero, termAt_zero] at termGe
      exact (Nat.not_succ_le_zero 1 (Nat.le_trans two termGe)).elim
    · exact positive
  obtain ⟨anchored, canon, anchoredLength, anchoredTake⟩ :=
    anchor _ (List.suffix_refl _) (List.cons_ne_nil _ _) node candidate j candidateMem jPos
      (candidateLog ▸ jBound)
  rw [candidateLog] at canon anchoredTake
  have viaAnchor : index <= j -> index <= anchored.length
      -> state.log.take index = anchored.take index
      -> state.log.take index <+: log := by
    intro le _ same
    have : log.take index = anchored.take index := by
      have := congrArg (List.take index) anchoredTake
      simp only [List.take_take, Nat.min_eq_left le] at this
      exact this
    rw [same, ← this]
    exact List.take_prefix _ _
  rcases Nat.lt_or_eq_of_le termGe with above | same
  · have bound : termAt log j <= later := by
      have := termAt_le_of_mem
        (terms _ (List.suffix_refl _) (List.cons_ne_nil _ _) node candidate candidateMem) j
      rw [candidateLog] at this
      rcases termCase with lt' | ⟨eq, _⟩
      · exact Nat.le_of_lt (Nat.lt_of_le_of_lt this lt')
      · exact Nat.le_trans this (Nat.le_of_eq eq)
    have sub := clean _ anchored above bound canon
    rcases Nat.lt_or_ge j index with short | long
    · exfalso
      have leaderSorted := sorted _ commitSuffix (List.cons_ne_nil _ _) leader state leaderNow
      have partSorted := leaderSorted.sublist (List.take_sublist index state.log)
      have mono := termAt_mono partSorted (Nat.le_of_lt short) (Nat.le_of_eq partLength.symm)
      have atJ : termAt (state.log.take index) j = termAt log j := by
        rw [← termAt_of_prefix sub (Nat.le_of_lt (Nat.lt_of_lt_of_eq short partLength.symm)),
          ← termAt_take (n := j) Nat.le.refl, ← anchoredTake,
          termAt_take Nat.le.refl]
      rw [atJ, partTerm] at mono
      exact Nat.lt_irrefl _ (Nat.lt_of_lt_of_le above mono)
    · exact viaAnchor long (Nat.le_trans long anchoredLength)
        (take_of_prefix_length sub partLength)
  · have indexLeJ : index <= j := by
      rcases upToDate with gt | ⟨_, ge⟩
      · exact (Nat.lt_irrefl _ (Nat.lt_of_lt_of_le gt (by rw [← same]; exact maxTermGe))).elim
      · exact Nat.le_trans maxGe ge
    rw [← same] at canon
    have leaderCanon : Canon small term state.log :=
      ⟨current :: past, commitSuffix, leader, state,
        ⟨leaderNow, leaderTerm, leaderRole, leaderLed⟩, rfl⟩
    have comparable := canon_chain canonMono (canon.mono electInner) leaderCanon
    have anchoredIndex := Nat.le_trans indexLeJ anchoredLength
    exact viaAnchor indexLeJ anchoredIndex
      (take_eq_take_of_comparable comparable anchoredIndex indexLe).symm

end Consensus.Proofs.Safety

namespace Consensus.Proofs.Safety

set_option linter.unusedSectionVars false
open CCF
open Model.Node
open Consensus.Proofs.Ledger
open Consensus.Proofs.Config
open Model (BOOTSTRAP_TERM)
variable [Config.InitialConfiguration]

/--
Either the committed part is already in `log`, or the two logs agree on a
prefix covering both commit indices, as quorum intersection needs.
-/
private theorem agree_or_contained {α : Type} {state log : List α}
    {base index commit : Nat} (baseLe : base <= index) (indexLe : index <= state.length)
    (frontier : commit <= log.length) (low : commit <= base -> state.take base <+: log)
    (high
      : base < commit
        -> exists part,
            log.take commit <+: part
            /\ (state.take index <+: part \/ part <+: state.take index))
    : state.take index <+: log
      \/ exists k, state.take k = log.take k /\ base <= k /\ commit <= k := by
  rcases (Nat.lt_or_ge base commit).symm with le | lt
  · exact Or.inr ⟨base, take_of_prefix_length (low le)
      (List.length_take_of_le (Nat.le_trans baseLe indexLe)), Nat.le.refl, le⟩
  · obtain ⟨part, inPart, comparable⟩ := high lt
    have commitLength : (log.take commit).length = commit := List.length_take_of_le frontier
    have partLong : commit <= part.length := commitLength ▸ inPart.length_le
    have indexLength : (state.take index).length = index := List.length_take_of_le indexLe
    rcases (Nat.lt_or_ge index commit).symm with le | short
    · refine Or.inr ⟨commit, ?_, Nat.le_of_lt lt, Nat.le.refl⟩
      calc
        state.take commit = (state.take index).take commit := by
          rw [List.take_take, Nat.min_eq_left le]
        _ = part.take commit :=
          take_eq_take_of_comparable comparable
            (Nat.le_trans le (Nat.le_of_eq indexLength.symm)) partLong
        _ = log.take commit := by
          rw [take_eq_of_prefix inPart (Nat.le_of_eq commitLength.symm), List.take_take,
            Nat.min_self]
    · left
      have sub : state.take index <+: part := by
        rcases comparable with sub | sub
        · exact sub
        · exact (Nat.lt_irrefl index (Nat.lt_of_lt_of_le short (Nat.le_trans partLong
            (Nat.le_trans sub.length_le (Nat.le_of_eq indexLength))))).elim
      have : state.take index <+: log.take commit := by
        rcases List.prefix_or_prefix_of_prefix sub inPart with inner | outer
        · exact inner
        · exact (Nat.lt_irrefl index (Nat.lt_of_lt_of_le short
            (Nat.le_trans (Nat.le_of_eq commitLength.symm)
              (Nat.le_trans outer.length_le (Nat.le_of_eq indexLength))))).elim
      exact this.trans (List.take_prefix _ _)

private theorem termAt_append_right {front back : List Entry} {index : Nat}
    (above : front.length < index) (bound : index <= (front ++ back).length)
    : exists entry, entry ∈ back /\ termAt (front ++ back) index = entry.term := by
  rw [termAt_eq (Nat.lt_of_le_of_lt (Nat.zero_le _) above) bound,
    List.getElem_append_right (Nat.le_sub_one_of_lt above)]
  exact ⟨_, List.getElem_mem _, rfl⟩

end Consensus.Proofs.Safety

namespace Consensus.Proofs.Safety.Ctx

set_option linter.unusedSectionVars false
open CCF
open Model.Node
open Consensus.Proofs.Ledger
open Consensus.Proofs.Config
open Model (BOOTSTRAP_TERM)
variable [Config.InitialConfiguration]
variable {nodes : List NodeID} {after before : Model.State}
  {rest : History} (c : Ctx nodes after before rest)
include c

private theorem termMonos : Everywhere TermMono (after :: before :: rest) :=
  (c.all Inv.term_mono).cons c.term_mono

private theorem sortedAll : Everywhere Sorted (after :: before :: rest) :=
  (c.all Inv.sorted).cons c.sorted

private theorem rootedAll : Everywhere RootedLogs (after :: before :: rest) :=
  (c.all Inv.rooted).cons c.rooted

private theorem votes : Everywhere VoteRecord (after :: before :: rest) :=
  (c.all Inv.vote_record).cons c.vote_record

private theorem old_step_in_new {node : NodeID} {later commit : Nat} {log : List Entry}
    (elect : ElectStep after before rest node later log commit)
    {current : Model.State} {past : History}
    (suffix : current :: past <:+ before :: rest) {leader : NodeID}
    {state : NodeState} {term base index : Nat}
    (step : CommitStep (current :: past) leader state term base index)
    (committed : Committed (current :: past) term (state.log.take index))
    (lt : term < later) (low : commit <= base -> state.log.take base <+: log)
    : state.log.take index <+: log := by
  have ⟨_, _, _, _, _, _, frontier, _⟩ := elect
  have committedH := committed.mono suffix
  have high : base < commit
      -> exists part,
          log.take commit <+: part
          /\ (state.log.take index <+: part \/ part <+: state.log.take index) := by
    intro above
    rcases c.elect_backed after before rest node later log commit (List.suffix_refl _) elect with
      zero | ⟨_, part, committedE, _, inPart⟩
    · exact (Nat.not_lt_zero base (zero ▸ above)).elim
    · exact ⟨part, inPart, committed_comparable c.inv.completeness c.monos committedH committedE⟩
  rcases agree_or_contained step.2.1 step.2.2.1 frontier low high with
    done | ⟨k, agree, baseLe, commitLe⟩
  · exact done
  · exact core c.suffix_tail c.termMonos c.monos (c.all Inv.sorted) (c.all Inv.rooted) suffix
      step
      (List.suffix_refl _) (List.suffix_refl _) elect (c.all Inv.persist) c.anchors
      (c.all Inv.terms) lt agree baseLe commitLe
      fun _ _ above _ canon => committed_in_canon c.inv.completeness c.monos committedH canon above

/-- A part committed before the step is in the log of a new election. -/
private theorem old_in_new {node : NodeID} {later commit : Nat} {log : List Entry}
    (elect : ElectStep after before rest node later log commit)
    {history : History} {term : Nat} {part : List Entry}
    (committed : Committed history term part) (suffix : history <:+ before :: rest)
    (lt : term < later)
    : part <+: log := by
  induction committed with
  | fresh step =>
      exact c.old_step_in_new elect suffix step (Committed.fresh step) lt
        fun _ => by rw [List.take_zero]; exact List.nil_prefix
  | chained step backing le within ih =>
      exact c.old_step_in_new elect suffix step (Committed.chained step backing le within)
        lt fun _ => within.trans (ih suffix (Nat.lt_of_le_of_lt le lt))
  | past _ ih => exact ih ((List.suffix_cons _ _).trans suffix) lt

/-- A part committed before the step is in every later elected log. -/
private theorem old_complete {term later commit : Nat} {node : NodeID}
    {part log : List Entry} (committed : Committed (before :: rest) term part)
    (elected : Elected (after :: before :: rest) node later log commit)
    (lt : term < later)
    : part <+: log := by
  rcases c.elected_after elected with old | step
  · exact c.inv.completeness term part node later log commit committed old lt
  · exact c.old_in_new step committed (List.suffix_refl _) lt

private theorem new_old_unique {node other : NodeID} {term commit : Nat}
    {log : List Entry}
    (elect : ElectStep after before rest node term log commit)
    (led : Led (before :: rest) other term)
    : node = other := by
  have ⟨candidate, _, candidateMem, _, candidateLog, _, frontier, _, _, _, _, three, voters,
    quorum, granted⟩ := elect
  rcases led with ⟨rfl, _⟩ | ⟨log', commit', a, b, r, suffix, elect'⟩
  · simp [BOOTSTRAP_TERM] at three
  have ⟨candidate', _, candidateMem', _, candidateLog', _, frontier', _, _, _, _, _, voters',
    quorum', granted'⟩ := elect'
  have agreement : exists k, log.take k = log'.take k /\ commit <= k /\ commit' <= k := by
    rcases Nat.le_total commit' commit with le | le
    · refine ⟨commit, ?_, Nat.le.refl, le⟩
      rcases c.elect_backed after before rest node term log commit (List.suffix_refl _) elect with
        zero | ⟨_, part, committed, below, inPart⟩
      · rw [zero, List.take_zero, List.take_zero]
      · have := c.inv.completeness _ part other term log' commit' committed
          ⟨a, b, r, suffix, elect'⟩
          (Nat.lt_of_le_of_lt below (Nat.sub_lt (Nat.lt_of_lt_of_le (Nat.zero_lt_succ 2) three)
            Nat.one_pos))
        exact take_of_prefix_length (inPart.trans this) (List.length_take_of_le frontier)
    · refine ⟨commit', ?_, le, Nat.le.refl⟩
      rcases c.inv.elect_backed a b r other term log' commit' suffix elect' with
        zero | ⟨_, part, committed, below, inPart⟩
      · rw [zero, List.take_zero, List.take_zero]
      · have := c.old_in_new elect committed ((List.suffix_cons _ _).trans suffix)
          (Nat.lt_of_le_of_lt below (Nat.sub_lt (Nat.lt_of_lt_of_le (Nat.zero_lt_succ 2) three)
            Nat.one_pos))
        exact (take_of_prefix_length (inPart.trans this) (List.length_take_of_le frontier')).symm
  obtain ⟨k, agree, le, le'⟩ := agreement
  obtain ⟨voter, mem, mem'⟩ := quorums_intersect GENESIS_configured
    (candidateLog ▸ c.inv.rooted node candidate candidateMem)
    (candidateLog' ▸ c.all Inv.rooted _ ((List.suffix_cons _ _).trans suffix)
      (List.cons_ne_nil _ _) other candidate' candidateMem')
    agree le le' quorum quorum'
  exact vote_unique c.exec c.votes (granted voter mem)
    ((granted' voter mem').mono (suffix.trans c.suffix_tail))

private theorem election_safety : ElectionSafety (after :: before :: rest) := by
  intro node other term left right
  rcases c.led_after left with left | ⟨_, _, leftStep⟩ <;>
    rcases c.led_after right with right | ⟨_, _, rightStep⟩
  · exact c.inv.election_safety node other term left right
  · exact (c.new_old_unique rightStep left).symm
  · exact c.new_old_unique leftStep right
  · exact (c.electStep leftStep).1.trans (c.electStep rightStep).1.symm

/-- A leader continuing in its term keeps its log. -/
private theorem keep_log (sameTerm : c.post.currentTerm = c.pre.currentTerm)
    (role : Not (c.pre.role = .candidate))
    (led : Led (before :: rest) c.actor c.pre.currentTerm)
    : c.pre.log <+: c.post.log := by
  cases Summary.kind c.sum with
  | same log _ => rw [log]; exact List.prefix_refl _
  | append _ _ _ _ advance =>
      rw [(Advance.facts advance).1]
      exact List.prefix_append _ _
  | ack _ _ _ _ _ _ advance => rw [(Advance.facts advance).1]; exact List.prefix_refl _
  | accept source request eq accepted =>
      exfalso
      obtain ⟨earlier, _, suffix, canon, aeok, _⟩ := c.accept_shape eq accepted
      have : source = c.actor :=
        c.inv.election_safety source c.actor request.term (canon.2.2.2.mono suffix)
          (by rw [accepted.1, sameTerm]; exact led)
      exact aeok.1 this.symm
  | elect wins =>
      have ⟨_, _, _, termCase, _⟩ := c.electStep (c.wins_elect wins)
      rcases termCase with lt | ⟨_, candidate⟩
      · exact (Nat.lt_irrefl _ (Nat.lt_of_lt_of_le lt (Nat.le_of_eq sameTerm))).elim
      · exact (role candidate).elim
  | install _ _ _ _ fresh _ _ _ _ =>
      have := led.two_le
      rw [fresh.2.1] at this
      omega

/-- Every leader log is nonempty: an elected log holds its quorum's configuration. -/
private theorem leader_logs : LeaderLogs (after :: before :: rest) := by
  intro node state now role
  rcases c.now_after now with ⟨rfl, rfl⟩ | ⟨_, old⟩
  · rcases Summary.leader c.sum role with ⟨preRole, termEq⟩ | wins
    · have keep := c.keep_log termEq (by rw [preRole]; simp)
        (c.inv.leader_led c.actor c.pre c.pre_now preRole)
      have nonempty := c.inv.leader_logs c.actor c.pre c.pre_now preRole
      intro empty
      rw [empty] at keep
      exact nonempty (List.prefix_nil.mp keep)
    · obtain ⟨candidate, campaign, quorum, logEq, _⟩ := Wins.facts wins
      have ⟨_, candidateLog, _, _⟩ := campaign
      have nonempty := hasQuorum_nonempty quorum
      rw [logEq]
      simp only [primaryState, lastCommittableIndex]
      split
      · rw [candidateLog]
        simp only [ne_eq, List.take_eq_nil_iff, not_or]
        exact ⟨Nat.ne_of_gt (Nat.lt_of_lt_of_le ‹candidate.commitIndex > 0› (Nat.le_max_left _ _)),
          nonempty⟩
      · rwa [candidateLog]
  · exact c.inv.leader_logs node state old role

/-- An earlier leadership of the actor in its new term continues. -/
private theorem old_led_actor (led : Led (before :: rest) c.actor c.post.currentTerm)
    : c.pre.currentTerm = c.post.currentTerm /\ Not (c.pre.role = .candidate) := by
  have le := c.term_le
  rcases c.inv.led_cur c.actor c.pre _ c.pre_now led with lt | ⟨eq, role⟩
  · exact (Nat.lt_irrefl _ (Nat.lt_of_lt_of_le lt le)).elim
  · exact ⟨eq.symm, role⟩

private theorem canon_mono : CanonMono (after :: before :: rest) := by
  have safety := c.election_safety
  intro node state now role led
  -- A leader log of the term recorded at the head is this state's log.
  have current : forall node' state', CanonNow (after :: before :: rest) node' state'
      state.currentTerm -> state'.log <+: state.log := by
    intro node' state' ⟨now', _, _, led'⟩
    have := safety node' node _ led' led
    subst this
    rw [now_unique c.exec now' now]
    exact List.prefix_refl _
  rcases c.now_after now with ⟨rfl, rfl⟩ | ⟨different, old⟩
  · have fromOld : Led (before :: rest) c.actor c.post.currentTerm
        -> c.pre.log <+: c.post.log /\ CanonMono (before :: rest)
            /\ c.pre.currentTerm = c.post.currentTerm
            /\ Not (c.pre.role = .candidate) := by
      intro oldLed
      obtain ⟨eq, preRole⟩ := c.old_led_actor oldLed
      exact ⟨c.keep_log eq.symm preRole (eq ▸ oldLed), c.inv.canon_mono, eq, preRole⟩
    refine ⟨fun log canon => ?_, fun log commit elected => ?_⟩
    · rcases c.canon_after canon with canon | ⟨node', state', canonNow, rfl⟩
      · have oldLed : Led (before :: rest) c.actor c.post.currentTerm := by
          obtain ⟨earlier, suffix, node', state', ⟨_, _, _, led'⟩, _⟩ := canon
          have := safety node' c.actor _ ((led'.mono suffix).mono c.suffix_tail) led
          subst this
          exact led'.mono suffix
        obtain ⟨keep, mono, eq, preRole⟩ := fromOld oldLed
        rw [← eq] at canon oldLed
        exact ((mono c.actor c.pre c.pre_now preRole oldLed).1 _ canon).trans keep
      · exact current node' state' canonNow
    · rcases c.elected_after elected with old | step
      · obtain ⟨keep, mono, eq, preRole⟩ := fromOld (Or.inr ⟨log, commit, old⟩)
        rw [← eq] at old
        exact ((mono c.actor c.pre c.pre_now preRole (Or.inr ⟨log, commit, old⟩)).2 log commit
          old).trans keep
      · exact (c.electStep step).2.2.2.2.2.2.1
  · have oldLed := c.led_other different led
    refine ⟨fun log canon => ?_, fun log commit elected => ?_⟩
    · rcases c.canon_after canon with canon | ⟨node', state', canonNow, rfl⟩
      · exact (c.inv.canon_mono node state old role oldLed).1 log canon
      · exact current node' state' canonNow
    · rcases c.elected_after elected with old' | step
      · exact (c.inv.canon_mono node state old role oldLed).2 log commit old'
      · exact absurd (c.electStep step).1 different

private theorem canonMonos : Everywhere CanonMono (after :: before :: rest) :=
  c.monos.cons c.canon_mono

private theorem anchor : Anchor (after :: before :: rest) := by
  intro node state index now positive bound
  rcases c.now_after now with ⟨rfl, rfl⟩ | ⟨_, old⟩
  · have viaPre : c.pre.log <+: c.post.log \/ c.post.log <+: c.pre.log
        -> index <= c.pre.log.length
        -> exists log,
            Canon (after :: before :: rest) (termAt c.post.log index) log
            /\ index <= log.length
            /\ c.post.log.take index = log.take index := by
      intro comparable within
      obtain ⟨log, canon, length, take⟩ :=
        c.inv.anchor c.actor c.pre index c.pre_now positive within
      have same := take_eq_take_of_comparable comparable within bound
      have termSame : termAt c.post.log index = termAt c.pre.log index := by
        rw [← termAt_take (n := index) Nat.le.refl, ← same, termAt_take Nat.le.refl]
      rw [termSame, ← same]
      exact ⟨log, canon.mono c.suffix_tail, length, take⟩
    rcases c.post_log with sub | ⟨entries, log, terms, leader, term, notCandidate⟩
        | ⟨earlier, source, sender, n, suffix, canon, _, log⟩
    · exact viaPre (Or.inr sub) (Nat.le_trans bound sub.length_le)
    · rcases (Nat.lt_or_ge c.pre.log.length index).symm with within | above
      · exact viaPre (Or.inl (log ▸ List.prefix_append _ _)) within
      · have termEq : termAt c.post.log index = c.post.currentTerm := by
          rw [log] at bound ⊢
          obtain ⟨entry, mem, eq⟩ := termAt_append_right above bound
          rw [eq, terms entry mem, term]
        refine ⟨c.post.log, ?_, bound, rfl⟩
        rw [termEq]
        refine ⟨after :: before :: rest, List.suffix_refl _, c.actor, c.post,
          ⟨c.post_now, rfl, notCandidate, ?_⟩, rfl⟩
        rw [term]
        exact (c.inv.leader_led c.actor c.pre c.pre_now leader).mono c.suffix_tail
    · rw [log] at bound ⊢
      have short : index <= n := Nat.le_trans bound (List.length_take_le _ _)
      obtain ⟨_, _, rfl⟩ := canon.1.nonempty
      obtain ⟨anchored, anchoredCanon, length, take⟩ :=
        c.anchors _ suffix (List.cons_ne_nil _ _) source sender index canon.1 positive
          (Nat.le_trans bound (by simp [Nat.min_le_right]))
      refine ⟨anchored, ?_, length, ?_⟩
      · rw [termAt_take short]
        exact anchoredCanon.mono (suffix.trans c.suffix_tail)
      · rw [List.take_take, Nat.min_eq_left short, take]
  · obtain ⟨log, canon, length, take⟩ := c.inv.anchor node state index old positive bound
    exact ⟨log, canon.mono c.suffix_tail, length, take⟩

/-- A part committed at the step is in every later elected log. -/
private theorem new_in_elected {leader : NodeID} {state : NodeState}
    {term base index : Nat}
    (step : CommitStep (after :: before :: rest) leader state term base index)
    (backing
      : base = 0
        \/ exists earlier part,
            (forall node later log commit,
              Elected (after :: before :: rest) node later log commit
              -> earlier < later
              -> part <+: log)
            /\ earlier <= term
            /\ state.log.take base <+: part)
    : forall later node log commit,
        Elected (after :: before :: rest) node later log commit
        -> term < later
        -> state.log.take index <+: log := by
  have safety := c.election_safety
  have canonMonos := c.canonMonos
  obtain ⟨⟨leaderNow, rfl, leaderRole, leaderLed⟩, baseLe, indexLe, signature, _⟩ := step
  have partSignature := take_signature signature
  have two : 2 <= state.currentTerm := leaderLed.two_le
  intro later
  induction later using Nat.strongRecOn with
  | _ later ih =>
      intro node log commit elected lt
      obtain ⟨a, b, r, electSuffix, elect⟩ := elected
      have ⟨candidate, _, candidateMem, _, _, _, frontier, termCase, _⟩ := elect
      have electInner : b :: r <:+ after :: before :: rest :=
        (List.suffix_cons _ _).trans electSuffix
      have innerH : b :: r <:+ before :: rest := suffix_of_cons_suffix electSuffix
      -- Every leader log of a term in `(term, later]` before the election holds the part.
      have clean
          : forall later' log',
              state.currentTerm < later'
              -> later' <= later
              -> Canon (b :: r) later' log'
              -> state.log.take index <+: log' := by
        intro later' log' above below canon
        obtain ⟨earlier, earlierSuffix, node', state', ⟨now', term', role', led'⟩, rfl⟩ :=
          canon
        rcases Nat.lt_or_eq_of_le below with lower | rfl
        · obtain ⟨log'', commit'', elected''⟩ := led'.elected (Nat.lt_of_le_of_lt two above)
          have inLog := ih later' lower node' log'' commit''
            ((elected''.mono earlierSuffix).mono electInner) above
          obtain ⟨_, _, rfl⟩ := now'.nonempty
          have clause := c.monos _ (earlierSuffix.trans innerH) (List.cons_ne_nil _ _)
          exact (prefix_committable inLog partSignature).trans
            ((clause node' state' now' role' (term' ▸ led')).2 log'' commit'' (term' ▸ elected''))
        · exfalso
          have ledInner : Led (b :: r) node' later' := led'.mono earlierSuffix
          have := safety node' node later' (ledInner.mono electInner)
            (Or.inr ⟨log, commit, a, b, r, electSuffix, elect⟩)
          subst this
          rcases c.all Inv.led_cur _ innerH (List.cons_ne_nil _ _) node' candidate later'
              candidateMem ledInner with lt' | ⟨eq, notCandidate⟩
          · rcases termCase with lt'' | ⟨eq'', _⟩
            · exact Nat.lt_irrefl _ (Nat.lt_trans lt' lt'')
            · exact Nat.lt_irrefl _ (Nat.lt_of_lt_of_le lt' (Nat.le_of_eq eq''))
          · rcases termCase with lt'' | ⟨_, isCandidate⟩
            · exact Nat.lt_irrefl _ (Nat.lt_of_le_of_lt (Nat.le_of_eq eq) lt'')
            · exact notCandidate isCandidate
      have low : commit <= base -> state.log.take base <+: log := by
        intro _
        rcases backing with zero | ⟨_, part, complete, below, inPart⟩
        · rw [zero, List.take_zero]
          exact List.nil_prefix
        · exact inPart.trans (complete node later log commit
            ⟨a, b, r, electSuffix, elect⟩ (Nat.lt_of_le_of_lt below lt))
      have high
          : base < commit
            -> exists part,
                log.take commit <+: part
                /\ (state.log.take index <+: part \/ part <+: state.log.take index) := by
        intro above
        rcases c.elect_backed a b r node later log commit electSuffix elect with
          zero | ⟨earlier, part, committed, below, inPart⟩
        · exact (Nat.not_lt_zero base (zero ▸ above)).elim
        refine ⟨part, inPart, ?_⟩
        obtain ⟨current', past', leader', state', _, index', suffix', ⟨⟨now', term', role', led'⟩,
          _⟩, rfl, _⟩ :=
          committed.shape
        have canon' : Canon (after :: before :: rest) earlier state'.log :=
          ⟨_, suffix'.trans electInner, leader', state', ⟨now', term', role', led'⟩, rfl⟩
        have leaderCanon : Canon (after :: before :: rest) state.currentTerm state.log :=
          ⟨_, List.suffix_refl _, leader, state, ⟨leaderNow, rfl, leaderRole, leaderLed⟩,
            rfl⟩
        rcases Nat.lt_trichotomy earlier state.currentTerm with lower | rfl | higher
        · obtain ⟨log'', commit'', elected''⟩ := leaderLed.elected
            (Nat.lt_of_le_of_lt (committed.signature).2.2 lower)
          have inLog := c.old_complete (committed.mono innerH) elected'' lower
          have inLeader := (prefix_committable inLog (committed.signature).1).trans
            ((c.canon_mono leader state leaderNow leaderRole (leaderLed)).2 log''
              commit'' elected'')
          exact comparable_of_prefix (List.take_prefix _ _) inLeader
        · rcases canon_chain canonMonos leaderCanon canon' with sub | sub
          · exact comparable_of_prefix ((List.take_prefix _ _).trans sub)
              (List.take_prefix _ _)
          · exact comparable_of_prefix (List.take_prefix _ _)
              ((List.take_prefix _ _).trans sub)
        · have := clean earlier state'.log higher (Nat.le_trans below (Nat.sub_le _ _))
            ⟨_, suffix', leader', state', ⟨now', term', role', led'⟩, rfl⟩
          exact comparable_of_prefix this (List.take_prefix _ _)
      rcases agree_or_contained baseLe indexLe frontier low high with
        done | ⟨k, agree, baseLe', commitLe⟩
      · exact done
      · exact core (List.suffix_refl _) c.termMonos canonMonos c.sortedAll c.rootedAll
          (List.suffix_refl _)
          ⟨⟨leaderNow, rfl, leaderRole, leaderLed⟩, baseLe, indexLe, signature, ‹_›⟩
          electSuffix electInner elect ((c.all Inv.persist).suffix innerH)
          (c.anchors.suffix innerH) ((c.all Inv.terms).suffix innerH) lt agree baseLe'
          commitLe clean

/-- A chained part is complete once its backing is, even when the step made both. -/
private theorem completeness : Completeness (after :: before :: rest) := by
  intro term part node later log commit committed
  generalize history : after :: before :: rest = current at committed
  induction committed generalizing node later log commit with
  | fresh step =>
      cases history
      exact c.new_in_elected step (Or.inl rfl) later node log commit
  | chained step backing le within ih =>
      cases history
      exact c.new_in_elected step
        (Or.inr ⟨_, _, fun node later log commit => ih node later log commit rfl, le, within⟩)
        later node log commit
  | past old =>
      cases history
      exact fun elected lt => c.old_complete old elected lt

end Consensus.Proofs.Safety.Ctx

namespace Consensus.Proofs.Safety

set_option linter.unusedSectionVars false
open CCF
open Model.Node
open Consensus.Proofs.Ledger
variable [Config.InitialConfiguration]

private theorem Backed.transfer {history : History} {log log' : List Entry}
    {commit term : Nat} (backed : Backed history log commit term)
    (agree : log'.take commit = log.take commit)
    : Backed history log' commit term := by
  rcases backed with zero | ⟨earlier, part, committed, le, within⟩
  · exact Or.inl zero
  · exact Or.inr ⟨earlier, part, committed, le, agree ▸ within⟩

private theorem maxCommittableIndexUpTo_le (log : List Entry) (frontier : Nat)
    : maxCommittableIndexUpTo log frontier <= frontier :=
  Nat.le_trans (maxCommittableIndexBounded (log.take frontier)) (List.length_take_le _ _)

end Consensus.Proofs.Safety

namespace Consensus.Proofs.Safety.Ctx

set_option linter.unusedSectionVars false
open CCF
open Model.Node
open Consensus.Proofs.Ledger
variable [Config.InitialConfiguration]
variable {nodes : List NodeID} {after before : Model.State}
  {rest : History} (c : Ctx nodes after before rest)
include c

private theorem pre_led (leader : c.pre.role = .primary)
    : Led (before :: rest) c.actor c.pre.currentTerm :=
  c.inv.leader_led c.actor c.pre c.pre_now leader

private theorem post_led
    (origin
      : (c.pre.role = .primary /\ c.post.currentTerm = c.pre.currentTerm)
        \/ Wins c.actor c.pre c.event c.post)
    : Led (after :: before :: rest) c.actor c.post.currentTerm := by
  rcases origin with ⟨leader, termEq⟩ | wins
  · rw [termEq]
    exact (c.pre_led leader).mono c.suffix_tail
  · exact Or.inr ⟨_, _, after, before, rest, List.suffix_refl _, c.wins_elect wins⟩

/-- An acknowledgement of a leader's term holds a prefix of the leader's log. -/
private theorem acked_pre (leader : c.pre.role = .primary) {voter : NodeID} {index : Nat}
    (acked : Acked (before :: rest) voter c.pre.currentTerm index)
    : exists acker,
        Seen (after :: before :: rest) voter acker
        /\ acker.currentTerm = c.pre.currentTerm
        /\ index <= c.pre.log.length
        /\ c.pre.log.take index <+: acker.log := by
  obtain ⟨acker, log, seen, termEq, canon, bound, sub⟩ := acked
  have notCandidate : Not (c.pre.role = .candidate) := by
    rw [leader]
    intro h
    cases h
  have inLog :=
    (c.inv.canon_mono c.actor c.pre c.pre_now notCandidate (c.pre_led leader)).1 log canon
  refine ⟨acker, seen.mono c.suffix_tail, termEq, Nat.le_trans bound inLog.length_le, ?_⟩
  rw [take_eq_of_prefix inLog bound]
  exact sub

/--
An advanced commit index ends a chain of commit steps, each backed by the one
before it and the first by the earlier commit index.
-/
private theorem advance_backed {middle : NodeState}
    (advance : Advance c.actor middle c.post)
    (old : Backed (before :: rest) c.post.log middle.commitIndex c.post.currentTerm)
    (led : Led (after :: before :: rest) c.actor c.post.currentTerm)
    (role : middle.role = .primary)
    (acks
      : forall voter,
          Not (voter = c.actor)
          -> 0 < middle.matchIndex voter
          -> exists acker,
              Seen (after :: before :: rest) voter acker
              /\ acker.currentTerm = c.post.currentTerm
              /\ c.post.log.take (middle.matchIndex voter) <+: acker.log)
    : Backed (after :: before :: rest) c.post.log c.post.commitIndex
        c.post.currentTerm := by
  rcases advance with same | ⟨log, term, _, _, _, _, _, eq, postRole⟩
  · subst same
    exact old.mono c.suffix_tail
  have notCandidate : Not (c.post.role = .candidate) := by
    rcases postRole with postRole | postRole <;> rw [postRole]
    · rw [role]
      intro h
      cases h
    · intro h
      cases h
  rw [eq]
  dsimp only [highestCommittableIndex]
  refine Direct.foldl_select_step _
    (fun commit => Backed (after :: before :: rest) c.post.log commit c.post.currentTerm)
    _ _ (old.mono c.suffix_tail) fun commit index member backed selected => ?_
  obtain ⟨above, signature, termEq, quorum⟩ := selected
  have bound : index <= middle.log.length := Nat.lt_succ_iff.mp (List.mem_range.mp member)
  obtain ⟨voters, quorum, members⟩
      : exists voters,
          hasQuorum
            ((activeConfigurations middle.log commit).filter
              fun configuration => configuration.index <= index)
            voters
          /\ forall voter, voter ∈ voters
              -> voter = c.actor \/ middle.matchIndex voter >= index :=
    ⟨_, quorum, fun _ mem => (Finset.mem_filter.mp mem).2⟩
  have step : CommitStep (after :: before :: rest) c.actor c.post c.post.currentTerm
      commit index := by
    refine ⟨⟨c.post_now, rfl, notCandidate, led⟩, Nat.le_of_lt above, ?_, ?_, ?_, voters, ?_, ?_⟩
    · rw [log]
      exact bound
    · rw [log]
      exact signature
    · rw [log, termEq, term]
    · rw [log]
      exact quorum
    · intro voter mem
      by_cases self : voter = c.actor
      · subst self
        exact ⟨c.post, c.post_seen, rfl, List.take_prefix _ _⟩
      · have ge := (members voter mem).resolve_left self
        obtain ⟨acker, seen, ackerTerm, sub⟩ :=
          acks voter self (Nat.lt_of_le_of_lt (Nat.zero_le _) (Nat.lt_of_lt_of_le above ge))
        exact ⟨acker, seen, ackerTerm, (take_prefix_take _ ge).trans sub⟩
  have committed
      : Committed (after :: before :: rest) c.post.currentTerm (c.post.log.take index) := by
    rcases backed with zero | ⟨earlier, part, backing, le, within⟩
    · rw [zero] at step
      exact .fresh step
    · exact .chained step backing le within
  exact Or.inr ⟨_, _, committed, Nat.le.refl, List.prefix_refl _⟩

private theorem pre_backed
    (agree : c.post.log.take c.pre.commitIndex = c.pre.log.take c.pre.commitIndex)
    (role : Not (c.pre.role = .candidate))
    (led : Led (before :: rest) c.actor c.pre.currentTerm)
    : Backed (before :: rest) c.post.log c.pre.commitIndex c.post.currentTerm :=
  (((c.inv.commit_backed c.actor c.pre c.pre_now).2 role led).weaken c.term_le).transfer
    agree

private theorem pre_backed_any
    (agree : c.post.log.take c.pre.commitIndex = c.pre.log.take c.pre.commitIndex)
    : exists term,
        Backed (after :: before :: rest) c.post.log c.pre.commitIndex term := by
  obtain ⟨⟨term, backed⟩, _⟩ := c.inv.commit_backed c.actor c.pre c.pre_now
  exact ⟨term, (backed.transfer agree).mono c.suffix_tail⟩

/-- A step keeping the committed prefix keeps a leader's backing in its term. -/
private theorem keep_backed
    (agree : c.post.log.take c.pre.commitIndex = c.pre.log.take c.pre.commitIndex)
    (commitEq : c.post.commitIndex = c.pre.commitIndex)
    (led : Led (after :: before :: rest) c.actor c.post.currentTerm)
    : Backed (after :: before :: rest) c.post.log c.post.commitIndex
        c.post.currentTerm := by
  rw [commitEq]
  rcases c.led_after led with old | ⟨log, commit, step⟩
  · rcases c.inv.led_cur c.actor c.pre c.post.currentTerm c.pre_now old with lt | ⟨same, preRole⟩
    · exact absurd c.term_le (Nat.not_le.mpr lt)
    · rw [same] at old
      exact (c.pre_backed agree preRole old).mono c.suffix_tail
  · have ⟨_, logEq, commitEq', _⟩ := c.electStep step
    have backed := c.elect_backed after before rest c.actor _ log commit (List.suffix_refl _) step
    rw [← logEq, ← commitEq'] at backed
    exact ((backed.weaken (Nat.sub_le _ _)).transfer agree).mono c.suffix_tail

/-- A leader's acknowledged prefix, from its match index. -/
private theorem match_pre (leader : c.pre.role = .primary) {voter : NodeID}
    (different : Not (voter = c.actor)) (positive : 0 < c.pre.matchIndex voter)
    : exists acker,
        Seen (after :: before :: rest) voter acker
        /\ acker.currentTerm = c.pre.currentTerm
        /\ c.pre.matchIndex voter <= c.pre.log.length
        /\ c.pre.log.take (c.pre.matchIndex voter) <+: acker.log :=
  c.acked_pre leader
    (c.inv.match_ack c.actor c.pre voter c.pre_now leader different positive)

private theorem accept_backed {source : NodeID} {request : AppendEntriesRequest}
    (received : c.event = .receive source (.appendEntriesRequest request))
    (accepted : Accepted c.pre request c.post)
    : exists term,
        Backed (after :: before :: rest) c.post.log c.post.commitIndex term := by
  obtain ⟨earlier, sender, suffix, canon, aeok, batchBound, postTake, shape, prevAgree⟩ :=
    c.accept_shape received accepted
  obtain ⟨requestTerm, _, commitLe, _, _, _, commitEq⟩ := accepted
  rw [commitEq]
  rcases Std.max_eq_or (a := c.pre.commitIndex)
      (b := maxCommittableIndexUpTo c.post.log
        (min request.primaryCommit (request.prevLogIndex + request.entries.length))) with
    choice | choice <;> rw [choice]
  · refine c.pre_backed_any ?_
    rcases shape with same | ⟨fresh, _⟩
    · rw [same]
    · rw [fresh]
      calc
        (sender.log.take (request.prevLogIndex + request.entries.length)).take
              c.pre.commitIndex
            = sender.log.take c.pre.commitIndex := by
          rw [List.take_take, Nat.min_eq_left (Nat.le_trans commitLe (Nat.le_add_right _ _))]
        _ = (sender.log.take request.prevLogIndex).take c.pre.commitIndex := by
          rw [List.take_take, Nat.min_eq_left commitLe]
        _ = (c.pre.log.take request.prevLogIndex).take c.pre.commitIndex := by
          rw [prevAgree]
        _ = c.pre.log.take c.pre.commitIndex := by
          rw [List.take_take, Nat.min_eq_left commitLe]
  · have kLe := maxCommittableIndexUpTo_le c.post.log
      (min request.primaryCommit (request.prevLogIndex + request.entries.length))
    have lcLe := aeok.2.2.2.2.2
    have senderTerm := canon.2.1
    obtain ⟨_, _, rfl⟩ := canon.1.nonempty
    rcases (c.all Inv.commit_backed _ suffix (List.cons_ne_nil _ _) source sender canon.1).2
        canon.2.2.1 (by rw [senderTerm]; exact canon.2.2.2) with
      zero | ⟨earlier', part, committed, le, within⟩
    · exact ⟨0, Or.inl (Nat.eq_zero_of_le_zero (Nat.le_trans kLe
        (Nat.le_trans (Nat.min_le_left _ _) (Nat.le_trans lcLe (Nat.le_of_eq zero)))))⟩
    · refine ⟨c.post.currentTerm, Or.inr
        ⟨earlier', part, committed.mono (suffix.trans c.suffix_tail),
          Nat.le_trans le (Nat.le_of_eq (senderTerm.trans requestTerm)), ?_⟩⟩
      generalize maxCommittableIndexUpTo c.post.log
        (min request.primaryCommit (request.prevLogIndex + request.entries.length)) = k at kLe ⊢
      have agree : c.post.log.take k = sender.log.take k := by
        calc
          c.post.log.take k
              = (c.post.log.take (request.prevLogIndex + request.entries.length)).take
                  k := by
            rw [List.take_take, Nat.min_eq_left (Nat.le_trans kLe (Nat.min_le_right _ _))]
          _ = (sender.log.take (request.prevLogIndex + request.entries.length)).take
                k := by
            rw [postTake]
          _ = sender.log.take k := by
            rw [List.take_take, Nat.min_eq_left (Nat.le_trans kLe (Nat.min_le_right _ _))]
      rw [agree]
      exact (take_prefix_take _
        (Nat.le_trans kLe (Nat.le_trans (Nat.min_le_left _ _) lcLe))).trans within

private theorem commit_backed : CommitBacked (after :: before :: rest) := by
  intro node state now
  rcases c.now_after now with ⟨rfl, rfl⟩ | ⟨different, old⟩
  · have strong : Backed (after :: before :: rest) c.post.log c.post.commitIndex
          c.post.currentTerm
        -> (exists term, Backed (after :: before :: rest) c.post.log c.post.commitIndex term)
          /\ (Not (c.post.role = .candidate)
              -> Led (after :: before :: rest) c.actor c.post.currentTerm
              -> Backed (after :: before :: rest) c.post.log c.post.commitIndex
                  c.post.currentTerm) :=
      fun backed => ⟨⟨_, backed⟩, fun _ _ => backed⟩
    cases Summary.kind c.sum with
    | same log commit =>
        have agree : c.post.log.take c.pre.commitIndex = c.pre.log.take c.pre.commitIndex := by
          rw [log]
        refine ⟨?_, fun _ led => c.keep_backed agree commit led⟩
        rw [commit]
        exact c.pre_backed_any agree
    | append entries sent leader _ advance =>
        have logEq : c.post.log = c.pre.log ++ entries := (Advance.facts advance).1
        have termEq : c.post.currentTerm = c.pre.currentTerm := (Advance.facts advance).2.1
        refine strong
          (c.advance_backed advance
            (c.pre_backed ?_ (by rw [leader]; simp) (c.pre_led leader)) ?_ leader ?_)
        · rw [logEq]
          exact List.take_append_of_le_length c.frontier_pre
        · rw [termEq]
          exact (c.pre_led leader).mono c.suffix_tail
        · intro voter different positive
          obtain ⟨acker, seen, ackerTerm, bound, sub⟩ := c.match_pre leader different positive
          refine ⟨acker, seen, by rw [ackerTerm, termEq], ?_⟩
          dsimp only
          rw [logEq, List.take_append_of_le_length bound]
          exact sub
    | ack source response received leader success responseTerm advance =>
        have logEq : c.post.log = c.pre.log := (Advance.facts advance).1
        have termEq : c.post.currentTerm = c.pre.currentTerm := (Advance.facts advance).2.1
        refine strong
          (c.advance_backed advance
            (c.pre_backed
              (by rw [logEq])
              (by rw [leader]; simp)
              (c.pre_led leader)) ?_ leader ?_)
        · rw [termEq]
          exact (c.pre_led leader).mono c.suffix_tail
        · intro voter different positive
          dsimp only at positive ⊢
          rw [logEq, termEq]
          by_cases fromSource : voter = source
          · subst fromSource
            rw [Function.update_self] at positive ⊢
            rcases Std.max_eq_or (a := c.pre.matchIndex voter) (b := response.lastLogIndex) with
              choice | choice <;> rw [choice] at positive ⊢
            · obtain ⟨acker, seen, ackerTerm, _, sub⟩ := c.match_pre leader different positive
              exact ⟨acker, seen, ackerTerm, sub⟩
            · obtain ⟨envelope, ok, sourceEq, _, payload⟩ := c.received_ok received
              simp only [MessageOK, payload] at ok
              have acked := ok success
              rw [sourceEq, responseTerm] at acked
              obtain ⟨acker, seen, ackerTerm, _, sub⟩ := c.acked_pre leader acked
              exact ⟨acker, seen, ackerTerm, sub⟩
          · rw [Function.update_of_ne fromSource] at positive ⊢
            obtain ⟨acker, seen, ackerTerm, _, sub⟩ := c.match_pre leader different positive
            exact ⟨acker, seen, ackerTerm, sub⟩
    | accept source request received accepted =>
        refine ⟨c.accept_backed received accepted, fun _ led => ?_⟩
        exfalso
        obtain ⟨earlier, _, suffix, canon, aeok, _⟩ := c.accept_shape received accepted
        have : source = c.actor :=
          c.election_safety source c.actor request.term
            (canon.2.2.2.mono (suffix.trans c.suffix_tail)) (by rw [accepted.1]; exact led)
        exact aeok.1 this.symm
    | elect wins =>
        have elect := c.wins_elect wins
        have winning := (c.electStep elect).2.2.2.2.2.2.1
        obtain ⟨candidate, ⟨_, candidateLog, candidateCommit, _⟩, _, advance⟩ := wins
        have committable : c.pre.commitIndex <= maxCommittableIndex c.pre.log := by
          rcases Nat.eq_zero_or_pos c.pre.commitIndex with zero | positive
          · exact Nat.le_trans (Nat.le_of_eq zero) (Nat.zero_le _)
          · exact signatureIndex_le_maxCommittableIndex
              ((c.pre_seen.frontier c.prior).2 positive)
        have agree : c.post.log.take c.pre.commitIndex = c.pre.log.take c.pre.commitIndex := by
          rw [take_eq_of_prefix winning
              (by rw [List.length_take]; exact Nat.le_min.mpr ⟨committable, c.frontier_pre⟩),
            List.take_take, Nat.min_eq_left committable]
        refine strong (c.advance_backed advance ?_ (Or.inr ⟨_, _, after, before, rest,
          List.suffix_refl _, elect⟩) rfl ?_)
        · show Backed _ _ candidate.commitIndex _
          rw [candidateCommit]
          exact ((c.elect_backed after before rest c.actor _ _ _ (List.suffix_refl _)
            elect).weaken (Nat.sub_le _ _)).transfer agree
        · intro voter _ positive
          exact absurd positive (Nat.lt_irrefl 0)
    | install entries initialized positive signature _ log commit _ role =>
        obtain ⟨_, _, _, term, part, committed, inPart⟩ :=
          c.snap_available initialized positive signature
        refine ⟨⟨term, Or.inr ⟨term, part, committed.mono c.suffix_tail, Nat.le.refl, ?_⟩⟩,
          fun _ led => ?_⟩
        · rw [log, commit, List.take_length]
          exact inPart
        · exfalso
          rcases c.led_after led with old | ⟨_, _, step⟩
          · have two := old.two_le
            rcases c.inv.led_cur c.actor c.pre _ c.pre_now old with lt | ⟨same, _⟩ <;>
              have := c.term_le <;> omega
          · rcases (c.electStep step).2.2.2.2.2.1 with elected | elected <;>
              simp [role] at elected
  · obtain ⟨⟨term, backed⟩, strong⟩ := c.inv.commit_backed node state old
    exact ⟨⟨term, backed.mono c.suffix_tail⟩,
      fun role led => (strong role (c.led_other different led)).mono c.suffix_tail⟩

/-- A signed prefix of the follower's log survives an accepted request, unless
the sender's leader log of a later term lacks it. -/
private theorem accept_persist {source : NodeID} {request : AppendEntriesRequest}
    (received : c.event = .receive source (.appendEntriesRequest request))
    (accepted : Accepted c.pre request c.post) {part : List Entry}
    (signature : isSignatureAt part part.length = true) (inPre : part <+: c.pre.log)
    : part <+: c.post.log
      \/ Bad (after :: before :: rest) part (termAt part part.length)
          c.post.currentTerm := by
  obtain ⟨earlier, sender, suffix, canon, _, batchBound, _, shape, _⟩ :=
    c.accept_shape received accepted
  rcases shape with same | ⟨fresh, differ⟩
  · left
    rw [same]
    exact inPre
  have requestTerm : request.term = c.post.currentTerm := accepted.1
  have senderCanon : Canon (before :: rest) c.post.currentTerm sender.log := by
    rw [← requestTerm]
    exact ⟨earlier, suffix, source, sender, canon, rfl⟩
  generalize request.prevLogIndex + request.entries.length = n at batchBound fresh differ
  -- A part agreeing with the sender beyond the batch end contradicts the truncation.
  have beyond : n < part.length -> Not (part.take n = sender.log.take n) := by
    intro long agree
    apply differ
    rw [← agree]
    exact take_eq_of_prefix inPre (Nat.le_of_lt long)
  by_cases inSender : part <+: sender.log
  · rcases (Nat.lt_or_ge n part.length).symm with short | long
    · left
      have := take_prefix_take sender.log short
      rw [← List.prefix_iff_eq_take.mp inSender] at this
      rw [fresh]
      exact this
    · exact (beyond long (take_eq_of_prefix inSender (Nat.le_of_lt long)).symm).elim
  · have positive := signature_pos signature
    have termLe : termAt part part.length <= c.post.currentTerm :=
      Nat.le_trans (termAt_le_of_mem (fun entry mem => c.inv.terms c.actor c.pre c.pre_now entry
        (inPre.subset mem)) _) c.term_le
    rcases Nat.lt_or_ge (termAt part part.length) c.post.currentTerm with lower | upper
    · exact Or.inr ⟨c.post.currentTerm, sender.log, lower, Nat.le.refl,
        senderCanon.mono c.suffix_tail, inSender⟩
    · exfalso
      obtain ⟨log, logCanon, length, take⟩ :=
        c.inv.anchor c.actor c.pre part.length c.pre_now positive inPre.length_le
      have partEq : c.pre.log.take part.length = part :=
        (List.prefix_iff_eq_take.mp inPre).symm
      have termEq : termAt c.pre.log part.length = c.post.currentTerm := by
        have := termAt_take (log := c.pre.log) (Nat.le_refl part.length)
        rw [partEq] at this
        exact this.symm.trans (Nat.le_antisymm termLe upper)
      rw [termEq] at logCanon
      have partLog : part = log.take part.length := partEq.symm.trans take
      have comparable := canon_chain c.monos logCanon senderCanon
      rcases (Nat.lt_or_ge sender.log.length part.length).symm with fits | long
      · apply inSender
        rw [partLog, take_eq_take_of_comparable comparable length fits]
        exact List.take_prefix _ _
      · have short := Nat.lt_of_le_of_lt batchBound long
        apply beyond short
        rw [partLog, List.take_take, Nat.min_eq_left (Nat.le_of_lt short)]
        exact take_eq_take_of_comparable comparable
          (Nat.le_trans batchBound (Nat.le_trans (Nat.le_of_lt long) length)) batchBound

/-- A signed prefix of the actor's log survives the step, unless a leader log
of a later term lacks it. -/
private theorem persist_pre {part : List Entry}
    (signature : isSignatureAt part part.length = true) (inPre : part <+: c.pre.log)
    : part <+: c.post.log
      \/ Bad (after :: before :: rest) part (termAt part part.length)
          c.post.currentTerm := by
  cases Summary.kind c.sum with
  | same log _ =>
      left
      rw [log]
      exact inPre
  | append _ _ _ _ advance =>
      left
      rw [(Advance.facts advance).1]
      exact inPre.trans (List.prefix_append _ _)
  | ack _ _ _ _ _ _ advance =>
      left
      rw [(Advance.facts advance).1]
      exact inPre
  | accept _ _ received accepted =>
      exact c.accept_persist received accepted signature inPre
  | elect wins =>
      left
      have winning : c.pre.log.take (maxCommittableIndex c.pre.log) <+: c.post.log :=
        (c.electStep (c.wins_elect wins)).2.2.2.2.2.2.1
      exact (prefix_committable inPre signature).trans winning
  | install _ _ _ _ fresh _ _ _ _ =>
      rw [fresh.2.2.1, List.prefix_nil] at inPre
      subst inPre
      simp [isSignatureAt, entryAt?] at signature

private theorem persist : Persist (after :: before :: rest) := by
  intro node state earlier index now seen signature
  rcases c.now_after now with ⟨rfl, rfl⟩ | ⟨different, old⟩
  · rcases c.seen_after seen with oldSeen | ⟨_, rfl⟩
    · rcases c.inv.persist c.actor c.pre earlier index c.pre_now oldSeen signature with
        inPre | ⟨later, log, lt, le, canon, missing⟩
      · have termEq : termAt (earlier.log.take index) (earlier.log.take index).length
            = termAt earlier.log index := by
          rw [List.length_take, Nat.min_eq_left (signature_bound signature),
            termAt_take Nat.le.refl]
        rw [← termEq]
        exact c.persist_pre (take_signature signature) inPre
      · exact Or.inr ⟨later, log, lt, Nat.le_trans le c.term_le, canon.mono c.suffix_tail, missing⟩
    · exact Or.inl (List.take_prefix _ _)
  · rcases c.seen_after seen with oldSeen | ⟨same, _⟩
    · rcases c.inv.persist node state earlier index old oldSeen signature with sub | bad
      · exact Or.inl sub
      · exact Or.inr (bad.mono c.suffix_tail)
    · exact (different same).elim

private theorem match_ack : MatchAck (after :: before :: rest) := by
  intro node state peer now leader different positive
  rcases c.now_after now with ⟨rfl, rfl⟩ | ⟨_, old⟩
  · rcases Summary.leader c.sum leader with ⟨preLeader, termEq⟩ | wins
    · rw [termEq]
      rcases Summary.matchIndex c.sum leader preLeader termEq peer with
        same | ⟨response, received, success, responseTerm, matchEq⟩
      · rw [same] at positive ⊢
        exact (c.inv.match_ack c.actor c.pre peer c.pre_now preLeader different
          positive).mono c.suffix_tail
      · rw [matchEq]
        obtain ⟨envelope, ok, sourceEq, _, payload⟩ := c.received_ok received
        simp only [MessageOK, payload] at ok
        have acked := ok success
        rw [sourceEq, responseTerm] at acked
        exact acked.mono c.suffix_tail
    · obtain ⟨_, _, _, _, _, _, zero, _⟩ := Wins.facts wins
      rw [zero] at positive
      exact absurd positive (Nat.lt_irrefl 0)
  · exact (c.inv.match_ack node state peer old leader different positive).mono c.suffix_tail

/-- Vote requests recorded for a candidacy stay accurate while it lasts. -/
private theorem rv_stable {node : NodeID} {term : Nat} {request : RequestVoteRequest}
    (seen : exists state, Seen (before :: rest) node state /\ state.currentTerm = term)
    (stable
      : forall state,
          Now (before :: rest) node state
          -> state.role = .candidate
          -> state.currentTerm = term
          -> makeRequestVoteRequest state = request)
    : forall state,
        Now (after :: before :: rest) node state
        -> state.role = .candidate
        -> state.currentTerm = term
        -> makeRequestVoteRequest state = request := by
  intro state now role termEq
  rcases c.now_after now with ⟨rfl, rfl⟩ | ⟨_, old⟩
  · obtain ⟨_, logEq, commitEq, ⟨_, freshTerm, _⟩ | ⟨preRole, sameTerm, _⟩⟩ :=
      Summary.candidate c.sum role
    · obtain ⟨earlier, earlierSeen, earlierTerm⟩ := seen
      have := c.inv.term_mono c.actor c.pre earlier c.pre_now earlierSeen
      exact absurd (Nat.le_trans
        (Nat.le_of_eq (earlierTerm.trans (termEq.symm.trans freshTerm)).symm) this)
        (Nat.not_succ_le_self _)
    · have preTerm : c.pre.currentTerm = term := by
        rw [← sameTerm]
        exact termEq
      have := stable c.pre c.pre_now preRole preTerm
      rw [makeRequestVoteRequest_eq] at this ⊢
      rw [logEq, commitEq, sameTerm]
      exact this
  · exact stable state old role termEq

private theorem seen_term {node : NodeID} {term : Nat}
    (seen : exists state, Seen (before :: rest) node state /\ state.currentTerm = term)
    : exists state,
        Seen (after :: before :: rest) node state /\ state.currentTerm = term := by
  obtain ⟨state, seen, termEq⟩ := seen
  exact ⟨state, seen.mono c.suffix_tail, termEq⟩

private theorem old_message {envelope : Model.Envelope}
    (ok : MessageOK (before :: rest) envelope)
    : MessageOK (after :: before :: rest) envelope := by
  cases h : envelope.payload with
  | appendEntriesRequest request =>
      simp only [MessageOK, h] at ok ⊢
      obtain ⟨earlier, suffix, rest'⟩ := ok
      exact ⟨earlier, suffix.trans c.suffix_tail, rest'⟩
  | appendEntriesResponse response =>
      simp only [MessageOK, h] at ok ⊢
      exact fun success => (ok success).mono c.suffix_tail
  | requestVoteRequest request =>
      simp only [MessageOK, h] at ok ⊢
      obtain ⟨seen, stable⟩ := ok
      exact ⟨c.seen_term seen, c.rv_stable seen stable⟩
  | requestVoteResponse response =>
      simp only [MessageOK, h] at ok ⊢
      intro granted
      obtain ⟨request, grantedBy, seen, stable⟩ := ok granted
      exact ⟨request, grantedBy.mono c.suffix_tail, c.seen_term seen, c.rv_stable seen stable⟩
  | requestPreVoteRequest _ => simp only [MessageOK, h]
  | requestPreVoteResponse _ => simp only [MessageOK, h]
  | proposeRequestVoteRequest _ => simp only [MessageOK, h]

private theorem new_message {envelope : Model.Envelope} (new : envelope ∈ c.sent)
    : MessageOK (after :: before :: rest) envelope := by
  obtain ⟨sourceEq, ok⟩ := Summary.sends c.sum envelope new
  cases h : envelope.payload with
  | appendEntriesRequest request =>
      simp only [h] at ok
      simp only [MessageOK, h]
      rw [sourceEq]
      obtain ⟨aeok, notCandidate, origin⟩ := ok
      refine ⟨after :: before :: rest, List.suffix_refl _, c.post,
        ⟨c.post_now, aeok.2.1.symm, notCandidate, ?_⟩, aeok⟩
      rw [aeok.2.1]
      exact c.post_led origin
  | appendEntriesResponse response =>
      simp only [h] at ok
      simp only [MessageOK, h]
      intro success
      obtain ⟨source, request, received, accepted, responseTerm, lastEq⟩ := ok success
      obtain ⟨earlier, sender, suffix, canon, _, batchBound, postTake, _, _⟩ :=
        c.accept_shape received accepted
      rw [sourceEq, responseTerm, lastEq]
      refine ⟨c.post, sender.log, c.post_seen, rfl,
        ⟨earlier, suffix.trans c.suffix_tail, source, sender, ?_, rfl⟩, batchBound, ?_⟩
      · rw [← accepted.1]
        exact canon
      · rw [← postTake]
        exact List.take_prefix _ _
  | requestVoteRequest request =>
      simp only [h] at ok
      simp only [MessageOK, h]
      rw [sourceEq]
      obtain ⟨termEq, _, stable⟩ := ok
      refine ⟨⟨c.post, c.post_seen, termEq.symm⟩, fun state now role _ => ?_⟩
      rw [c.now_post now] at role ⊢
      exact stable role
  | requestVoteResponse response =>
      simp only [h] at ok
      simp only [MessageOK, h]
      obtain ⟨termEq, grants⟩ := ok
      intro granted
      obtain ⟨request, received, requestTerm, upToDate, voted⟩ := grants granted
      obtain ⟨_, ok', sourceEq', _, payload'⟩ := c.received_ok received
      simp only [MessageOK, payload'] at ok'
      obtain ⟨seen, stable⟩ := ok'
      rw [sourceEq', requestTerm] at seen stable
      rw [termEq]
      refine ⟨request, ?_, c.seen_term seen, c.rv_stable seen stable⟩
      rw [sourceEq]
      exact ⟨after, before, rest, List.suffix_refl _, ⟨c.pre, c.post, c.tr.pre_mem,
        c.tr.post_mem, c.term_le, rfl, voted, upToDate⟩, Or.inr seen⟩
  | requestPreVoteRequest _ => simp only [MessageOK, h]
  | requestPreVoteResponse _ => simp only [MessageOK, h]
  | proposeRequestVoteRequest _ => simp only [MessageOK, h]

private theorem messages : Messages (after :: before :: rest) := by
  intro envelope pending
  rcases c.tr.mem_network pending with old | new
  · exact c.old_message (c.inv.messages envelope old)
  · exact c.new_message new

private theorem message_terms : MessageTerms (after :: before :: rest) := by
  intro envelope pending bumping
  rcases c.tr.mem_network pending with old | new
  · exact c.inv.message_terms envelope old bumping
  · have two := c.post_two (Or.inr ⟨envelope, new, bumping⟩)
    obtain ⟨_, ok⟩ := Summary.sends c.sum envelope new
    cases h : envelope.payload with
    | appendEntriesRequest request =>
        simp only [h] at ok
        simp only [Message.term]
        exact Nat.le_trans two (Nat.le_of_eq ok.1.2.1.symm)
    | appendEntriesResponse _ =>
        rw [h] at bumping
        exact bumping.elim
    | requestVoteRequest request =>
        simp only [h] at ok
        simp only [Message.term]
        exact Nat.le_trans two (Nat.le_of_eq ok.1.symm)
    | requestVoteResponse response =>
        simp only [h] at ok
        simp only [Message.term]
        exact Nat.le_trans two (Nat.le_of_eq ok.1.symm)
    | requestPreVoteRequest request =>
        simp only [h, Message.term] at ok ⊢
        exact Nat.le_trans two (Nat.le_of_eq ok.symm)
    | requestPreVoteResponse response =>
        simp only [h, Message.term] at ok ⊢
        exact Nat.le_trans two (Nat.le_of_eq ok.symm)
    | proposeRequestVoteRequest _ =>
        rw [h] at bumping
        exact bumping.elim

private theorem inv_step : Inv (after :: before :: rest) :=
  {
    terms := c.terms
    sorted := c.sorted
    active := c.active
    term_mono := c.term_mono
    vote_record := c.vote_record
    led_cur := c.led_cur
    leader_led := c.leader_led
    candidate := c.candidate
    elect_backed := c.elect_backed
    election_safety := c.election_safety
    canon_mono := c.canon_mono
    anchor := c.anchor
    completeness := c.completeness
    commit_backed := c.commit_backed
    persist := c.persist
    match_ack := c.match_ack
    messages := c.messages
    message_terms := c.message_terms
    rooted := c.rooted
    leader_logs := c.leader_logs
  }

end Consensus.Proofs.Safety.Ctx

namespace Consensus.Proofs.Safety

set_option linter.unusedSectionVars false
open CCF
open Model.Node
open Consensus.Proofs.Ledger
variable [Config.InitialConfiguration]

/-- The invariant holds at every point of every execution. -/
private theorem good_of_exec {nodes : List NodeID} {history : History}
    (exec : Exec nodes history)
    : Good history := by
  induction exec with
  | initial initialized =>
      intro earlier suffix nonempty
      rcases List.suffix_cons_iff.mp suffix with rfl | inner
      · exact inv_initial initialized
      · exact (nonempty (List.eq_nil_of_suffix_nil inner)).elim
  | step prior stepped ih =>
      obtain ⟨transition⟩ := LocalTransition.ofStep stepped
      have c : Ctx nodes _ _ _ := ⟨.step prior stepped, transition, ih⟩
      intro earlier suffix nonempty
      rcases List.suffix_cons_iff.mp suffix with rfl | inner
      · exact c.inv_step
      · exact ih earlier inner nonempty

/-- Every reachable state is the head of a history satisfying the invariant. -/
private theorem inv_of_reachable {nodes : List NodeID} {state : Model.State}
    (reachable
      : (Model.transitionSystem Config.INITIAL_CONFIGURATION nodes).Reachable state)
    : exists history, Exec nodes (state :: history) /\ Inv (state :: history) := by
  obtain ⟨history, exec⟩ := exec_of_reachable reachable
  exact ⟨history, exec, good_of_exec exec _ (List.suffix_refl _) (List.cons_ne_nil _ _)⟩

/-- The committed logs of two nodes in one state are comparable. -/
private theorem committed_logs_comparable {nodes : List NodeID} {history : History}
    (exec : Exec nodes history) {left right : NodeID}
    {leftState rightState : NodeState} (leftNow : Now history left leftState)
    (rightNow : Now history right rightState)
    : leftState.committedLog <+: rightState.committedLog
      \/ rightState.committedLog <+: leftState.committedLog := by
  have good := good_of_exec exec
  have nonempty : Not (history = []) := by
    rintro rfl
    exact leftNow
  have inv := good _ (List.suffix_refl _) nonempty
  unfold NodeState.committedLog
  obtain ⟨_, zero | ⟨_, part, committed, _, within⟩⟩ :=
    (inv.commit_backed left leftState leftNow).1
  · left
    rw [zero, List.take_zero]
    exact List.nil_prefix
  obtain ⟨_, zero | ⟨_, part', committed', _, within'⟩⟩ :=
    (inv.commit_backed right rightState rightNow).1
  · right
    rw [zero, List.take_zero]
    exact List.nil_prefix
  rcases committed_comparable inv.completeness (good.everywhere Inv.canon_mono) committed
      committed' with sub | sub
  · exact comparable_of_prefix (within.trans sub) within'
  · exact comparable_of_prefix within (within'.trans sub)

end Consensus.Proofs.Safety

namespace Consensus.Proofs.Election

open CCF (Finset)
open Model.Node

private theorem primary_eq_of_reachable [Config.InitialConfiguration]
    {nodes : List Model.Node.NodeID} {state : Model.State}
    (reachable
      : (Model.transitionSystem Config.INITIAL_CONFIGURATION nodes).Reachable state)
    {left right : Model.Node.NodeID} {leftState rightState : Model.Node.NodeState}
    (leftMember : (left, leftState) ∈ state.nodes)
    (rightMember : (right, rightState) ∈ state.nodes)
    (leftLeader : leftState.role = .primary) (rightLeader : rightState.role = .primary)
    (sameTerm : leftState.currentTerm = rightState.currentTerm)
    : left = right := by
  obtain ⟨history, _, inv⟩ := Safety.inv_of_reachable reachable
  have leftLed := inv.leader_led left leftState leftMember leftLeader
  rw [sameTerm] at leftLed
  exact inv.election_safety left right _ leftLed
    (inv.leader_led right rightState rightMember rightLeader)

public theorem election_safety
    : forall (config : Finset NodeID),
      forall (nodes : List NodeID)
              (trace : CCF.Execution.Trace (Model.transitionSystem config nodes))
              (state : Model.State),
      forall (left right : NodeID) (leftState rightState : NodeState),
        (state ∈ trace
          /\ (left, leftState) ∈ state.nodes
          /\ (right, rightState) ∈ state.nodes
          /\ leftState.role = .primary
          /\ rightState.role = .primary
          /\ leftState.currentTerm = rightState.currentTerm)
        -> left = right := by
  intro config nodes trace state left right leftState rightState
    ⟨member, leftMember, rightMember, leftLeader, rightLeader, sameTerm⟩
  let _ : Proofs.Config.InitialConfiguration := ⟨config⟩
  exact Proofs.Election.primary_eq_of_reachable (trace.reachable member)
    leftMember rightMember leftLeader rightLeader sameTerm

end Consensus.Proofs.Election

namespace Consensus.Proofs.CommittedLogs

open CCF (Finset)
open Model.Node
open Consensus.Proofs.Config

private theorem committed_logs_prefix_of_le [Config.InitialConfiguration]
    {nodes : List Model.Node.NodeID}
    {trace
      : CCF.Execution.Trace (Model.transitionSystem Config.INITIAL_CONFIGURATION nodes)}
    {earlierIndex laterIndex : Nat} {earlier later : Model.State}
    {earlierNode laterNode : Model.Node.NodeID}
    {earlierState laterState : Model.Node.NodeState}
    (ordered : earlierIndex <= laterIndex)
    (earlierFound : trace.stateAt earlierIndex = some earlier)
    (laterFound : trace.stateAt laterIndex = some later)
    (earlierMember : (earlierNode, earlierState) ∈ earlier.nodes)
    (laterMember : (laterNode, laterState) ∈ later.nodes)
    : earlierState.committedLog <+: laterState.committedLog
      \/ laterState.committedLog <+: earlierState.committedLog := by
  obtain ⟨carried, carriedMember, grown⟩ :=
    Direct.committed_log_later earlierFound earlierMember (laterIndex - earlierIndex)
      later (by rwa [Nat.add_sub_cancel' ordered])
  obtain ⟨history, exec⟩ :=
    Safety.exec_of_reachable (trace.reachable (CCF.Execution.Trace.stateAt_mem laterFound))
  rcases Safety.committed_logs_comparable exec carriedMember laterMember with
    carriedFirst | laterFirst
  · exact Or.inl (grown.trans carriedFirst)
  · exact List.prefix_or_prefix_of_prefix grown laterFirst

public theorem committed_logs_prefix
    : forall (config : Finset NodeID),
      forall (nodes : List NodeID)
              (trace : CCF.Execution.Trace (Model.transitionSystem config nodes)),
      forall (stateA stateB : Model.State),
      forall (left right : NodeID) (leftState rightState : NodeState),
        (stateA ∈ trace
          /\ stateB ∈ trace
          /\ (left, leftState) ∈ stateA.nodes
          /\ (right, rightState) ∈ stateB.nodes)
        -> leftState.committedLog <+: rightState.committedLog
            \/ rightState.committedLog <+: leftState.committedLog := by
  intro config nodes trace stateA stateB left right leftState rightState
    ⟨memberA, memberB, leftMember, rightMember⟩
  let _ : Proofs.Config.InitialConfiguration := ⟨config⟩
  obtain ⟨indexA, foundA⟩ := CCF.Execution.Trace.mem_iff_exists_stateAt.mp memberA
  obtain ⟨indexB, foundB⟩ := CCF.Execution.Trace.mem_iff_exists_stateAt.mp memberB
  rcases Nat.le_total indexA indexB with ordered | ordered
  · exact Proofs.CommittedLogs.committed_logs_prefix_of_le ordered
      foundA.symm foundB.symm leftMember rightMember
  · exact (Proofs.CommittedLogs.committed_logs_prefix_of_le ordered
      foundB.symm foundA.symm rightMember leftMember).symm

end Consensus.Proofs.CommittedLogs
