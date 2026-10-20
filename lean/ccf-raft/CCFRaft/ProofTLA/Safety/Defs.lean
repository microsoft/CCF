module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import CCFRaft.ProofTLA.Safety.Summary

@[expose] public section

set_option linter.unusedSectionVars false

/-!
# The safety invariant

The invariant is a predicate on an execution history, newest state first. It
refers to earlier states directly: elections, votes, acknowledgements and
commits are records found in the history rather than ghost variables.

* `Granted` records a vote, `Elected` an election, `Led` the leader of a term.
* `Canon h T C`: `C` was the log of the leader of term `T` while it led.
* `Committed h T P`: a leader of `T` had part `P` (ending in a signature of
  term `T`) acknowledged by a quorum of every configuration active for it.

The central clause is `completeness`: every committed part is contained in
the log of every candidate elected at a later term.
-/

namespace CCFRaft.ProofTLA.Safety

open CCF
open Model.Node

variable [Initial]

abbrev History := List (Model.State)

/-- `node` has `state` in the newest state of `history`. -/
def Now : History -> NodeID -> NodeState -> Prop
  | [], _, _ => False
  | current :: _, node, state => (node, state) ∈ current.nodes

/-- `envelope` is queued in the newest state of `history`. -/
def Pending : History -> Model.Envelope -> Prop
  | [], _ => False
  | current :: _, envelope => envelope ∈ current.network

/-- `node` had `state` at some point of `history`. -/
def Seen (history : History) (node : NodeID) (state : NodeState) : Prop :=
  exists current, current ∈ history /\ (node, state) ∈ current.nodes

/-- The vote request of a candidate with this term, log and commit index. -/
def vals (term : Nat) (log : List (Entry)) (commit : Nat) : RequestVoteRequest where
  term
  lastCommittableTerm := termAt log (max commit (maxCommittableIndex log))
  lastCommittableIndex := max commit (maxCommittableIndex log)

/-- `voter` votes for `candidate` in `term`, its log up to date for `request`. -/
def GrantStep (after before : Model.State) (voter candidate : NodeID) (term : Nat)
    (request : RequestVoteRequest)
    : Prop :=
  exists granting granted,
    (voter, granting) ∈ before.nodes
    /\ (voter, granted) ∈ after.nodes
    /\ granting.currentTerm <= term
    /\ granted.currentTerm = term
    /\ granted.votedFor = some candidate
    /\ voteLogUpToDate granting request

def Granted (history : History) (voter candidate : NodeID) (term : Nat)
    (request : RequestVoteRequest)
    : Prop :=
  exists after before rest,
    after :: before :: rest <:+ history
    /\ GrantStep after before voter candidate term request

/-- `node` becomes the leader of `term`, campaigning with `log` and `commit`. -/
def ElectStep (after before : Model.State) (rest : History)
    (node : NodeID) (term : Nat) (log : List (Entry)) (commit : Nat)
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

def Elected (history : History) (node : NodeID) (term : Nat)
    (log : List (Entry)) (commit : Nat)
    : Prop :=
  exists after before rest,
    after :: before :: rest <:+ history
    /\ ElectStep after before rest node term log commit

/-- `node` led `term`: the bootstrap leader, or elected. -/
def Led (history : History) (node : NodeID) (term : Nat) : Prop :=
  (term = Model.BOOTSTRAP_TERM /\ Initial.configuration.min = (node : WithTop NodeID))
  \/ exists log commit, Elected history node term log commit

/-- `node` now has `state` as the leader of `term`, possibly stepped down. -/
def CanonNow (history : History) (node : NodeID) (state : NodeState) (term : Nat)
    : Prop :=
  Now history node state
  /\ state.currentTerm = term
  /\ Not (state.role = .candidate)
  /\ Led history node term

/-- `log` was the log of the leader of `term` at some point. -/
def Canon (history : History) (term : Nat) (log : List (Entry)) : Prop :=
  exists earlier,
    earlier <:+ history
    /\ exists node state, CanonNow earlier node state term /\ state.log = log

/-- A leader of `term` with `state` has its first `index` entries acknowledged
by a quorum of the configurations active at `base` and starting at or before `index`. -/
def CommitStep (history : History) (leader : NodeID) (state : NodeState)
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

/-- Prefixes committed by a leader, each backed by earlier commits. -/
inductive Committed : History -> Nat -> List (Entry) -> Prop where
  | fresh {current : Model.State} {rest : History} {leader : NodeID}
    {state : NodeState} {term index : Nat}
    (step : CommitStep (current :: rest) leader state term 0 index)
    : Committed (current :: rest) term (state.log.take index)
  | chained {current : Model.State} {rest : History} {leader : NodeID}
    {state : NodeState} {term base index earlier : Nat}
    {part : List (Entry)}
    (step : CommitStep (current :: rest) leader state term base index)
    (backing : Committed rest earlier part) (le : earlier <= term)
    (within : state.log.take base <+: part)
    : Committed (current :: rest) term (state.log.take index)
  | past {current : Model.State} {rest : History} {term : Nat}
    {part : List (Entry)} (old : Committed rest term part)
    : Committed (current :: rest) term part

/-- The first `commit` entries of `log` lie within a part committed by `term`. -/
def Backed (history : History) (log : List (Entry)) (commit term : Nat) : Prop :=
  commit = 0
  \/ exists earlier part,
      Committed history earlier part /\ earlier <= term /\ log.take commit <+: part

/-- `voter` held the first `index` entries of a leader log of `term` in `term`. -/
def Acked (history : History) (voter : NodeID) (term index : Nat) : Prop :=
  exists acker log,
    Seen history voter acker
    /\ acker.currentTerm = term
    /\ Canon history term log
    /\ index <= log.length
    /\ log.take index <+: acker.log

/-- A leader of a term in `(term, bound]` lacked `part`. -/
def Bad (history : History) (part : List (Entry)) (term bound : Nat) : Prop :=
  exists later log,
    term < later /\ later <= bound /\ Canon history later log /\ Not (part <+: log)

/-- What a queued message tells about its sender. -/
def MessageOK (history : History) (envelope : Model.Envelope) : Prop :=
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

def Terms (history : History) : Prop :=
  forall node state,
    Now history node state
    -> forall entry, entry ∈ state.log -> entry.term <= state.currentTerm

def Sorted (history : History) : Prop :=
  forall node state,
    Now history node state
    -> state.log.Pairwise fun first second => first.term <= second.term

def Active (history : History) : Prop :=
  forall node state,
    Now history node state -> Not (state.role = .none) -> 2 <= state.currentTerm

def TermMono (history : History) : Prop :=
  forall node state earlier,
    Now history node state
    -> Seen history node earlier
    -> earlier.currentTerm <= state.currentTerm

def VoteRecord (history : History) : Prop :=
  forall node state earlier candidate,
    Now history node state
    -> Seen history node earlier
    -> earlier.votedFor = some candidate
    -> earlier.currentTerm < state.currentTerm
        \/ (earlier.currentTerm = state.currentTerm /\ state.votedFor = some candidate)

def LedCur (history : History) : Prop :=
  forall node state term,
    Now history node state
    -> Led history node term
    -> term < state.currentTerm
        \/ (term = state.currentTerm /\ Not (state.role = .candidate))

def LeaderLed (history : History) : Prop :=
  forall node state,
    Now history node state -> state.role = .primary -> Led history node state.currentTerm

def Candidate (history : History) : Prop :=
  forall node state,
    Now history node state
    -> state.role = .candidate
    -> 3 <= state.currentTerm
        /\ state.votedFor = some node
        /\ (forall voter,
              voter ∈ state.votesGranted
              -> Granted history voter node state.currentTerm
                  (vals state.currentTerm state.log state.commitIndex))
        /\ Backed history state.log state.commitIndex (state.currentTerm - 1)

def ElectBacked (history : History) : Prop :=
  forall after before rest node term log commit,
    after :: before :: rest <:+ history
    -> ElectStep after before rest node term log commit
    -> Backed (before :: rest) log commit (term - 1)

def ElectionSafety (history : History) : Prop :=
  forall node other term, Led history node term -> Led history other term -> node = other

def CanonMono (history : History) : Prop :=
  forall node state,
    Now history node state
    -> Not (state.role = .candidate)
    -> Led history node state.currentTerm
    -> (forall log, Canon history state.currentTerm log -> log <+: state.log)
        /\ forall log commit,
            Elected history node state.currentTerm log commit
            -> log.take (maxCommittableIndex log) <+: state.log

def Anchor (history : History) : Prop :=
  forall node state index,
    Now history node state
    -> 0 < index
    -> index <= state.log.length
    -> exists log,
        Canon history (termAt state.log index) log
        /\ index <= log.length
        /\ state.log.take index = log.take index

def Completeness (history : History) : Prop :=
  forall term part node later log commit,
    Committed history term part
    -> Elected history node later log commit
    -> term < later
    -> part <+: log

def CommitBacked (history : History) : Prop :=
  forall node state,
    Now history node state -> Backed history state.log state.commitIndex state.currentTerm

def Persist (history : History) : Prop :=
  forall node state earlier index,
    Now history node state
    -> Seen history node earlier
    -> isSignatureAt earlier.log index = true
    -> earlier.log.take index <+: state.log
        \/ Bad history (earlier.log.take index) (termAt earlier.log index)
            state.currentTerm

def MatchAck (history : History) : Prop :=
  forall node state peer,
    Now history node state
    -> state.role = .primary
    -> Not (peer = node)
    -> 0 < state.matchIndex peer
    -> Acked history peer state.currentTerm (state.matchIndex peer)

def Messages (history : History) : Prop :=
  forall envelope, Pending history envelope -> MessageOK history envelope

def MessageTerms (history : History) : Prop :=
  forall envelope,
    Pending history envelope -> Bumping envelope.payload -> 2 <= envelope.payload.term

/-- The configuration transaction the initial primary starts with. -/
def genesisEntry : Entry where
  term := Model.BOOTSTRAP_TERM
  content :=
    .transaction 0 { configuration := some Initial.configuration }

/-- Logs start with the genesis entry, and leaders' logs are nonempty. -/
def Genesis (history : History) : Prop :=
  forall node state,
    Now history node state
    -> (forall first, state.log.head? = some first -> first = genesisEntry)
        /\ (state.role = .primary -> Not (state.log = []))

structure Inv (history : History) : Prop where
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
  genesis : Genesis history

/-- The invariant holds at every point of the history. -/
def Good (history : History) : Prop :=
  forall earlier, earlier <:+ history -> Not (earlier = []) -> Inv earlier

end CCFRaft.ProofTLA.Safety
