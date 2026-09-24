-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

import CCFRaft.Proofs.Invariant.Messages

open CCFRaft.Model.Local (
  BOOTSTRAP_TERM Bootstrap Configuration Entry EntryContent INITIAL_CONFIGURATION
    INITIAL_LEADER INITIAL_PRE_VOTE_STATUS MembershipState NodeState PreVoteStatus Role
    activeConfigurations activeNodeUnion allConfigurations allRetiredCommittedNodes
    becomeCandidateNodeState campaignEligible configurationsInLog configurationsInLogFrom
    currentConfiguration currentConfigurationAt entryAt? findHighestPossibleMatch
    hasConfigurationMajority highestActiveConfigurationWithNode implicitConfiguration
    initialNodeState isSignatureAt lastCommittableIndex lastCommittableTerm
    latestConfiguration maxCommittableIndex maxCommittableIndexUpTo maxCommittableTerm
    messageEntries refreshRetirementState retiredCommittedIndexFrom
    retiredCommittedIndexInLog retiredCommittedNodesUpTo retiredCommittedNodesUpToFrom
    retirementCommittableIndexInLog retirementCompletedNodes
    retirementIndexFromConfigurations retirementIndexInLog signatureIndexAfterFrom termAt
    updateIndex
  )

set_option autoImplicit false

namespace CCFRaft.Proofs.Invariant

variable {Node TxId : Type}
variable [DecidableEq Node] [DecidableEq TxId] [Bootstrap Node]
variable {joined : Finset Node}

/-- Every node's commit index points within its current log. -/
def CommitIndicesBounded (state : Model.State Node TxId) : Prop :=
  forall node, ((nodeOf state) node).commitIndex <= ((nodeOf state) node).log.length

/-- Every positive node commit frontier points to a signature entry. -/
def CommittedFrontierIsSignature (state : Model.State Node TxId) : Prop :=
  forall node,
    0 < ((nodeOf state) node).commitIndex
    -> isSignatureAt ((nodeOf state) node).log ((nodeOf state) node).commitIndex = true

/-- Equal index and term identify the same complete log prefix. -/
def LogMatching (state : Model.State Node TxId) : Prop :=
  forall left right index leftEntry rightEntry,
    entryAt? ((nodeOf state) left).log index = some leftEntry
    -> entryAt? ((nodeOf state) right).log index = some rightEntry
    -> leftEntry.term = rightEntry.term
    -> ((nodeOf state) left).log.take index = ((nodeOf state) right).log.take index

/-- Entry terms do not decrease as log indices increase. -/
def MonoLog (state : Model.State Node TxId) : Prop :=
  forall node earlier later earlierEntry laterEntry,
    earlier < later
    -> entryAt? ((nodeOf state) node).log earlier = some earlierEntry
    -> entryAt? ((nodeOf state) node).log later = some laterEntry
    -> earlierEntry.term <= laterEntry.term

end CCFRaft.Proofs.Invariant

/-!
# Arbitrary-term Raft proof properties

Arbitrary-term Raft permits arbitrarily many elections, so the proof cannot
name one old history and one new history. The invariant below keeps the core
safety statements explicit and records the state-local evidence used by the
Raft election and replication arguments.

The proof-only vote history is not runtime state.  It remembers the unique
candidate selected by each voter in each term after `votedFor` is cleared by a
later `UpdateTerm`.
-/

namespace CCFRaft.Proofs.Invariant

variable {Node TxId : Type}
variable [DecidableEq Node] [DecidableEq TxId] [Bootstrap Node]
variable {joined : Finset Node}

/-- A proof-only record of the candidate selected by a voter in a term. -/
abbrev VoteHistory (Node : Type) := Node -> Nat -> Option Node

/-- A proof-only canonical owner for each term once that term is elected. -/
abbrev TermOwners (Node : Type) := Nat -> Option Node

/-- Immutable proof-only data frozen when one candidate is promoted. -/
structure ElectionRecord (Node TxId : Type) where
  leader : Node
  supporters : Finset Node
  ballotLog : List (Entry Node TxId)
  ballotCommitIndex : Nat
  ballotActive : List (Configuration Node)
  promotionLog : List (Entry Node TxId)
  candidateLog : Node -> List (Entry Node TxId)
  voterLog : Node -> List (Entry Node TxId)

/-- At most one frozen promotion record is retained for each term. -/
abbrev ElectionHistory (Node TxId : Type) :=
  Nat -> Option (ElectionRecord Node TxId)

/--
Proof-only evidence for one signed configuration activation. The old and new
authorities are explicit because later proofs must relate their quorum systems;
the governing list freezes every active configuration which required support.
-/
structure ActivationRecord (Node TxId : Type) where
  leader : Node
  history : List (Entry Node TxId)
  priorCommitIndex : Nat
  activationFrontier : Nat
  activationTerm : Nat
  oldConfiguration : Configuration Node
  newConfiguration : Configuration Node
  governingActive : List (Configuration Node)
  jointSupporters : Finset Node
  supporterAckTerm : Node -> Nat
  supporterAckIndex : Node -> Nat
  supporterHistory : Node -> List (Entry Node TxId)

/-- Immutable activation events are keyed by configuration, term, and frontier. -/
structure ActivationKey (Node : Type) where
  configurationIndex : Nat
  term : Nat
  frontier : Nat
  leader : Node
deriving DecidableEq

abbrev ActivationHistory (Node TxId : Type) :=
  ActivationKey Node -> Option (ActivationRecord Node TxId)

/--
A signed frontier permanently moves the frozen history from one current
configuration to a later one, with one support set satisfying every governing
configuration. This is the future bridge between replication evidence and
configuration activation; it is intentionally not part of `InvariantFacts`.
-/
def ActivationRecord.Valid (record : ActivationRecord Node TxId) : Prop :=
  record.priorCommitIndex < record.activationFrontier
  /\ record.activationFrontier <= record.history.length
  /\ record.oldConfiguration
      = currentConfigurationAt record.history record.priorCommitIndex
  /\ record.newConfiguration
      = currentConfigurationAt record.history record.activationFrontier
  /\ Not (record.oldConfiguration = record.newConfiguration)
  /\ isSignatureAt record.history record.activationFrontier = true
  /\ record.governingActive
      = ((allConfigurations record.history).filter
          fun configuration =>
            record.oldConfiguration.index <= configuration.index
            /\ configuration.index <= record.activationFrontier)
  /\ record.newConfiguration ∈ record.governingActive
  /\ forall configuration,
      configuration ∈ record.governingActive
      -> hasConfigurationMajority record.jointSupporters configuration

/--
After activation, the frozen current-configuration index never regresses. A
later activation may supersede the recorded configuration, hence the index
comparison rather than equality.
-/
def ActivationRecord.Permanent (record : ActivationRecord Node TxId) : Prop :=
  forall frontier,
    record.activationFrontier <= frontier
    -> frontier <= record.history.length
    -> record.newConfiguration.index
        <= (currentConfigurationAt record.history frontier).index

/--
Skeleton history facts for the future reconfiguration proof. Records are
valid, keyed by their activated configuration, and retain the permanent signed
transition; no runtime field or invariant dependency is introduced yet.
-/
structure ActivationHistoryFacts (activations : ActivationHistory Node TxId) : Prop where
  indexed
    : forall index record,
        activations index = some record
        -> index.configurationIndex = record.newConfiguration.index
            /\ index.term = record.activationTerm
            /\ index.frontier = record.activationFrontier
            /\ index.leader = record.leader
  sameConfigurationComparable
    : forall leftIndex left rightIndex right,
        activations leftIndex = some left
        -> activations rightIndex = some right
        -> left.newConfiguration.index = right.newConfiguration.index
        -> left.history.take left.activationFrontier
              <+: right.history.take right.activationFrontier
            \/ right.history.take right.activationFrontier
                <+: left.history.take left.activationFrontier
  valid : forall index record, activations index = some record -> record.Valid
  permanent : forall index record, activations index = some record -> record.Permanent
  termPositive
    : forall index record,
        activations index = some record -> BOOTSTRAP_TERM <= record.activationTerm
  supporterAcks
    : forall index record,
        activations index = some record
        -> termAt record.history record.activationFrontier = record.activationTerm
            /\ forall supporter,
                supporter ∈ record.jointSupporters
                -> record.supporterAckTerm supporter = record.activationTerm
                    /\ record.activationFrontier <= record.supporterAckIndex supporter
                    /\ record.supporterAckIndex supporter
                        <= (record.supporterHistory supporter).length
                    /\ (record.supporterHistory supporter).take record.activationFrontier
                        = record.history.take record.activationFrontier
  priorActivation
    : forall index record,
        activations index = some record
        -> 0 < record.oldConfiguration.index
        -> Exists
            fun priorIndex =>
              Exists
                fun prior =>
                  activations priorIndex = some prior
                  /\ prior.newConfiguration.index < record.newConfiguration.index
                  /\ record.oldConfiguration ∈ prior.governingActive
                  /\ prior.history.take prior.activationFrontier
                      <+: record.history.take record.activationFrontier

/--
Recorded activation ACK terms remain lower bounds on each supporter's current
term. The immutable ACK histories stay in `ActivationRecord`; this state-indexed
fact retains only monotone term progress.
-/
def ActivationSupporterProgress
    (state : Model.State Node TxId)
    (activations : ActivationHistory Node TxId)
    : Prop :=
  forall index record,
    activations index = some record
    -> forall supporter,
        supporter ∈ record.jointSupporters
        -> record.activationTerm <= ((nodeOf state) supporter).currentTerm

/-- Some frozen election after one signed prefix's term already omits it. -/
def EarlierBadElectionForPrefix
    (elections : ElectionHistory Node TxId)
    (supportedPrefix : List (Entry Node TxId))
    (prefixTerm bound : Nat)
    : Prop :=
  Exists
    fun badTerm =>
      Exists
        fun badRecord =>
          prefixTerm < badTerm
          /\ badTerm <= bound
          /\ elections badTerm = some badRecord
          /\ Not (supportedPrefix <+: badRecord.promotionLog)

/--
Every activation supporter still contains the signed activation prefix, unless
a later frozen election no newer than that supporter's current term already
provides the induction handoff.
-/
def ActivationSupporterCurrentHistory
    (state : Model.State Node TxId)
    (elections : ElectionHistory Node TxId)
    (activations : ActivationHistory Node TxId)
    : Prop :=
  forall index record,
    activations index = some record
    -> forall supporter,
        supporter ∈ record.jointSupporters
        -> record.history.take record.activationFrontier <+: ((nodeOf state) supporter).log
            \/ EarlierBadElectionForPrefix
                elections
                (record.history.take record.activationFrontier)
                record.activationTerm
                ((nodeOf state) supporter).currentTerm

/--
One immutable activation event covers a node's current configuration at the
prefix shared by that event and the node's committed log.
-/
structure ConfigurationCoverageWitness
    (state : Model.State Node TxId)
    (activations : ActivationHistory Node TxId)
    (node : Node) where
  activationIndex : ActivationKey Node
  activation : ActivationRecord Node TxId
  stored : activations activationIndex = some activation
  configurationCovered
    : currentConfiguration ((nodeOf state) node) ∈ activation.governingActive
  activationTermBound : activation.activationTerm <= ((nodeOf state) node).currentTerm
  configurationIndexBound
    : (currentConfiguration ((nodeOf state) node)).index
      <= min ((nodeOf state) node).commitIndex activation.activationFrontier
  historyAgreement
    : activation.history.take
        (min ((nodeOf state) node).commitIndex activation.activationFrontier)
      = ((nodeOf state) node).log.take
          (min ((nodeOf state) node).commitIndex activation.activationFrontier)
  higherAuthority
    : forall higherIndex higher,
        activations higherIndex = some higher
        -> (currentConfiguration ((nodeOf state) node)).index < higher.newConfiguration.index
        -> activation.history.take
              (min ((nodeOf state) node).commitIndex activation.activationFrontier)
            <+: higher.history.take higher.activationFrontier
  lowerAuthority
    : forall lowerIndex lower,
        activations lowerIndex = some lower
        -> lower.newConfiguration.index < (currentConfiguration ((nodeOf state) node)).index
        -> lower.history.take lower.activationFrontier
            <+: activation.history.take
                  (min ((nodeOf state) node).commitIndex activation.activationFrontier)
  sameAuthority
    : forall sameIndex same,
        activations sameIndex = some same
        -> same.newConfiguration.index = (currentConfiguration ((nodeOf state) node)).index
        -> same.newConfiguration = currentConfiguration ((nodeOf state) node)
  candidateTermStrict
    : ((nodeOf state) node).role = .candidate
      -> activation.activationTerm < ((nodeOf state) node).currentTerm

/--
Every positive current configuration is covered by an immutable activation
event. The event may activate a later configuration when a partial
AppendEntries request exposes an intermediate configuration.
-/
def ConfigurationCoverageFacts
    (state : Model.State Node TxId)
    (activations : ActivationHistory Node TxId)
    : Prop :=
  forall node,
    0 < (currentConfiguration ((nodeOf state) node)).index
    -> Nonempty (ConfigurationCoverageWitness state activations node)

structure ConfigurationFrontierCoverageWitness
    (activations : ActivationHistory Node TxId)
    (history : List (Entry Node TxId))
    (frontier termBound : Nat) where
  activationIndex : ActivationKey Node
  activation : ActivationRecord Node TxId
  stored : activations activationIndex = some activation
  configurationCovered
    : currentConfigurationAt history frontier ∈ activation.governingActive
  activationTermBound : activation.activationTerm <= termBound
  configurationIndexBound
    : (currentConfigurationAt history frontier).index
      <= min frontier activation.activationFrontier
  historyAgreement
    : activation.history.take (min frontier activation.activationFrontier)
      = history.take (min frontier activation.activationFrontier)
  higherAuthority
    : forall higherIndex higher,
        activations higherIndex = some higher
        -> (currentConfigurationAt history frontier).index < higher.newConfiguration.index
        -> activation.history.take (min frontier activation.activationFrontier)
            <+: higher.history.take higher.activationFrontier
  lowerAuthority
    : forall lowerIndex lower,
        activations lowerIndex = some lower
        -> lower.newConfiguration.index < (currentConfigurationAt history frontier).index
        -> lower.history.take lower.activationFrontier
            <+: activation.history.take (min frontier activation.activationFrontier)
  sameAuthority
    : forall sameIndex same,
        activations sameIndex = some same
        -> same.newConfiguration.index = (currentConfigurationAt history frontier).index
        -> same.newConfiguration = currentConfigurationAt history frontier

def CommittedConfigurationCoverage
    (state : Model.State Node TxId)
    (activations : ActivationHistory Node TxId)
    : Prop :=
  forall node frontier,
    frontier <= ((nodeOf state) node).commitIndex
    -> 0 < (currentConfigurationAt ((nodeOf state) node).log frontier).index
    -> isSignatureAt ((nodeOf state) node).log frontier = true
    -> Nonempty
        (ConfigurationFrontierCoverageWitness
          activations ((nodeOf state) node).log frontier
          ((nodeOf state) node).currentTerm)

def QueuedConfigurationCoverage
    (state : Model.State Node TxId)
    (appendHistory : AppendRequestKey Node TxId -> List (Entry Node TxId))
    (activations : ActivationHistory Node TxId)
    : Prop :=
  forall destination request,
    (appendRequestEnvelope request ∈ state.network /\ request.2.1 = destination)
    -> forall frontier,
        frontier
          <= min request.2.2.leaderCommit (request.2.2.prevLogIndex + request.2.2.entries.length)
        -> 0 < (currentConfigurationAt (appendHistory request) frontier).index
        -> isSignatureAt (appendHistory request) frontier = true
        -> Nonempty
            (ConfigurationFrontierCoverageWitness
              activations (appendHistory request) frontier request.2.2.term)

/--
Every positive authority frozen in an election ballot is covered by an
activation event through the frontier shared by the ballot and the event.
-/
def BallotConfigurationCoverage
    (activations : ActivationHistory Node TxId)
    (term : Nat)
    (record : ElectionRecord Node TxId)
    : Prop :=
  let authority := currentConfigurationAt record.ballotLog record.ballotCommitIndex
  0 < authority.index
  -> Exists
      fun activationIndex =>
        Exists
          fun activation =>
            let shared := min record.ballotCommitIndex activation.activationFrontier
            activations activationIndex = some activation
            /\ authority ∈ activation.governingActive
            /\ activation.activationTerm < term
            /\ authority.index <= shared
            /\ activation.history.take shared = record.ballotLog.take shared

/-- Immutable proof-only evidence retained after a successful ACK is dequeued. -/
structure ProcessedAckSnapshot (Node TxId : Type) where
  term : Nat
  index : Nat
  history : List (Entry Node TxId)

/-- Latest processed successful ACK evidence for each leader/peer pair. -/
abbrev ProcessedAckHistory (Node TxId : Type) :=
  Node -> Node -> Option (ProcessedAckSnapshot Node TxId)

/--
Proof-only evidence for one actual commit.  `commitFrontier` is the original
current-term quorum frontier; `supportedLength` may be a shorter prefix copied
to a follower without changing the actual commit term or ACK evidence.
`authority` is the configuration governing the original commit frontier.
-/
structure CommitEvidence (Node TxId : Type) where
  commitTerm : Nat
  history : List (Entry Node TxId)
  commitFrontier : Nat
  supportedLength : Nat
  authority : Configuration Node
  ackQuorum : Finset Node

/-- Retain the same actual commit evidence while supporting a shorter prefix. -/
def CommitEvidence.restrict (evidence : CommitEvidence Node TxId) (supportedLength : Nat)
    : CommitEvidence Node TxId :=
  { evidence with supportedLength }

/-- Current proof-only commit evidence retained by each node. -/
abbrev NodeCommitEvidence (Node TxId : Type) :=
  Node -> Option (CommitEvidence Node TxId)

/-- Commit evidence advertised by each immutable AppendEntries request. -/
abbrev RequestCommitEvidence (Node TxId : Type) :=
  AppendRequestKey Node TxId -> Option (CommitEvidence Node TxId)

/-- Entry terms do not decrease inside one proof-only history. -/
def MonoHistory (history : List (Entry Node TxId)) : Prop :=
  forall earlier later earlierEntry laterEntry,
    earlier < later
    -> entryAt? history earlier = some earlierEntry
    -> entryAt? history later = some laterEntry
    -> earlierEntry.term <= laterEntry.term

/-- One immutable log snapshot agrees with the canonical history of each entry. -/
def HistoryCanonical
    (canonicalHistory : Nat -> List (Entry Node TxId))
    (history : List (Entry Node TxId))
    : Prop :=
  forall index entry,
    entryAt? history index = some entry
    -> entryAt? (canonicalHistory entry.term) index = some entry
        /\ history.take index = (canonicalHistory entry.term).take index

/--
Every retained activation is tied to the same canonical histories and term
owners as the live logs and queued AppendEntries snapshots.
-/
structure ActivationCanonicalFacts
    (canonicalHistory : Nat -> List (Entry Node TxId))
    (owners : TermOwners Node)
    (activations : ActivationHistory Node TxId)
    : Prop where
  termOwner
    : forall index record,
        activations index = some record
        -> owners record.activationTerm = some record.leader
  recordCanonical
    : forall index record,
        activations index = some record
        -> HistoryCanonical canonicalHistory record.history
  activationFrontierCanonical
    : forall index record,
        activations index = some record
        -> record.history.take record.activationFrontier
            = (canonicalHistory record.activationTerm).take record.activationFrontier
  supporterCanonical
    : forall index record,
        activations index = some record
        -> forall supporter,
            supporter ∈ record.jointSupporters
            -> HistoryCanonical canonicalHistory (record.supporterHistory supporter)

/--
Temporal closure between immutable activation ACKs and later frozen ballots.
The shared-authority branch retains the exact intersecting voter snapshot from
which RequestVote freshness derives the promotion-prefix conclusion.
-/
structure ActivationElectionFacts
    (votes : VoteHistory Node)
    (elections : ElectionHistory Node TxId)
    (activations : ActivationHistory Node TxId)
    : Prop where
  closure
    : forall activationIndex activation electionTerm election,
        activations activationIndex = some activation
        -> elections electionTerm = some election
        -> activation.activationTerm < electionTerm
        -> activation.history.take activation.activationFrontier <+: election.promotionLog
            \/ Exists
                fun configuration =>
                  configuration ∈ activation.governingActive
                  /\ configuration ∈ election.ballotActive
                  /\ Exists
                      fun voter =>
                        voter ∈ activation.jointSupporters
                        /\ voter ∈ election.supporters
                        /\ votes voter electionTerm = some election.leader
                        /\ activation.history.take activation.activationFrontier
                            <+: election.voterLog voter
                        /\ activation.history.take activation.activationFrontier
                            <+: election.promotionLog

/-- Every log entry is from a term already observed by its local node. -/
def EntriesDoNotExceedCurrentTerm (state : Model.State Node TxId) : Prop :=
  forall node entry,
    entry ∈ ((nodeOf state) node).log -> entry.term <= ((nodeOf state) node).currentTerm

/-- Every participating node has reached the bootstrap term. -/
def CurrentTermsPositive (state : Model.State Node TxId) : Prop :=
  forall node,
    Not (((nodeOf state) node).role = .none)
    -> BOOTSTRAP_TERM <= ((nodeOf state) node).currentTerm

/-- Zero denotes an unknown term; numbered terms start at bootstrap. -/
def TermNumberValid (term : Nat) : Prop :=
  term = 0 \/ BOOTSTRAP_TERM <= term

/-- Inactive nodes retain either an unknown or a numbered current term. -/
def CurrentTermsValid (state : Model.State Node TxId) : Prop :=
  forall node, TermNumberValid ((nodeOf state) node).currentTerm

/-- Queued packets advertise only unknown or numbered terms. -/
def NetworkTermsValid (state : Model.State Node TxId) : Prop :=
  forall destination message,
    (message ∈ state.network /\ message.target = destination) -> TermNumberValid message.payload.term

/-- Candidates start each election with exactly their own persistent vote. -/
def CandidatesSelfVote (state : Model.State Node TxId) : Prop :=
  forall node,
    ((nodeOf state) node).role = .candidate
    -> ((nodeOf state) node).votedFor = some node /\ node ∈ ((nodeOf state) node).votesGranted

/-- Every runtime candidacy is for a post-bootstrap term. -/
def CandidatesAboveBootstrap (state : Model.State Node TxId) : Prop :=
  forall node,
    ((nodeOf state) node).role = .candidate
    -> BOOTSTRAP_TERM < ((nodeOf state) node).currentTerm

/-- Every active leader keeps both replication cursors inside its own log. -/
def LeaderProgressBounded (state : Model.State Node TxId) : Prop :=
  forall leader,
    ((nodeOf state) leader).role = .leader
    -> forall peer,
        ((nodeOf state) leader).sentIndex peer <= ((nodeOf state) leader).log.length
        /\ ((nodeOf state) leader).matchIndex peer <= ((nodeOf state) leader).log.length

/--
The proof history agrees with the runtime vote in the current term, is empty
in future terms, and justifies every vote counted by an active candidate or
leader.
-/
structure VoteHistoryFacts (state : Model.State Node TxId) (history : VoteHistory Node)
    : Prop where
  bootstrapEmpty : forall voter, history voter BOOTSTRAP_TERM = none
  current
    : forall voter,
        history voter ((nodeOf state) voter).currentTerm = ((nodeOf state) voter).votedFor
  future
    : forall voter term,
        ((nodeOf state) voter).currentTerm < term -> history voter term = none
  counted
    : forall candidate voter,
        (((nodeOf state) candidate).role = .candidate
          \/ ((nodeOf state) candidate).role = .leader)
        -> voter ∈ ((nodeOf state) candidate).votesGranted
        -> history voter ((nodeOf state) candidate).currentTerm = some candidate

/-- The unique synthetic key used to retain a granted vote after dequeue. -/
def grantedVoteKey (voter : Node) (term : Nat) (candidate : Node)
    : VoteResponseKey Node :=
  (voter, candidate, { term, voteGranted := true })

/-- The immutable fields of an AppendEntries request snapshot one history. -/
def RequestSnapshots
    (history : List (Entry Node TxId))
    (request : AppendRequestKey Node TxId)
    : Prop :=
  request.2.2.prevLogIndex + request.2.2.entries.length <= history.length
  /\ request.2.2.prevLogTerm = termAt history request.2.2.prevLogIndex
  /\ history.take (request.2.2.prevLogIndex + request.2.2.entries.length)
      = history.take request.2.2.prevLogIndex ++ request.2.2.entries

/--
An advertised commit is still represented by the source's current committed
log.  This survives delayed delivery because committed logs are append-only.
-/
def RequestCommitStillPresent
    (state : Model.State Node TxId)
    (history : List (Entry Node TxId))
    (request : AppendRequestKey Node TxId)
    : Prop :=
  history.take request.2.2.leaderCommit <+: ((nodeOf state) request.1).committedLog

/--
A successful response remembers an immutable source-log history.  While the
response is processable by its same-term destination leader, that history is
still a prefix of the leader's current append-only log.
-/
def SuccessfulResponseSnapshot
    (state : Model.State Node TxId)
    (history : List (Entry Node TxId))
    (response : AppendResponseKey Node)
    : Prop :=
  response.2.2.success = true
  -> response.2.2.lastLogIndex <= history.length
      /\ response.2.2.term <= ((nodeOf state) response.2.1).currentTerm
      /\ (response.2.2.term = ((nodeOf state) response.2.1).currentTerm
          -> (((nodeOf state) response.2.1).role = .leader
                /\ history <+: ((nodeOf state) response.2.1).log)
              \/ ((nodeOf state) response.2.1).role = .follower
              \/ ((nodeOf state) response.2.1).role = .preVoteCandidate
              \/ ((nodeOf state) response.2.1).role = .none)

/-- A vote snapshot ends exactly at its latest signature. -/
abbrev EndsAtMaxCommittable (history : List (Entry Node TxId)) : Prop :=
  maxCommittableIndex history = history.length

/--
Queued messages retain their immutable log/vote snapshots.  The witness
functions are proof-only maps keyed by complete message values.
-/
structure NetworkHistoryFacts
    (state : Model.State Node TxId)
    (appendHistory : AppendRequestKey Node TxId -> List (Entry Node TxId))
    (responseHistory : AppendResponseKey Node -> List (Entry Node TxId))
    (voteRequestHistory : VoteRequestKey Node -> List (Entry Node TxId))
    (voteCandidateHistory : VoteResponseKey Node -> List (Entry Node TxId))
    (voteVoterHistory : VoteResponseKey Node -> List (Entry Node TxId))
    (votes : VoteHistory Node)
    : Prop where
  addressed
    : forall destination message,
        (message ∈ state.network /\ message.target = destination) -> message.target = destination
  appendRequest
    : forall destination request,
        (appendRequestEnvelope request ∈ state.network /\ request.2.1 = destination)
        -> RequestSnapshots (appendHistory request) request
            /\ request.2.2.leaderCommit <= (appendHistory request).length
            /\ RequestCommitStillPresent state (appendHistory request) request
  appendResponse
    : forall destination response,
        (appendResponseEnvelope response ∈ state.network /\ response.2.1 = destination)
        -> SuccessfulResponseSnapshot state (responseHistory response) response
  voteRequest
    : forall destination request,
        (voteRequestEnvelope request ∈ state.network /\ request.2.1 = destination)
        -> request.2.2.lastCommittableIndex = (voteRequestHistory request).length
            /\ request.2.2.lastCommittableTerm
                = termAt (voteRequestHistory request) (voteRequestHistory request).length
            /\ EndsAtMaxCommittable (voteRequestHistory request)
            /\ BOOTSTRAP_TERM < request.2.2.term
            /\ request.2.2.term <= ((nodeOf state) request.1).currentTerm
            /\ (request.2.2.term = ((nodeOf state) request.1).currentTerm
                -> (((nodeOf state) request.1).role = .candidate
                    \/ ((nodeOf state) request.1).role = .leader)
                -> voteRequestHistory request <+: ((nodeOf state) request.1).log)
  voteResponse
    : forall destination response,
        (voteResponseEnvelope response ∈ state.network /\ response.2.1 = destination)
        -> response.2.2.voteGranted = true
        -> response.2.2.term <= ((nodeOf state) response.2.1).currentTerm
            /\ votes response.1 response.2.2.term = some response.2.1
            /\ EndsAtMaxCommittable (voteCandidateHistory response)
            /\ EndsAtMaxCommittable (voteVoterHistory response)
            /\ Model.Local.voteLogUpToDate
                { ((nodeOf state) response.1) with log := voteVoterHistory response }
                {
                  term := response.2.2.term
                  lastCommittableTerm :=
                    termAt
                      (voteCandidateHistory response)
                      (voteCandidateHistory response).length
                  lastCommittableIndex :=
                    (voteCandidateHistory response).length
                }

/-- Whether a granted same-term response is still queued at its candidate. -/
def queuedGrantedVote (state : Model.State Node TxId) (candidate voter : Node) : Prop :=
  Exists
    fun response =>
      (voteResponseEnvelope response ∈ state.network /\ response.2.1 = candidate)
      /\ response.2.2.voteGranted = true
      /\ response.2.2.term = ((nodeOf state) candidate).currentTerm
      /\ response.1 = voter
      /\ response.2.1 = candidate

/--
Processed votes and granted same-term responses still in flight are two
representations of the same election evidence.
-/
noncomputable def effectiveElectionVoters (state : Model.State Node TxId) (candidate : Node)
    : Finset Node := by
  classical
  exact
    joined.filter fun voter =>
      voter ∈ ((nodeOf state) candidate).votesGranted \/
        queuedGrantedVote state candidate voter

/-- A strict quorum of processed or queued granted votes. -/
def hasEffectiveElectionMajority (state : Model.State Node TxId) (candidate : Node) : Prop :=
  (activeConfigurations ((nodeOf state) candidate)).all
    fun configuration =>
      decide
        (hasConfigurationMajority (effectiveElectionVoters (joined := joined) state candidate) configuration)

noncomputable instance (state : Model.State Node TxId) (candidate : Node)
    : Decidable (hasEffectiveElectionMajority (joined := joined) state candidate) := by
  exact Classical.propDecidable _

/--
A node is currently eligible when the exact canonical RequestVote generated
from the candidate's current term and log would pass the grant predicate.
-/
def currentlyEligibleElectionVoter (state : Model.State Node TxId) (candidate voter : Node)
    : Prop :=
  let request := voteRequestKey state candidate voter
  request.2.2.term = ((nodeOf state) voter).currentTerm
  /\ Model.Local.voteLogUpToDate ((nodeOf state) voter) request.2.2
  /\ (((nodeOf state) voter).votedFor = none
      \/ ((nodeOf state) voter).votedFor = some candidate)

/--
Potential voters combine persistent processed/in-flight evidence with
nodes whose current state would grant the candidate's canonical request.
This is the source-side election evidence which exists before send or grant.
-/
noncomputable def potentialElectionVoters (state : Model.State Node TxId) (candidate : Node)
    : Finset Node := by
  classical
  exact
    joined.filter fun voter =>
      voter ∈ effectiveElectionVoters (joined := joined) state candidate \/
        currentlyEligibleElectionVoter state candidate voter

/-- A strict quorum of persistent or currently eligible election voters. -/
def hasPotentialElectionMajority (state : Model.State Node TxId) (candidate : Node) : Prop :=
  (activeConfigurations ((nodeOf state) candidate)).all
    fun configuration =>
      decide
        (hasConfigurationMajority (potentialElectionVoters (joined := joined) state candidate) configuration)

noncomputable instance (state : Model.State Node TxId) (candidate : Node)
    : Decidable (hasPotentialElectionMajority (joined := joined) state candidate) := by
  exact Classical.propDecidable _

/--
Election supporters after arbitrary local term/vote updates.  Effective
supporters retain their frozen vote snapshots; all other supporters are
classified only by the log-freshness check which a canonical vote request
would perform.
-/
noncomputable def relaxedElectionVoters (state : Model.State Node TxId) (candidate : Node)
    : Finset Node := by
  classical
  let request := voteRequestKey state candidate candidate
  exact
    joined.filter fun voter =>
      voter ∈ effectiveElectionVoters (joined := joined) state candidate \/
        (((nodeOf state) voter).currentTerm <=
            ((nodeOf state) candidate).currentTerm /\
          Model.Local.voteLogUpToDate ((nodeOf state) voter) request.2.2)

/--
Relaxed election support is still a strict majority in every active candidate
configuration; relaxing voter timing does not relax quorum authority.
-/
def hasRelaxedElectionMajority (state : Model.State Node TxId) (candidate : Node) : Prop :=
  (activeConfigurations ((nodeOf state) candidate)).all
    fun configuration =>
      decide
        (hasConfigurationMajority (relaxedElectionVoters (joined := joined) state candidate) configuration)

noncomputable instance (state : Model.State Node TxId) (candidate : Node)
    : Decidable (hasRelaxedElectionMajority (joined := joined) state candidate) := by
  exact Classical.propDecidable _

/--
Supporters for a future election term.  The candidate itself is always a
supporter; every other supporter must currently be no newer than the target
term and consider the unchanged candidate log up to date.
-/
noncomputable def futureElectionVoters
    (state : Model.State Node TxId)
    (candidate : Node)
    (targetTerm : Nat)
    : Finset Node := by
  classical
  let request :=
    { (voteRequestKey state candidate candidate).2.2 with
      term := targetTerm }
  exact
    joined.filter fun voter =>
      voter = candidate \/
        (((nodeOf state) voter).currentTerm <= targetTerm /\
          Model.Local.voteLogUpToDate ((nodeOf state) voter) request)

/--
Future election support is interpreted against an explicit frozen ballot
configuration list, rather than whichever configurations are active later.
-/
def hasFutureElectionMajority
    (state : Model.State Node TxId)
    (candidate : Node)
    (targetTerm : Nat)
    (ballotActive : List (Configuration Node))
    : Prop :=
  ballotActive.all
    fun configuration =>
      decide
        (hasConfigurationMajority
          (futureElectionVoters (joined := joined) state candidate targetTerm)
          configuration)

noncomputable instance
    (state : Model.State Node TxId)
    (candidate : Node)
    (targetTerm : Nat)
    (ballotActive : List (Configuration Node))
    : Decidable (hasFutureElectionMajority (joined := joined) state candidate targetTerm ballotActive) := by
  exact Classical.propDecidable _

/--
Each processed or queued vote has a persistent proof-only snapshot.  The
synthetic key lets response dequeue retain the candidate/voter histories and
their original RequestVote up-to-date check without adding runtime state.
-/
def GrantedVoteSnapshots
    (state : Model.State Node TxId)
    (votes : VoteHistory Node)
    (voteCandidateHistory : VoteResponseKey Node -> List (Entry Node TxId))
    (voteVoterHistory : VoteResponseKey Node -> List (Entry Node TxId))
    : Prop :=
  forall candidate voter,
    (((nodeOf state) candidate).role = .candidate \/ ((nodeOf state) candidate).role = .leader)
    -> voter ∈ effectiveElectionVoters (joined := joined) state candidate
    ->  let response := grantedVoteKey voter ((nodeOf state) candidate).currentTerm candidate
        votes voter ((nodeOf state) candidate).currentTerm = some candidate
        /\ (voter = candidate
            \/ (voteCandidateHistory response <+: ((nodeOf state) candidate).log
                /\ EndsAtMaxCommittable (voteCandidateHistory response)
                /\ EndsAtMaxCommittable (voteVoterHistory response)
                /\ response.2.2.term <= ((nodeOf state) voter).currentTerm
                /\ Model.Local.voteLogUpToDate
                    { ((nodeOf state) voter) with log := voteVoterHistory response }
                    {
                      term := response.2.2.term
                      lastCommittableTerm :=
                        termAt
                          (voteCandidateHistory response)
                          (voteCandidateHistory response).length
                      lastCommittableIndex :=
                        (voteCandidateHistory response).length
                    }))

/-- Active election snapshots retain canonical agreement for both log views. -/
def GrantedVoteCanonicalSnapshots
    (state : Model.State Node TxId)
    (canonicalHistory : Nat -> List (Entry Node TxId))
    (voteCandidateHistory voteVoterHistory
      : VoteResponseKey Node -> List (Entry Node TxId))
    : Prop :=
  forall candidate voter,
    (((nodeOf state) candidate).role = .candidate \/ ((nodeOf state) candidate).role = .leader)
    -> voter ∈ effectiveElectionVoters (joined := joined) state candidate
    -> voter = candidate
        \/ (HistoryCanonical
              canonicalHistory
              (voteCandidateHistory
                (grantedVoteKey voter ((nodeOf state) candidate).currentTerm candidate))
            /\ MonoHistory
                (voteCandidateHistory
                  (grantedVoteKey voter ((nodeOf state) candidate).currentTerm candidate))
            /\ HistoryCanonical
                canonicalHistory
                (voteVoterHistory
                  (grantedVoteKey voter ((nodeOf state) candidate).currentTerm candidate))
            /\ MonoHistory
                (voteVoterHistory
                  (grantedVoteKey voter ((nodeOf state) candidate).currentTerm candidate)))

/-- Voters whose retained term-indexed choices name one candidate. -/
noncomputable def historicalElectionVoters
    (configuration : Configuration Node)
    (votes : VoteHistory Node)
    (term : Nat)
    (candidate : Node)
    : Finset Node := by
  classical
  exact configuration.nodes.filter fun voter =>
    votes voter term = some candidate

/-- A strict quorum of persistent voter choices elected one term owner. -/
def hasHistoricalElectionMajority
    (votes : VoteHistory Node)
    (term : Nat)
    (candidate : Node)
    (configuration : Configuration Node)
    : Prop :=
  hasConfigurationMajority
    (historicalElectionVoters configuration votes term candidate)
    configuration

noncomputable instance
    (votes : VoteHistory Node)
    (term : Nat)
    (candidate : Node)
    (configuration : Configuration Node)
    : Decidable (hasHistoricalElectionMajority votes term candidate configuration) := by
  exact Classical.propDecidable _

/--
Term ownership is proof-only election history.  Leaders claim their term when
promoted. Canonical histories identify the owner of every represented entry,
while election records retain the provenance of every owned term.
-/
structure TermOwnershipFacts
    (state : Model.State Node TxId)
    (votes : VoteHistory Node)
    (appendHistory : AppendRequestKey Node TxId -> List (Entry Node TxId))
    (canonicalHistory : Nat -> List (Entry Node TxId))
    (owners : TermOwners Node)
    : Prop where
  bootstrap : owners BOOTSTRAP_TERM = some INITIAL_LEADER
  activeLeader
    : forall leader,
        ((nodeOf state) leader).role = .leader
        -> owners ((nodeOf state) leader).currentTerm = some leader
  logEntryAgreement
    : forall node index entry,
        entryAt? ((nodeOf state) node).log index = some entry
        -> entryAt? (canonicalHistory entry.term) index = some entry
            /\ ((nodeOf state) node).log.take index
                = (canonicalHistory entry.term).take index
  queuedHistoryEntryAgreement
    : forall destination request,
        (appendRequestEnvelope request ∈ state.network /\ request.2.1 = destination)
        -> forall index entry,
            entryAt? (appendHistory request) index = some entry
            -> entryAt? (canonicalHistory entry.term) index = some entry
                /\ (appendHistory request).take index
                    = (canonicalHistory entry.term).take index
  activeLeaderHistory
    : forall leader,
        ((nodeOf state) leader).role = .leader
        -> canonicalHistory ((nodeOf state) leader).currentTerm = ((nodeOf state) leader).log
  canonicalEntryOwner
    : forall term index entry,
        entryAt? (canonicalHistory term) index = some entry
        -> Exists fun owner => owners entry.term = some owner
  canonicalMonoLog : forall term, MonoHistory (canonicalHistory term)
  /-- A current-term owner is active or has stepped down without a new term. -/
  ownerProgress
    : forall term owner,
        owners term = some owner
        -> term <= ((nodeOf state) owner).currentTerm
            /\ (term = ((nodeOf state) owner).currentTerm
                -> ((nodeOf state) owner).role = .leader
                    \/ ((nodeOf state) owner).role = .follower
                    \/ ((nodeOf state) owner).role = .preVoteCandidate
                    \/ ((nodeOf state) owner).role = .none)
  queuedAppendMetadata
    : forall destination request,
        (appendRequestEnvelope request ∈ state.network /\ request.2.1 = destination)
        -> Not (request.1 = request.2.1)
            /\ owners request.2.2.term = some request.1
            /\ forall entry, entry ∈ appendHistory request -> entry.term <= request.2.2.term
  queuedActiveSourceHistory
    : forall destination request,
        (appendRequestEnvelope request ∈ state.network /\ request.2.1 = destination)
        -> request.2.2.term = ((nodeOf state) request.1).currentTerm
        -> ((nodeOf state) request.1).role = .leader
        -> appendHistory request <+: ((nodeOf state) request.1).log

/--
Every non-bootstrap owned term retains the exact supporters, ballot
configurations, and log snapshots which elected it. These immutable records
support induction across elections which happened before an old prefix became
fully quorum-supported.
-/
structure ElectionHistoryFacts
    (state : Model.State Node TxId)
    (votes : VoteHistory Node)
    (canonicalHistory : Nat -> List (Entry Node TxId))
    (owners : TermOwners Node)
    (elections : ElectionHistory Node TxId)
    : Prop where
  recordOwned
    : forall term record, elections term = some record -> owners term = some record.leader
  ownerRecorded
    : forall term owner,
        owners term = some owner
        -> ((term = BOOTSTRAP_TERM /\ owner = INITIAL_LEADER)
            \/ Exists
                fun record =>
                  elections term = some record /\ record.leader = owner)
  majority
    : forall term record,
        elections term = some record
        -> forall configuration,
            configuration ∈ record.ballotActive
            -> hasConfigurationMajority record.supporters configuration
  voted
    : forall term record voter,
        elections term = some record
        -> voter ∈ record.supporters
        -> votes voter term = some record.leader
  ballotConfigurations
    : forall term record,
        elections term = some record
        -> record.ballotActive
            = activeConfigurations
                {
                  ((nodeOf state) record.leader) with
                    log := record.ballotLog
                    commitIndex := record.ballotCommitIndex
                }
  promotionFromBallot
    : forall term record,
        elections term = some record
        -> record.promotionLog
            = record.ballotLog.take (maxCommittableIndex record.ballotLog)
  promotionCanonical
    : forall term record,
        elections term = some record -> record.promotionLog <+: canonicalHistory term
  /--
  Primitive provenance for the immutable promotion snapshot's shape, not a
  stored safety conclusion. Retain it even when no current derivation reads it.
  -/
  promotionCommittable
    : forall term record,
        elections term = some record -> EndsAtMaxCommittable record.promotionLog
  promotionEntriesBeforeTerm
    : forall term record,
        elections term = some record
        -> forall entry, entry ∈ record.promotionLog -> entry.term < term
  candidatePrefix
    : forall term record voter,
        elections term = some record
        -> voter ∈ record.supporters
        -> record.candidateLog voter <+: record.promotionLog
  candidateCanonical
    : forall term record voter,
        elections term = some record
        -> voter ∈ record.supporters
        -> HistoryCanonical canonicalHistory (record.candidateLog voter)
  /--
  Primitive provenance for each immutable candidate vote snapshot's shape,
  not a stored safety conclusion. Retain it even when no current derivation
  reads it.
  -/
  candidateCommittable
    : forall term record voter,
        elections term = some record
        -> voter ∈ record.supporters
        -> EndsAtMaxCommittable (record.candidateLog voter)
  voterCanonical
    : forall term record voter,
        elections term = some record
        -> voter ∈ record.supporters
        -> HistoryCanonical canonicalHistory (record.voterLog voter)
  voterCommittable
    : forall term record voter,
        elections term = some record
        -> voter ∈ record.supporters
        -> EndsAtMaxCommittable (record.voterLog voter)
  upToDate
    : forall term record voter,
        elections term = some record
        -> voter ∈ record.supporters
        -> Model.Local.voteLogUpToDate
            { ((nodeOf state) voter) with log := record.voterLog voter }
            {
              term
              lastCommittableTerm :=
                termAt (record.candidateLog voter) (record.candidateLog voter).length
              lastCommittableIndex :=
                (record.candidateLog voter).length
            }
  termAboveBootstrap
    : forall term record, elections term = some record -> BOOTSTRAP_TERM < term

/-- Every queued leader history contains that term's promotion snapshot. -/
def ElectionQueuedHistoryFacts
    (state : Model.State Node TxId)
    (appendHistory : AppendRequestKey Node TxId -> List (Entry Node TxId))
    (elections : ElectionHistory Node TxId)
    : Prop :=
  forall destination request,
    (appendRequestEnvelope request ∈ state.network /\ request.2.1 = destination)
    -> forall record,
        elections request.2.2.term = some record
        -> record.promotionLog <+: appendHistory request

/--
Any live candidate with materialised winning support in an already-owned term
shares a governing configuration with that term's frozen ballot. For a stale
ballot, the shared configuration is supplied by the permanent activation chain
rather than by a global fixed-world quorum.
-/
structure ElectionConfigurationFacts
    (state : Model.State Node TxId)
    (elections : ElectionHistory Node TxId)
    (activations : ActivationHistory Node TxId)
    : Prop where
  ballotCommittedFrontierSignature
    : forall term record,
        elections term = some record
        -> record.ballotCommitIndex <= maxCommittableIndex record.ballotLog
            /\ (0 < record.ballotCommitIndex
                -> isSignatureAt record.ballotLog record.ballotCommitIndex = true)
  ballotCurrentAuthorityActivation
    : forall term record,
        elections term = some record
        -> BallotConfigurationCoverage activations term record
  ballotCurrentAuthorityActive
    : forall term record,
        elections term = some record
        -> currentConfigurationAt record.ballotLog record.ballotCommitIndex
            ∈ record.ballotActive
  supporterCurrentHistory : ActivationSupporterCurrentHistory state elections activations
  potentialShared
    : forall term record candidate,
        elections term = some record
        -> ((nodeOf state) candidate).role = .candidate
        -> ((nodeOf state) candidate).currentTerm = term
        -> hasEffectiveElectionMajority (joined := joined) state candidate
        -> Exists
            fun configuration =>
              configuration ∈ record.ballotActive
              /\ configuration ∈ activeConfigurations ((nodeOf state) candidate)
  effectiveCandidatesShared
    : forall left right,
        ((nodeOf state) left).role = .candidate
        -> ((nodeOf state) right).role = .candidate
        -> ((nodeOf state) left).currentTerm = ((nodeOf state) right).currentTerm
        -> hasEffectiveElectionMajority (joined := joined) state left
        -> hasEffectiveElectionMajority (joined := joined) state right
        -> Exists
            fun configuration =>
              configuration ∈ activeConfigurations ((nodeOf state) left)
              /\ configuration ∈ activeConfigurations ((nodeOf state) right)
  candidateEntriesBeforeTerm
    : forall candidate,
        ((nodeOf state) candidate).role = .candidate
        -> forall entry,
            entry ∈ ((nodeOf state) candidate).log
            -> entry.term < ((nodeOf state) candidate).currentTerm

/--
Every locally committed log is represented by a member of every strict
majority of that node's current configuration. This is the
configuration-qualified form of `QuorumLogInv` from `ccfraft.tla`.
-/
def QuorumLog (state : Model.State Node TxId) : Prop :=
  forall node configuration,
    configuration = currentConfiguration ((nodeOf state) node)
    -> forall quorum : Finset Node,
        hasConfigurationMajority quorum configuration
        -> Exists
            fun witness =>
              witness ∈ configuration.nodes
              /\ witness ∈ quorum
              /\ ((nodeOf state) node).committedLog <+: ((nodeOf state) witness).log

/-- Whether one queued successful response acknowledges an index for a leader. -/
def queuedSuccessfulAck
    (state : Model.State Node TxId)
    (responseHistory : AppendResponseKey Node -> List (Entry Node TxId))
    (leader peer : Node)
    (index : Nat)
    : Prop :=
  Exists
    fun response =>
      (appendResponseEnvelope response ∈ state.network /\ response.2.1 = leader)
      /\ response.2.2.success = true
      /\ response.2.2.term = ((nodeOf state) leader).currentTerm
      /\ response.1 = peer
      /\ response.2.1 = leader
      /\ index <= response.2.2.lastLogIndex
      /\ responseHistory response <+: ((nodeOf state) leader).log

/--
Processed match indices and same-term successful responses still queued at the
leader are two representations of the same acknowledgement evidence.
-/
noncomputable def effectiveAckers
    (state : Model.State Node TxId)
    (responseHistory : AppendResponseKey Node -> List (Entry Node TxId))
    (leader : Node)
    (index : Nat)
    : Finset Node := by
  classical
  exact
    joined.filter fun node =>
      node = leader \/
        ((nodeOf state) leader).matchIndex node >= index \/
        queuedSuccessfulAck state responseHistory leader node index

/-- A strict quorum of processed or queued successful acknowledgements. -/
def hasEffectiveMajorityAt
    (state : Model.State Node TxId)
    (responseHistory : AppendResponseKey Node -> List (Entry Node TxId))
    (leader : Node)
    (index : Nat)
    : Prop :=
  (activeConfigurations ((nodeOf state) leader)).all
    fun configuration =>
      decide
        (configuration.index <= index
          -> hasConfigurationMajority
              (effectiveAckers (joined := joined) state responseHistory leader index)
              configuration)

noncomputable instance
    (state : Model.State Node TxId)
    (responseHistory : AppendResponseKey Node -> List (Entry Node TxId))
    (leader : Node)
    (index : Nat)
    : Decidable (hasEffectiveMajorityAt (joined := joined) state responseHistory leader index) := by
  exact Classical.propDecidable _

/-- A follower can accept a request without first changing its term or role. -/
def canProduceAppendAckAt
    (node : NodeState Node TxId)
    (request : AppendRequestKey Node TxId)
    (index : Nat)
    : Prop :=
  Exists
    fun nextNode =>
      Exists
        fun response =>
          Model.Local.acceptAppendEntriesRequest? request.2.1 node request.2.2
            = some (nextNode, response)
          /\ response.success = true
          /\ index <= response.lastLogIndex

/-- The exact local node update performed after observing a newer term. -/
def prepareNodeForUpdateTerm (node : NodeState Node TxId) (term : Nat)
    : NodeState Node TxId :=
  {
    node with
      role := .follower
      currentTerm := term
      isNewFollower := true
      votedFor := none
  }

/--
A request is ACKable now, or becomes directly ACKable after the exact local
UpdateTerm preparation for its term.
-/
def canProduceAppendAckEventuallyAt
    (node : NodeState Node TxId)
    (request : AppendRequestKey Node TxId)
    (index : Nat)
    : Prop :=
  canProduceAppendAckAt node request index
  \/ (node.currentTerm < request.2.2.term
      /\ index <= request.2.2.prevLogIndex + request.2.2.entries.length)

/--
A queued request reserves one future acknowledgement while it is directly
ACKable now or after observing its newer term.
-/
def queuedAppendReserve
    (state : Model.State Node TxId)
    (appendHistory : AppendRequestKey Node TxId -> List (Entry Node TxId))
    (leader peer : Node)
    (index : Nat)
    : Prop :=
  Exists
    fun request =>
      (appendRequestEnvelope request ∈ state.network /\ request.2.1 = peer)
      /\ request.1 = leader
      /\ request.2.1 = peer
      /\ request.2.2.term = ((nodeOf state) leader).currentTerm
      /\ canProduceAppendAckEventuallyAt ((nodeOf state) peer) request index
      /\ appendHistory request <+: ((nodeOf state) leader).log

/--
Potential supporters combine materialised acknowledgements with queued
requests which can still materialise one.  This is proof-only Raft
committability, independent of `commitIndex` and CCF signature committability.
-/
noncomputable def potentialAckers
    (state : Model.State Node TxId)
    (appendHistory : AppendRequestKey Node TxId -> List (Entry Node TxId))
    (responseHistory : AppendResponseKey Node -> List (Entry Node TxId))
    (leader : Node)
    (index : Nat)
    : Finset Node := by
  classical
  exact
    joined.filter fun node =>
      node ∈ effectiveAckers (joined := joined) state responseHistory leader index \/
        queuedAppendReserve state appendHistory leader node index

/-- A strict quorum of materialised or still-reserved acknowledgements. -/
def hasPotentialMajorityAt
    (state : Model.State Node TxId)
    (appendHistory : AppendRequestKey Node TxId -> List (Entry Node TxId))
    (responseHistory : AppendResponseKey Node -> List (Entry Node TxId))
    (leader : Node)
    (index : Nat)
    : Prop :=
  (activeConfigurations ((nodeOf state) leader)).all
    fun configuration =>
      decide
        (configuration.index <= index
          -> hasConfigurationMajority
              (potentialAckers (joined := joined) state appendHistory responseHistory leader index)
              configuration)

noncomputable instance
    (state : Model.State Node TxId)
    (appendHistory : AppendRequestKey Node TxId -> List (Entry Node TxId))
    (responseHistory : AppendResponseKey Node -> List (Entry Node TxId))
    (leader : Node)
    (index : Nat)
    : Decidable
        (hasPotentialMajorityAt (joined := joined) state appendHistory responseHistory leader index) := by
  exact Classical.propDecidable _

/--
Permanent activation history either provides a direct signed-prefix bridge
into a successor ballot, or identifies one governing configuration on which
the old replication support and successor election support intersect.
-/
structure ActivationQuorumFacts
    (state : Model.State Node TxId)
    (appendHistory : AppendRequestKey Node TxId -> List (Entry Node TxId))
    (responseHistory : AppendResponseKey Node -> List (Entry Node TxId))
    (elections : ElectionHistory Node TxId)
    (activations : ActivationHistory Node TxId)
    : Prop where
  history : ActivationHistoryFacts activations
  recordBridge
    : forall source index,
        ((nodeOf state) source).role = .leader
        -> termAt ((nodeOf state) source).log index = ((nodeOf state) source).currentTerm
        -> isSignatureAt ((nodeOf state) source).log index = true
        -> hasPotentialMajorityAt (joined := joined) state appendHistory responseHistory source index
        -> forall term record,
            elections term = some record
            -> ((nodeOf state) source).currentTerm < term
            -> ((nodeOf state) source).log.take index <+: record.promotionLog
                \/ Exists
                    fun configuration =>
                      configuration ∈ activeConfigurations ((nodeOf state) source)
                      /\ configuration.index <= index
                      /\ configuration ∈ record.ballotActive
  candidateBridge
    : forall source index,
        ((nodeOf state) source).role = .leader
        -> termAt ((nodeOf state) source).log index = ((nodeOf state) source).currentTerm
        -> isSignatureAt ((nodeOf state) source).log index = true
        -> hasPotentialMajorityAt (joined := joined) state appendHistory responseHistory source index
        -> forall candidate,
            ((nodeOf state) candidate).role = .candidate
            -> hasPotentialElectionMajority (joined := joined) state candidate
            -> ((nodeOf state) source).currentTerm < ((nodeOf state) candidate).currentTerm
            -> ((nodeOf state) source).log.take index <+: ((nodeOf state) candidate).log
                \/ Exists
                    fun configuration =>
                      configuration ∈ activeConfigurations ((nodeOf state) source)
                      /\ configuration.index <= index
                      /\ configuration ∈ activeConfigurations ((nodeOf state) candidate)
  committedBridge
    : forall source index,
        ((nodeOf state) source).role = .leader
        -> termAt ((nodeOf state) source).log index = ((nodeOf state) source).currentTerm
        -> isSignatureAt ((nodeOf state) source).log index = true
        -> hasEffectiveMajorityAt (joined := joined) state responseHistory source index
        -> forall node,
            ((nodeOf state) source).log.take index <+: ((nodeOf state) node).committedLog
            \/ ((nodeOf state) node).committedLog <+: ((nodeOf state) source).log.take index
            \/ Exists
                fun configuration =>
                  configuration ∈ activeConfigurations ((nodeOf state) source)
                  /\ configuration.index <= index
                  /\ configuration = currentConfiguration ((nodeOf state) node)
  potentialBridge
    : forall left leftIndex,
        ((nodeOf state) left).role = .leader
        -> termAt ((nodeOf state) left).log leftIndex = ((nodeOf state) left).currentTerm
        -> isSignatureAt ((nodeOf state) left).log leftIndex = true
        -> hasEffectiveMajorityAt (joined := joined) state responseHistory left leftIndex
        -> forall right rightIndex,
            ((nodeOf state) right).role = .leader
            -> termAt ((nodeOf state) right).log rightIndex = ((nodeOf state) right).currentTerm
            -> isSignatureAt ((nodeOf state) right).log rightIndex = true
            -> hasEffectiveMajorityAt (joined := joined) state responseHistory right rightIndex
            -> ((nodeOf state) left).log.take leftIndex
                  <+: ((nodeOf state) right).log.take rightIndex
                \/ ((nodeOf state) right).log.take rightIndex
                    <+: ((nodeOf state) left).log.take leftIndex
                \/ Exists
                    fun configuration =>
                      configuration ∈ activeConfigurations ((nodeOf state) left)
                      /\ configuration.index <= leftIndex
                      /\ configuration ∈ activeConfigurations ((nodeOf state) right)
                      /\ configuration.index <= rightIndex
  queuedComparable
    : forall activationIndex activation destination request,
        activations activationIndex = some activation
        -> (appendRequestEnvelope request ∈ state.network /\ request.2.1 = destination)
        -> request.2.2.term = activation.activationTerm
        -> activation.history.take activation.activationFrontier <+: appendHistory request
            \/ appendHistory request
                <+: activation.history.take activation.activationFrontier
  committedCoverage : CommittedConfigurationCoverage state activations
  queuedCoverage : QueuedConfigurationCoverage state appendHistory activations

/--
An ACK supporter which later participates in an election either still had the
acknowledged prefix in its frozen voter log, or some strictly intermediate
elected term had already lost that prefix.  The latter alternative is what a
least-counterexample induction rules out.
-/
def AckerElectionHistory
    (state : Model.State Node TxId)
    (responseHistory : AppendResponseKey Node -> List (Entry Node TxId))
    (elections : ElectionHistory Node TxId)
    : Prop :=
  forall source index,
    ((nodeOf state) source).role = .leader
    -> termAt ((nodeOf state) source).log index = ((nodeOf state) source).currentTerm
    -> isSignatureAt ((nodeOf state) source).log index = true
    -> forall term record voter,
        elections term = some record
        -> voter ∈ record.supporters
        -> voter ∈ effectiveAckers (joined := joined) state responseHistory source index
        -> ((nodeOf state) source).currentTerm < term
        -> ((nodeOf state) source).log.take index <+: record.voterLog voter
            \/ Exists
                fun earlierTerm =>
                  Exists
                    fun earlierRecord =>
                      ((nodeOf state) source).currentTerm < earlierTerm
                      /\ earlierTerm < term
                      /\ elections earlierTerm = some earlierRecord
                      /\ Not
                          (((nodeOf state) source).log.take index
                            <+: earlierRecord.promotionLog)

/--
An ACK supporter which later acknowledges a configuration activation retains
the lower-term signed prefix in its immutable activation snapshot, unless an
intervening election no later than the activation term already omitted it.
-/
def AckerActivationHistory
    (state : Model.State Node TxId)
    (responseHistory : AppendResponseKey Node -> List (Entry Node TxId))
    (elections : ElectionHistory Node TxId)
    (activations : ActivationHistory Node TxId)
    : Prop :=
  forall source index,
    ((nodeOf state) source).role = .leader
    -> termAt ((nodeOf state) source).log index = ((nodeOf state) source).currentTerm
    -> isSignatureAt ((nodeOf state) source).log index = true
    -> forall activationIndex activation configuration supporter,
        activations activationIndex = some activation
        -> configuration ∈ activation.governingActive
        -> supporter ∈ activation.jointSupporters
        -> supporter ∈ effectiveAckers (joined := joined) state responseHistory source index
        -> ((nodeOf state) source).currentTerm < activation.activationTerm
        -> ((nodeOf state) source).log.take index <+: activation.supporterHistory supporter
            \/ Exists
                fun earlierTerm =>
                  Exists
                    fun earlierRecord =>
                      ((nodeOf state) source).currentTerm < earlierTerm
                      /\ earlierTerm <= activation.activationTerm
                      /\ elections earlierTerm = some earlierRecord
                      /\ Not
                          (((nodeOf state) source).log.take index
                            <+: earlierRecord.promotionLog)

/-- Some elected term up to a bound is the first known loss of one prefix. -/
def EarlierBadElection
    (state : Model.State Node TxId)
    (elections : ElectionHistory Node TxId)
    (source : Node)
    (index bound : Nat)
    : Prop :=
  EarlierBadElectionForPrefix
    elections
    (((nodeOf state) source).log.take index)
    ((nodeOf state) source).currentTerm
    bound

/--
A materialised ACK remains in the supporter's current log unless an elected
intermediate term has already omitted it.
-/
def AckerCurrentHistory
    (state : Model.State Node TxId)
    (responseHistory : AppendResponseKey Node -> List (Entry Node TxId))
    (elections : ElectionHistory Node TxId)
    : Prop :=
  forall source index,
    ((nodeOf state) source).role = .leader
    -> termAt ((nodeOf state) source).log index = ((nodeOf state) source).currentTerm
    -> isSignatureAt ((nodeOf state) source).log index = true
    -> forall voter,
        voter ∈ effectiveAckers (joined := joined) state responseHistory source index
        -> ((nodeOf state) source).log.take index <+: ((nodeOf state) voter).log
            \/ EarlierBadElection
                state elections source index
                ((nodeOf state) voter).currentTerm

/--
When a non-self voter records a higher-term vote, every earlier ACK prefix is
present in that immutable voter snapshot unless an already elected
intermediate term omitted it.
-/
def AckerVoteHistory
    (state : Model.State Node TxId)
    (votes : VoteHistory Node)
    (responseHistory : AppendResponseKey Node -> List (Entry Node TxId))
    (voteVoterHistory : VoteResponseKey Node -> List (Entry Node TxId))
    (elections : ElectionHistory Node TxId)
    : Prop :=
  forall source index,
    ((nodeOf state) source).role = .leader
    -> termAt ((nodeOf state) source).log index = ((nodeOf state) source).currentTerm
    -> isSignatureAt ((nodeOf state) source).log index = true
    -> forall voter voteTerm candidate,
        voter ∈ effectiveAckers (joined := joined) state responseHistory source index
        -> votes voter voteTerm = some candidate
        -> Not (voter = candidate)
        -> ((nodeOf state) source).currentTerm < voteTerm
        -> ((nodeOf state) source).log.take index
              <+: voteVoterHistory (grantedVoteKey voter voteTerm candidate)
            \/ EarlierBadElection state elections source index voteTerm

/--
An activation supporter which later grants a non-self vote retains the signed
activation prefix in its immutable voter snapshot, unless an intervening
election already provides the induction handoff.
-/
def ActivationVoteHistory
    (votes : VoteHistory Node)
    (voteVoterHistory : VoteResponseKey Node -> List (Entry Node TxId))
    (elections : ElectionHistory Node TxId)
    (activations : ActivationHistory Node TxId)
    : Prop :=
  forall activationIndex activation voter voteTerm candidate,
    activations activationIndex = some activation
    -> voter ∈ activation.jointSupporters
    -> votes voter voteTerm = some candidate
    -> Not (voter = candidate)
    -> activation.activationTerm < voteTerm
    -> activation.history.take activation.activationFrontier
          <+: voteVoterHistory (grantedVoteKey voter voteTerm candidate)
        \/ EarlierBadElectionForPrefix
            elections
            (activation.history.take activation.activationFrontier)
            activation.activationTerm
            voteTerm

/--
Each positive active-leader match frontier is justified by an immutable
successful-ACK history.  A zero frontier has no processed evidence.
-/
structure ProcessedAckHistoryFacts
    (state : Model.State Node TxId)
    (history : ProcessedAckHistory Node TxId)
    : Prop where
  zero
    : forall leader,
        ((nodeOf state) leader).role = .leader
        -> forall peer,
            ((nodeOf state) leader).matchIndex peer = 0 -> history leader peer = none
  positive
    : forall leader,
        ((nodeOf state) leader).role = .leader
        -> forall peer,
            0 < ((nodeOf state) leader).matchIndex peer
            -> Exists
                fun snapshot =>
                  history leader peer = some snapshot
                  /\ snapshot.term = ((nodeOf state) leader).currentTerm
                  /\ snapshot.index = ((nodeOf state) leader).matchIndex peer
                  /\ snapshot.index <= snapshot.history.length
                  /\ snapshot.history.take snapshot.index
                      = ((nodeOf state) leader).log.take snapshot.index

/-- One evidence value exactly justifies the supplied committed prefix. -/
def CommitEvidence.Valid
    (evidence : CommitEvidence Node TxId)
    (supportedPrefix : List (Entry Node TxId))
    : Prop :=
  evidence.commitFrontier <= evidence.history.length
  /\ termAt evidence.history evidence.commitFrontier = evidence.commitTerm
  /\ evidence.supportedLength <= evidence.commitFrontier
  /\ evidence.history.take evidence.supportedLength = supportedPrefix
  /\ evidence.authority = currentConfigurationAt evidence.history evidence.commitFrontier
  /\ hasConfigurationMajority evidence.ackQuorum evidence.authority
  /\ isSignatureAt evidence.history evidence.commitFrontier = true
  /\ (0 < evidence.supportedLength
      -> isSignatureAt evidence.history evidence.supportedLength = true)

/--
Evidence is known only when it occupies a live proof-state slot: either
it supports a node's current nonempty committed log, or it is attached to a
currently queued nonempty AppendEntries commit advertisement.
-/
def KnownCommitEvidence
    (state : Model.State Node TxId)
    (appendHistory : AppendRequestKey Node TxId -> List (Entry Node TxId))
    (nodeEvidence : NodeCommitEvidence Node TxId)
    (requestEvidence : RequestCommitEvidence Node TxId)
    (evidence : CommitEvidence Node TxId)
    (supportedPrefix : List (Entry Node TxId))
    : Prop :=
  (Exists
    fun node =>
      0 < ((nodeOf state) node).commitIndex
      /\ nodeEvidence node = some evidence
      /\ supportedPrefix = ((nodeOf state) node).committedLog)
  \/ (Exists
        fun destination =>
          Exists
            fun request =>
              (appendRequestEnvelope request ∈ state.network /\ request.2.1 = destination)
              /\ 0 < request.2.2.leaderCommit
              /\ requestEvidence request = some evidence
              /\ supportedPrefix = (appendHistory request).take request.2.2.leaderCommit)

/--
Current nonempty commits and queued nonempty leader-commit advertisements
carry proof-only evidence.  Zero-valued slots are outside the live evidence
relation and remain unconstrained.
-/
structure CommitEvidenceFacts
    (state : Model.State Node TxId)
    (appendHistory : AppendRequestKey Node TxId -> List (Entry Node TxId))
    (nodeEvidence : NodeCommitEvidence Node TxId)
    (requestEvidence : RequestCommitEvidence Node TxId)
    : Prop where
  nodePositive
    : forall node,
        0 < ((nodeOf state) node).commitIndex
        -> Exists
            fun evidence =>
              nodeEvidence node = some evidence
              /\ evidence.Valid ((nodeOf state) node).committedLog
              /\ evidence.supportedLength = ((nodeOf state) node).commitIndex
              /\ evidence.commitTerm <= ((nodeOf state) node).currentTerm
  requestPositive
    : forall destination request,
        (appendRequestEnvelope request ∈ state.network /\ request.2.1 = destination)
        -> 0 < request.2.2.leaderCommit
        -> Exists
            fun evidence =>
              requestEvidence request = some evidence
              /\ evidence.Valid ((appendHistory request).take request.2.2.leaderCommit)
              /\ evidence.supportedLength = request.2.2.leaderCommit
              /\ evidence.commitTerm <= request.2.2.term

/--
Per-ACK prospective closure retained with each live commit witness.  These
member-wise facts are stronger than a current majority statement: they remain
usable when one newly eligible voter creates the first election majority.
-/
structure ProspectiveCommitEvidenceFacts
    (state : Model.State Node TxId)
    (appendHistory : AppendRequestKey Node TxId -> List (Entry Node TxId))
    (nodeEvidence : NodeCommitEvidence Node TxId)
    (requestEvidence : RequestCommitEvidence Node TxId)
    (elections : ElectionHistory Node TxId)
    : Prop where
  commitTermPositive
    : forall evidence supportedPrefix,
        KnownCommitEvidence
          state appendHistory nodeEvidence requestEvidence
          evidence supportedPrefix
        -> BOOTSTRAP_TERM <= evidence.commitTerm
  electionClosure
    : forall evidence supportedPrefix,
        KnownCommitEvidence
          state appendHistory nodeEvidence requestEvidence
          evidence supportedPrefix
        -> forall term record,
            elections term = some record
            -> evidence.commitTerm < term
            -> evidence.history.take evidence.commitFrontier <+: record.promotionLog
  currentMember
    : forall evidence supportedPrefix,
        KnownCommitEvidence
          state appendHistory nodeEvidence requestEvidence
          evidence supportedPrefix
        -> forall member,
            member ∈ evidence.ackQuorum
            -> evidence.history.take evidence.commitFrontier <+: ((nodeOf state) member).log
  sameTermQueuedComparable
    : forall evidence supportedPrefix,
        KnownCommitEvidence
          state appendHistory nodeEvidence requestEvidence
          evidence supportedPrefix
        -> forall destination request,
            (appendRequestEnvelope request ∈ state.network /\ request.2.1 = destination)
            -> evidence.commitTerm = request.2.2.term
            -> appendHistory request <+: evidence.history
                \/ evidence.history.take evidence.commitFrontier <+: appendHistory request
  relaxedSupporterCarriesFrontier
    : forall evidence supportedPrefix,
        KnownCommitEvidence
          state appendHistory nodeEvidence requestEvidence
          evidence supportedPrefix
        -> forall candidate member,
            ((nodeOf state) candidate).role = .candidate
            -> evidence.commitTerm < ((nodeOf state) candidate).currentTerm
            -> (forall entry,
                  entry ∈ ((nodeOf state) candidate).log
                  -> entry.term < ((nodeOf state) candidate).currentTerm)
            -> member ∈ evidence.ackQuorum
            -> member ∈ relaxedElectionVoters (joined := joined) state candidate
            -> evidence.history.take evidence.commitFrontier
                <+: ((nodeOf state) candidate).log

/--
Authority-tagged commit evidence is ordered by the permanent activation chain.
Same-authority evidence is compared by ordinary configuration-majority
intersection; this package retains the immutable cross-authority bridge and
supported-prefix comparability when evidence is restricted to an older signed
frontier.
-/
structure ActivationEvidenceFacts
    (state : Model.State Node TxId)
    (appendHistory : AppendRequestKey Node TxId -> List (Entry Node TxId))
    (responseHistory : AppendResponseKey Node -> List (Entry Node TxId))
    (nodeEvidence : NodeCommitEvidence Node TxId)
    (requestEvidence : RequestCommitEvidence Node TxId)
    (elections : ElectionHistory Node TxId)
    (activations : ActivationHistory Node TxId)
    : Prop where
  authorityRecorded
    : forall evidence supportedPrefix,
        KnownCommitEvidence
          state appendHistory nodeEvidence requestEvidence
          evidence supportedPrefix
        -> evidence.authority = implicitConfiguration
            \/ Exists
                fun activationIndex =>
                  Exists
                    fun record =>
                      activations activationIndex = some record
                      /\ evidence.authority ∈ record.governingActive
                      /\ record.activationTerm <= evidence.commitTerm
  authorityIndexUnique
    : forall left leftPrefix,
        KnownCommitEvidence
          state appendHistory nodeEvidence requestEvidence
          left leftPrefix
        -> forall right rightPrefix,
            KnownCommitEvidence
              state appendHistory nodeEvidence requestEvidence
              right rightPrefix
            -> left.authority.index = right.authority.index
            -> left.authority = right.authority
  authorityBridge
    : forall earlier earlierPrefix,
        KnownCommitEvidence
          state appendHistory nodeEvidence requestEvidence
          earlier earlierPrefix
        -> forall later laterPrefix,
            KnownCommitEvidence
              state appendHistory nodeEvidence requestEvidence
              later laterPrefix
            -> earlier.authority.index < later.authority.index
            -> earlier.history.take earlier.commitFrontier
                <+: later.history.take later.commitFrontier
  supportedPrefixesComparable
    : forall left leftPrefix,
        KnownCommitEvidence
          state appendHistory nodeEvidence requestEvidence
          left leftPrefix
        -> forall right rightPrefix,
            KnownCommitEvidence
              state appendHistory nodeEvidence requestEvidence
              right rightPrefix
            -> left.history.take left.supportedLength
                  <+: right.history.take right.supportedLength
                \/ right.history.take right.supportedLength
                    <+: left.history.take left.supportedLength
  candidateBridge
    : forall evidence supportedPrefix,
        KnownCommitEvidence
          state appendHistory nodeEvidence requestEvidence
          evidence supportedPrefix
        -> forall candidate,
            ((nodeOf state) candidate).role = .candidate
            -> hasPotentialElectionMajority (joined := joined) state candidate
            -> evidence.commitTerm < ((nodeOf state) candidate).currentTerm
            -> evidence.history.take evidence.commitFrontier
                  <+: ((nodeOf state) candidate).log
                \/ evidence.authority ∈ activeConfigurations ((nodeOf state) candidate)

/--
Any current-term signature frontier already acknowledged by a majority is
compatible with every committed log.  This covers delayed ACK processing by
an isolated old leader.
-/
def PotentialCommitSafe
    (state : Model.State Node TxId)
    (responseHistory : AppendResponseKey Node -> List (Entry Node TxId))
    : Prop :=
  forall leader index,
    ((nodeOf state) leader).role = .leader
    -> termAt ((nodeOf state) leader).log index = ((nodeOf state) leader).currentTerm
    -> isSignatureAt ((nodeOf state) leader).log index = true
    -> hasEffectiveMajorityAt (joined := joined) state responseHistory leader index
    -> forall node,
        ((nodeOf state) leader).log.take index <+: ((nodeOf state) node).committedLog
        \/ ((nodeOf state) node).committedLog <+: ((nodeOf state) leader).log.take index

/--
Every higher-term election winner already contains each lower-term current-term
signature frontier that an active leader could commit from its recorded
acknowledgements.  This is the delayed-ACK bridge needed when an old leader
commits after a newer election.
-/
def PotentialCommitElectionSafe
    (state : Model.State Node TxId)
    (responseHistory : AppendResponseKey Node -> List (Entry Node TxId))
    : Prop :=
  forall source index,
    ((nodeOf state) source).role = .leader
    -> termAt ((nodeOf state) source).log index = ((nodeOf state) source).currentTerm
    -> isSignatureAt ((nodeOf state) source).log index = true
    -> hasEffectiveMajorityAt (joined := joined) state responseHistory source index
    -> forall winner,
        (((nodeOf state) winner).role = .leader
          \/ (((nodeOf state) winner).role = .candidate
              /\ hasEffectiveElectionMajority (joined := joined) state winner))
        -> ((nodeOf state) source).currentTerm < ((nodeOf state) winner).currentTerm
        -> ((nodeOf state) source).log.take index <+: ((nodeOf state) winner).log

/--
Every current-term signature frontier that an active leader could commit is
already represented in every strict quorum.  Advancing `commitIndex`
therefore preserves `QuorumLog` even when ACK processing is delayed.
-/
def PotentialCommitQuorumLog
    (state : Model.State Node TxId)
    (responseHistory : AppendResponseKey Node -> List (Entry Node TxId))
    : Prop :=
  forall source index,
    ((nodeOf state) source).role = .leader
    -> termAt ((nodeOf state) source).log index = ((nodeOf state) source).currentTerm
    -> isSignatureAt ((nodeOf state) source).log index = true
    -> hasEffectiveMajorityAt (joined := joined) state responseHistory source index
    -> forall configuration,
        configuration ∈ activeConfigurations ((nodeOf state) source)
        -> configuration.index <= index
        -> forall quorum : Finset Node,
            hasConfigurationMajority quorum configuration
            -> Exists
                fun witness =>
                  witness ∈ configuration.nodes
                  /\ witness ∈ quorum
                  /\ ((nodeOf state) source).log.take index <+: ((nodeOf state) witness).log

/--
Any two current-term signature frontiers already acknowledged by strict
majorities are prefix-comparable.  This lets one such prefix become committed
without invalidating delayed commit evidence retained by another active leader.
-/
def PotentialCommitsComparable
    (state : Model.State Node TxId)
    (responseHistory : AppendResponseKey Node -> List (Entry Node TxId))
    : Prop :=
  forall left leftIndex,
    ((nodeOf state) left).role = .leader
    -> termAt ((nodeOf state) left).log leftIndex = ((nodeOf state) left).currentTerm
    -> isSignatureAt ((nodeOf state) left).log leftIndex = true
    -> hasEffectiveMajorityAt (joined := joined) state responseHistory left leftIndex
    -> forall right rightIndex,
        ((nodeOf state) right).role = .leader
        -> termAt ((nodeOf state) right).log rightIndex = ((nodeOf state) right).currentTerm
        -> isSignatureAt ((nodeOf state) right).log rightIndex = true
        -> hasEffectiveMajorityAt (joined := joined) state responseHistory right rightIndex
        -> ((nodeOf state) left).log.take leftIndex
              <+: ((nodeOf state) right).log.take rightIndex
            \/ ((nodeOf state) right).log.take rightIndex
                <+: ((nodeOf state) left).log.take leftIndex

/--
A candidate which already has a winning quorum is ready for promotion: it
contains every committed prefix belonging to a node in a lower term.
-/
def WinningCandidateCompleteness (state : Model.State Node TxId) : Prop :=
  forall candidate,
    ((nodeOf state) candidate).role = .candidate
    -> hasEffectiveElectionMajority (joined := joined) state candidate
    -> forall node,
        Not (candidate = node)
        -> ((nodeOf state) candidate).currentTerm > ((nodeOf state) node).currentTerm
        -> ((nodeOf state) node).committedLog <+: ((nodeOf state) candidate).log

/--
A candidate which can win has no entry from its election term anywhere yet.
This is the arbitrary-term form of `CandidateTermNotInLogInv`.
-/
def CandidateTermNotInLogs (state : Model.State Node TxId) : Prop :=
  forall candidate,
    ((nodeOf state) candidate).role = .candidate
    -> hasEffectiveElectionMajority (joined := joined) state candidate
    -> forall node index entry,
        entryAt? ((nodeOf state) node).log index = some entry
        -> Not (entry.term = ((nodeOf state) candidate).currentTerm)

/--
An active leader contains the complete prefix through every entry carrying its
term.  This prevents a later client append from colliding at an existing
same-term index.
-/
def LeaderTermDominance (state : Model.State Node TxId) : Prop :=
  forall leader,
    ((nodeOf state) leader).role = .leader
    -> forall node index entry,
        entryAt? ((nodeOf state) node).log index = some entry
        -> entry.term = ((nodeOf state) leader).currentTerm
        -> index <= ((nodeOf state) leader).log.length
            /\ ((nodeOf state) node).log.take index = ((nodeOf state) leader).log.take index

/--
The current TLA state-local leader-completeness formula.  Leaders need contain
the committed logs of strictly lower-term peers, not those of newer peers.
-/
def LeaderCompleteness (state : Model.State Node TxId) : Prop :=
  forall leader,
    ((nodeOf state) leader).role = .leader
    -> forall node,
        Not (leader = node)
        -> ((nodeOf state) leader).currentTerm > ((nodeOf state) node).currentTerm
        -> ((nodeOf state) node).committedLog <+: ((nodeOf state) leader).log

def LeadersHaveElectionWitness (state : Model.State Node TxId) : Prop :=
  forall leader,
    ((nodeOf state) leader).role = .leader
    -> ((leader = INITIAL_LEADER /\ ((nodeOf state) leader).currentTerm = BOOTSTRAP_TERM)
        \/ Exists
            fun configuration =>
              configuration ∈ allConfigurations ((nodeOf state) leader).log
              /\ hasConfigurationMajority ((nodeOf state) leader).votesGranted configuration)

/--
Immutable election, activation, and commit evidence. Each field supplies one
causal edge used to order committed prefixes across terms and configurations.
-/
structure HistoricalSafetyFacts
    (state : Model.State Node TxId)
    (votes : VoteHistory Node)
    (appendHistory : AppendRequestKey Node TxId -> List (Entry Node TxId))
    (responseHistory : AppendResponseKey Node -> List (Entry Node TxId))
    (voteRequestHistory : VoteRequestKey Node -> List (Entry Node TxId))
    (voteCandidateHistory : VoteResponseKey Node -> List (Entry Node TxId))
    (voteVoterHistory : VoteResponseKey Node -> List (Entry Node TxId))
    (owners : TermOwners Node)
    (canonicalHistory : Nat -> List (Entry Node TxId))
    (elections : ElectionHistory Node TxId)
    (activations : ActivationHistory Node TxId)
    (nodeEvidence : NodeCommitEvidence Node TxId)
    (requestEvidence : RequestCommitEvidence Node TxId)
    : Prop where
  termOwnership : TermOwnershipFacts state votes appendHistory canonicalHistory owners
  electionHistory : ElectionHistoryFacts state votes canonicalHistory owners elections
  electionConfigurations : ElectionConfigurationFacts (joined := joined) state elections activations
  grantedVoteCanonical
    : GrantedVoteCanonicalSnapshots (joined := joined)
        state canonicalHistory voteCandidateHistory voteVoterHistory
  ackerCurrent : AckerCurrentHistory (joined := joined) state responseHistory elections
  ackerVotes : AckerVoteHistory (joined := joined) state votes responseHistory voteVoterHistory elections
  activationVotes : ActivationVoteHistory votes voteVoterHistory elections activations
  ackerElections : AckerElectionHistory (joined := joined) state responseHistory elections
  ackerActivations : AckerActivationHistory (joined := joined) state responseHistory elections activations
  queuedElections : ElectionQueuedHistoryFacts state appendHistory elections
  activationProgress : ActivationSupporterProgress state activations
  activationQuorums
    : ActivationQuorumFacts (joined := joined) state appendHistory responseHistory elections activations
  commitEvidence : CommitEvidenceFacts state appendHistory nodeEvidence requestEvidence
  prospectiveCommits
    : ProspectiveCommitEvidenceFacts (joined := joined)
        state appendHistory nodeEvidence requestEvidence elections
  activationEvidence
    : ActivationEvidenceFacts (joined := joined)
        state appendHistory responseHistory
        nodeEvidence requestEvidence elections activations
  activationCanonical : ActivationCanonicalFacts canonicalHistory owners activations
  activationElections : ActivationElectionFacts votes elections activations
  configurationCoverage : ConfigurationCoverageFacts state activations

/-- Operationally populated node state belongs only to joined nodes. -/
structure RuntimeNodeCarrierFacts (state : Model.State Node TxId) : Prop where
  activeRoles
    : forall node,
        ((nodeOf state) node).role = .candidate \/ ((nodeOf state) node).role = .leader
        -> node ∈ joined
  positiveMatches
    : forall leader peer,
        0 < ((nodeOf state) leader).matchIndex peer -> peer ∈ joined
  appendResponses
    : forall destination response,
        (appendResponseEnvelope response ∈ state.network /\ response.2.1 = destination)
        -> response.1 ∈ joined
  nonemptyLogs : forall node, Not (((nodeOf state) node).log = []) -> node ∈ joined

/-- Every runtime support carrier contains only nodes which have joined. -/
structure JoinedCarrierFacts (state : Model.State Node TxId) : Prop where
  activeNodes : forall node, activeNodeUnion ((nodeOf state) node) ⊆ joined
  configurationNodes
    : forall node configuration,
        configuration ∈ allConfigurations ((nodeOf state) node).log
        -> configuration.nodes ⊆ joined
  grantedVotes : forall node, ((nodeOf state) node).votesGranted ⊆ joined
  voteRequestDestinations
    : forall destination request,
        (voteRequestEnvelope request ∈ state.network /\ request.2.1 = destination)
        -> destination ∈ joined
  appendRequestDestinations
    : forall destination request,
        (appendRequestEnvelope request ∈ state.network /\ request.2.1 = destination)
        -> destination ∈ joined
  appendRequestConfigurations
    : forall destination request,
        (appendRequestEnvelope request ∈ state.network /\ request.2.1 = destination)
        -> forall configuration,
            configuration ∈ allConfigurations request.2.2.entries
            -> configuration.nodes ⊆ joined
  voteResponseSources
    : forall destination response,
        (voteResponseEnvelope response ∈ state.network /\ response.2.1 = destination)
        -> response.1 ∈ joined
  runtimeNodes : RuntimeNodeCarrierFacts (joined := joined) state

/--
Allocated identities are exactly the identities that have joined. Allocation,
join history, and configuration membership remain distinct state concepts.
-/
def AllocatedNodesExactlyJoined (_state : Model.State Node TxId) : Prop :=
  forall node, node ∈ joined <-> node ∈ joined

/-- The invariant preserved by the reconfiguring transition system. -/
structure InvariantFacts
    (state : Model.State Node TxId)
    (votes : VoteHistory Node)
    (appendHistory : AppendRequestKey Node TxId -> List (Entry Node TxId))
    (responseHistory : AppendResponseKey Node -> List (Entry Node TxId))
    (voteRequestHistory : VoteRequestKey Node -> List (Entry Node TxId))
    (voteCandidateHistory : VoteResponseKey Node -> List (Entry Node TxId))
    (voteVoterHistory : VoteResponseKey Node -> List (Entry Node TxId))
    : Prop where
  commitIndicesBounded : CommitIndicesBounded state
  currentTermsPositive : CurrentTermsPositive state
  entriesDoNotExceedCurrentTerm : EntriesDoNotExceedCurrentTerm state
  candidatesSelfVote : CandidatesSelfVote state
  leadersHaveElectionWitness : LeadersHaveElectionWitness state
  leaderProgressBounded : LeaderProgressBounded state
  voteHistory : VoteHistoryFacts state votes
  networkHistory
    : NetworkHistoryFacts
        state appendHistory responseHistory
        voteRequestHistory voteCandidateHistory voteVoterHistory votes
  historicalSafety
    : Exists
        fun owners =>
          Exists
            fun canonicalHistory =>
              Exists
                fun elections =>
                  Exists
                    fun activations =>
                      Exists
                        fun nodeEvidence =>
                          Exists
                            fun requestEvidence =>
                              HistoricalSafetyFacts (joined := joined) state votes appendHistory
                                responseHistory voteRequestHistory voteCandidateHistory
                                voteVoterHistory owners canonicalHistory elections
                                activations nodeEvidence requestEvidence
  grantedVoteSnapshots
    : GrantedVoteSnapshots (joined := joined) state votes voteCandidateHistory voteVoterHistory
  processedAckHistory : Exists fun history => ProcessedAckHistoryFacts state history
  joinedCarriers : JoinedCarrierFacts (joined := joined) state
  allocatedNodesExactlyJoined : AllocatedNodesExactlyJoined (joined := joined) state
  currentTermsValid : CurrentTermsValid state
  networkTermsValid : NetworkTermsValid state

/-- Existentially package every consensus-safety invariant component. -/
def SystemInductiveInvariant (state : Model.State Node TxId) : Prop :=
  Exists
    fun votes =>
      Exists
        fun appendHistory =>
          Exists
            fun responseHistory =>
              Exists
                fun voteRequestHistory =>
                  Exists
                    fun voteCandidateHistory =>
                      Exists
                        fun voteVoterHistory =>
                          InvariantFacts (joined := joined)
                            state votes appendHistory responseHistory voteRequestHistory
                            voteCandidateHistory voteVoterHistory

/-- Safety and concrete-step side conditions for one ghost joined set. -/
structure StateInvariant (state : Model.State Node TxId) (joined : Finset Node) : Prop where
  safety : SystemInductiveInvariant (joined := joined) state
  distinct : (state.nodes.map Prod.fst).Nodup
  initialJoined : INITIAL_CONFIGURATION ⊆ joined
  unjoined
    : forall node, node ∉ joined -> nodeOf state node = initialNodeState node
  endpoints
    : forall envelope,
        envelope ∈ state.network
        -> envelope.source ∈ joined /\ envelope.target ∈ joined

/-- The invariant of a concrete state, with an existential proof-only joined set. -/
def Inv (state : Model.State Node TxId) : Prop :=
  Exists fun joined : Finset Node => StateInvariant state joined

end CCFRaft.Proofs.Invariant
