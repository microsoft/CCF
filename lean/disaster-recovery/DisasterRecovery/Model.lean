import Std

namespace DisasterRecovery

abbrev Id := Nat
abbrev Txid := Nat

structure Gossip where
  src : Id
  txid : Txid
deriving Repr, BEq, Hashable

structure Vote where
  src : Id
  recv : List Gossip
deriving Repr, BEq, Hashable

inductive Msg where
  | gossip (value : Gossip)
  | vote (value : Vote)
  | iAmOpen (src : Id)
deriving Repr, BEq, Hashable

inductive Phase where
  | vote
  | openJoin
  | open (timeout : Bool)
  | join
deriving Repr, BEq, Hashable, Inhabited

structure ActorState where
  nextStep : Phase
  gossips : List Gossip
  votes : List Vote
  submittedVote : Option (Prod Id Vote)
  txid : Txid
deriving Repr, BEq, Hashable, Inhabited

structure Envelope where
  src : Id
  dst : Id
  msg : Msg
deriving Repr, BEq, Hashable

structure GlobalState where
  actors : Array ActorState
  timers : Array Bool
  network : List Envelope
deriving Repr, BEq, Hashable, Inhabited

inductive Action where
  | deliver (envelope : Envelope)
  | timeout (id : Id)
deriving Repr, BEq, Hashable

structure Output where
  sent : List (Prod Id Msg) := []
  setTimer : Bool := false
deriving Repr, BEq

private def comma (values : List String) : String :=
  String.intercalate "," values

def gossipKey (gossip : Gossip) : String :=
  s!"g({gossip.src},{gossip.txid})"

def voteKey (vote : Vote) : String :=
  s!"v({vote.src},[{comma (vote.recv.map gossipKey)}])"

def msgKey : Msg -> String
  | .gossip gossip => gossipKey gossip
  | .vote vote => voteKey vote
  | .iAmOpen src => s!"o({src})"

def envelopeKey (envelope : Envelope) : String :=
  s!"e({envelope.src},{envelope.dst},{msgKey envelope.msg})"

def phaseKey : Phase -> String
  | .vote => "vote"
  | .openJoin => "openjoin"
  | .open false => "open0"
  | .open true => "open1"
  | .join => "join"

def submittedKey : Option (Prod Id Vote) -> String
  | none => "none"
  | some (dst, vote) => s!"some({dst},{voteKey vote})"

def actorKey (actor : ActorState) : String :=
  s!"s({phaseKey actor.nextStep},[{comma (actor.gossips.map gossipKey)}],[{comma (actor.votes.map voteKey)}],{submittedKey actor.submittedVote},{actor.txid})"

private def networkRunsFrom (current : Envelope) (count : Nat) :
    List Envelope -> List (Prod Envelope Nat)
  | [] => [(current, count)]
  | head :: tail =>
      if head == current then
        networkRunsFrom current (count + 1) tail
      else
        (current, count) :: networkRunsFrom head 1 tail

private def networkRuns : List Envelope -> List (Prod Envelope Nat)
  | [] => []
  | head :: tail => networkRunsFrom head 1 tail

def stateKey (state : GlobalState) : String :=
  let actors := String.intercalate ";" (state.actors.toList.map actorKey)
  let timers := comma (((List.range state.timers.size).filter
    (fun id => state.timers[id]!)).map toString)
  let network := comma ((networkRuns state.network).map fun (env, count) =>
    s!"{envelopeKey env}#{count}")
  s!"S([{actors}],[{timers}],[{network}])"

def actionKey : Action -> String
  | .deliver env => s!"deliver({env.src},{env.dst},{msgKey env.msg})"
  | .timeout id => s!"timeout({id},election)"

private def insertSorted (before : a -> a -> Bool) (value : a) : List a -> List a
  | [] => [value]
  | head :: tail =>
      if before value head then
        value :: head :: tail
      else
        head :: insertSorted before value tail

private def insertUniqueSorted [BEq a] (before : a -> a -> Bool) (value : a) (values : List a) :
    List a :=
  if values.contains value then values else insertSorted before value values

private def removeOne [BEq a] (value : a) : List a -> List a
  | [] => []
  | head :: tail => if head == value then tail else head :: removeOne value tail

private def gossipGreater (left right : Gossip) : Bool :=
  right.txid < left.txid || (right.txid == left.txid && right.src < left.src)

private def gossipBefore (left right : Gossip) : Bool :=
  left.src < right.src || (left.src == right.src && left.txid < right.txid)

private def gossipListBefore : List Gossip -> List Gossip -> Bool
  | [], [] => false
  | [], _ :: _ => true
  | _ :: _, [] => false
  | left :: leftTail, right :: rightTail =>
      if left == right then gossipListBefore leftTail rightTail
      else gossipBefore left right

private def voteBefore (left right : Vote) : Bool :=
  left.src < right.src || (left.src == right.src && gossipListBefore left.recv right.recv)

private def msgBefore : Msg -> Msg -> Bool
  | .gossip left, .gossip right => gossipBefore left right
  | .gossip _, _ => true
  | .vote _, .gossip _ => false
  | .vote left, .vote right => voteBefore left right
  | .vote _, .iAmOpen _ => true
  | .iAmOpen _, .gossip _ => false
  | .iAmOpen _, .vote _ => false
  | .iAmOpen left, .iAmOpen right => left < right

private def envelopeBefore (left right : Envelope) : Bool :=
  left.src < right.src ||
    (left.src == right.src &&
      (left.dst < right.dst || (left.dst == right.dst && msgBefore left.msg right.msg)))

private def maximumGossip : List Gossip -> Option Gossip
  | [] => none
  | head :: tail =>
      some (tail.foldl (fun current candidate =>
        if gossipGreater candidate current then candidate else current) head)

private def voteForMax (gossips : List Gossip) (id : Id) : Option (Prod Id Vote) := do
  let maximum <- maximumGossip gossips
  pure (maximum.src, { src := id, recv := gossips })

private def otherPeers (n id : Nat) : List Id :=
  (List.range n).filter (fun peer => peer != id)

private def advanceStep (n id : Nat) (timeout : Bool) (state : ActorState) :
    Prod ActorState (Prod Output Bool) :=
  match state.nextStep with
  | .vote =>
      if state.gossips.length == n || timeout then
        match voteForMax state.gossips id with
        | none => (state, {}, false)
        | some (dst, vote) =>
            let next := {
              state with
              nextStep := .openJoin
              submittedVote := some (dst, vote)
              votes := if dst == id then insertUniqueSorted voteBefore vote state.votes else state.votes
            }
            let sent := if dst == id then [] else [(dst, Msg.vote vote)]
            (next, { sent }, true)
      else
        (state, {}, false)
  | .openJoin =>
      if state.votes.length >= (n + 1) / 2 || timeout then
        let sent := (otherPeers n id).map (fun peer => (peer, Msg.iAmOpen id))
        ({ state with nextStep := .open timeout }, { sent }, true)
      else
        (state, {}, false)
  | _ => (state, {}, false)

def advanceSeveral (n id : Nat) (timeout : Bool) (state : ActorState) :
    Prod ActorState Output :=
  let (state1, output1, advanced1) := advanceStep n id timeout state
  if advanced1 then
    let (state2, output2, _) := advanceStep n id timeout state1
    (state2, { sent := output1.sent ++ output2.sent })
  else
    (state, {})

def onMessage (n id : Nat) (state : ActorState) (msg : Msg) :
    Option (Prod ActorState Output) :=
  let received :=
    match msg with
    | .gossip gossip =>
        if !state.gossips.contains gossip && state.submittedVote.isNone then
          { state with gossips := insertUniqueSorted gossipBefore gossip state.gossips }
        else
          state
    | .vote vote =>
        { state with votes := insertUniqueSorted voteBefore vote state.votes }
    | .iAmOpen _ =>
        match state.nextStep with
        | .open _ => state
        | _ => { state with nextStep := .join }
  let (next, output) := advanceSeveral n id false received
  some (next, output)

def onTimeout (n id : Nat) (state : ActorState) : Option (Prod ActorState Output) :=
  match state.nextStep with
  | .vote =>
      if state.gossips.isEmpty then none
      else
        let (next, output) := advanceSeveral n id true state
        some (next, { output with setTimer := true })
  | .openJoin =>
      if state.votes.isEmpty then none
      else some (advanceSeveral n id true state)
  | _ => none

private def applyOutput (src : Id) (output : Output) (state : GlobalState) : GlobalState :=
  let network := output.sent.foldl
    (fun current (dst, msg) => insertSorted envelopeBefore { src, dst, msg } current)
    state.network
  let timers := if output.setTimer then state.timers.set! src true else state.timers
  { state with network, timers }

private def startActor (n id : Nat) : Prod ActorState Output :=
  let gossip := { src := id, txid := id }
  let initial : ActorState := {
    nextStep := .vote
    gossips := [gossip]
    votes := []
    submittedVote := none
    txid := id
  }
  let output : Output := {
    sent := (otherPeers n id).map (fun peer => (peer, Msg.gossip gossip))
    setTimer := true
  }
  let (state, advanced) := advanceSeveral n id false initial
  (state, { sent := output.sent ++ advanced.sent, setTimer := true })

def initialState (n : Nat) : GlobalState :=
  (List.range n).foldl (fun global id =>
    let (actor, output) := startActor n id
    let withActor := {
      global with
      actors := global.actors.push actor
      timers := global.timers.push false
    }
    applyOutput id output withActor)
    { actors := #[], timers := #[], network := [] }

private def distinctNetworkFrom (previous : Envelope) : List Envelope -> List Envelope
  | [] => []
  | head :: tail =>
      if head == previous then
        distinctNetworkFrom previous tail
      else
        head :: distinctNetworkFrom head tail

private def distinctNetwork : List Envelope -> List Envelope
  | [] => []
  | head :: tail => head :: distinctNetworkFrom head tail

def actions (state : GlobalState) : List Action :=
  (distinctNetwork state.network).map Action.deliver ++
    ((List.range state.timers.size).filter
      (fun id => state.timers[id]!)).map Action.timeout

def nextState (n : Nat) (state : GlobalState) : Action -> Option GlobalState
  | .deliver envelope => do
      let actor <- state.actors[envelope.dst]?
      let (nextActor, output) <- onMessage n envelope.dst actor envelope.msg
      let delivered := {
        state with
        actors := state.actors.set! envelope.dst nextActor
        network := removeOne envelope state.network
      }
      pure (applyOutput envelope.dst output delivered)
  | .timeout id => do
      guard (state.timers[id]?.getD false)
      let actor <- state.actors[id]?
      let (nextActor, output) <- onTimeout n id actor
      let expired := {
        state with
        actors := state.actors.set! id nextActor
        timers := state.timers.set! id false
      }
      pure (applyOutput id output expired)

def reachedOpen (state : GlobalState) : Bool :=
  state.actors.any fun actor =>
    match actor.nextStep with
    | .open _ => true
    | _ => false

def reachedOpenTimeout (state : GlobalState) (expected : Bool) : Bool :=
  state.actors.any fun actor => actor.nextStep == .open expected

def unanimousVotes (n : Nat) (state : GlobalState) : Bool :=
  state.actors.all fun actor =>
    match actor.submittedVote with
    | none => false
    | some (_, vote) =>
        (List.range n).all fun peer => vote.recv.any (fun gossip => gossip.src == peer)

def majorityHaveSameMaximum (state : GlobalState) : Bool :=
  let chosen := state.actors.toList.filterMap fun actor => do
    let (_, vote) <- actor.submittedVote
    let maximum <- maximumGossip vote.recv
    pure maximum.src
  let chosen := chosen.foldl (fun values id =>
    insertSorted (fun left right => left < right) id values) []
  let majorityIndex := state.actors.size / 2
  match chosen[majorityIndex]? with
  | none => false
  | some majority => (chosen.take majorityIndex).all (fun chosen => chosen == majority)

private def implies (left right : Bool) : Bool :=
  !left || right

def legacyValuations (n : Nat) (state : GlobalState) : Array Bool :=
  let openCount := state.actors.countP fun actor =>
    match actor.nextStep with
    | .open _ => true
    | _ => false
  let allOpenJoin := state.actors.all (fun actor => actor.nextStep == .openJoin)
  let allVotesDelivered := !state.network.any fun envelope =>
    match envelope.msg with
    | .vote _ => true
    | _ => false
  let majorityIndex := state.actors.size / 2
  let commitTxid := (state.actors[majorityIndex]!).txid
  let persisted := state.actors.all fun actor =>
    match actor.nextStep with
    | .open _ => actor.txid >= commitTxid
    | _ => true
  #[
    implies (unanimousVotes n state) (reachedOpenTimeout state false),
    reachedOpen state,
    implies (majorityHaveSameMaximum state) (reachedOpenTimeout state false),
    implies (!reachedOpenTimeout state true) (openCount <= 1),
    !(allOpenJoin && allVotesDelivered),
    implies (!reachedOpenTimeout state true) persisted,
    implies (state.actors.size > 1) (reachedOpen state),
    reachedOpenTimeout state true,
    majorityHaveSameMaximum state && reachedOpenTimeout state false
  ]

def legacyPropertyNames : Array String := #[
  "Unanimous votes => no chance of a fork",
  "Open",
  "Majority votes => no fork",
  "No open with timeout, no fork",
  "Deadlock",
  "Persist committed txs",
  "Open is possible",
  "Unsafe open with timeout",
  "Majority vote still opens without timeout"
]

def legacyExpectations : Array String := #[
  "eventually", "eventually", "eventually",
  "always", "always", "always",
  "sometimes", "sometimes", "sometimes"
]

end DisasterRecovery
