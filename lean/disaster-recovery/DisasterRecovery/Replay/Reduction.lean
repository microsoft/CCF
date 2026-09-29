import DisasterRecovery.Replay.Records
import Std.Data.HashMap
import Std.Data.HashSet

set_option autoImplicit false

/-!
Reduces the records of one recovery-decision-protocol run to replay
instructions. Records do not say which executions took effect, because
concurrent executions on a node can conflict and re-execute, and the newest
execution on a node that stops to join may never commit. For each node, the
reduction keeps every account of its executions that the node's records allow,
and replays the account that finishes with the most effective executions.
-/

namespace DisasterRecovery.Replay

open Lean Model.Local

/-- What the e2e scenario must end with. -/
structure Scenario where
  participants : Nat
  openKind : OpenKind

/-- Protocol state that a node's records show it committed. -/
structure CommittedState where
  phase : Phase := .gossiping
  timeout : Phase := .gossiping
  gossips : List (Location × TxID) := []
  votes : List Location := []
  chosen : Option Location := none
deriving BEq, Hashable, Inhabited

/-- What later records can read. Gossiping records do not read votes. -/
def CommittedState.observable (state : CommittedState) : CommittedState :=
  {
    phase := state.phase
    timeout := state.timeout
    gossips := if state.phase == .gossiping then state.gossips else []
    votes := if state.phase == .voting then state.votes else []
    chosen :=
      if state.phase == .voting || state.phase == .joining then state.chosen else none
  }

/-- What determines the node's later steps. -/
def CommittedState.relevant (state : CommittedState) : CommittedState :=
  {
    state.observable with
      votes :=
        if state.phase == .gossiping || state.phase == .voting then state.votes else []
  }

/-- The gossips `advance()` read: a gossip adds its sender unless already present. -/
private def readGossips (state : CommittedState) (event : TraceEvent)
    : List (Location × TxID) :=
  match event.body with
  | .receive source (.gossip value) _ _ =>
      if state.gossips.any (·.1 == source) then
        state.gossips
      else
        (state.gossips ++ [(source, value)]).mergeSort fun left right => left.1 <= right.1
  | _ => state.gossips

private def addVote (votes : List Location) (source : Location) : List Location :=
  if votes.contains source then votes else (votes ++ [source]).mergeSort

/-- The votes `advance()` read: a vote adds its sender. -/
private def readVotes (state : CommittedState) (event : TraceEvent) : List Location :=
  match event.body with
  | .receive source .vote _ _ => addVote state.votes source
  | _ => state.votes

/-- Whether an execution that read this committed state records what it read. -/
private def explains (state : CommittedState) (event : TraceEvent) (execution : Execution)
    : Bool :=
  if event.isIAmOpen then
    -- IAmOpen is rejected in Opening and Open, and records its own writes.
    (state.phase == .gossiping || state.phase == .voting || state.phase == .joining)
    && state.timeout == execution.preTimeout
  else if state.phase != execution.pre || state.timeout != execution.preTimeout then
    false
  else
    match state.phase with
    | .gossiping => some (readGossips state event) == execution.gossips
    | .voting => some (readVotes state event) == execution.votes
    | .joining => state.chosen == execution.chosen
    | _ => true

/-- The committed state if the execution took effect, from what it recorded. -/
private def after (state : CommittedState) (event : TraceEvent) (execution : Execution)
    : CommittedState :=
  {
    phase := execution.post
    timeout := execution.postTimeout
    gossips := execution.gossips.getD state.gossips
    votes := execution.votes.getD (readVotes state event)
    chosen := execution.chosen <|> state.chosen
  }

private def describe (state : CommittedState) : String :=
  let gossips :=
    state.gossips.map fun (location, value) => s!"{location}={value.view}.{value.seqno}"
  ", ".intercalate
    ([s!"{phaseName state.phase} with timeout {phaseName state.timeout}"]
      ++ (if state.phase == .gossiping then
            ["gossips {" ++ ", ".intercalate gossips ++ "}"]
          else
            [])
      ++ (if state.phase == .voting then
            ["votes [" ++ ", ".intercalate state.votes ++ "]"]
          else
            [])
      ++ (state.chosen.map (s!"chosen {·}")).toList)

/-- A replay unit: one retry's sends, or one execution, and the rule that placed it. -/
inductive Item where
  | retry (stale : Bool) (sends : Array TraceEvent)
  | execution (rule : String) (event : TraceEvent)
deriving Inhabited

private def Item.first : Item → TraceEvent
  | .retry _ sends => sends[0]!
  | .execution _ event => event

/-- One consistent account of which of a node's executions took effect. -/
structure Hypothesis where
  /-- Committed states, oldest first. Items run while each was the latest. -/
  states : Array CommittedState := #[{}]
  /-- Effective phase writes that no committed record has confirmed yet. -/
  unconfirmed : List Phase := []
  /-- A record has read the votes in Voting. -/
  votesRead : Bool := false
  restarted : Bool := false
  completed : Bool := false
  effective : Nat := 0
  /-- Placed items and their segments, newest first. -/
  items : List (Nat × Item) := []
deriving Inhabited

private structure HypothesisKey where
  relevant : CommittedState
  observable : List CommittedState
  unconfirmed : List Phase
  votesRead : Bool
  restarted : Bool
  completed : Bool
deriving BEq, Hashable

private def Hypothesis.current (hypothesis : Hypothesis) : CommittedState :=
  hypothesis.states.back?.getD {}

private def Hypothesis.key (hypothesis : Hypothesis) : HypothesisKey :=
  {
    relevant := hypothesis.current.relevant
    observable := hypothesis.states.toList.map CommittedState.observable
    unconfirmed := hypothesis.unconfirmed
    votesRead := hypothesis.votesRead
    restarted := hypothesis.restarted
    completed := hypothesis.completed
  }

private def Hypothesis.place (hypothesis : Hypothesis) (segment : Nat) (item : Item)
    : Hypothesis :=
  { hypothesis with items := (segment, item) :: hypothesis.items }

/-- The placed items, segment by segment. -/
private def Hypothesis.placed (hypothesis : Hypothesis) : Array Item :=
  Id.run do
    let mut segments : Array (Array Item) := Array.replicate hypothesis.states.size #[]
    for (segment, item) in hypothesis.items.reverse do
      segments := segments.modify segment (·.push item)
    return segments.flatten

private def Hypothesis.finished (hypothesis : Hypothesis) : Bool :=
  hypothesis.completed || (hypothesis.restarted && hypothesis.current.phase == .joining)

/-- committed-write: a committed record confirms the oldest effective phase write. -/
private def commit (hypothesis : Hypothesis) (post : Phase)
    : Except String (List Hypothesis) :=
  match hypothesis.unconfirmed with
  | [] =>
      throw s!"committed {phaseName post} without an effective execution that wrote it"
  | next :: rest =>
      if next != post then
        throw
          s!"committed {phaseName post}, but the next effective phase write is {phaseName next}"
      else
        pure
          [{
            hypothesis with
              unconfirmed := rest, completed := hypothesis.completed || post == .open
          }]

/-- retry and stale-retry: a retry reads a committed state in its batch's phase. -/
private def retry (hypothesis : Hypothesis) (sends : Array TraceEvent)
    : Except String (List Hypothesis) := do
  let .send _ target message := sends[0]!.body | throw "a retry batch starts with a send"
  let (wanted, chosen) : Phase × Option Location :=
    match message with
    | .gossip _ => (.gossiping, none)
    | .vote => (.voting, some target)
    | .iAmOpen => (.opening, none)
  let candidates :=
    (List.range hypothesis.states.size).filter
      fun index =>
        let state := hypothesis.states[index]!
        state.phase == wanted && (chosen.isNone || state.chosen == chosen)
  let (some oldest, some latest) := (candidates.head?, candidates.getLast?)
  | throw
      s!"no committed state sends {messageName message}:{target} first; the node was {describe hypothesis.current}"
  -- Every such state sends the same messages. The oldest is the earliest
  -- point in the node's replay, which no receive can precede.
  let stale := latest != hypothesis.states.size - 1
  return [hypothesis.place oldest (.retry stale sends)]

/-- The accounts in which the execution did, and did not, take effect. -/
private def execute (hypothesis : Hypothesis) (event : TraceEvent) (execution : Execution)
    (final : Bool)
    : Except String (List Hypothesis) := do
  let explaining :=
    (List.range hypothesis.states.size).filter
      fun index =>
        explains hypothesis.states[index]! event execution
  let some lastExplaining := explaining.getLast?
  | throw
      s!"no committed state explains what the execution read; the node was {describe hypothesis.current}"
  let readsVotes := !event.isIAmOpen && execution.pre == .voting
  -- stale-execution and superseded-execution: the execution did not take effect.
  let ineffective := { hypothesis with votesRead := hypothesis.votesRead || readsVotes }
  if !final then
    return [ineffective]
  if let .receive source .vote _ _ := event.body then
    if execution.pre == .gossiping && execution.post == .gossiping then
      -- gossiping-vote: the vote only adds its sender, which no Gossiping
      -- record reads. It committed before the writers after the state it
      -- read, but not after a record read the votes in Voting.
      if hypothesis.votesRead then
        return [ineffective]
      let segment := lastExplaining
      let states :=
        hypothesis.states.mapIdx
          fun index state =>
            if index < segment then
              state
            else
              { state with votes := addVote state.votes source }
      let rule :=
        if segment == hypothesis.states.size - 1 then "execution" else "gossiping-vote"
      let effective :=
        { ineffective with states, effective := hypothesis.effective + 1 }.place segment
          (.execution rule event)
      return [ineffective, effective]
  let current := hypothesis.current
  if !explains current event execution then
    return [ineffective]
  -- execution: the execution read the latest committed state and took effect.
  -- A new committed state starts a segment with the execution that wrote it.
  let state := after current event execution
  let wrotePhase := event.isIAmOpen || execution.post != execution.pre
  let states :=
    if state.observable != current.observable then
      hypothesis.states.push state
    else
      hypothesis.states.pop.push state
  let effective :=
    {
      ineffective with
        states
        unconfirmed :=
          hypothesis.unconfirmed ++ (if wrotePhase then [execution.post] else [])
        restarted := hypothesis.restarted || execution.restart
        effective := hypothesis.effective + 1
    }.place
      (states.size - 1) (.execution "execution" event)
  if event.isIAmOpen && state.relevant == current.relevant then
    -- A repeated IAmOpen only adds a Joining write, which may stay
    -- unconfirmed, so it subsumes the account in which it did not take effect.
    return [effective]
  return [ineffective, effective]

/-- More consistent accounts than this indicate a trace the rules cannot resolve. -/
private def maxHypotheses : Nat :=
  256

/-- Keeps every account of the node's executions that its records allow. -/
private def infer (node : Location) (events : Array TraceEvent)
    (batches : Std.HashMap Nat (Array TraceEvent))
    : Checked (Bool × Array Hypothesis) := do
  -- Receives of one message re-execute it, and at most the last takes effect.
  let mut laterCauses : Std.HashSet (Option (Location × Nat)) := {}
  let mut final : Std.HashMap Nat Bool := {}
  for event in events.reverse do
    if let .receive _ _ causedBy _ := event.body then
      final := final.insert event.sequence (!laterCauses.contains causedBy)
      laterCauses := laterCauses.insert causedBy
  let mut participating := false
  let mut hypotheses : Array Hypothesis := #[{}]
  for event in events do
    let location := event.record.location
    if let .committed post := event.body then
      if !participating then
        -- participation: the first committed record, for Gossiping.
        require (post == .gossiping)
          s!"{location}: node {node}'s first committed record is for {phaseName post}"
        participating := true
        continue
    -- The retry and failover timers start when that record is emitted.
    if event.body matches .send .. | .timeout _ then
      require participating
        s!"{location}: {event.kind} before node {node}'s committed Gossiping record"
    let mut sends := #[]
    if let .send batch _ _ := event.body then
      sends := batches.getD batch #[]
      unless sends[0]?.map (·.sequence) == some event.sequence do
        continue
    let mut successors : Array Hypothesis := #[]
    let mut failure : Option (Nat × String) := none
    for hypothesis in hypotheses do
      let outcome :=
        match event.body, event.execution? with
        | .committed post, _ => commit hypothesis post
        | .send .., _ => retry hypothesis sends
        | _, some (_, execution) =>
            execute hypothesis event execution (final.getD event.sequence true)
        | _, none => throw "unsupported record"
      match outcome with
      | .ok more => successors := successors ++ more.toArray
      | .error message =>
          if failure.all (·.1 <= hypothesis.effective) then
            failure := some (hypothesis.effective, message)
    if successors.isEmpty then
      throw (.invalid s!"{location}: node {node}: {(failure.map (·.2)).getD ""}")
    -- Keep the most effective account of each key, in first-seen order.
    let mut kept : Array Hypothesis := #[]
    let mut positions : Std.HashMap HypothesisKey Nat := {}
    for hypothesis in successors do
      match positions[hypothesis.key]? with
      | some position =>
          if kept[position]!.effective < hypothesis.effective then
            kept := kept.set! position hypothesis
      | none =>
          positions := positions.insert hypothesis.key kept.size
          kept := kept.push hypothesis
    hypotheses := kept
    require (hypotheses.size <= maxHypotheses)
      s!"{location}: node {node}: more than {maxHypotheses} consistent accounts"
  return (participating, hypotheses)

/-- Sorts each node's records by sequence, which runs from 0 without repeats. -/
private def group (events : Array TraceEvent)
    : Checked (List Location × List (Location × Array TraceEvent)) := do
  let some first := events[0]?
  | throw (.incomplete "no recovery-decision-protocol trace records found")
  let locations := first.expectedLocations
  require (!locations.isEmpty && locations.eraseDups.length == locations.length)
    s!"{first.record.location}: expected_locations must be nonempty and unique"
  let mut order : Array Location := #[]
  let mut nodes : Std.HashMap Location (Array TraceEvent) := {}
  for event in events do
    require (event.expectedLocations == locations)
      s!"{event.record.location}: expected_locations differ from {first.record.location}"
    require (locations.contains event.node)
      s!"{event.record.location}: node {event.node} is not an expected location"
    unless nodes.contains event.node do
      order := order.push event.node
    nodes := nodes.insert event.node ((nodes.getD event.node #[]).push event)
  for node in order do
    let records :=
      (nodes.getD node #[]).toList.mergeSort
        fun left right =>
          left.sequence <= right.sequence
    for event in records, index in [:records.length] do
      require (event.sequence >= index)
        s!"{event.record.location}: node {node} repeats sequence {event.sequence}"
      if event.sequence != index then
        throw
          (.incomplete
            s!"node {node} has no record with sequence {index} before {event.record.location}")
    nodes := nodes.insert node records.toArray
  return (locations, locations.filterMap fun node => (nodes.get? node).map (node, ·))

/-- Checks that each receive names the send that produced its message. -/
private def link (nodes : List (Location × Array TraceEvent)) : Checked Unit := do
  for (_, records) in nodes do
    for event in records do
      let location := event.record.location
      let .receive source message causedBy _ := event.body | continue
      let some (sender, sequence) := causedBy
      | throw
          (.invalid
            s!"{location}: {event.kind} has no caused_by, so its send was not traced")
      let cause := s!"caused_by {sender}:{sequence}"
      let some sent := nodes.lookup sender
      | throw (.incomplete s!"{location}: {cause} names a node with no records yet")
      let some send := sent[sequence]?
      | throw (.incomplete s!"{location}: {cause} names a record not logged yet")
      let context := s!"{location}: {cause} at {send.record.location}"
      let .send _ target payload := send.body
      | throw (.invalid s!"{context} is a {send.kind} record, not a send")
      require (messageName payload == messageName message && target == event.node)
        s!"{context} does not send {messageName message} to {event.node}"
      require (source == sender) s!"{context} was sent by {sender}, not source {source}"
      require (payload == message) s!"{context} sends a different gossip TxID"

/--
Checks that the records have an order in which each send precedes its
receives. Real traces always do, because sequences are taken as records are
emitted.
-/
private def checkCausalOrder (nodes : List (Location × Array TraceEvent))
    : Checked Unit := do
  let names := nodes.map (·.1)
  let queues := nodes.toArray.map (·.2)
  let mut positions := Array.replicate queues.size 0
  let mut progress := true
  while progress do
    progress := false
    for queue in queues, index in [:queues.size] do
      while positions[index]! < queue.size do
        if let some (sender, sequence) := queue[positions[index]!]!.causedBy? then
          if positions[(names.findIdx? (· == sender)).getD 0]! <= sequence then
            break
        positions := positions.modify index (· + 1)
        progress := true
  let blocked :=
    (queues.zip positions).toList.filterMap
      fun (queue, position) =>
        queue[position]?.map (·.record.location)
  require blocked.isEmpty
    s!"receives precede their sends in a cycle at {", ".intercalate blocked}"

/-- Groups each retry's sends, and checks each is everything one retry sends. -/
private def retryBatches (node : Location) (locations : List Location)
    (records : Array TraceEvent)
    : Checked (Std.HashMap Nat (Array TraceEvent) × Option TxID) := do
  let mut order : Array Nat := #[]
  let mut batches : Std.HashMap Nat (Array TraceEvent) := {}
  let mut recovered : Option TxID := none
  for event in records do
    let .send batch _ message := event.body | continue
    unless batches.contains batch do
      order := order.push batch
    batches := batches.insert batch ((batches.getD batch #[]).push event)
    if let .gossip value := message then
      if let some earlier := recovered then
        require (earlier == value)
          s!"{event.record.location}: node {node} gossips {value.view}.{value.seqno}, but earlier gossiped {earlier.view}.{earlier.seqno}"
      recovered := some value
  let render (sends : List (String × Location)) : String :=
    toString (sends.map fun (kind, target) => s!"{kind}:{target}")
  let gossips := locations.map ("gossip", ·)
  for batch in order do
    let events := batches.getD batch #[]
    let sends :=
      events.toList.filterMap
        fun event =>
          match event.body with
          | .send _ target message => some (messageName message, target)
          | _ => none
    let some (kind, target) := sends.head? | continue
    let expected :=
      match kind with
      | "gossip" => gossips
      | "vote" => ("vote", target) :: gossips
      | _ => (locations.filter (· != node)).map ("iAmOpen", ·)
    if sends != expected.take sends.length || sends.length > expected.length then
      throw
        (.invalid
          s!"{events[0]!.record.location}: node {node}'s batch {batch} sends {render sends}, not one retry's {render expected}")
    if sends.length < expected.length then
      throw
        (.incomplete
          s!"{events.back!.record.location}: node {node}'s batch {batch} has not logged {render (expected.drop sends.length)}")
  return (batches, recovered)

/-- The actions and observations of one item, in replay order. -/
private def Item.instructions : Item → Array Instruction
  | .retry stale sends =>
      let rule := if stale then "stale-retry" else "retry"
      let node := sends[0]!.node
      let sent :=
        sends.toList.filterMap
          fun event =>
            match event.body with
            | .send _ target message => some (target, message)
            | _ => none
      #[
        .action (.local node .retry) (sends.toList.map (·.origin rule)),
        .outputs node sent [] (sends.toList.map (·.origin s!"{rule}-outputs"))
      ]
  | .execution rule event =>
      match event.execution? with
      | none => #[]
      | some (action, recorded) =>
          let pre : StateFields :=
            if event.isIAmOpen then
              { timeoutState := recorded.preTimeout }
            else
              {
                phase := recorded.pre
                timeoutState := recorded.preTimeout
                chosen := if recorded.pre == .joining then recorded.chosen else none
              }
          let post : StateFields :=
            {
              phase := recorded.post
              timeoutState := recorded.postTimeout
              gossips := recorded.gossips
              votes := recorded.votes
              chosen := recorded.chosen
              openKind := recorded.openKind
              restartRequested := if recorded.restart then some true else none
            }
          let notifications : List Notification :=
            if let some kind := recorded.openKind then
              [.opening kind]
            else if recorded.restart then
              (recorded.chosen.map .restart).toList
            else if recorded.pre == .opening && recorded.post == .open then
              [.completed]
            else
              []
          #[
            .state event.node pre [event.origin s!"{rule}-pre"],
            .action action [event.origin rule],
            .outputs event.node [] notifications [event.origin s!"{rule}-outputs"],
            .state event.node post [event.origin s!"{rule}-post"]
          ]

/-- Orders every node's items so that each message is sent before it is received. -/
private def linearize (items : List (Location × Array Item))
    : Checked (Array Instruction) := do
  let queues := items.toArray.map (·.2)
  let mut sent : Std.HashSet (Location × Nat) := {}
  let mut positions := Array.replicate queues.size 0
  let mut result := #[]
  let mut progress := true
  while progress do
    progress := false
    for queue in queues, index in [:queues.size] do
      while positions[index]! < queue.size do
        let item := queue[positions[index]!]!
        if let some cause := item.first.causedBy? then
          unless sent.contains cause do
            break
        if let .retry _ sends := item then
          sent :=
            sends.foldl (fun sent send => sent.insert (send.node, send.sequence)) sent
        result := result ++ item.instructions
        positions := positions.modify index (· + 1)
        progress := true
  let blocked :=
    (queues.zip positions).toList.filterMap
      fun (queue, position) =>
        queue[position]?.map (·.first.record.location)
  require blocked.isEmpty
    s!"receives precede their sends in a cycle at {", ".intercalate blocked}"
  return result

/-- The first of the accounts that finish, or else of all accounts, with the most effective executions. -/
private def best (hypotheses : Array Hypothesis) : Hypothesis :=
  hypotheses.foldl (init := hypotheses[0]!)
    fun chosen hypothesis =>
      if (hypothesis.finished && !chosen.finished)
          || (hypothesis.finished == chosen.finished
              && hypothesis.effective > chosen.effective) then
        hypothesis
      else
        chosen

structure Reduced where
  header : Header
  instructions : Array Instruction

/-- Translates node records into replay instructions, ending with the scenario's. -/
def reduce (records : Array Record) (scenario : Scenario) : Checked Reduced := do
  let events ← records.mapM parseEvent
  let (locations, nodes) ← group events
  link nodes
  checkCausalOrder nodes
  let mut recovered := []
  let mut items := []
  let mut finals := []
  let mut pending := []
  for (node, records) in nodes do
    let (batches, txid) ← retryBatches node locations records
    if let some value := txid then
      recovered := recovered ++ [(node, value)]
    let (participating, hypotheses) ← infer node records batches
    unless participating do
      throw (.incomplete s!"node {node} has records but no committed Gossiping record")
    let chosen := best hypotheses
    items := items ++ [(node, chosen.placed)]
    finals := finals ++ [(node, chosen, records.back!)]
    unless chosen.finished do
      pending :=
        pending
        ++ [s!"node {node} has neither completed nor requested a restart; it is {describe chosen.current}"]
  let mut instructions ← linearize items
  let participated :=
    s!"{finals.length} nodes participated, expected {scenario.participants}"
  require (finals.length <= scenario.participants) participated
  if finals.length < scenario.participants then
    pending := pending ++ [participated]
  if pending.isEmpty && !finals.any (·.2.1.completed) then
    pending := ["no node has completed opening"]
  unless pending.isEmpty do
    throw (.incomplete ("\n".intercalate pending))
  for (node, chosen, last) in finals do
    let fields : StateFields :=
      if chosen.completed then
        { phase := some .open, openKind := some scenario.openKind }
      else
        { phase := some .joining, restartRequested := some true }
    instructions := instructions.push (.state node fields [last.origin "scenario"])
  return { header := .make locations (finals.map (·.1)) recovered, instructions }

end DisasterRecovery.Replay
