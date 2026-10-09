import DisasterRecovery.TraceValidation.Records

set_option autoImplicit false

/-!
Orders the records of one recovery-decision-protocol run as the nodes committed
them, and tells logs that are still growing from logs that no order explains.
Each execution record carries the version that CCF reported for its
transaction, so a node's commit order is version order, with each write before
the executions that read at its version. The replay checks everything else.
`replayer/README.md` gives the rules.
-/

namespace DisasterRecovery.TraceValidation

open Lean Model.Local

/-- How many nodes take part in the e2e scenario. -/
structure Scenario where
  participants : Nat

/-- A replay unit: one retry's sends, or one execution. -/
inductive Item where
  | retry (sends : Array TraceEvent)
  | execution (event : TraceEvent)
deriving Inhabited

/-- Each node's records by sequence, which runs from 0 without repeats. -/
private def group (events : Array TraceEvent)
    : Checked (List (Location × Array TraceEvent)) := do
  (events.toList.map (·.node)).eraseDups.mapM
    fun node => do
      let records := (events.filter (·.node == node)).qsort (·.sequence < ·.sequence)
      for event in records, index in [:records.size] do
        require (event.sequence >= index) s!"{event.record.location}: repeated sequence"
        if event.sequence != index then
          throw (.incomplete s!"node {node} has not logged sequence {index} yet")
      return (node, records)

/-- Each retry's sends, with the one `sm_state` version the retry read. -/
private def retryBatches (locations : List Location) (records : Array TraceEvent)
    : Checked (List (Nat × Array TraceEvent)) := do
  let sends :=
    records.filterMap
      fun event =>
        match event.body with
        | .send batch _ _ version => some (batch, version, event)
        | _ => none
  (sends.toList.map (·.1)).eraseDups.mapM
    fun batch => do
      let batched := sends.filter (·.1 == batch)
      let (_, version, first) := batched[0]!
      require (batched.all (·.2.1 == version))
        s!"{first.record.location}: batch read two versions"
      -- A retry gossips to every location, after voting if it is in Voting, or
      -- sends IAmOpen to every other location.
      let size :=
        match first.body with
        | .send _ _ .vote _ => locations.length + 1
        | .send _ _ .iAmOpen _ => locations.length - 1
        | _ => locations.length
      if batched.size < size then
        throw (.incomplete s!"{first.record.location}: batch is partly logged")
      return (version, batched.map (·.2.2))

/-- One node's items in commit order, and the phase and open kind it ends in. -/
private def reduceNode (node : Location) (records : Array TraceEvent)
    (retries : List (Nat × Array TraceEvent))
    : Checked (Array Item × Phase × Option OpenKind) := do
  -- start: the protocol starts at the version of the transaction that wrote its
  -- initial phases.
  let starts :=
    records.filterMap
      fun event =>
        match event.body with
        | .start version _ => some (event, version)
        | _ => none
  let some (start, initial) := starts[0]?
  | throw (.incomplete s!"node {node} has no start record yet")
  require (starts.size == 1) s!"{start.record.location}: node {node} started twice"
  -- commit-order: CCF reports the version a transaction committed at if it
  -- wrote, and the version it read at otherwise, so a write comes before the
  -- reads at its version.
  let executions :=
    (records.filterMap fun event => event.execution?.map ((event, ·.2))).qsort
      fun (_, x) (_, y) =>
        x.version < y.version || (x.version == y.version && x.wrote && !y.wrote)
  for (event, x) in executions do
    require (if x.wrote then x.version > initial else x.version >= initial)
      s!"{event.record.location}: version {x.version} precedes the start at {initial}"
  for ((_, x), (event, y)) in executions.toList.zip executions.toList.tail do
    require (!(x.wrote && y.wrote && x.version == y.version))
      s!"{event.record.location}: two writes at version {y.version}"
  -- retry: a retry runs right after the `sm_state` write it read.
  let written := initial :: (executions.toList.filter (·.2.wrote)).map (·.2.version)
  for (version, sends) in retries do
    unless written.contains version do
      throw
        (.incomplete
          s!"{sends[0]!.record.location}: no logged write is at the version {version} it read")
  let retriesAt (version : Nat) : Array Item :=
    (retries.filter (·.1 == version)).toArray.map (.retry ·.2)
  let mut items := retriesAt initial
  let mut phase := Phase.gossiping
  let mut openKind : Option OpenKind := none
  for (event, x) in executions do
    items := items.push (.execution event)
    phase := x.post
    openKind := x.openKind <|> openKind
    if x.wrote then
      items := items ++ retriesAt x.version
  return (items, phase, openKind)

/-- The actions and observations of one item, in replay order. -/
private def Item.instructions : Item → Array Instruction
  | .retry sends =>
      let node := sends[0]!.node
      let sent :=
        sends.toList.filterMap
          fun event =>
            match event.body with
            | .send _ target message _ => some (target, message)
            | _ => none
      #[
        .action (.local node .retry) (sends.toList.map (·.origin "retry")),
        .outputs node sent [] (sends.toList.map (·.origin "retry-outputs"))
      ]
  | .execution event =>
      match event.execution? with
      | none => #[]
      | some (action, recorded) =>
          -- IAmOpen records its own Joining write as `pre`, not the phase it
          -- was received in.
          let pre : StateFields :=
            {
              phase := if event.isIAmOpen then none else some recorded.pre
              timeoutState := recorded.preTimeout
            }
          let post : StateFields :=
            {
              phase := recorded.post
              timeoutState := recorded.postTimeout
              chosen := recorded.chosen
              openKind := recorded.openKind
              restartRequested := if recorded.restart then some true else none
            }
          -- Nodes do not log notifications, which follow from what advance() wrote.
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
            .state event.node pre [event.origin "commit-order-pre"],
            .action action [event.origin "commit-order"],
            .outputs event.node [] notifications [event.origin "commit-order-outputs"],
            .state event.node post [event.origin "commit-order-post"]
          ]

/--
delivery: interleaves the nodes' items so that each receive takes a copy of its
message that its source has already sent to its node, and that no other receive
has taken, as the model's network delivers any queued copy.
-/
private def linearize (queues : Array (Array Item)) : Checked (Array Instruction) := do
  let mut queued : List (Location × Location × Message) := []
  let mut positions := Array.replicate queues.size 0
  let mut result := #[]
  let mut progress := true
  while progress do
    progress := false
    for queue in queues, index in [:queues.size] do
      while positions[index]! < queue.size do
        let item := queue[positions[index]!]!
        match item with
        | .retry sends =>
            queued :=
              queued
              ++ sends.toList.filterMap
                  fun event =>
                    match event.body with
                    | .send _ target message _ => some (event.node, target, message)
                    | _ => none
        | .execution event =>
            if let .receive source message _ := event.body then
              let envelope := (source, event.node, message)
              if !queued.contains envelope then
                break
              queued := Shared.MultiNodeTransitionSystem.removeOne envelope queued
        result := result ++ item.instructions
        positions := positions.modify index (· + 1)
        progress := true
  -- A send that a growing log has not logged yet may still come.
  unless (queues.zip positions).all fun (queue, position) => position == queue.size do
    throw (.incomplete "a receive has no earlier send of its message from its source")
  return result

structure Reduced where
  header : Header
  instructions : Array Instruction
  /-- Why the participants do not end as the scenario expects, if the replay succeeds. -/
  scenario : Option String

/-- Translates node records into replay instructions, once the scenario can be decided. -/
def reduce (records : Array Record) (scenario : Scenario) : Checked Reduced := do
  let events ← records.mapM parseEvent
  -- config: every node started with the same expected locations.
  let starts :=
    events.filterMap
      fun event =>
        match event.body with
        | .start _ expected => some (event, expected)
        | _ => none
  let some (_, locations) := starts[0]?
  | throw (.incomplete "no recovery-decision-protocol start record found")
  for (event, other) in starts do
    require (other == locations)
      s!"{event.record.location}: expected_locations differs between nodes"
  let nodes ← group events
  let mut queues := #[]
  let mut ends := []
  for (node, records) in nodes do
    let (items, phase, kind) ← reduceNode node records (← retryBatches locations records)
    queues := queues.push items
    ends := ends ++ [(node, phase, kind)]
  let instructions ← linearize queues
  let recovered :=
    events.toList.filterMap
      fun event =>
        match event.body with
        | .send _ _ (.gossip txid) _ => some (event.node, txid)
        | _ => none
  -- scenario: participants end once they open or join.
  let failed := ends.length > scenario.participants
  let status :=
    ends.map
      fun (node, phase, kind) =>
        s!"{node} is {phaseName phase}{(kind.map (s!" by {openKindName ·}")).getD ""}"
  unless failed
          || ends.length == scenario.participants
              && ends.any (·.2.2.isSome)
              && ends.all fun (_, phase, _) => phase != .gossiping && phase != .voting do
    throw (.incomplete s!"participants have not all opened or joined: {status}")
  return {
    header := .make locations (ends.map (·.1)) recovered
    instructions
    scenario :=
      if failed then
        some s!"expected {scenario.participants} participants, but {status}"
      else
        none
  }

end DisasterRecovery.TraceValidation
