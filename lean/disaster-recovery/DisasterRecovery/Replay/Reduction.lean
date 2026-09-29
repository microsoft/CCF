import DisasterRecovery.Replay.Records
import Std.Data.HashSet

set_option autoImplicit false

/-!
Orders the records of one recovery-decision-protocol run as the nodes committed
them, and tells logs that are still growing from logs that no order explains.
The replay checks everything else. `replay/README.md` gives the rules.
-/

namespace DisasterRecovery.Replay

open Lean Model.Local

/-- What the e2e scenario must end with. -/
structure Scenario where
  participants : Nat
  openKind : OpenKind

/-- A replay unit: one retry's sends, or one execution and the rule that placed it. -/
inductive Item where
  | retry (sends : Array TraceEvent)
  | execution (rule : String) (event : TraceEvent)
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
      -- A retry votes and gossips to every location, or sends IAmOpen to every other one.
      let size :=
        match first.body with
        | .send _ _ .vote _ => locations.length + 1
        | .send _ _ .iAmOpen _ => locations.length - 1
        | _ => locations.length
      if batched.size < size then
        throw (.incomplete s!"{first.record.location}: batch is partly logged")
      return (version, batched.map (·.2.2))

/-- Whether an execution writes `sm_state`, and whether it writes `timeout_sm_state`. -/
private def writes (event : TraceEvent) (x : Execution) : Bool × Bool :=
  (event.isIAmOpen || x.post != x.pre, x.postTimeout != x.preTimeout)

/-- The locations of the gossips (in Gossiping) or votes (in Voting) `advance()` read. -/
private def Execution.set (execution : Execution) : Option (List Location) :=
  execution.gossips.map (·.map (·.1)) <|> execution.votes

/-- The location a received gossip, if `gossips`, or else a received vote inserts. -/
private def TraceEvent.inserts? (event : TraceEvent) (gossips : Bool) : Option Location :=
  match event.body, gossips with
  | .receive source (.gossip _) _ _, true
  | .receive source .vote _ _, false => some source
  | _, _ => none

/--
The committed states of a set, oldest first, from `base` to `last`. A reader
of a state has a higher sequence than the insert that wrote it, so the
lowest-sequence insert that recorded a state added its last element.
-/
private def chain (base : List Location) (inserts : Array (Location × List Location))
    : List Location → Nat → Option (List (List Location))
  | last, 0 => if last == base then some [last] else none
  | last, fuel + 1 => do
      if last == base then return [last]
      let (source, _) ← inserts.find? (·.2 == last)
      return (← chain base inserts (last.erase source) fuel) ++ [last]

/-- One node's items in commit order, and the phase and open kind it ends in. -/
private def reduceNode (node : Location) (records : Array TraceEvent)
    (retries : List (Nat × Array TraceEvent))
    : Checked (Array Item × Phase × Option OpenKind) := do
  -- participation: the first committed record, for Gossiping, has the initial versions.
  let some start := records.find? (·.body matches .committed ..)
  | throw (.incomplete s!"node {node} has no committed Gossiping record yet")
  let .committed .gossiping initial := start.body
  | throw (.invalid s!"{start.record.location}: first committed phase is not Gossiping")
  -- rolled-back: only the last execution of a message or timeout request can commit.
  let executions := records.filterMap fun event => event.execution?.map ((event, ·.2))
  let final :=
    executions.filter
      fun (e, _) =>
        (records.findRev? (·.causedBy? == e.causedBy?)).any (·.sequence == e.sequence)
  -- segment: executions read committed versions, which one chain of writes produced.
  let pairs :=
    ((initial, initial)
      :: executions.toList.map
          fun (_, x) => (x.preVersion, x.preTimeoutVersion)).eraseDups.mergeSort
      fun (a, b) (c, d) => max a b <= max c d
  for (before, after) in pairs.zip pairs.tail do
    let top := max after.1 after.2
    require
      (top > max before.1 before.2
        && (after.1 == before.1 || after.1 == top)
        && (after.2 == before.2 || after.2 == top))
      s!"node {node} read versions {after} after {before}, which no one write explains"
  -- writer: a retry may show one sm_state write after the newest versions read.
  let newest := max pairs.getLast!.1 pairs.getLast!.2
  let later := ((retries.map (·.1)).filter (· > newest)).eraseDups
  require (later.length <= 1) s!"node {node} retried from {later} after reading {newest}"
  let mut phase := Phase.gossiping
  let mut openKind : Option OpenKind := none
  let mut votes : List Location := []
  let mut items : Array Item := #[]
  for (pre, preTimeout) in pairs, index in [:pairs.length] do
    -- retry: a retry runs where the sm_state version it read is first read.
    if pairs.findIdx? (·.1 == pre) == some index then
      items := items ++ (retries.filter (·.1 == pre)).toArray.map (.retry ·.2)
    let candidates :=
      final.filter fun (_, x) => x.preVersion == pre && x.preTimeoutVersion == preTimeout
    let (writers, others) :=
      candidates.partition fun (e, x) => writes e x != (false, false)
    -- writer: the next versions, or a later write, show the one execution that committed.
    let next := pairs[index + 1]?
    let matching :=
      writers.filter
        fun (e, x) =>
          match next with
          | some (sm, timeout) => writes e x == (sm != pre, timeout != preTimeout)
          | none => later.isEmpty || (writes e x).1
    let witnessed := next.isSome || !later.isEmpty
    let writer := matching[0]?
    -- Writers with the same action and recorded fields replay alike, so they are one.
    let distinct := (matching.toList.map (·.1.execution?)).eraseDups.length
    unless distinct == 1 || (distinct == 0 && !witnessed) do
      throw
        ((if witnessed then Failure.invalid else .incomplete)
          s!"node {node}: {distinct} different final executions that read {(pre, preTimeout)} could have written the next versions")
    -- set-chain: readers of the gossips or votes follow the insert of the state they read.
    let mut placed := others
    if let some
            gossiping := (candidates.find? (·.2.set.isSome)).map (·.2.gossips.isSome) then
      let sets := others.filterMap (·.2.set)
      let base := if gossiping then [] else votes
      let top :=
        (writer.bind (·.2.set)).getD
          (sets.foldl (fun a b => if b.length > a.length then b else a) base)
      require
        ((writer.bind (·.2.set)).isSome
          || sets.all fun set => set.length < top.length || set == top)
        s!"node {node}: two largest sets read at {(pre, preTimeout)}"
      let inserts :=
        (others ++ writer.toArray).filterMap
          fun (e, x) =>
            (e.inserts? gossiping).bind fun source => x.set.map (source, ·)
      let some states := chain base inserts top (top.length + 1)
      | throw (.invalid s!"node {node}: no inserts explain {top} at {(pre, preTimeout)}")
      -- An insert off the chain did not commit, but a reader off it read no committed state.
      let (chained, unchained) := others.partition fun (_, x) => x.set.all states.contains
      require (unchained.all fun (e, _) => (e.inserts? gossiping).isSome)
        s!"node {node} read sets at {(pre, preTimeout)} that were never committed"
      placed :=
        (chained.toList.mergeSort
          fun (_, x) (_, y) =>
            (x.set.map (·.length)).getD 0 <= (y.set.map (·.length)).getD 0).toArray
    for (event, execution) in placed ++ writer.toArray do
      let writing := writer.any (·.1.sequence == event.sequence)
      items := items.push (.execution (if writing then "writer" else "execution") event)
      if let some source := event.inserts? false then
        votes := insertVote source votes
      if writing && (writes event execution).1 then
        phase := execution.post
      openKind := execution.openKind <|> openKind
    if next.isNone && writer.any (fun (e, x) => (writes e x).1) then
      items := items ++ (retries.filter (later.contains ·.1)).toArray.map (.retry ·.2)
  require (retries.all fun (v, _) => pairs.any (·.1 == v) || later.contains v)
    s!"node {node} retried from an sm_state version that no execution read or wrote"
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
  | .execution rule event =>
      match event.execution? with
      | none => #[]
      | some (action, recorded) =>
          -- IAmOpen records its own Joining write, not the phase it read.
          let read := if event.isIAmOpen then none else some recorded.pre
          let pre : StateFields :=
            {
              phase := read
              timeoutState := recorded.preTimeout
              chosen := if read == some .joining then recorded.chosen else none
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

/-- Interleaves the nodes' items so that each message is received after it is sent. -/
private def linearize (queues : Array (Array Item)) : Checked (Array Instruction) := do
  let mut sent : Std.HashSet (Location × Nat) := {}
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
            sent := sends.foldl (fun s e => s.insert (e.node, e.sequence)) sent
        | .execution _ event =>
            if event.body matches .receive .. && !event.causedBy?.all sent.contains then
              break
        result := result ++ item.instructions
        positions := positions.modify index (· + 1)
        progress := true
  require ((queues.zip positions).all fun (queue, position) => position == queue.size)
    "receives precede their sends in a cycle"
  return result

structure Reduced where
  header : Header
  instructions : Array Instruction
  /-- Why the participants do not end as the scenario expects, if the replay succeeds. -/
  scenario : Option String

/-- Translates node records into replay instructions, once the scenario can be decided. -/
def reduce (records : Array Record) (scenario : Scenario) : Checked Reduced := do
  let events ← records.mapM parseEvent
  let some first := events[0]?
  | throw (.incomplete "no recovery-decision-protocol trace records found")
  let nodes ← group events
  let mut queues := #[]
  let mut ends := []
  for (node, records) in nodes do
    -- Each execution names its cause, which a growing log may not have logged yet.
    for event in records do
      if event.execution?.isSome then
        let some (sender, sequence) := event.causedBy?
        | throw (.invalid s!"{event.record.location}: {event.kind} has no caused_by")
        let some cause := (nodes.lookup sender).bind (·[sequence]?)
        | throw (.incomplete s!"{event.record.location}: its cause is not logged yet")
        require
          (match event.body, cause.body with
            | .timeout .., .timeoutRequest => sender == node
            | .receive source message _ _, .send _ target payload _ =>
                source == sender && target == node && payload == message
            | _, _ => false)
          s!"{event.record.location}: {cause.record.location} did not cause it"
    let (items, phase, kind) ←
      reduceNode node records (← retryBatches first.expectedLocations records)
    queues := queues.push items
    ends := ends ++ [(node, phase, kind)]
  let instructions ← linearize queues
  let recovered :=
    events.toList.filterMap
      fun event =>
        match event.body with
        | .send _ _ (.gossip txid) _ => some (event.node, txid)
        | _ => none
  -- Participants end once they open or join; an opening of another kind fails already.
  let failed :=
    ends.length > scenario.participants
    || ends.any fun (_, p, k) => p != .joining && k.any (· != scenario.openKind)
  let status :=
    ends.map
      fun (node, phase, kind) =>
        s!"{node} is {phaseName phase}{(kind.map (s!" by {openKindName ·}")).getD ""}"
  unless failed
          || ends.length == scenario.participants
              && ends.any (·.2.2.isSome)
              && ends.all fun (_, phase, _) => phase != .gossiping && phase != .voting do
    throw (.incomplete s!"participants have not all opened or joined: {status}")
  let expected :=
    s!"expected participants to open by {openKindName scenario.openKind} or join"
  return {
    header := .make first.expectedLocations (ends.map (·.1)) recovered
    instructions
    scenario := if failed then some s!"{expected}, but {status}" else none
  }

end DisasterRecovery.Replay
