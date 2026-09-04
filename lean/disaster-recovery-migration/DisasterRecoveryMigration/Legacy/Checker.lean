import DisasterRecoveryMigration.Legacy.Model

namespace DisasterRecoveryMigration.Legacy

structure Edge where
  src : Nat
  action : Action
  dst : Nat
deriving Repr, BEq

structure Graph where
  states : Array GlobalState
  edges : Array Edge
  parents : Array (Option (Prod Nat Action))

def enumerate (n : Nat) : IO Graph := do
  let initial := initialState n
  let mut states := #[initial]
  let mut edges := #[]
  let mut parents : Array (Option (Prod Nat Action)) := #[none]
  let mut seen : Std.HashMap String Nat := {}
  seen := seen.insert (stateKey initial) 0
  let mut cursor := 0
  while cursor < states.size do
    let state := states[cursor]!
    for action in actions state do
      match nextState n state action with
      | none => pure ()
      | some next =>
          let key := stateKey next
          let (dst, discovered) :=
            match seen[key]? with
            | some index => (index, false)
            | none => (states.size, true)
          if discovered then
            seen := seen.insert key dst
            states := states.push next
            parents := parents.push (some (cursor, action))
          edges := edges.push { src := cursor, action, dst }
    cursor := cursor + 1
  pure { states, edges, parents }

def valuationBits (values : Array Bool) : String :=
  String.ofList (values.toList.map fun value => if value then '1' else '0')

private structure ExportEdge where
  src : Nat
  action : String
  dst : Nat

private def exportEdgeLE (left right : ExportEdge) : Bool :=
  left.src < right.src ||
    (left.src == right.src &&
      (left.action < right.action ||
        (left.action == right.action && left.dst <= right.dst)))

private def traceTo (graph : Graph) (target : Nat) : List Action :=
  let rec collect (index : Nat) (fuel : Nat) (suffix : List Action) : List Action :=
    match fuel with
    | 0 => suffix
    | fuel + 1 =>
      match graph.parents[index]? |>.bind id with
      | none => suffix
      | some (parent, action) => collect parent fuel (action :: suffix)
  collect target graph.states.size []

private def printTrace (graph : Graph) (target : Nat) : IO Unit := do
  let trace := traceTo graph target
  if trace.isEmpty then
    IO.eprintln "  trace: <initial state>"
  else
    for (action, step) in trace.zipIdx do
      IO.eprintln s!"  {step + 1}. {actionKey action}"

private def eventuallyGood (graph : Graph) (property : Nat) : Array Bool :=
  Id.run do
    let mut good :=
      graph.states.map fun state => (legacyValuations state.actors.size state)[property]!
    let mut remaining := Array.replicate graph.states.size 0
    let mut predecessors : Array (List Nat) := Array.replicate graph.states.size []
    for edge in graph.edges do
      remaining := remaining.modify edge.src (fun count => count + 1)
      predecessors := predecessors.modify edge.dst (fun values => edge.src :: values)
    let mut queue := #[]
    for index in List.range good.size do
      if good[index]! then queue := queue.push index
    let mut cursor := 0
    while cursor < queue.size do
      let resolved := queue[cursor]!
      for predecessor in predecessors[resolved]! do
        if !good[predecessor]! then
          remaining := remaining.modify predecessor (fun count => count - 1)
          if remaining[predecessor]! == 0 then
            good := good.set! predecessor true
            queue := queue.push predecessor
      cursor := cursor + 1
    return good

def checkGraph (n : Nat) (graph : Graph) : IO Bool := do
  IO.eprintln s!"reachable states: {graph.states.size}, transitions: {graph.edges.size}"
  let mut passed := true
  for property in List.range legacyPropertyNames.size do
    let name := legacyPropertyNames[property]!
    let expectation := legacyExpectations[property]!
    let values := graph.states.map fun state => (legacyValuations n state)[property]!
    let eventual := if expectation == "eventually" then eventuallyGood graph property else #[]
    let result :=
      if expectation == "always" then values.all id
      else if expectation == "sometimes" then values.any id
      else eventual[0]!
    IO.eprintln s!"{if result then "PASS" else "FAIL"} [{expectation}] {name}"
    if result && expectation == "sometimes" then
      match (List.range values.size).find? (fun index => values[index]!) with
      | none => pure ()
      | some index =>
          IO.eprintln "  shortest example:"
          printTrace graph index
    else if !result then
      passed := false
      let witness :=
        if expectation == "always" then
          (List.range values.size).find? fun index => !values[index]!
        else if expectation == "sometimes" then
          some 0
        else
          (List.range values.size).find? fun index =>
            !eventual[index]!
      match witness with
      | none => IO.eprintln "  no reachable example"
      | some index => printTrace graph index
  pure passed

def exportGraph (n : Nat) (graph : Graph) : IO Unit := do
  let canonical := (graph.states.toList.zipIdx.map fun (state, bfsId) =>
    (stateKey state, bfsId)).mergeSort (fun left right => left.1 <= right.1)
  let mut ids := Array.replicate graph.states.size 0
  for ((_, bfsId), canonicalId) in canonical.zipIdx do
    ids := ids.set! bfsId canonicalId
  IO.println "format\tccf-legacy-dr-graph-v1"
  IO.println s!"nodes\t{n}"
  IO.println s!"init\t{ids[0]!}"
  for ((key, bfsId), canonicalId) in canonical.zipIdx do
    IO.println s!"state\t{canonicalId}\t{key}\t{valuationBits (legacyValuations n graph.states[bfsId]!)}"
  let canonicalEdges := (graph.edges.toList.map fun edge => {
    src := ids[edge.src]!
    action := actionKey edge.action
    dst := ids[edge.dst]!
  }).mergeSort exportEdgeLE
  for edge in canonicalEdges do
    IO.println s!"edge\t{edge.src}\t{edge.action}\t{edge.dst}"

end DisasterRecoveryMigration.Legacy
