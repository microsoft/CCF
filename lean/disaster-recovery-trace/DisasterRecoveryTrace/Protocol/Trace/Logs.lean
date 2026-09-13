import DisasterRecoveryTrace.Protocol.Trace.Replay

namespace DisasterRecoveryTrace.Protocol.Trace

open DisasterRecovery.Protocol.Model
open Lean

inductive LogError where
  | invalid (message : String)
  | incomplete (message : String)
deriving Repr, BEq

structure LocatedEvent where
  path : String
  line : Nat
  event : TraceEvent
deriving Repr, BEq

def LocatedEvent.origin (record : LocatedEvent) : String :=
  s!"{record.path}:{record.line}"

structure LogSnapshot where
  events : List LocatedEvent := []
  partialLines : List String := []
deriving Repr

private def logEvent (line : String) : Except String (Option TraceEvent) := do
  let message <- match Json.parse line with
    | .ok json =>
        match json.getObjVal? "msg" with
        | .ok (.str message) => pure message
        | _ => pure ""
    | .error _ => pure line
  match message.splitOn "RDP_TRACE " with
  | [] | [_] => pure none
  | _ :: rest => some <$> parseEvent (String.intercalate "RDP_TRACE " rest)

def extractLog (path input : String) : Except LogError LogSnapshot := do
  let lines := input.splitOn "\n"
  let mut snapshot : LogSnapshot := {}
  -- Only newline-terminated records are stable while the node is writing.
  for (line, index) in lines.dropLast.zipIdx do
    match logEvent line with
    | .error message =>
        throw (.invalid s!"{path}:{index + 1}: invalid trace record: {message}")
    | .ok none => pure ()
    | .ok (some event) =>
        snapshot := { snapshot with
          events := { path, line := index + 1, event } :: snapshot.events }
  if !(lines.getLast?.getD "").isEmpty then
    snapshot := { snapshot with partialLines := [s!"{path}:{lines.length}"] }
  pure { snapshot with events := snapshot.events.reverse }

def extractLogBytes (path : String) (input : ByteArray) : Except LogError LogSnapshot := do
  let mut endOffset := 0
  let mut line := 1
  for index in [:input.size] do
    if input[index]! == 10 then
      endOffset := index + 1
      line := line + 1
  let some text := String.fromUTF8? (input.extract 0 endOffset)
    | throw (.invalid s!"{path}: invalid UTF-8 in newline-terminated log data")
  let snapshot <- extractLog path text
  pure { snapshot with
    partialLines := if endOffset < input.size then [s!"{path}:{line}"] else [] }

private def eventLE (a b : LocatedEvent) : Bool :=
  a.event.node < b.event.node ||
    (a.event.node == b.event.node && a.event.sequence <= b.event.sequence)

def linearize (events : List LocatedEvent) :
    Except LogError (List LocatedEvent) := do
  let some first := events.head?
    | throw (.incomplete "no recovery-decision-protocol trace events found")
  let sorted := events.mergeSort eventLE
  let mut previous : Option TraceEvent := none
  let mut messageIds : List (String × LocatedEvent) := []
  let mut missing : List String := []
  for record in sorted do
    let event := record.event
    if event.instanceId != first.event.instanceId ||
        event.expectedLocations != first.event.expectedLocations then
      throw (.invalid s!"{record.origin}: recovery identity changed")
    if let some id := event.messageId then
      if messageIds.any (fun entry => entry.1 == id) then
        throw (.invalid s!"{record.origin}: duplicate message_id '{id}'")
      messageIds := (id, record) :: messageIds
    let expected := match previous with
      | some prev =>
          if prev.node == event.node then prev.sequence + 1 else 0
      | none => 0
    if event.sequence < expected then
      throw (.invalid s!"{record.origin}: duplicate node sequence {event.sequence}")
    if event.sequence > expected then
      missing := s!"{record.origin}: node {event.node} sequence {event.sequence}, expected {expected}"
        :: missing
    previous := some event
  for record in sorted do
    if let some cause := record.event.causedBy then
      match messageIds.find? (fun entry => entry.1 == cause) with
      | none =>
          missing := s!"{record.origin}: caused_by '{cause}' has no matching send" :: missing
      | some (_, source) =>
          if source.event.kind != .send then
            throw (.invalid s!"{record.origin}: caused_by '{cause}' does not identify a send")
  if !missing.isEmpty then
    throw (.incomplete (String.intercalate "\n" missing.reverse))

  let mut remaining := sorted
  let mut ordered : List LocatedEvent := []
  let mut emittedIds : List String := []
  let mut nextSequence : List (Location × Nat) := []
  for _ in events do
    let ready := remaining.find? fun record =>
      let event := record.event
      let sequence := (nextSequence.find? (fun entry => entry.1 == event.node)).map Prod.snd
        |>.getD 0
      event.sequence == sequence &&
        (event.causedBy.map emittedIds.contains |>.getD true)
    let some record := ready
      | throw (.invalid "recovery trace contains a causal cycle")
    remaining := remaining.filter fun other =>
      other.event.node != record.event.node || other.event.sequence != record.event.sequence
    ordered := record :: ordered
    emittedIds := record.event.messageId.toList ++ emittedIds
    nextSequence := (record.event.node, record.event.sequence + 1) ::
      nextSequence.filter (fun entry => entry.1 != record.event.node)
  pure ordered.reverse

structure Scenario where
  participatingNodes : Nat
  openKind : OpenKind
deriving Repr

def validateLogs (logs : List (String × ByteArray)) (scenario : Scenario) :
    Except LogError Nat := do
  if scenario.participatingNodes == 0 then
    throw (.invalid "expected participating-node count must be positive")
  let mut events := []
  let mut partialLines := []
  for (path, input) in logs do
    let snapshot <- extractLogBytes path input
    events := events ++ snapshot.events
    partialLines := partialLines ++ snapshot.partialLines
  for record in events do
    if record.event.kind == .open && record.event.openKind != some scenario.openKind then
      throw (.invalid s!"{record.origin}: unexpected scenario open kind")
  let ordered <- linearize events
  let state <- match replay (ordered.map LocatedEvent.event) with
    | .ok state => pure state
    | .error failure =>
        let origin := (ordered[failure.prefixLength - 1]?).map LocatedEvent.origin
          |>.getD "trace"
        throw (.invalid s!"{origin}: {renderFailure failure}")
  let started := state.active.map (fun active => active.startedNodes.length) |>.getD 0
  if started > scenario.participatingNodes then
    throw (.invalid s!"started {started} nodes, expected {scenario.participatingNodes}")
  if started < scenario.participatingNodes then
    throw (.incomplete s!"started {started} nodes, expected {scenario.participatingNodes}")
  match finish state ordered.length with
  | .error failure => throw (.incomplete (renderFailure failure))
  | .ok () => pure ()
  if !partialLines.isEmpty then
    throw (.incomplete s!"unterminated log lines: {String.intercalate ", " partialLines}")
  pure ordered.length

end DisasterRecoveryTrace.Protocol.Trace
