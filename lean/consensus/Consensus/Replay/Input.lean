module

-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

public import Consensus.Replay.Interpreter

import Std.Data.HashMap

public section

namespace Consensus.Replay

open Lean

def require (condition : Bool) (message : String) : Except String Unit :=
  unless condition do throw message

def object (value : Json) : Except String (List (String × Json)) :=
  (·.toList) <$> value.getObj?

def field (value : Json) (key : String) : Except String Json :=
  (value.getObjVal? key).mapError (fun error => s!"{key}: {error}")

def optional (value : Json) (key : String) : Option Json :=
  (value.getObjVal? key).toOption

def text (value : Json) : Except String String :=
  value.getStr?

def natural : Json → Except String Nat
  | .num { mantissa := .ofNat value, exponent := 0 } => pure value
  | _ => throw "expected natural number"

def string (value : Json) (key : String) : Except String String :=
  field value key >>= text

def nat (value : Json) (key : String) : Except String Nat :=
  field value key >>= natural

def boolean (value : Json) (key : String) : Except String Bool :=
  field value key >>= Json.getBool?

def configuration (value : Json) : Except String (List String) := do
  let nodes ← object (← field value "nodes")
  return nodes.map Prod.fst

structure Record where
  file : String
  line : Nat
  value : Json
deriving Inhabited

def Record.location (record : Record) : String := s!"{record.file}:{record.line}"

/-- Read one JSON record per line without a schema pass. -/
def parseLog (file input : String) : Except String (Array Record) := do
  let mut records := #[]
  let lines := if input.isEmpty then [] else input.splitOn "\n"
  let lines := if input.endsWith "\n" then lines.dropLast else lines
  for raw in lines, line in [1:lines.length + 1] do
    let raw := if raw.endsWith "\r" then raw.dropEnd 1 |>.toString else raw
    let value ← (Json.parse raw).mapError (fun error => s!"{file}:{line}: {error}")
    records := records.push { file, line, value }
  return records

def readLog (path : System.FilePath) : IO (Except String (Array Record)) := do
  let path ← IO.FS.realPath path
  let bytes ← IO.FS.readBinFile path
  let some input := String.fromUTF8? bytes
  | return .error s!"{path}: invalid UTF-8"
  return parseLog path.toString input

structure Event where
  /-- The trace line the event was read from. -/
  record : Record
  /--
  `m_ts`: a counter the emitting process (`pid`) increments for each record it emits, so its
  order within a `pid` is the order of emission. Other tags share the counter, so it may
  have gaps.
  -/
  m_ts : Nat
  /--
  `ts`: the wall-clock emission time in nanoseconds, when the trace records it. Clocks of
  different processes may disagree, and one may step backwards.
  -/
  ts : Option Nat
  /-- `msg.function`: the name of the event. -/
  function : String
  /-- `msg.state.node_id`: the node the event is about. -/
  node : String
  /-- `msg`: the event's own fields. -/
  message : Json
  /-- `msg.state`: the node's consensus state when the event was emitted. -/
  state : Json
  /-- Cache identifier shared by byte-identical `msg` payloads, for observation caching. -/
  stateId : Option Nat := none
deriving Inhabited

def Event.origin (event : Event) (rule : String) : Origin :=
  { file := event.record.file, line := event.record.line, rule }

/-- A parsed CFT record queued in its emitting process's bucket before sorting by `m_ts`. -/
private structure BucketEntry where
  file : String
  m_ts : Nat
  line : Nat
  ts : Option Nat
  message : Json
  stateId : Option Nat

private structure ParsedMessage where
  isCmd : Bool
  function : String
  node : String
  state : Json
  extraDeclared : List String

private def parseMessage (message : Json) : Except String ParsedMessage := do
  if (optional message "cmd").isSome then
    return {
      isCmd := true, function := "", node := "", state := Json.null, extraDeclared := []
    }
  let function ← string message "function"
  let state ←
    if function == "retired_committed_tx" then
      pure Json.null
    else
      field message "state"
  let node ←
    string (if function == "retired_committed_tx" then message else state) "node_id"
  let mut extraDeclared : List String := []
  if function == "retired_committed_tx" then
    extraDeclared := (← string message "retired_node_id") :: extraDeclared
  if function == "add_configuration" then
    extraDeclared := (← configuration message) ++ extraDeclared
  return { isCmd := false, function, node, state, extraDeclared }

private def buildStreamsFromBuckets (buckets : Std.HashMap String (Array BucketEntry))
    : Except String (Array (Array Event) × List String) := do
  let sortedPids := buckets.keys.mergeSort
  let mut nodeEvents : Std.HashMap String (Array Event) := {}
  let mut pids : Std.HashMap String String := {}
  let mut declared : List String := []
  let mut parsedCache : Std.HashMap Nat ParsedMessage := {}
  for pid in sortedPids do
    let entries :=
      (buckets[pid]!).qsort
        fun a b =>
          a.m_ts < b.m_ts || (a.m_ts == b.m_ts && a.line < b.line)
    let mut previous : Option (Nat × String × Nat) := none
    for entry in entries do
      let location := s!"{entry.file}:{entry.line}"
      if let some (lastMts, earlierFile, earlierLine) := previous then
        if lastMts == entry.m_ts then
          throw
            s!"{location}: m_ts {entry.m_ts} of pid '{pid}' repeats {earlierFile}:{earlierLine}"
      previous := some (entry.m_ts, entry.file, entry.line)
      let parsed ←
        match entry.stateId.bind (parsedCache[·]?) with
        | some cached => pure cached
        | none =>
            let parsed ← (parseMessage entry.message).mapError (s!"{location}: " ++ ·)
            if let some id := entry.stateId then
              parsedCache := parsedCache.insert id parsed
            pure parsed
      unless parsed.isCmd do
        if let some other := pids[parsed.node]? then
          unless other == pid do
            throw
              s!"{location}: node '{parsed.node}' is traced by pids '{other}' and '{pid}'"
        pids := pids.insert parsed.node pid
        let record : Record :=
          { file := entry.file, line := entry.line, value := Json.null }
        let ev : Event :=
          {
            record
            m_ts := entry.m_ts
            ts := entry.ts
            function := parsed.function
            node := parsed.node
            message := entry.message
            state := parsed.state
            stateId := entry.stateId
          }
        nodeEvents :=
          nodeEvents.alter parsed.node
            fun
            | some arr => some (arr.push ev)
            | none => some #[ev]
        declared := parsed.node :: parsed.extraDeclared ++ declared
  let streams := pids.keys.mergeSort.toArray.map fun node => nodeEvents[node]?.getD #[]
  return (streams, declared.mergeSort.eraseDups)

/--
Order each process's records by `m_ts`, skip driver command records and records with a
`tag` other than `ccf.cft`, split events into per-node streams sorted by node, and collect
node identities.
-/
def prepareEvents (records : Array Record)
    : Except String (Array (Array Event) × List String) := do
  let records :=
    records.filter
      fun record => (optional record.value "tag").all (· == Json.str "ccf.cft")
  let mut buckets : Std.HashMap String (Array BucketEntry) := {}
  for record in records do
    let (pid, m_ts, ts, message) ←
      (do
        let pid ← string record.value "pid"
        let m_ts ← nat record.value "m_ts"
        let ts ← (optional record.value "ts").mapM natural
        let message ← field record.value "msg"
        return (pid, m_ts, ts, message))
      |>.mapError (s!"{record.location}: " ++ ·)
    let entry : BucketEntry :=
      { file := record.file, m_ts, line := record.line, ts, message, stateId := none }
    buckets :=
      buckets.alter pid
        fun
        | some arr => some (arr.push entry)
        | none => some #[entry]
  buildStreamsFromBuckets buckets

private def byteEqAt (s : String) (pos : Nat) (lit : String) : Bool :=
  if pos + lit.utf8ByteSize > s.utf8ByteSize then
    false
  else
    let rec go (i : Nat) : Bool :=
      if h : i < lit.utf8ByteSize then
        if h2 : pos + i < s.utf8ByteSize then
          if s.getUTF8Byte ⟨pos + i⟩ h2 == lit.getUTF8Byte ⟨i⟩ h then
            go (i + 1)
          else
            false
        else
          false
      else
        true
      termination_by lit.utf8ByteSize - i
    go 0

private def scanAsciiNat (s : String) (pos : Nat) : Option (Nat × Nat) :=
  let rec go (i acc : Nat) (saw : Bool) : Option (Nat × Nat) :=
    if h : i < s.utf8ByteSize then
      let b := s.getUTF8Byte ⟨i⟩ h
      if b >= 48 && b <= 57 then
        go (i + 1) (acc * 10 + (b - 48).toNat) true
      else if saw then
        some (acc, i)
      else
        none
    else if saw then
      some (acc, i)
    else
      none
    termination_by s.utf8ByteSize - i
  go pos 0 false

private def scanSimpleJsonString (s : String) (pos : Nat) : Option (String × Nat) :=
  let rec go (i : Nat) : Option (String × Nat) :=
    if h : i < s.utf8ByteSize then
      let b := s.getUTF8Byte ⟨i⟩ h
      if b == 34 then
        some (String.Pos.Raw.extract s ⟨pos⟩ ⟨i⟩, i + 1)
      else if b == 92 || b < 32 || b >= 128 then
        none
      else
        go (i + 1)
    else
      none
    termination_by s.utf8ByteSize - i
  go pos

private inductive FastLine where
  | skip
  | fast (pid : String) (m_ts ts : Nat) (msgRaw : String)
  | fallback

/-- Match standard Fluentd NDJSON lines to skip non-`ccf.cft` tags and reuse identical `msg` JSON. -/
private def matchFluentdLine (raw : String) : FastLine :=
  if !byteEqAt raw 0 "{\"tag\": \"" then
    .fallback
  else
    match scanSimpleJsonString raw 9 with
    | none => .fallback
    | some (tag, p0) =>
        if tag != "ccf.cft" then
          .skip
        else if !byteEqAt raw p0 ", \"ts\": " then
          .fallback
        else
          match scanAsciiNat raw (p0 + 8) with
          | none => .fallback
          | some (ts, p1) =>
              if !byteEqAt raw p1 ", \"pid\": \"" then
                .fallback
              else
                match scanSimpleJsonString raw (p1 + 10) with
                | none => .fallback
                | some (pid, p2) =>
                    if !byteEqAt raw p2 ", \"m_ts\": " then
                      .fallback
                    else
                      match scanAsciiNat raw (p2 + 10) with
                      | none => .fallback
                      | some (m_ts, p3) =>
                          if !byteEqAt raw p3 ", \"msg\": " then
                            .fallback
                          else
                            let msgStart := p3 + 9
                            let size := raw.utf8ByteSize
                            if h : msgStart < size then
                              if raw.getUTF8Byte ⟨size - 1⟩
                                    (Nat.sub_lt (Nat.lt_of_le_of_lt (Nat.zero_le _) h)
                                      Nat.zero_lt_one)
                                  == 125 then
                                .fast pid m_ts ts
                                  (String.Pos.Raw.extract raw ⟨msgStart⟩ ⟨size - 1⟩)
                              else
                                .fallback
                            else
                              .fallback

/--
Stream an NDJSON trace file line by line, skipping non-`ccf.cft` lines before JSON parsing
and reusing parsed `msg` objects across consecutive identical events from the same process.
-/
def readEvents (path : System.FilePath)
    : IO (Except String (Array (Array Event) × List String)) := do
  let path ← IO.FS.realPath path
  let file := path.toString
  let handle ← IO.FS.Handle.mk path .read
  let mut line : Nat := 0
  let mut buckets : Std.HashMap String (Array BucketEntry) := {}
  let mut msgCache : Std.HashMap String (String × Json × Nat) := {}
  let mut nextStateId : Nat := 1
  let mut error : Option String := none
  while error.isNone do
    let raw ← handle.getLine
    if raw.isEmpty then
      break
    line := line + 1
    let raw :=
      let raw := if raw.endsWith "\n" then raw.dropEnd 1 |>.toString else raw
      if raw.endsWith "\r" then raw.dropEnd 1 |>.toString else raw
    let mut handled := false
    match matchFluentdLine raw with
    | .skip => handled := true
    | .fast pid m_ts ts msgRaw =>
        match msgCache[pid]? with
        | some (cachedRaw, cachedJson, cachedId) =>
            if cachedRaw == msgRaw then
              let entry : BucketEntry :=
                {
                  file
                  m_ts
                  line
                  ts := some ts
                  message := cachedJson
                  stateId := some cachedId
                }
              buckets :=
                buckets.alter pid
                  fun
                  | some arr => some (arr.push entry)
                  | none => some #[entry]
              handled := true
            else
              match Json.parse msgRaw with
              | .ok msgJson =>
                  let id := nextStateId
                  nextStateId := nextStateId + 1
                  msgCache := msgCache.insert pid (msgRaw, msgJson, id)
                  let entry : BucketEntry :=
                    {
                      file,
                      m_ts,
                      line,
                      ts := some ts,
                      message := msgJson,
                      stateId := some id
                    }
                  buckets :=
                    buckets.alter pid
                      fun
                      | some arr => some (arr.push entry)
                      | none => some #[entry]
                  handled := true
              | .error _ => pure ()
        | none =>
            match Json.parse msgRaw with
            | .ok msgJson =>
                let id := nextStateId
                nextStateId := nextStateId + 1
                msgCache := msgCache.insert pid (msgRaw, msgJson, id)
                let entry : BucketEntry :=
                  {
                    file,
                    m_ts,
                    line,
                    ts := some ts,
                    message := msgJson,
                    stateId := some id
                  }
                buckets :=
                  buckets.alter pid
                    fun
                    | some arr => some (arr.push entry)
                    | none => some #[entry]
                handled := true
            | .error _ => pure ()
    | .fallback => pure ()
    unless handled do
      match Json.parse raw with
      | .error err => error := some s!"{file}:{line}: {err}"
      | .ok value =>
          if (optional value "tag").all (· == Json.str "ccf.cft") then
            match (do
                    let pid ← string value "pid"
                    let m_ts ← nat value "m_ts"
                    let ts ← (optional value "ts").mapM natural
                    let message ← field value "msg"
                    return (pid, m_ts, ts, message)) with
            | .error err => error := some s!"{file}:{line}: {err}"
            | .ok (pid, m_ts, ts, message) =>
                let entry : BucketEntry :=
                  { file, m_ts, line, ts, message, stateId := none }
                buckets :=
                  buckets.alter pid
                    fun
                    | some arr => some (arr.push entry)
                    | none => some #[entry]
  if let some err := error then
    return .error err
  return buildStreamsFromBuckets buckets

end Consensus.Replay
