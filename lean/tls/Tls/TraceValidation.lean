-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import Tls.Properties.Stages
public import Tls.TraceValidation.Records

public section

/-!
Replays schema 1 traces of the connection engine through the model.

Each connection is replayed on its own, against an unconstrained peer. Each traced worker pass
must be explained by one `interleavedPass` of the model: the replayer supplies the records the
pass went on to read and searches the few socket behaviours a pass can observe, and accepts
the pass if one of them leaves the model in the state the engine reported. The README states
what this does and does not establish.
-/

namespace Tls.TraceValidation

open Lean Tls.Model Tls.Properties

/-- Why a trace was not accepted. -/
inductive FailureKind where
  /-- The engine did something the model does not. -/
  | rejected
  /-- The trace is malformed, truncated, or inconsistent with itself. -/
  | invalidTrace
  /-- The trace is well formed, but shows something the model does not cover. -/
  | unsupported
deriving DecidableEq, Repr

/-- A failure, with its diagnostic. -/
structure Failure where
  /-- What kind of failure. -/
  kind : FailureKind
  /-- A human-readable diagnostic. -/
  message : String

private def rejected {α : Type} (message : String) : Except Failure α :=
  .error ⟨.rejected, message⟩

private def invalid {α : Type} (message : String) : Except Failure α :=
  .error ⟨.invalidTrace, message⟩

private def unsupported {α : Type} (message : String) : Except Failure α :=
  .error ⟨.unsupported, message⟩

/-! ## The environment the replayer supplies -/

/-- Records a replayed socket holds. A stage is offered between none and all of it. -/
def socketCapacity : Nat := 16

/--
A model configuration a connection is replayed with. Only the record budget comes from the
engine. Neither the input buffer nor the read allowance ever limits a pass: the engine's
limits are in bytes, and the replayer offers each pass only the records it went on to read.

With `kernel`, a socket polls writable exactly when it accepts a record, which satisfies
`Config.Kernel`. Without it, a socket always polls writable, and so may refuse a KeyUpdate
which the engine started because it polled writable. Tests which gate writes artificially
produce such sockets.
-/
def replayConfig (budget : Nat) (kernel : Bool) : Config :=
  {
    recordBudget := budget
    socketCapacity := socketCapacity
    writableThreshold := if kernel then 1 else 0
    inputBuffer := 1048576
    readsPerPass := 1048576
    maxQueuedOutput := none
  }

/-- One behaviour of the socket and of inbound admission during a pass. -/
structure Candidate where
  /-- Inbound admission is saturated. -/
  saturated : Bool
  /-- The first stage which sees the peer closed, by position; four if none does. -/
  closedFrom : Nat
  /-- Records the socket accepts from the retry stage. -/
  retry : Nat
  /-- Records the socket accepts from the prefetch stage. -/
  prefetch : Nat
  /-- Records the socket accepts from the read stage, which may send KeyUpdate responses. -/
  read : Nat
  /-- Records the socket accepts from the write stage. -/
  write : Nat
  /-- How many times the read stage may call `SSL_read`. -/
  reads : Nat
deriving Repr

private def stageIndex : Stage → Nat
  | .retry => 0
  | .prefetch => 1
  | .read => 2
  | .write => 3

private def Candidate.free (candidate : Candidate) : Stage → Nat
  | .retry => candidate.retry
  | .prefetch => candidate.prefetch
  | .read => candidate.read
  | .write => candidate.write

/-- The interleaving a candidate stands for. Before each stage the socket's send buffer is
reset to leave the chosen room; what the peer has sent is left as it is. -/
def Candidate.interleaving (candidate : Candidate) : Interleaving where
  env stage :=
    {
      saturated := candidate.saturated,
      peerClosed := candidate.closedFrom ≤ stageIndex stage
    }
  socket stage socket :=
    {
      socket with
        outbound :=
          List.replicate (socketCapacity - candidate.free stage) (.keyUpdate false)
    }
  reads := candidate.reads

/--
Every candidate for a pass which constructed `responses` KeyUpdate records, given the read
allowances to try. A write stage puts at most two records on the socket: a KeyUpdate and an
application record. A read stage puts on it the responses it constructs, and one constructed
by an earlier pass which it flushes.
-/
def candidates (responses : Nat) (allowances : List Nat) : List Candidate :=
  let rooms := [2, 1, 0]
  allowances.flatMap
    fun reads =>
      [false, true].flatMap
        fun saturated =>
          [4, 3, 2, 1, 0].flatMap
            fun closedFrom =>
              rooms.flatMap
                fun retry =>
                  rooms.flatMap
                    fun prefetch =>
                      (List.range (responses + 2)).reverse.flatMap
                        fun read =>
                          rooms.map
                            fun write =>
                              {
                                saturated,
                                closedFrom,
                                retry,
                                prefetch,
                                read,
                                write,
                                reads
                              }

/-! ## What is compared -/

/-- What the trace hooks report of a connection after a pass, as far as the model has it. -/
structure Observation where
  /-- The connection survived the pass. -/
  alive : Bool
  /-- The pass closed the connection because the peer exceeded the receive budget. -/
  exceeded : Bool
  /-- Application records the pass put on the socket. -/
  wrote : Nat
  /-- Records from the peer which the pass decrypted. -/
  decrypted : Nat
  /-- The size of each piece of plaintext the pass handed to the owner. -/
  delivered : List Nat
  /-- `TrafficKeys::sent`. -/
  sent : Nat
  /-- `TrafficKeys::received`. -/
  received : Nat
  /-- `SSL_in_init`. -/
  inInit : Bool
  /-- A KeyUpdate is scheduled or owed. -/
  updateQueued : Bool
  /-- A write must be retried. -/
  writeRetry : Bool
  /-- `want_write`. -/
  wantWrite : Bool
  /-- `read_wants_write`. -/
  readWantsWrite : Bool
  /-- Output remains queued. -/
  outputQueued : Bool
deriving DecidableEq, Repr

/-- Nothing but its deliveries, its writes and the reason is compared of a pass which closed
its connection. -/
def Observation.normal (observation : Observation) : Observation :=
  if observation.alive then
    observation
  else
    {
      alive := false
      exceeded := observation.exceeded
      wrote := observation.wrote
      decrypted := 0
      delivered := observation.delivered
      sent := 0
      received := 0
      inInit := false
      updateQueued := false
      writeRetry := false
      wantWrite := false
      readWantsWrite := false
      outputQueued := false
    }

/-- Records the peer has sent which OpenSSL has not decrypted. A held record has been. -/
def undecrypted (io : Io) : Nat :=
  io.socket.inbound.length
  + io.conn.ssl.input.length
  - (if io.conn.ssl.held then 1 else 0)

/-- What the engine reported. -/
def Observation.ofPass (pass : Pass) : Observation :=
  {
    alive := pass.alive
    exceeded := pass.exceeded
    wrote := (pass.operations.filter (· matches .wrote _)).length
    decrypted := (pass.operations.filter (· matches .recordIn 22 | .recordIn 23)).length
    delivered :=
      pass.operations.filterMap
        fun
        | .delivered bytes => some bytes
        | _ => none
    sent := pass.sent
    received := pass.received
    inInit := pass.inInit
    updateQueued := pass.updateQueued
    writeRetry := pass.retry != 0
    wantWrite := pass.wantWrite
    readWantsWrite := pass.readWantsWrite
    outputQueued := pass.queued != 0
  }

/--
What the hooks would report of the model's connection.

One counter moves earlier in the engine than in the model, and this is where that is accounted
for. OpenSSL reports a KeyUpdate it sends when it constructs the message, so
`TrafficKeys::sent` is already zero while that record waits to be flushed. The model counts
the record under the old key until it is flushed.
-/
def Observation.ofModel (config : Config) (before : Io) (io : Io) : Observation :=
  {
    alive := io.conn.alive
    exceeded := !io.conn.alive && config.recordBudget < io.conn.ssl.received
    wrote := before.conn.output.length - io.conn.output.length
    decrypted := undecrypted before - undecrypted io
    delivered := (io.delivered.map (·.payload)).filter (· != 0)
    sent := if io.conn.ssl.pending = .update then 0 else io.conn.ssl.sent
    received := io.conn.ssl.received
    inInit := io.conn.ssl.pending = .update
    updateQueued := io.conn.ssl.updateQueued
    writeRetry := io.conn.writeRetry
    wantWrite := io.conn.wantWrite
    readWantsWrite := io.conn.readWantsWrite
    outputQueued := !io.conn.output.isEmpty
  }

/-- The model's pass explains the engine's: it broke no OpenSSL rule and reports the same
state. -/
def explains (config : Config) (before : Io) (pass : Pass) (io : Io) : Bool :=
  !io.conn.ssl.misused
  && (Observation.ofModel config before io).normal == (Observation.ofPass pass).normal

/-! ## Lookahead over one connection's passes -/

/-- `SSL_ERROR_SYSCALL`. -/
def sslErrorSyscall : Nat := 5

/-- `SSL_ERROR_ZERO_RETURN`. -/
def sslErrorZeroReturn : Nat := 6

/-- `SSL_R_UNEXPECTED_EOF_WHILE_READING`, which OpenSSL reports as a protocol error. -/
def reasonUnexpectedEof : Nat := 294

/-- The pass saw the peer go away: a clean close, an end of input, or a failed system call. -/
def peerEnded (operations : List Operation) : Bool :=
  operations.any
    fun
    | .readFailed error => error == sslErrorZeroReturn || error == sslErrorSyscall
    | .writeFailed error => error == sslErrorSyscall
    | .errorReason reason => reason == reasonUnexpectedEof
    | .prefetchFailed => true
    | _ => false

/--
The offset in a connection's output at which each of its application records starts. The
engine cuts its queued bytes into records as it writes them, so the records are known only
from the writes. Bytes never written form the record being retried, if any, and one more.
-/
def recordStarts (passes : List Pass) : Except Failure (List Nat) := do
  let mut queued := 0
  let mut written := 0
  let mut retry := 0
  let mut starts : Array Nat := #[]
  for pass in passes do
    if pass.queuedBefore < queued then
      invalid "queued output shrank between passes"
    let mut wrote := 0
    for operation in pass.operations do
      if let .wrote bytes := operation then
        starts := starts.push (written + wrote)
        wrote := wrote + bytes
    if pass.queued + wrote != pass.queuedBefore then
      invalid "queued output does not account for what the pass wrote"
    written := written + wrote
    queued := pass.queued
    retry := pass.retry
  if queued != 0 then
    starts := starts.push written
    if 0 < retry ∧ retry < queued then
      starts := starts.push (written + retry)
  return starts.toList

private def nextMessage : List (Nat × Operation) → Except Failure (Option Bool)
  | [] => pure none
  | (_, .keyUpdateIn requested) :: _ => pure (some requested)
  | (_, .recordIn _) :: _ => unsupported "a handshake record which is not a KeyUpdate"
  | _ :: rest => nextMessage rest

private def collect : Bool → List (Nat × Operation) → Except Failure (List (Nat × Record))
  | _, [] => pure []
  | awaiting, (index, operation) :: rest =>
      match operation with
      | .recordIn 23 =>
          if awaiting then
            unsupported "a handshake record which is not a KeyUpdate"
          else
            let payload :=
              match rest with
              | (next, .delivered bytes) :: _ => if next = index then bytes else 0
              | _ => 0
            (collect false rest).map ((index, .app payload) :: ·)
      | .recordIn 22 =>
          if awaiting then
            unsupported "a handshake record which is not a KeyUpdate"
          else
            (nextMessage rest).bind
              fun
              | some requested =>
                  (collect true rest).map ((index, .keyUpdate requested) :: ·)
              | none => (collect false rest).map ((index, .keyUpdate false) :: ·)
      -- An alert: the peer is closing, and the pass which reads it reports that.
      | .recordIn 21 => pure []
      | .recordIn other => unsupported s!"a record with content type {other}"
      | .keyUpdateIn _ =>
          if awaiting then
            collect false rest
          else
            unsupported "several KeyUpdate messages in one record"
      | _ => collect awaiting rest

/--
The records the peer sent, in the model's terms, attached to the pass at which the replayer
offers them. An application record carries the size of its plaintext. OpenSSL reports a
KeyUpdate message after the record which carried it, possibly in a later pass, so whether it
requests an update is found by looking ahead.

A pass which began with input pending read records which the engine had already taken off the
socket. Those are offered to the last earlier pass which began with none pending, so that the
model has them buffered too.
-/
def arrivals (passes : List Pass) : Except Failure (List (List Record)) := do
  let operations :=
    passes.zipIdx.flatMap
      fun (pass, index) => pass.operations.map fun operation => (index, operation)
  let records ← collect false operations
  let decrypted :=
    (List.range passes.length).map fun index => (records.filter (·.1 == index)).map (·.2)
  let (offered, _) :=
    (passes.zip decrypted).foldr
      (fun (pass, records) (offered, later) =>
        if pass.first || !pass.pendingBefore then
          ((records ++ later) :: offered, [])
        else
          ([] :: offered, records ++ later))
      (([], []) : List (List Record) × List Record)
  return offered

/--
How many times the pass's read stage called `SSL_read` to any effect: once for each
application record, for each KeyUpdate message processed, and for each KeyUpdate record which
was answered before its message was processed.
-/
def readCalls : List Operation → Nat
  | [] => 0
  | .recordIn 23 :: rest => readCalls rest + 1
  | .keyUpdateIn _ :: rest => readCalls rest + 1
  | .recordIn 22 :: .recordOut 22 :: rest => readCalls rest + 1
  | _ :: rest => readCalls rest

/-! ## Replay -/

/-- One way of replaying a connection which still explains every pass so far. -/
structure Alternative where
  /-- Its sockets satisfy `Config.Kernel`. -/
  kernel : Bool
  /-- The model's connection. -/
  conn : Conn
  /-- Records the peer has sent which the model has not taken off the socket. -/
  inbound : List Record := []

/-- One connection between its passes. -/
structure Connection where
  /-- `TrafficKeyPolicy::record_budget`. -/
  budget : Nat
  /-- The replays which still explain every pass, under each kind of socket. -/
  alternatives : List Alternative
  /-- Bytes of output the engine had queued when its last pass ended. -/
  queued : Nat := 0
  /-- Bytes of output the engine has accepted. -/
  offset : Nat := 0
  /-- Where the application records not yet given to the model start. -/
  starts : List Nat
  /-- The records offered at each remaining pass. -/
  arrivals : List (List Record)
  /-- The next unused payload. -/
  nextPayload : Nat := 0

/-- The state of a replay. -/
structure World where
  /-- The connections which are open, by engine and connection id. -/
  connections : List ((Nat × Nat) × Connection) := []
  /-- The connections which have been closed. -/
  finished : List (Nat × Nat) := []
  /-- Records accepted. -/
  count : Nat := 0
  /-- Passes accepted. -/
  passes : Nat := 0
  /-- Connections established. -/
  established : Nat := 0
  /-- Connections closed which only a socket outside `Config.Kernel` explains. -/
  outsideKernel : Nat := 0
  /-- The test case the engine was running. -/
  label : String := "<none>"
  /-- `trace_end` has been read. -/
  ended : Bool := false

private def describe (observation : Observation) : String :=
  let flag (name : String) (value : Bool) := if value then s!" {name}" else ""
  if observation.alive then
    s!"alive sent={observation.sent} received={observation.received} wrote={observation.wrote} decrypted={observation.decrypted} delivered={observation.delivered}{flag "in_init" observation.inInit}{flag "update_queued" observation.updateQueued}{flag "write_retry" observation.writeRetry}{flag "want_write" observation.wantWrite}{flag "read_wants_write" observation.readWantsWrite}{flag "output_queued" observation.outputQueued}"
  else
    s!"closed wrote={observation.wrote} delivered={observation.delivered}{flag "budget_exceeded" observation.exceeded}"

private def keyUpdatesSent (pass : Pass) : Nat :=
  (pass.operations.filter (· matches .keyUpdateOut _)).length

/-- The model's pass under one candidate. -/
def run (config : Config) (readable : Bool) (start : Io) (candidate : Candidate) : Io :=
  interleavedPass config candidate.interleaving readable start

private def startOf (budget : Nat) (pass : Pass) (records : List Record)
    (payloads : Option (List Payload)) (alternative : Alternative)
    : Option (Config × Bool × Io) := do
  let config := replayConfig budget alternative.kernel
  let conn ←
    match payloads with
    | some payloads => send config payloads alternative.conn
    | none => some alternative.conn
  let readable := pass.first || pass.readable || pass.pendingBefore
  return (
    config,
    readable,
    { conn, socket := { inbound := alternative.inbound ++ records } }
  )

private def candidatesFor (pass : Pass) : List Candidate :=
  candidates (keyUpdatesSent pass) [readCalls pass.operations, 1048576]

/-- Replays one pass under one alternative, if some candidate explains it. -/
def replayAlternative (budget : Nat) (pass : Pass) (records : List Record)
    (payloads : Option (List Payload)) (alternative : Alternative)
    : Option Alternative := do
  let (config, readable, start) ← startOf budget pass records payloads alternative
  let candidate ←
    (candidatesFor pass).find?
      fun candidate =>
        explains config start pass (run config readable start candidate)
  let io := run config readable start candidate
  return { alternative with conn := io.conn, inbound := io.socket.inbound }

private def outcomes (budget : Nat) (pass : Pass) (records : List Record)
    (payloads : Option (List Payload)) (alternative : Alternative)
    : String :=
  let sockets :=
    if alternative.kernel then "kernel sockets" else "sockets which always poll writable"
  match startOf budget pass records payloads alternative with
  | none => s!"model with {sockets}: the connection is closed"
  | some (config, readable, start) =>
      let distinct :=
        ((candidatesFor pass).map
          fun candidate =>
            describe
              (Observation.ofModel config start
                (run config readable start candidate)).normal).eraseDups
      let more :=
        if distinct.length > 6 then s!" | and {distinct.length - 6} more" else ""
      s!"model with {sockets}: {" | ".intercalate (distinct.take 6)}{more}"

/-- Replays one pass of an open connection. -/
def replayPass (connection : Connection) (pass : Pass) : Except Failure Connection := do
  if pass.budget != connection.budget then
    invalid "the record budget changed"
  let (records, arrivals) ←
    match connection.arrivals with
    | records :: arrivals => pure (records, arrivals)
    | [] => invalid "a pass beyond the connection's last"
  let appended := pass.queuedBefore - connection.queued
  let offset := connection.offset + appended
  let sent := (connection.starts.takeWhile (· < offset)).length
  let payloads :=
    if appended = 0 then
      none
    else
      some ((List.range sent).map (· + connection.nextPayload))
  if !pass.alive && !pass.exceeded && !peerEnded pass.operations then
    rejected
      "the engine closed the connection, but neither for the receive budget nor because the peer went away"
  if socketCapacity < keyUpdatesSent pass + 3 then
    unsupported s!"{keyUpdatesSent pass} KeyUpdate records sent in one pass"
  let alternatives :=
    connection.alternatives.filterMap
      (replayAlternative connection.budget pass records payloads)
  if alternatives.isEmpty then
    rejected
      s!"no socket behaviour makes the model's pass match the engine's. engine: {describe (Observation.ofPass pass).normal}. {". ".intercalate (connection.alternatives.map (outcomes connection.budget pass records payloads))}"
  return {
    connection with
      alternatives
      queued := pass.queued
      offset
      starts := connection.starts.drop sent
      arrivals
      nextPayload := connection.nextPayload + sent
  }

private def passesOf (trace : Array Event) (key : Nat × Nat) : List Pass :=
  trace.toList.filterMap
    fun
    | .pass pass => if (pass.engine, pass.conn) == key then some pass else none
    | _ => none

private def close (world : World) (key : Nat × Nat) (connection : Connection) : World :=
  {
    world with
      connections := world.connections.filter (·.1 != key)
      finished := key :: world.finished
      outsideKernel :=
        world.outsideKernel + (if connection.alternatives.any (·.kernel) then 0 else 1)
  }

/-- Applies one record. `trace` is the whole trace, for lookahead. -/
def step (trace : Array Event) (world : World) (event : Event)
    : Except Failure World := do
  if world.ended then
    invalid "a record after trace_end"
  let world := { world with count := world.count + 1 }
  match event with
  | .traceStart schema =>
      if world.count != 1 then invalid "trace_start is not the first record"
      if schema != 1 then unsupported s!"schema {schema}"
      return world
  | .label kind name =>
      return {
        world with
          label :=
            if kind == "case" then
              name
            else
              s!"{(world.label.splitOn " / ").headD ""} / {name}"
      }
  | .traceEnd events =>
      if events + 1 != world.count then
        invalid s!"trace_end counts {events} records, but {world.count - 1} precede it"
      return { world with ended := true }
  | .abort engine conn =>
      let key := (engine, conn)
      match world.connections.lookup key with
      | some connection => return close world key connection
      | none => invalid "abort of a connection which is not open"
  | .pass pass =>
      let key := (pass.engine, pass.conn)
      let (world, connection) ←
        if pass.first then do
          if (world.connections.lookup key).isSome || world.finished.contains key then
            invalid "a connection was established twice"
          if pass.budget < 2 then
            invalid "a record budget below two"
          let passes := passesOf trace key
          let connection : Connection :=
            {
              budget := pass.budget
              alternatives :=
                [
                  { kernel := true, conn := .initial },
                  { kernel := false, conn := .initial }
                ]
              starts := ← recordStarts passes
              arrivals := ← arrivals passes
            }
          pure ({ world with established := world.established + 1 }, connection)
        else
          match world.connections.lookup key with
          | some connection => pure (world, connection)
          | none => invalid "a pass over a connection which is not open"
      let connection ← replayPass connection pass
      let world := { world with passes := world.passes + 1 }
      if !pass.alive || pass.closed then
        return close world key connection
      else
        return {
          world with
            connections := (key, connection) :: world.connections.filter (·.1 != key)
        }

/-- The outcome of checking a trace, printed as JSON by `tls-replay --json`. -/
structure Report where
  /-- `accepted`, `rejected`, `invalid_trace`, or `unsupported`. -/
  status : String
  /-- Records accepted before the outcome. -/
  events : Nat
  /-- A human-readable diagnostic. -/
  message : String
  /-- The failing record's sequence number, if decoded. -/
  seq? : Option Nat := none
  /-- The failing record's engine, if it has one. -/
  engine? : Option Nat := none
  /-- The failing record's connection, if it has one. -/
  conn? : Option Nat := none
deriving Repr, BEq, ToJson

/-- The report status for a failure kind. -/
def statusName : FailureKind → String
  | .rejected => "rejected"
  | .invalidTrace => "invalid_trace"
  | .unsupported => "unsupported"

private def failureReport (world : World) (seq? : Option Nat) (event? : Option Event)
    (failure : Failure)
    : Report :=
  let identity :=
    match event? with
    | some (.pass pass) => some (pass.engine, pass.conn)
    | some (.abort engine conn) => some (engine, conn)
    | _ => none
  let number (value : Option Nat) := (value.map toString).getD "<none>"
  {
    status := statusName failure.kind
    events := world.count
    message :=
      s!"record {world.count + 1} seq={number seq?} case={world.label} engine={number (identity.map (·.1))} conn={number (identity.map (·.2))}: {failure.message}"
    seq?
    engine? := identity.map (·.1)
    conn? := identity.map (·.2)
  }

/-- Checks a whole trace, one record per line, stopping at the first failure. -/
def checkLines (lines : List String) : Report :=
  Id.run do
    let mut decoded : Array (Nat × Event) := #[]
    for line in lines do
      let world : World := { count := decoded.size }
      match parseLine line with
      | .error message => return failureReport world none none ⟨.invalidTrace, message⟩
      | .ok json =>
          match decode json with
          | .error message =>
              return failureReport world (num json "seq").toOption none
                ⟨.invalidTrace, message⟩
          | .ok record => decoded := decoded.push record
    let trace := decoded.map (·.2)
    let mut world : World := {}
    for (seq, event) in decoded do
      if seq != world.count + 1 then
        return failureReport world (some seq) (some event)
          ⟨.invalidTrace, s!"expected seq {world.count + 1}"⟩
      match step trace world event with
      | .ok next => world := next
      | .error failure => return failureReport world (some seq) (some event) failure
    if !world.ended then
      return failureReport world none none
        ⟨.invalidTrace, "truncated trace: missing trace_end"⟩
    if world.passes == 0 then
      return failureReport world none none
        ⟨.invalidTrace, "no coverage: the trace has no pass"⟩
    let outsideKernel :=
      world.outsideKernel
      + (world.connections.filter
          fun (_, connection) => !connection.alternatives.any (·.kernel)).length
    return {
      status := "accepted"
      events := world.count
      message :=
        s!"accepted {world.count} records: {world.passes} passes over {world.established} connections, {outsideKernel} of them explained only by a socket which polled writable and then refused a KeyUpdate"
    }

/-- Checks the trace in the file at `path`. -/
def checkFile (path : System.FilePath) : IO Report := do
  let text ← IO.FS.readFile path
  let lines := text.splitOn "\n"
  -- A final newline leaves one empty piece, which is not a record.
  let lines := if lines.getLast? == some "" then lines.dropLast else lines
  return checkLines lines

/-- The process exit code: 0 accepted, 1 rejected, 2 invalid trace, 3 unsupported. -/
def Report.exitCode (report : Report) : UInt32 :=
  match report.status with
  | "accepted" => 0
  | "rejected" => 1
  | "unsupported" => 3
  | _ => 2

end Tls.TraceValidation
