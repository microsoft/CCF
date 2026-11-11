-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import Tls.Model.OpenSsl

@[expose] public section

/-!
One worker pass of `OpenSSLConnectionEngine` over an established connection with the
traffic-key policy enabled, and the owner's `send`. Each definition is named after the C++
function it follows in `src/tls/openssl_connection_engine.h`.
-/

namespace Tls.Model

/-- `TrafficKeys::update_due`: one record under the sending key is left for KeyUpdate. -/
def updateDue (config : Config) (conn : Conn) : Bool :=
  config.recordBudget ≤ conn.ssl.sent + 1

/-- `SSL_in_init`: a KeyUpdate has been started and is not yet on the socket. -/
def inInit (conn : Conn) : Bool :=
  conn.ssl.pending = .update

/-- `has_pending_input`: OpenSSL holds input which no socket event will announce. -/
def hasInput (conn : Conn) : Bool :=
  !conn.ssl.input.isEmpty

/-- `read_blocked_by_write`: `SSL_read` must not be entered behind this pending write. -/
def readBlockedByWrite (conn : Conn) : Bool :=
  conn.writeRetry
  && conn.wantWrite
  && !conn.readWantsWrite
  && (inInit conn || conn.ssl.updateQueued)

/-- `update_awaits_socket`: the next write would begin with a KeyUpdate, and the socket does
not poll writable. Such a write is left unstarted. -/
def updateAwaitsSocket (config : Config) (env : Env) (io : Io) : Bool :=
  !io.conn.writeRetry
  && !io.conn.readWantsWrite
  && !inInit io.conn
  && (updateDue config io.conn || io.conn.ssl.updateQueued)
  && !(pollsWritable config io.socket || env.peerClosed)

/-- `schedule_traffic_keys`: schedule a KeyUpdate when one is due and no retry is outstanding. -/
def scheduleTrafficKeys (config : Config) (conn : Conn) : Conn :=
  if conn.writeRetry || conn.readWantsWrite || inInit conn || !updateDue config conn then
    conn
  else
    { conn with ssl := conn.ssl.keyUpdate }

/-- Close the connection. Its queued output is never written. -/
def close (io : Io) : Io :=
  { io with conn.alive := false }

/-- `do_write`: write at most one record of the queued output. -/
def doWrite (config : Config) (env : Env) (io : Io) : Io :=
  if io.conn.readWantsWrite then
    io
  else
    match io.conn.output with
    | [] => { io with conn.wantWrite := false }
    | payload :: rest =>
        if updateAwaitsSocket config env io then
          { io with conn.wantWrite := true }
        else
          let conn := scheduleTrafficKeys config io.conn
          let (result, ssl, socket) := sslWrite config env payload conn.ssl io.socket
          let io := { io with conn := { conn with ssl }, socket }
          match result with
          | .written =>
              {
                io with
                  conn.output := rest
                  conn.queued := io.conn.queued - 1
                  conn.writeRetry := false
                  conn.wantWrite := !rest.isEmpty
              }
          | .wantWrite => { io with conn.writeRetry := true, conn.wantWrite := true }
          | .failed => close io

/-- `do_read`: read up to `fuel` records, stopping early behind a pending write. The second
component is `more_to_read`. -/
def doRead (config : Config) (env : Env) : Nat → Io → Io × Bool
  | 0, io => (io, hasInput io.conn)
  | fuel + 1, io =>
      if env.saturated then
        (io, hasInput io.conn)
      else
        let (result, ssl, socket) := sslRead config env io.conn.ssl io.socket
        let io := { io with conn.ssl := ssl, socket }
        match result with
        | .failed => (close io, false)
        | .wantWrite =>
            ({ io with conn.wantWrite := true, conn.readWantsWrite := true }, false)
        | .data delivery =>
            let io :=
              {
                io with
                  conn.readWantsWrite := false, delivered := io.delivered ++ [delivery]
              }
            if io.conn.writeRetry then
              (io, hasInput io.conn)
            else
              doRead config env fuel io
        | .wantRead progressed =>
            let io := { io with conn.readWantsWrite := false }
            if !readBlockedByWrite io.conn && progressed && hasInput io.conn then
              doRead config env fuel io
            else
              (io, false)

/-- The fallback in `drive_ready`: fill the input buffer without processing TLS. -/
def prefetch (config : Config) (env : Env) (io : Io) : Io :=
  let (ssl, socket) := refill config io.conn.ssl io.socket
  let io := { io with conn.ssl := ssl, socket }
  if !hasInput io.conn && env.peerClosed then
    close io
  else
    doWrite config env io

/-- `drive_ready`: retry a pending write, read unless that write forbids it, then write. -/
def driveReady (config : Config) (env : Env) (readable : Bool) (io : Io) : Io × Bool :=
  let io := if io.conn.writeRetry then doWrite config env io else io
  let io :=
    if io.conn.alive
        && readBlockedByWrite io.conn
        && !env.saturated
        && readable
        && !hasInput io.conn then
      prefetch config env io
    else
      io
  if !io.conn.alive || readBlockedByWrite io.conn then
    (io, false)
  else
    let (io, more) :=
      if readable || io.conn.readWantsWrite || hasInput io.conn then
        doRead config env config.readsPerPass io
      else
        (io, false)
    if io.conn.alive then
      let io := doWrite config env io
      (
        io,
        more
        || (!io.conn.readWantsWrite && !readBlockedByWrite io.conn && hasInput io.conn)
      )
    else
      (io, false)

/-- `read_interest_withheld`. -/
def readInterestWithheld (env : Env) (conn : Conn) : Bool :=
  env.saturated || conn.readPaused || conn.readWantsWrite

/-- A readable event the loop may act on: buffered input, socket input, or a hang-up. -/
def readableEvent (env : Env) (io : Io) : Bool :=
  (io.conn.pendingRead || !io.socket.inbound.isEmpty || env.peerClosed)
  && !readInterestWithheld env io.conn

/-- A writable event the loop may act on. -/
def writableEvent (config : Config) (env : Env) (io : Io) : Bool :=
  io.conn.wantWrite
  && (pollsWritable config io.socket || env.peerClosed)
  && !(env.saturated && io.conn.readWantsWrite)

/-- `complete_drive`, and the loop's handling of its result. -/
def completeDrive (readable more : Bool) (before : Conn) (io : Io) : Io :=
  {
    io with
      conn.readPaused := readBlockedByWrite io.conn && hasInput io.conn
      conn.pendingRead := (before.pendingRead && !readable) || more
      conn.dirty := false
  }

/--
One worker pass, from `dispatch_connection` to `complete_drive`. Disabled unless the owner has
sent output or an actionable event is pending. A pass is atomic: the peer and the kernel do
not act during it.
-/
def pass (config : Config) (env : Env) (io : Io) : Option Io :=
  let readable := readableEvent env io
  if io.conn.alive && (io.conn.dirty || readable || writableEvent config env io) then
    let (driven, more) := driveReady config env readable io
    some (completeDrive readable more io.conn driven)
  else
    none

/-- `admit_output`: whether the bound, if set, leaves room for `data` in the queued output. -/
def admitsOutput (config : Config) (conn : Conn) (data : List Payload) : Bool :=
  !config.maxQueuedOutput.any (· - conn.queued < data.length)

/--
The owner's `send`. A send which would take the queued output beyond the bound closes the
connection instead of being accepted.
-/
def send (config : Config) (data : List Payload) (conn : Conn) : Option Conn :=
  if conn.alive then
    if admitsOutput config conn data then
      some
        {
          conn with
            output := conn.output ++ data
            queued := conn.queued + data.length
            dirty := true
        }
    else
      some { conn with alive := false }
  else
    none

end Tls.Model
