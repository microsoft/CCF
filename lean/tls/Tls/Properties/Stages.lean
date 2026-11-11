-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import Tls.Model

@[expose] public section

/-!
A worker pass which is not atomic.

The model's `pass` lets nothing else happen while it runs. A real pass shares its socket with
the peer and the kernel, which act while it runs. `interleavedPass` runs the same stages as
`driveReady` and lets them act before each one. It is the step which trace validation replays.
-/

namespace Tls.Properties

open Tls.Model

/-- The stages of `driveReady`, in order. -/
inductive Stage where
  /-- Retry a pending write. -/
  | retry
  /-- Behind a write which forbids reads, fill the input buffer and try that write again. -/
  | prefetch
  /-- Read. -/
  | read
  /-- Write. -/
  | write
deriving DecidableEq, Repr

/-- What surrounds a pass which is not atomic. -/
structure Interleaving where
  /-- What each stage observes of inbound admission and of the peer. -/
  env : Stage → Env
  /-- What the peer and the kernel do to the socket before each stage. -/
  socket : Stage → Socket → Socket
  /--
  How many times the read stage may call `SSL_read`. The engine limits a pass by the bytes it
  reads and by its attempts at control messages, neither of which the model has.
  -/
  reads : Nat

/-- The interleaving of an atomic pass: one environment, a socket which only the pass changes,
and the model's own read allowance. -/
def Interleaving.atomic (config : Config) (env : Env) : Interleaving :=
  { env := fun _ => env, socket := fun _ socket => socket, reads := config.readsPerPass }

/-- Let the peer and the kernel act before a stage. -/
def Interleaving.enter (interleaving : Interleaving) (stage : Stage) (io : Io) : Io :=
  { io with socket := interleaving.socket stage io.socket }

/-- `driveReady`, with the peer and the kernel acting before each of its stages. -/
def interleavedDrive (config : Config) (interleaving : Interleaving) (readable : Bool)
    (io : Io)
    : Io × Bool :=
  let io := retryStage config (interleaving.env .retry) (interleaving.enter .retry io)
  let io :=
    prefetchStage config (interleaving.env .prefetch) readable
      (interleaving.enter .prefetch io)
  if !io.conn.alive || readBlockedByWrite io.conn then
    (io, false)
  else
    let read :=
      readStage
        { config with readsPerPass := interleaving.reads }
        (interleaving.env .read)
        readable
        (interleaving.enter .read io)
    writeStage config (interleaving.env .write) (interleaving.enter .write read.1, read.2)

/--
A worker pass which is not atomic. `readable` is whatever the loop dispatched the pass with:
unlike `pass`, nothing here says that the loop only runs a pass which has something to do.
-/
def interleavedPass (config : Config) (interleaving : Interleaving) (readable : Bool)
    (io : Io)
    : Io :=
  let driven := interleavedDrive config interleaving readable io
  completeDrive readable driven.2 io.conn driven.1

/--
The connections an engine can hold when its passes are not atomic, whatever its peer and its
owner do. Trace validation replays each connection as such a sequence of steps.
-/
inductive Replayable (config : Config) : Conn → Prop where
  /-- A connection starts established, with unused keys and nothing buffered. -/
  | initial : Replayable config .initial
  /-- The owner sends output. -/
  | send {conn next : Conn} (data : List Payload) (reached : Replayable config conn)
    (sent : Model.send config data conn = some next)
    : Replayable config next
  /-- The engine closes the connection without a pass. -/
  | abort {conn : Conn} (reached : Replayable config conn)
    : Replayable config { conn with alive := false }
  /-- A worker pass over an open connection, on any socket and with any interleaving. -/
  | pass {conn : Conn} (interleaving : Interleaving) (readable : Bool) (socket : Socket)
    (reached : Replayable config conn) (alive : conn.alive = true)
    : Replayable config
        (interleavedPass config interleaving readable { conn, socket }).conn

end Tls.Properties
