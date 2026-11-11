-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import Tls.Model

@[expose] public section

/-!
A measure of the work which two engines have left, used to state that worker passes cannot
continue for ever without new output from an owner.
-/

namespace Tls.Properties

open Tls.Model

/--
The work one end has left, as a bound on the passes it can cause.

A queued record costs six: its sender may put a KeyUpdate and then the record on the socket,
and each record on a socket costs two (see `work`). A record not yet started costs three more
than one whose write is pending. A buffered input record costs one. The remaining terms are
wake-ups which a pass consumes without moving a record, and the pass which closes the end.
-/
def endWork (conn : Conn) : Nat :=
  6 * conn.output.length
  + (if conn.ssl.pending.isApp then 0 else 3)
  + conn.ssl.input.length
  + (if conn.dirty then 2 else 0)
  + (if conn.wantWrite && conn.output.isEmpty then 1 else 0)
  + (if conn.pendingRead && conn.ssl.input.isEmpty then 1 else 0)
  + (if conn.alive then 1 else 0)

/-- The work two engines have left. A record on a socket is buffered and then processed. -/
def work (state : Pair.State) : Nat :=
  endWork state.left
  + endWork state.right
  + 2 * state.toRight.length
  + 2 * state.toLeft.length

/-- The work an action adds: what `endWork` charges for the output an owner sends. -/
def addedWork : Pair.Action → Nat
  | .send _ data => 6 * data.length + 2
  | _ => 0

/-- Whether an action is a worker pass. -/
def isPass : Pair.Action → Bool
  | .pass _ => true
  | _ => false

end Tls.Properties
