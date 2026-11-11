-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import Std

@[expose] public section

/-!
State of one end of a TLS 1.3 connection with the traffic-key policy enabled, as held by
`OpenSSLConnectionEngine` (`src/tls/openssl_connection_engine.h`) and its `SSL` object.

The unit of data is one TLS record: a `Payload` is the plaintext of one application record,
socket buffers hold whole records, and every capacity is a number of records.
-/

namespace Tls.Model

/-- The plaintext of one application record. -/
abbrev Payload := Nat

/-- An encrypted TLS 1.3 record on the wire. -/
inductive Record where
  /-- Application data. -/
  | app (payload : Payload)
  /-- A KeyUpdate message. Engines only send `requested := false`; other peers may request. -/
  | keyUpdate (requested : Bool)
deriving DecidableEq, Repr

/-- Engine constants and the kernel's socket behaviour, in records. -/
structure Config where
  /-- `TrafficKeyPolicy::record_budget`: records protected under one key in one direction. -/
  recordBudget : Nat
  /-- Records a kernel socket buffer holds. A write is accepted while it holds fewer. -/
  socketCapacity : Nat
  /-- Free records a socket buffer needs before it polls writable. -/
  writableThreshold : Nat
  /-- Records the input-buffer BIO holds (64 KiB in the engine). -/
  inputBuffer : Nat
  /-- Records one worker pass reads (`max_read_per_event` and `max_pending_retries`). -/
  readsPerPass : Nat
  /-- `Config::max_queued_output`: the opt-in bound on accepted and unwritten output. -/
  maxQueuedOutput : Option Nat
deriving DecidableEq, Repr

/-- The engine's constants: it rejects a budget below two, and its buffers are not empty. -/
def Config.Engine (config : Config) : Prop :=
  2 ≤ config.recordBudget ∧ 0 < config.inputBuffer ∧ 0 < config.readsPerPass

/--
The kernel assumptions which progress relies on: an empty socket polls writable, and a socket
which polls writable accepts a record. Nothing relates `writableThreshold` to `inputBuffer`:
draining a full input buffer from a full socket need not make that socket poll writable.
-/
def Config.Kernel (config : Config) : Prop :=
  0 < config.writableThreshold ∧ config.writableThreshold ≤ config.socketCapacity

/-- What an `SSL_write` which returned `SSL_ERROR_WANT_WRITE` has left unflushed. -/
inductive Pending where
  /-- No write is pending. -/
  | none
  /-- A KeyUpdate record is constructed but not on the socket: the connection is in init. -/
  | update
  /-- An application record is constructed but not on the socket. -/
  | app (payload : Payload)
deriving DecidableEq, Repr

/-- The `SSL` object, with its input-buffer BIO and the per-key counts of `TrafficKeys`. -/
structure Ssl where
  /-- Records protected under the current sending key. -/
  sent : Nat := 0
  /-- Records decrypted under the current receiving key. -/
  received : Nat := 0
  /-- The record of a started write which the socket has not accepted. -/
  pending : Pending := .none
  /--
  `SSL_get_key_update_type() != SSL_KEY_UPDATE_NONE`: a KeyUpdate is to be sent, either
  scheduled by `SSL_key_update` or owed in response to a peer's request.
  -/
  updateQueued : Bool := false
  /-- Ciphertext in the input-buffer BIO: read from the socket but not processed. -/
  input : List Record := []
  /-- Set by an operation which OpenSSL's contract forbids; never cleared. -/
  misused : Bool := false
deriving DecidableEq, Repr

/-- One end of a kernel socket: a buffer of whole records in each direction, oldest first. -/
structure Socket where
  /-- The receive buffer: records the peer has written and this end has not read. -/
  inbound : List Record := []
  /-- The send buffer: records this end has written and the peer has not read. -/
  outbound : List Record := []
deriving DecidableEq, Repr

/-- One end of a connection: the engine's `Conn` and its `SSL` object. -/
structure Conn where
  /-- The OpenSSL state. -/
  ssl : Ssl := {}
  /-- Plaintext accepted from the owner and not yet written, oldest first. -/
  output : List Payload := []
  /-- `queued_output`: the engine's count of `output`, charged against the bound. -/
  queued : Nat := 0
  /-- `write_retry_length != 0`: the last `SSL_write` must be retried. -/
  writeRetry : Bool := false
  /-- `want_write`: progress needs the socket to poll writable. -/
  wantWrite : Bool := false
  /-- `read_wants_write`: an `SSL_read` is blocked writing a KeyUpdate response. -/
  readWantsWrite : Bool := false
  /-- `read_paused`: read interest is withheld behind a started write. -/
  readPaused : Bool := false
  /-- A readable event is pending because input is buffered where polling cannot see it. -/
  pendingRead : Bool := false
  /-- A pass is due because the owner sent output since the last one. -/
  dirty : Bool := false
  /-- Cleared when the engine closes the connection. -/
  alive : Bool := true
deriving DecidableEq, Repr

/-- Plaintext handed to the owner's `OnData` callback. -/
structure Delivery where
  /-- The delivered plaintext. -/
  payload : Payload
  /-- The position of its record among those received under the same key, from one. -/
  keyRecord : Nat
deriving DecidableEq, Repr

/-- What a worker pass acts on: its connection, its socket, and what it delivers. -/
structure Io where
  /-- The connection being driven. -/
  conn : Conn
  /-- The connection's socket. -/
  socket : Socket
  /-- Plaintext delivered so far by this pass. -/
  delivered : List Delivery := []
deriving DecidableEq, Repr

/-- What a pass observes of its environment. Both are fixed for the duration of a pass. -/
structure Env where
  /-- Node-wide inbound admission is saturated (`InboundAdmission::saturated`). -/
  saturated : Bool
  /-- The peer has closed its end of the connection. -/
  peerClosed : Bool
deriving DecidableEq, Repr

end Tls.Model
