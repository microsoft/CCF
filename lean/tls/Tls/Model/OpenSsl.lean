-- Copyright (c) Microsoft Corporation. All rights reserved.
-- Licensed under the Apache 2.0 License.

module

public import Tls.Model.Types

@[expose] public section

/-!
The kernel socket and the parts of OpenSSL's TLS 1.3 record and KeyUpdate behaviour which the
engine depends on. They are assumptions: they follow the engine's comments and documentation,
and are not checked against OpenSSL here. `SSL_MODE_AUTO_RETRY` is cleared, so `sslRead`
returns after each post-handshake message.
-/

namespace Tls.Model

/-- The kernel accepts a record whenever the send buffer is not completely full. -/
def accepts (config : Config) (socket : Socket) : Bool :=
  socket.outbound.length < config.socketCapacity

/-- A socket polls writable only once `writableThreshold` records of its send buffer are free. -/
def pollsWritable (config : Config) (socket : Socket) : Bool :=
  socket.outbound.length + config.writableThreshold ≤ config.socketCapacity

/-- Whether an application record is pending. -/
def Pending.isApp : Pending → Bool
  | .app _ => true
  | _ => false

/-- The result of `SSL_write`. -/
inductive WriteResult where
  /-- The application record is on the socket. -/
  | written
  /-- `SSL_ERROR_WANT_WRITE`: the same write must be retried before any other. -/
  | wantWrite
  /-- A fatal error: the peer has gone away. -/
  | failed
deriving DecidableEq, Repr

/-- The result of `SSL_read`. -/
inductive ReadResult where
  /-- One application record's plaintext. -/
  | data (delivery : Delivery)
  /-- `SSL_ERROR_WANT_READ`, after consuming a post-handshake message if `progressed`. -/
  | wantRead (progressed : Bool)
  /-- `SSL_ERROR_WANT_WRITE`: a KeyUpdate must reach the socket before reading resumes. -/
  | wantWrite
  /-- End of input, a fatal error, or a record beyond the receive budget. -/
  | failed
deriving DecidableEq, Repr

/-- `SSL_key_update(SSL_KEY_UPDATE_NOT_REQUESTED)`. Illegal while a write is pending or the
connection is in init. -/
def Ssl.keyUpdate (ssl : Ssl) : Ssl :=
  if ssl.pending = .none then
    { ssl with updateQueued := true }
  else
    { ssl with misused := true }

/-- On entering handshake processing with no write pending, a queued KeyUpdate is constructed.
It is the last record under the old sending key, and the connection is in init until it is
flushed. -/
def Ssl.startUpdate (ssl : Ssl) : Ssl :=
  if ssl.updateQueued ∧ ssl.pending = .none then
    { ssl with sent := ssl.sent + 1, updateQueued := false, pending := .update }
  else
    ssl

/-- Flush a constructed KeyUpdate if the socket accepts it. The new sending key starts. -/
def flushUpdate (config : Config) (ssl : Ssl) (socket : Socket) : Ssl × Socket :=
  if ssl.pending = .update ∧ accepts config socket then
    (
      { ssl with pending := .none, sent := 0 },
      { socket with outbound := socket.outbound ++ [.keyUpdate false] }
    )
  else
    (ssl, socket)

/-- The input-buffer BIO, when empty, takes what it can hold from the socket. -/
def refill (config : Config) (ssl : Ssl) (socket : Socket) : Ssl × Socket :=
  if ssl.input = [] then
    (
      { ssl with input := socket.inbound.take config.inputBuffer },
      { socket with inbound := socket.inbound.drop config.inputBuffer }
    )
  else
    (ssl, socket)

/--
`SSL_write` of one record's plaintext. A pending application record must be retried with the
same data. Otherwise a queued KeyUpdate is sent first, and `payload` is protected only once
that record is on the socket.
-/
def sslWrite (config : Config) (env : Env) (payload : Payload) (ssl : Ssl)
    (socket : Socket)
    : WriteResult × Ssl × Socket :=
  if env.peerClosed then
    (.failed, ssl, socket)
  else
    match ssl.pending with
    | .app pendingPayload =>
        let ssl := if pendingPayload = payload then ssl else { ssl with misused := true }
        if accepts config socket then
          (
            .written,
            { ssl with pending := .none },
            { socket with outbound := socket.outbound ++ [.app pendingPayload] }
          )
        else
          (.wantWrite, ssl, socket)
    | _ =>
        let (ssl, socket) := flushUpdate config ssl.startUpdate socket
        if ssl.pending = .update then
          (.wantWrite, ssl, socket)
        else
          let ssl := { ssl with sent := ssl.sent + 1 }
          if accepts config socket then
            (.written, ssl, { socket with outbound := socket.outbound ++ [.app payload] })
          else
            (.wantWrite, { ssl with pending := .app payload }, socket)

/--
`SSL_read` of at most one record. Illegal while an application write is pending and a
KeyUpdate is queued: meeting a post-handshake message would then start the queued KeyUpdate
inside the pending write, which OpenSSL fails fatally.

An unflushed KeyUpdate goes first, and a queued one is sent before another post-handshake
message is processed. A record beyond the receive budget fails without yielding plaintext.
The record which OpenSSL holds while it sends a response is left at the head of the input.
-/
def sslRead (config : Config) (env : Env) (ssl : Ssl) (socket : Socket)
    : ReadResult × Ssl × Socket :=
  let ssl :=
    if ssl.updateQueued ∧ ssl.pending.isApp then { ssl with misused := true } else ssl
  let (ssl, socket) := flushUpdate config ssl socket
  if ssl.pending = .update then
    (.wantWrite, ssl, socket)
  else
    let (ssl, socket) := refill config ssl socket
    match ssl.input with
    | [] => (if env.peerClosed then .failed else .wantRead false, ssl, socket)
    | record :: rest =>
        let received := ssl.received + 1
        if config.recordBudget < received then
          (.failed, { ssl with received }, socket)
        else
          match record with
          | .app payload =>
              (
                .data { payload, keyRecord := received },
                { ssl with input := rest, received },
                socket
              )
          | .keyUpdate requested =>
              if ssl.updateQueued ∧ ssl.pending.isApp then
                (.failed, ssl, socket)
              else
                let (ssl, socket) := flushUpdate config ssl.startUpdate socket
                if ssl.pending = .update then
                  (.wantWrite, ssl, socket)
                else
                  (
                    .wantRead true,
                    { ssl with input := rest, received := 0, updateQueued := requested },
                    socket
                  )

end Tls.Model
