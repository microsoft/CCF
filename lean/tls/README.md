# Lean model of the TLS connection engine

This package contains an executable Lean model of one connection of `OpenSSLConnectionEngine` (`src/tls/openssl_connection_engine.h`) with the opt-in traffic-key policy (`src/tls/traffic_keys.h`) and the opt-in queued output bound enabled, the properties stated about it, machine-checked proofs of those properties, and a replayer that checks traces recorded by the engine's C++ unit tests against the model.
It does not change CCF behavior or introduce a normal-build dependency.
The engine's behaviour is described in the "Opt-in traffic-key policy" and "Opt-in queued output bound" sections of [`doc/architecture/tls_internals.rst`](../../doc/architecture/tls_internals.rst).
[The Lean module guide](../AGENT.md) describes the module layout, which this package shares with the other models.

## Contents

| Purpose                                                    | Location                                |
| ---------------------------------------------------------- | --------------------------------------- |
| Proved theorems and their witnesses                        | `Tls/Properties.lean`                   |
| Records, configuration, connection and socket state        | `Tls/Model/Types.lean`                  |
| The kernel socket and the OpenSSL behaviour relied on      | `Tls/Model/OpenSsl.lean`                |
| One worker pass of the engine, and the owner's `send`      | `Tls/Model/Engine.lean`                 |
| The two compositions, `node` and `pair`                    | `Tls/Model.lean`                        |
| The work measure, streams, and passes which are not atomic | `Tls/Properties/`                       |
| Proof implementations                                      | `Tls/Proofs/`                           |
| Regression scenarios evaluated by the kernel at build time | `Tls/Tests/Scenarios.lean`              |
| Replay of recorded C++ traces                              | `Tls/TraceValidation.lean`              |
| Strict decoding of those traces                            | `Tls/TraceValidation/`                  |
| Replayer executable, and valid and invalid trace fixtures  | `replayer/`                             |
| Shared transition-system and execution definitions         | [`../common/CCF/`](../common/README.md) |

Human review covers the model, the full theorem statements in `Properties.lean`, the definitions they use, and their one-line references to proof implementations.
The proof implementations under `Proofs/` are verified by the build and `lake check` and are marked `linguist-generated` in `.gitattributes`.

## Model

The unit of data is one TLS record.
A `Payload` is the plaintext of one application record, socket buffers hold whole records, and every capacity in `Config` is a number of records.

`Tls/Model/OpenSsl.lean` models the kernel socket and OpenSSL, on an `Ssl` value and a `Socket`.
`sslWrite` and `sslRead` follow the contract which the engine depends on: a write which returned `SSL_ERROR_WANT_WRITE` must be retried with the same data, a queued KeyUpdate is sent by the next write before that write's application record, the connection is in init until that record is flushed, and a peer's `KeyUpdate(update_requested)` queues a response.
A read which meets a KeyUpdate record while a response is queued sends that response and returns before it processes the message, holding the record (`Ssl.held`) until the next read.
Three operations are forbidden by that contract: retrying a write with other data, `SSL_key_update` with a write pending, and `SSL_read` with an application write pending and a KeyUpdate queued.
The model does not reject them.
It sets `Ssl.misused`, which is never cleared, so that the absence of such operations is a property of the engine and not of the model's construction.

`Tls/Model/Engine.lean` models one worker pass, from `dispatch_connection` to `complete_drive`.
Each definition is named after the C++ function it follows: `doWrite`, `doRead`, `driveReady`, `updateAwaitsSocket`, `scheduleTrafficKeys`, `readBlockedByWrite`, `readInterestWithheld` and `completeDrive`.
`driveReady` is the composition of four stages: retry a pending write, prefetch input behind a write which forbids reads, read, and write.
`pass` is disabled unless the owner has sent output or an actionable event is pending, as the loop would not schedule it.

`Tls/Model.lean` composes the engine in two ways.

- `node` is one engine with any number of connections.
  Each connection faces an unconstrained peer, which may write any record, read, or close at any time, and an unconstrained owner.
  The connections share only node-wide inbound admission, which may change at any time.
- `pair` is two engines facing each other across the two socket buffers of one connection.
  Each end has its own inbound admission, which may change at any time, and either end may be closed at any time.

### Assumptions

`Config.Engine` states what the engine enforces of its own constants: a record budget of at least two, and a non-empty input buffer and read allowance.
Every theorem assumes it.

`Config.Kernel` states the kernel behaviour which progress relies on: a socket which polls writable accepts a record, and an empty socket polls writable.
Only the progress and termination theorems assume it.
Nothing relates `writableThreshold` to `inputBuffer`, so the model does not assume that draining an input buffer makes the peer's socket poll writable.

Inbound admission is an environment assumption.
The model lets it saturate and reopen arbitrarily, and does not model `InboundAdmission` itself.

The OpenSSL behaviour in `Tls/Model/OpenSsl.lean` is also an assumption.
It is taken from the engine's comments and documentation and from the description of OpenSSL 3.3 and 3.5 given with the engine change.
[Trace validation](#trace-validation) checks it against the OpenSSL which the unit tests link, for the executions those tests produce, and one of its steps was corrected as a result.
One part of it is still not exercised by anything: that `SSL_read` fails fatally when it meets a post-handshake message with an application write pending and a response owed.
That was inferred from the OpenSSL sources; the traces show the engine never calling `SSL_read` in that state, so they neither confirm nor contradict it.
Every theorem is about the engine running against this modelled OpenSSL.

### Abstractions

- Records are atomic.
  A socket accepts or refuses a whole record, so partial record writes, partial records in the input buffer, and the difference between ciphertext buffered in the BIO and input already processed by OpenSSL are not modelled.
- A pass is atomic, and socket buffers take effect at once.
  The peer and the kernel do not act during a pass, and space freed by one end is visible to the other immediately.
  Passes of the two ends of a `pair` therefore interleave but never overlap.
  Real passes are not atomic: recorded traces show a write refused and then accepted within one pass.
  `interleavedPass`, in `Tls/Properties/Stages.lean`, lets the peer and the kernel act between the stages of a pass; the safety theorems are also proved for it, and it is what trace validation replays.
  The progress theorems are proved for atomic passes only.
- Poll readiness is observed as it is, with no delay and no stale events.
- Connections start established, with nothing queued.
  The handshake, the `on_handshake` hook and establishment cancellation are not modelled.
  Nor is output sent while a client connection is being established, which the engine charges to the same bound from `begin_establishing` and keeps charged once the connection is adopted.
- The cross-thread output queue, the loop's pending commands and the output buffer are one list, `Conn.output`.
  The queued output count is decremented as each record is written, where the engine reports it as the pass completes.
  The engine's count can therefore be higher than the model's, and the engine can close a connection on a send which the model accepts.
- A send beyond the queued output bound closes the connection at once, where the engine closes it on its next pass and discards sends made in between.
  A send to a closed connection is disabled in the model, where the engine discards it.
- One allowance, `readsPerPass`, stands for both the per-pass byte cap and the bounded further attempts for control messages.
  It counts calls to `SSL_read`, where the engine's limits are in bytes and attempts.
- The engine's counter of records sent under a key, `TrafficKeys::sent`, resets when OpenSSL constructs a KeyUpdate, which recorded traces show to be before that record is flushed.
  The model's `Ssl.sent` counts the KeyUpdate under the old key until it is flushed.
  The engine therefore would not count a record which OpenSSL wrote under the old key between the two; none has been observed.
- Memory is counted in records: the input buffer and the queued output.
  OpenSSL's own record buffers and the plaintext handed to the owner are not counted.

### Out of scope

- Connections without the traffic-key policy, including RPC, and plaintext connections.
- Graceful close with flush-before-close.
  The model has only closes which do not flush: shutdown, idle expiry, a failed read or write, and the queued output bound.
- The `close_notify` alert sent on close.
  It is a record under the sending key which the model does not count.
  A reading of `SSL_shutdown` and `ssl3_send_alert` in OpenSSL 3.3 and 3.5, made for the engine change and not tested, found that no alert is written while the connection is in init or a write is pending.
  In every other state the invariant `Coherent.reserve` in `Tls/Proofs/Local.lean` leaves one record under the sending key.
  Together these indicate that `close_notify` stays within the budget, but no theorem states it.
- TCP resets, and loss of data which a closed end had not read.
- Idle timeouts, handshake deadlines, engine start and stop, and the threading of the loop and its workers.

## Properties

`Tls/Properties.lean` states each claim as a proved theorem in `Tls.Properties`, whose one-line proof refers to an implementation in `Tls/Proofs/`.
No `sorry`, custom axioms, unsafe declarations, or external solver are used; `lake check` accepts only Lean's standard `propext`, `Quot.sound` and `Classical.choice`.
Each claim is followed by a `_witness` lemma showing that its premises can hold, or that its bound is attained, on a concrete execution which the kernel evaluates.

| Theorem                            | System             | Assumes        | Established scope                                                                                        |
| ---------------------------------- | ------------------ | -------------- | -------------------------------------------------------------------------------------------------------- |
| `key_budget_respected`             | `node`             | Engine         | Per-key record counts stay within the budget, sending always and receiving while open                    |
| `plaintext_within_budget`          | `node`             | Engine         | No pass delivers plaintext from a record beyond the receive budget                                       |
| `openssl_contract_respected`       | `node`             | Engine         | No forbidden OpenSSL operation is ever performed                                                         |
| `memory_bounded`                   | `node`             | Engine         | Buffered input never exceeds the input buffer, and queued output never exceeds the bound when one is set |
| `connections_isolated`             | `node`             | none           | An event on one connection changes neither admission nor any other connection                            |
| `engines_safe`                     | `pair`             | Engine         | The four safety properties above, for both ends of two engines                                           |
| `stream_integrity`                 | `pair`             | Engine         | What one owner has been handed is a prefix of what the other owner had accepted                          |
| `deadlock_free`                    | `pair`             | none           | The shared `DeadlockFree`, which holds trivially here                                                    |
| `progress_enabled`                 | `pair`             | Engine, Kernel | With both ends open, anything in transit to an end which admits input enables a pass which consumes work |
| `pass_consumes_work`               | `pair`             | Engine, Kernel | Every pass strictly reduces the work measure                                                             |
| `passes_bounded`                   | `pair`             | Engine, Kernel | The passes of an execution are bounded by the work at its start and the work its sends add               |
| `quiescent_delivered`              | `pair`             | Engine, Kernel | With both ends open, no pass enabled and input admitted, everything accepted has been delivered          |
| `atomic_pass_interleaved`          | one pass           | none           | An atomic pass is an interleaved pass in which nothing else acts                                         |
| `replayed_connections_safe`        | interleaved passes | Engine         | Key budgets, OpenSSL contract and memory bounds hold of every connection reached by interleaved passes   |
| `replayed_plaintext_within_budget` | interleaved passes | Engine         | No interleaved pass delivers plaintext from a record beyond the receive budget                           |

The `node` theorems hold against any peer, including one which requests KeyUpdates, sends more records than the budget allows, or never reads.
The last three relate the model to the non-atomic passes which [trace validation](#trace-validation) replays.
The `pair` theorems are about two engines, which never request KeyUpdates.

### What the progress results do and do not claim

`work`, in `Tls/Properties/Progress.lean`, bounds the passes which the records in flight can still cause.
Together, `progress_enabled`, `pass_consumes_work`, `passes_bounded` and `quiescent_delivered` give a terminating progress measure and enabled progress.
Under a scheduler which runs enabled passes, a receiver whose admission reopens, and owners which stop sending, they imply that everything accepted is delivered unless an end closes.
That last implication is an argument about these theorems.
It is not itself a Lean theorem: the package states no property of infinite executions and no fairness assumption.

The following are not claimed.

- Anything about progress without `Config.Kernel`.
  `key_budget_respected_witness` uses a kernel which reports a full socket as writable, and reaches an engine holding a KeyUpdate which its socket did not take.
- Progress against a peer which is not an engine.
  A peer which requests a KeyUpdate and does not read leaves the engine waiting with its reads withheld; `Tests/Scenarios.lean` keeps that execution.
  The connection stays open and within its memory bounds.
- Progress while the receiver's admission stays saturated, or after either end closes.
- That the deferral of a write beginning with a KeyUpdate is necessary.
  The proofs show that with it, two engines are never left in init at the end of a pass.
  The model's atomic passes and immediate sockets cannot show what two engines without it would do.
- `deadlock_free` holds only because inbound admission may always change; `progress_enabled` is the useful statement.
- `connections_isolated` is close to the model's construction, since `node` gives connections no shared state other than admission.
  It would not detect sharing in the engine which the model does not represent, such as the cross-thread queue, the loop thread or the worker pool.

### What the model shows about the engine

Between two engines under `Config.Kernel`, a write which begins with a KeyUpdate is started only on a socket which then accepts it.
Neither end is therefore in init, owes a response, or has a read blocked on a write when a pass ends.
This is the invariant `Settled` in `Tls/Proofs/Pass.lean`, and it is why the reciprocal case makes progress: both ends keep reading.
`progress_enabled_witness` reaches that case, with a KeyUpdate due, output queued and a full socket at both ends.

It follows that the engine's fallback, which prefetches input behind a started write and sets `read_paused`, is never used between two engines in this model (`prefetchStage_quiet` in the same file).
It is used against a peer which requests KeyUpdates.
Whether it can be needed between two real engines depends on behaviour which the model abstracts: partial record writes, and space freed by one end not being visible to the other at once.

## Tests

`Tls/Tests/Scenarios.lean` holds executions which the kernel evaluates when the package is built, so a change to the model which alters them fails the build.

- The reciprocal case, run until no pass is enabled, delivering both directions in full across a KeyUpdate each way.
- The same attempt to start a KeyUpdate on a full socket under the modelled kernel, where the pass is not scheduled, and under a kernel which reports a full socket as writable, where the KeyUpdate is started and blocks reads.
- A hand-written state in which both ends have started a KeyUpdate and neither can proceed, with a proof that two engines cannot reach it.
- The queued output bound closing a connection whose peer does not read, without writing its output.
- A peer which requests a KeyUpdate and does not read.
- Each of the three forbidden OpenSSL operations setting `misused`.

## Validation

Run the following commands from this directory:

```console
lake build --wfail --fail-fast
lake exe check-imports
lake build ccf_common/+CCF
lake lint
lake check --inadvisably-no-sandbox
./replayer/check-fixtures.sh
../../scripts/lean-format-checks.sh tls
```

These are the same checks as the [disaster-recovery validation](../disaster-recovery/README.md#validation), which describes each of them and the package's linter options.

## Trace validation

`tls-replay` replays traces recorded from the C++ engine through the model, one connection at a time.

### Capture

A build configured with `-DCCF_TLS_TRACING=ON` compiles hooks into `src/tls/openssl_connection_engine.h` and `src/tls/traffic_keys.h`.
While the `openssl_server_test` unit test runs with `CCF_TLS_TRACE_FILE` set to an absolute path, they write one NDJSON record for each worker pass over an established connection which has a traffic-key policy.
The hooks only read connection state, and without the option they compile to nothing, as `CCF_KV_TRACING` does for the KV store.
`tests/tls_trace_validation.py` runs the test several times, because the engine's passes depend on timing, and fails unless the traces between them reach the states the model is about, such as an unflushed KeyUpdate, a response owed behind a pending write, and a record beyond the receive budget.

A `pass` record carries what the pass was dispatched with (`readable`, `pending_before`, `queued_before`), the connection state when it ended, and `ops`, an ordered list of what OpenSSL and the engine did:

| Token       | Meaning                                                                                          |
| ----------- | ------------------------------------------------------------------------------------------------ |
| `r<type>`   | OpenSSL decrypted a record with this inner content type (23 application, 22 handshake, 21 alert) |
| `rk<0\|1>`  | OpenSSL processed a peer's KeyUpdate message, which did or did not request an update             |
| `w<type>`   | OpenSSL encrypted a record with this inner content type                                          |
| `wk<0\|1>`  | OpenSSL constructed a KeyUpdate message                                                          |
| `d<bytes>`  | `SSL_read` returned plaintext, which the engine handed to its owner                              |
| `s<bytes>`  | `SSL_write` returned having written this much plaintext                                          |
| `e<error>`  | `SSL_read` failed with this `SSL_get_error` result                                               |
| `f<error>`  | `SSL_write` failed with this `SSL_get_error` result                                              |
| `x<reason>` | The reason OpenSSL queued for the protocol error just reported                                   |
| `u0`, `p0`  | `SSL_key_update` failed; the input ended while the input buffer was being filled                 |

### How a trace maps onto the model

- **Each connection is replayed on its own**, as a connection of `node` whose peer is unconstrained.
  This covers a connection to another engine and one to a raw OpenSSL peer alike.
  Nothing compares what one engine sent with what the other received.
- **One engine pass is one `interleavedPass` of the model.**
  It runs the stages of `driveReady` and lets the peer and the kernel change the socket before each.
- **The replayer chooses the socket.**
  The trace does not record what the kernel did, so for each pass the replayer tries the few behaviours a pass can observe: how many records the socket accepts from each stage, from which stage the peer appears closed, and whether inbound admission is saturated.
  The pass is accepted if one of them leaves the model's connection in the state the engine reported.
- **Each connection is tried under two kinds of socket**: one which polls writable exactly when it accepts a record, as `Config.Kernel` requires, and one which always polls writable and may then refuse a KeyUpdate.
  Tests which gate writes artificially need the second, and the replayer reports how many connections did.
- **Records are reconstructed by looking ahead.**
  The engine cuts its queued output into records as it writes them, and OpenSSL reports a peer's KeyUpdate message after the record which carried it, sometimes in a later pass.
  An application record's payload is the size of its plaintext.
- **Input is offered when the engine fetched it.**
  A pass which began with input pending read records the engine had already taken off the socket; the replayer offers those at the last earlier pass which began with none pending, and allows each pass as many `SSL_read` calls as its tokens show it made.

After each pass the replayer compares, between the model and the engine: whether the connection survived; `TrafficKeys::sent` and `received`; `SSL_in_init`; whether a KeyUpdate is scheduled or owed; whether a write must be retried; `want_write`; `read_wants_write`; whether output remains queued; how many application records were written; how many records were decrypted; and the size of each piece of plaintext delivered.
Of a pass which closed its connection it compares the deliveries, the writes, and the reason, which must be the receive budget or the peer going away.
The engine's `sent` is expected to be zero while the model has a KeyUpdate constructed and unflushed, for the reason given under [Abstractions](#abstractions).

### What is not checked

- **When passes run.**
  Which events the loop dispatches a pass with, `read_paused`, `more_to_read` and read interest are not compared.
  The progress theorems depend on these, so a passing replay does not support them.
- **The queued output bound.**
  It is in bytes, the model's is in records, and the replayed configuration has none.
- **Where unread input is.**
  The model's view of what is in the input buffer, as opposed to still on the socket, is reconstructed and not observed, and partial records are not represented.
- **Inbound admission.**
  The replayer chooses whether it is saturated; the trace does not show that the engine did not read while it was.
- **The kernel assumptions.**
  The trace does not record what `poll` returned.
- **What was written, record by record.**
  The `w` tokens are not compared; a missing or extra record shows only through the counters and flags.
  Plaintext is compared by size, not content.
- **The handshake, connections without a policy, and graceful close**, which the model does not have.
  A connection closed once its output was flushed is treated as closed after that pass.
- **Anything the tests do not do.**
  A trace shows only the executions which were recorded.

### What a passing replay establishes

For every recorded pass, the connection state the engine reported is the state of a model connection after one interleaved pass from the state before it, under some behaviour of the socket.
So on those executions the engine's rules for reading and writing, and OpenSSL's behaviour as the engine observed it, are behaviours the model allows.
`replayed_connections_safe` and `replayed_plaintext_within_budget` then apply to every model state the replay passes through.

It does not establish that the model allows only what the engine does, that the engine behaves this way on executions which were not recorded, or anything about progress.

### What the first traces showed

- The model's `sslRead` sent an owed response and processed the message which prompted it in one step.
  The engine can end a pass between the two, when its bound on further attempts for control messages is reached, so the model had no state for the engine to be in.
  `sslRead` now returns between them.
  Every theorem was re-proved.
- The engine's `sent` counter resets earlier than the model's, as described under [Abstractions](#abstractions).
- With an application write pending and a response owed, the engine did not call `SSL_read` until the write completed, and OpenSSL sent the response before the next application record, as the model has it.

### Running it

```console
cmake -S ../.. -B ../../build-tls-trace -GNinja -DCMAKE_BUILD_TYPE=Debug -DCCF_TLS_TRACING=ON
cmake --build ../../build-tls-trace --target openssl_server_test
lake build --wfail tls-replay
python3 ../../tests/tls_trace_validation.py \
  --binary ../../build-tls-trace/openssl_server_test \
  --checker .lake/build/bin/tls-replay --output ../../build-tls-trace/tls-traces
```

`tls-replay [--json] <trace.ndjson>` exits with 0 if the trace is accepted, 1 if the model rejects it, 2 if it is malformed, and 3 if it shows something the model does not cover.
Configuring with `-DCCF_TLS_TRACE_CHECKER=<path to tls-replay>` as well registers the same check as the `tls_trace_validation` test.
`replayer/fixtures/` holds traces captured from individual test cases, which must be accepted, and diffs against them which must be rejected with the status their name begins with.
