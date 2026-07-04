# Design plan: streaming subscription endpoints (C++, HTTP/1.1, SSE)

Status: **Draft for review** - no implementation yet. This document proposes how
CCF could support application-defined, read-only **subscription endpoints** that
a client connects to once and then receives a continuous stream of committed
entries matching a predefined query, starting from a client-specified `TxID`.

Scope decisions already fixed for this first iteration (see
[Section 13](#13-open-questions-and-decisions) for what is still open):

- **C++ only.** No JavaScript/TypeScript support in phase 1.
- **HTTP/1.1 only.** HTTP/2 is explicitly out of scope for this plan.
- **Server-Sent Events (SSE, `text/event-stream`)** as the wire format. Not
  NDJSON, not a binary framing.
- **Client-specified starting `TxID`.** The stream begins at a seqno the client
  chooses (not the beginning of time, and not only "from now").
- **Authorization is checked once, at subscribe time,** with the stream's
  lifetime capped to the credential's expiry in a method-aware way. Detecting
  revocation *during* a stream is out of scope. See
  [Section 10](#10-authentication-and-credential-expiry).

This work is split into **two independent tasks** (see
[Section 3](#3-two-independent-tasks)):

- **Task T (transport):** a reusable HTTP/1.1 chunked streaming response,
  generalising the existing commit-callback "hold the connection and respond
  later" mechanism. Useful on its own, testable without any subscription logic.
- **Task S (subscriptions):** the subscription endpoint, manager, matching, and
  delivery, built on Task T.

---

## 1. Goal

Allow applications to declare endpoints that a client can connect to in order to
**subscribe to a query** and then **receive an update every time a newly
committed transaction produces data matching that query**, beginning from a
`TxID` the client specifies in the initial request.

Hard constraints:

- **Read-only.** Serving a subscription must never open a writing `ccf::kv::Tx`,
  never append to the ledger, and never require write access. It only observes
  already-committed state.
- **Committed entries only.** Like historical queries, a subscriber only ever
  observes transactions that consensus has committed, so nothing delivered can
  later be rolled back (see [Section 9](#9-consistency-elections-rollback-and-forwarding)).
- **Client-specified starting point.** The first request names a starting
  `TxID`/seqno; the stream is a forward-only, read-only view from there.
- **Application-defined.** Apps declare these endpoints and supply the query,
  match predicate, and event projection in C++.

Non-goals for phase 1: HTTP/2, JavaScript apps, bidirectional streaming,
server-side durable subscriptions, revocation-aware re-authentication during a
stream (see [Section 10](#10-authentication-and-credential-expiry)).

---

## 2. Mental model: a historical range query that never ends

The feature is best understood as an extension of the existing historical query
machinery ([include/ccf/historical_queries_interface.h](../../include/ccf/historical_queries_interface.h),
[include/ccf/historical_queries_adapter.h](../../include/ccf/historical_queries_adapter.h)).

A historical *range* query fetches read-only state for a seqno range
`[from .. to]` and returns it. A **subscription is the same thing with `to`
pinned to "the latest commit" and continuously advancing**: as new transactions
commit, the effective upper bound grows, and each newly matching entry is pushed
to the client over a held-open connection instead of being returned in a single
response.

So one subscription proceeds in two phases that share the same delivery format:

1. **Catch-up** over `[from .. commit_now]`: exactly a historical range query.
   For a large past range this is where an **index** earns its keep - it answers
   "which seqnos matched?" without scanning the ledger (see
   [Section 5](#5-matching-what-using-the-indexer-for-matching-actually-means)).
2. **Live tail** from `commit_now` onward: as each new transaction commits, the
   manager is woken by the commit-callback subsystem, inspects that single
   committed transaction directly (no index needed), and streams it if it
   matches.

```mermaid
sequenceDiagram
    participant C as Client
    participant A as Subscription adapter (endpoint)
    participant M as SubscriptionManager
    participant I as Index (ccf::indexing, catch-up only)
    participant H as Historical state cache
    participant K as CommitCallback subsystem

    C->>A: GET /app/sub/{query}?from=<txid> (Accept: text/event-stream)
    A->>A: authenticate + authorize ONCE, validate query & from
    A->>M: register subscriber(query, cursor=from, stream)
    Note over A: response_is_pending = true (hold HTTP/1.1 connection)
    A-->>C: 200 OK, Transfer-Encoding: chunked, SSE headers

    rect rgb(235,245,255)
    Note over M,H: Catch-up: [from .. commit] as a historical range query
    M->>I: get_write_txs_in_range(query, cursor, commit)
    I-->>M: matching seqnos (or scan if no index)
    M->>H: get_stores_for(handle, matching seqnos)
    H-->>M: read-only stores (async; retry until ready)
    M->>A: project + write SSE event per matching entry
    A-->>C: event: entry ... (id: view.seqno)
    end

    rect rgb(235,255,235)
    Note over K,M: Live tail: woken by commit advance
    K->>M: on_commit_advance(new committed TxID)
    M->>H: get_stores_for(handle, new seqnos in (prev, new])
    H-->>M: read-only store(s)
    M->>M: inspect store directly -> matches query?
    M->>A: project + write SSE event
    A-->>C: event: entry ...
    end

    C--xA: disconnect
    A->>M: unregister subscriber, free handle + stream
```

---

## 3. Two independent tasks

### Task T - HTTP/1.1 chunked streaming transport

A general capability: "hold an HTTP/1.1 connection open and write the response
body incrementally over time." This has value beyond subscriptions and can be
built and merged on its own, with a trivial test endpoint that streams a few
heartbeats.

It is a direct generalisation of the **commit-callback response path** that
already exists. Today, when an endpoint defers its response until its
transaction commits ([src/http/http_session.h](../../src/http/http_session.h)),
the framework already:

1. sets `response_is_pending = true`
   ([rpc_context_impl.h](../../src/node/rpc_context_impl.h)) so no unary response
   is sent when the handler returns;
2. captures a `shared_ptr` to the `HTTPServerSession` (`self`) so it outlives the
   handler;
3. registers a `CommitCallbackSubsystem` callback that, when commit is reached,
   calls `send_response_impl(*self, ...)` to write the response late.

Task T generalises step 3 from **one** late response into **many** incremental
writes: a `ResponseStream` handle whose `start`/`write`/`close` route to the same
held session, emitting HTTP/1.1 chunked-transfer framing. See
[Section 6](#6-task-t-transport-detail).

### Task S - subscription endpoints

Everything specific to subscriptions - the manager, matching, catch-up,
live-tail notification, limits - built on Task T's `ResponseStream`. See
[Sections 5](#5-matching-what-using-the-indexer-for-matching-actually-means)
and [7](#7-task-s-subscription-detail).

Task S depends on Task T; Task T does not depend on Task S.

---

## 4. Why a subscription is not itself an indexer strategy

An earlier idea was to model each subscription as an `ccf::indexing::Strategy`
whose `handle_committed_transaction` fans out to live connections. Checking
[src/indexing/indexer.h](../../src/indexing/indexer.h) shows this does **not**
fit a client-specified starting `TxID`, and this is recorded so it is not
revisited blindly:

- Each strategy exposes a **single** `next_requested()` seqno - one monotonic
  cursor per strategy. It cannot serve two clients positioned at different
  seqnos at once.
- The indexer fetches from the **global minimum** `next_requested()` across *all*
  installed strategies (capped at `MAX_REQUESTABLE` = 500 per tick), so one
  subscriber starting near genesis would drag the shared indexer position
  backward and penalise every other index on the node.
- It is built to construct *persistent, forward-only aggregate indexes*, not to
  replay arbitrary historical ranges per client.

So a subscription is **not** an indexer strategy. The indexer is still used, but
only for *matching* (job #1 below), which is a normal, shared, forward-only index
- exactly what it is designed for.

---

## 5. Matching: what "using the indexer for matching" actually means

A subscription needs three separable jobs. Being explicit about them is what
keeps the design clean:

1. **Matching** - "which committed transactions are relevant to this query?"
2. **Data fetch** - "give me the read-only state of those transactions."
3. **Notification** - "tell me when there are new committed transactions."

"Using the indexer for matching" refers to **job #1 only**.

### The index answers "which seqnos matched?"

An `ccf::indexing` strategy such as
[`SeqnosByKey_InMemory`](../../include/ccf/indexing/strategies/seqnos_by_key_in_memory.h)
maintains, in memory, a map of `KV key -> every seqno that wrote to that key`
([seqnos_by_key_in_memory.cpp](../../src/indexing/strategies/seqnos_by_key_in_memory.cpp)
does `seqnos_by_key[k].insert(tx_id.seqno)` for each write). So for a subscription
to key `K`, the index answers *"which seqnos in `[from .. commit]` touched `K`?"*
via `get_write_txs_in_range(K, from, commit)` with an in-memory lookup, **no
ledger scan**.

The existing logging sample already uses exactly this matching + fetch pattern in
its `log/public/historical/range` endpoint
([samples/apps/logging/logging.cpp](../../samples/apps/logging/logging.cpp)):

```cpp
// 1. MATCHING: ask the index which seqnos are relevant
auto interesting_seqnos =
  index_per_public_key->get_write_txs_in_range(id, range_begin, range_end);
// 2. DATA FETCH: ask the historical cache for those transactions
stores = historical_cache.get_stores_for(handle, interesting_seqnos.value());
// 3. project each store into the response
```

A subscription's **catch-up** phase is this loop, streamed as SSE.

### The index is only needed for catch-up, not for live tail

This nuance narrows the indexer's role considerably:

- **Catch-up over a large past range** is where the index matters: finding the
  handful of matching seqnos among potentially millions without the index would
  mean fetching and inspecting every transaction in the range. So an index is
  *recommended* for any endpoint that permits a deep past `from`.
- **Live tail** does **not** need an index. Each committed transaction's store
  contains only *that transaction's* writes, so the manager inspects it directly
  ("did this transaction touch `K`?") - cheap, no pre-built index, and no
  ordering dependency on the app's index strategy.

So an index is an *optional accelerator for catch-up*, not a hard dependency of
the feature. Endpoints that never allow a deep past `from` (e.g. "from now"
only), or that accept the cost of scanning, can omit it entirely.

### Matching options offered to apps

- **Index-backed catch-up** (recommended): app supplies a `range_match` that
  wraps an index's `get_write_txs_in_range`. Efficient for sparse matches over
  big ranges.
- **Scan catch-up** (fallback): no index; the manager fetches the range and
  applies the app's per-transaction `match` predicate. Simple, supports arbitrary
  predicates, heavier for big ranges.
- **Live tail** always uses the per-transaction `match` predicate against the
  freshly committed store.

> Decision D2 in [Section 13](#13-open-questions-and-decisions) is about how
> expressive a query may be in v1 (exact key vs prefix/range vs arbitrary
> predicate), which determines whether an index can back it.

---

## 6. Task T (transport) detail

HTTP/1.1 has **no** incremental response writer today:
[http_builder.h](../../src/http/http_builder.h) always emits a single body with
`Content-Length`, and `send_response_impl` in
[http_session.h](../../src/http/http_session.h) explicitly throws on trailers.

### Public handle

```cpp
// include/ccf/endpoints/response_streaming.h  (new, public)
namespace ccf::endpoints
{
  class ResponseStream
  {
  public:
    // Send status line + headers with Transfer-Encoding: chunked, switching the
    // connection into streaming mode. Must be called exactly once, first.
    virtual bool start(
      ccf::http_status status, ccf::http::HeaderMap&& headers) = 0;

    // Emit one chunk: "<hex-size>\r\n<bytes>\r\n". Returns false if peer is gone.
    virtual bool write(std::span<const uint8_t> data) = 0;

    // Emit the terminating "0\r\n\r\n" (plus optional trailers) and release.
    virtual bool close(ccf::http::HeaderMap&& trailers = {}) = 0;

    // Invoked when the client disconnects or the session is torn down.
    virtual void set_on_close(std::function<void()> cb) = 0;

    virtual ~ResponseStream() = default;
  };
  using ResponseStreamPtr = std::shared_ptr<ResponseStream>;
}
```

### Implementation, built on the commit-callback held-response pattern

- **Chunked writer** in [http_builder.h](../../src/http/http_builder.h): build a
  header block with `Transfer-Encoding: chunked` and no `Content-Length`; helpers
  to frame a data chunk and the terminating chunk (with optional trailer
  headers).
- **Session support** in [http_session.h](../../src/http/http_session.h): reuse
  the exact lifetime trick the commit-callback path already uses (capture a
  `shared_ptr` to `HTTPServerSession`), but keep it alive for the duration of the
  stream and route `write`/`close` to `session.send_data(...)` instead of a
  single `send_response_impl`.
- **Pending wiring**: obtaining a stream sets `response_is_pending = true`
  ([rpc_context_impl.h](../../src/node/rpc_context_impl.h)) so no unary/error
  response races the stream.

### App access

```cpp
// include/ccf/rpc_context.h (new virtual), impl in rpc_context_impl.h
virtual ccf::endpoints::ResponseStreamPtr start_response_stream() = 0;
```

> The same `ResponseStream` abstraction can later be backed by HTTP/2
> (`HTTP2StreamResponder` in [http2_session.h](../../src/http/http2_session.h)
> already does `start_stream`/`send_data`/`close_stream`), with no app-facing
> change - but no HTTP/2 code is written in phase 1.

### Task T deliverable / test

A trivial `make_command_endpoint` that calls `start_response_stream()`, writes a
few chunks over successive ticks, and closes. Round-trip test: feed the produced
bytes back through llhttp and assert a well-formed chunked response.

---

## 7. Task S (subscription) detail

### 7.1 Application API

```cpp
// include/ccf/subscription_adapter.h (new)
namespace ccf::subscription
{
  // Opaque, app-defined description of what the client subscribed to,
  // parsed from the request (e.g. a KV key from a path param).
  struct Query { /* app-defined, carried opaquely by the framework */ };

  // Does this single committed transaction match `query`? Runs against a
  // read-only store of just that transaction's writes. Used for live tail
  // (always) and for scan-based catch-up (when no index is supplied).
  using MatchFn = std::function<bool(
    const Query&, const ccf::TxID&, const ccf::kv::ReadOnlyStorePtr&)>;

  // Turn a matching transaction into the bytes of one SSE `data:` payload.
  using ProjectFn = std::function<std::vector<uint8_t>(
    const Query&, const ccf::TxID&, const ccf::kv::ReadOnlyStorePtr&)>;

  // Optional index-backed catch-up: matching seqnos in a range, or nullopt if
  // the index is not yet populated to `to` (retry later).
  using RangeMatchFn = std::function<std::optional<ccf::SeqNoCollection>(
    const Query&, ccf::SeqNo from, ccf::SeqNo to)>;

  struct Handlers
  {
    QueryExtractor      extract_query;  // request -> Query (or 400)
    StartSeqnoExtractor extract_from;   // request -> starting TxID (default: now)
    MatchFn             match;          // per-transaction predicate
    ProjectFn           project;        // matching tx -> SSE payload
    RangeMatchFn        range_match;    // optional index-backed catch-up
  };

  // Mirrors historical read_only_adapter_v4: returns a command endpoint fn.
  ccf::endpoints::CommandEndpointFunction subscription_adapter(
    ccf::AbstractNodeContext& node_context, Handlers handlers);
}
```

Registration mirrors how indexes and historical endpoints are wired today:

```cpp
// In the app's init_handlers():

// (Optional, for catch-up acceleration) install an index.
auto records_index =
  std::make_shared<ccf::indexing::strategies::SeqnosByKey_InMemory<RecordsMap>>(
    records_map);
context.get_indexing_strategies().install_strategy(records_index);

ccf::subscription::Handlers h;
h.extract_query = /* parse {key} from path */;
h.extract_from  = ccf::subscription::start_from_header;  // ?from= / Last-Event-ID
h.match   = /* does this store touch records_map[key]? */;
h.project = /* serialise {seqno, key, value} */;
h.range_match = [records_index](const auto& q, auto from, auto to) {
  return records_index->get_write_txs_in_range(q.key, from, to);
};

make_command_endpoint(
  "/records/subscribe/{key}", HTTP_GET,
  ccf::subscription::subscription_adapter(context, h),
  {ccf::user_cert_auth_policy})
  .set_forwarding_required(ccf::endpoints::ForwardingRequired::Never)
  .install();
```

It is a **command** endpoint (`make_command_endpoint`): no `ccf::kv::Tx` is
opened, satisfying "no TX, no write access". It can be `Mode::ReadOnly` and served
from any node (see [Section 9](#9-consistency-elections-rollback-and-forwarding)).

### 7.2 Notification: built on the commit-callback subsystem

The `CommitCallbackSubsystem`
([src/node/commit_callback_subsystem.h](../../src/node/commit_callback_subsystem.h))
already has `trigger_callbacks(committed, view_history)` invoked whenever the
commit index advances. Its current callbacks are per-`TxID`, one-shot.

Task S adds a small, natural extension: a set of **commit-advance observers** that
fire on every `trigger_callbacks` with the new committed `TxID`. The
`SubscriptionManager` registers one such observer and uses it to wake its
delivery pump precisely when new commits happen - directly reusing the
commit-callback path rather than polling. (Falling back to the node tick for
retries and catch-up progress is also fine.)

### 7.3 Data fetch: historical cache, per subscriber

Both phases obtain transaction data from the historical state cache using a
**per-subscriber `RequestHandle`**:
`get_stores_for(handle, seqnos)`
([historical_queries_interface.h](../../include/ccf/historical_queries_interface.h)),
which returns empty until the async ledger fetch completes, then the full set.
This is the same call the logging sample uses, so cost is bounded and shared with
normal historical queries.

### 7.4 The SubscriptionManager (new subsystem)

Owns the whole lifecycle:

- The set of active subscribers, each:
  `{ Query, cursor, phase, ResponseStreamPtr, RequestHandle, authenticated identity }`.
- A single commit-advance observer ([Section 7.2](#72-notification-built-on-the-commit-callback-subsystem)).
- The delivery pump, run on wake / tick:
  - **Catch-up** (`cursor < commit`): matching seqnos via `range_match` (index)
    or scan; fetch via `get_stores_for`; project; write SSE; advance `cursor`.
  - **Live tail** (`cursor == commit`): for new seqnos in `(prev_commit, commit]`,
    fetch, apply `match` to each store directly, project matches, write SSE.
- **Phase handoff:** `cursor` is the single source of truth. Catch-up walks it
  toward the latest commit; when it reaches the current commit the subscriber
  flips to `LIVE` (emitting an optional `caught_up` marker). A short lock around
  the flip re-reads commit to close the race, so no entry is dropped or
  duplicated across the boundary.
- Heartbeats, resource limits, eviction ([Section 8](#8-resumption-and-back-pressure)).
- Cleanup: `set_on_close` and failed `write`s trigger `remove_subscriber`, which
  drops cached historical state (`drop_cached_states(handle)`) and releases the
  stream.

### 7.5 Wire format: SSE

```
event: entry
id: 4.135
data: {"seqno":135,"view":4,"key":"...","value":...}

event: caught_up
data: {"seqno":135}

event: heartbeat
data: {}
```

- `id: <view>.<seqno>` is the resumption token; a reconnecting client sends
  `Last-Event-ID` (or `from=`) and resumes from that seqno + 1.
- Headers: `Content-Type: text/event-stream`, `Cache-Control: no-cache`,
  `Transfer-Encoding: chunked`.
- Payload is app-defined via `project`, so the app controls exactly what a
  subscriber sees.

---

## 8. Resumption and back-pressure

- **Resumption.** Every event carries `id: <view>.<seqno>`. Reconnect with
  `Last-Event-ID`/`from=` resumes from that seqno + 1. Redelivery around a
  reconnect is at-least-once; clients dedupe by id.
- **Slow consumers.** `ResponseStream::write` reports failure/would-block; the
  manager tracks per-subscriber buffered bytes and, on exceeding a configurable
  cap, **disconnects** with a terminal `event: overflow` (decision D3).
- **Global limits.** Max concurrent subscribers per node and per caller identity,
  enforced at admission (`429`/`503`), respecting existing `max_open_sessions`
  accounting in [rpc_sessions.h](../../src/enclave/rpc_sessions.h).
- **Catch-up depth.** Bound how far back `from` may be (config); deep catch-up
  shares the historical cache with normal historical queries.

---

## 9. Consistency: elections, rollback, and forwarding

Only **committed** transactions are ever delivered (catch-up via the historical
cache; live tail woken by the commit-advance signal derived from
`consensus->get_committed_txid()`), so a subscriber never observes speculative
state and nothing delivered is ever rolled back.

- **Any node can serve a subscription.** Indexes and the historical cache exist on
  every node and this is read-only, so the endpoint is `ForwardingRequired::Never`
  and can run on backups - spreading streaming load off the primary.
- **Node-local commit index.** Nodes may differ slightly; a subscriber sees its
  node's committed prefix and, on reconnect elsewhere, resumes by seqno.
- **View changes** do not affect subscribers (commit is monotonic).
- **Node restart drops all streams** (in-memory only). Clients reconnect (to any
  node) with their last id and resume. Documented; no server-side durability.

---

## 10. Authentication and credential expiry

A subscription can hold a connection open far longer than the credential that
authorized it stays valid. Because SSE is server-to-client only, the client
cannot present a fresh credential on the open stream - so "re-authentication" in
practice means "reconnect". The natural expiry horizon differs sharply by auth
method, so the framework treats expiry per method rather than with a single
blanket timeout.

### Expiry characteristics by method

- **User / member certificate** (`ccf::user_cert_auth_policy` /
  `member_cert_auth_policy`,
  [cert_auth.cpp](../../src/endpoints/authentication/cert_auth.cpp)): the
  credential is the mutual-TLS client certificate. Authentication checks both the
  X.509 validity period (`notBefore`/`notAfter`) and that the cert hash is present
  in the `USER_CERTS`/`MEMBER_CERTS` KV table. Horizon: the cert `notAfter` (often
  long, e.g. a year), but the user/member can be **revoked by governance at any
  time** via removal from that table. The cert is bound to the TLS session, so it
  cannot be silently swapped mid-stream.
- **JWT bearer token** (`ccf::jwt_auth_policy`,
  [jwt_auth.cpp](../../src/endpoints/authentication/jwt_auth.cpp)): authentication
  checks `exp` (required) and `nbf` (optional) against the current time, and the
  signature against JWKS keys stored in the KV. Horizon: the `exp` claim, which is
  typically **short** (minutes to about an hour) - so a JWT-authorized stream will
  routinely outlive its token unless bounded. The signing key may also be rotated
  or removed by governance.
- **COSE Sign1** (`ccf::cose_auth_policy`,
  [cose_auth.cpp](../../src/endpoints/authentication/cose_auth.cpp)): carries a
  `ccf.gov.msg.created_at` timestamp and is bounded by the signer certificate's
  validity. Primarily a governance / one-shot method and unlikely for streaming,
  but if used the signer cert validity is the horizon.
- **Empty / no auth** (`ccf::empty_auth_policy`): no credential, no expiry.

### Proposed handling (phase 1): cap stream lifetime to credential expiry

At subscribe time the adapter already holds the authenticated identity, from
which it can derive a **credential expiry instant**:

- JWT: the `exp` claim (honouring `nbf` at admission).
- Cert: the certificate `notAfter`.
- COSE: the signer certificate `notAfter`.
- Empty: none (unbounded, subject only to the resource limits in
  [Section 8](#8-resumption-and-back-pressure)).

The `SubscriptionManager` records this expiry per subscriber and, when it is
reached, **closes the stream** with a terminal `event: auth_expired` carrying the
last delivered `id`. The client then reconnects with a fresh credential and
resumes from `Last-Event-ID` - reusing the resumption flow that already exists for
dropped connections ([Section 8](#8-resumption-and-back-pressure)). This respects
short token lifetimes without any bidirectional re-auth and needs no new protocol.

### Explicitly out of scope for phase 1

- **Revocation-aware re-checking.** Detecting that a user was removed from
  `USER_CERTS`, or a JWKS key rotated, *during* a stream would require
  periodically re-running the auth policy against a fresh read-only `Tx`. That
  catches revocation (not just clock expiry) but adds cost and complexity, so it
  is deferred. The lifetime cap above still bounds worst-case exposure to the
  credential's original validity.
- **Re-auth on the same connection.** Not possible with unidirectional SSE;
  reconnect is the mechanism.

### Consequence to decide

Short JWT `exp` values mean a JWT-authorized subscription may be forced to
reconnect every few minutes. Options: accept frequent reconnects (cheap, given
resumption); recommend or require longer-lived tokens (or a dedicated
subscription audience) for these endpoints; or make the cap configurable per
endpoint. See decision D9 in
[Section 13](#13-open-questions-and-decisions).

---

## 11. Threading and concurrency

- The commit-advance observer fires from the same context that runs consensus
  commit updates and the indexer ([node_state.h](../../src/node/node_state.h)),
  on the enclave main loop ([src/enclave/enclave.h](../../src/enclave/enclave.h)).
  Writing a response to a held session from this context already happens today in
  the commit-callback path, so there is precedent.
- Plan: run all subscription delivery on the main loop thread; the
  `SubscriptionManager` guards its subscriber table with a mutex (as the indexer
  and commit-callback subsystems guard theirs). `ResponseStream` holds a weak
  reference to the session (as `HTTP2StreamResponder` already does) and fails
  writes gracefully once the session is gone.
- **To verify during implementation:** that inbound processing for a session and
  tick-thread writes to the same session cannot interleave partial chunks; if the
  session can process inbound on a task thread, serialise its output through the
  session's own lock. No new worker threads are introduced.

---

## 12. New / changed files (phase 1)

Task T (transport):

| File | New/changed | Purpose |
| --- | --- | --- |
| `include/ccf/endpoints/response_streaming.h` | new | Public `ResponseStream` interface |
| `src/http/http_builder.h` | changed | Chunked-transfer response building |
| `src/http/http_session.h` | changed | HTTP/1.1 streaming responder; keep session alive |
| `src/node/rpc_context_impl.h` | changed | `start_response_stream()`, pending wiring |
| `include/ccf/rpc_context.h` | changed | Public `start_response_stream()` declaration |

Task S (subscriptions):

| File | New/changed | Purpose |
| --- | --- | --- |
| `src/node/commit_callback_subsystem.h` | changed | Add commit-advance observers |
| `include/ccf/subscription_adapter.h` | new | Adapter + `Handlers`/`Query` types |
| `src/node/rpc/subscription_adapter.cpp` | new | Adapter implementation |
| `src/node/subscription_manager.h` / `.cpp` | new | Registry, pump, matching, limits, cleanup |
| `samples/apps/logging/logging.cpp` | changed | Example subscription endpoint |
| `tests/...` | new | e2e + unit tests (see [Section 14](#14-testing-plan)) |
| `doc/build_apps/...`, `CHANGELOG.md` | changed | Docs + changelog entry |

Explicitly **not** touched in phase 1: `src/http/http2_*` and `src/js/*`.

---

## 13. Open questions and decisions

Settled: transport = HTTP/1.1 only; framing = SSE; language = C++ only; auth
checked once at subscribe with the stream lifetime capped to the credential's
expiry (method-aware, [Section 10](#10-authentication-and-credential-expiry));
start = client-specified `TxID`; a subscription is not an indexer strategy; an
index is an optional catch-up accelerator, not a hard dependency.

Still open:

- **D1 - "from" spelling.** `?from=<txid>` query param, a request header, and/or
  `Last-Event-ID` for reconnect? Default when omitted = current commit ("from
  now")? *(Recommend: accept `?from=` and `Last-Event-ID`; default = now.)*
- **D2 - Query expressiveness in v1.** Exact KV key in one map (maps directly onto
  [SeqnosByKey_InMemory](../../include/ccf/indexing/strategies/seqnos_by_key_in_memory.h))
  vs key prefix/range vs arbitrary app predicate. This also decides whether an
  index can back catch-up. *(Recommend: start with exact key.)*
- **D3 - Slow-consumer policy.** Disconnect on overflow (recommended) vs
  drop/coalesce (latest-value only).
- **D4 - Event payload.** Raw serialised KV value vs app JSON projection vs
  optional attached receipt. *(Recommend: app projection; receipt opt-in, off by
  default.)*
- **D5 - Batching granularity.** One SSE event per matching KV write vs one event
  per transaction. *(Recommend: per transaction, so the `id`/seqno is
  unambiguous.)*
- **D6 - Catch-up without an index.** Allow scan-based catch-up for arbitrary
  `match`-only queries, or require an index for any endpoint permitting a past
  `from`? *(Recommend: allow scan but document cost; require index for
  production-grade endpoints.)*
- **D7 - Heartbeat interval / idle timeout** defaults and configurability.
- **D8 - Observability.** Which metrics (active subscribers, bytes streamed,
  catch-up lag, evictions) and where.
- **D9 - Credential-expiry cap for short-lived tokens.** Given the lifetime cap
  in [Section 10](#10-authentication-and-credential-expiry), how should very short
  JWT `exp` values be handled: accept frequent reconnects, recommend/require
  longer-lived (or dedicated-audience) tokens for subscription endpoints, or make
  the cap configurable per endpoint? *(Recommend: accept reconnects by default;
  allow a per-endpoint minimum-lifetime hint.)*

---

## 14. Testing plan

- **Task T unit (C++):** chunked writer round-trip - feed produced bytes through
  llhttp and assert a well-formed chunked response with trailers (extend
  [src/http/test](../../src/http/test)); a session that streams N chunks then
  closes.
- **Task S unit (C++):** `SubscriptionManager` cursor/phase logic with a stub
  `ResponseStream`: ordering, catch-up -> live handoff with no gaps/dupes,
  multiple subscribers at different `from`, unsubscribe/cleanup.
- **End-to-end (Python, [tests/](../../tests)):**
  - `from` in the past -> catch-up then live tail; ordered ids and `caught_up`.
  - Default (from now); commit writes; live events arrive.
  - Reconnect with `Last-Event-ID` resumes without gaps.
  - Subscribe on a backup node with forwarding disabled.
  - Limits: too many subscribers -> `429/503`; slow consumer -> overflow
    disconnect.
  - Node restart drops streams; client reconnects and resumes.
  - Confirm no `Tx` is opened / no ledger growth (read-only).
- **Soak/perf:** many concurrent subscribers at a sustained commit rate; measure
  memory, catch-up lag, and that serving on backups keeps the primary unloaded.

---

## 15. Suggested phased roadmap

**Task T (transport), independently mergeable:**

1. **T1** - `ResponseStream` + HTTP/1.1 chunked writer + `start_response_stream()`
   + demo endpoint streaming heartbeats. Unit tests.

**Task S (subscriptions), on top of T:**

2. **S1** - commit-advance observer + `SubscriptionManager` + `subscription_adapter`;
   "from now" (live-tail-only) subscriptions. Sample app + e2e.
3. **S2** - catch-up: per-subscriber historical fetch + index-backed `range_match`
   (and scan fallback) for arbitrary past `from`; `caught_up` handoff.
4. **S3** - hardening: back-pressure/overflow, per-caller quotas, heartbeat and
   idle-timeout config, resumption edge cases, metrics, docs + changelog.

Later phases (out of scope now): HTTP/2 backend; JavaScript support.

---

## 16. Summary

A subscription is a historical range query that never ends: the client names a
starting `TxID`, catch-up replays `[from .. commit]`, and live tail streams every
subsequent matching commit - all read-only, over a held-open HTTP/1.1 chunked
connection framed as SSE. The work splits cleanly into an independent
**transport** task (Task T), which generalises the existing commit-callback
"hold the connection, respond later" mechanism into incremental chunked writes,
and a **subscription** task (Task S) on top of it. Matching separates into three
jobs - *matching* (an optional index, needed only to accelerate catch-up over a
large past range), *data fetch* (the historical state cache, per subscriber), and
*notification* (a commit-advance observer added to the commit-callback subsystem).
A subscription is deliberately **not** an indexer strategy, because the indexer's
single forward-only cursor cannot replay arbitrary client-specified start points.
Credential expiry is handled method-awarely by capping each stream's lifetime to
its credential's validity ([Section 10](#10-authentication-and-credential-expiry)).
Please review the open decisions in
[Section 13](#13-open-questions-and-decisions) before implementation.
