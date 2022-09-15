Request Flow
============

These diagrams summarise the flow of a user request from a client, executed on a CCF node. Each shows execution of a ``POST /copy/A/B`` endpoint which does a KV read from the key specified in ``A``, and writes the obtained value back to the KV at key ``B``.

These show the progression from parsing through several layers of dispatch, in code that is part of the framework, down to the app code which is under the control of application developers.

.. note:: This page only discusses execution, and does not show how execution results are then replicated to reach consensus.

Normal flow
-----------

This is the simple, usual flow, where the request is submitted to a primary node capable of writing to the KV. Only the receiving node interacts with the request. The entire execution is synchronous, writing the response back to the client before proceeding with any other work.

.. mermaid::

  sequenceDiagram
      participant User
      participant NetStack
      participant Frontend
      participant App
      participant KV

      User->>NetStack: POST /copy/A/B

      rect rgba(191, 223, 255, 0.5)
      note over NetStack,KV: Inside single CCF node
      NetStack->>NetStack: TLS decrypt request
      NetStack->>NetStack: HTTP parse request
      NetStack->>+Frontend: Frontend Dispatch
      note left of Frontend: Tx is created here
      Frontend->>Frontend: is_open(tx)
      Frontend->>App: find_endpoint(tx, ctx)
      App->>App: h = find_handler_for(tx, ctx)
      App-->>Frontend: return h
      Frontend->>Frontend: get_authenticated_identity(tx, ctx)
      Frontend->>Frontend: forward?
      Frontend->>App: execute_endpoint(tx, ctx, h)
      App->>KV: tx.get(A)
      KV-->>App: return a
      App->>KV: tx.put(B, a)
      KV-->>App: return
      App->>App: ctx.set_claims_digest(...)
      App->>App: ctx.set_response(OK, "Copied {a} from {A} to {B}")
      App-->>Frontend: return
      Frontend->>Frontend: tx.commit()
      Frontend->>-Frontend: response.set_header(TX_HEADER, tx.commit_id())
      note left of Frontend: Tx is destroyed here
      Frontend-->>NetStack: return
      NetStack->>NetStack: HTTP serialise response
      NetStack->>NetStack: TLS encrypt response
      end

      NetStack-->>User: 200 OK "Copied {a} from {A} to {B}"

Forwarding flow
---------------

When write request are submitted to a follower node, they must be forwarded to the primary for execution. This diagram shows how that is done, between a follower node A and a primary B. Decryption and some dispatch still occurs on the follower, as it must lookup the correct endpoint's metadata to determine whether this request should be forwarded. When A establishes that the request should be forwarded, it queues a node-to-node (N2N) forwarding message to the primary describing the original request. The synchronous execution the follower A now completes without writing any response to the user, but maintaining an open TLS session and some local state that a response is pending.

When the primary B receives the forwarded command, it executes the same dispatch and execution that it would if it had directly received the request, but with a different stack at the top level. Specifically, it will eventually write its response back over the encrypted node-to-node channel to A, rather than the original caller.

When follower A receives the forwarded response, it writes this to the TLS session that was maintained earlier, and marks the pending response as completed.

.. mermaid::

  sequenceDiagram
      participant User
      participant NetStackA
      participant FrontendA
      participant N2NA
      participant N2NB
      participant FrontendB

      participant App
      participant KV

      User->>NetStackA: POST /copy/A/B

      rect rgba(191, 223, 255, 0.5)
      note over NetStackA,N2NA: Inside CCF node A
      NetStackA->>NetStackA: TLS decrypt request
      NetStackA->>NetStackA: HTTP parse request
      NetStackA->>+FrontendA: Frontend Dispatch
      note left of FrontendA: Tx is created here
      FrontendA->>FrontendA: is_open(tx)
      FrontendA->>FrontendA: find_endpoint(tx, ctx)
      FrontendA->>FrontendA: get_authenticated_identity(tx, ctx)
      FrontendA->>-FrontendA: forward?
      FrontendA->>N2NA: forward()
      N2NA->>N2NA: Queue forwarded msg
      N2NA-->>FrontendA: return
      FrontendA->>FrontendA: ctx.pending_response = true
      note left of FrontendA: Tx is destroyed here
      FrontendA-->>NetStackA: return
      end

      N2NA->>N2NB: forwarded_cmd

      rect rgba(191, 223, 255, 0.5)
      note over N2NB,KV: Inside CCF node B
      N2NB->>N2NB: N2N parse
      N2NB->>+FrontendB: Frontend Dispatch
      note left of FrontendB: Tx is created here
      FrontendB->>FrontendB: is_open(tx)
      FrontendB->>App: find_endpoint(tx, ctx)
      App->>App: h = find_handler_for(tx, ctx)
      App-->>FrontendB: return h
      FrontendB->>FrontendB: get_authenticated_identity(tx, ctx)
      FrontendB->>FrontendB: forward?
      FrontendB->>App: execute_endpoint(tx, ctx, h)
      App->>KV: tx.get(A)
      KV-->>App: return a
      App->>KV: tx.put(B, a)
      KV-->>App: return
      App->>App: ctx.set_response(OK, "Copied {a} from {A} to {B}")
      App-->>FrontendB: return
      FrontendB->>FrontendB: tx.commit()
      FrontendB->>-FrontendB: response.set_header(TX_HEADER, tx.commit_id())
      FrontendB-->>N2NB: return
      note left of FrontendB: Tx is destroyed here
      N2NB->>N2NB: HTTP serialise response
      end

      N2NB-->>N2NA: forwarded_response

      N2NA->>N2NA: N2N Parse
      N2NA->>NetStackA: reply_async(session, response)
      NetStackA->>NetStackA: TLS encrypt response

      NetStackA-->>User: 200 OK "Copied {a} from {A} to {B}"

External executor flow
----------------------

This shows the flow for the in-development external executor app, where implementation of the user endpoints is offloaded to an external trusted executor. This is achieved by providing a remote KV API over which the executor can invoke actions of the local KV, using a persistent ``Tx`` object shared between multiple requests.

The result is that the user's interaction is unchanged - they send a HTTPS request to a single CCF node and get the same format of response, but the app logic can be decoupled from the CCF enclave.

.. note:: Some steps are elided/abbreviated for clarity. This diagram does not show the registration of executors.

.. mermaid::

  sequenceDiagram
      participant User
      participant Executor
      participant NetStack
      participant Frontend
      participant App
      participant KV

      User->>NetStack: POST /copy/A/B

      rect rgba(191, 223, 255, 0.5)
      note over NetStack,App: Inside single CCF node
      NetStack->>NetStack: TLS decrypt request
      NetStack->>NetStack: HTTP parse request
      NetStack->>Frontend: Frontend Dispatch
      activate Frontend
      note left of Frontend: tx1 is created here
      Frontend->>Frontend: is_open(tx1)
      Frontend->>App: find_endpoint(tx1, ctx)
      App->>App: e = find_executor_for(ctx)
      App-->>Frontend: return e
      Frontend->>Frontend: get_authenticated_identity(tx1, ctx)
      Frontend->>Frontend: forward?
      Frontend->>App: execute_endpoint(tx1, ctx, e)
      note over Frontend,App: tx1 is stolen here
      deactivate Frontend
      activate App
      App->>App: pending_reqs[e].append(tx1, ctx)
      App->>App: ctx.pending_response = true
      App-->>Frontend: return
      Frontend-->>NetStack: return
      end

      Executor->>NetStack: POST /StartTx

      rect rgba(191, 223, 255, 0.5)
      NetStack->>NetStack: TLS decrypt request
      NetStack->>NetStack: HTTP parse request
      NetStack->>Frontend: Frontend Dispatch
      activate Frontend
      Frontend->>Frontend: is_open(tx2)
      Frontend->>App: find_endpoint(tx2, ctx)
      App->>App: h = find_handler_for(tx2, ctx)
      App-->>Frontend: return h
      Frontend->>Frontend: get_authenticated_identity(tx2, ctx)
      Frontend->>Frontend: forward?
      Frontend->>App: execute_endpoint(tx2, ctx, h)
      App->>App: active_reqs[e] = pending_reqs.pop(e)
      App->>App: ctx.set_response(OK, describe_request(active_reqs[e]))
      App-->>Frontend: return
      Frontend->>Frontend: tx.commit()
      Frontend->>Frontend: response.set_header(TX_HEADER, tx.commit_id())
      Frontend-->>NetStack: return
      deactivate Frontend
      NetStack->>NetStack: HTTP serialise response
      NetStack->>NetStack: TLS encrypt response
      end

      NetStack-->>Executor: 200 OK {RequestDescription}

      activate Executor
      Executor->>Executor: Process RequestDescription

      Executor->>NetStack: POST /KV.Get {key=A}
      rect rgba(191, 223, 255, 0.5)
      note over NetStack,App: ...
      Frontend->>App: execute_endpoint(tx3, ctx, h)
      App->>App: tx = active_reqs[e].tx
      Note right of App: // Gets tx1
      App->>KV: tx1.get(A)
      KV-->>App: return a
      App->>App: ctx.set_response(OK, {value=a})
      App-->>Frontend: return
      note over NetStack,Frontend: ...
      end
      NetStack-->>Executor: 200 OK {value=a}

      Executor->>NetStack: POST /KV.Put {key=B, value=a}
      rect rgba(191, 223, 255, 0.5)
      note over NetStack,App: ...
      Frontend->>App: execute_endpoint(tx4, ctx, h)
      App->>App: tx = active_reqs[e].tx
      Note right of App: // Gets tx1
      App->>KV: tx1.put(B, a)
      KV-->>App: return
      App->>App: ctx.set_response(OK)
      App-->>Frontend: return
      note over NetStack,Frontend: ...
      end
      NetStack-->>Executor: 200 OK

      Executor->>NetStack: POST /EndTx {code=200, body="Copied {a} from {A} to {B}"}
      rect rgba(191, 223, 255, 0.5)
      note over NetStack,App: ...
      Frontend->>App: execute_endpoint(tx5, ctx, h)
      App->>App: tx = active_reqs[e].tx
      Note right of App: // Gets tx1
      App->>App: result = tx1.commit()
      App->>App: response = (result, code, body)
      App->>App: HTTP serialise response
      App->>NetStack: reply_async(active_reqs[e].ctx.session, response)
      App->>App: ctx.set_response(OK)
      App->>App: active_reqs.pop(e)
      note over App: tx1 is destroyed here
      deactivate App
      App-->>Frontend: return
      note over NetStack,Frontend: ...
      end
      NetStack-->>Executor: 200 OK

      deactivate Executor

      NetStack->>NetStack: TLS encrypt response
      
      NetStack-->>User: 200 OK "Copied {a} from {A} to {B}"
