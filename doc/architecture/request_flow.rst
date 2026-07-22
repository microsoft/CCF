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
      Frontend->>Frontend: is_open()
      Frontend->>Frontend: Store is Ready
      note left of Frontend: Tx is created here
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
      FrontendA->>FrontendA: is_open()
      FrontendA->>FrontendA: Store is Ready
      note left of FrontendA: Tx is created here
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
      FrontendB->>FrontendB: is_open()
      FrontendB->>FrontendB: Store is Ready
      note left of FrontendB: Tx is created here
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

Redirection flow
----------------

CCF supports HTTP redirections as an alternative to forwarding. When a request arrives that cannot be executed locally, rather than forwarding it to an appropriate node over the node-to-node channels, the node can return a HTTP redirect response advising the caller to resubmit the request directly to that node. This uses standard HTTP semantics, reporting the redirect target in a ``Location`` header. Most HTTP clients will have an option to follow this redirect automatically, and all should have an option to enable this behaviour if desired. Alternatively, client applications may choose to intercept this redirect response and manually interpret it, perhaps to alter the resubmitted request or to update the target node for future requests.

.. warning:: Many HTTP clients will strip out ``Authorization`` headers when following Cross-Origin redirects. This means that if your client is automatically following redirects, and you submit a request with a JWT token as authorization, if you are redirected you may see a surprising authorization failure. In this scenario we recommend intercepting the redirect responses manually, so that the request can be resubmitted without stripping headers.

Similar to forwarding, the redirect behaviour is partly controlled by per-endpoint metadata, so the initially receiving node must parse the request and go through endpoint dispatch before making a forwarding decision.

There are currently 2 supported modes for redirections. In the first, the response sends the user directly to the suggested node. This will only work if that node has an accessible name, which can be included in the ``Location`` header and accessed by the user.

.. mermaid::

  sequenceDiagram
      autonumber
      participant U as User
      participant B as Backup (nodeA.ccf.com)
      participant P as Primary (nodeB.ccf.com)

      U->>B: POST /copy/A/B
      B->>B: Lookup endpoint
      B->>B: Decide request should be redirected
      B->>B: Build redirect response
      B-->>U: 307 REDIRECT Location: nodeB.ccf.com/copy/A/B

      U->>P: POST /copy/A/B
      P->>P: Lookup endpoint
      P->>P: Decide request can be executed
      P->>P: Execute request
      P-->>U: 200 OK "Copied {a} from {A} to {B}"

For deployments where nodes are not directly accessible, redirections can still be supported via multiple load balancers. All that is required is `a` public name for each redirect purpose, with up-to-date balancing to the correct nodes. More simply, that currently means maintaining a `write` load balancer which can direct external traffic to a primary.

.. mermaid::

  sequenceDiagram
      autonumber
      participant U as User
      participant LB as General LB (service.ccf.com)
      participant B as Backup
      participant WLB as Write LB (write.service.ccf.com)
      participant P as Primary

      U->>LB: POST /copy/A/B
      LB->>B: POST /copy/A/B
      B->>B: Lookup endpoint
      B->>B: Decide request should be redirected
      B->>B: Build redirect response
      B-->>U: 307 REDIRECT Location: write.service.ccf.com/copy/A/B

      U->>WLB: POST /copy/A/B
      WLB->>P: POST /copy/A/B
      P->>P: Lookup endpoint
      P->>P: Decide request can be executed
      P->>P: Execute request
      P-->>U: 200 OK "Copied {a} from {A} to {B}"

To use redirection behaviour, and choose whether to redirect to a node or a load balancer, set the ``redirections`` field in the :doc:`launch configuration </operations/configuration>`.
