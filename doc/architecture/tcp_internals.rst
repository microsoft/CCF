TCP Internals
=============

Overview
~~~~~~~~

In CCF, the :term:`TCP` host layer is implemented using `libuv <https://libuv.org/>`_, allowing us to listen for connections from other nodes and requests from clients as well as connect to other nodes.

Both :term:`RPC` and Node-to-Node connections use TCP to communicate with external resources and then pass the packets through the :term:`ring buffer` to communicate with the enclave.

CCF uses a HTTP :term:`REST` interface to call programs inside the enclave, so the process is usually read request, call enclave function and receive response (via `ring buffer` message), send the response to the client.

However, the TCP implementation in CCF is generic and could adapt to other common communication processes, but perhaps would need to change how the users (RPC, Node-to-node) use it.

Overall structure
~~~~~~~~~~~~~~~~~

The `TCPImpl` class (in ``src/host/tcp.h``) implements all TCP logic (using the asynchronous `libuv`), used by both `RPCConnections` and `NodeConnections`.

Because `TCPImpl` does not have access to the `ring buffer`, it must use behaviour classes to allow users to register callbacks on actions (ex. `on_read`, `on_accept`, etc).

Most of the call backs are for logging purposes, but the two important ones are:
- `on_accept` on servers, which creates a new socket to communicate with the particular connecting client
- `on_read`, which takes the data that is read and writes it to the `ring buffer`

For note-to-node connections, the behaviours are:
- `NodeServerBehaviour`, the main listening socket and, `on_accept`, creates a new socket to communicate with a particular connecting client
- `NodeIncomingBehaviour`, the socket that is created above, that waits for input and passes that to the enclave
- `NodeOutgoingBehaviour`, a socket that is created by the enclave (via ring buffer messages into the host), to connect to external nodes

For RPC connections, the behaviours are:
- `RPCServerBehaviour`, same as the `NodeServerBehaviour` above
- `RPCClientBehaviour`, a misnomer, used for both incoming and outgoing behaviours above

Here's a diagram with the types of behaviours and their relationships:

.. mermaid::

  graph BT
      subgraph TCP
          TCPBehaviour
          TCPServerBehaviour
      end

      subgraph RPCConnections
          RPCClientBehaviour
          RCPServerBehaviour
      end

      subgraph NodeConnections
          NodeConnectionBehaviour
          NodeIncomingBehaviour
          NodeOutgoingBehaviour
          NodeServerBehaviour
      end

          RPCClientBehaviour --> TCPBehaviour
          NodeConnectionBehaviour --> TCPBehaviour
          NodeIncomingBehaviour --> NodeConnectionBehaviour
          NodeOutgoingBehaviour --> NodeConnectionBehaviour
          NodeServerBehaviour --> TCPServerBehaviour
          RCPServerBehaviour --> TCPServerBehaviour


State machine
~~~~~~~~~~~~~

The `TCPImpl` has an internal state machine where states change as reactions to callbacks from `libuv`.

Since it implements both server (listen, peer, read) and client (connect, write) logic, the state helps common functions to know where to continue to on completion.

The complete state machine diagram, without failed states, is:

.. mermaid::

    stateDiagram-v2
        %% Server side
        FRESH --> LISTENING_RESOLVING : server
        LISTENING_RESOLVING --> LISTENING : uv_listen

        %% Client side
        state client_host <<choice>>
        FRESH --> client_host : client
        client_host --> BINDING : client_host != null

        BINDING --> CONNECTING_RESOLVING : client_host resolved

        client_host --> CONNECTING_RESOLVING : client_host == null
        CONNECTING_RESOLVING --> CONNECTING : host resolved

        CONNECTING --> CONNECTING_RESOLVING : retry
        CONNECTING --> CONNECTED : uv_tcp_connect

        %% Peer side
        FRESH --> CONNECTED : peer

        %% Disconnect / reconnect
        CONNECTED --> DISCONNECTED : error<br>close
        DISCONNECTED --> RECONNECTING : retry
        RECONNECTING --> FRESH : init

Some failed states give transition to retries / reconnects, others are terminal and close the connection.

Server logic
~~~~~~~~~~~~

The main cycle of a server is the following:
- create a main socket and listen for connections
- on accepting a new connection, creates a new (`peer`) socket to communicate with that client

  - read the request, communicate with the enclave, get the response backs
  - send the response to the client
  - close the socket

There could be several `peer` sockets open communicating with different clients at the same time and it's up to `libuv` to handle the asynchronous tasks.

Here's a diagram of the control flow for a server connection:

.. mermaid::

    graph TD
        subgraph RPCConnections
            rl(listen)
            subgraph RPCServerBehaviour
                rsboa(on_accept)
            end
        end

        subgraph TCPImpl
            tl(listen)
            tr(resolve)
            tor(on_resolved)
            tlr(listen_resolved)
            toa(on_accept)
            tp[TCP peer]
        end

        subgraph NodeConnections
            nctor(NodeConnections)
            subgraph NodeServerBehaviour
                nsboa(on_accept)
            end
        end

        %% Entry Points
        rl --> tl
        nctor --> tl

        %% Listen path
        tl -- LISTENING_RESOLVING --> tr
        tr -. via: DNS::resolve .-> tor
        tor --> tlr
        tlr -. LISTENING<br>via: uv_listen .-> toa
        toa --> rsboa
        toa --> nsboa
        toa ==> tp

The control flow of the `peer` connection is similar to the client (below), but the order is reverse.

The client first writes the request and then waits for the response, while the peer first waits for the request and then writes the response back.

Client logic
~~~~~~~~~~~~

Clients don't have a cycle, as they connect to an existing server, send the request, wait for the response and disconnect.

Clients are used from the enclave side (Node-to-node and RPC), via a `ring buffer` message.

Node-to-node clients are used for pings across nodes, electing a new leader, etc.

RPC clients are used for REST service callbacks from other services, ex. metrics.

Here's the diagram of the client control flow:

.. mermaid::

    graph TD
        subgraph RPCConnections
            rc(connect)
            rw(write)
            subgraph RPCClientBehaviour
                rsbor(on_read)
            end
        end

        subgraph TCPImpl
            tc(connect)
            tocr(on_client_resolved)
            tcb(client_bind)
            tr(resolve)
            tor(on_resolved)
            tcr(connect_resolved)
            toc(on_connect<br>CONNECTED)

            trs(read_start)
            toa(on_alloc)
            tore(on_read)
            tof(on_free)

            tw(write)
            tow(on_write)
            tfw(free_write)
            tsw(send_write)
        end

        subgraph NodeConnections
            ncc(create_connection)
            nw(ccf::node_outbound)
            subgraph NodeConnectionBehaviour
                nsbor(on_read)
            end
        end

        %% Entry Points
        rc --> tc
        ncc --> tc
        rw --> tw
        nw --> tw

        %% Connect path
        tc -- CONNECTING_RESOLVING --> tr
        tc -. BINDING<br>via: DNS::resolve .-> tocr
        tocr --> tcb
        tcb -- uv_tcp_bind<br>CONNECTING_RESOLVING --> tr
        tr -. via: DNS::resolve .-> tor
        tor --> tcr
        tcr -. CONNECTING<br>via: uv_tcp_connect .-> toc
        toc -- retry<br>CONNECTING_RESOLVING --> tcr
        toc -- pending writes --> tw
        toc --> trs

        %% Read path
        trs -. via: uv_read_start .-> toa
        trs -. via: uv_read_start .-> tore
        tore -- DISCONNECTED<br>uv_read_stop --> tof
        tore --> rsbor
        tore --> nsbor

        %% Write path
        tw -- CONNECTED --> tsw
        tw -- DISCONNECTED<br>no data --> tfw
        tsw -. via: uv_write .-> tow
        tow --> tfw

Note that some clients have a `client_host` parameter separate from `host` that is used for testing, and uses the state `BINDING`.

The `client_host` is resolved separately, bound to the client handle (via `uv_tcp_bind`) but the call to `uv_tcp_connect` is done on the `host` address.

This allows us to bind separate addresses to the client side while connecting to the `host`, to allow external packet filters (like `iptables`) to restrict traffic.
