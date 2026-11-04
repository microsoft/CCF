TCP Internals
=============

Overview
~~~~~~~~

CCF's node-to-node :term:`TCP` transport uses `libuv <https://libuv.org/>`_ to listen for connections from other nodes and connect to peers.
This document describes that transport, not the client-facing :term:`RPC` stack.
RPC connections use a separate socket and session implementation, with OpenSSL terminating :term:`TLS` in the connection layer; see :doc:`tls_internals` for the current RPC/TLS design.

Overall structure
~~~~~~~~~~~~~~~~~

:ccf_repo:`TCPImpl </src/host/tcp.h>` implements asynchronous socket handling using ``libuv``.
:ccf_repo:`NodeConnectionsImpl </src/host/node_connections.h>` uses it to implement the node's typed :ccf_repo:`AbstractNodeTransport </src/node/node_transport.h>` interface.
Socket operations and connection state are owned by the libuv loop thread.

``TCPImpl`` uses behaviour classes to separate generic socket handling from protocol-specific callbacks such as ``on_accept`` and ``on_read``:

- ``NodeServerBehaviour`` handles the listening socket and creates a peer socket for each accepted connection.
- ``NodeIncomingBehaviour`` handles an accepted connection and associates it with a peer node.
- ``NodeOutgoingBehaviour`` handles a connection opened to a peer node.
- ``NodeConnectionBehaviour`` is the common base for incoming and outgoing connections and assembles complete node frames from received bytes.

.. mermaid::

    graph BT
        NodeConnectionBehaviour --> SocketBehaviour
        NodeIncomingBehaviour --> NodeConnectionBehaviour
        NodeOutgoingBehaviour --> NodeConnectionBehaviour
        NodeServerBehaviour --> SocketBehaviour

Inbound and outbound messages
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Incoming connections carry length-prefixed frames, not HTTP requests.
``NodeConnectionBehaviour::on_read`` buffers partial frames, checks the configured maximum frame size, and extracts the message type and sender node ID.
Complete payloads are copied into owned buffers and passed to the node's inbound handler on the libuv thread.
The node queues their processing through :ccf_repo:`NodeIngress </src/node/node_inbound_message.h>`.
The transport's association of a connection with a node ID is not authentication; authenticated node-to-node channels protect the messages above this TCP layer.

Before dispatching a consensus message to Raft, the channels layer verifies the legacy consensus header and its replay counter, then passes separate header and ledger-body views that omit the channel tag.
Neither view copies or modifies the owned inbound buffer.
The consensus receive API takes a ``message`` span containing only the Raft message struct and an optional ``payload`` span containing appended ledger bytes.
The payload defaults to an empty view for messages without appended entries, including heartbeats.
Those ledger bytes are not authenticated by the legacy channel and retain their independent ledger validation.
Raft consumes the normalized buffer synchronously, while the inbound handler retains ownership.

Outbound transport operations may be submitted from any thread.
Sends, address updates, and closes first pass through the same ordered task lane as ledger mutations.
This ensures that an ``AppendEntries`` message reads ledger entries only after preceding appends have been applied and preserves the order of transport operations.
The assembled frames and control operations are queued for the libuv thread, which drains them in ``flush_outbound()``.
The transport creates an outgoing connection when needed and reuses connections for subsequent messages rather than disconnecting after each request/response exchange.

.. mermaid::

    flowchart LR
        Socket["TCP peer socket"] --> Frame["NodeConnectionBehaviour"]
        Frame --> Inbound["Owned payload / inbound handler"]
        Inbound --> Ingress["NodeIngress"]
        Node["Node / worker threads"] --> Lane["Ordered ledger task lane"]
        Lane --> Ready["Ready outbound queue"]
        Ready --> Flush["flush_outbound on libuv thread"]
        Flush --> Socket

State machine
~~~~~~~~~~~~~

``TCPImpl`` has an internal state machine whose transitions are driven by libuv callbacks.
It supports listeners, accepted peer sockets, and outgoing connections.
The successful paths, address-family fallback, and disconnect transitions are:

.. mermaid::

    stateDiagram-v2
        FRESH --> LISTENING_RESOLVING : server
        LISTENING_RESOLVING --> LISTENING : uv_listen

        state client_host <<choice>>
        FRESH --> client_host : client
        client_host --> BINDING : client_host != null
        BINDING --> CONNECTING_RESOLVING : client_host resolved
        client_host --> CONNECTING_RESOLVING : client_host == null
        CONNECTING_RESOLVING --> CONNECTING : host resolved
        CONNECTING_RESOLVING --> RECONNECTING : address family changed
        RECONNECTING --> FRESH : handle reinitialised
        FRESH --> CONNECTING_RESOLVING : resume address-family fallback
        CONNECTING --> CONNECTING_RESOLVING : retry
        CONNECTING --> CONNECTED : uv_tcp_connect

        FRESH --> CONNECTED : peer
        CONNECTED --> DISCONNECTED : error / close

Connection attempts may retry the next resolved address, resetting the socket handle if its address family changes.
Disconnection is terminal for a ``TCPImpl`` instance; ``NodeConnectionsImpl`` removes it.
A subsequent send attempts to create a connection if none exists and the peer's address is known; connection creation may fail.
Accepted and outgoing sockets both read and write node messages once connected.
Libuv reports read and write completion asynchronously, so the loop can handle multiple peer connections concurrently.

An outgoing connection may specify a ``client_host`` separately from the destination ``host``.
It is resolved and bound locally with ``uv_tcp_bind`` before connecting to the destination with ``uv_tcp_connect``.
Tests use this to give connections distinct source addresses so that packet filters such as ``iptables`` can selectively restrict traffic.
