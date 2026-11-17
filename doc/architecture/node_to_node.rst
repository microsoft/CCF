Node-to-Node Channels
=====================

CCF nodes communicate over authenticated channels whose cryptographic endpoints are inside each node's TEE.
Channels are used for two purposes:

- Sending integrity-protected consensus headers for ledger replication from the primary to backup nodes, or from a candidate node to other replicas during an election.
- Forwarding encrypted client requests from backups to the primary node for execution.

Opt-in TLS Transport
~~~~~~~~~~~~~~~~~~~~

CCF supports mutually authenticated TLS 1.3 alongside its legacy channel protocol.
Configure ``network.node_to_node_tls_interface`` to enable the TLS listener and outbound TLS.
A pair uses TLS only when the local configuration enables it and the peer's recorded node metadata includes a TLS endpoint; all other pairs use legacy channels.
A TLS connection failure never triggers a downgrade to legacy.
The existing ``network.node_to_node_interface`` remains required in this bridge release.
See :doc:`/operations/configuration` for configuration and :doc:`/releases/migration_7_x_to_8_x` for upgrade preparation.

TLS authenticates existing service-endorsed node certificates, binds the peer node ID to the certificate's public key, and deliberately ignores certificate expiry as legacy channels do.
Certificate renewal with unchanged keys updates future handshakes without reconnecting established streams.
Consensus receives authenticated, normalized headers and ledger payloads only after TLS admission.
Ledger encryption and integrity checks remain independent and unchanged.
AppendEntries frames are assembled, including ledger bytes, on the ledger-mutation lane after the preceding ledger writes.
Both transports use :ccf_repo:`send_node_frame </src/host/node_frame.h>` for this ordering and assembly; it is independent of the legacy socket implementation.

The temporary :ccf_repo:`NodeChannelBridge </src/node/node_channel_bridge.h>` and :ccf_repo:`NodeTransportBridge </src/host/node_transport_bridge.h>` adapt the two backends during migration and are removed with legacy interoperability.
:ccf_repo:`Bridge tests </tests/n2n_transport_bridge.py>` cover legacy-only and mixed networks, while :ccf_repo:`TLS tests </tests/n2n_tls.py>` retain the all-TLS lifecycle coverage.

Consensus and forwarded requests/responses use separate TLS connections on one listener.
ALPN identifiers ``ccf-consensus/1`` and ``ccf-forwarding/1`` distinguish their protocols; other or absent ALPN is rejected.
Each sender owns one outbound stream per peer and purpose, independently of incoming streams, avoiding simultaneous-dial arbitration.
There is no ordering between forwarding and consensus streams.
Forwarding remains supported without a separate enablement flag.

The shared :doc:`tls_internals` engine enforces the TLS 1.3 AES-GCM sending-key policy.
If blocked control output aborts a connection, later sends establish a fresh authenticated connection.
Consensus retries replication through its existing protocol; forwarded calls are never automatically replayed and may return the existing forwarding timeout.
Idle streams expire after four election timeouts.

This transport connects trusted service nodes; operators must restrict network access to the node-to-node ports to those nodes.
Its resource policy aims for parity with legacy channels, not general-purpose listener or memory-exhaustion protection.
While establishing each outgoing TLS stream, the owner retains only the latest consensus message or up to ten forwarded messages in arrival order.
Additional forwarding sends report failure to the caller.
Ledger frame assembly is deferred until the stream is authenticated, so replaced consensus messages do not trigger ledger reads.
Failed establishment discards queued messages rather than replaying them on another connection.
Once established, streams use the shared engine's existing buffering and backpressure without an aggregate memory budget.
The configured ``node_to_node.max_message_size`` still limits individual incoming frames; vector capacity reuse and memory use with slow established peers are not given stronger guarantees than the legacy transport.

Legacy Channels
~~~~~~~~~~~~~~~

The remaining sections describe the legacy protocol.
Legacy headers contain consensus information that is integrity protected but not encrypted; replicated ledger entries are independently encrypted with the ledger key.
Each legacy channel has a corresponding TCP socket, managed by the node's I/O layer (see :doc:`tcp_internals`).
The network and host infrastructure are untrusted, so legacy channels rely on their own cryptographic protection rather than on the transport.
Outgoing channels (i.e. those initiated by the local node) are responsible for the lifetime of an outgoing TCP connection, while incoming channels are created when a peer first contacts the local node on its well-known node-to-node interface.


Channel Establishment Protocol
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A set of two 256-bit AES-GCM keys are generated for each pair of nodes. Each key is derived from a shared secret established from the authenticated Diffie-Hellman key exchange protocol. Each node's public key share is integrity protected using the node's identity certificate, which is endorsed by the shared :term:`Service Identity`.

Replay of previous messages is disallowed by using a monotonic counter as the AES-GCM IV used for each encrypt/integrity-protect operation on the channel. Replayed messages are discarded by the receiving node that keeps track of the sender's last IV (although receiving nodes accept IV forward jumps).

Encryption keys are automatically refreshed periodically (in line with https://datatracker.ietf.org/doc/html/rfc8446#section-5.5) by starting a fresh key-exchange protocol.

The following diagram shows how this key-exchange protocol executes when a new node is added to the network, with the contents of each message.

.. mermaid::
    :config: {sequence: {width: 280}}

    sequenceDiagram
        participant Primary as Primary (P)
        participant Backup as Backup (B)

        Backup->>+Primary: Join request over TLS
        Note over Primary: Consortium trusts backup
        Primary-->>+Backup: Service identity S = {S_priv, S_pub} over TLS

        Primary->>+Backup: key_exchange_init: {P's public key share} signed with P's node cert (endorsed by S)

        Note over Backup: Verifies endorsement of P's cert with S_pub Verifies signature with P's cert

        Backup->>+Primary: key_exchange_response: {B's public key share + P's public key share} signed with B's node cert (endorsed by S)

        Note over Primary: Verifies endorsement of B's cert with S_pub verifies signature with B's cert

        Note over Primary: Derives channel send and recv keys from shared secret

        Primary->>+Backup: key_exchange_final: {P's public key share + B's public key share} signed with P's node cert (endorsed by S)

        Note over Backup: Verifies endorsement of P's cert with S_pub Verifies signature with P's cert

        Note over Backup: Derives channel send and recv keys from shared secret

        Note over Primary, Backup: Node-to-node channel between P and B is now established

        Primary->>+Backup: Consensus headers message (e.g. replication) (integrity protected with channel key)
        Backup->>+Primary: Consensus headers response

        Backup->>+Primary: Forwarded client HTTP request (encrypted with channel key)
        Primary->>+Backup: Forwarded client HTTP response

This diagram shows the state machine for a channel on each node, with the messages that trigger each transition.

.. mermaid::

    stateDiagram-v2
        [*] --> INACTIVE
        INACTIVE --> INITIATED: initiate()
        INITIATED --> ESTABLISHED: key_exchange_response

        INACTIVE --> WAITING_FOR_FINAL: key_exchange_init
        INITIATED --> WAITING_FOR_FINAL: key_exchange_init (higher priority)
        WAITING_FOR_FINAL --> ESTABLISHED: key_exchange_final

        %%INITIATED --> INACTIVE: close()
        %%WAITING_FOR_FINAL --> INACTIVE: close()
        %%ESTABLISHED --> INACTIVE: close()

The brief sequence diagram of a successful key exchange is as follows.

.. mermaid::

    sequenceDiagram
        participant Node1 as Node1 (A)
        participant Node2 as Node2 (B)

        Note over Node1: state := Initiated
        Node1->>+Node2: key_exchange_init

        Note over Node2: state := WaitingForFinal
        Node2->>+Node1: key_exchange_response

        Note over Node1: state := Established
        Node1->>+Node2: key_exchange_final

        Note over Node2: state := Established

However, if messages are dropped this protocol can reach various deadlocked states. Once the channel is established we are able to process dropped and reordered messages on the receiving end, so we should also be robust to these during channel establishment. Even with perfect network conditions and honest hosts, if we want to support legitimate closure of channels then we should be robust to this happening during key establishment. The following diagram shows some of the issues when key exchange messages are dropped.

.. mermaid::

    sequenceDiagram
        participant N1 as Node 1
        participant Node1 as Node1 Channel
        participant Node2 as Node2 Channel
        participant N2 as Node 2

        N1 ->>+ Node1: send(2, M)
        Note over Node1: state := Initiated

        alt init dropped
            Node1 --x Node2: init

            rect rgba(200, 10, 10, .5)
                N2 ->>+ Node2: send(1, N)
                Note over Node2: state := Initiated
                Node2-->>+Node1: init
                Note over Node1: Ignored if lower-priority
            end
        else init delivered
            Node1-->>+Node2: init
            Note over Node2: state := WaitingForFinal

            alt response dropped
                Node2 --x Node1: response

                rect rgba(200, 10, 10, .5)
                    N2 ->>+ Node2: send(1, N)
                    Note over Node2: Ignored due to WaitingForFinal
                end

                rect rgba(200, 10, 10, .5)
                    N1 ->>+ Node1: send(2, M)
                    Node1-->>+Node2: init
                    Note over Node2: Ignored due to WaitingForFinal
                end
            else response delivered
                Node2-->>+Node1: response
                Note over Node1: state := Established

                alt final dropped
                    Node1 --x Node2: final

                    rect rgba(200, 10, 10, .5)
                        Node1-->>+Node2: encrypted(M)
                        Note over Node2: Unable to decrypt M
                    end

                    rect rgba(200, 10, 10, .5)
                        N2 ->>+ Node2: send(1, N)
                        Node2-->>+Node1: init
                        Note over Node1: Ignored if lower-priority
                    end

                else final delivered
                    Node1-->>+Node2: final
                    Note over Node2: state := Established

                    rect rgba(10, 200, 10, .3)
                        Node1-->>+Node2: encrypted(M)
                        Note over Node1: Successfully decrypted M

                        Node2-->>+Node1: encrypted(N)
                        Note over Node1: Successfully decrypted N
                    end
                end
            end
        end

To be robust to this, I think we need to reason about what a node should do in response to each type of message, in each state. An initial approach to this is summarised by the following proposed flowchart.

.. mermaid::

    graph TD
        %% Every emit is currently actually only done the first time
        s_unknown(Unknown)
        s_inactive(state:=INACTIVE)
        s_initiated(state:=INITIATED)
        s_waiting(state:=WAITING_FOR_FINAL)
        s_established(state:=ESTABLISHED)

        s_generate[Generate key]
        s_queue_new(outgoing:=M)
        s_emit_kei[Emit key_exchange_init]
        s_queue_new_init(Outgoing:=M')
        s_emit_ker[Emit key_exchange_response]
        s_use_key[Use their key]
        s_queue_new_waiting(Outgoing:=M')
        s_emit_kef[Emit key_exchange_final]
        s_dual_kei{Which has priority?}

        s_unknown =="receive|send"==> s_inactive
        s_inactive =="send(M)"==> s_queue_new
        s_queue_new ==> s_generate

        %% They're trying to talk to us, but we're not in the right state! Help
        %% them start over
        s_inactive --"receive(response)|receive(final)"--> s_generate

        s_generate ==> s_emit_kei

        s_emit_kei ==> s_initiated

        s_initiated --"send(M')"--> s_queue_new_init
        s_queue_new_init --> s_emit_kei
        s_initiated --> s_emit_kei

        s_initiated =="receive(response)"==> s_emit_kef
        s_established --"receive(response)"--> s_emit_kef
        s_emit_kef ==> s_established
        
        s_initiated --"receive(init)"--> s_dual_kei
        s_dual_kei --I win--> s_emit_kei
        s_dual_kei --They win--> s_use_key
        s_use_key ==> s_emit_ker

        s_inactive =="receive(init)"==> s_use_key
        s_emit_ker ==> s_waiting
        
        s_waiting --"send(M')"--> s_queue_new_waiting
        s_queue_new_waiting --> s_emit_ker

        s_waiting --"receive(init)"--> s_emit_ker
        s_waiting --"receive(response)"--> s_waiting
        s_waiting =="receive(final)"====> s_established

        s_initiated-."close()"....-> s_inactive
        s_waiting-."close()"....-> s_inactive
        s_established-."close()"....-> s_inactive

This does not yet deal with key rotation, and I believe we need an establishment-attempt nonce to prevent replay attacks that could re-establish an old, overused key. While the summary above says we start a fresh key-exchange protocol, the actual implementation attempts to do this in parallel with encrypted messages over an existing channel. If we build a protocol which can reliably deal with legitimate reconnection attempts, it would be preferable to re-use that for key rotation - deliberately close an existing connection and start fresh with a new channel - rather than building an additional rotation protocol.

An open question here is whether we need to handle channel closures and re-opening. If we do not, then we can consider all dropped messages here as malicious DoS, but perhaps simplify the protections. One option is to avoid ever closing a channel - if a node has opened a channel to another node, it remains communicating with them forever. Another is to determine a point after which a channel can be safely closed - if the channel is used only for consensus and not forwarding, it may be safe to close after a node's retirement.
