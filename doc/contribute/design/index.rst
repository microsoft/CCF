Design
======

.. note:: The design documentation is mostly targeted to CCF contributors. It does not intend to be a comprehensive coverage of the design of CCF and only details some areas of the project.

Node-to-Node Channels
---------------------

CCF nodes communicate over channels which terminate in each node’s enclave. Channels are used for two purposes:

- Sending integrity-protected consensus headers for ledger replication from the primary to backup nodes, or from a candidate node to other replicas during an election.
- Forwarding encrypted client requests from backups to the primary node for execution.

.. note:: CCF does not use TLS for node-to-node channels for efficiency reasons:

    - The ledger entries to be replicated between nodes are encrypted with the ledger key (AES GCM) and we want to avoid having to encrypt them again once per backup.
    - Headers sent between nodes only contain consensus information that is not confidential and does not need to be encrypted.

Each channel has a corresponding TCP socket opened on the node's untrusted host. Outgoing channels (i.e. those initiated by the local node) are responsible for the lifetime of a client connection on the host, while incoming channels are created when a peer first contact the local node on its well-known node-to-node interface.


Channel Establishment Protocol
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A set of two 256-bit AES-GCM keys are generated for each pair of nodes. Each key is derived from a shared secret established from the authenticated Diffie-Hellman key exchange protocol. Each node's public key share is integrity protected using the node's identity certificate, which is endorsed by the shared service identity.

Replay of previous messages is disallowed by using a monotonic counter as the AES-GCM IV used for each encrypt/integrity-protect operation on the channel. Replayed messages are discarded by the receiving node that keeps track of the sender's last IV (although receiving nodes accept IV forward jumps).

Encryption keys are automatically refreshed periodically (in line with https://datatracker.ietf.org/doc/html/rfc8446#section-5.5) by starting a fresh key-exchange protocol.

.. mermaid::

    sequenceDiagram
        participant Primary as Primary (P)
        participant Backup as Backup (B)

        Backup->>+Primary: Join request over TLS
        Note over Primary: Consortium trusts backup
        Primary-->>+Backup: Service identity S = {S_priv, S_pub} over TLS

        Primary->>+Backup: key_exchange_init: {P's public key share} <br> signed with P's node cert (endorsed by S)

        Note over Backup: Verifies endorsement of P's cert with S_pub <br> Verifies signature with P's cert

        Backup->>+Primary: key_exchange_response: {B's public key share + P's public key share}  <br>  signed with B's node cert (endorsed by S)

        Note over Primary: Verifies endorsement of B's cert with S_pub <br> verifies signature with B's cert

        Note over Primary: Derives channel send and recv keys from shared secret

        Primary->>+Backup: key_exchange_final: {P's public key share + B's public key share}  <br> signed with P's node cert (endorsed by S)

        Note over Backup: Verifies endorsement of P's cert with S_pub <br> Verifies signature with P's cert

        Note over Backup: Derives channel send and recv keys from shared secret

        Note over Primary, Backup: Node-to-node channel between P and B is now established


        Primary->>+Backup: Consensus headers message (e.g. replication) <br> (integrity protected with channel key)
        Backup->>+Primary: Consensus headers response

        Backup->>+Primary: Forwarded client HTTP request <br> (encrypted with channel key)
        Primary->>+Backup: Forwarded client HTTP response


        


