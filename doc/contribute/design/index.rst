Design
======

.. note:: The design documentation is mostly targeted at CCF contributors and does not intend to be a comprehensive coverage of the design of CCF and only details some areas of the project.

Node-to-Node Channels
---------------------

.. note:: Only applicable for CFT consensus

CCF nodes communicate over channels which terminate in each node’s enclave. Channels are used for two purposes:

- Sending integrity-protected consensus headers for ledger replication from the primary to backup nodes, or from a candidate node to other replicas during an election.
- Forwarding encrypted client requests from backups to the primary node for execution.

.. note:: CCF does not TLS for node-to-node channels for efficiency reasons:

    - The ledger entries to be replicated between nodes are encrypted with the ledger key (AES GCM) and we want to avoid having to encrypt them again once per backup.
    - Headers sent between nodes only contain consensus information that is not confidential and does not need to be encrypted.


Protocol
~~~~~~~~

.. mermaid::

    sequenceDiagram
        participant Primary as Primary (P)
        participant Backup as Backup (B)

        Backup->>+Primary: Join request over TLS
        Note over Primary: Consortium trusts backup
        Primary-->>+Backup: Service identity S = {S_priv, S_pub} over TLS


        Note over Primary, Backup: Node-to-node channel establishment starts (over TCP)

        Primary->>+Backup: key_exchange_init: {P's public key share} signed with P's node cert (endorsed by S)

        Note over Backup: Verifies endorsement of P's cert with S_pub <br> verifies signature with P's cert

        Backup->>+Primary: key_exchange_final: {B's public key share + P's public key share} signed with B's node cert (endorsed by S)

        Note over Primary: Verifies endorsement of B's cert with S_pub <br> verifies signature with B's cert

        Note over Primary: Derives channel send and recv keys from shared secret

        Primary->>+Backup: key_exchange_final: {P's public key share + B's public key share} signed with P's node cert (endorsed by S)

        Note over Backup: Verifies endorsement of P's cert with S_pub <br> verifies signature with P's cert

        Note over Backup: Derives channel send and recv keys from shared secret






        Note over Primary: Primary replicates ledger entries...

        Note over Primary: Integrity protect consensus and header with channel AES GCM key

        Note over Primary: Fetches encrypted entries from ledger

        Primary->>+Backup: Integrity-protected consensus hdr + ledger entries

        Note over Backup: Verifies integrity of header and apply ledger entries


        


