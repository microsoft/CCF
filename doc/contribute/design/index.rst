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

    Note left of Primary: Consortium trusts backup

    Primary-->>+Backup: Service identity {S_priv, S_pub} over TLS



    Note over Primary, Backup: Node-to-node channel establishment starts (over TCP)

    Primary->>+Backup: ECDH_pub_half_P signed with S_priv

    Note over Backup: Backup verifies signature with S_pub. [Shared Secret]

    Backup->>+Primary: ECDH_pub_half_B signed with S_priv

    Note over Primary: Primary verifies signature with S_pub. [Shared Secret]

    Note over Primary, Backup: Node-to-node channel established.

    P and B initialise AES GCM context with Shared Secret.



    Note over Primary: Primary replicates ledger entries...

    Note over Primary: Integrity protect consensus and header with channel AES GCM key

    Note over Primary: Fetches encrypted entries from ledger

    Primary->>+Backup: Integrity-protected consensus hdr + ledger entries

    Note over Backup: Verifies integrity of header and apply ledger entries


