Ledger
======

The ledger is the persistent distributed append-only record of the transactions that have been executed by the network. It is written by the primary when a transaction is committed and replicated to all backups which maintain their own duplicated copy.

A node writes its ledger to a directory as specified by the ``--ledger-dir`` command line argument.

Ledger Encryption
-----------------

Each entry in the ledger corresponds to a transaction (or delta) committed by the primary's key-value store.

When a transaction is committed, each affected ``Store::Map`` is serialised in different security domains (i.e. public or private), based on the policy set when the ``Store::Map`` was created (default is private). Public ``Store::Map`` are serialised and stored in the ledger as plaintext while private ``Store::Map`` are serialised and encrypted before being stored.

Ledger entries are integrity-protected and encrypted using a symmetric key shared by all trusted nodes (see :ref:`developers/cryptography:Algorithms and Curves`). This key is kept secure inside each enclave. See :ref:`members/common_member_operations:Rekeying Ledger` for details on how members can rotate the ledger encryption key.

Note that even if a transaction only affects a private ``Store::Map``, unencrypted information such as the version number is always present in the serialised entry. More information about the ledger entry format is available in the :ref:`developers/kv/kv_serialisation:Serialised Transaction Format` section.

Ledger Replication
------------------

The replication process currently uses Raft as the consensus algorithm and therefore the terminology changes slightly. Instead of primary we use the term leader and instead of backup we use the term follower.

As such, the replicated process relies on authenticated Append Entries (AE) headers sent from the leader to followers and which specify the start and end index of the encrypted deltas payload. When an AE header is emitted from a node's enclave for replication, the corresponding encrypted deltas are read from the ledger and appended to the AE header.

The following diagram describes how deltas committed by the leader are written to the ledger and how they are replicated to one follower. Note that the full replication process and acknowledgment from the follower is not detailed here.

.. mermaid::

    sequenceDiagram
        participant Leader KV
        participant Leader Raft
        participant Leader Host
        participant Leader Ledger

        participant Follower Ledger
        participant Follower Host
        participant Follower Raft
        participant Follower KV

        Note left of Leader KV: tx.commit(): Serialise transaction based on maps security domain
        Leader KV->>+Leader Raft: replicate (batch of serialised deltas)

        loop for each serialised delta in batch
            Leader Raft->>+Leader Host: log_append (delta)
            Leader Host->>+Leader Ledger: write(delta)

            Leader Raft->>+Leader Host: node_outbound (AE)
            Leader Raft-->>+Leader KV: replicate success

            Note right of Leader Host: Append Ledger entries to AE
            loop for each entry in AE
                Leader Host->>+Leader Ledger: read(entry's index)
                Leader Ledger-->>Leader Host: delta
            end
            Leader Host->>+Follower Host: TCP packet (AE + deltas)

            Follower Host->>+Follower Raft: node_inbound (AE + deltas)

            Follower Raft->>Follower Raft: recv_authenticated (AE + deltas)
            loop for each delta
                Follower Raft->>Follower Host: log_append (delta)
                Follower Host->>+Follower Ledger: write(delta)
                Follower Raft->>Follower KV: deserialise(delta)
                Follower KV-->>+Follower Raft: deserialise success
            end

        end


Reading and Verifing Ledger
---------------------------

A Python implementation for parsing the ledger can be found in `ledger.py <https://github.com/microsoft/CCF/blob/master/tests/infra/ledger.py>`_.

The ``Ledger`` class is constructed using the path of the ledger. It then exposes an iterator for transaction data structures, where each transaction is composed of the following:

 * The GCM header (gcm_header)
 * The serialised public domain, containing operations made only on public tables (get_public_domain)

.. note:: Parsing the encrypted private data (which begins immediately after the public data on the ledger, and is optional) is not supported by the ``Ledger`` class at the moment.

An example of how to read and verify entries on the ledger can be found in `governance_history.py <https://github.com/microsoft/CCF/blob/master/tests/governance_history.py>`_, which verifies the voting history.
Since every vote request is signed by the voting member, verified by the primary and then stored on the ledger, the test performs the following (this sequence of operations is performed sequentially per transaction):

 1. Read and store the member certificates
 2. Read an entry from the ``ccf.governance.history`` table (each entry in the table contains the member id of the voting member, along with the signed request)
 3. Create a public key using the certificate of the voting member (which was stored on step 1)
 4. Verify the signature using the public key and the raw request
 5. Repeat steps 2 - 4 until all voting history entries have been read