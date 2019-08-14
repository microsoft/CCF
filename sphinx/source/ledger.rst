Ledger
======

The ledger is the persistent distributed append-only record of the transactions that have been executed by the network. It is written by the primary when a transaction is committed and replicated to all backups which maintain their own duplicated copy.

A node writes its ledger to a file as specified by the ``--ledger-file`` command line argument.

Ledger encryption
-----------------

Each entry in the ledger corresponds to a transaction (or delta) committed by the primary's key-value store.

When a transaction is committed, each affected ``Store::Map`` is serialised in different security domains (i.e. public or private), based on the policy set when the ``Store::Map`` was created (default is private). Public ``Store::Map`` are serialised and stored in the ledger as plaintext while private ``Store::Map`` are serialised and encrypted before being stored.

Note that even if a transaction only affects a private ``Store::Map``, unencrypted information such as the version number is always present in the serialised entry. More information about the ledger entry format is available in the :ref:`protocol` section.

.. note:: Private ``Store::Map`` are encrypted using `GCM`_ by a key (a.k.a. network secrets) shared by all nodes in the CCF network.

.. _`GCM`: https://en.wikipedia.org/wiki/Galois/Counter_Mode

Ledger replication
------------------

The replication process currently uses Raft as the consensus algorithm. As such, it relies on authenticated Append Entries (AE) headers sent from the primary to backups and which specify the start and end index of the encrypted deltas payload. When an AE header is emitted from a node's enclave for replication, the corresponding encrypted deltas are read from the ledger and appended to the AE header.

The following diagram describes how deltas committed by the primary are written to the ledger and how they are replicated to one backup. Note that the full replication process and acknowledgment from the backup is not detailed here.

.. mermaid::

    sequenceDiagram
        participant Primary KV
        participant Primary Raft
        participant Primary Host
        participant Primary Ledger

        participant Backup Ledger
        participant Backup Host
        participant Backup Raft
        participant Backup KV

        Note left of Primary KV: tx.commit(): Serialise transaction based on maps security domain
        Primary KV->>+Primary Raft: replicate (batch of serialised deltas)

        loop for each serialised delta in batch
            Primary Raft->>+Primary Host: log_append (delta)
            Primary Host->>+Primary Ledger: write(delta)

            Primary Raft->>+Primary Host: node_outbound (AE)
            Primary Raft-->>+Primary KV: replicate success

            Note right of Primary Host: Append Ledger entries to AE
            loop for each entry in AE
                Primary Host->>+Primary Ledger: read(entry's index)
                Primary Ledger-->>Primary Host: delta
            end
            Primary Host->>+Backup Host: TCP packet (AE + deltas)

            Backup Host->>+Backup Raft: node_inbound (AE + deltas)

            Backup Raft->>Backup Raft: recv_authenticated (AE + deltas)
            loop for each delta
                Backup Raft->>Backup Host: log_append (delta)
                Backup Host->>+Backup Ledger: write(delta)
                Backup Raft->>Backup KV: deserialise(delta)
                Backup KV-->>+Backup Raft: deserialise success
            end

        end


Reading the ledger and verifying entries
----------------------------------------

The ledger is stored as a series of a 4 byte transaction length field followed by a transaction (as described on the :ref:`protocol` section).

A python implementation for parsing the ledger can be found on ledger.py.

The ``Ledger`` class is constructed using the path of the ledger. It then exposes an iterator for transaction data structures, where each transaction is composed of the following:

 * The GCM header (gcm_header)
 * The serialised public domain, containing operations made only on public tables (get_public_domain)

.. note:: Parsing the encrypted private data (which begins immediately after the public data on the ledger, and is optional) is not supported by the ``Ledger`` class at the moment. This will be added at a later stage.
..

An example of how to read and verify entries on the ledger can be found on ``votinghistory.py``, which verifies the voting history.
Since every vote request is signed by the requesting member, verified by the primary and then stored on the ledger, the test performs the following (this sequence of operations is performed sequentially per transaction):
 1. Read and store the member certificates
 2. Read an entry from the ``votinghistory`` table (each entry on the ``votinghistory`` table contains the member id of the voting member, along with the signed request)
 3. Create a public key using the certificate of the voting member (which was stored on step 1)
 4. Verify the signature using the public key and the raw request
 5. Repeat steps 2 - 4 until all voting history entries have been read