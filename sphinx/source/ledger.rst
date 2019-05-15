Ledger
======

The ledger is the persistent distributed append-only record of the transactions that have been executed by the network. It is written by the leader when a transaction is committed and replicated to all followers which maintain their own duplicated copy.

A node writes its ledger to a file as specified by the ``--ledger-file`` command line argument.

Ledger encryption
-----------------

Each entry in the ledger corresponds to a transaction (or delta) committed by the leader's key-value store.

When a transaction is committed, each affected ``Store::Map`` is serialised in different security domains (i.e. public or private), based on the policy set when the ``Store::Map`` was created (default is private). Public ``Store::Map`` are serialised and stored in the ledger as plaintext while private ``Store::Map`` are serialised and encrypted before being stored.

Note that even if a transaction only affects a private ``Store::Map``, unencrypted information such as the version number is always present in the serialised entry. More information about the ledger entry format is available in the :ref:`protocol` section.

.. note:: Private ``Store::Map`` are encrypted using `GCM`_ by a key (a.k.a. network secrets) shared by all nodes in the CCF network.

.. _`GCM`: https://en.wikipedia.org/wiki/Galois/Counter_Mode

Ledger replication
------------------

The replication process currently uses Raft as the consensus algorithm. As such, it relies on authenticated Append Entries (AE) headers sent from the leader to followers and which specify the start and end index of the encrypted deltas payload. When an AE header is emitted from a node's enclave for replication, the corresponding encrypted deltas are read from the ledger and appended to the AE header.

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