Introduction
============

Overview
--------

The purpose of a CCF network is to run a highly secure, highly available, and high performance multi-party computation (MPC) application.

The CCF framework makes this possible by providing a key-value store replicated across a network of nodes running in Trusted Execution Environments (TEE).
They communicate with each other over secure channels based on TLS and Intel SGX remote attestations, on top of which they run a conventional
Crash Fault Tolerant Replication (CFTR) protocol, Raft [#raft]_.

.. mermaid::

    graph TB
        cl(Client) -- JSON-RPC over TLS --- ch(CCF Host)
        ch -- Consensus Protocol --- ocn(Other CCF Nodes)
        ch(CCF Host) -- TLS --- ce(CCF Enclave)
        subgraph Enclave
        ce(CCF Enclave) -- KV Store Transactions --- ue(Application)
        end

Trusted Execution
-----------------

CCF relies on OpenEnclave [#oe]_ for trusted execution.

Consensus
---------

Consensus between the nodes participating in a CCF network is maintained by an implementation of the Raft [#raft]_ algorithm.

Blockchain
----------

A CCF network writes an immutable continuous (and often encrypted) transaction log for the key-value store.
The log resembles a blockchain and enables disaster recovery and audits.

Governance
----------

The configuration of the network is stored in the replicated key-value store itself.
Stakeholders of the network, referred to as members, can dynamically change this configuration through votes.
The rules for voting are determined by the network's constitution. 

.. rubric:: Footnotes

.. [#raft] `Raft Consensus Algorithm (PDF) <https://raft.github.io/raft.pdf>`_.
.. [#oe] `OpenEnclave SDK <https://openenclave.io/sdk/>`_.