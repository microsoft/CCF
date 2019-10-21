CCF Concepts
============

This page provides a broad overview of the key concepts and components of CCF.

The following diagram shows a CCF network made of 3 nodes, running the same application inside an enclave. The effects of user and member transactions are eventually committed to a replicated encrypted ledger. A consortium of members is in charge of governing the network.

.. image:: ccf_concepts.svg

Network and nodes
-----------------

A CCF network consists of several nodes, each running on top of a Trusted Execution Environment (:term:`TEE`), or enclave, such as :term:`SGX`. As such, a CCF network is decentralised and highly-available.

Nodes are run and maintained by :term:`operators`.

Application
-----------

Each node runs the same application (a.k.a. transaction engine). An application is a collection of endpoints that can be triggered by trusted :term:`users`' :term:`JSON-RPC` requests over :term:`TLS`.

Each endpoint mutates an in-enclave-memory Key-Value Store that is replicated across all nodes in the network. Changes to the Key-Value Store must be agreed by a variable number of nodes, depending on the consensus algorithm selected (either Raft or PBFT), before being applied.

Ledger
------

All changes to the Key-Value Store are encrypted and recorded by each node of the network to disk to a decentralised ledger.

The integrity of the ledger is guaranteed by a Merkle tree whose root is periodically signed by the current primary/leader node.

Governance
----------

A CCF network is governed by a :term:`consortium` of :term:`members`. The :term:`constitution`, recorded in the ledger itself, defines a set of rules that members should follow.

Members can submit proposals to modify the state of the Key-Value Store. For examples, members can decide to allow a new trusted user to issue requests to the application or to add a new member to the consortium.

Proposals are executed only when the conditions defined in the constitution are met (e.g. a majority of members have voted favourably for that proposal).
