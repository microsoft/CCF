What is CCF?
============

This page gives a broad overview of the fundamentals of CCF. This is where you should start if you're new to CCF.

CCF in a Hundred Words
----------------------

The Confidential Consortium Framework (CCF) is an open-source framework for building a new category of secure, highly-available, and performant applications that focus on multi-party compute and data.

Leveraging the power of trusted execution environments (:term:`TEE`, or enclave), decentralised systems concepts, and cryptography, CCF enables enterprise-ready multiparty systems.

CCF is based on web technologies: clients interact with CCF JavaScript applications over HTTPS.

Core Concepts
-------------

The following diagram shows a basic CCF network made of 3 nodes. All nodes run the same application inside an enclave. The effects of user and member transactions are eventually committed to a replicated encrypted ledger. A consortium of members is in charge of governing the network.

.. image:: ../img/ccf_concepts.svg

Network and Nodes
~~~~~~~~~~~~~~~~~

A CCF network consists of several nodes, each running on top of a Trusted Execution Environment (:term:`TEE`), such as Intel :term:`SGX`. A CCF network is decentralised and highly-available.

Nodes are run and maintained by :term:`Operators`. However, nodes must be trusted by the consortium of members before participating in a CCF network.

.. note:: Find out more about Operators in the :doc:`../operations/index` section.

Application
~~~~~~~~~~~

Each node runs the same application, written in JavaScript or C++. An application is a collection of endpoints that can be triggered by trusted :term:`Users`' HTTP commands over :term:`TLS`.

Each endpoint can mutate or read the in-enclave-memory Key-Value Store that is replicated across all nodes in the network. Changes to the Key-Value Store must be agreed by a variable number of nodes, depending on the consensus algorithm selected (either CFT or BFT), before being applied.

The Key-Value Store is a collection of maps (associating a key to a value) that are defined by the application. These maps can be private (encrypted in the ledger) or public (integrity-protected and visible by anyone that has access to the ledger).

Since all nodes in the CCF network can read the content of private maps, it is up to the application logic to control the access to such maps. Since every application endpoint has access to the identity of the user triggering it, it is easy to restrict which maps (and entries in those maps) a user can read or write to.

.. note:: Find out how to build CCF applications in the :doc:`../build_apps/index` section.

Ledger
~~~~~~

All changes to the Key-Value Store are encrypted and recorded by each node of the network to disk to a decentralised auditable ledger.

The integrity of the ledger is guaranteed by a :term:`Merkle Tree` whose root is periodically signed by the current primary/leader node.

.. note:: Find out how to audit the CCF ledger in the :doc:`../audit/index` section.

Governance
~~~~~~~~~~

A CCF network is governed by a consortium of :term:`Members`. The scriptable :term:`Constitution`, recorded in the ledger itself, defines a set of rules that members must follow.

Members can submit proposals to modify the state of the Key-Value Store. For example, members can vote to allow a new trusted user to issue requests to the application or to add a new member to the consortium.

Proposals are executed only when the conditions defined in the constitution are met (e.g. a majority of members have voted favourably for that proposal).

.. note:: Find out more about member governance in the :doc:`../governance/index` section.