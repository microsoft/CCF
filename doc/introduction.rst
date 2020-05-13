Introduction
============

Overview
--------

.. image:: img/ccf.svg
  :width: 250
  :align: right

The Confidential Consortium Framework (CCF) is an open-source framework for building a new category of secure, highly available,
and performant applications that focus on multi-party compute and data. While not limited just to blockchain applications,
CCF can enable high-scale, confidential blockchain networks that meet key enterprise requirements
— providing a means to accelerate production enterprise adoption of blockchain technology.

Leveraging the power of trusted execution environments (:term:`TEE`), decentralized systems concepts, and cryptography,
CCF enables enterprise-ready computation or blockchain networks that deliver:

 * **Throughput and latency approaching database speeds.** Through its use of TEEs, the framework creates a network of remotely attestable enclaves.
   This gives a web of trust across the distributed system, allowing a user that verifies a single cryptographic quote from a CCF node to
   effectively verify the entire network. This simplifies consensus and thus improves transaction speed and latency — all without compromising security or assuming trust.

 * **Richer, more flexible confidentiality models.** Beyond safeguarding data access with encryption-in-use via TEEs, we use industry standards (:term:`TLS` and remote attestation)
   to ensure secure node communication. Transactions can be processed in the clear or revealed only to authorized parties, without requiring complicated confidentiality schemes.

 * **Network and service policy management through non-centralized governance.** The framework provides a network and service configuration to express and manage consortium
   and multi-party policies. Governance actions, such as adding members to the governing consortium or initiating catastrophic recovery, can be managed and recorded through
   standard ledger transactions agreed upon via stakeholder voting.

 * **Improved efficiency versus traditional blockchain networks.** The framework improves on bottlenecks and energy consumption by eliminating computationally intensive
   consensus algorithms for data integrity, such as proof-of-work or proof-of-stake.

A consortium first approach
---------------------------

In a public blockchain network, anyone can transact on the network, actors on the network are pseudo-anonymous and untrusted, and anyone can add nodes to the network
— with full access to the ledger and with the ability to participate in consensus. Similarly, other distributed data technologies (such as distributed databases)
can have challenges in multi-party scenarios when it comes to deciding what party operates it and whether that party could choose or could be compelled to act maliciously.

In contrast, in a consortium or multi-party network backed by TEEs, such as CCF, consortium member identities and node identities are known and controlled.
A trusted network of enclaves running on physical nodes is established without requiring the actors that control those nodes to trust one another
—  what code is run is controlled and correctness of its output can be guaranteed, simplifying the consensus methods and reducing duplicative validation of data.

Microsoft has taken this approach in developing CCF: using :term:`TEE` technology, the enclave of each node in the network (where cryptographically protected data is processed)
can decide whether it can trust the enclaves of other nodes based on mutual attestation exchange and mutual authentication, regardless of whether the parties involved
trust each other or not. This enables a network of verifiable, remotely attestable enclaves on which to run a distributed ledger and execute confidential and secure
transactions in highly performant and highly available fashion.


A flexible confidentiality layer for multi-party computation
------------------------------------------------------------

CCF currently runs on Intel :term:`SGX`-enabled platforms. Because CCF uses the :term:`Open Enclave` SDK
as the foundation for running in an enclave, as :term:`Open Enclave` supports new TEE technologies, CCF will be able to run on new platforms. Networks can be run on-premises,
in one or many cloud-hosted data centers, including :term:`Microsoft Azure`, or in any hybrid configuration.

Ledger providers can use CCF to enable higher throughput and higher confidentiality guarantees for distributed ledger applications.
CCF developers can write application logic (also known as smart contracts) and enforce application-level access control in several languages by conﬁguring CCF
to embed one of several language runtimes on top of its key-value store. Clients then communicate with a running CCF service over :term:`TLS`.
