Glossary
========

.. glossary::  
  Azure Confidential Compute
    `Azure Confidential Compute <https://azure.microsoft.com/en-us/solutions/confidential-compute/>`_ protects the confidentiality and integrity of your data and code while it's processed in the public cloud.

  Constitution
    JavaScript module that defines possible governance actions, and how members' proposals are validated, resolved and applied to the service.

  Commit Evidence
    A :ref:`unique string <use_apps/verify_tx:Commit Evidence>` produced per transaction, and included in the Merkle Tree along with the :term:`Write Set` digest and the `claims_digest`. The reveal of that string guarantees the transaction is committed.

  CFT
    Crash Fault Tolerance is a type of fault tolerance that allows the system to tolerate network and node failures up to
    a given limit. CFT however does not account for any nodes behaving maliciously. Read more on CFT :ref:`here <architecture/consensus/index:Consensus Protocol>`.

  Enclave
    `Trusted Execution Environments <https://en.wikipedia.org/wiki/Trusted_execution_environment>`_, allowing fully encrypted and auditable execution without direct access from the host machine.

  Members
    Constitute the consortium governing a CCF network. Their public identity should be registered in CCF.

  Merkle Tree
    `Tree structure <https://en.wikipedia.org/wiki/Merkle_tree>`_ which records the hash of every transaction and guarantees the integrity of the CCF ledger.

  Microsoft Azure
    `Microsoft Azure <https://azure.microsoft.com>`_ is a cloud computing service created by Microsoft for building, testing, deploying, and managing applications and services through Microsoft-managed data centers.

  Node identity
    The public identity of a node in a service, represented as an X.509 certificate containing an endorsement from the :term:`Service Identity`. It is used to issue transaction receipts. See :ref:`here <architecture/Cryptography:Node>` for more detail.

  Omission Fault
    Type of failure where consensus messages exchanged between nodes are lost due to unreliable network. This may cause one or more nodes to be isolated from the rest of the network.

  Operators
    Are in charge of operating a CCF network (e.g. adding or removing nodes). Their identities are not registered in CCF.

  Ring Buffer
    The ring buffer is a data structure that allows communication between the (unprotected) host and the enclave. Data that is written to one side can be read on the other. Only specific types of messages are supported to make sure each package that goes across is read by the right process in the right way.

  REST
    `Representational state transfer <https://en.wikipedia.org/wiki/Representational_state_transfer>`_ is a set of constraints on web APIs, usually implemented over HTTP using JSON as request and response objects exchanged between a requesting client and an implementation server.

  RPC
    `Remote Procedure Call <https://en.wikipedia.org/wiki/Remote_procedure_call>`_ is a way to execute functions in remote machines. CCF uses :term:`REST` host services to allow clients to execute programs inside the :term:`enclave` via the :term:`ring buffer`.

  Service identity
    The public identity of the CCF service, represented as an X.509 certificate. It is used to authenticate the service to clients and other nodes. See :ref:`here <architecture/Cryptography:Service>` for more detail.

  SEV-SNP
    `AMD Secure Encrypted Virtualisation - Secure Nested Paging <https://www.amd.com/en/processors/amd-secure-encrypted-virtualization>`_ is a trusted execution environment platform. It is a technology used to isolate virtual machines from the hypervisor with strong memory integrity protection.

  TCP
    `Transmission Control Protocol <https://en.wikipedia.org/wiki/Transmission_Control_Protocol>`_ is a network protocol over IP that provides sessions and ordered streams, which we use to connect between nodes and external clients.

  TEE
    `Trusted Execution Environment <https://en.wikipedia.org/wiki/Trusted_execution_environment>`_ is a secure area of a main processor. It guarantees code and data loaded inside to be protected with respect to confidentiality and integrity. Often referred to as "enclave".

  TLS
    `Transport Layer Security <https://en.wikipedia.org/wiki/Transport_Layer_Security>`_ is an IETF cryptographic protocol standard designed to secure communications between a client and a server over a computer network.

  Transaction ID
    Unique transaction identifier in CCF, composed of a View and a Sequence Number separated by a period. Sequence Numbers start from 1, and are contiguous. Views are monotonic. E.g. The transaction ID ``2.15`` indicates the View is ``2`` and the Sequence Number is ``15``. Sequence Numbers are also referred to as a :cpp:type:`ccf::kv::Version` in the context of the Key-Value store.

  Users
    Directly interact with the application running in CCF. Their public identity should be voted in by members before they are allowed to issue requests.

  Write Set
    The keys and values written to during a CCF transaction. The state of the Key Value store at a given :term:`Transaction ID` is logically the successive application of all write sets up to that point.
