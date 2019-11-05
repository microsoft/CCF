Glossary
========

.. glossary::

  Azure Confidential Compute
    `Azure Confidential Compute <https://azure.microsoft.com/en-us/solutions/confidential-compute/>`_ protects the confidentiality and integrity of your data and code while it’s processed in the public cloud.

  Consensus Protocols
    The term Consensus protocol refers to either Raft or PBFT. Generic Consensus terminology will use `primary` node and `backup` node to indicate node responsibility in carrying out the protocol(s). These correspond in Raft to `leader` and `follower`.

  Constitution
    Set of rules written as a Lua script that define how members' proposals are accepted.

  FLC
    `Flexible Launch Control <https://github.com/intel/linux-sgx/blob/master/psw/ae/ref_le/ref_le.md#flexible-launch-control>`_ is a feature of the Intel :term:`SGX` architecture.

  JSON-RPC
    `JSON-RPC <https://en.wikipedia.org/wiki/JSON-RPC>`_ is a remote procedure call protocol encoded in JSON. It is the format used by clients (i.e. members, users and operators) to interact with CCF.

  Members
    Constitute the consortium governing a CCF network. Their public identity should be registered in CCF.

  Microsoft Azure
    `Microsoft Azure <https://azure.microsoft.com>`_ is a cloud computing service created by Microsoft for building, testing, deploying, and managing applications and services through Microsoft-managed data centers.

  Open Enclave
    `Open Enclave SDK <https://openenclave.io/sdk>`_ is an SDK for building enclave applications in C and C++.

  Operators
    Are in charge of operating a CCF network (e.g. adding or removing nodes). Their identities are not registered in CCF.

  Open Enclave Engine
    `Open Enclave Engine <https://github.com/Microsoft/oe-engine>`_ is a template generation tool for :term:`Azure Confidential Compute`.

  Quorum
    A quorum of members is defined as the minimum number of members required to accept governance proposals. It is defined by the governance as a Lua script set when a CCF network is created.

  SGX
    `Intel Software Guard Extensions <https://software.intel.com/en-us/sgx>`_ is a set of instructions that increases the security of application code and data, giving them more protection from disclosure or modification. Developers can partition sensitive information into enclaves, which are areas of execution in memory with more security protection.

  TEE
    `Trusted Execution Environment <https://en.wikipedia.org/wiki/Trusted_execution_environment>`_ is a secure area of a main processor. It guarantees code and data loaded inside to be protected with respect to confidentiality and integrity. Often referred to as "enclave".

  TLS
    `Transport Layer Security <https://en.wikipedia.org/wiki/Transport_Layer_Security>`_ is an IETF cryptographic protocol standard designed to secure communications between a client and a server over a computer network.

  Users
    Directly interact with the transaction engine/application running in CCF. Their public identity should be voted in by members before they are allowed to issue requests.