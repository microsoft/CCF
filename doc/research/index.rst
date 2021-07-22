Research
========

:doc:`TLA+ model of CCF's Raft modifications <raft-tla>`
  CCF implements some modifications to Raft as it was originally proposed by Ongaro and Ousterhout. Specifically, CCF constrains that only appended entries that were signed by the primary can be committed. Any other entry that has not been globally committed is rolled back. Additionally, the CCF implementation introduced a variant of the reconfiguration that is different from the one proposed by the original Raft paper. In CCF CFT, reconfigurations are  done via one transaction (as described :doc:`here </overview/consensus>`).

  The TLA+ model of CCF's Raft changes can be found in the `CCF GitHub repository <https://github.com/microsoft/CCF/tree/main/tla>`_.

`PAC: Practical Accountability for CCF <https://arxiv.org/abs/2105.13116>`_
  Permissioned ledger systems execute transactions on a set of replicas governed by members of a consortium. They use Byzantine fault tolerance protocols to distribute trust among the replicas, and thus can ensure linearizability if fewer than 1/3 of the replicas misbehave. With more misbehaving replicas, current systems provide no guarantees, and all replicas and members share the blame.

  We describe PAC, a permissioned ledger system that assigns blame to misbehaving replicas while supporting governance transactions to change the consortium membership and the set of replicas. PAC signs and stores protocol messages in the ledger and provides clients with signed, universally-verifiable receipts as evidence that a transaction executed at a certain ledger position. If clients obtain a sequence of receipts that violate linearizability, anyone can audit the ledger and the sequence of receipts to assign blame to at least 1/3 of the replicas, even if all replicas and members misbehave. Auditing assigns blame by finding contradictory statements signed by the same replica. Since the set of replicas changes, PAC determines the valid signing keys at any point in the ledger using a shorter sub-ledger of governance transactions. PAC provides a strong disincentive to misbehavior at low cost: it can execute more than 48,000 transactions per second, and clients receive receipts in two network round trips.


`CCF: A Framework for Building Confidential Verifiable Replicated Service <https://github.com/microsoft/CCF/blob/main/CCF-TECHNICAL-REPORT.pdf>`_
  This paper presents CCF, a framework to build permissioned confidential blockchains. CCF provides a simple programming
  model of a highly-available data store and a universally-verifiable log that implements a ledger abstraction. CCF
  leverages trust in a consortium of governing members and in a network of replicated hardware-protected execution
  environments to achieve high throughput, low latency, strong integrity and strong confidentiality for application data
  and code executing on the ledger.
  
.. toctree::
  raft-tla
  PAC: Practical Accountability for CCF <https://arxiv.org/abs/2105.13116>
  CCF whitepaper <https://github.com/microsoft/CCF/blob/main/CCF-TECHNICAL-REPORT.pdf>
