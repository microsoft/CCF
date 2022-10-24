Research
========

`IA-CCF: Individual Accountability for Permissioned Ledgers <https://arxiv.org/abs/2105.13116>`_
  Permissioned ledger systems allow a consortium of members that do not trust one another to execute transactions safely on a set of replicas. Such systems typically use Byzantine fault tolerance (BFT) protocols to distribute trust, which only ensures safety when fewer than 1/3 of the replicas misbehave. Providing guarantees beyond this threshold is a challenge: current systems assume that the ledger is corrupt and fail to identify misbehaving replicas or hold the members that operate them accountable---instead all members share the blame.

 We describe IA-CCF, a new permissioned ledger system that provides individual accountability. It can assign blame to the individual members that operate misbehaving replicas regardless of the number of misbehaving replicas or members. IA-CCF achieves this by signing and logging BFT protocol messages in the ledger, and by using Merkle trees to provide clients with succinct, universally-verifiable receipts as evidence of successful transaction execution. Anyone can audit the ledger against a set of receipts to discover inconsistencies and identify replicas that signed contradictory statements. IA-CCF also supports changes to consortium membership and replicas by tracking signing keys using a sub-ledger of governance transactions. IA-CCF provides strong disincentives to misbehavior with low overhead: it executes 47,000 tx/s while providing clients with receipts in two network round trips.

|TR|
  This paper presents CCF, a framework to build permissioned confidential blockchains. CCF provides a simple programming
  model of a highly-available data store and a universally-verifiable log that implements a ledger abstraction. CCF
  leverages trust in a consortium of governing members and in a network of replicated hardware-protected execution
  environments to achieve high throughput, low latency, strong integrity and strong confidentiality for application data
  and code executing on the ledger.

.. |TR| replace:: :ccf_repo:`CCF: A Framework for Building Confidential Verifiable Replicated Service </CCF-TECHNICAL-REPORT.pdf>`
