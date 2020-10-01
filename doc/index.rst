CCF documentation
=================

.. image:: img/ccf.svg
  :width: 250
  :align: right

Welcome to the Confidential Consortium Framework (CCF) documentation.

TODO: Fancy css, see https://github.com/apache/couchdb-documentation/blob/1433b3c4c713998fa0707463e15c304845d93120/templates/pages/index.html#L52


First Steps
-----------

.. toctree::
    :maxdepth: 1

    concepts
    quickstart/install

- :ref:`CCF overview <concepts:CCF Overview>`
- Install CCF
- Start a sample CCF application
- How to use a sample CCF service (Python library as well)

Build a CCF application
-----------------------

- Link to JavaScript/TypeScript application
- Link to C++ application

CCF roles
---------

(Not mutually exclusive)

- Operations
- Governance
- Users: commit + receipt + new network identity on recovery
- Audit [new?]: ledger chunks, snapshots


Technical Overview
------------------

In-depth version of the concepts:
- Architecture:
  - Ledger
  - Constitution
  - Replication and Consensus

- Guarantees
  - ACID
  - Crypto


TODO: Link to crypto, ACID guarantees, etc.

Contribute
----------

- Link to contribution guidelines
- Setup a CCF environment, build CCF.



.. toctree::
    :maxdepth: 1
    :hidden:

    concepts
    quickstart/index.rst
    members/index.rst
    developers/index.rst
    operators/index.rst
    users/index.rst

    glossary