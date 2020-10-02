CCF documentation
=================

.. image:: img/ccf.svg
  :width: 250
  :align: right

Welcome to the Confidential Consortium Framework (CCF) documentation.

First Steps
-----------

- :ref:`CCF overview <concepts:CCF Overview>`
- :ref:`Install CCF <quickstart/install:Install CCF>`
- :ref:`Start a sample CCF application <quickstart/test_network:Starting a Test Network>`
- How to use a sample CCF service (Python library as well)
- `What's new in the latest version of CCF? <https://github.com/microsoft/CCF/releases/latest>`_


Build a CCF application
-----------------------

- Maybe create a SGX VM: :ref:`quickstart/create_vm:Create Azure SGX VM`
- First, setup a CCF development environment. :ref:`quickstart/build_setup:Setup CCF Development Environment`

- Link to JavaScript/TypeScript application
- Link to C++ application


Contribute
----------

- :ref:`Contribute to CCF <quickstart/contribute:Contribute to CCF>`
- Link to contribution guidelines
- Setup a CCF environment, build CCF.


Next Steps
----------

Once your setup is complete, you may want to get familiar with some of CCF's :ref:`Concepts <concepts:Concepts>`. You will then be able to:

1. :ref:`Create a consortium and agree on the constitution <members/index:Governance>`
2. :ref:`Develop a CCF application, based on the example logging application <developers/example:Example Application>`
3. :ref:`Start a new CCF network to deploy the application <operators/start_network:Starting a New Network>`
4. :ref:`Let the consortium configure and open the network to users <members/open_network:Opening a Network>`
5. :ref:`Have users issue business transactions to the application <users/index:Using Apps>`





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


TODO: Fancy css, see https://github.com/apache/couchdb-documentation/blob/1433b3c4c713998fa0707463e15c304845d93120/templates/pages/index.html#L52

TODO: Explain ``cchost`` as host utility that will start an enclave


.. toctree::
    :maxdepth: 1
    :hidden:

    Home <index.rst>
    concepts
    members/index.rst
    developers/index.rst
    operators/index.rst
    users/index.rst
    design/index.rst

    glossary