Onboarding
==========

This page aims to be a list of resources that should be helpful if you want to start contributing to CCF.

Introduction
------------

Start by reading :doc:`/overview/what_is_ccf`.

If you encounter any terms or acronyms that you do not know, check the :doc:`/overview/glossary`. If the word you are looking for is not defined, create an `issue <https://github.com/microsoft/CCF/issues/new/choose>`_.

Create an SGX VM if necessary
-----------------------------

If you intend to make changes that need to work on Intel SGX, you will want an :doc:`SGX VM </contribute/create_vm>` to check you didn't introduce instructions that are illegal in enclave, and to evaluate the performance impact of your change.

Build CCF
---------

First complete :doc:`/contribute/build_setup`, and see :doc:`/contribute/build_ccf`.

Walk through a sample application
---------------------------------

:doc:`/build_apps/example_cpp` documents the sample C++ app under ``/samples/apps/logging`` in the repo.

The logging application is simple, but exercises most features of the framework, and is extensively used in the end to end tests.

To run a locally built copy of this application in a sandbox, see :doc:`/build_apps/run_app`. The package name will be ``samples/apps/logging/liblogging``:

.. code-block:: bash

    ~/CCF/build$ ../tests/sandbox/sandbox.sh -p samples/apps/logging/liblogging

    Setting up Python environment...
    Python environment successfully setup
    [11:44:33.376] Starting 1 CCF node...
    [11:44:33.376] Virtual mode enabled
    [11:44:35.025] Started CCF network with the following nodes:
    [11:44:35.025]   Node [0] = https://127.0.0.1:8000
    [11:44:35.025] You can now issue business transactions to the samples/apps/logging/liblogging application
    [11:44:35.025] Keys and certificates have been copied to the common folder: /home/$USER/CCF/build/workspace/sandbox_common
    [11:44:35.025] See https://microsoft.github.io/CCF/main/use_apps/issue_commands.html for more information
    [11:44:35.025] Press Ctrl+C to shutdown the network

Have a look at the Continuous Integration jobs
----------------------------------------------

The main CI job for CCF is defined in :ccf_repo:`a YAML file in the repo </.azure-pipelines.yml>` and runs are accessible `here <https://dev.azure.com/MSRC-CCF/CCF/_build?definitionId=3&_a=summary>`__.

That job gates pull requests, and is also used with a different trigger (on tags like ``ccf-*``) to produce releases.

Three more in-depth jobs are run every day:

- The `Daily build <https://dev.azure.com/MSRC-CCF/CCF/_build?definitionId=7>`_ (:ccf_repo:`.daily.yml </.daily.yml>`) is longer version of the CI, and makes use of instrumentation (ASAN, UBSAN...).
- The `Threading build <https://dev.azure.com/MSRC-CCF/CCF/_build?definitionId=13>`_ (:ccf_repo:`.multi-thread.yml </.multi-thread.yml>`) tests CCF with multiple worker threads.
- The `Stress build <https://dev.azure.com/MSRC-CCF/CCF/_build?definitionId=9>`_ (:ccf_repo:`.stress.yml </.stress.yml>`) runs long-lived tests against CCF networks.

Documentation is built and published to GitHub Pages by `this job <https://dev.azure.com/MSRC-CCF/CCF/_build?definitionId=4>`_ (:ccf_repo:`YAML </.azure-pipelines-gh-pages.yml>`).

Review the release and compatibility policy
-------------------------------------------

:doc:`/build_apps/release_policy` defines what changes are possible in CCF and what timeline they must follow.

Simplified Data Flow Map
------------------------

This chart is a simplified illustration of the data flow in a running CCF service. Where possible, nodes and edges have been made links to the most relevant documentation page or file.

Note that this diagram deliberately does not represent host-to-enclave communication.

.. mermaid::

    flowchart TB
        Client[HTTPS/1.1 Client <a href='../build_apps/auth/index.html'>auth</a>] -- TLS 1.2 or 1.3 --> TLSSession
        TLSSession[TLS Session <a href='https://github.com/microsoft/CCF/blob/main/src/enclave/tls_session.h'>src</a>] -- PlainText --> HTTPSession
        HTTPSession[HTTP Session <a href='https://github.com/microsoft/CCF/blob/main/src/http/http_session.h'>src</a>] -- Request --> Endpoint[Application Endpoint <a href='../build_apps/api.html#application-endpoint-registration'>doc</a>]
        Endpoint -- Response --> HTTPSession
        HTTPSession --> TLSSession
        TLSSession --> Client
        Endpoint -- WriteSet --> Store[Store <a href='../build_apps/kv/index.html'>doc</a>]
        Store -- LedgerEntry --> Ledger[Ledger <a href='../architecture/ledger.html'>doc</a>]
        Ledger -- LedgerEntry --> Disk
        Store[Key-Value Store] -- Digest --> MerkleTree[Merkle Tree <a href='../architecture/merkle_tree.html'>doc</a>]
        Store -- LedgerEntry --> Consensus[Consensus <a href='../architecture/consensus/index.html'>doc</a>]
        Consensus -- Messages --> OtherNodes[Other Nodes <a href='../architecture/node_to_node.html'>doc</a>]
        OtherNodes --> Consensus
        Consensus -- Sign --> MerkleTree
        MerkleTree -- Signature --> Store

Doxygen
-------

Doxygen description of the codebase is available `here <../doxygen/index.html>`_.