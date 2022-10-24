Python Library
==============

This page describes the Python API of the :py:class:`ccf.ledger` module which can be used by auditors to parse a CCF ledger.

The latest version of the CCF Python tools package is `available on PyPi <https://pypi.org/project/ccf/>`_ and can be installed as follows:

.. code-block:: bash

    $ pip install ccf

.. tip::

    Use the :ref:`read_ledger.py` to display the content of a CCF ledger from the command line.

Tutorial
--------

This tutorial demonstrates how to parse the ledger produced by a CCF node. It shows a very basic example which loops through all transactions in the ledger and displays the content of all updates to a well-known built-in table.

First, the paths to the ledger directories should be set:

.. code-block:: python

    ledger_dirs = ["</path/to/ledger/dir>"] # List of a single ledger directory

.. note:: By default, ledger directories are created under the node directory (See :ref:`operations/configuration:``ledger``` configuration entry).

Then, import the ledger module and instantiate a :py:class:`ccf.ledger` object:

.. literalinclude:: ../../python/ledger_tutorial.py
    :language: py
    :start-after: SNIPPET_START: create_ledger
    :end-before: SNIPPET_END: create_ledger

By default, non-committed ledger files are ignored, unless the ``committed_only`` argument is set to ``False``.

In this particular example, a target table is set. This is a public table that can be read and audited from the ledger directly. In this example, the target table is the well-known ``public:ccf.gov.nodes.info`` table that keeps track of all nodes in the network.

.. literalinclude:: ../../python/ledger_tutorial.py
    :language: py
    :start-after: SNIPPET: target_table
    :lines: 1

.. note:: In practice, it is likely that auditors will want to run more elaborate logic when parsing the ledger. For example, this might involve auditing governance operations and looping over multiple tables.

Finally, the ledger can be iterated over. For each transaction in the ledger, the public tables changed within that transaction are observed. If the target table is included, we loop through all keys and values modified in that transaction.

.. literalinclude:: ../../python/ledger_tutorial.py
    :language: py
    :start-after: SNIPPET_START: iterate_over_ledger
    :end-before: SNIPPET_END: iterate_over_ledger

.. tip:: The integrity of the ledger is automatically verified when iterating over transactions.

.. _read_ledger.py:

``read_ledger.py`` command line utility
---------------------------------------

The ``read_ledger.py`` command line utility can be used to parse, verify the integrity and display the public content of the ledger directory:

.. code-block:: bash

    $ read_ledger.py /path/to/ledger/dir
    Reading ledger from ['/path/to/ledger/dir']
    Contains 9 chunks
    chunk /path/to/first/ledger/chunk (committed)
      seqno 1 (9 public tables) # Number of tables written at seqno 1
        table "public:ccf.gov.constitution" (1 write): # 1 write to this table at seqno 1
          <u64: 0>: # key
            "class Action ..." # value
        table "public:ccf.gov.members.acks" (2 writes): # 2 writes to this table at seqno 1
            ...
      seqno 31 (0 public tables) # transaction at seqno 31 is private only
      -- private: 94 bytes # size of private entry
    ...
    Ledger verification complete. Found 15 signatures, and verified until 2.52 # Ledger integrity verified up to seqno 2.52

By default, non-committed ledger files are ignored, unless the ``--uncommitted`` command line argument is specified.

Alternatively, ``read_ledger.py`` can parse the content of a snapshot file:

.. code-block:: bash

    $ read_ledger.py --snapshot /path/to/snapshot/file
    Reading snapshot from /path/to/snapshot/file (committed)
      seqno 12 (15 public tables)
    ...

.. note::

    The output of the ``read_ledger.py`` utility can be filtered by :ref:`key-value store table <build_apps/kv/kv_how_to:Map Naming>` using the ``--tables <regex>`` arguments, e.g.:

    .. code-block:: bash

        $ read_ledger.py /path/to/ledger/dir --tables ".*ccf.gov.proposals.*"
        # Only displays governance proposal related tables

Example
-------

An example of how to read and verify entries on the ledger can be found in :ccf_repo:`governance_history.py </tests/governance_history.py>`, which verifies the member voting history for a short-lived service.

Since every vote request is signed by the voting member, verified by the primary node and then stored on the ledger, the test performs the following (this sequence of operations is performed sequentially per transaction):

 1. Read and store the member certificates
 2. Read an entry from the ``public:ccf.gov.history`` table (each entry in the table contains the member id of the voting member, along with their latest signed request)
 3. Create a public key using the certificate of the voting member (which was stored on step 1)
 4. Verify the signature using the public key and the raw request
 5. Repeat steps 2 - 4 until all voting history entries have been read

API
---

.. autoclass:: ccf.ledger.Ledger
    :members:

.. autoclass:: ccf.ledger.LedgerChunk
    :members:

.. autoclass:: ccf.ledger.Transaction
    :inherited-members:
    :members:

.. autoclass:: ccf.ledger.Snapshot
    :inherited-members:
    :members:

.. autoclass:: ccf.ledger.PublicDomain
    :members:

.. automodule:: ccf.receipt
    :members: