Parsing the Ledger with Python
==============================

This page describes the Python API of the :py:class:`ccf.ledger` module which can be used by auditors to parse a CCF ledger. To install the `ccf` Python package, run:

.. code-block:: bash

    $ pip install ccf

Tutorial
--------

This tutorial demonstrates how to parse the ledger produced by a CCF node. It shows a very basic example which loops through all transactions in the ledger and counts how many times all keys in a target key-value store table are updated.

First, the path to the ledger directory should be set:

.. code-block:: python

    ledger_dir = "</path/to/ledger/dir>" # Path to ledger directory

.. note:: By default, the ledger directory is created under the node directory.

Then, import the ledger module:

.. literalinclude:: ../../python/tutorial.py
    :language: py
    :start-after: SNIPPET: import_ledger
    :lines: 1

In this particular example, a target table is set. This is a public table that can be read and audited from the ledger directly. In this example, the target table is the well-known ``ccf.nodes`` table that keeps track of all nodes in the network.

.. literalinclude:: ../../python/tutorial.py
    :language: py
    :start-after: SNIPPET: target_table
    :lines: 1

.. note:: In practice, it is likely that auditors will want to run more elaborate logic when parsing the ledger. For example, this might involve verifying signatures transactions or auditing governance operations and looping over multiple tables.

Finally, the ledger can be iterated over. For each transaction in the ledger, the public tables changed within that transaction are observed. If the target table is included, we loop through all keys and values modified in that transaction.

.. literalinclude:: ../../python/tutorial.py
    :language: py
    :start-after: SNIPPET_START: iterate_over_ledger
    :end-before: SNIPPET_END: iterate_over_ledger

API
---

.. autoclass:: ccf.ledger.Ledger
    :members:

.. autoclass:: ccf.ledger.Transaction
    :members:

.. autoclass:: ccf.ledger.PublicDomain
    :members:

