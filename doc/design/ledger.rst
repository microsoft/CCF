Ledger
======

All network state is contained in the ledger. A single up-to-date copy of the ledger is enough to start a successor
service if necessary, following the :ref:`operators/recovery:Disaster Recovery` procedure.

Each node in a network creates and maintains its own local copy of the ledger. Committed entries are always identical,
but a node may be more or less up to date, and uncommitted entries may differ.

Location
--------

Nodes can be configured to store their ledger under a particular directory with the `--ledger-dir` command-line option.

File layout
-----------

The ledger directory contains a series of ledger files (or chunks). The size of each ledger file is controlled by the ``--ledger-chunk-bytes`` command line option.

.. note:: When a new node joins from a snapshot (see :ref:`operators/start_network:Resuming from Existing Snapshot`), it is important that subsequent ledger files are the same on all nodes. To do so, a new ledger file is created every time a snapshot is generated, even if the specified size of the file has not yet been reached.

Files containing only committed entries are named ``ledger_$STARTSEQNO-$ENDSEQNO.committed``. These files are closed and immutable, it is safe to replicate them to backup storage. They are identical across nodes, provided ``--ledger-chunk-bytes`` has been set to the same value.

.. warning:: Removing files from a ledger directory may cause a node to crash.

Files that still contain some uncommitted entries will be named ``ledger_$STARTSEQNO-$ENDSEQNO`` or ``ledger_$STARTSEQNO`` for the last one. These files are typically held open by the ``cchost`` process, which may modify their content, or even erase them completely. Uncommitted ledger files may differ arbitrarily across nodes.

It is important to note that while all entries stored in files ending in ``.committed`` are committed, not all committed entries are stored in such a file at any given time. A number of them are typically in the in-progress files, waiting to be flushed to a ``.committed`` file once the size threshold is met.

The listing below is an example of what a ledger directory may look like:

.. code-block:: bash

    $ ./cchost --ledger-dir $LEDGER_DIR ...
    $ cd $LEDGER_DIR
    $ ls -la
    -rw-rw-r-- 1 user user 1.6M Jun 16 14:08 ledger_1-7501.committed
    ...
    -rw-rw-r-- 1 user user 1.1M Jun 16 14:08 ledger_92502-97501.committed
    -rw-rw-r-- 1 user user 553K Jun 16 14:08 ledger_97502
