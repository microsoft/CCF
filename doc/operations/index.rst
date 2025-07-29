Operations
==========

This section describes how :term:`Operators` manage the different nodes constituting a CCF network.

.. panels::

    :fa:`laptop-code` :doc:`run_setup`
    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

    Set up a VM or a container to run a CCF application node.

    ---

    :fa:`play-circle` :doc:`start_network`
    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

    Start a new instance of a CCF service, and add an initial set of execution nodes.

    ---

    :fa:`cogs` :doc:`configuration`
    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

    Configure CCF nodes from JSON configuration file.

    ---

    :fa:`laptop-code` :doc:`cli`
    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^

    Command-Line Interface for CCF executables.

    ---

    :fa:`upload` :doc:`ledger_snapshot`
    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

    Understand how to backup ledger files and provision new nodes from a state snapshot.

    ---

    :fa:`database` :doc:`data_persistence`
    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

    Best practices and durability guarantees for ledger and snapshot files.

    ---

    :fa:`sync-alt` :doc:`code_upgrade`
    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

    Upgrade a live service with minimal downtime.

    ---

    :fa:`stamp` :doc:`certificates`
    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

    Set and renew nodes and service x509 certificates.

    ---

    :fa:`helicopter` :doc:`recovery`
    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

    Recover a service instance from a catastrophic failure, using one or more ledger copies.

    ---

    :fa:`network-wired` :doc:`network`
    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

    Configure a network to deploy a CCF service.

    ---

    :fa:`microchip` :doc:`platforms/index`
    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

    Platforms and trusted execution environments supported by CCF.

    ---

    :fa:`wrench` :doc:`troubleshooting`
    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

    Troubleshooting tips for unexpected events.

    ---

    :fa:`tachometer-alt` :doc:`resource_usage`
    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

    Monitor node resource consumption.

    ---

    :fa:`terminal` :doc:`operator_rpc_api`
    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

    Node API reference.

.. toctree::
    :hidden:

    run_setup
    start_network
    configuration
    cli
    ledger_snapshot
    data_persistence
    code_upgrade
    certificates
    recovery
    network
    platforms/index
    troubleshooting
    resource_usage
    operator_rpc_api
