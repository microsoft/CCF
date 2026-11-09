Operations
==========

This section describes how :term:`Operators` manage the different nodes constituting a CCF network.

.. grid:: 1 2 2 2
    :gutter: 3

    .. grid-item-card:: :fas:`laptop-code` :doc:`run_setup`

        Set up a VM or a container to run a CCF application node.

    .. grid-item-card:: :fas:`play-circle` :doc:`start_network`

        Start a new instance of a CCF service, and add an initial set of execution nodes.

    .. grid-item-card:: :fas:`cogs` :doc:`configuration`

        Configure CCF nodes using a JSON configuration file.

    .. grid-item-card:: :fas:`laptop-code` :doc:`cli`

        Use the command-line interface for CCF executables.

    .. grid-item-card:: :fas:`upload` :doc:`ledger_snapshot`

        Back up ledger files and provision new nodes from a state snapshot.

    .. grid-item-card:: :fas:`database` :doc:`data_persistence`

        Understand durability and best practices for ledger and snapshot files.

    .. grid-item-card:: :fas:`sync-alt` :doc:`code_upgrade`

        Upgrade a live service with minimal downtime.

    .. grid-item-card:: :fas:`stamp` :doc:`certificates`

        Set and renew node and service X.509 certificates.

    .. grid-item-card:: :fas:`helicopter` :doc:`recovery`

        Recover a service instance from a catastrophic failure, using one or more ledger copies.

    .. grid-item-card:: :fas:`network-wired` :doc:`network`

        Configure a network to deploy a CCF service.

    .. grid-item-card:: :fas:`microchip` :doc:`platforms/index`

        Explore platforms and trusted execution environments supported by CCF.

    .. grid-item-card:: :fas:`wrench` :doc:`troubleshooting`

        Troubleshoot unexpected events.

    .. grid-item-card:: :fas:`tachometer-alt` :doc:`resource_usage`

        Monitor node resource consumption.

    .. grid-item-card:: :fas:`terminal` :doc:`operator_rpc_api`

        Consult the node API reference.

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
