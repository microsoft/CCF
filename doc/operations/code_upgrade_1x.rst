Code Upgrade 1.x from 2.0 Guidelines
====================================

.. note:: The generic code upgrade procedure is described :doc:`here </operations/code_upgrade>`.

The CCF 2.0 release introduces major improvements and new features from 1.x LTS releases. To be able to upgrade the service as smoothly as possible and make the most of these new features, operators should follow this specific guide to upgrade their 1.x service.

New ``cchost`` JSON Configuration
---------------------------------

The configuration for a single CCF node (specific to ``cchost`` binary) is now a single JSON file, rather than a set of command line arguments or INI/YAML configuration file (see :doc:`/operations/configuration` for more details).

The ``migrate_1_x_config.py`` Python script, available as part of the :doc:`ccf Python package </audit/python_library>`, converts an existing 1.x ``.ini`` configuration file to a 2.0 JSON configuration file:

.. code-block:: bash

    $ pip install ccf
    $ migrate_1_x_config.py config_1_x.ini 2_x_config.json # migrate_1_x_config.py is in path
    2022-01-01 10:00:00.000 | INFO     | __main__:<module>:69 - Reading 1.x configuration file: config_1_x.ini
    2022-01-01 10:00:00.000 | DEBUG    | __main__:<module>:77 - Found sections: ['default', 'start', 'join', 'recover']
    2022-01-01 10:00:00.000 | INFO     | __main__:<module>:98 - Command type: start
    2022-01-01 10:00:00.000 | SUCCESS  | __main__:<module>:215 - JSON configuration successfully written to: 2_x_config.json

The ``cchost`` executable can be used to verify the validity of the migrated configuration file (without launching the enclave application):

.. code-block:: bash

    $ /opt/ccf/bin/cchost --config 2_x_config.json --check
    2022-01-01T10:00:00.000000Z        100 [info ] ../src/host/main.cpp:78              | CCF version: ccf-2.0.0
    2022-01-01T10:00:00.000000Z        100 [info ] ../src/host/main.cpp:95              | Configuration file successfully verified

Upgrade to Latest 1.x LTS before 2.0
------------------------------------

During the code upgrade process, the service will temporarily be made of nodes from different CCF versions. This means that breaking changes introduced in 2.0 (e.g. ledger format for application claims) introduce incompatibility with the ledger format that 1.x nodes can apply.

To prevent this, operators should first complete the :ref:`code upgrade procedure <operations/code_upgrade:Procedure>` from the current 1.x version the service is running on (e.g. ``1.0.10``) to latest version of the 1.x LTS. Once this is done, the service can be safely upgraded to 2.0.

Cycle 2.x Nodes Once
--------------------

Once the service has been upgraded to 2.0, the new nodes should be cycled once. This consists of running the code upgrade procedure from 2.0 to the same 2.0 version (i.e. without registering a new code version or updating the constitution scripts).

This is because new 2.0 nodes should join the service from a 2.0 node for their endorsed node certificate to be recorded in the ledger (:ref:`audit/builtin_maps:``nodes.endorsed_certificates``` table) and ultimately provide more convenient ledger audit.

Constitution Upgrade
--------------------

The sample constitution scripts in :ccf_repo:`samples/constitutions/` have changed significantly since 1.x, as has the underlying JS API. It is highly recommended to upgrade the constitution after the upgrade to 2.0. Any existing constitution scripts based on the 1.x samples will likely require adjustment prior to that; both to ensure they are safe and secure, and to make use of new features that were added since 1.x.