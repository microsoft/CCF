Deploying an Application
========================

The quickest way to deploy a CCF application is to use the `start_test_network.sh <https://github.com/microsoft/CCF/blob/master/start_test_network.sh>`_ test script, specifying the :ref:`enclave image <developers/index:Building Apps>` to run.

The script creates a new test CCF network composed of 3 nodes running locally. All the governance requests required to open the network to users are automatically issued.

For example, deploying the ``liblogging`` example application:

.. code-block:: bash

    $ cd CCF/build
    $ ../start_test_network.sh --package ./liblogging.enclave.so.signed
    Setting up Python environment...
    Python environment successfully setup
    [2019-10-29 14:47:41.562] Starting 3 CCF nodes...
    [2019-10-29 14:48:12.138] Started CCF network with the following nodes:
    [2019-10-29 14:48:12.138]   Node [ 0] = 127.177.10.108:37765
    [2019-10-29 14:48:12.138]   Node [ 1] = 127.169.74.37:58343
    [2019-10-29 14:48:12.138]   Node [ 2] = 127.131.108.179:50532
    [2019-10-29 14:48:12.138] You can now issue business transactions to the ./liblogging.enclave.so.signed application.
    [2019-10-29 14:48:12.138] See https://microsoft.github.io/CCF/users/issue_commands.html for more information.
    [2019-10-29 14:48:12.138] Press Ctrl+C to shutdown the network.

.. note::

    - To use CCF `virtual` mode, the same command can be run with ``TEST_ENCLAVE=virtual`` set as environment variable and the virtual version of the enclave application passed to the script. For example ``$ TEST_ENCLAVE=virtual ../start_test_network.sh --package ./liblogging.virtual.so``.
    - The ``--verbose`` argument can be used to display all commands issued by operators and members to start the network.

The log files (``out`` and ``err``) and ledger (``<node_id>.ledger``) for each CCF node can be found under ``CCF/build/workspace/test_network_<node_id>``.

.. note:: The first time the command is run, a Python virtual environment will be created. This may take a few seconds. It will not be run the next time the ``start_test_network.sh`` script is started.

In a different terminal, using the local IP address and port of the CCF nodes displayed by the command (e.g. ``127.177.10.108:37765`` for node ``0``), it is then possible for users to :ref:`issue business requests <users/issue_commands:Issuing Commands>`.

Recovering a Service
--------------------

The ``start_test_network.sh`` script can also be used to automatically recover a defunct network, as per the steps described :ref:`here <members/accept_recovery:Accepting Recovery and Submitting Shares>`. The ledger to be recovered (``--ledger``) and the directory containing the members and users identities and the network encryption public key (``--common-dir``) should be passed as arguments to the script.

.. code-block:: bash

    $ cd CCF/build
    $ cp ./workspace/test_network_0/0.ledger .
    $ ../start_test_network.sh -p liblogging.enclave.so.signed --recover --ledger 0.ledger --common-dir ./workspace/test_network_common/
    [2020-05-14 11:12:56.580] Starting 3 CCF nodes...
    [2020-05-14 11:12:56.580] Virtual mode enabled
    [2020-05-14 11:12:56.580] Recovering network from ledger 0.ledger and common directory ./workspace/test_network_common/
    [2020-05-14 11:13:01.154] Started CCF network with the following nodes:
    [2020-05-14 11:13:01.155]   Node [ 3] = 127.213.21.224:60433
    [2020-05-14 11:13:01.155]   Node [ 4] = 127.87.46.254:37443
    [2020-05-14 11:13:01.155]   Node [ 5] = 127.136.206.136:34330
    [2020-05-14 11:13:01.155] You can now issue business transactions to the liblogging.virtual.so application.
    [2020-05-14 11:13:01.155] See https://microsoft.github.io/CCF/users/issue_commands.html for more information.
    [2020-05-14 11:13:01.155] Press Ctrl+C to shutdown the network.

The effects of transactions committed by the defunct network should then be recovered. Users can also :ref:`issue new business requests <users/issue_commands:Issuing Commands>`.