Deploying an Application
========================

The quickest way to deploy a CCF application is to use the `start_test_network.sh <https://github.com/microsoft/CCF/blob/master/start_test_network.sh>`_ test script, specifying the :ref:`enclave image <developers/index:Writing CCF Applications>` to run.

The script creates a new test CCF network composed of 3 nodes running locally. All the governance requests required to open the network to users are automatically issued.

For example, deploying the ``liblogging`` example application:

.. code-block:: bash

    $ cd CCF/build
    $ ../start_test_network.sh ./liblogging.enclave.so.signed
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

.. note:: To use CCF `virtual` mode, the same command can be run with ``TEST_ENCLAVE=virtual`` set as environment variable and the virtual version of the enclave application passed to the script. For example ``$ TEST_ENCLAVE=virtual ../start_test_network.sh ./liblogging.virtual.so``.

The log files (``out`` and ``err``) and ledger (``<node_id>.ledger``) for each CCF node can be found under ``CCF/build/workspace/test_network_<node_id>``.

.. note:: The first time the command is run, a Python virtual environment will be created. This may take a few seconds. It will not be run the next time the ``start_test_network.sh`` script is started.

In a different terminal, using the local IP address and port of the CCF nodes displayed by the command (e.g. ``127.177.10.108:37765`` for node ``0``), it is then possible for users to :ref:`issue business requests <users/issue_commands:Issuing Commands>`.

