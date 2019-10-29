Deploy Application on CCF
=========================

The quickest way to deploy a CCF application is to use the `deploy_ccf.sh <https://github.com/microsoft/CCF/blob/master/deploy_ccf.sh>`_ script, specifying the :ref:`CCF application <Writing CCF Applications>` to run.

The script creates a new CCF network composed of 3 nodes and automatically issues all the governance requests required to open the network to users.

For example, deploying the ``libloggingenc`` example application:

.. code-block:: bash

    $ cd CCF/build
    $ ../deploy_ccf.sh libloggingenc
    Setting up Python environment...
    Python environment successfully setup
    [2019-10-29 14:47:41.562] Starting 3 CCF nodes...
    [2019-10-29 14:48:12.138] Started CCF network with the following nodes:
    [2019-10-29 14:48:12.138]   Node [ 0] = 127.177.10.108:37765
    [2019-10-29 14:48:12.138]   Node [ 1] = 127.169.74.37:58343
    [2019-10-29 14:48:12.138]   Node [ 2] = 127.131.108.179:50532
    [2019-10-29 14:48:12.138] You can now issue business transactions to the libloggingenc application.
    [2019-10-29 14:48:12.138] See https://microsoft.github.io/CCF/users/issue_commands.html for more information.
    [2019-10-29 14:48:12.138] Press Ctrl+C to shutdown the network.

.. note:: The first time the command is run, a Python virtual environment will be created. This may take a few seconds and will not be run the next time the ``deploy_ccf.sh`` is run.

In a different terminal, using the local IP address and port of the CCF nodes displayed by the command (e.g. ``127.177.10.108:37765`` for node ``0``), it is then possible for users to :ref:`issue business requests <Issuing Commands>`.

