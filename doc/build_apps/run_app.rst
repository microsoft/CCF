Running CCF Applications
========================

This document explains how to spin up a test CCF network and submit simple commands to it using `curl`_. We use curl here because it is a standard tool and broadly available - you should be able to get the same results with any HTTP client, provided you can configure the appropriate caller and CA identities. Once you have built your own app, you should be able to test it in the same way - simply pass the path to your app binary to ``sandbox.sh`` as ``-p/--package``, and call the endpoints defined by your app.

Startup
-------

.. note:: Before starting a CCF sandbox environment, make sure that:

    - The CCF runtime environment has successfully been setup (see :doc:`/operations/run_setup`).
    - CCF is installed (see :doc:`/build_apps/install_bin`)

The quickest way to start a CCF sandbox is to use the ``sandbox.sh`` script available as part of the CCF install, specifying the :doc:`enclave image </build_apps/build_app>` to run.
``sandbox.sh`` is a thin wrapper around ``start_network.py``. It ensures the necessary Python dependencies are available and sets some sensible default values.
``sandbox.sh`` is a demonstration tool, and not intended for use in production deployments.
There are a large number of additional configuration options, documented by passing the ``--help`` argument. You may wish to pass ``-v`` which will make the script significantly more verbose, printing the precise ``curl`` commands which were used to communicate with the test network.

This script automates the steps described in :doc:`/operations/start_network`, in summary:

- generating new identities (private keys and certs) for the initial members and users
- starting the initial ``cchost`` node
- starting multiple additional nodes, instructed to ``join`` the initial node
- verifying that each node has successfully joined the new service
- proposing and passing governance votes using the generated member identities

The script creates a new one node CCF test network running locally. All the governance requests required to open the network to users are automatically issued.

For example, deploying the generic JS application:

.. code-block:: bash

    $ /opt/ccf/bin/sandbox.sh
    Setting up Python environment...
    Python environment successfully setup
    [16:14:05.294] Starting 1 CCF node...
    [16:14:05.295] Virtual mode enabled
    [16:14:10.010] Started CCF network with the following nodes:
    [16:14:10.011]   Node [0] = https://127.0.0.1:8000
    [16:14:10.011] You can now issue business transactions to the opt/ccf/lib/libjs_generic application.
    [16:14:10.011] Loaded JS application: /opt/ccf/samples/logging/js
    [16:14:10.011] Keys and certificates have been copied to the common folder: ./workspace/sandbox_common
    [16:14:10.011] See https://microsoft.github.io/CCF/main/use_apps/issue_commands.html for more information.
    [16:14:10.011] Press Ctrl+C to shutdown the network.

.. note::

    - ``sandbox.sh`` defaults to using CCF's `virtual` mode, which does not require or make use of SGX. To load debug or release enclaves and make use of SGX, ``--enclave-type`` must be set to the right value, for example: ``sandbox.sh --enclave-type release -p ./libjs.enclave.so.signed``
    - The ``--verbose`` argument can be used to display all commands issued by operators and members to start the network.

The command output shows the addresses of the CCF nodes where commands may be submitted (ie, via ``curl https://127.0.0.1:8000/...``).
The log files (``out`` and ``err``) and ledger directory (``<node_id>.ledger``) for each CCF node can be found under ``./workspace/sandbox_<node_id>``.

.. note:: The first time the command is run, a Python virtual environment will be created. This may take a few seconds. It will not be run the next time the ``sandbox.sh`` script is started.

In a different terminal, using the local IP address and port of the CCF nodes displayed by the command (e.g. ``https://127.0.0.1:8000`` for node ``0``), it is then possible for users to :ref:`issue business requests <use_apps/issue_commands:Issuing Commands>`.

Authentication
--------------

When establishing a TLS connection with a CCF service both the service and client must prove their identity.

The service identity is created at startup. The initial node generates a fresh private key which exists solely within the service's enclaves. A certificate of the corresponding public key is emitted (``service_cert.pem``) and used by all subsequent connections to confirm they are communicating with the intended service.

Each member and user is identified by the cert with which they were registered with the service, either at genesis or in a subsequent ``set_member`` or ``set_user`` governance proposal. Access to the corresponding private key allows a client to submit commands as this member or user. For this test network these are all freshly generated and stored in the same common workspace for easy access. In a real deployment only certificates would be shared; private keys would be created by each participant, and remain confidential in their possession.

When using curl the server's identity is provided by ``--cacert`` and the client identity by ``--cert`` and ``--key``. Resources under the ``/gov`` path require member identities, while those under ``/app`` typically require user identities.

These certificates and keys are copied by the sandbox script to the common workspace directory, displayed by the start network script. By default this is ``workspace/sandbox_common``.

Basic Commands
--------------

For ease of access, we copy the generated PEMs to the current directory:

.. code-block:: bash

    $ cp workspace/sandbox_common/*.pem .

Now we can submit a first command, to find the current commit index of the test network:

.. code-block:: bash

    $ curl https://127.0.0.1:8000/app/commit -X GET --cacert service_cert.pem --cert user0_cert.pem --key user0_privk.pem
    {"transaction_id": 2.30}

This should look much like a standard HTTP server, with error codes for missing resources or resources the caller is not authorized to access:

.. code-block:: bash

    $ curl https://127.0.0.1:8000/app/not/a/real/resource -X GET --cacert service_cert.pem --cert user0_cert.pem --key user0_privk.pem -i
    HTTP/1.1 404 Not Found

    $ curl https://127.0.0.1:8000/gov/proposals -X POST --cacert service_cert.pem --cert user0_cert.pem --key user0_privk.pem -i
    HTTP/1.1 403 Forbidden

Logging App Commands
--------------------

The business transaction endpoints defined by our application are available under the ``/app`` prefix. For example, consider the ``"log/private"`` endpoint installed by the C++ logging application:

.. literalinclude:: ../../samples/apps/logging/logging.cpp
    :language: cpp
    :start-after: SNIPPET_START: install_record
    :end-before: SNIPPET_END: install_record
    :dedent:

This is available at the ``/app/log/private`` path:

.. code-block:: bash

    $ curl https://127.0.0.1:8000/app/log/private -X POST --cacert service_cert.pem --cert user0_cert.pem --key user0_privk.pem -H "Content-Type: application/json" --data-binary '{"id": 42, "msg": "Logged to private table"}'
    true

This has written an entry to the CCF KV, which can be retrieved by a future request:

.. code-block:: bash

    $ curl https://127.0.0.1:8000/app/log/private?id=42 -X GET --cacert service_cert.pem --cert user0_cert.pem --key user0_privk.pem
    {"msg":"Logged to private table"}

We can log messages in the public table via the ``/app/log/public`` path:

.. code-block:: bash

    $ curl https://127.0.0.1:8000/app/log/public -X POST --cacert service_cert.pem --cert user0_cert.pem --key user0_privk.pem -H "Content-Type: application/json" --data-binary '{"id": 42, "msg": "Logged to public table"}'
    true

    $ curl https://127.0.0.1:8000/app/log/public?id=42 -X GET --cacert service_cert.pem --cert user0_cert.pem --key user0_privk.pem
    {"msg":"Logged to public table"}

Note that the paths to these handlers is arbitrary. The names of the endpoints do not affect whether the result works with public or private tables - that is determined entirely by the application code. The logging app contains very simple examples, and real business transactions are likely to read and write from multiple tables. The difference between public and private tables is that private tables are encrypted before being written to the ledger, so their contents are only visible within the service's enclaves, whereas public tables can be read and audited directly from the ledger. This can be crudely checked by grepping the produced ledger files:

.. code-block:: bash

    $ grep "Logged to public table" workspace/sandbox_0/0.ledger/ledger_1 -q && echo "Visible" || echo "Not visible"
    Visible

    $ grep "Logged to private table" workspace/sandbox_0/0.ledger/ledger_1 -q && echo "Visible" || echo "Not visible"
    Not visible

Sandbox recovery
----------------

The ``sandbox.sh`` script can also be used to automatically recover a defunct network, as per the steps described :ref:`here <governance/accept_recovery:Accepting Recovery and Submitting Shares>`. The ledger to be recovered (``--ledger-dir``) and the directory containing the members and users identities (``--common-dir``) should be passed as arguments to the script.

Additionally, if snapshots were generated by the defunct service, the recovery procedure can be significantly sped up by re-starting from the latest available snapshot (``--snapshots-dir``).

.. code-block:: bash

    $ cp -r ./workspace/sandbox_0/0.ledger .
    $ cp -r ./workspace/sandbox_0/snapshots . # Optional, only if snapshots are available
    $ /opt/ccf/bin/sandbox.sh --recover --ledger-dir 0.ledger --common-dir ./workspace/sandbox_common/ [--snapshots-dir snapshots]
    Setting up Python environment...
    Python environment successfully setup
    [16:24:29.563] Starting 1 CCF node...
    [16:24:29.563] Recovering network from:
    [16:24:29.563]  - Common directory: ./workspace/sandbox_common/
    [16:24:29.563]  - Ledger: 0.ledger
    [16:24:29.563] No available snapshot to recover from. Entire transaction history will be replayed.
    [16:24:32.885] Started CCF network with the following nodes:
    [16:24:32.885]   Node [0] = https://127.0.0.1:8000
    [16:14:10.011] You can now issue business transactions to the opt/ccf/lib/libjs_generic application.
    [16:14:10.011] Loaded JS application: /opt/ccf/samples/logging/js
    [16:14:10.011] Keys and certificates have been copied to the common folder: ./workspace/sandbox_common
    [16:24:32.885] See https://microsoft.github.io/CCF/main/use_apps/issue_commands.html for more information.
    [16:24:32.885] Press Ctrl+C to shutdown the network.

The effects of transactions committed by the defunct network should then be recovered. Users can also :ref:`issue new business requests <use_apps/issue_commands:Issuing Commands>`.

.. note:: The ``--ledger-recovery-timeout`` argument should be used to specify the maximum timeout (in seconds) that the script will wait for CCF to recover the ledger. Depending on the size of the ledger to recover, this timeout may have to be set to a large value.

Integration Tests
-----------------

The ``sandbox.sh`` script can be a helpful element of infrastructure to execute Integration Tests against a CCF test network running a particular application (see `test_install.sh <https://github.com/microsoft/CCF/blob/main/tests/test_install.sh>`_ script as example).

``test_install.sh`` illustrates how to wait for the sandbox to be `ready <https://github.com/microsoft/CCF/blob/main/tests/test_install.sh#L33>`_ before issuing application transactions, how to shut it down cleanly, and how to trigger a recovery. Recovering a test network can be a useful way to inspect post-test application test.

Performance Tests
-----------------

``sandbox.sh`` can be equally useful for performance testing, for example with a load testing tool such as `vegeta <https://github.com/tsenart/vegeta>`_:

.. code-block:: bash

    $ /opt/ccf/bin/sandbox.sh --package ./liblogging.virtual.so
    ...
    [16:14:10.011]   Node [0] = https://127.0.0.1:8000
    ...
    [16:14:10.011] Keys and certificates have been copied to the common folder: /data/src/CCF/build/workspace/sandbox_common
    ...

.. code-block:: bash

    # Extracted from the output of sandbox.sh, above.
    $ export SCDIR=/data/src/CCF/build/workspace/sandbox_common
    $ export VEGETA=/opt/vegeta/vegeta
    $ $VEGETA attack --targets sample_targets.json
                     --format json --duration 10s \
                     --cert $SCDIR/user0_cert.pem \
                     --key $SCDIR/user0_privk.pem \
                     --root-certs $SCDIR/service_cert.pem | /opt/vegeta/vegeta report

Where ``sample_targets.json`` is a file containing some sample requests to be sent as load testing, for example:

.. code-block:: json

    {"method": "POST", "url": "https://127.0.0.1:8000/app/log/private", "header": {"Content-Type": ["application/json"]}, "body": "eyJpZCI6IDAsICJtc2ciOiAiUHJpdmF0ZSBtZXNzYWdlOiAwIn0="}
    {"method": "GET", "url": "https://127.0.0.1:8000/app/log/private?id=0", "header": {"Content-Type": ["application/json"]}}

.. _curl: https://curl.haxx.se/
