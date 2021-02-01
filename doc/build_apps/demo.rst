End-to-end demo
===============

This document explains how to spin up a test CCF network and submit simple commands to it using `curl`_. We use curl here because it is a standard tool and broadly available - you should be able to get the same results with any HTTP client, provided you can configure the appropriate caller and CA identities. Once you have built your own app, you should be able to test it in the same way - simply replace ``liblogging`` with the name of your app binary, and call the endpoints defined by your app.

Startup
-------

This uses the :ref:`example C++ logging app <build_apps/logging_cpp:Logging (C++)>` and the ``sandbox.sh`` helper script included in CCF releases under the 'bin' directory.

``sandbox.sh`` is a thin wrapper around ``start_network.py``. It ensures the necessary Python dependencies are available and sets some sensible default values.
There are a large number of additional configuration options, documented by passing the ``--help`` argument. You may wish to pass ``-v`` which will make the script significantly more verbose, printing the precise ``curl`` commands which were used to communicate with the test network.

This script automates the steps described in :doc:`/operations/start_network`, in summary:

- generating new identities (private keys and certs) for the initial members and users
- starting the initial ``cchost`` node
- starting multiple additional nodes, instructed to ``join`` the initial node
- verifying that each node has successfully joined the new service
- proposing and passing governance votes using the generated member identities

The following command will run a simple one node test network on a single machine:

.. code-block:: bash

    $ cd CCF/build

    $ ../tests/sandbox.sh -p ./liblogging.virtual.so
    Setting up Python environment...
    Python environment successfully setup
    [16:14:05.294] Starting 1 CCF node...
    [16:14:05.295] Virtual mode enabled
    [16:14:10.010] Started CCF network with the following nodes:
    [16:14:10.011]   Node [0] = https://127.0.0.1:8000
    [16:14:10.011] You can now issue business transactions to the ./liblogging.virtual.so application.
    [16:14:10.011] Keys and certificates have been copied to the common folder: /data/src/CCF/build/workspace/sandbox_common
    [16:14:10.011] See https://microsoft.github.io/CCF/master/use_apps/issue_commands.html for more information.
    [16:14:10.011] Press Ctrl+C to shutdown the network.

The command output shows the addresses of the CCF nodes where commands may be submitted (eg, in this case, via ``curl https://127.0.0.1:8000/...``).
The output and error logs of each node can be found in the node-specific directory in the workspace (eg, ``workspace/sandbox_0/err`` is node 0's stderr).

Authentication
--------------

When establishing a TLS connection with a CCF service both the service and client must prove their identity.

The service identity is created at startup. The initial node generates a fresh private key which exists solely within the service's enclaves. A certificate of the corresponding public key is emitted (``networkcert.pem``) and used by all subsequent connections to confirm they are communicating with the intended service.

Each member and user is identified by the cert with which they were registered with the service, either at genesis or in a subsequent ``new_member`` or ``new_user`` governance proposal. Access to the corresponding private key allows a client to submit commands as this member or user. For this test network these are all freshly generated and stored in the same common workspace for easy access. In a real deployment only the certificates would be shared; the private keys would be distributed and remain confidential.

When using curl the server's identity is provided by ``--cacert`` and the client identity by ``--cert`` and ``--key``. Resources under the ``/gov`` path require member identities, while those under ``/app`` typically require user identities.

These certificates and keys are copied by the sandbox script to the common workspace directory, displayed by the start network script. By default this is ``workspace/sandbox_common``.

Basic Commands
--------------

For ease of access, we copy the generated PEMs to the current directory:

.. code-block:: bash

    $ cp workspace/sandbox_common/*.pem .

Now we can submit a first command, to find the current commit index of the test network:

.. code-block:: bash

    $ curl https://127.251.192.205:36981/app/commit -X GET --cacert networkcert.pem --cert user0_cert.pem --key user0_privk.pem
    {"seqno":30,"view":2}

This should look much like a standard HTTP server, with error codes for missing resources or resources the caller is not authorized to access:

.. code-block:: bash

    $ curl https://127.251.192.205:36981/app/not/a/real/resource -X GET --cacert networkcert.pem --cert user0_cert.pem --key user0_privk.pem -i
    HTTP/1.1 404 Not Found

    $ curl https://127.251.192.205:36981/gov/proposals -X POST --cacert networkcert.pem --cert user0_cert.pem --key user0_privk.pem -i
    HTTP/1.1 403 Forbidden

Logging App Commands
--------------------

The business transaction endpoints defined by our application are available under the ``/app`` prefix. For example, consider the ``"log/private"`` endpoint installed by the C++ logging application:

.. literalinclude:: ../../samples/apps/logging/logging.cpp
    :language: cpp
    :start-after: SNIPPET_START: install_record
    :end-before: SNIPPET_END: install_record
    :dedent: 6

This is available at the ``/app/log/private`` path:

.. code-block:: bash

    $ curl https://127.251.192.205:36981/app/log/private -X POST --cacert networkcert.pem --cert user0_cert.pem --key user0_privk.pem -H "Content-Type: application/json" --data-binary '{"id": 42, "msg": "Logged to private table"}'
    true

This has written an entry to the CCF KV, which can be retrieved by a future request:

.. code-block:: bash

    $ curl https://127.251.192.205:36981/app/log/private?id=42 -X GET --cacert networkcert.pem --cert user0_cert.pem --key user0_privk.pem
    {"msg":"Logged to private table"}

We can log messages in the public table via the ``/app/log/public`` path:

.. code-block:: bash

    $ curl https://127.251.192.205:36981/app/log/public -X POST --cacert networkcert.pem --cert user0_cert.pem --key user0_privk.pem -H "Content-Type: application/json" --data-binary '{"id": 42, "msg": "Logged to public table"}'
    true

    $ curl https://127.251.192.205:36981/app/log/public?id=42 -X GET --cacert networkcert.pem --cert user0_cert.pem --key user0_privk.pem
    {"msg":"Logged to public table"}

Note that the paths to these handlers is arbitrary. The names of the endpoints do not affect whether the result works with public or private tables - that is determined entirely by the application code. The logging app contains very simple examples, and real business transactions are likely to read and write from multiple tables. The difference between public and private tables is that private tables are encrypted before being written to the ledger, so their contents are only visible within the service's enclaves, whereas public tables can be read and audited directly from the ledger. This can be crudely checked by grepping the produced ledger files:

.. code-block:: bash

    $ grep "Logged to public table" workspace/sandbox_0/0.ledger/ledger_1 -q && echo "Visible" || echo "Not visible"
    Visible

    $ grep "Logged to private table" workspace/sandbox_0/0.ledger/ledger_1 -q && echo "Visible" || echo "Not visible"
    Not visible

.. _curl: https://curl.haxx.se/
