Python Client Tutorial
======================

Install
-------

The CCF Python tools package can be used to interact with an existing running service and provides utilities to:

- Issue HTTP requests over TLS to a CCF service
- Build custom governance proposals and votes
- Parse and verify the integrity of a CCF ledger

The latest version of the CCF Python tools package is `available on PyPi <https://pypi.org/project/ccf/>`_ and can be installed as follows:

.. code-block:: bash

    $ pip install ccf

.. note:: The CCF Python tools package does `not` provide utilities to build and deploy CCF applications.

A step-by-step tutorial on how to use the CCF Python package is available :ref:`here <use_apps/python_tutorial:Python Client Tutorial>`.

Uninstall
---------

To uninstall the CCF Python package, run:

.. code-block:: bash

    $ pip uninstall ccf


Tutorial
--------

.. note:: The CCF Python client module uses `Python Requests <https://requests.readthedocs.io/en/master/>`_ by default, but can be switched to a ``curl``-based client (printing each command to stdout) by running with the environment variable ``CURL_CLIENT`` set.

This tutorial describes how a Python client can securely issue requests to a running CCF network. It is assumed that the CCF network has already been started (e.g. after having :doc:`deployed a sandbox service </build_apps/run_app>`).

.. note:: See :ref:`Python Client API <use_apps/python_api:Python Client API>` for the complete API specification.

In the Python interpreter or new file:

.. literalinclude:: ../../python/tutorial.py
    :language: py
    :start-after: SNIPPET: import_clients
    :lines: 1

Set the following CCF node variables:

.. code-block:: python

    host = "<node-host>"            # Node address or domain (str)
    port = <node-port>              # Node port (int)
    ca = "<path/to/service/cert>"   # Service certificate path

.. note:: :doc:`When starting a CCF sandbox </build_apps/run_app>`, use any node's IP address and port number. All certificates and keys can be found in the associated ``common_dir`` folder.

Create a new :py:class:`ccf.clients.CCFClient` instance which will create a secure TLS connection to the target node part of the network specified via ``ca``:

.. literalinclude:: ../../python/tutorial.py
    :language: py
    :start-after: SNIPPET: anonymous_client
    :lines: 1

You can then use the ``anonymous_client`` to issue requests that do not require authentication (typically, ``GET`` endpoints under ``/node``). Every call returns a :py:class:`ccf.clients.Response` object associated with the HTTP response.

.. literalinclude:: ../../python/tutorial.py
    :language: py
    :start-after: SNIPPET_START: anonymous_requests
    :end-before: SNIPPET_END: anonymous_requests

TLS Session Authentication
--------------------------

To create a client authenticated via TLS and issue application or governance requests, the session identity (certificate and private key) should be specified:

.. code-block:: python

    cert = "</path/to/client/cert>"         # Client certificate path
    key = "</path/to/client/private/key>"   # Private key certificate path

Create a new instance of :py:class:`ccf.clients.CCFClient`, this time specifying the client's certificate and private key as :py:class:`ccf.clients.Identity`:

.. literalinclude:: ../../python/tutorial.py
    :language: py
    :start-after: SNIPPET_START: session_authenticated_client
    :end-before: SNIPPET_END: session_authenticated_client

The authenticated client can then be used to issue ``POST`` requests, e.g. registering new public and private messages to the default logging application:

.. literalinclude:: ../../python/tutorial.py
    :language: py
    :start-after: SNIPPET_START: authenticated_post_requests
    :end-before: SNIPPET_END: authenticated_post_requests

It is possible to use the same :py:class:`ccf.clients.CCFClient` instance to wait for the transaction to be committed by the network:

.. literalinclude:: ../../python/tutorial.py
    :language: py
    :start-after: SNIPPET: wait_for_commit
    :lines: 1

In fact, even an anonymous client can be used to verify that a transaction is committed. This is because only the sequence number and view associated with the transaction are required to verify that a transaction is committed.

.. literalinclude:: ../../python/tutorial.py
    :language: py
    :start-after: SNIPPET: any_client_can_wait
    :lines: 1

.. warning:: This does not imply that the content of a confidential transaction issued by an authenticated client is visible by an unauthenticated client. Access control to the confidential resource is handled by the CCF application logic.

Finally, the authenticated client can be used to issue ``GET`` requests and verify that the previous messages have successfully been recorded:

.. literalinclude:: ../../python/tutorial.py
    :language: py
    :start-after: SNIPPET_START: authenticated_get_requests
    :end-before: SNIPPET_END: authenticated_get_requests

Request Signature Authentication
--------------------------------

Alternatively, the client's identity can be derived from the client signature on the request:

.. literalinclude:: ../../python/tutorial.py
    :language: py
    :start-after: SNIPPET_START: signature_authenticated_client
    :end-before: SNIPPET_END: signature_authenticated_client

Signed requests can then be submitted the usual way, e.g.:

.. literalinclude:: ../../python/tutorial.py
    :language: py
    :start-after: SNIPPET_START: signed_request
    :end-before: SNIPPET_END: signed_request

.. note:: It is possible to set different session and signing identities for a :py:class:`ccf.clients.CCFClient` instance. If the triggered CCF application endpoint has registered both authentication policies, it is up to the application logic to check for the identity type.