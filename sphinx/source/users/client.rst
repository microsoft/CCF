Client
======

CCF provides two client implementations (C++ and Python).

C++ Client
----------

.. doxygenclass:: JsonRpcTlsClient
   :project: CCF
   :members:

Alternatively, the ``SigJsonRpcTlsClient`` can be used to issue signed requests (useful for governance).

.. doxygenclass:: SigJsonRpcTlsClient
   :project: CCF
   :members:

Python Client
-------------

Available as part of CCF Python infra: https://github.com/microsoft/CCF/blob/master/tests/infra/clients.py.

The ``Checker`` class in `ccf.py <https://github.com/microsoft/CCF/blob/master/tests/infra/ccf.py>`_ can be used as a wrapper to wait for requests to be committed.

HTTP
----

HTTP support is now available experimentally in CCF. To enable it, follow the standard build procedure, and passing `-DHTTP=ON` to cmake.

Testcases will automatically switch to using the appropriate clients.
The CCF Python infra client can be used without any modifications other than exporting the ``HTTP`` environment variable.
By default, the Python infra uses `requests <https://realpython.com/python-requests/>`_, but exporting the ``CURL_CLIENT`` environment variable will switch to a ``curl``-based client instead.

The ``start_test_network.sh`` script documented in :ref:`quickstart/index:Quickstart` defaults to using ``curl``.
A simple ``scurl.sh`` wrapper script is automatically generated under ``build/``, and allows sending signed requests to CCF.