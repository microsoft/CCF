Client
======

CCF provides two client implementations (C++ and Python).

C++ Client
----------

.. doxygenclass:: RpcTlsClient
   :project: CCF
   :members:

Alternatively, the ``SigRpcTlsClient`` can be used to issue signed requests (useful for governance).

.. doxygenclass:: SigRpcTlsClient
   :project: CCF
   :members:

Python Client
-------------

Available as part of CCF Python infra: https://github.com/microsoft/CCF/blob/master/tests/infra/jsonrpc.py.

The ``Checker`` class in `ccf.py <https://github.com/microsoft/CCF/blob/master/tests/infra/ccf.py>`_ can be used as a wrapper to wait for requests to be committed.

.. warning:: The Python client does not yet support signed requests.