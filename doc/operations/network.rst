Networking
==========

HTTP 
----

All built-in RPC interfaces for a given node (see :ref:`operations/configuration:``network.rpc_interfaces```) use HTTP/1.1. Operators that require HTTP/2 at the public edge can terminate it at a reverse proxy and forward HTTP/1.1 to CCF.

Configuration
~~~~~~~~~~~~~

Operators can cap the size of client HTTP requests (body and header) for each RPC interface in the :ref:`operations/configuration:``network.rpc_interfaces.[name].http_configuration``` configuration section. These configuration entries are optional and have sensible default values. 

If a client HTTP request breaches any of these values, the client is returned a `413 <https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Status/413>`_ or `431 <https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Status/431>`_ HTTP error and the session is automatically closed by the CCF node.
